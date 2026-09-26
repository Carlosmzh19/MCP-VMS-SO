"""
tools/windows/dns.py - DNS autoritativo genérico (FASE 2C).

Lectura L0: dns_list_zones, dns_list_records, dns_test_resolution.
Escritura L2 (ACK_IRREVERSIBLE, riesgo AD): dns_add_a_record (idempotente:
already_exists), dns_delete_record.
"""

import base64
import json
import logging

from core.audit import audit_log
from core.config import get_machine, SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, require_double_confirm
from core.ssh import build_ssh_args, clean_output, run_process
from core.validation import validate_not_empty
from core.validators import validate_dns_ip, validate_domain_fqdn, validate_ip

mcp = None

logger = logging.getLogger(__name__)


def _invoke_ps_b64(data: dict, script: str, timeout: int = SSH_TIMEOUT_DEFAULT) -> dict:
    """Ejecuta un script PS multilínea vía base64 UTF-16LE (EncodedCommand)."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = (
        f"$b64='{encoded}'; "
        f"$bytes=[Convert]::FromBase64String($b64); "
        f"$code=[Text.Encoding]::Unicode.GetString($bytes); "
        f"Invoke-Expression $code"
    )
    return run_process(build_ssh_args(data["ssh_host"], command), timeout=timeout)


def _dry_run(machine: str, confirm: bool, acknowledge: bool, ack_text: str, tool: str):
    """Gate L2 ACK_IRREVERSIBLE: JSON dry_run si falta, None si OK."""
    gate = require_double_confirm(
        confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, "", "", tool)
    if gate["ok"]:
        return None
    gate["machine"] = machine
    audit_log(tool, machine, f"dry_run missing={','.join(gate.get('missing', []))}")
    return json.dumps(gate, ensure_ascii=False, indent=2)


def register_dns(mcp_instance):
    """Registra las herramientas DNS con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def dns_list_zones(machine: str) -> str:
        """Lista zonas DNS (Get-DnsServerZone). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-DnsServerZone "
                  "| Select-Object ZoneName,ZoneType,IsAutoCreated,DynamicUpdate "
                  "| ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("dns_list_zones", machine, "list zonas DNS")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def dns_list_records(machine: str, zone: str) -> str:
        """Lista registros de una zona (Get-DnsServerResourceRecord). L0."""
        validate_not_empty(machine, "machine")
        validate_not_empty(zone, "zone")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$z='{escape_ps_single_quote(zone.strip())}'; "
                  "Get-DnsServerResourceRecord -ZoneName $z "
                  "| Select-Object HostName,RecordType,Timestamp,"
                  "@{N='Data';E={$_.RecordData.IPv4Address}} "
                  "| ConvertTo-Json -Depth 4")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("dns_list_records", machine, f"list registros zona={zone}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def dns_test_resolution(machine: str, fqdn: str, dns_server_ip: str = "") -> str:
        """Resuelve un FQDN (Resolve-DnsName, opcional contra un DNS dado). L0."""
        validate_not_empty(machine, "machine")
        validate_domain_fqdn(fqdn)
        server_clause = ""
        if dns_server_ip and dns_server_ip.strip():
            validate_dns_ip(dns_server_ip.strip())
            server_clause = (f" -Server '{escape_ps_single_quote(dns_server_ip.strip())}'")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$n='{escape_ps_single_quote(fqdn.strip())}'; "
                  f"Resolve-DnsName -Name $n{server_clause} -ErrorAction Stop "
                  "| Select-Object Name,Type,IPAddress,Section "
                  "| ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("dns_test_resolution", machine,
                  f"resolve {fqdn} via={dns_server_ip or 'default'}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def dns_add_a_record(machine: str, zone: str, rec_name: str, ipv4: str,
                         confirm: bool = False, acknowledge: bool = False,
                         ack_text: str = "") -> str:
        """Crea registro A (idempotente: already_exists). L2."""
        validate_not_empty(machine, "machine")
        validate_not_empty(zone, "zone")
        validate_not_empty(rec_name, "rec_name")
        validate_ip(ipv4)
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "dns_add_a_record")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$z='{escape_ps_single_quote(zone.strip())}'; "
            f"$n='{escape_ps_single_quote(rec_name.strip())}'; "
            f"$ip='{escape_ps_single_quote(ipv4.strip())}'; "
            "$found=Get-DnsServerResourceRecord -ZoneName $z -Name $n "
            "-RRType 'A' -ErrorAction SilentlyContinue "
            "| Select-Object -First 1; "
            "if($found){ Write-Output '__ALREADY_EXISTS__'; "
            "$found | Select-Object HostName,RecordType | ConvertTo-Json -Compress } "
            "else { Add-DnsServerResourceRecordA -ZoneName $z -Name $n "
            "-IPv4Address $ip; Write-Output '__CREATED__'; "
            "Get-DnsServerResourceRecord -ZoneName $z -Name $n -RRType 'A' "
            "| Select-Object HostName,RecordType | ConvertTo-Json -Compress }"
        )
        result = _invoke_ps_b64(data, script)
        result["already_exists"] = "__ALREADY_EXISTS__" in (result.get("stdout", "") or "")
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("dns_add_a_record", machine,
                  f"L2-ACK add A {rec_name}.{zone} -> {ipv4}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def dns_delete_record(machine: str, zone: str, rec_name: str,
                          record_type: str = "A",
                          confirm: bool = False, acknowledge: bool = False,
                          ack_text: str = "") -> str:
        """Elimina registro DNS (Remove-DnsServerResourceRecord). L2."""
        validate_not_empty(machine, "machine")
        validate_not_empty(zone, "zone")
        validate_not_empty(rec_name, "rec_name")
        if record_type not in ("A", "AAAA", "CNAME", "PTR", "MX", "TXT", "SRV", "NS"):
            raise ValueError(
                f"record_type no válido: {record_type!r}. "
                "Usa A|AAAA|CNAME|PTR|MX|TXT|SRV|NS.")
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "dns_delete_record")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$z='{escape_ps_single_quote(zone.strip())}'; "
            f"$n='{escape_ps_single_quote(rec_name.strip())}'; "
            f"Remove-DnsServerResourceRecord -ZoneName $z -Name $n "
            f"-RRType '{record_type}' -Force; "
            "Write-Output '__RECORD_DELETED__'"
        )
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("dns_delete_record", machine,
                  f"L2-ACK delete {record_type} {rec_name}.{zone}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
