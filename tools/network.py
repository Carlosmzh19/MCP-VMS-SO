"""
tools/network.py - Configuración de red.

Proporciona herramientas para gestionar IPs, DNS, firewall
y configuración de red en VMs Windows.
"""

import json
import logging

from core.config import get_machine
from core.ps_escape import escape_ps_single_quote
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty
from core.security_gate import require_double_confirm, ACK_SSH
from core.validators import (
    validate_dns_ip,
    validate_gateway_in_subnet,
    validate_ip,
    validate_prefix,
)

from .network_safe import (
    POST_CHECK_HINT,
    SSH_CUT_WARNING,
    SNAPSHOT_REMINDER,
    build_preflight,
)

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas de red con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_network_config(machine: str) -> str:
        """Muestra la configuración de red de la VM (interfaces, IPs, DNS, gateway)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-NetIPConfiguration | "
            "Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway,DnsServer | "
            "ConvertTo-Json -Depth 3 -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_network_config", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_ip_address(
        machine: str,
        interface: str,
        ip_address: str,
        prefix_length: int,
        default_gateway: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """
        Cambia la IP estática de una interfaz de red.
        La interfaz es el nombre de la interfaz (ej: 'Ethernet', 'Wi-Fi').

        L2 ACK_SSH con eco de la IP nueva (Fase 4): exige confirm=true +
        acknowledge=true + ack_text='SE-QUE-PUEDO-PERDER-SSH' + eco de
        ip_address en echo_confirm. Sin L2 completo retorna dry_run con
        preflight (sin SSH).
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(ip_address, "ip_address")
        validate_ip(ip_address.strip())
        validate_prefix(prefix_length)
        prefix = int(prefix_length)  # type: ignore[arg-type]
        if default_gateway:
            validate_ip(default_gateway.strip())

        preflight = build_preflight(
            new_ip=ip_address.strip(),
            prefix=prefix,
            gateway=default_gateway.strip() if default_gateway else "",
        )

        gate = require_double_confirm(
            confirm,
            acknowledge,
            ack_text,
            ACK_SSH,
            echo_confirm,
            ip_address.strip(),
            "set_ip_address",
        )
        if not gate["ok"]:
            audit_log("set_ip_address", machine, "dry_run L2 incompleto")
            return json.dumps(
                {
                    **gate,
                    "tool": "set_ip_address",
                    "machine": machine,
                    "preflight": preflight,
                    "warning": gate["warning"] + " " + SSH_CUT_WARNING,
                    "snapshot_reminder": SNAPSHOT_REMINDER,
                },
                ensure_ascii=False,
                indent=2,
            )

        if default_gateway:
            # Con L2 completo el gateway fuera de subred bloquea (brick).
            validate_gateway_in_subnet(
                ip_address.strip(), prefix, default_gateway.strip()
            )

        data = get_machine(machine)

        esc_iface = escape_ps_single_quote(interface)
        parts = [
            f"Remove-NetIPAddress -InterfaceAlias '{esc_iface}' -Confirm:$false -ErrorAction SilentlyContinue"
        ]

        cmd_add = f"New-NetIPAddress -InterfaceAlias '{esc_iface}' -IPAddress '{ip_address}' -PrefixLength {prefix}"
        if default_gateway:
            cmd_add += f" -DefaultGateway '{default_gateway}'"
        parts.append(cmd_add)

        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_ip_address", machine, f"interface={interface} ip={ip_address} L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_dns_server(
        machine: str,
        interface: str,
        dns_server: str,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """Cambia el servidor DNS de una interfaz de red.

        L2 ACK_SSH con eco del DNS (Fase 4): exige confirm=true +
        acknowledge=true + ack_text='SE-QUE-PUEDO-PERDER-SSH' + eco de
        dns_server en echo_confirm. Sin L2 completo retorna dry_run con
        preflight (sin SSH).
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(dns_server, "dns_server")
        validate_dns_ip(dns_server.strip())

        preflight = build_preflight(new_dns=dns_server.strip())

        gate = require_double_confirm(
            confirm,
            acknowledge,
            ack_text,
            ACK_SSH,
            echo_confirm,
            dns_server.strip(),
            "set_dns_server",
        )
        if not gate["ok"]:
            audit_log("set_dns_server", machine, "dry_run L2 incompleto")
            return json.dumps(
                {
                    **gate,
                    "tool": "set_dns_server",
                    "machine": machine,
                    "preflight": preflight,
                    "warning": gate["warning"] + " " + SSH_CUT_WARNING,
                    "snapshot_reminder": SNAPSHOT_REMINDER,
                },
                ensure_ascii=False,
                indent=2,
            )

        data = get_machine(machine)

        esc_iface = escape_ps_single_quote(interface)
        command = (
            f"Set-DnsClientServerAddress -InterfaceAlias '{esc_iface}' "
            f"-ServerAddresses '{dns_server}'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_dns_server", machine, f"interface={interface} dns={dns_server} L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_dns_cache(machine: str) -> str:
        """Muestra la cache DNS de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-DnsClientCache | "
            "Select-Object Entry,RecordName,Data,Type | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_dns_cache", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def flush_dns(machine: str) -> str:
        """Limpia la cache DNS de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "Clear-DnsClientCache; Write-Output 'DNS_CACHE_FLUSHED'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("flush_dns", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_firewall_rules(machine: str, profile: str = "Any") -> str:
        """
        Lista reglas de firewall de la VM.
        Profile puede ser: Any, Domain, Private, Public.
        """
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        valid_profiles = ("Any", "Domain", "Private", "Public")
        if profile not in valid_profiles:
            raise ValueError(
                f"profile no válido: {profile!r}. Valores válidos: {', '.join(valid_profiles)}."
            )

        profile_arg = "" if profile == "Any" else f" -Profile {profile}"
        command = (
            f"Get-NetFirewallRule -Direction Inbound -Enabled True "
            f"-Action Allow{profile_arg} | "
            f"Select-Object Name,DisplayName,Direction,Action,Profile | "
            f"ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        if result["ok"] and result["stdout"].strip():
            try:
                parsed = json.loads(result["stdout"])
                if isinstance(parsed, dict):
                    result["stdout"] = json.dumps([parsed], ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                pass

        audit_log("get_firewall_rules", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def open_firewall_port(
        machine: str,
        name: str,
        port: int,
        protocol: str = "TCP",
        confirm: bool = False,
    ) -> str:
        """
        Abre un puerto en el firewall de la VM (regla de entrada).
        """
        require_confirmation(confirm, "open_firewall_port")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        esc_name = escape_ps_single_quote(name)
        command = (
            f"New-NetFirewallRule -Name '{esc_name}' "
            f"-DisplayName '{esc_name}' "
            f"-Enabled True -Direction Inbound "
            f"-Protocol {protocol} -LocalPort {port} -Action Allow"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("open_firewall_port", machine, f"name={name} port={port}/{protocol}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def enable_firewall_rule(machine: str, name: str, confirm: bool = False) -> str:
        """Habilita una regla de firewall existente."""
        require_confirmation(confirm, "enable_firewall_rule")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        command = f"Enable-NetFirewallRule -Name '{escape_ps_single_quote(name)}'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("enable_firewall_rule", machine, f"enabled={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def disable_firewall_rule(machine: str, name: str, confirm: bool = False) -> str:
        """Deshabilita una regla de firewall existente."""
        require_confirmation(confirm, "disable_firewall_rule")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        command = f"Disable-NetFirewallRule -Name '{escape_ps_single_quote(name)}'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_firewall_rule", machine, f"disabled={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)