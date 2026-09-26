"""
tools/workflows/domain_health.py - Workflow check_domain_health (FASE 5, L0).

Solo lectura: ping DC<->CLI, DNS del cliente == IP del DC, nslookup,
nltest /dsgetdc, Get-ADDomain, Get-DnsServerZone, Test-NetConnection
445/389. Agrega PASS/FAIL por capa. Sin confirm.
"""

import json
import logging

from core.audit import audit_log
from core.config import SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.validation import validate_not_empty
from core.validators import validate_domain_fqdn

from ._common import (
    EVIDENCE_DIR_HINT,
    SNAPSHOT_REMINDER_L0,
    _invoke_ps_b64,
    preflight_ssh,
)

mcp = None

logger = logging.getLogger(__name__)

# Capas evaluadas, en el orden del plan (Resumen §22).
LAYERS = [
    "ping_dc",
    "dns_client_points_dc",
    "nslookup",
    "dsgetdc",
    "ad_domain",
    "dns_zones",
    "smb_445",
    "ldap_389",
]


def _layer_script_dc(domain: str) -> str:
    d = escape_ps_single_quote(domain)
    return " ".join(
        [
            "$ErrorActionPreference='Continue';",
            f"$dom='{d}';",
            "function L($n,$ok,$det){",
            "  $s=if($ok){'PASS'}else{'FAIL'};",
            "  Write-Output (\"LAYER|\"+$n+\"|\"+$s+\"|\"+$det) };",
            "try { $p=Test-Connection -ComputerName $dom -Count 2 -Quiet;",
            "  L 'ping_dc' $p \"ping $dom desde DC\" }",
            "catch { L 'ping_dc' $false $_.Exception.Message };",
            "try { $z=Get-DnsServerZone -ErrorAction Stop | Select-Object -ExpandProperty ZoneName;",
            "  $has=$z -contains $dom;",
            "  L 'dns_zones' $has (\"zonas: \"+($z -join ',')) }",
            "catch { L 'dns_zones' $false $_.Exception.Message };",
            "try { $ad=Get-ADDomain -ErrorAction Stop;",
            "  L 'ad_domain' $true (\"DNSRoot=\"+$ad.DNSRoot+\" Mode=\"+$ad.DomainMode) }",
            "catch { L 'ad_domain' $false $_.Exception.Message };",
            "try { $r=Resolve-DnsName -Name $dom -Server 127.0.0.1 -ErrorAction Stop;",
            "  L 'nslookup' $true (($r | Select-Object -First 1 | ForEach-Object { $_.IPAddress }) -join ',') }",
            "catch { L 'nslookup' $false $_.Exception.Message };",
            "try { $o=nltest /dsgetdc:$dom 2>&1 | Out-String;",
            "  L 'dsgetdc' ($LASTEXITCODE -eq 0) ($o.Trim().Split(\"`n\") | Select-Object -First 2 -join ' ') }",
            "catch { L 'dsgetdc' $false $_.Exception.Message };",
            "foreach($port in @(445,389)){",
            "  $n=if($port -eq 445){'smb_445'}else{'ldap_389'};",
            "  try { $t=Test-NetConnection -ComputerName 'localhost' -Port $port -WarningAction SilentlyContinue;",
            "    L $n $t.TcpTestSucceeded (\"localhost:\"+$port) }",
            "  catch { L $n $false $_.Exception.Message } }",
        ]
    )


def _layer_script_client(domain: str) -> str:
    d = escape_ps_single_quote(domain)
    return " ".join(
        [
            "$ErrorActionPreference='Continue';",
            f"$dom='{d}';",
            "function L($n,$ok,$det){",
            "  $s=if($ok){'PASS'}else{'FAIL'};",
            "  Write-Output (\"LAYER|\"+$n+\"|\"+$s+\"|\"+$det) };",
            "try { $p=Test-Connection -ComputerName $dom -Count 2 -Quiet;",
            "  L 'ping_dc' $p \"ping $dom desde cliente\" }",
            "catch { L 'ping_dc' $false $_.Exception.Message };",
            "try { $dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |",
            "    Select-Object -ExpandProperty ServerAddresses);",
            "  $dcIp=@([Net.Dns]::GetHostAddresses($dom) | Where-Object {",
            "    $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString });",
            "  $hit=@($dns | Where-Object { $dcIp -contains $_ });",
            "  L 'dns_client_points_dc' ($hit.Count -gt 0) (\"dns=\"+($dns -join ',')+\" dc=\"+($dcIp -join ',')) }",
            "catch { L 'dns_client_points_dc' $false $_.Exception.Message };",
            "try { $r=Resolve-DnsName -Name $dom -ErrorAction Stop;",
            "  L 'nslookup' $true (($r | Select-Object -First 1 | ForEach-Object { $_.IPAddress }) -join ',') }",
            "catch { L 'nslookup' $false $_.Exception.Message };",
            "try { $o=nltest /dsgetdc:$dom 2>&1 | Out-String;",
            "  L 'dsgetdc' ($LASTEXITCODE -eq 0) ($o.Trim().Split(\"`n\") | Select-Object -First 2 -join ' ') }",
            "catch { L 'dsgetdc' $false $_.Exception.Message };",
            "try { $a=Get-ADDomain -Server $dom -ErrorAction Stop;",
            "  L 'ad_domain' $true (\"DNSRoot=\"+$a.DNSRoot) }",
            "catch { L 'ad_domain' $false $_.Exception.Message };",
            "try { $z=Resolve-DnsName -Name $dom -Type SOA -ErrorAction Stop;",
            "  L 'dns_zones' $true 'SOA resuelve' }",
            "catch { L 'dns_zones' $false $_.Exception.Message };",
            "foreach($port in @(445,389)){",
            "  $n=if($port -eq 445){'smb_445'}else{'ldap_389'};",
            "  try { $t=Test-NetConnection -ComputerName $dom -Port $port -WarningAction SilentlyContinue;",
            "    L $n $t.TcpTestSucceeded ($dom+\":\"+$port) }",
            "  catch { L $n $false $_.Exception.Message } }",
        ]
    )


def parse_layers(stdout: str) -> list:
    """Convierte líneas LAYER|name|PASS|detail en lista ordenada por LAYERS."""
    found = {}
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("LAYER|"):
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        _, name, status, detail = parts
        found[name.strip()] = {
            "layer": name.strip(),
            "status": status.strip(),
            "detail": detail.strip(),
        }
    layers = []
    for name in LAYERS:
        layers.append(
            found.get(name, {"layer": name, "status": "UNKNOWN", "detail": "sin dato"})
        )
    return layers


def register_domain_health(mcp_instance):
    """Registra el workflow check_domain_health con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def check_domain_health(
        machine_dc: str, machine_client: str, domain_name: str
    ) -> str:
        """Salud del dominio por capas DC + cliente (ping/DNS/nslookup/dsgetdc/AD/445/389). L0."""
        validate_not_empty(machine_dc, "machine_dc")
        validate_not_empty(machine_client, "machine_client")
        validate_domain_fqdn(domain_name)
        domain = domain_name.strip()

        data_dc, err = preflight_ssh(machine_dc)
        if err is not None:
            audit_log("check_domain_health", machine_dc, "abortado: test_ssh DC falló")
            return err
        data_cli, err = preflight_ssh(machine_client)
        if err is not None:
            audit_log(
                "check_domain_health", machine_client, "abortado: test_ssh CLI falló"
            )
            return err

        res_dc = _invoke_ps_b64(data_dc, _layer_script_dc(domain), SSH_TIMEOUT_DEFAULT)
        res_cli = _invoke_ps_b64(
            data_cli, _layer_script_client(domain), SSH_TIMEOUT_DEFAULT
        )
        layers_dc = parse_layers(res_dc.get("stdout", "") or "")
        layers_cli = parse_layers(res_cli.get("stdout", "") or "")

        # PASS global solo si todas las capas de ambos lados pasan.
        all_pass = all(
            layer["status"] == "PASS" for layer in layers_dc + layers_cli
        )
        out = {
            "ok": all_pass,
            "machine_dc": machine_dc,
            "machine_client": machine_client,
            "domain": domain,
            "dc": layers_dc,
            "client": layers_cli,
            "failed": [
                f"{side}:{layer['layer']}"
                for side, layers in (("dc", layers_dc), ("client", layers_cli))
                for layer in layers
                if layer["status"] != "PASS"
            ],
            "snapshot_reminder": SNAPSHOT_REMINDER_L0,
            "evidence_hint": EVIDENCE_DIR_HINT,
        }
        audit_log(
            "check_domain_health", f"{machine_dc}+{machine_client}",
            f"health {domain} ok={all_pass} failed={len(out['failed'])}",
        )
        return json.dumps(out, ensure_ascii=False, indent=2)
