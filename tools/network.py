"""
tools/network.py - Configuración de red.

Proporciona herramientas para gestionar IPs, DNS, firewall
y configuración de red en VMs Windows.
"""

import json
import logging
from datetime import datetime

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


def audit_log(tool: str, machine: str, detail: str) -> None:
    """Registra una acción de auditoría."""
    timestamp = datetime.now().isoformat()
    logger.info("AUDIT: %s | %s | %s | %s", timestamp, tool, machine, detail)


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
    ) -> str:
        """
        Cambia la IP estática de una interfaz de red.
        La interfaz es el nombre de la interfaz (ej: 'Ethernet', 'Wi-Fi').
        """
        require_confirmation(confirm, "set_ip_address")
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(ip_address, "ip_address")
        get_machine(machine)

        parts = [
            f"Remove-NetIPAddress -InterfaceAlias '{interface}' -Confirm:$false -ErrorAction SilentlyContinue"
        ]

        cmd_add = f"New-NetIPAddress -InterfaceAlias '{interface}' -IPAddress '{ip_address}' -PrefixLength {prefix_length}"
        if default_gateway:
            cmd_add += f" -DefaultGateway '{default_gateway}'"
        parts.append(cmd_add)

        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_ip_address", machine, f"interface={interface} ip={ip_address}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_dns_server(
        machine: str,
        interface: str,
        dns_server: str,
        confirm: bool = False,
    ) -> str:
        """Cambia el servidor DNS de una interfaz de red."""
        require_confirmation(confirm, "set_dns_server")
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(dns_server, "dns_server")
        data = get_machine(machine)

        command = (
            f"Set-DnsClientServerAddress -InterfaceAlias '{interface}' "
            f"-ServerAddresses '{dns_server}'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_dns_server", machine, f"interface={interface} dns={dns_server}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

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

        command = (
            f"Get-NetFirewallRule -Direction Inbound -Enabled True "
            f"-Action Allow | "
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

        command = (
            f"New-NetFirewallRule -Name '{name}' "
            f"-DisplayName '{name}' "
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

        command = f"Enable-NetFirewallRule -Name '{name}'"

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

        command = f"Disable-NetFirewallRule -Name '{name}'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_firewall_rule", machine, f"disabled={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)