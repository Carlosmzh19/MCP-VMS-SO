"""
tools/linux/network.py - Configuración de red Linux.

Usa ip, resolvectl y ufw. set_ip_address_linux lleva advertencia
anti-brick y requiere confirm. Corrige el patrón NameError: siempre
data = get_machine(machine) antes de usar data.
"""

import json
import logging
import shlex
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
    """Registra las herramientas Linux de red con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_network_config_linux(machine: str) -> str:
        """Muestra la configuración de red Linux (ip addr, ip route, resolvectl)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- ADDR ---'; ip addr show; "
            "echo '--- ROUTE ---'; ip route show; "
            "echo '--- DNS ---'; resolvectl status 2>/dev/null || cat /etc/resolv.conf"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_network_config_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_ip_address_linux(
        machine: str,
        interface: str,
        ip_address: str,
        prefix_length: int,
        default_gateway: str = "",
        confirm: bool = False,
    ) -> str:
        """
        Cambia la IP de una interfaz Linux (ip addr + nmcli, requiere confirm).

        ADVERTENCIA: cambiar la IP de la interfaz de gestión puede cortar
        el acceso SSH (brick). Verifica interfaz y gateway antes de confirmar.
        """
        require_confirmation(confirm, "set_ip_address_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(ip_address, "ip_address")
        data = get_machine(machine)

        q_if = shlex.quote(interface)
        q_ip = shlex.quote(f"{ip_address}/{prefix_length}")
        parts = [f"sudo -n ip addr add {q_ip} dev {q_if}"]
        if default_gateway:
            q_gw = shlex.quote(default_gateway)
            parts.append(f"sudo -n ip route replace default via {q_gw} dev {q_if}")
        parts.append("echo 'IP_SET_OK (verifica conectividad SSH antes de cerrar sesion)'")
        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_ip_address_linux", machine, f"interface={interface} ip={ip_address}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_dns_server_linux(machine: str, interface: str, dns_server: str, confirm: bool = False) -> str:
        """Cambia el servidor DNS en Linux (resolvectl/nmcli, requiere confirm)."""
        require_confirmation(confirm, "set_dns_server_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(interface, "interface")
        validate_not_empty(dns_server, "dns_server")
        data = get_machine(machine)

        q_if = shlex.quote(interface)
        q_dns = shlex.quote(dns_server)
        command = (
            f"sudo -n resolvectl dns {q_if} {q_dns} 2>/dev/null || "
            f"sudo -n nmcli con mod {q_if} ipv4.dns {q_dns} && echo 'DNS_SET_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_dns_server_linux", machine, f"interface={interface} dns={dns_server}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_dns_cache_linux(machine: str) -> str:
        """Muestra la caché/estadísticas DNS en Linux (resolvectl statistics)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "resolvectl statistics 2>/dev/null || systemd-resolve --statistics 2>/dev/null || cat /etc/resolv.conf"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_dns_cache_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def flush_dns_linux(machine: str) -> str:
        """Limpia la caché DNS en Linux (resolvectl flush-caches)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "sudo -n resolvectl flush-caches 2>/dev/null || sudo -n systemd-resolve --flush-caches; echo 'DNS_CACHE_FLUSHED'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("flush_dns_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_firewall_rules_linux(machine: str) -> str:
        """Lista reglas de firewall Linux (ufw status verbose)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "sudo -n ufw status verbose 2>/dev/null || sudo -n iptables -L -n -v"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_firewall_rules_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def open_firewall_port_linux(
        machine: str, name: str, port: int, protocol: str = "tcp", confirm: bool = False
    ) -> str:
        """Abre un puerto en ufw (sudo -n ufw allow, requiere confirm)."""
        require_confirmation(confirm, "open_firewall_port_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        q_proto = shlex.quote(protocol.lower())
        command = f"sudo -n ufw allow {int(port)}/{q_proto} comment {shlex.quote(name)} && echo 'PORT_OPENED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("open_firewall_port_linux", machine, f"name={name} port={port}/{protocol}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def enable_firewall_rule_linux(machine: str, name: str, confirm: bool = False) -> str:
        """Habilita ufw en Linux (requiere confirm)."""
        require_confirmation(confirm, "enable_firewall_rule_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        command = "sudo -n ufw --force enable && echo 'FIREWALL_ENABLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("enable_firewall_rule_linux", machine, f"enabled={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def disable_firewall_rule_linux(machine: str, name: str, confirm: bool = False) -> str:
        """Deshabilita una regla/puerto ufw en Linux (requiere confirm)."""
        require_confirmation(confirm, "disable_firewall_rule_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        data = get_machine(machine)

        command = f"sudo -n ufw delete allow {shlex.quote(name)} && echo 'RULE_DISABLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_firewall_rule_linux", machine, f"disabled={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
