"""
tools/linux/network.py - Configuración de red Linux.

Usa ip, resolvectl y ufw. set_ip_address_linux lleva advertencia
anti-brick y requiere confirm. Corrige el patrón NameError: siempre
data = get_machine(machine) antes de usar data.
"""

import json
import logging
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty
from core.security_gate import require_double_confirm, ACK_SSH
from core.validators import (
    validate_dns_ip,
    validate_gateway_in_subnet,
    validate_ip,
    validate_prefix,
)

from ..network_safe import (
    POST_CHECK_HINT,
    SSH_CUT_WARNING,
    SNAPSHOT_REMINDER,
    build_preflight,
)

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


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
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """
        Cambia la IP de una interfaz Linux (ip addr + nmcli).

        L2 ACK_SSH con eco de la IP nueva (Fase 4): exige confirm=true +
        acknowledge=true + ack_text='SE-QUE-PUEDO-PERDER-SSH' + eco de
        ip_address en echo_confirm. Sin L2 completo retorna dry_run con
        preflight (sin SSH).

        ADVERTENCIA: cambiar la IP de la interfaz de gestión puede cortar
        el acceso SSH (brick). Verifica interfaz y gateway antes de confirmar.
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
            "set_ip_address_linux",
        )
        if not gate["ok"]:
            audit_log("set_ip_address_linux", machine, "dry_run L2 incompleto")
            return json.dumps(
                {
                    **gate,
                    "tool": "set_ip_address_linux",
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

        audit_log("set_ip_address_linux", machine, f"interface={interface} ip={ip_address} L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_dns_server_linux(
        machine: str,
        interface: str,
        dns_server: str,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """Cambia el servidor DNS en Linux (resolvectl/nmcli).

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
            "set_dns_server_linux",
        )
        if not gate["ok"]:
            audit_log("set_dns_server_linux", machine, "dry_run L2 incompleto")
            return json.dumps(
                {
                    **gate,
                    "tool": "set_dns_server_linux",
                    "machine": machine,
                    "preflight": preflight,
                    "warning": gate["warning"] + " " + SSH_CUT_WARNING,
                    "snapshot_reminder": SNAPSHOT_REMINDER,
                },
                ensure_ascii=False,
                indent=2,
            )

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

        audit_log("set_dns_server_linux", machine, f"interface={interface} dns={dns_server} L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)

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
