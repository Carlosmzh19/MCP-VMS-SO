"""
tools/connectivity.py - Herramientas de conectividad.

Proporciona herramientas para verificar conectividad SSH,
alcanzabilidad de red y listar máquinas disponibles.
"""

import json
import logging
from datetime import datetime

from core.config import get_machines, get_machine
from core.ssh import (
    build_ssh_args,
    build_ping_args,
    run_process,
    clean_output,
    diagnose_ssh_error,
    SSH_TEST_TIMEOUT,
    SSH_PING_TIMEOUT,
)
from core.validation import validate_not_empty

# Referencia al servidor MCP - se establece vía register()
mcp = None

logger = logging.getLogger(__name__)


def audit_log(tool: str, machine: str, detail: str) -> None:
    """Registra una acción de auditoría."""
    timestamp = datetime.now().isoformat()
    logger.info("AUDIT: %s | %s | %s | %s", timestamp, tool, machine, detail)


def register(mcp_instance):
    """Registra las herramientas de conectividad con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_machines() -> str:
        """Lista las VMs que este MCP permite administrar."""
        machines = get_machines()
        output = []
        for name, data in machines.items():
            output.append({
                "name": name,
                "ssh_host": data["ssh_host"],
                "os": data.get("os", "unknown"),
                "ip": data.get("ip", ""),
                "description": data.get("description", ""),
                "ssh_user": data.get("ssh_user", ""),
            })
        return json.dumps(output, ensure_ascii=False, indent=2)

    @mcp.tool()
    def test_ssh(machine: str) -> str:
        """
        Comprueba que el host puede autenticarse por SSH contra la VM.
        Usa el alias configurado en ~/.ssh/config.
        """
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        host = data["ssh_host"]

        result = run_process(
            build_ssh_args(host, "echo MCP_SSH_OK"),
            timeout=SSH_TEST_TIMEOUT,
        )

        error_hint = diagnose_ssh_error(result.get("stderr", ""), result.get("return_code", -1))
        if error_hint:
            result["diagnosis"] = error_hint

        audit_log("test_ssh", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def check_reachability(machine: str) -> str:
        """
        Comprueba desde el host si la IP de la VM responde a ping.
        Usa la IP configurada en el alias SSH.
        """
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        host = data["ssh_host"]

        # Obtener IP desde ssh -G
        result = run_process(
            [SSH_BINARY, "-G", host],
            timeout=SSH_PING_TIMEOUT,
        )

        hostname = ""
        if result["ok"]:
            for line in result["stdout"].splitlines():
                if line.lower().startswith("hostname "):
                    hostname = line.split(" ", 1)[1].strip()
                    break

        if not hostname:
            return json.dumps(
                {
                    "ok": False,
                    "error": "No se pudo determinar HostName desde ssh -G.",
                    "machine": machine,
                },
                ensure_ascii=False,
                indent=2,
            )

        ping_result = run_process(
            build_ping_args(hostname),
            timeout=SSH_PING_TIMEOUT,
        )
        ping_result["machine"] = machine
        ping_result["resolved_host"] = hostname

        audit_log("check_reachability", machine, "ok" if ping_result["ok"] else "unreachable")
        return json.dumps(clean_output(ping_result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def machine_profile(machine: str) -> str:
        """
        Devuelve el perfil de configuración de una VM.
        Útil para que el modelo conozca el contexto de la máquina.
        """
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        profile = {
            "name": machine,
            "ssh_host": data["ssh_host"],
            "os": data.get("os", "unknown"),
            "ip": data.get("ip", ""),
            "description": data.get("description", ""),
            "ssh_user": data.get("ssh_user", ""),
        }

        audit_log("machine_profile", machine, "ok")
        return json.dumps(profile, ensure_ascii=False, indent=2)


# Importar SSH_BINARY que se necesita en check_reachability
from core.ssh import SSH_BINARY
