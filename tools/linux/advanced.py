"""
tools/linux/advanced.py - Ejecución avanzada en Linux (bash genérico).

run_bash_script_linux ejecuta scripts bash multilínea vía base64.
run_command_linux es el equivalente genérico de run_command para Linux.
"""

import base64
import json
import logging
from datetime import datetime

from core.config import get_machine, SSH_TIMEOUT_DEFAULT
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_timeout, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas Linux de ejecución avanzada con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def run_bash_script_linux(
        machine: str,
        script: str,
        timeout_seconds: int = SSH_TIMEOUT_DEFAULT,
        confirm: bool = False,
    ) -> str:
        """
        Ejecuta un script bash multilínea en la VM Linux.
        El script se codifica en base64 para evitar problemas de comillas.
        Requiere confirm=true para ejecutarse.
        """
        require_confirmation(confirm, "run_bash_script_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(script, "script")
        validate_timeout(timeout_seconds)
        data = get_machine(machine)

        encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
        command = f"echo '{encoded}' | base64 -d | bash -s"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=timeout_seconds,
        )

        result["machine"] = machine
        result["os"] = data.get("os", "linux")

        audit_log("run_bash_script_linux", machine, f"script_len={len(script)}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def run_command_linux(
        machine: str,
        command: str,
        timeout_seconds: int = SSH_TIMEOUT_DEFAULT,
        confirm: bool = False,
    ) -> str:
        """
        Ejecuta un comando bash genérico en la VM Linux (nota: sin wrapper sudo automático).

        Esta herramienta otorga control administrativo sobre la VM.
        Debe usarse solo contra máquinas de laboratorio autorizadas.
        Requiere confirm=true. Antepone 'sudo -n' manualmente si necesitas privilegios.
        """
        require_confirmation(confirm, "run_command_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(command, "command")
        validate_timeout(timeout_seconds)
        data = get_machine(machine)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=timeout_seconds,
        )

        result["machine"] = machine
        result["os"] = data.get("os", "linux")

        audit_log("run_command_linux", machine, f"cmd={command[:100]}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
