"""
tools/advanced.py - Ejecución avanzada de comandos.

Proporciona herramientas para ejecutar comandos arbitrarios
y scripts PowerShell en VMs remotas.
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


def audit_log(tool: str, machine: str, detail: str) -> None:
    """Registra una acción de auditoría."""
    timestamp = datetime.now().isoformat()
    logger.info("AUDIT: %s | %s | %s | %s", timestamp, tool, machine, detail)


def register(mcp_instance):
    """Registra las herramientas de ejecución avanzada con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def run_command(
        machine: str,
        command: str,
        timeout_seconds: int = SSH_TIMEOUT_DEFAULT,
        confirm: bool = False,
    ) -> str:
        """
        Ejecuta un comando remoto por SSH.

        Esta herramienta otorga control administrativo sobre la VM.
        Debe usarse solo contra máquinas de laboratorio autorizadas.
        Requiere confirm=true para ejecutarse.
        """
        require_confirmation(confirm, "run_command")
        validate_not_empty(machine, "machine")
        validate_not_empty(command, "command")
        validate_timeout(timeout_seconds)
        data = get_machine(machine)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=timeout_seconds,
        )

        result["machine"] = machine
        result["os"] = data.get("os", "unknown")

        audit_log("run_command", machine, f"cmd={command[:100]}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def run_powershell_script(
        machine: str,
        script: str,
        timeout_seconds: int = SSH_TIMEOUT_DEFAULT,
        confirm: bool = False,
    ) -> str:
        """
        Ejecuta un script PowerShell multilinea en la VM.
        El script se codifica en base64 para evitar problemas de comillas.
        Requiere confirm=true para ejecutarse.
        """
        require_confirmation(confirm, "run_powershell_script")
        validate_not_empty(machine, "machine")
        validate_not_empty(script, "script")
        validate_timeout(timeout_seconds)
        data = get_machine(machine)

        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")

        command = (
            f"$b64='{encoded}'; "
            f"$bytes=[Convert]::FromBase64String($b64); "
            f"$code=[Text.Encoding]::Unicode.GetString($bytes); "
            f"Invoke-Expression $code"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=timeout_seconds,
        )

        result["machine"] = machine
        result["os"] = data.get("os", "unknown")

        audit_log("run_powershell_script", machine, f"script_len={len(script)}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
