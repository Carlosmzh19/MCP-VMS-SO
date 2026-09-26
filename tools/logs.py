"""
tools/logs.py - Gestión de logs unificado.

Proporciona herramientas para obtener logs del sistema,
soportando tanto Windows (Get-WinEvent) como Linux (journalctl).
"""

import json
import logging
from datetime import datetime

from core.config import get_machine, IS_WINDOWS
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_lines

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas de logs con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_logs(
        machine: str,
        source: str,
        lines: int = 100,
    ) -> str:
        """
        Obtiene logs de un servicio/fuente.

        Windows:
            source = nombre de un LogName de Windows Event Log,
            por ejemplo: System, Application, Security

        Futuro Linux:
            source = nombre del servicio para journalctl -u
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(source, "source")
        validate_lines(lines)
        data = get_machine(machine)
        os_type = data.get("os", "unknown")

        if os_type == "windows":
            command = (
                f"Get-WinEvent -LogName '{source}' -MaxEvents {lines} -ErrorAction SilentlyContinue | "
                f"Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | "
                f"ConvertTo-Json -Compress"
            )
            timeout = 60
        elif os_type == "linux":
            command = (
                f"journalctl -u {source} -n {lines} "
                f"--no-pager --output=short-iso"
            )
            timeout = 30
        else:
            raise ValueError(f"OS no soportado: {os_type}")

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=timeout,
        )

        audit_log("get_logs", machine, f"source={source} lines={lines}")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_event_logs(machine: str, log_name: str = "System", lines: int = 100) -> str:
        """
        Obtiene registros del Windows Event Log (específico de Windows).
        LogName típicos: System, Application, Security, Setup.
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(log_name, "log_name")
        validate_lines(lines)
        data = get_machine(machine)

        command = (
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents {lines} -ErrorAction SilentlyContinue | "
            f"Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | "
            f"ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log("get_event_logs", machine, f"log={log_name} lines={lines}")
        return json.dumps(clean_output(result, 50000), ensure_ascii=False, indent=2)
