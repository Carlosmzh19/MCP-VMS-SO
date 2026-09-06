"""
tools/linux/logs.py - Gestión de logs Linux (journalctl/syslog).

get_event_logs_linux es un alias de journalctl para compatibilidad.
"""

import json
import logging
import shlex
from datetime import datetime

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_lines

mcp = None

logger = logging.getLogger(__name__)


def audit_log(tool: str, machine: str, detail: str) -> None:
    """Registra una acción de auditoría."""
    timestamp = datetime.now().isoformat()
    logger.info("AUDIT: %s | %s | %s | %s", timestamp, tool, machine, detail)


def register(mcp_instance):
    """Registra las herramientas Linux de logs con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_logs_linux(machine: str, source: str, lines: int = 100) -> str:
        """
        Obtiene logs de un servicio Linux vía journalctl -u.
        Si source es 'syslog', lee /var/log/syslog directamente.
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(source, "source")
        validate_lines(lines)
        data = get_machine(machine)

        q_src = shlex.quote(source)
        if source in ("syslog", "messages", "syslog-ng"):
            command = f"tail -n {lines} /var/log/syslog 2>/dev/null || tail -n {lines} /var/log/messages"
        else:
            command = f"journalctl -u {q_src} -n {lines} --no-pager --output=short-iso"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_logs_linux", machine, f"source={source} lines={lines}")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_event_logs_linux(machine: str, log_name: str = "syslog", lines: int = 100) -> str:
        """
        Alias journalctl de get_event_logs para Linux.
        log_name: nombre de unidad systemd o 'syslog'.
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(log_name, "log_name")
        validate_lines(lines)
        data = get_machine(machine)

        q_log = shlex.quote(log_name)
        if log_name in ("syslog", "messages", "System"):
            command = f"tail -n {lines} /var/log/syslog 2>/dev/null || journalctl -n {lines} --no-pager"
        else:
            command = f"journalctl -u {q_log} -n {lines} --no-pager --output=short-iso"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log("get_event_logs_linux", machine, f"log={log_name} lines={lines}")
        return json.dumps(clean_output(result, 50000), ensure_ascii=False, indent=2)
