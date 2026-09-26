"""
tools/linux/audit.py - Auditoria Linux (Fase 3).

Lectura sin friccion (L0, sin confirm):
- get_journal_linux: journalctl con filtros de unidad/prioridad.
- get_auditd_rules_linux: reglas de auditd (auditctl -l) + estado.

No colisiona con tools/linux/logs.py (get_logs_linux /
get_event_logs_linux): nombres nuevos con sufijo _linux.

Patron: get_machine + build_ssh_args + run_process + clean_output,
sudo -n + shlex.quote, @mcp.tool() -> str JSON.
"""

import json
import logging
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_lines
from core.audit import audit_log

mcp = None

logger = logging.getLogger(__name__)

_JOURNAL_PRIORITIES = {
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
    "0", "1", "2", "3", "4", "5", "6", "7",
}


def register(mcp_instance):
    """Registra las herramientas Linux de auditoria."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_journal_linux(
        machine: str, unit: str = "", lines: int = 100, priority: str = ""
    ) -> str:
        """Lee el journal de systemd (journalctl, L0).

        Sin 'unit' muestra el journal general; con 'unit' filtra por
        unidad systemd (-u). 'priority' opcional (emerg..debug o 0..7).
        """
        validate_not_empty(machine, "machine")
        validate_lines(lines)
        data = get_machine(machine)

        parts = [f"journalctl --no-pager -n {int(lines)} --output=short-iso"]
        if unit:
            validate_not_empty(unit, "unit")
            parts.append(f"-u {shlex.quote(unit)}")
        if priority:
            prio = str(priority).strip().lower()
            if prio not in _JOURNAL_PRIORITIES:
                raise ValueError(
                    f"priority no valida: {priority!r}. Usa emerg|alert|crit|err|"
                    "warning|notice|info|debug o 0..7."
                )
            parts.append(f"-p {shlex.quote(prio)}")
        command = " ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log(
            "get_journal_linux",
            machine,
            f"unit={unit or 'all'} lines={lines} priority={priority or 'any'} "
            + ("ok" if result["ok"] else "failed"),
        )
        return json.dumps(clean_output(result, 50000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_auditd_rules_linux(machine: str) -> str:
        """Lista las reglas de auditd (auditctl -l) + estado del servicio (L0)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- AUDITCTL RULES ---'; "
            "sudo -n auditctl -l 2>/dev/null || auditctl -l 2>/dev/null || echo 'AUDITCTL_UNAVAILABLE'; "
            "echo '--- AUDITD STATUS ---'; "
            "systemctl status auditd --no-pager 2>/dev/null || service auditd status 2>/dev/null "
            "|| echo 'AUDITD_STATUS_UNAVAILABLE'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_auditd_rules_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)
