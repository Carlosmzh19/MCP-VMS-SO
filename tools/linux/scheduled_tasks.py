"""
tools/linux/scheduled_tasks.py - Tareas programadas Linux (cron + timers).

Usa crontab y systemctl list-timers. Crear/eliminar requieren confirm.
"""

import base64
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
    """Registra las herramientas Linux de tareas programadas con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_scheduled_tasks_linux(machine: str) -> str:
        """Lista cron jobs y systemd timers en Linux."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- CRONTAB ---'; crontab -l 2>/dev/null || echo 'NO_CRONTAB'; "
            "echo '--- SYSTEM TIMERS ---'; systemctl list-timers --all --no-pager"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_scheduled_tasks_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_task_detail_linux(machine: str, task_name: str) -> str:
        """Obtiene el detalle de un cron job o timer systemd por nombre."""
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        data = get_machine(machine)

        q_task = shlex.quote(task_name)
        command = (
            f"crontab -l 2>/dev/null | grep -F {q_task} || echo 'NOT_IN_CRONTAB'; "
            f"echo '--- TIMER ---'; systemctl status {q_task} --no-pager 2>/dev/null; "
            f"systemctl cat {q_task} 2>/dev/null || true"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_task_detail_linux", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_scheduled_task_linux(
        machine: str, task_name: str, action: str, trigger_time: str = "", confirm: bool = False
    ) -> str:
        """
        Crea una entrada cron en Linux (requiere confirm).
        task_name: comentario identificador; action: comando a ejecutar;
        trigger_time: 'HH:mm' diario o expresión cron completa de 5 campos.
        """
        require_confirmation(confirm, "create_scheduled_task_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        validate_not_empty(action, "action")
        data = get_machine(machine)

        if trigger_time and len(trigger_time.split()) == 5:
            schedule = trigger_time
        elif trigger_time and ":" in trigger_time:
            try:
                hh, mm = trigger_time.split(":")[:2]
                schedule = f"{int(mm)} {int(hh)} * * *"
            except ValueError:
                raise ValueError("trigger_time debe ser 'HH:mm' o expresión cron de 5 campos.")
        else:
            schedule = "0 * * * *"

        cron_line = f"{schedule} {action}  # MCP:{task_name}"
        encoded = base64.b64encode(cron_line.encode("utf-8")).decode("ascii")
        command = (
            f"echo '{encoded}' | base64 -d > /tmp/mcp_cron_line.txt && "
            f"(crontab -l 2>/dev/null; cat /tmp/mcp_cron_line.txt) | crontab - && "
            f"echo 'TASK_CREATED_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_scheduled_task_linux", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def delete_scheduled_task_linux(machine: str, task_name: str, confirm: bool = False) -> str:
        """Elimina entradas cron marcadas con # MCP:<task_name> (requiere confirm)."""
        require_confirmation(confirm, "delete_scheduled_task_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        data = get_machine(machine)

        q_task = shlex.quote(f"# MCP:{task_name}")
        command = (
            f"crontab -l 2>/dev/null | grep -v -F {q_task} | crontab - && "
            f"echo 'TASK_DELETED_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("delete_scheduled_task_linux", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
