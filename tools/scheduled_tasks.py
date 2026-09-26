"""
tools/scheduled_tasks.py - Gestión de tareas programadas.

Proporciona herramientas para listar, consultar, crear y eliminar
tareas programadas en VMs Windows.
"""

import json
import logging
from datetime import datetime

from core.config import get_machine
from core.ps_escape import escape_ps_single_quote
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas de tareas programadas con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_scheduled_tasks(machine: str) -> str:
        """Lista las tareas programadas de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-ScheduledTask | "
            "Select-Object TaskName,TaskPath,State,NextRunTime | "
            "Sort-Object TaskName | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_scheduled_tasks", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_task_detail(machine: str, task_name: str) -> str:
        """Obtiene el detalle de una tarea programada."""
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        data = get_machine(machine)

        esc_task = escape_ps_single_quote(task_name)
        command = (
            f"Get-ScheduledTask -TaskName '{esc_task}' | "
            f"Select-Object TaskName,TaskPath,State,Actions,Triggers,Principal | "
            f"ConvertTo-Json -Depth 5 -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_task_detail", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_scheduled_task(
        machine: str,
        task_name: str,
        action: str,
        trigger_time: str = "",
        confirm: bool = False,
    ) -> str:
        """
        Crea una tarea programada básica.
        trigger_time en formato HH:mm (ej: '14:00' para las 2pm).
        """
        require_confirmation(confirm, "create_scheduled_task")
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        validate_not_empty(action, "action")
        data = get_machine(machine)

        escaped_action = action.replace("'", "''")
        esc_task = escape_ps_single_quote(task_name)

        if trigger_time:
            command = (
                f"$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-Command \"{escaped_action}\"'; "
                f"$trigger = New-ScheduledTaskTrigger -Daily -At '{trigger_time}'; "
                f"Register-ScheduledTask -TaskName '{esc_task}' -Action $action -Trigger $trigger; "
                f"Write-Output 'TASK_CREATED_OK'"
            )
        else:
            command = (
                f"$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-Command \"{escaped_action}\"'; "
                f"Register-ScheduledTask -TaskName '{esc_task}' -Action $action; "
                f"Write-Output 'TASK_CREATED_OK'"
            )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_scheduled_task", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def delete_scheduled_task(machine: str, task_name: str, confirm: bool = False) -> str:
        """Elimina una tarea programada."""
        require_confirmation(confirm, "delete_scheduled_task")
        validate_not_empty(machine, "machine")
        validate_not_empty(task_name, "task_name")
        data = get_machine(machine)

        esc_task = escape_ps_single_quote(task_name)
        command = (
            f"Unregister-ScheduledTask -TaskName '{esc_task}' -Confirm:$false; "
            f"Write-Output 'TASK_DELETED_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("delete_scheduled_task", machine, f"task={task_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)