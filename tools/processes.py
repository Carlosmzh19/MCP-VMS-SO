"""
tools/processes.py - Gestión de procesos.

Proporciona herramientas para listar, consultar y terminar
procesos en VMs Windows.
"""

import json
import logging
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
    """Registra las herramientas de procesos con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_processes(machine: str) -> str:
        """Lista los procesos activos de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-Process | "
            "Select-Object Name,Id,CPU,WorkingSet64 | "
            "Sort-Object Name | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_processes", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_process_detail(machine: str, process_name: str) -> str:
        """Obtiene detalle de un proceso por nombre."""
        validate_not_empty(machine, "machine")
        validate_not_empty(process_name, "process_name")
        data = get_machine(machine)

        command = (
            f"Get-Process -Name '{process_name}' | "
            f"Select-Object Name,Id,StartTime,CPU,WorkingSet64,Threads | "
            f"ConvertTo-Json -Depth 2 -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        if result["ok"] and result["stdout"].strip():
            try:
                parsed = json.loads(result["stdout"])
                if isinstance(parsed, dict):
                    result["stdout"] = json.dumps([parsed], ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                pass

        audit_log("get_process_detail", machine, f"process={process_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def kill_process(machine: str, process_name: str, confirm: bool = False) -> str:
        """Termina un proceso por nombre."""
        require_confirmation(confirm, "kill_process")
        validate_not_empty(machine, "machine")
        validate_not_empty(process_name, "process_name")
        data = get_machine(machine)

        command = (
            f"Stop-Process -Name '{process_name}' -Force; "
            f"if ($?) {{ Write-Output 'PROCESS_KILLED_OK' }} else {{ Write-Output 'KILL_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("kill_process", machine, f"killed={process_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
