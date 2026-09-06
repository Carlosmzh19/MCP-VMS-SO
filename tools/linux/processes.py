"""
tools/linux/processes.py - Gestión de procesos Linux.

Usa ps, kill y pkill. Nunca usa sudo con prompt (solo kill directo).
"""

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
    """Registra las herramientas Linux de procesos con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_processes_linux(machine: str) -> str:
        """Lista los procesos activos de la VM Linux (ps aux)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "ps aux --sort=-%cpu | head -n 200"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_processes_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_process_detail_linux(machine: str, process_name: str) -> str:
        """Obtiene el detalle de un proceso Linux por nombre o PID."""
        validate_not_empty(machine, "machine")
        validate_not_empty(process_name, "process_name")
        data = get_machine(machine)

        q_proc = shlex.quote(process_name)
        if process_name.isdigit():
            command = f"ps -p {q_proc} -f -o pid,ppid,user,pcpu,pmem,etime,cmd"
        else:
            command = f"ps -C {q_proc} -f -o pid,ppid,user,pcpu,pmem,etime,cmd || pgrep -a -f {q_proc}"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_process_detail_linux", machine, f"process={process_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def kill_process_linux(machine: str, process_name: str, confirm: bool = False) -> str:
        """Termina un proceso Linux por nombre o PID (kill/pkill, requiere confirm)."""
        require_confirmation(confirm, "kill_process_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(process_name, "process_name")
        data = get_machine(machine)

        q_proc = shlex.quote(process_name)
        if process_name.isdigit():
            command = f"kill -TERM {q_proc} && echo 'PROCESS_KILLED_OK'"
        else:
            command = f"pkill -f {q_proc} && echo 'PROCESS_KILLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("kill_process_linux", machine, f"killed={process_name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
