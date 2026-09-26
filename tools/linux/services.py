"""
tools/linux/services.py - Gestión de servicios Linux (systemd).

Usa systemctl con sudo -n para acciones privilegiadas.
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


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas Linux de servicios con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_services_linux(machine: str) -> str:
        """Lista los servicios systemd de la VM Linux."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "systemctl list-units --type=service --all --no-pager"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_services_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_service_status_linux(machine: str, service: str) -> str:
        """Obtiene el estado de un servicio systemd específico."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        q_svc = shlex.quote(service)
        command = f"systemctl status {q_svc} --no-pager; echo '--- ACTIVE ---'; systemctl is-active {q_svc}"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_service_status_linux", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def start_service_linux(machine: str, service: str) -> str:
        """Inicia un servicio systemd detenido (sudo -n)."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        q_svc = shlex.quote(service)
        command = f"sudo -n systemctl start {q_svc} && echo 'SERVICE_STARTED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("start_service_linux", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def stop_service_linux(machine: str, service: str, confirm: bool = False) -> str:
        """Detiene un servicio systemd en ejecución (requiere confirm)."""
        require_confirmation(confirm, "stop_service_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        q_svc = shlex.quote(service)
        command = f"sudo -n systemctl stop {q_svc} && echo 'SERVICE_STOPPED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("stop_service_linux", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def restart_service_linux(machine: str, service: str) -> str:
        """Reinicia un servicio systemd (sudo -n)."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        q_svc = shlex.quote(service)
        command = f"sudo -n systemctl restart {q_svc} && echo 'SERVICE_RESTARTED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=45,
        )

        audit_log("restart_service_linux", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
