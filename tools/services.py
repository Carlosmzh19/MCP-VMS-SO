"""
tools/services.py - Gestión de servicios.

Proporciona herramientas para listar, consultar, iniciar, detener
y reiniciar servicios en VMs Windows.
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
    """Registra las herramientas de servicios con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_services(machine: str) -> str:
        """Lista los servicios de la VM con su estado y tipo de inicio."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-Service | "
            "Select-Object Name,DisplayName,Status,StartType | "
            "Sort-Object Name | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_services", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_service_status(machine: str, service: str) -> str:
        """Obtiene el estado de un servicio específico."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        command = (
            f"Get-Service -Name '{service}' | "
            f"Select-Object Name,DisplayName,Status,StartType,ServiceType | "
            f"ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_service_status", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def start_service(machine: str, service: str) -> str:
        """Inicia un servicio detenido."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        command = (
            f"Start-Service -Name '{service}'; "
            f"if ($?) {{ Write-Output 'SERVICE_STARTED_OK' }} else {{ Write-Output 'START_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("start_service", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def stop_service(machine: str, service: str, confirm: bool = False) -> str:
        """Detiene un servicio en ejecución."""
        require_confirmation(confirm, "stop_service")
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        command = (
            f"Stop-Service -Name '{service}' -Force; "
            f"if ($?) {{ Write-Output 'SERVICE_STOPPED_OK' }} else {{ Write-Output 'STOP_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("stop_service", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def restart_service(machine: str, service: str) -> str:
        """Reinicia un servicio."""
        validate_not_empty(machine, "machine")
        validate_not_empty(service, "service")
        data = get_machine(machine)

        command = (
            f"Restart-Service -Name '{service}' -Force; "
            f"if ($?) {{ Write-Output 'SERVICE_RESTARTED_OK' }} else {{ Write-Output 'RESTART_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=45,
        )

        audit_log("restart_service", machine, f"service={service}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
