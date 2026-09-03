"""
tools/system.py - Diagnóstico del sistema.

Proporciona herramientas para obtener información del sistema,
disco, actualizaciones, logs de eventos y variables de entorno.
"""

import json
import logging
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
    """Registra las herramientas de sistema con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_system_info(machine: str) -> str:
        """Obtiene información básica del sistema (hostname, OS, memoria, disco)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "$os = Get-CimInstance Win32_OperatingSystem; "
            "$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1; "
            "Write-Output '--- COMPUTERNAME ---'; "
            "$env:COMPUTERNAME; "
            "Write-Output '--- OS ---'; "
            "$os.Caption; "
            "$os.Version; "
            "$os.OSArchitecture; "
            "Write-Output '--- MEMORY ---'; "
            "$totalMem = [math]::Round($os.TotalVisibleMemorySize/1MB, 2); "
            "$freeMem = [math]::Round($os.FreePhysicalMemory/1MB, 2); "
            "Write-Output \"Total: ${totalMem} GB\"; "
            "Write-Output \"Free: ${freeMem} GB\"; "
            "Write-Output '--- CPU ---'; "
            "$cpu.Name; "
            "$cpu.NumberOfCores; "
            "Write-Output '--- DISK ---'; "
            "Get-PSDrive -PSProvider FileSystem | "
            "Select-Object Name,@{N='UsedGB';E={[math]::Round($_.Used/1GB,2)}},@{N='FreeGB';E={[math]::Round($_.Free/1GB,2)}} | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_system_info", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_disk_info(machine: str) -> str:
        """Obtiene información detallada de discos y unidades."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-PSDrive -PSProvider FileSystem | "
            "Select-Object Name,Used,Free,Provider,Root | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_disk_info", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_event_logs(machine: str, log_name: str = "System", lines: int = 100) -> str:
        """
        Obtiene registros del Windows Event Log.
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

    @mcp.tool()
    def get_installed_software(machine: str) -> str:
        """Lista el software instalado desde el registro de Windows."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | "
            "Where-Object {$_.DisplayName} | "
            "Sort-Object DisplayName | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log("get_installed_software", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 50000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_hotfixes(machine: str) -> str:
        """Lista las actualizaciones (hotfixes) instaladas."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-HotFix | "
            "Select-Object HotFixID,Description,InstalledOn,InstalledBy | "
            "Sort-Object InstalledOn -Descending | "
            "ConvertTo-Json -Compress"
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

        audit_log("get_hotfixes", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_environment_vars(machine: str) -> str:
        """Lista las variables de entorno del sistema."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-ChildItem Env: | "
            "Select-Object Name,Value | "
            "Sort-Object Name | "
            "ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_environment_vars", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_environment_var(
        machine: str, name: str, value: str, target: str = "Machine", confirm: bool = False
    ) -> str:
        """
        Establece una variable de entorno.
        Target puede ser: Machine, User, Process.
        """
        require_confirmation(confirm, "set_environment_var")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        validate_not_empty(value, "value")
        data = get_machine(machine)

        command = (
            f"[System.Environment]::SetEnvironmentVariable('{name}', '{value}', '{target}'); "
            f"Write-Output 'ENV_VAR_SET_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_environment_var", machine, f"name={name} target={target}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
