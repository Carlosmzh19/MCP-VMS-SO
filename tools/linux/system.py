"""
tools/linux/system.py - Diagnóstico del sistema Linux.

Implementaciones con bash/systemd: hostnamectl, lsb_release, uname,
uptime, free, df, dpkg y printenv. Si core/os_router o core/ssh no
existen aún, se usa fallback defensivo data.get("os") + sudo -n.
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


def _sudo(command: str, data: dict, requires_privilege: bool = False) -> str:
    """Antepone sudo -n si se requiere privilegio (nunca sudo interactivo)."""
    try:
        from core.os_router import get_os_type  # type: ignore
        from core.ssh import wrap_sudo  # type: ignore
        return wrap_sudo(command, get_os_type(data.get("os", "linux")), requires_privilege)
    except Exception:
        if requires_privilege:
            return f"sudo -n {command}"
        return command


def register(mcp_instance):
    """Registra las herramientas Linux de sistema con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_system_info_linux(machine: str) -> str:
        """Obtiene información básica del sistema Linux (hostname, distro, memoria, disco)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- HOSTNAME ---'; hostnamectl --static 2>/dev/null || hostname; "
            "echo '--- OS ---'; lsb_release -a 2>/dev/null || cat /etc/os-release; "
            "echo '--- KERNEL ---'; uname -a; "
            "echo '--- UPTIME ---'; uptime; "
            "echo '--- MEMORY ---'; free -h; "
            "echo '--- DISK ---'; df -h"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_system_info_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_disk_info_linux(machine: str) -> str:
        """Obtiene información detallada de discos en Linux (df, lsblk)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "df -hT; echo '--- LSBLK ---'; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_disk_info_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_installed_software_linux(machine: str) -> str:
        """Lista el software instalado en Linux (dpkg)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "dpkg -l 2>/dev/null | head -n 500 || rpm -qa 2>/dev/null | head -n 500"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log("get_installed_software_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 50000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_environment_vars_linux(machine: str) -> str:
        """Lista las variables de entorno del sistema Linux."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "printenv | sort"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_environment_vars_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_environment_var_linux(
        machine: str, name: str, value: str, confirm: bool = False
    ) -> str:
        """Establece una variable de entorno persistente en /etc/environment (requiere confirm)."""
        require_confirmation(confirm, "set_environment_var_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        validate_not_empty(value, "value")
        data = get_machine(machine)

        q_name = shlex.quote(name)
        q_value = shlex.quote(f"{name}={value}")
        # Elimina línea previa y añade la nueva de forma atómica con sudo -n.
        inner = (
            f"grep -v ^{q_name}= /etc/environment > /tmp/env.tmp 2>/dev/null; "
            f"echo {q_value} >> /tmp/env.tmp; "
            f"cat /tmp/env.tmp | sudo -n tee /etc/environment > /dev/null; "
            f"echo 'ENV_VAR_SET_OK'"
        )
        command = _sudo(inner, data, requires_privilege=False)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_environment_var_linux", machine, f"name={name}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
