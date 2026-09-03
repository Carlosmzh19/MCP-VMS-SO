"""
tools/users.py - Gestión de usuarios y grupos.

Proporciona herramientas para administrar usuarios locales,
grupos y miembros de grupos en VMs Windows.
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
    """Registra las herramientas de usuarios con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_users(machine: str) -> str:
        """Lista los usuarios locales de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-LocalUser | "
            "Select-Object Name,Enabled,LastLogon,PasswordRequired,Description | "
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

        audit_log("list_users", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_user(
        machine: str,
        username: str,
        password: str,
        description: str = "",
        confirm: bool = False,
    ) -> str:
        """
        Crea un usuario local en la VM.
        La contraseña se envía de forma segura al proceso PowerShell.
        """
        require_confirmation(confirm, "create_user")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(password, "password")
        data = get_machine(machine)

        escaped_pw = password.replace("'", "''")
        escaped_desc = description.replace("'", "''")

        command = (
            f"$secPw = ConvertTo-SecureString '{escaped_pw}' -AsPlainText -Force; "
            f"New-LocalUser -Name '{username}' -Password $secPw "
            f"-FullName '{username}' -Description '{escaped_desc}' -PasswordNeverExpires; "
            f"Get-LocalUser -Name '{username}' | "
            f"Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json -Compress"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_user", machine, f"created={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def delete_user(machine: str, username: str, confirm: bool = False) -> str:
        """Elimina un usuario local de la VM."""
        require_confirmation(confirm, "delete_user")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        command = (
            f"Remove-LocalUser -Name '{username}'; "
            f"if ($?) {{ Write-Output 'USER_DELETED_OK' }} else {{ Write-Output 'DELETE_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("delete_user", machine, f"deleted={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_groups(machine: str) -> str:
        """Lista los grupos locales de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-LocalGroup | "
            "Select-Object Name,Description | "
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

        audit_log("list_groups", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def add_user_to_group(machine: str, username: str, group: str, confirm: bool = False) -> str:
        """Agrega un usuario a un grupo local."""
        require_confirmation(confirm, "add_user_to_group")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(group, "group")
        data = get_machine(machine)

        command = (
            f"Add-LocalGroupMember -Group '{group}' -Member '{username}'; "
            f"if ($?) {{ Write-Output 'MEMBER_ADDED_OK' }} else {{ Write-Output 'ADD_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("add_user_to_group", machine, f"user={username} group={group}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def remove_user_from_group(
        machine: str, username: str, group: str, confirm: bool = False
    ) -> str:
        """Remueve un usuario de un grupo local."""
        require_confirmation(confirm, "remove_user_from_group")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(group, "group")
        data = get_machine(machine)

        command = (
            f"Remove-LocalGroupMember -Group '{group}' -Member '{username}'; "
            f"if ($?) {{ Write-Output 'MEMBER_REMOVED_OK' }} else {{ Write-Output 'REMOVE_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("remove_user_from_group", machine, f"user={username} group={group}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def enable_user(machine: str, username: str) -> str:
        """Habilita una cuenta de usuario local."""
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        command = (
            f"Enable-LocalUser -Name '{username}'; "
            f"if ($?) {{ Write-Output 'USER_ENABLED_OK' }} else {{ Write-Output 'ENABLE_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("enable_user", machine, f"enabled={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def disable_user(machine: str, username: str, confirm: bool = False) -> str:
        """Deshabilita una cuenta de usuario local."""
        require_confirmation(confirm, "disable_user")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        command = (
            f"Disable-LocalUser -Name '{username}'; "
            f"if ($?) {{ Write-Output 'USER_DISABLED_OK' }} else {{ Write-Output 'DISABLE_FAILED' }}"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_user", machine, f"disabled={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
