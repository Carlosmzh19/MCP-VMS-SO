"""
tools/linux/users.py - Gestión de usuarios y grupos Linux.

Usa getent, useradd/userdel, usermod, gpasswd y passwd con sudo -n.
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
    """Registra las herramientas Linux de usuarios con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def list_users_linux(machine: str) -> str:
        """Lista los usuarios locales de la VM Linux (getent passwd)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "getent passwd | awk -F: '{print $1\":\"$3\":\"$6\" \"$7}' | sort"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_users_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_user_linux(
        machine: str, username: str, password: str, confirm: bool = False
    ) -> str:
        """Crea un usuario Linux con home (useradd -m + chpasswd, requiere confirm)."""
        require_confirmation(confirm, "create_user_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(password, "password")
        data = get_machine(machine)

        q_user = shlex.quote(username)
        # La contraseña se pasa por stdin a chpasswd (no queda en historial).
        escaped_pw = password.replace("'", "'\"'\"'")
        command = (
            f"sudo -n useradd -m -s /bin/bash {q_user} && "
            f"echo '{username}:{escaped_pw}' | sudo -n chpasswd && "
            f"echo 'USER_CREATED_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_user_linux", machine, f"created={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def delete_user_linux(machine: str, username: str, confirm: bool = False) -> str:
        """Elimina un usuario Linux y su home (userdel -r, requiere confirm)."""
        require_confirmation(confirm, "delete_user_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        q_user = shlex.quote(username)
        command = f"sudo -n userdel -r {q_user} && echo 'USER_DELETED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("delete_user_linux", machine, f"deleted={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_groups_linux(machine: str) -> str:
        """Lista los grupos locales de la VM Linux (getent group)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "getent group | sort"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_groups_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def add_user_to_group_linux(machine: str, username: str, group: str, confirm: bool = False) -> str:
        """Agrega un usuario Linux a un grupo (usermod -aG, requiere confirm)."""
        require_confirmation(confirm, "add_user_to_group_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(group, "group")
        data = get_machine(machine)

        command = f"sudo -n usermod -aG {shlex.quote(group)} {shlex.quote(username)} && echo 'MEMBER_ADDED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("add_user_to_group_linux", machine, f"user={username} group={group}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def remove_user_from_group_linux(
        machine: str, username: str, group: str, confirm: bool = False
    ) -> str:
        """Remueve un usuario Linux de un grupo (gpasswd -d, requiere confirm)."""
        require_confirmation(confirm, "remove_user_from_group_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        validate_not_empty(group, "group")
        data = get_machine(machine)

        command = f"sudo -n gpasswd -d {shlex.quote(username)} {shlex.quote(group)} && echo 'MEMBER_REMOVED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("remove_user_from_group_linux", machine, f"user={username} group={group}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def enable_user_linux(machine: str, username: str) -> str:
        """Habilita una cuenta de usuario Linux (usermod -U + passwd -u)."""
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        q_user = shlex.quote(username)
        command = f"sudo -n usermod -U {q_user} 2>/dev/null; sudo -n passwd -u {q_user} && echo 'USER_ENABLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("enable_user_linux", machine, f"enabled={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def disable_user_linux(machine: str, username: str, confirm: bool = False) -> str:
        """Deshabilita una cuenta de usuario Linux (usermod -L + passwd -l, requiere confirm)."""
        require_confirmation(confirm, "disable_user_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        data = get_machine(machine)

        q_user = shlex.quote(username)
        command = f"sudo -n usermod -L {q_user} && sudo -n passwd -l {q_user} && echo 'USER_DISABLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_user_linux", machine, f"disabled={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
