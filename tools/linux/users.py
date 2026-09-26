"""
tools/linux/users.py - Gestión de usuarios y grupos Linux.

Usa getent, useradd/userdel, usermod, gpasswd y passwd con sudo -n.
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


def _redact_secrets(result: dict, *secrets: str) -> dict:
    """Reemplaza secretos en command/stdout/stderr por *** (no loguear claves)."""
    redacted_cmd = []
    for part in result.get("command", []):
        text = str(part)
        for s in secrets:
            if s:
                text = text.replace(s, "***")
        redacted_cmd.append(text)
    result["command"] = ["REDACTED"] if any("***" in c for c in redacted_cmd) else redacted_cmd
    for key in ("stdout", "stderr"):
        text = str(result.get(key, ""))
        for s in secrets:
            if s:
                text = text.replace(s, "***")
        result[key] = text
    return result


from core.audit import audit_log


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
        machine: str, username: str, password: str = "", confirm: bool = False,
        password_b64: str = "",
    ) -> str:
        """Crea un usuario Linux con home (useradd -m + chpasswd, requiere confirm)."""
        require_confirmation(confirm, "create_user_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(username, "username")
        if password_b64:
            validate_not_empty(password_b64, "password_b64")
            try:
                base64.b64decode(password_b64.strip(), validate=True)
            except Exception:
                raise ValueError("password_b64 no es base64 válido.")
        elif password:
            validate_not_empty(password, "password")
        else:
            raise ValueError("Debe aportar 'password' o 'password_b64'.")
        data = get_machine(machine)

        q_user = shlex.quote(username)
        if password_b64:
            b64 = password_b64.strip()
            q_b64 = shlex.quote(b64)
            # b64 -> claro solo en tubería remota, nunca en argv/ps en claro.
            command = (
                f"sudo -n /usr/sbin/useradd -m -s /bin/bash {q_user} && "
                f"(printf '%s:' {q_user}; echo {q_b64} | base64 -d) | sudo -n /usr/sbin/chpasswd && "
                f"echo 'USER_CREATED_OK'"
            )
            secrets = (b64,)
        else:
            # Compat: contraseña en claro solo en tubería a chpasswd.
            escaped_pw = password.replace("'", "'\"'\"'")
            command = (
                f"sudo -n /usr/sbin/useradd -m -s /bin/bash {q_user} && "
                f"echo '{username}:{escaped_pw}' | sudo -n /usr/sbin/chpasswd && "
                f"echo 'USER_CREATED_OK'"
            )
            secrets = (password,)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )
        _redact_secrets(result, *secrets)

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
        command = f"sudo -n /usr/sbin/userdel -r {q_user} && echo 'USER_DELETED_OK'"

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

        command = f"sudo -n /usr/sbin/usermod -aG {shlex.quote(group)} {shlex.quote(username)} && echo 'MEMBER_ADDED_OK'"

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

        command = f"sudo -n /usr/bin/gpasswd -d {shlex.quote(username)} {shlex.quote(group)} && echo 'MEMBER_REMOVED_OK'"

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
        command = f"sudo -n /usr/sbin/usermod -U {q_user} 2>/dev/null; sudo -n /usr/bin/passwd -u {q_user} && echo 'USER_ENABLED_OK'"

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
        command = f"sudo -n /usr/sbin/usermod -L {q_user} && sudo -n /usr/bin/passwd -l {q_user} && echo 'USER_DISABLED_OK'"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("disable_user_linux", machine, f"disabled={username}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
