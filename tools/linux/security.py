"""
tools/linux/security.py - Seguridad Linux.

Política de contraseñas vía chage/login.defs, carpetas compartidas
vía configuración Samba y firewall vía ufw.
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
    """Registra las herramientas Linux de seguridad con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_password_policy_linux(machine: str) -> str:
        """Obtiene la política de contraseñas Linux (login.defs + chage)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- LOGIN.DEFS ---'; grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs; "
            "echo '--- CHAGE (root) ---'; sudo -n /usr/bin/chage -l root 2>/dev/null || chage -l $(whoami)"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_password_policy_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_password_policy_linux(
        machine: str,
        min_pw_length: int = 0,
        max_pw_age: int = 0,
        min_pw_age: int = 0,
        unique_pw_count: int = 0,
        confirm: bool = False,
    ) -> str:
        """
        Cambia la política de contraseñas Linux (chage/login.defs, requiere confirm).
        Usa 0 para no cambiar un parámetro.
        """
        require_confirmation(confirm, "set_password_policy_linux")
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        parts = []
        if max_pw_age > 0:
            parts.append(f"sudo -n /usr/bin/chage -M {int(max_pw_age)} $(whoami)")
        if min_pw_age > 0:
            parts.append(f"sudo -n /usr/bin/chage -m {int(min_pw_age)} $(whoami)")
        if min_pw_length > 0:
            parts.append(
                f"sudo -n /bin/sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN {int(min_pw_length)}/' /etc/login.defs"
            )
        if unique_pw_count > 0:
            parts.append(
                f"grep -q 'remember=' /etc/pam.d/common-password 2>/dev/null && "
                f"sudo -n /bin/sed -i 's/remember=[0-9]*/remember={int(unique_pw_count)}/' /etc/pam.d/common-password || "
                f"echo 'UNIQUE_PW_REQUIRES_MANUAL_PAM_EDIT'"
            )
        if not parts:
            parts.append("echo 'NO_CHANGES_REQUESTED'")
        else:
            parts.append("echo 'PASSWORD_POLICY_UPDATED_OK'")
        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_password_policy_linux", machine, f"max={max_pw_age} min_len={min_pw_length}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_shared_folders_linux(machine: str) -> str:
        """Lista carpetas compartidas Samba en Linux (smb.conf + smbstatus)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- SMB.CONF SHARES ---'; grep -E '^\\[.*\\]' /etc/samba/smb.conf 2>/dev/null || echo 'NO_SAMBA_CONFIG'; "
            "echo '--- SMBSTATUS ---'; smbstatus --shares 2>/dev/null || echo 'SMBSTATUS_UNAVAILABLE'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_shared_folders_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_firewall_status_linux(machine: str) -> str:
        """Obtiene el estado del firewall Linux (ufw status)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "sudo -n ufw status verbose 2>/dev/null || sudo -n iptables -L -n"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_firewall_status_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_shared_folder_linux(
        machine: str, name: str, path: str, description: str = "", confirm: bool = False
    ) -> str:
        """Crea una carpeta compartida Samba en Linux (requiere confirm)."""
        require_confirmation(confirm, "create_shared_folder_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        validate_not_empty(path, "path")
        data = get_machine(machine)

        q_path = shlex.quote(path)
        q_name = shlex.quote(f"[{name}]")
        q_comment = shlex.quote(description or name)
        command = (
            f"sudo -n mkdir -p {q_path} && "
            f"{{ echo {q_name}; echo '   path = {path}'; echo '   comment = {description or name}'; "
            f"echo '   browseable = yes'; echo '   read only = no'; }} | "
            f"sudo -n tee -a /etc/samba/smb.conf > /dev/null && echo 'SHARE_CREATED_OK'"
        )
        _ = (q_comment,)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_shared_folder_linux", machine, f"name={name} path={path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
