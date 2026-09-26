"""
tools/security.py - Herramientas de seguridad.

Proporciona herramientas para gestionar políticas de contraseñas
y carpetas compartidas en VMs Windows.
"""

import json
import logging
from datetime import datetime

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas de seguridad con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_password_policy(machine: str) -> str:
        """Obtiene la política de contraseñas de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = "net accounts"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_password_policy", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_password_policy(
        machine: str,
        min_pw_length: int = 0,
        max_pw_age: int = 0,
        min_pw_age: int = 0,
        unique_pw_count: int = 0,
        confirm: bool = False,
    ) -> str:
        """
        Cambia la política de contraseñas.
        Usa 0 para no cambiar un parámetro.
        """
        require_confirmation(confirm, "set_password_policy")
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        parts = ["net accounts"]
        if min_pw_length > 0:
            parts.append(f"/MINPWLEN:{min_pw_length}")
        if max_pw_age > 0:
            parts.append(f"/MAXPWAGE:{max_pw_age}")
        if min_pw_age > 0:
            parts.append(f"/MINPWAGE:{min_pw_age}")
        if unique_pw_count > 0:
            parts.append(f"/UNIQUEPW:{unique_pw_count}")

        command = " ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("set_password_policy", machine, f"command={command}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_shared_folders(machine: str) -> str:
        """Lista las carpetas compartidas de la VM."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "Get-SmbShare | "
            "Select-Object Name,Path,Description,CurrentUsers | "
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

        audit_log("list_shared_folders", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def create_shared_folder(
        machine: str,
        name: str,
        path: str,
        description: str = "",
        confirm: bool = False,
    ) -> str:
        """Crea una carpeta compartida en la VM."""
        require_confirmation(confirm, "create_shared_folder")
        validate_not_empty(machine, "machine")
        validate_not_empty(name, "name")
        validate_not_empty(path, "path")
        data = get_machine(machine)

        escaped_desc = description.replace("'", "''")

        command = (
            f"New-SmbShare -Name '{name}' -Path '{path}' "
            f"-Description '{escaped_desc}' -ReadAccess Everyone; "
            f"Write-Output 'SHARE_CREATED_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("create_shared_folder", machine, f"name={name} path={path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
