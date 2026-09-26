"""
tools/linux/files.py - Operaciones de archivos en Linux.

Usa cat, ls, base64 + sudo -n tee (mismo patrón que tools/files.py:92)
y SCP sin cambios. Default /home/carlos en listados.
"""

import base64
import json
import logging
import shlex
from datetime import datetime
from pathlib import Path

from core.config import get_machine, SCP_TIMEOUT
from core.ssh import (
    build_ssh_args,
    build_scp_args,
    scp_destination,
    run_process,
    clean_output,
)
from core.validation import validate_not_empty, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas Linux de archivos con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def read_file_linux(machine: str, remote_path: str, max_chars: int = 20000) -> str:
        """Lee un archivo de texto de la VM Linux (cat, sudo -n cat para /etc/*)."""
        validate_not_empty(machine, "machine")
        validate_not_empty(remote_path, "remote_path")
        data = get_machine(machine)

        q_path = shlex.quote(remote_path)
        if remote_path.startswith("/etc/"):
            command = f"sudo -n cat -- {q_path} 2>/dev/null || cat -- {q_path}"
        else:
            command = f"cat -- {q_path}"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("read_file_linux", machine, f"path={remote_path}")
        return json.dumps(
            clean_output(result, max_chars),
            ensure_ascii=False,
            indent=2,
        )

    @mcp.tool()
    def write_file_linux(machine: str, remote_path: str, content: str, confirm: bool = False) -> str:
        """
        Escribe un archivo de texto en la VM Linux.
        El contenido se codifica en base64 (patrón tools/files.py:92 con sudo -n tee).
        """
        require_confirmation(confirm, "write_file_linux")
        validate_not_empty(machine, "machine")
        validate_not_empty(remote_path, "remote_path")
        data = get_machine(machine)

        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
        q_path = shlex.quote(remote_path)
        command = (
            f"echo '{encoded}' | base64 -d | "
            f"sudo -n tee -- {q_path} > /dev/null && echo 'FILE_WRITTEN_OK'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("write_file_linux", machine, f"path={remote_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def upload_file_linux(machine: str, local_path: str, remote_path: str) -> str:
        """Sube un archivo desde el host hacia la VM Linux mediante SCP."""
        validate_not_empty(machine, "machine")
        validate_not_empty(local_path, "local_path")
        validate_not_empty(remote_path, "remote_path")
        data = get_machine(machine)

        local = Path(local_path).expanduser().resolve()
        if not local.exists():
            raise FileNotFoundError(f"No existe: {local}")
        if not local.is_file():
            raise ValueError(f"No es un archivo: {local}")

        host = data["ssh_host"]
        destination = scp_destination(host, remote_path)
        args = build_scp_args(host, str(local), remote_path, direction="upload")

        result = run_process(args, timeout=SCP_TIMEOUT)

        audit_log("upload_file_linux", machine, f"local={local_path} remote={remote_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def download_file_linux(machine: str, remote_path: str, local_path: str) -> str:
        """Descarga un archivo desde la VM Linux hacia el host mediante SCP."""
        validate_not_empty(machine, "machine")
        validate_not_empty(remote_path, "remote_path")
        validate_not_empty(local_path, "local_path")
        data = get_machine(machine)

        target = Path(local_path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)

        host = data["ssh_host"]
        source = scp_destination(host, remote_path)
        args = build_scp_args(host, remote_path, str(target), direction="download")

        result = run_process(args, timeout=SCP_TIMEOUT)

        audit_log("download_file_linux", machine, f"remote={remote_path} local={local_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_directory_linux(machine: str, remote_path: str = "/home/carlos") -> str:
        """Lista el contenido de un directorio remoto Linux (ls -la)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        q_path = shlex.quote(remote_path)
        command = f"ls -la -- {q_path}"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("list_directory_linux", machine, f"path={remote_path}")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)
