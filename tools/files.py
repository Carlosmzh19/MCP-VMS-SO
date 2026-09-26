"""
tools/files.py - Operaciones de archivos.

Proporciona herramientas para leer, escribir, subir, descargar
y listar archivos/directorios en VMs remotas.
"""

import base64
import json
import logging
from datetime import datetime
from pathlib import Path

from core.config import get_machine, IS_WINDOWS
from core.ssh import (
    build_ssh_args,
    build_scp_args,
    scp_destination,
    run_process,
    clean_output,
    SCP_TIMEOUT,
)
from core.validation import validate_not_empty, require_confirmation

mcp = None

logger = logging.getLogger(__name__)


from core.audit import audit_log


def register(mcp_instance):
    """Registra las herramientas de archivos con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def read_file(machine: str, remote_path: str, max_chars: int = 20000) -> str:
        """Lee un archivo de texto de la VM."""
        validate_not_empty(machine, "machine")
        validate_not_empty(remote_path, "remote_path")
        data = get_machine(machine)
        os_type = data.get("os", "unknown")

        if os_type == "windows":
            command = f"Get-Content -Raw -LiteralPath '{remote_path}'"
        elif os_type == "linux":
            command = f"cat -- '{remote_path}'"
        else:
            raise ValueError(f"OS no soportado: {os_type}")

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("read_file", machine, f"path={remote_path}")
        return json.dumps(
            clean_output(result, max_chars),
            ensure_ascii=False,
            indent=2,
        )

    @mcp.tool()
    def write_file(machine: str, remote_path: str, content: str, confirm: bool = False) -> str:
        """
        Escribe un archivo de texto en la VM.
        El contenido se codifica en base64 para evitar problemas de comillas.
        """
        require_confirmation(confirm, "write_file")
        validate_not_empty(machine, "machine")
        validate_not_empty(remote_path, "remote_path")
        data = get_machine(machine)
        os_type = data.get("os", "unknown")

        encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")

        if os_type == "windows":
            command = (
                f"$b64='{encoded}'; "
                f"$bytes=[Convert]::FromBase64String($b64); "
                f"$text=[Text.Encoding]::UTF8.GetString($bytes); "
                f"Set-Content -LiteralPath '{remote_path}' "
                f"-Value $text -Encoding UTF8; "
                f"Write-Output 'FILE_WRITTEN_OK'"
            )
        elif os_type == "linux":
            command = (
                f"echo '{encoded}' | base64 -d | "
                f"sudo tee -- '{remote_path}' > /dev/null"
            )
        else:
            raise ValueError(f"OS no soportado: {os_type}")

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("write_file", machine, f"path={remote_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def upload_file(machine: str, local_path: str, remote_path: str) -> str:
        """Sube un archivo desde el host hacia la VM mediante SCP."""
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

        audit_log("upload_file", machine, f"local={local_path} remote={remote_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def download_file(machine: str, remote_path: str, local_path: str) -> str:
        """Descarga un archivo desde la VM hacia el host mediante SCP."""
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

        audit_log("download_file", machine, f"remote={remote_path} local={local_path}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def list_directory(machine: str, remote_path: str = "C:\\") -> str:
        """Lista el contenido de un directorio remoto."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        os_type = data.get("os", "unknown")

        if os_type == "windows":
            command = (
                f"Get-ChildItem -LiteralPath '{remote_path}' | "
                f"Select-Object Name,Length,LastWriteTime,Mode | "
                f"ConvertTo-Json -Compress"
            )
        elif os_type == "linux":
            command = f"ls -la '{remote_path}'"
        else:
            raise ValueError(f"OS no soportado: {os_type}")

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        if os_type == "windows" and result["ok"] and result["stdout"].strip():
            try:
                parsed = json.loads(result["stdout"])
                if isinstance(parsed, dict):
                    result["stdout"] = json.dumps([parsed], ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                pass

        audit_log("list_directory", machine, f"path={remote_path}")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)
