"""
core/ssh.py - Executor SSH cross-platform.

Detecta el sistema operativo del host y usa los binarios correctos:
- Windows: ssh.exe, scp.exe, ping.exe
- Linux/macOS: ssh, scp, ping
"""

import platform
import shutil
import subprocess
from typing import Any

from .config import (
    SSH_CONNECT_TIMEOUT,
    SSH_TEST_TIMEOUT,
    SSH_PING_TIMEOUT,
    SSH_TIMEOUT_DEFAULT,
    SCP_TIMEOUT,
    IS_WINDOWS,
)


# =============================================================================
# DETECCIÓN DE BINARIOS
# =============================================================================

def _find_binary(name_windows: str, name_unix: str) -> str:
    """Busca el binario correcto según la plataforma."""
    if IS_WINDOWS:
        path = shutil.which(name_windows) or shutil.which(name_unix)
        return path or name_windows
    return name_unix


SSH_BINARY = _find_binary("ssh.exe", "ssh")
SCP_BINARY = _find_binary("scp.exe", "scp")
PING_BINARY = _find_binary("ping.exe", "ping")


# =============================================================================
# CONSTRUCCIÓN DE COMANDOS
# =============================================================================

def build_ssh_args(
    host: str,
    command: str,
    *,
    connect_timeout: int = SSH_CONNECT_TIMEOUT,
    extra_options: dict[str, str] | None = None,
) -> list[str]:
    """
    Construye argumentos para ssh.exe/ssh.

    Args:
        host: Alias SSH o user@hostname.
        command: Comando a ejecutar en la VM remota.
        connect_timeout: Timeout de conexión en segundos.
        extra_options: Opciones SSH adicionales (-o key=value).

    Returns:
        Lista de argumentos para subprocess.run().
    """
    args: list[str] = [
        SSH_BINARY,
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "BatchMode=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    if extra_options:
        for key, value in extra_options.items():
            args.extend(["-o", f"{key}={value}"])
    args.extend([host, command])
    return args


def build_scp_args(
    host: str,
    source: str,
    destination: str,
    *,
    connect_timeout: int = SSH_CONNECT_TIMEOUT,
    direction: str = "upload",
) -> list[str]:
    """
    Construye argumentos para scp.exe/scp.

    Args:
        host: Alias SSH de la máquina destino.
        source: Ruta origen (local en upload, remota en download).
        destination: Ruta destino (remota en upload, local en download).
        connect_timeout: Timeout de conexión.
        direction: "upload" (local -> host:remote) o "download"
            (host:remote -> local).

    Returns:
        Lista de argumentos para subprocess.run().
    """
    if direction not in ("upload", "download"):
        raise ValueError(
            f"direction debe ser 'upload' o 'download', recibido: {direction!r}."
        )
    if direction == "upload":
        remote = destination
        prefix = f"{host}:"
        if remote.startswith(prefix):
            remote_part = remote[len(prefix):]
        else:
            remote_part = remote
        return [
            SCP_BINARY,
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "BatchMode=yes",
            source,
            f"{host}:{remote_part}",
        ]
    # download: source es remoto, destination es local.
    remote = source
    prefix = f"{host}:"
    if remote.startswith(prefix):
        remote_part = remote[len(prefix):]
    else:
        remote_part = remote
    return [
        SCP_BINARY,
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "BatchMode=yes",
        f"{host}:{remote_part}",
        destination,
    ]


def build_ping_args(hostname: str) -> list[str]:
    """
    Construye argumentos para ping.

    Args:
        hostname: IP o hostname a hacer ping.

    Returns:
        Lista de argumentos para subprocess.run().
    """
    if IS_WINDOWS:
        return [PING_BINARY, "-n", "1", hostname]
    return [PING_BINARY, "-c", "1", hostname]


def scp_destination(host: str, remote_path: str) -> str:
    """Construye el destino SCP (host:path)."""
    return f"{host}:{remote_path}"


# =============================================================================
# EJECUCIÓN DE PROCESOS
# =============================================================================

def run_process(
    args: list[str],
    timeout: int = SSH_TIMEOUT_DEFAULT,
) -> dict[str, Any]:
    """
    Ejecuta un proceso externo con timeout y captura de salida.

    Args:
        args: Argumentos del comando.
        timeout: Timeout en segundos.

    Returns:
        Diccionario con ok, return_code, stdout, stderr, command.
    """
    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "command": args,
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "return_code": -1,
            "stdout": exc.stdout or "",
            "stderr": (
                (exc.stderr or "")
                + f"\nProceso excedió el timeout de {timeout} segundos."
            ),
            "command": args,
            "timeout": True,
        }

    except FileNotFoundError as exc:
        return {
            "ok": False,
            "return_code": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": args,
            "error": "Ejecutable no encontrado. Verifica PATH.",
        }

    except Exception as exc:
        return {
            "ok": False,
            "return_code": -1,
            "stdout": "",
            "stderr": str(exc),
            "command": args,
            "error": type(exc).__name__,
        }


# =============================================================================
# DIAGNÓSTICO DE ERRORES SSH
# =============================================================================

SSH_ERROR_PATTERNS: dict[str, str] = {
    "Connection refused": "El host remoto está apagado o el servicio SSH no está ejecutándose.",
    "Connection closed by remote": "El host remoto cerró la conexión.",
    "No route to host": "Red inalcanzable. Verifica estado de la VM y red de VirtualBox.",
    "Permission denied": "Autenticación SSH fallida. Verifica la clave en authorized_keys.",
    "Host key verification failed": "La clave del host cambió. Elimina la clave antigua de known_hosts.",
    "Connection timed out": "No se puede alcanzar el host. Verifica IP, firewall y puerto SSH.",
    "No such host": "Resolución DNS fallida. Verifica hostname en la config SSH.",
    "ssh: connect to host": "Conexión fallida. Verifica que el host sea accesible.",
    "sudo: a password is required": "El comando requiere sudo sin contraseña. Configura NOPASSWD en sudoers.",
    "is not in the sudoers file": "El usuario no tiene permisos sudo. Agrégalo al grupo sudo o a sudoers.",
    "command not found": "Comando no encontrado en la VM. Verifica que esté instalado y en el PATH.",
}


def diagnose_ssh_error(stderr: str, return_code: int) -> str | None:
    """
    Analiza el stderr de SSH para errores conocidos.

    Args:
        stderr: Salida de error del proceso SSH.
        return_code: Código de retorno del proceso.

    Returns:
        Mensaje descriptivo del error o None si no se reconoce.
    """
    if not stderr:
        if return_code == 255:
            return "Error SSH genérico (código 255). Verifica conectividad y configuración."
        return None

    stderr_lower = stderr.lower()
    for pattern, hint in SSH_ERROR_PATTERNS.items():
        if pattern.lower() in stderr_lower:
            return hint

    if return_code == 255:
        return "Error SSH genérico (código 255). Verifica conectividad y configuración."

    return None


# =============================================================================
# UTILIDADES DE LIMPIEZA
# =============================================================================

def needs_sudo(os_type: str, requires_privilege: bool) -> bool:
    """
    Determina si un comando necesita prefijo sudo.

    Args:
        os_type: Tipo de SO ('windows' o 'linux').
        requires_privilege: True si el comando requiere privilegios.

    Returns:
        True solo cuando el SO es linux y se requieren privilegios.
    """
    if not requires_privilege:
        return False
    if not os_type:
        return False
    return str(os_type).strip().lower() == "linux"


def wrap_sudo(command: str, os_type: str, requires_privilege: bool) -> str:
    """
    Antepone 'sudo -n' al comando cuando corresponde.

    Args:
        command: Comando original a ejecutar.
        os_type: Tipo de SO ('windows' o 'linux').
        requires_privilege: True si el comando requiere privilegios.

    Returns:
        Comando con 'sudo -n ' antepuesto solo para linux+privilegiado,
        sin cambios en cualquier otro caso.
    """
    if needs_sudo(os_type, requires_privilege):
        return f"sudo -n {command}"
    return command


def clean_output(
    result: dict[str, Any],
    max_chars: int = 10000,
) -> dict[str, Any]:
    """
    Limita el tamaño de stdout y stderr en el resultado.

    Args:
        result: Diccionario resultado de run_process().
        max_chars: Máximo de caracteres por campo.

    Returns:
        Diccionario con salida limitada.
    """
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    result["stdout"] = stdout[-max_chars:] if len(stdout) > max_chars else stdout
    result["stderr"] = stderr[-max_chars:] if len(stderr) > max_chars else stderr
    return result
