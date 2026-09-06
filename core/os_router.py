"""
core/os_router.py - Enrutamiento por sistema operativo.

Determina el SO de cada máquina (windows|linux) y ayuda a
enrutar la ejecución hacia la implementación correcta.
"""

import logging
from collections.abc import Callable
from typing import Any

from .config import get_machine

logger = logging.getLogger(__name__)

SUPPORTED_OS = frozenset({"windows", "linux"})


def get_os_type(machine: str) -> str:
    """
    Obtiene el tipo de SO de una máquina.

    Args:
        machine: Nombre de la máquina configurada.

    Returns:
        'windows' o 'linux' normalizado en minúsculas.

    Raises:
        ValueError: Si la máquina es desconocida o su SO no es válido.
    """
    data = get_machine(machine)
    os_type = data.get("os")
    if not os_type or not str(os_type).strip():
        raise ValueError(
            f"La máquina '{machine}' no tiene el campo 'os' configurado."
        )
    normalized = str(os_type).strip().lower()
    if normalized not in SUPPORTED_OS:
        raise ValueError(
            f"SO no soportado para la máquina '{machine}': {os_type!r}. "
            "Valores válidos: windows, linux."
        )
    return normalized


def require_os(machine: str, expected: str) -> dict[str, Any]:
    """
    Verifica que una máquina tenga el SO esperado.

    Args:
        machine: Nombre de la máquina configurada.
        expected: SO esperado ('windows' o 'linux').

    Returns:
        Diccionario con la configuración de la máquina.

    Raises:
        ValueError: Si el SO no coincide o no es válido.
    """
    expected_norm = str(expected).strip().lower() if expected else ""
    if expected_norm not in SUPPORTED_OS:
        raise ValueError(
            f"SO esperado no válido: {expected!r}. "
            "Valores válidos: windows, linux."
        )
    data = get_machine(machine)
    actual = get_os_type(machine)
    if actual != expected_norm:
        raise ValueError(
            f"La máquina '{machine}' es '{actual}' "
            f"pero la herramienta requiere '{expected_norm}'."
        )
    logger.debug("require_os ok: %s es %s", machine, actual)
    return data


def dispatch(
    machine: str,
    windows_fn: Callable[..., Any] | None = None,
    linux_fn: Callable[..., Any] | None = None,
    *args: Any,
    handlers: dict[str, Callable[..., Any]] | None = None,
    **kwargs: Any,
) -> Any:
    """
    Enruta una llamada a la implementación según el SO de la máquina.

    Args:
        machine: Nombre de la máquina configurada.
        windows_fn: Función a ejecutar si la máquina es windows.
        linux_fn: Función a ejecutar si la máquina es linux.
        *args: Argumentos posicionales para la función elegida.
        handlers: Diccionario alternativo {'windows': fn, 'linux': fn}.
        **kwargs: Argumentos de palabra clave para la función elegida.

    Returns:
        El retorno de la función elegida.

    Raises:
        ValueError: Si el SO no es válido o falta el handler correspondiente.
    """
    os_type = get_os_type(machine)
    table: dict[str, Callable[..., Any] | None] = {
        "windows": windows_fn,
        "linux": linux_fn,
    }
    if handlers:
        table.update(handlers)
    fn = table.get(os_type)
    if fn is None:
        raise ValueError(
            f"No hay implementación para SO '{os_type}' "
            f"en la máquina '{machine}'."
        )
    logger.debug("dispatch: %s -> %s", machine, os_type)
    return fn(*args, **kwargs)


# Alias para compatibilidad.
dispatch_os = dispatch
