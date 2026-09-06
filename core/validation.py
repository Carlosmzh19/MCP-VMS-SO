"""
core/validation.py - Utilidades de validación reutilizables.

Funciones para validar parámetros de entrada de las herramientas MCP.
"""

from .config import SSH_MAX_TIMEOUT, MAX_EVENT_LOG_LINES, DESTRUCTIVE_TOOLS


def validate_not_empty(value: str, field_name: str) -> None:
    """
    Valida que un campo de texto no esté vacío.

    Args:
        value: Valor a validar.
        field_name: Nombre del campo (para el mensaje de error).

    Raises:
        ValueError: Si el valor está vacío o es solo espacios.
    """
    if not value or not value.strip():
        raise ValueError(f"{field_name} no puede estar vacío.")


def validate_timeout(timeout: int) -> None:
    """
    Valida que el timeout esté en el rango permitido.

    Args:
        timeout: Valor de timeout a validar.

    Raises:
        ValueError: Si el timeout está fuera de rango.
    """
    if timeout < 1 or timeout > SSH_MAX_TIMEOUT:
        raise ValueError(
            f"timeout_seconds debe estar entre 1 y {SSH_MAX_TIMEOUT}."
        )


def validate_lines(lines: int) -> None:
    """
    Valida que el número de líneas esté en el rango permitido.

    Args:
        lines: Número de líneas a validar.

    Raises:
        ValueError: Si lines está fuera de rango.
    """
    if lines < 1 or lines > MAX_EVENT_LOG_LINES:
        raise ValueError(
            f"lines debe estar entre 1 y {MAX_EVENT_LOG_LINES}."
        )


def validate_max_chars(max_chars: int) -> None:
    """
    Valida que max_chars esté en el rango permitido.

    Args:
        max_chars: Valor a validar.

    Raises:
        ValueError: Si max_chars está fuera de rango.
    """
    if max_chars < 1 or max_chars > 100000:
        raise ValueError("max_chars debe estar entre 1 y 100000.")


def require_confirmation(confirm: bool, tool_name: str) -> None:
    """
    Requiere que confirm sea True para herramientas destructivas.

    Args:
        confirm: Valor del parámetro confirm.
        tool_name: Nombre de la herramienta (para el mensaje de error).

    Raises:
        ValueError: Si confirm es False.
    """
    if not confirm:
        raise ValueError(
            f"La herramienta '{tool_name}' es potencialmente destructiva. "
            f"Debes pasar confirm=true para ejecutarla."
        )


def is_destructive(tool_name: str) -> bool:
    """
    Verifica si una herramienta está en la lista de destructivas.

    Args:
        tool_name: Nombre de la herramienta.

    Returns:
        True si la herramienta es destructiva.
    """
    return tool_name in DESTRUCTIVE_TOOLS


def validate_os_supported(os_type: str) -> None:
    """
    Valida que el tipo de SO sea soportado.

    Args:
        os_type: Tipo de SO a validar ('windows' o 'linux').

    Raises:
        ValueError: Si el SO no es windows ni linux.
    """
    if not os_type or str(os_type).strip().lower() not in ("windows", "linux"):
        raise ValueError(
            f"os_type no soportado: {os_type!r}. "
            "Valores válidos: windows, linux."
        )


def validate_linux_path(path: str) -> None:
    """
    Valida que una ruta sea una ruta Linux absoluta válida.

    Args:
        path: Ruta a validar.

    Raises:
        ValueError: Si la ruta está vacía, no empieza con /
            o tiene estilo Windows (ej. C:\\ o C:/).
    """
    if not path or not str(path).strip():
        raise ValueError("path no puede estar vacío.")
    text = str(path).strip()
    if len(text) >= 2 and text[1] == ":":
        raise ValueError(
            f"Ruta no válida en Linux: {path!r}. "
            "Las rutas Windows (ej. C:\\...) no están permitidas."
        )
    if "\\" in text:
        raise ValueError(
            f"Ruta no válida en Linux: {path!r}. Usa '/' como separador."
        )
    if not text.startswith("/"):
        raise ValueError(
            f"Ruta no válida en Linux: {path!r}. "
            "Debe ser absoluta y empezar con '/'."
        )
