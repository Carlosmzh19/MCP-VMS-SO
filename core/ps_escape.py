"""
core/ps_escape.py - Escape para literales PowerShell entre comillas simples.

En PowerShell, dentro de '...' la única forma de incluir una comilla
simple es duplicarla (''). Este helper centraliza ese escape para
evitar inyección por interpolación f"'{var}'".
"""


def escape_ps_single_quote(value: str) -> str:
    """
    Duplica las comillas simples para uso seguro en literales PS '...'.

    Args:
        value: Texto a escapar.

    Returns:
        Texto con cada ' reemplazada por ''.
    """
    return str(value).replace("'", "''")
