"""
core/audit.py - Auditoría centralizada del MCP.

Único punto de `audit_log(tool, machine, detail)` para todo el proyecto.
Sanitiza secretos antes de loguear: password_b64/password/safe_mode/
credential/secret nunca llegan a logs/mcp.log ni al JSON de retorno.

El RotatingFileHandler vive en server.py (no aquí).
"""

import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

# Claves sensibles: cualquier "clave=valor" con estas claves se redacta.
_SENSITIVE_PATTERN = re.compile(
    r"(?i)(password_b64|password|safe_mode\w*|safemode\w*|credential|secret)"
    r"(\s*[:=]\s*)(\S+)"
)


def sanitize_detail(detail: str) -> str:
    """
    Reemplaza valores de secretos en el texto de auditoría por ***.

    Args:
        detail: Texto libre de detalle (resumen sin secretos idealmente).

    Returns:
        Texto con los valores sensibles redactados.
    """
    if not detail:
        return detail
    return _SENSITIVE_PATTERN.sub(r"\1\2***", str(detail))


def audit_log(tool: str, machine: str, detail: str) -> None:
    """
    Registra una acción de auditoría (secreto-sanitisada).

    Firma idéntica a la histórica de tools/*.py para refactor mecánico.

    Args:
        tool: Nombre de la herramienta.
        machine: Nombre de la máquina objetivo.
        detail: Resumen sin secretos (ou_dn, sam, share, ip nueva,
            dry_run/L2-ACK). Cualquier secreto residual se redacta.
    """
    timestamp = datetime.now().isoformat()
    logger.info(
        "AUDIT: %s | %s | %s | %s",
        timestamp,
        tool,
        machine,
        sanitize_detail(detail),
    )
