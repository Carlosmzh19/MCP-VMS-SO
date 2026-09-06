"""
tools/common - Utilidades compartidas para herramientas MCP.

Provee el helper audit_log usado por los módulos Windows y Linux.
"""

import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def audit_log(tool: str, machine: str, detail: str) -> None:
    """Registra una acción de auditoría."""
    timestamp = datetime.now().isoformat()
    logger.info("AUDIT: %s | %s | %s | %s", timestamp, tool, machine, detail)
