"""
tools/windows - Herramientas MCP Windows Server (FASE 2: AD/DNS/File/Auditoría).

Cada módulo expone su función register_* (nombres del plan Fase 2) y este
paquete las agrega en register_windows_tools sin tocar los 11 register
existentes de tools/*.py.
"""

from .ad_forest import register_ad_forest
from .ad_org import register_ad_org
from .audit_gpo import register_audit_gpo
from .dns import register_dns
from .fileserver import register_fileserver

__all__ = [
    "register_ad_forest",
    "register_ad_org",
    "register_dns",
    "register_fileserver",
    "register_audit_gpo",
    "register_windows_tools",
]


def register_windows_tools(mcp_instance) -> None:
    """Registra todas las herramientas Windows Server (Fase 2) con el MCP."""
    register_ad_forest(mcp_instance)
    register_ad_org(mcp_instance)
    register_dns(mcp_instance)
    register_fileserver(mcp_instance)
    register_audit_gpo(mcp_instance)
