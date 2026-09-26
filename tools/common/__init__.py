"""
tools/common - Utilidades compartidas para herramientas MCP.

Re-exporta audit_log centralizado (core/audit.py, Fase 1) para
compatibilidad con importadores históricos de tools.common.
"""

from core.audit import audit_log, sanitize_detail

__all__ = ["audit_log", "sanitize_detail"]
