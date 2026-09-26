"""
tools/workflows - Workflows compuestos idempotentes (FASE 5).

Compone las primitivas de Fases 2-4 (no crea primitivas nuevas): cada
workflow hace preflight test_ssh + snapshot_reminder + steps[] +
evidence + already_exists por paso.

Workflows:
- provision_org (L2): OU raíz + sub-OUs + grupos + usuarios CSV + membresías.
- check_domain_health (L0): PASS/FAIL por capa DC + cliente.
- publish_share (L2): share + NTFS + efectivo + prueba desde cliente.
- collect_evidence (L0): paquete AD/DNS/auditoría/GPO/eventos + download hint.
"""

from .domain_health import register_domain_health
from .evidence import register_collect_evidence
from .provision_org import register_provision_org
from .publish_share import register_publish_share

__all__ = [
    "register_provision_org",
    "register_domain_health",
    "register_publish_share",
    "register_collect_evidence",
    "register_workflows",
]


def register_workflows(mcp_instance) -> None:
    """Registra los cuatro workflows de Fase 5 con el servidor MCP."""
    register_provision_org(mcp_instance)
    register_domain_health(mcp_instance)
    register_publish_share(mcp_instance)
    register_collect_evidence(mcp_instance)
