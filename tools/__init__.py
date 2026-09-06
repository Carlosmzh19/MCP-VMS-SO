"""
tools - Paquete de herramientas MCP.

Cada módulo contiene herramientas para una categoría específica.
Todos los módulos exponen una función register(mcp_instance) que
registra las herramientas con el servidor MCP.
"""

from .connectivity import register as register_connectivity
from .users import register as register_users
from .network import register as register_network
from .services import register as register_services
from .processes import register as register_processes
from .system import register as register_system
from .logs import register as register_logs
from .files import register as register_files
from .security import register as register_security
from .scheduled_tasks import register as register_scheduled_tasks
from .advanced import register as register_advanced
from .linux import register_linux_tools


def register_all_tools(mcp_instance) -> None:
    """
    Registra todas las herramientas con el servidor MCP.

    Args:
        mcp_instance: Instancia del servidor MCP (FastMCP).
    """
    register_connectivity(mcp_instance)
    register_users(mcp_instance)
    register_network(mcp_instance)
    register_services(mcp_instance)
    register_processes(mcp_instance)
    register_system(mcp_instance)
    register_logs(mcp_instance)
    register_files(mcp_instance)
    register_security(mcp_instance)
    register_scheduled_tasks(mcp_instance)
    register_advanced(mcp_instance)
    # Herramientas Linux con sufijo _linux (sin colisión con Windows).
    register_linux_tools(mcp_instance)
