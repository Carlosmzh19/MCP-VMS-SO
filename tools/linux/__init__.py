"""
tools/linux - Herramientas MCP para VMs Linux (bash/systemd).

Cada módulo expone una función register(mcp_instance) que registra
las variantes Linux con sufijo _linux para evitar colisiones con
las herramientas Windows existentes en tools/*.py.
"""

from .system import register as register_linux_system
from .files import register as register_linux_files
from .services import register as register_linux_services
from .processes import register as register_linux_processes
from .logs import register as register_linux_logs
from .users import register as register_linux_users
from .network import register as register_linux_network
from .security import register as register_linux_security
from .scheduled_tasks import register as register_linux_scheduled_tasks
from .advanced import register as register_linux_advanced
from .identity import register as register_linux_identity
from .samba import register as register_linux_samba
from .netplan import register as register_linux_netplan
from .realm import register as register_linux_realm
from .audit import register as register_linux_audit


def register_linux_tools(mcp_instance) -> None:
    """Registra todas las herramientas Linux con el servidor MCP."""
    register_linux_system(mcp_instance)
    register_linux_files(mcp_instance)
    register_linux_services(mcp_instance)
    register_linux_processes(mcp_instance)
    register_linux_logs(mcp_instance)
    register_linux_users(mcp_instance)
    register_linux_network(mcp_instance)
    register_linux_security(mcp_instance)
    register_linux_scheduled_tasks(mcp_instance)
    register_linux_advanced(mcp_instance)
    register_linux_identity(mcp_instance)
    register_linux_samba(mcp_instance)
    register_linux_netplan(mcp_instance)
    register_linux_realm(mcp_instance)
    register_linux_audit(mcp_instance)
