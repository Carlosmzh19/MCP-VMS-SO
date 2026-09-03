"""
virtualbox-ssh-mcp: Servidor MCP para administración de VMs Windows via SSH.

Este servidor permite a OpenCode (o cualquier cliente MCP) administrar
VMs Windows ejecutando comandos PowerShell/SSH remotos de forma segura.

Arquitectura:
    OpenCode → MCP stdio → ssh.exe/scp.exe → VM remota

Uso:
    python server.py
"""

import logging
import platform
import sys
from pathlib import Path

# =============================================================================
# CONFIGURACIÓN DE LOGGING
# =============================================================================

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "mcp.log"

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stderr),
    ],
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("virtualbox-ssh-mcp")

# =============================================================================
# IMPORTACIÓN DE COMPONENTES CORE
# =============================================================================

# Asegurar que el directorio del proyecto está en sys.path
PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from core.config import BASE_DIR, MACHINES_FILE, HOST_OS

# =============================================================================
# CREACIÓN DEL SERVIDOR MCP
# =============================================================================

try:
    from fastmcp import FastMCP
except ImportError as e:
    logger.error(
        "No se pudo importar FastMCP (%s). Ejecuta: pip install -r requirements.txt",
        e,
    )
    sys.exit(1)

mcp = FastMCP(
    name="virtualbox-ssh-mcp",
    instructions=(
        "MCP local para administrar VMs Windows mediante SSH. "
        "Permite gestionar usuarios, red, servicios, procesos, archivos, "
        "seguridad, tareas programadas y ejecución remota de comandos."
    ),
)

# =============================================================================
# REGISTRO DE HERRAMIENTAS
# =============================================================================

from tools import register_all_tools

logger.info("Registrando herramientas MCP...")
register_all_tools(mcp)
logger.info("Herramientas registradas correctamente.")

# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Iniciando virtualbox-ssh-mcp...")
    logger.info("Host OS: %s", platform.platform())
    logger.info("Python: %s", sys.version)
    logger.info("Config: %s", MACHINES_FILE)
    logger.info("Logs: %s", LOG_FILE)
    logger.info("=" * 60)

    try:
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario.")
    except Exception as exc:
        logger.exception("Error fatal en el servidor: %s", exc)
        sys.exit(1)
