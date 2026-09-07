"""
core/config.py - Configuración centralizada del MCP.

Carga machines.json, define constantes y proporciona utilidades de configuración.
"""

import json
import platform
from pathlib import Path
from typing import Any


# =============================================================================
# RUTAS BASE
# =============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"
MACHINES_FILE = CONFIG_DIR / "machines.json"

# Asegurar que los directorios existen
LOG_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# DETECCIÓN DE PLATAFORMA
# =============================================================================

HOST_OS = platform.system()  # "Windows", "Linux", "Darwin"
IS_WINDOWS = HOST_OS == "Windows"
IS_LINUX = HOST_OS == "Linux"


# =============================================================================
# TIMEOUTS
# =============================================================================

SSH_TIMEOUT_DEFAULT = 60
SSH_CONNECT_TIMEOUT = 10
SSH_MAX_TIMEOUT = 600
SSH_TEST_TIMEOUT = 20
SSH_PING_TIMEOUT = 10
SCP_TIMEOUT = 120


# =============================================================================
# LÍMITES DE SALIDA
# =============================================================================

MAX_OUTPUT_CHARS = 10000
MAX_LOG_CHARS = 30000
MAX_EVENT_LOG_CHARS = 50000
MAX_EVENT_LOG_LINES = 1000


# =============================================================================
# HERRAMIENTAS DESTRUCTIVAS (Fase 1: viven en core/constants.py)
# =============================================================================

# Re-export para compatibilidad Fase 0 (core/validation.py y tests).
from .constants import DESTRUCTIVE_TOOLS  # noqa: F401


# =============================================================================
# CARGA DE CONFIGURACIÓN
# =============================================================================

def load_machines_config() -> dict[str, Any]:
    """Carga el archivo machines.json."""
    if not MACHINES_FILE.exists():
        raise FileNotFoundError(
            f"Archivo de configuración no encontrado: {MACHINES_FILE}"
        )
    with MACHINES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_machines() -> dict[str, Any]:
    """Obtiene el diccionario de máquinas configuradas."""
    config = load_machines_config()
    machines = config.get("machines", {})
    if not isinstance(machines, dict) or not machines:
        raise RuntimeError("No hay máquinas configuradas en machines.json")
    return machines


def get_machine(machine: str) -> dict[str, Any]:
    """Obtiene la configuración de una máquina específica."""
    machines = get_machines()
    if machine not in machines:
        available = ", ".join(sorted(machines.keys()))
        raise ValueError(
            f"Máquina desconocida: {machine}. Disponibles: {available}"
        )
    return machines[machine]
