"""
tests/test_config.py - Tests para core.config.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from core.config import (
    BASE_DIR,
    CONFIG_DIR,
    LOG_DIR,
    MACHINES_FILE,
    HOST_OS,
    IS_WINDOWS,
    IS_LINUX,
    SSH_TIMEOUT_DEFAULT,
    SSH_CONNECT_TIMEOUT,
    SSH_MAX_TIMEOUT,
    MAX_OUTPUT_CHARS,
    DESTRUCTIVE_TOOLS,
    load_machines_config,
    get_machines,
    get_machine,
)


class TestConstantes:
    """Tests para constantes de configuración."""

    def test_base_dir_exists(self):
        """BASE_DIR debe existir."""
        assert BASE_DIR.exists()

    def test_config_dir_exists(self):
        """CONFIG_DIR debe existir."""
        assert CONFIG_DIR.exists()

    def test_log_dir_exists(self):
        """LOG_DIR debe existir."""
        assert LOG_DIR.exists()

    def test_machines_file_path(self):
        """MACHINES_FILE debe apuntar a config/machines.json."""
        assert MACHINES_FILE.name == "machines.json"
        assert MACHINES_FILE.parent == CONFIG_DIR

    def test_host_os_is_valid(self):
        """HOST_OS debe ser un sistema operativo válido."""
        assert HOST_OS in ("Windows", "Linux", "Darwin")

    def test_is_windows_is_bool(self):
        """IS_WINDOWS debe ser un booleano."""
        assert isinstance(IS_WINDOWS, bool)

    def test_is_linux_is_bool(self):
        """IS_LINUX debe ser un booleano."""
        assert isinstance(IS_LINUX, bool)

    def test_timeouts_are_positive(self):
        """Los timeouts deben ser positivos."""
        assert SSH_TIMEOUT_DEFAULT > 0
        assert SSH_CONNECT_TIMEOUT > 0
        assert SSH_MAX_TIMEOUT > 0

    def test_max_output_chars_positive(self):
        """MAX_OUTPUT_CHARS debe ser positivo."""
        assert MAX_OUTPUT_CHARS > 0

    def test_destructive_tools_is_frozenset(self):
        """DESTRUCTIVE_TOOLS debe ser un frozenset."""
        assert isinstance(DESTRUCTIVE_TOOLS, frozenset)

    def test_destructive_tools_contains_expected(self):
        """DESTRUCTIVE_TOOLS debe contener herramientas conocidas."""
        assert "run_command" in DESTRUCTIVE_TOOLS
        assert "delete_user" in DESTRUCTIVE_TOOLS
        assert "kill_process" in DESTRUCTIVE_TOOLS


class TestLoadMachinesConfig:
    """Tests para load_machines_config()."""

    def test_load_config_returns_dict(self):
        """load_machines_config() debe retornar un diccionario."""
        config = load_machines_config()
        assert isinstance(config, dict)

    def test_load_config_has_machines_key(self):
        """load_machines_config() debe tener la clave 'machines'."""
        config = load_machines_config()
        assert "machines" in config

    def test_load_config_file_not_found(self):
        """load_machines_config() debe raise FileNotFoundError si no existe."""
        with patch("core.config.MACHINES_FILE") as mock_file:
            mock_file.exists.return_value = False
            with pytest.raises(FileNotFoundError):
                load_machines_config()


class TestGetMachines:
    """Tests para get_machines()."""

    def test_get_machines_returns_dict(self):
        """get_machines() debe retornar un diccionario."""
        machines = get_machines()
        assert isinstance(machines, dict)

    def test_get_machines_not_empty(self):
        """get_machines() no debe retornar un diccionario vacío."""
        machines = get_machines()
        assert len(machines) > 0


class TestGetMachine:
    """Tests para get_machine()."""

    def test_get_existing_machine(self):
        """get_machine() debe retornar la config de una máquina existente."""
        machines = get_machines()
        first_name = list(machines.keys())[0]
        machine = get_machine(first_name)
        assert isinstance(machine, dict)
        assert "ssh_host" in machine

    def test_get_nonexistent_machine(self):
        """get_machine() debe raise ValueError para máquina inexistente."""
        with pytest.raises(ValueError, match="desconocida"):
            get_machine("maquina-inexistente-falsa")

    def test_machine_has_required_fields(self):
        """Cada máquina debe tener campos requeridos."""
        machines = get_machines()
        for name, data in machines.items():
            assert "ssh_host" in data, f"{name} falta ssh_host"
