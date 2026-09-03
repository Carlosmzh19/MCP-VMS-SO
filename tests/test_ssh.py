"""
tests/test_ssh.py - Tests para core.ssh.
"""

import pytest
from unittest.mock import patch, MagicMock

from core.ssh import (
    SSH_BINARY,
    SCP_BINARY,
    PING_BINARY,
    build_ssh_args,
    build_scp_args,
    build_ping_args,
    scp_destination,
    run_process,
    clean_output,
    diagnose_ssh_error,
)


class TestBinaries:
    """Tests para detección de binarios."""

    def test_ssh_binary_is_string(self):
        """SSH_BINARY debe ser un string."""
        assert isinstance(SSH_BINARY, str)

    def test_scp_binary_is_string(self):
        """SCP_BINARY debe ser un string."""
        assert isinstance(SCP_BINARY, str)

    def test_ping_binary_is_string(self):
        """PING_BINARY debe ser un string."""
        assert isinstance(PING_BINARY, str)


class TestBuildSshArgs:
    """Tests para build_ssh_args()."""

    def test_basic_ssh_args(self):
        """build_ssh_args() debe generar argumentos básicos correctos."""
        args = build_ssh_args("test-host", "echo hello")
        assert args[0] == SSH_BINARY
        assert "test-host" in args
        assert "echo hello" in args
        assert "-o" in args
        assert "BatchMode=yes" in args

    def test_ssh_args_has_connect_timeout(self):
        """build_ssh_args() debe incluir ConnectTimeout."""
        args = build_ssh_args("host", "cmd", connect_timeout=15)
        assert any("ConnectTimeout=15" in arg for arg in args)

    def test_ssh_args_with_extra_options(self):
        """build_ssh_args() debe incluir opciones extra."""
        extra = {"StrictHostKeyChecking": "no"}
        args = build_ssh_args("host", "cmd", extra_options=extra)
        assert any("StrictHostKeyChecking=no" in arg for arg in args)

    def test_ssh_args_has_server_alive(self):
        """build_ssh_args() debe incluir ServerAliveInterval."""
        args = build_ssh_args("host", "cmd")
        assert any("ServerAliveInterval=" in arg for arg in args)


class TestBuildScpArgs:
    """Tests para build_scp_args()."""

    def test_basic_scp_args(self):
        """build_scp_args() debe generar argumentos correctos."""
        args = build_scp_args("host", "/local/file", "/remote/file")
        assert args[0] == SCP_BINARY
        assert "/local/file" in args
        assert "host:/remote/file" in args

    def test_scp_args_has_batch_mode(self):
        """build_scp_args() debe incluir BatchMode=yes."""
        args = build_scp_args("host", "src", "dst")
        assert any("BatchMode=yes" in arg for arg in args)


class TestBuildPingArgs:
    """Tests para build_ping_args()."""

    def test_ping_args_format(self):
        """build_ping_args() debe generar argumentos de ping."""
        args = build_ping_args("192.168.1.1")
        assert PING_BINARY in args
        assert "192.168.1.1" in args
        # Debe tener -n (Windows) o -c (Linux)
        assert any(flag in args for flag in ["-n", "-c"])


class TestScpDestination:
    """Tests para scp_destination()."""

    def test_destination_format(self):
        """scp_destination() debe generar formato host:path."""
        result = scp_destination("myhost", "/path/to/file")
        assert result == "myhost:/path/to/file"


class TestRunProcess:
    """Tests para run_process()."""

    def test_successful_command(self):
        """run_process() debe manejar comandos exitosos."""
        result = run_process(["echo", "hello"], timeout=5)
        assert result["ok"] is True
        assert result["return_code"] == 0
        assert "hello" in result["stdout"]

    def test_failed_command(self):
        """run_process() debe manejar comandos fallidos."""
        result = run_process(["ls", "/nonexistent_path_xyz"], timeout=5)
        assert result["ok"] is False
        assert result["return_code"] != 0

    def test_timeout_handling(self):
        """run_process() debe manejar timeouts."""
        result = run_process(["ping", "127.0.0.1"], timeout=1)
        # ping puede o no exceder 1 segundo, verificar que no crashea
        assert "return_code" in result

    def test_file_not_found(self):
        """run_process() debe manejar ejecutables inexistentes."""
        result = run_process(["nonexistent_executable_xyz"], timeout=5)
        assert result["ok"] is False
        assert "error" in result

    def test_result_has_required_fields(self):
        """El resultado debe tener campos requeridos."""
        result = run_process(["echo", "test"], timeout=5)
        assert "ok" in result
        assert "return_code" in result
        assert "stdout" in result
        assert "stderr" in result
        assert "command" in result


class TestCleanOutput:
    """Tests para clean_output()."""

    def test_clean_output_short(self):
        """clean_output() no debe truncar salida corta."""
        result = {"stdout": "short", "stderr": "error"}
        cleaned = clean_output(result, max_chars=100)
        assert cleaned["stdout"] == "short"
        assert cleaned["stderr"] == "error"

    def test_clean_output_long(self):
        """clean_output() debe truncar salida larga."""
        long_stdout = "x" * 200
        result = {"stdout": long_stdout, "stderr": ""}
        cleaned = clean_output(result, max_chars=100)
        assert len(cleaned["stdout"]) == 100

    def test_clean_output_preserves_end(self):
        """clean_output() debe preservar el final de la salida."""
        long_stdout = "A" * 50 + "B" * 50
        result = {"stdout": long_stdout, "stderr": ""}
        cleaned = clean_output(result, max_chars=50)
        assert cleaned["stdout"] == "B" * 50


class TestDiagnoseSshError:
    """Tests para diagnose_ssh_error()."""

    def test_connection_refused(self):
        """diagnose_ssh_error() debe detectar Connection refused."""
        hint = diagnose_ssh_error("Connection refused", 255)
        assert hint is not None
        assert "apagado" in hint.lower() or "ssh" in hint.lower()

    def test_permission_denied(self):
        """diagnose_ssh_error() debe detectar Permission denied."""
        hint = diagnose_ssh_error("Permission denied", 255)
        assert hint is not None
        assert "autenticación" in hint.lower() or "key" in hint.lower()

    def test_no_route(self):
        """diagnose_ssh_error() debe detectar No route to host."""
        hint = diagnose_ssh_error("No route to host", 255)
        assert hint is not None

    def test_empty_stderr_with_255(self):
        """diagnose_ssh_error() debe manejar stderr vacío con código 255."""
        hint = diagnose_ssh_error("", 255)
        assert hint is not None
        assert "255" in hint

    def test_empty_stderr_with_0(self):
        """diagnose_ssh_error() debe retornar None para éxito sin error."""
        hint = diagnose_ssh_error("", 0)
        assert hint is None

    def test_unknown_error(self):
        """diagnose_ssh_error() debe manejar errores desconocidos."""
        hint = diagnose_ssh_error("something weird happened", 1)
        assert hint is None
