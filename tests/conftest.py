"""
tests/conftest.py - Fixtures Fase 6 (sin VMs, solo mocks).

Provee mocks de run_process / build_ssh_args / get_machine más un
FakeMCP para capturar las funciones registradas vía @mcp.tool().
"""

import json
from unittest.mock import MagicMock

import pytest

FAKE_MACHINE = {
    "ssh_host": "test-host",
    "os": "windows",
    "ip": "192.168.10.20",
    "description": "VM de pruebas (mock)",
    "ssh_user": "tester",
}

FAKE_MACHINE_LINUX = {
    "ssh_host": "test-linux",
    "os": "linux",
    "ip": "192.168.10.30",
    "description": "VM Linux de pruebas (mock)",
    "ssh_user": "carlos",
}


class FakeMCP:
    """Sustituto mínimo de FastMCP: @tool() registra y devuelve la función."""

    def __init__(self):
        self.tools = {}

    def tool(self, *decorator_args, **decorator_kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn

        return deco


@pytest.fixture
def fake_mcp():
    """FakeMCP fresco por test."""
    return FakeMCP()


@pytest.fixture
def fake_machine_data():
    """Dict de máquina mock (Windows)."""
    return dict(FAKE_MACHINE)


@pytest.fixture
def fake_machine_linux():
    """Dict de máquina mock (Linux)."""
    return dict(FAKE_MACHINE_LINUX)


def ok_result(stdout="MOCK_OK", stderr=""):
    """Resultado tipo run_process() exitoso."""
    return {
        "ok": True,
        "return_code": 0,
        "stdout": stdout,
        "stderr": stderr,
        "command": ["ssh", "mock"],
    }


def fail_result(stdout="", stderr="mock-error"):
    """Resultado tipo run_process() fallido."""
    return {
        "ok": False,
        "return_code": 1,
        "stdout": stdout,
        "stderr": stderr,
        "command": ["ssh", "mock"],
    }


@pytest.fixture
def mock_ssh_ok(monkeypatch):
    """Parchea core.ssh.run_process/build_ssh_args con éxito genérico."""
    import core.ssh as ssh_mod

    monkeypatch.setattr(
        ssh_mod, "build_ssh_args", lambda host, cmd, **kw: ["ssh", host, cmd]
    )
    monkeypatch.setattr(ssh_mod, "run_process", lambda args, timeout=60: ok_result())
    return ssh_mod


@pytest.fixture
def mock_get_machine(monkeypatch):
    """Parchea core.config.get_machine para no leer machines.json real."""
    import core.config as cfg

    def _fake(name):
        if "linux" in str(name):
            return dict(FAKE_MACHINE_LINUX)
        return dict(FAKE_MACHINE)

    monkeypatch.setattr(cfg, "get_machine", _fake)
    return _fake


def patch_tool_module(module, run_stdout="MOCK_OK", called=None):
    """Parchea un módulo de tool (get_machine/build_ssh_args/run_process).

    Args:
        module: módulo ya importado (ej. tools.windows.ad_org).
        run_stdout: stdout que devolverá run_process mockeado.
        called: dict opcional para registrar llamadas {"run": int}.

    Returns:
        MagicMock del run_process mockeado (para asserts de no-llamada).
    """
    if called is None:
        called = {}

    def _get_machine(name):
        if "linux" in str(name):
            return dict(FAKE_MACHINE_LINUX)
        return dict(FAKE_MACHINE)

    def _build(host, cmd, **kw):
        return ["ssh", host, cmd]

    mock_run = MagicMock(side_effect=lambda args, timeout=60: ok_result(run_stdout))

    def _run(args, timeout=60):
        called["run"] = called.get("run", 0) + 1
        return mock_run(args, timeout=timeout)

    module.get_machine = _get_machine
    module.build_ssh_args = _build
    module.run_process = _run
    return mock_run
