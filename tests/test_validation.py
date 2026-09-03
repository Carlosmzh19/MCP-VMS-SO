"""
tests/test_validation.py - Tests para core.validation.
"""

import pytest

from core.validation import (
    validate_not_empty,
    validate_timeout,
    validate_lines,
    validate_max_chars,
    require_confirmation,
    is_destructive,
)


class TestValidateNotEmpty:
    """Tests para validate_not_empty()."""

    def test_valid_string(self):
        """validate_not_empty() no debe fallar con string válido."""
        validate_not_empty("hello", "field")  # No exception

    def test_empty_string_raises(self):
        """validate_not_empty() debe raise ValueError con string vacío."""
        with pytest.raises(ValueError, match="no puede estar vacío"):
            validate_not_empty("", "field")

    def test_whitespace_only_raises(self):
        """validate_not_empty() debe raise ValueError con solo espacios."""
        with pytest.raises(ValueError, match="no puede estar vacío"):
            validate_not_empty("   ", "field")

    def test_none_raises(self):
        """validate_not_empty() debe raise ValueError con None."""
        with pytest.raises((ValueError, AttributeError)):
            validate_not_empty(None, "field")


class TestValidateTimeout:
    """Tests para validate_timeout()."""

    def test_valid_timeout(self):
        """validate_timeout() no debe fallar con timeout válido."""
        validate_timeout(30)  # No exception
        validate_timeout(1)
        validate_timeout(600)

    def test_zero_timeout_raises(self):
        """validate_timeout() debe raise ValueError con 0."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_timeout(0)

    def test_negative_timeout_raises(self):
        """validate_timeout() debe raise ValueError con negativo."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_timeout(-1)

    def test_too_large_timeout_raises(self):
        """validate_timeout() debe raise ValueError con timeout muy grande."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_timeout(9999)


class TestValidateLines:
    """Tests para validate_lines()."""

    def test_valid_lines(self):
        """validate_lines() no debe fallar con valor válido."""
        validate_lines(100)  # No exception
        validate_lines(1)
        validate_lines(1000)

    def test_zero_lines_raises(self):
        """validate_lines() debe raise ValueError con 0."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_lines(0)

    def test_too_many_lines_raises(self):
        """validate_lines() debe raise ValueError con líneas excesivas."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_lines(9999)


class TestValidateMaxChars:
    """Tests para validate_max_chars()."""

    def test_valid_max_chars(self):
        """validate_max_chars() no debe fallar con valor válido."""
        validate_max_chars(20000)  # No exception
        validate_max_chars(1)
        validate_max_chars(100000)

    def test_zero_max_chars_raises(self):
        """validate_max_chars() debe raise ValueError con 0."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_max_chars(0)

    def test_too_large_max_chars_raises(self):
        """validate_max_chars() debe raise ValueError con valor excesivo."""
        with pytest.raises(ValueError, match="entre 1 y"):
            validate_max_chars(999999)


class TestRequireConfirmation:
    """Tests para require_confirmation()."""

    def test_confirmation_true(self):
        """require_confirmation() no debe fallar con confirm=True."""
        require_confirmation(True, "test_tool")  # No exception

    def test_confirmation_false_raises(self):
        """require_confirmation() debe raise ValueError con confirm=False."""
        with pytest.raises(ValueError, match="destructiva"):
            require_confirmation(False, "test_tool")

    def test_error_includes_tool_name(self):
        """El mensaje de error debe incluir el nombre de la herramienta."""
        with pytest.raises(ValueError, match="my_tool"):
            require_confirmation(False, "my_tool")


class TestIsDestructive:
    """Tests para is_destructive()."""

    def test_known_destructive_tool(self):
        """is_destructive() debe retornar True para herramientas destructivas."""
        assert is_destructive("run_command") is True
        assert is_destructive("delete_user") is True
        assert is_destructive("kill_process") is True

    def test_non_destructive_tool(self):
        """is_destructive() debe retornar False para herramientas no destructivas."""
        assert is_destructive("list_machines") is False
        assert is_destructive("test_ssh") is False
        assert is_destructive("get_system_info") is False

    def test_unknown_tool(self):
        """is_destructive() debe retornar False para herramienta desconocida."""
        assert is_destructive("unknown_tool_xyz") is False
