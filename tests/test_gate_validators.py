"""
tests/test_gate_validators.py - Tests Fase 1: gate L2 + validadores.

Sin VMs: todo es validación local, sin SSH.
"""

import base64

import pytest

from core.audit import audit_log, sanitize_detail
from core.constants import DESTRUCTIVE_TOOLS, IRREVERSIBLE_TOOLS
from core.security_gate import (
    ACK_IRREVERSIBLE,
    ACK_ROLES,
    ACK_SSH,
    destructive,
    require_double_confirm,
)
from core.validators import (
    validate_ack_text,
    validate_dn,
    validate_dns_ip,
    validate_domain_fqdn,
    validate_gateway_in_subnet,
    validate_group_scope,
    validate_ip,
    validate_password_b64,
    validate_prefix,
    validate_sam,
    validate_share_name,
    validate_unc,
    validate_yaml_safe,
)


def _gate(**over):
    params = {
        "confirm": True,
        "acknowledge": True,
        "ack_text": ACK_IRREVERSIBLE,
        "expected_ack": ACK_IRREVERSIBLE,
        "echo": "lab.test",
        "expected_echo": "lab.test",
        "tool_name": "ad_install_forest",
    }
    params.update(over)
    return require_double_confirm(**params)


class TestDoubleConfirm:
    def test_ok_when_complete(self):
        res = _gate()
        assert res["ok"] is True
        assert res["dry_run"] is False

    def test_dry_run_without_confirm(self):
        res = _gate(confirm=False)
        assert res["ok"] is False
        assert res["dry_run"] is True
        assert "confirm=true" in res["missing"]
        assert "warning" in res and "would_run" in res

    def test_dry_run_without_acknowledge(self):
        res = _gate(acknowledge=False)
        assert res["ok"] is False
        assert res["dry_run"] is True

    def test_dry_run_wrong_ack(self):
        res = _gate(ack_text="si-lo-se")
        assert res["ok"] is False
        assert res["dry_run"] is True

    def test_dry_run_echo_mismatch(self):
        res = _gate(echo="otro.test")
        assert res["ok"] is False
        assert res["dry_run"] is True

    def test_warning_mentions_snapshot(self):
        res = _gate(confirm=False)
        assert "snapshot" in res["warning"].lower()

    def test_ssh_ack_phrase(self):
        res = _gate(
            ack_text=ACK_SSH,
            expected_ack=ACK_SSH,
            echo="192.168.10.20",
            expected_echo="192.168.10.20",
            tool_name="set_ip_address",
        )
        assert res["ok"] is True


class TestDestructiveDecorator:
    def test_l1_requires_confirm(self):
        @destructive(level="L1")
        def delete_user(machine: str, confirm: bool = False):
            return "ok"

        assert delete_user("m", confirm=True) == "ok"
        with pytest.raises(ValueError, match="confirm=true"):
            delete_user("m", confirm=False)

    def test_l2_blocks_without_ack(self):
        @destructive(level="L2", expected_ack=ACK_SSH)
        def set_ip_address(machine: str, confirm=False, acknowledge=False,
                            ack_text=""):
            return "ok"

        with pytest.raises(ValueError):
            set_ip_address("m", confirm=True, acknowledge=False,
                            ack_text=ACK_SSH)

    def test_l2_passes_with_all(self):
        @destructive(level="L2", expected_ack=ACK_SSH)
        def set_ip_address(machine: str, confirm=False, acknowledge=False,
                            ack_text=""):
            return "ok"

        assert set_ip_address("m", confirm=True, acknowledge=True,
                               ack_text=ACK_SSH) == "ok"

    def test_ack_constants(self):
        assert ACK_IRREVERSIBLE == "SE-QUE-ES-IRREVERSIBLE"
        assert ACK_SSH == "SE-QUE-PUEDO-PERDER-SSH"
        assert ACK_ROLES == "SE-QUE-INSTALA-ROLES"


class TestConstants:
    def test_destructive_compat(self):
        from core.config import DESTRUCTIVE_TOOLS as VIA_CONFIG

        assert VIA_CONFIG is DESTRUCTIVE_TOOLS

    def test_destructive_has_linux(self):
        assert "set_ip_address_linux" in DESTRUCTIVE_TOOLS
        assert "run_command_linux" in DESTRUCTIVE_TOOLS
        assert "set_ip_address" in DESTRUCTIVE_TOOLS

    def test_irreversible_content(self):
        for tool in (
            "ad_install_forest", "ad_install_roles", "join_domain",
            "ad_join_domain", "set_ip_address", "set_ip_address_linux",
            "set_dns_server", "set_dns_server_linux", "netplan_set_linux",
            "netplan_apply_linux", "realm_join_linux", "realm_leave_linux",
            "share_create", "ntfs_grant", "samba_create_share_linux",
            "ad_create_ou", "ad_create_group", "ad_create_user",
            "ad_set_password", "ad_restart_after_promote",
        ):
            assert tool in IRREVERSIBLE_TOOLS
        assert isinstance(IRREVERSIBLE_TOOLS, frozenset)


class TestValidators:
    def test_ip_ok(self):
        validate_ip("192.168.10.20")

    @pytest.mark.parametrize("bad", ["", "999.1.1.1", "192.168.1", "abc",
                                      "1.2.3.4.5"])
    def test_ip_bad(self, bad):
        with pytest.raises(ValueError):
            validate_ip(bad)

    def test_prefix_ok(self):
        validate_prefix(24)

    @pytest.mark.parametrize("bad", [0, 33, -1, "x"])
    def test_prefix_bad(self, bad):
        with pytest.raises(ValueError):
            validate_prefix(bad)

    def test_gateway_same_subnet(self):
        validate_gateway_in_subnet("192.168.10.20", 24, "192.168.10.1")

    def test_gateway_other_subnet(self):
        with pytest.raises(ValueError, match="subred"):
            validate_gateway_in_subnet("192.168.10.20", 24, "192.168.20.1")

    def test_dns_ok(self):
        validate_dns_ip("192.168.10.10")

    def test_dns_rejects_zero(self):
        with pytest.raises(ValueError):
            validate_dns_ip("0.0.0.0")

    def test_fqdn_ok(self):
        validate_domain_fqdn("lab.test")

    @pytest.mark.parametrize("bad", ["", "lab", "-lab.test", "lab..test"])
    def test_fqdn_bad(self, bad):
        with pytest.raises(ValueError):
            validate_domain_fqdn(bad)

    def test_dn_ok(self):
        validate_dn("OU=Ventas,DC=lab,DC=test")

    @pytest.mark.parametrize("bad", ["", "OU=Ventas", "OU=X,DC=lab*",
                                      "OU=A(DC=x)"])
    def test_dn_bad(self, bad):
        with pytest.raises(ValueError):
            validate_dn(bad)

    def test_sam_ok(self):
        validate_sam("alu01")

    @pytest.mark.parametrize("bad", ["", "a" * 21, "con espacio", "alu/01"])
    def test_sam_bad(self, bad):
        with pytest.raises(ValueError):
            validate_sam(bad)

    @pytest.mark.parametrize("scope", ["Global", "DomainLocal", "Universal"])
    def test_scope_ok(self, scope):
        validate_group_scope(scope)

    def test_scope_bad(self):
        with pytest.raises(ValueError):
            validate_group_scope("Local")

    def test_share_ok(self):
        validate_share_name("Datos")

    @pytest.mark.parametrize("bad", ["", "A/B", "a:b", ".", "x" * 81])
    def test_share_bad(self, bad):
        with pytest.raises(ValueError):
            validate_share_name(bad)

    def test_unc_ok(self):
        validate_unc("\\\\SRV\\Datos")

    def test_unc_bad(self):
        with pytest.raises(ValueError):
            validate_unc("C:\\Datos")

    def test_yaml_ok(self):
        validate_yaml_safe(
            "network:\n  version: 2\n  ethernets:\n"
            "    enp0s3:\n      dhcp4: true\n"
        )

    def test_yaml_rejects_tabs(self):
        with pytest.raises(ValueError, match="tabulador"):
            validate_yaml_safe("network:\n\tversion: 2\n")

    def test_yaml_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_yaml_safe("   ")

    def test_ack_exact(self):
        validate_ack_text(ACK_IRREVERSIBLE, ACK_IRREVERSIBLE)
        with pytest.raises(ValueError):
            validate_ack_text("se-que-es-irreversible", ACK_IRREVERSIBLE)

    def test_password_b64_ok(self):
        b64 = base64.b64encode("Secreto123".encode("utf-8")).decode()
        assert validate_password_b64(b64) == "Secreto123"

    def test_password_b64_bad_encoding(self):
        with pytest.raises(ValueError):
            validate_password_b64("!!!no-b64!!!")

    def test_password_b64_too_short(self):
        b64 = base64.b64encode(b"abc").decode()
        with pytest.raises(ValueError, match="corto"):
            validate_password_b64(b64)


class TestAuditSanitizes:
    def test_sanitize_redacts_keys(self):
        dirty = "user=x password_b64=QUJD safe_mode=Secreto credential:tok"
        clean = sanitize_detail(dirty)
        assert "QUJD" not in clean
        assert "***" in clean
        assert "user=x" in clean

    def test_audit_log_callable(self):
        audit_log("test_tool", "test_machine", "dry_run ok")
