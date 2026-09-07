"""
tests/test_ad_dns_share.py - Tests Fase 6 (sin VMs, todo mockeado).

Cubre: AD idempotente already_exists, share prohíbe Everyone,
validators ip/subnet, netplan YAML inválido sin tocar VM,
passwords fuera de logs y dirección SCP download.
"""

import base64
import json

import pytest

from tests.conftest import FakeMCP, patch_tool_module
from core.audit import sanitize_detail
from core.ssh import build_scp_args
from core.validators import (
    validate_gateway_in_subnet,
    validate_ip,
    validate_password_b64,
    validate_prefix,
    validate_yaml_safe,
)


def _b64(secret: str) -> str:
    return base64.b64encode(secret.encode("utf-8")).decode("ascii")


# =============================================================================
# AD idempotente: already_exists
# =============================================================================

class TestAdIdempotent:
    def test_ad_create_ou_already_exists(self):
        import tools.windows.ad_org as mod

        called = {}
        patch_tool_module(mod, run_stdout="__ALREADY_EXISTS__\n{}", called=called)
        fake = FakeMCP()
        mod.register_ad_org(fake)
        fn = fake.tools["ad_create_ou"]

        out = json.loads(
            fn(
                machine="winserver-vm",
                ou_name="Ventas",
                path_dn="DC=lab,DC=test",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )
        )
        assert out["already_exists"] is True
        assert called.get("run") == 1

    def test_ad_create_group_already_exists(self):
        import tools.windows.ad_org as mod

        patch_tool_module(mod, run_stdout="__ALREADY_EXISTS__\n{}")
        fake = FakeMCP()
        mod.register_ad_org(fake)
        fn = fake.tools["ad_create_group"]

        out = json.loads(
            fn(
                machine="winserver-vm",
                group_name="Ventas-RW",
                scope="Global",
                category="Security",
                path_dn="OU=Ventas,DC=lab,DC=test",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )
        )
        assert out["already_exists"] is True

    def test_ad_create_user_already_exists(self):
        import tools.windows.ad_org as mod

        patch_tool_module(mod, run_stdout="__ALREADY_EXISTS__\n{}")
        fake = FakeMCP()
        mod.register_ad_org(fake)
        fn = fake.tools["ad_create_user"]

        out = json.loads(
            fn(
                machine="winserver-vm",
                full_name="Alumno Uno",
                sam="alu01",
                upn="alu01@lab.test",
                ou_dn="OU=Users,DC=lab,DC=test",
                password_b64=_b64("Secreto123"),
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )
        )
        assert out["already_exists"] is True


# =============================================================================
# Share: prohibido Everyone
# =============================================================================

class TestShareNoEveryone:
    def test_share_create_rejects_everyone_full(self):
        import tools.windows.fileserver as mod

        fake = FakeMCP()
        mod.register_fileserver(fake)
        fn = fake.tools["share_create"]

        with pytest.raises(ValueError, match="[Ee]veryone"):
            fn(
                machine="winserver-vm",
                share_name="Datos",
                folder_path="D:\\Datos",
                full=["Everyone"],
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )

    def test_share_create_rejects_todos(self):
        import tools.windows.fileserver as mod

        fake = FakeMCP()
        mod.register_fileserver(fake)
        fn = fake.tools["share_create"]

        with pytest.raises(ValueError, match="[Tt]odos|prohibida"):
            fn(
                machine="winserver-vm",
                share_name="Datos",
                folder_path="D:\\Datos",
                read=["Todos"],
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )

    def test_share_grant_rejects_everyone(self):
        import tools.windows.fileserver as mod

        fake = FakeMCP()
        mod.register_fileserver(fake)
        fn = fake.tools["share_grant_access"]

        with pytest.raises(ValueError, match="[Ee]veryone|prohibida"):
            fn(
                machine="winserver-vm",
                share_name="Datos",
                account="Everyone",
                access_right="Read",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )

    def test_share_create_requires_at_least_one_group(self):
        import tools.windows.fileserver as mod

        fake = FakeMCP()
        mod.register_fileserver(fake)
        fn = fake.tools["share_create"]

        with pytest.raises(ValueError, match="al menos 1 grupo"):
            fn(
                machine="winserver-vm",
                share_name="Datos",
                folder_path="D:\\Datos",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )


# =============================================================================
# Validators: ip / subnet
# =============================================================================

class TestValidatorsIpSubnet:
    def test_validate_ip_ok(self):
        validate_ip("192.168.10.20")

    @pytest.mark.parametrize("bad", ["", "999.1.1.1", "192.168.1", "abc"])
    def test_validate_ip_bad(self, bad):
        with pytest.raises(ValueError):
            validate_ip(bad)

    def test_validate_prefix_ok(self):
        validate_prefix(24)

    @pytest.mark.parametrize("bad", [0, 33, -1])
    def test_validate_prefix_bad(self, bad):
        with pytest.raises(ValueError):
            validate_prefix(bad)

    def test_gateway_same_subnet_ok(self):
        validate_gateway_in_subnet("192.168.10.20", 24, "192.168.10.1")

    def test_gateway_other_subnet_fails(self):
        with pytest.raises(ValueError, match="subred"):
            validate_gateway_in_subnet("192.168.10.20", 24, "192.168.20.1")


# =============================================================================
# Netplan: YAML inválido sin tocar VM
# =============================================================================

class TestNetplanInvalidNoVm:
    def test_netplan_set_rejects_tabs_without_ssh(self):
        import tools.linux.netplan as mod

        mock_run = patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN")
        fake = FakeMCP()
        mod.register(fake)
        fn = fake.tools["netplan_set_linux"]

        with pytest.raises(ValueError, match="tabulador"):
            fn(
                machine="mint-vm",
                file="/etc/netplan/01-lab.yaml",
                content_yaml="network:\n\tversion: 2\n",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-PUEDO-PERDER-SSH",
                echo_confirm="/etc/netplan/01-lab.yaml",
            )
        mock_run.assert_not_called()

    def test_netplan_set_rejects_bad_indent_without_ssh(self):
        import tools.linux.netplan as mod

        mock_run = patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN")
        fake = FakeMCP()
        mod.register(fake)
        fn = fake.tools["netplan_set_linux"]

        with pytest.raises(ValueError, match="indentaci"):
            fn(
                machine="mint-vm",
                file="/etc/netplan/01-lab.yaml",
                content_yaml="network:\n   version: 2\n",
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-PUEDO-PERDER-SSH",
                echo_confirm="/etc/netplan/01-lab.yaml",
            )
        mock_run.assert_not_called()

    def test_validate_yaml_safe_direct(self):
        with pytest.raises(ValueError):
            validate_yaml_safe("   ")
        # YAML válido mínimo no lanza.
        validate_yaml_safe("network:\n  version: 2\n")


# =============================================================================
# Passwords fuera de logs
# =============================================================================

class TestPasswordNotInLogs:
    def test_sanitize_redacts_password_b64(self):
        secret = _b64("Secreto123")
        dirty = f"user=alu01 password_b64={secret} ok"
        clean = sanitize_detail(dirty)
        assert secret not in clean
        assert "***" in clean
        assert "user=alu01" in clean

    def test_validate_password_b64_ok_and_short(self):
        assert validate_password_b64(_b64("Secreto123")) == "Secreto123"
        with pytest.raises(ValueError, match="corto"):
            validate_password_b64(_b64("abc"))

    def test_ad_create_user_redacts_command(self):
        import tools.windows.ad_org as mod

        patch_tool_module(mod, run_stdout="__CREATED__\n{}")
        fake = FakeMCP()
        mod.register_ad_org(fake)
        fn = fake.tools["ad_create_user"]

        pw = _b64("Secreto123")
        out = json.loads(
            fn(
                machine="winserver-vm",
                full_name="Alumno Uno",
                sam="alu01",
                upn="alu01@lab.test",
                ou_dn="OU=Users,DC=lab,DC=test",
                password_b64=pw,
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )
        )
        dumped = json.dumps(out, ensure_ascii=False)
        assert pw not in dumped
        assert "Secreto123" not in dumped
        assert out.get("command") == "[redacted ad_create_user]"


# =============================================================================
# SCP download: dirección host:remote -> local
# =============================================================================

class TestScpDownloadDirection:
    def test_download_order_is_remote_then_local(self):
        args = build_scp_args(
            "myhost", "/remote/file.txt", "/local/file.txt", direction="download"
        )
        # Forma: scp ... host:/remote ... /local
        assert args[-2] == "myhost:/remote/file.txt"
        assert args[-1] == "/local/file.txt"

    def test_upload_order_is_local_then_remote(self):
        args = build_scp_args(
            "myhost", "/local/file.txt", "/remote/file.txt", direction="upload"
        )
        assert args[-2] == "/local/file.txt"
        assert args[-1] == "myhost:/remote/file.txt"

    def test_invalid_direction_raises(self):
        with pytest.raises(ValueError, match="direction"):
            build_scp_args("h", "a", "b", direction="sideways")
