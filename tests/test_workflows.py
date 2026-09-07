"""
tests/test_workflows.py - Tests Fase 6 de workflows (sin VMs, todo mockeado).

Cubre: provision_org dry_run (sin SSH), check_domain_health L0
(solo lectura, sin confirm) y publish_share dry_run (sin SSH).
"""

import json

import pytest

from tests.conftest import FakeMCP, patch_tool_module


class TestProvisionDryRun:
    def test_provision_org_dry_run_without_confirm(self):
        import tools.workflows.provision_org as mod

        called = {}
        patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN", called=called)
        # preflight tampoco debe tocarse en dry_run; blindarlo por si acaso.
        mod.preflight_ssh = lambda m: (
            None,
            json.dumps({"ok": False, "error": "no debe llamarse en dry_run"}),
        )
        fake = FakeMCP()
        mod.register_provision_org(fake)
        fn = fake.tools["provision_org"]

        out = json.loads(
            fn(
                machine_dc="winserver-vm",
                org_name="Ventas",
                ous=["Users", "Groups"],
                groups=["Ventas-RW"],
                users_csv_json="",
                confirm=False,
            )
        )
        assert out["ok"] is False
        assert out["dry_run"] is True
        assert "plan" in out
        assert any("Ventas" in p for p in out["plan"])
        assert called.get("run", 0) == 0

    def test_provision_org_dry_run_mentions_snapshot(self):
        import tools.workflows.provision_org as mod

        patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN")
        mod.preflight_ssh = lambda m: (None, json.dumps({"ok": False}))
        fake = FakeMCP()
        mod.register_provision_org(fake)
        fn = fake.tools["provision_org"]

        out = json.loads(
            fn(machine_dc="winserver-vm", org_name="Ventas", confirm=False)
        )
        assert "snapshot" in json.dumps(out, ensure_ascii=False).lower()


class TestDomainHealthL0:
    def test_check_domain_health_no_confirm_all_pass(self):
        import tools.workflows.domain_health as mod

        layers = (
            "LAYER|ping_dc|PASS|ok\n"
            "LAYER|dns_client_points_dc|PASS|ok\n"
            "LAYER|nslookup|PASS|ok\n"
            "LAYER|dsgetdc|PASS|ok\n"
            "LAYER|ad_domain|PASS|ok\n"
            "LAYER|dns_zones|PASS|ok\n"
            "LAYER|smb_445|PASS|ok\n"
            "LAYER|ldap_389|PASS|ok\n"
        )
        mod.preflight_ssh = lambda m: ({"ssh_host": "h", "os": "windows"}, None)
        mod._invoke_ps_b64 = lambda data, script, timeout: {
            "ok": True,
            "return_code": 0,
            "stdout": layers,
            "stderr": "",
            "command": ["ssh", "mock"],
        }
        fake = FakeMCP()
        mod.register_domain_health(fake)
        fn = fake.tools["check_domain_health"]

        # L0: sin parámetros confirm/acknowledge en la firma.
        import inspect

        assert "confirm" not in inspect.signature(fn).parameters
        out = json.loads(
            fn(
                machine_dc="winserver-vm",
                machine_client="win11-vm",
                domain_name="lab.test",
            )
        )
        assert out["ok"] is True
        assert out["failed"] == []
        assert len(out["dc"]) == 8
        assert len(out["client"]) == 8

    def test_check_domain_health_reports_failed_layers(self):
        import tools.workflows.domain_health as mod

        layers = "LAYER|ping_dc|FAIL|timeout\nLAYER|nslookup|PASS|ok\n"
        mod.preflight_ssh = lambda m: ({"ssh_host": "h", "os": "windows"}, None)
        mod._invoke_ps_b64 = lambda data, script, timeout: {
            "ok": True,
            "return_code": 0,
            "stdout": layers,
            "stderr": "",
            "command": ["ssh", "mock"],
        }
        fake = FakeMCP()
        mod.register_domain_health(fake)
        fn = fake.tools["check_domain_health"]

        out = json.loads(
            fn(
                machine_dc="winserver-vm",
                machine_client="win11-vm",
                domain_name="lab.test",
            )
        )
        assert out["ok"] is False
        assert len(out["failed"]) > 0


class TestPublishDryRun:
    def test_publish_share_dry_run_without_confirm(self):
        import tools.workflows.publish_share as mod

        called = {}
        patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN", called=called)
        mod.preflight_ssh = lambda m: (
            None,
            json.dumps({"ok": False, "error": "no debe llamarse en dry_run"}),
        )
        fake = FakeMCP()
        mod.register_publish_share(fake)
        fn = fake.tools["publish_share"]

        groups = json.dumps([{"account": "LAB\\Ventas-RW", "access": "Change"}])
        out = json.loads(
            fn(
                machine_dc="winserver-vm",
                machine_client="win11-vm",
                share_name="Datos",
                path="D:\\Datos",
                groups_json=groups,
                confirm=False,
            )
        )
        assert out["ok"] is False
        assert out["dry_run"] is True
        assert "plan" in out
        assert called.get("run", 0) == 0

    def test_publish_share_rejects_everyone_without_ssh(self):
        import tools.workflows.publish_share as mod

        mock_run = patch_tool_module(mod, run_stdout="SHOULD-NOT-RUN")
        fake = FakeMCP()
        mod.register_publish_share(fake)
        fn = fake.tools["publish_share"]

        groups = json.dumps([{"account": "Everyone", "access": "Full"}])
        with pytest.raises(ValueError, match="[Ee]veryone|prohibida"):
            fn(
                machine_dc="winserver-vm",
                machine_client="win11-vm",
                share_name="Datos",
                path="D:\\Datos",
                groups_json=groups,
                confirm=True,
                acknowledge=True,
                ack_text="SE-QUE-ES-IRREVERSIBLE",
            )
        mock_run.assert_not_called()
