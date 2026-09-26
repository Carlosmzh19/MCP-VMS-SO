"""
tools/linux/realm.py - Union opcional a Active Directory (Fase 3).

- realm_check_linux (L0): realm discover (+ sssd) sin modificar nada.
- realm_join_linux (L2): realm join con password_b64 por stdin,
  valida FQDN; advierte que el DNS del cliente debe apuntar al DC.
- realm_leave_linux (L2): realm leave.

Requiere en la VM: realmd/sssd/adcli. Patron: get_machine +
build_ssh_args + run_process + clean_output, sudo -n + shlex.quote,
scripts via base64|bash -s, sufijo _linux, @mcp.tool() -> str JSON.
"""

import base64
import json
import logging
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty
from core.security_gate import require_double_confirm, ACK_IRREVERSIBLE
from core.validators import validate_domain_fqdn, validate_sam, validate_dn, validate_password_b64
from core.audit import audit_log

mcp = None

logger = logging.getLogger(__name__)


def _redact_secrets(result: dict, *secrets: str) -> dict:
    """Reemplaza secretos en command/stdout/stderr por *** (no loguear claves)."""
    redacted_cmd = []
    for part in result.get("command", []):
        text = str(part)
        for s in secrets:
            if s:
                text = text.replace(s, "***")
        redacted_cmd.append(text)
    result["command"] = ["REDACTED"] if any("***" in c for c in redacted_cmd) else redacted_cmd
    for key in ("stdout", "stderr"):
        text = str(result.get(key, ""))
        for s in secrets:
            if s:
                text = text.replace(s, "***")
        result[key] = text
    return result


def _sq(text: str) -> str:
    """Comilla simple segura para shell remoto."""
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def register(mcp_instance):
    """Registra las herramientas Linux de realm/AD."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def realm_check_linux(machine: str, domain: str = "") -> str:
        """Comprueba realm/sssd (L0).

        Sin 'domain': lista realms unidos + estado sssd. Con 'domain':
        ademas realm discover (requiere que el DNS resuelva el dominio,
        idealmente apuntando al DC).
        """
        validate_not_empty(machine, "machine")
        if domain:
            validate_domain_fqdn(domain)
        data = get_machine(machine)

        parts = []
        if domain:
            parts.append(f"echo '--- DISCOVER {domain} ---'; realm discover {shlex.quote(domain)}")
        parts.append("echo '--- REALM LIST ---'; realm list 2>/dev/null || echo 'NO_REALMS_JOINED'")
        parts.append(
            "echo '--- SSSD ---'; systemctl is-active sssd 2>/dev/null || "
            "systemctl status sssd --no-pager 2>/dev/null || echo 'SSSD_UNAVAILABLE'"
        )
        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log("realm_check_linux", machine, f"domain={domain or '-'}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def realm_join_linux(
        machine: str,
        domain: str,
        user: str,
        password_b64: str,
        ou: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Une la VM a Active Directory (realm join, L2).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-ES-IRREVERSIBLE'.
        Sin L2 completo retorna dry_run SIN tocar SSH. 'ou' opcional es el DN
        destino del objeto equipo. La password viaja en b64 y entra por stdin:
        nunca en claro en argv/ps, logs ni JSON. AVISO: el DNS del cliente
        debe apuntar al DC o el join fallara.
        """
        validate_not_empty(machine, "machine")
        validate_domain_fqdn(domain)
        validate_sam(user)
        validate_password_b64(password_b64)
        if ou:
            validate_dn(ou)
        b64 = str(password_b64).strip()

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_IRREVERSIBLE, domain, domain, "realm_join_linux",
        )
        if not gate["ok"]:
            audit_log("realm_join_linux", machine, f"dry_run domain={domain}")
            return json.dumps(
                {
                    **gate,
                    "tool": "realm_join_linux",
                    "machine": machine,
                    "domain": domain,
                    "warning_dns": (
                        "El DNS del cliente debe apuntar al DC para resolver "
                        f"{domain} antes de unir."
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        join_cmd = f"sudo -n realm join --user={_sq(user)}"
        if ou:
            join_cmd += f" --computer-ou={_sq(ou)}"
        join_cmd += f" {_sq(domain)}"
        inner_lines = [
            "set -euo pipefail",
            f"DOMAIN={_sq(domain)}",
            "echo 'HINT: el DNS del cliente debe apuntar al DC.'",
            'getent hosts "$DOMAIN" || '
            'echo "DNS_WARN: $DOMAIN no resuelve; verifica DNS hacia el DC." >&2',
            f"echo {_sq(b64)} | base64 -d | {join_cmd}",
            'realm list || echo "REALM_LIST_EMPTY"',
            "systemctl is-active sssd 2>/dev/null || "
            "sudo -n systemctl status sssd --no-pager 2>/dev/null || true",
            "echo 'REALM_JOIN_OK'",
        ]
        inner = "\n".join(inner_lines) + "\n"
        outer = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        command = f"echo '{outer}' | base64 -d | bash -s"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=180,
        )
        _redact_secrets(result, b64, outer)

        audit_log("realm_join_linux", machine, f"domain={domain} user={user} L2-ACK")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def realm_leave_linux(
        machine: str,
        domain: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Saca la VM del dominio (realm leave, L2).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-ES-IRREVERSIBLE'.
        Sin L2 completo retorna dry_run SIN tocar SSH.
        """
        validate_not_empty(machine, "machine")
        if domain:
            validate_domain_fqdn(domain)
        echo = domain if domain else "leave"

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_IRREVERSIBLE, echo, echo, "realm_leave_linux",
        )
        if not gate["ok"]:
            audit_log("realm_leave_linux", machine, f"dry_run domain={domain or '-'}")
            return json.dumps(
                {
                    **gate,
                    "tool": "realm_leave_linux",
                    "machine": machine,
                    "domain": domain,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        q_domain = f" {shlex.quote(domain)}" if domain else ""
        command = (
            f"sudo -n realm leave{q_domain} && echo 'REALM_LEFT_OK'; "
            "realm list 2>/dev/null || echo 'NO_REALMS_JOINED'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=120,
        )

        audit_log("realm_leave_linux", machine, f"domain={domain or '-'} L2-ACK")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
