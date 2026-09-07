"""
tools/linux/identity.py - Identidad Linux complementaria (Fase 3).

Completa tools/linux/users.py SIN duplicarlo (users.py ya cubre
list/create/delete/enable/disable de usuarios y grupos locales):
- get_user_linux (L0): id + getent + grupos + chage -l.
- set_password_linux (L2): chpasswd por stdin desde password_b64,
  nunca en claro en argv/ps; script via base64|bash -s.
- set_password_expiry_linux (L1): chage -M/-m/-W por usuario.

Patron: get_machine + build_ssh_args + run_process + clean_output,
sudo -n + shlex.quote, sufijo _linux, @mcp.tool() -> str JSON.
Secretos nunca en logs ni en el JSON (redactados + audit sanitizado).
"""

import base64
import json
import logging
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, require_confirmation
from core.security_gate import require_double_confirm, ACK_IRREVERSIBLE
from core.validators import validate_sam, validate_password_b64
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
    """Registra las herramientas Linux de identidad complementaria."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_user_linux(machine: str, username: str) -> str:
        """Detalle de un usuario Linux (id + getent + grupos + chage -l)."""
        validate_not_empty(machine, "machine")
        validate_sam(username)
        data = get_machine(machine)

        q_user = shlex.quote(username)
        command = (
            f"id {q_user}; "
            f"echo '--- GETENT ---'; getent passwd {q_user}; "
            f"echo '--- GROUPS ---'; groups {q_user} 2>/dev/null || id -nG {q_user}; "
            f"echo '--- CHAGE ---'; sudo -n chage -l {q_user} 2>/dev/null || echo 'CHAGE_UNAVAILABLE'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("get_user_linux", machine, f"user={username} " + ("ok" if result["ok"] else "failed"))
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_password_linux(
        machine: str,
        username: str,
        password_b64: str,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Cambia la password de un usuario Linux (chpasswd por stdin desde b64, L2).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-ES-IRREVERSIBLE'.
        Sin L2 completo retorna dry_run SIN tocar SSH. El secreto viaja en
        base64 dentro de un script base64|bash -s y entra a chpasswd por
        tuberia: nunca en claro en argv/ps, logs ni JSON.
        """
        validate_not_empty(machine, "machine")
        validate_sam(username)
        secret = validate_password_b64(password_b64)
        if ":" in secret or "\n" in secret or "\r" in secret:
            raise ValueError(
                "password_b64 no apto para chpasswd: no puede contener ':' ni saltos de linea."
            )
        b64 = str(password_b64).strip()

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_IRREVERSIBLE, username, username, "set_password_linux",
        )
        if not gate["ok"]:
            audit_log("set_password_linux", machine, f"dry_run user={username}")
            return json.dumps(
                {
                    **gate,
                    "tool": "set_password_linux",
                    "machine": machine,
                    "target_user": username,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        inner_lines = [
            "set -euo pipefail",
            f"U={_sq(username)}",
            'if ! id "$U" >/dev/null 2>&1; then echo "USER_NOT_FOUND: $U" >&2; exit 1; fi',
            f"(printf '%s:' \"$U\"; echo {_sq(b64)} | base64 -d) | sudo -n chpasswd",
            "echo 'PASSWORD_SET_OK'",
        ]
        inner = "\n".join(inner_lines) + "\n"
        outer = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        command = f"echo '{outer}' | base64 -d | bash -s"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )
        _redact_secrets(result, b64, outer)

        audit_log("set_password_linux", machine, f"user={username} L2-ACK")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def set_password_expiry_linux(
        machine: str,
        username: str,
        max_days: int = 0,
        min_days: int = 0,
        warn_days: int = 0,
        confirm: bool = False,
    ) -> str:
        """Cambia la expiracion de password de un usuario (chage, requiere confirm).

        Usa 0 para no cambiar un parametro; al menos uno debe ser > 0.
        """
        require_confirmation(confirm, "set_password_expiry_linux")
        validate_not_empty(machine, "machine")
        validate_sam(username)
        for label, value in (("max_days", max_days), ("min_days", min_days), ("warn_days", warn_days)):
            if int(value) < 0:
                raise ValueError(f"{label} no puede ser negativo.")
        if int(max_days) == 0 and int(min_days) == 0 and int(warn_days) == 0:
            raise ValueError(
                "Sin cambios: aporta al menos max_days, min_days o warn_days > 0."
            )
        data = get_machine(machine)

        q_user = shlex.quote(username)
        parts = []
        if int(max_days) > 0:
            parts.append(f"sudo -n chage -M {int(max_days)} {q_user}")
        if int(min_days) > 0:
            parts.append(f"sudo -n chage -m {int(min_days)} {q_user}")
        if int(warn_days) > 0:
            parts.append(f"sudo -n chage -W {int(warn_days)} {q_user}")
        parts.append(f"sudo -n chage -l {q_user}")
        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log(
            "set_password_expiry_linux",
            machine,
            f"user={username} max={max_days} min={min_days} warn={warn_days}",
        )
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
