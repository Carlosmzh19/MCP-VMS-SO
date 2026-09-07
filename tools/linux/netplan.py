"""
tools/linux/netplan.py - Red avanzada Netplan (Fase 3).

- netplan_list_files_linux (L0): ls /etc/netplan/.
- netplan_get_linux (L0): cat de un YAML (validate_linux_path +
  confinamiento a /etc/netplan/) o de todos si no se indica file.
- netplan_set_linux (L2 ACK_SSH, eco filename): valida YAML basico en
  host (validate_yaml_safe) + backup .bak + netplan generate; si
  generate falla restaura .bak. NO aplica (eso es netplan_apply).
- netplan_apply_linux (L2 ACK_SSH): netplan generate + apply con
  post-check ip addr/route.

Patron: get_machine + build_ssh_args + run_process + clean_output,
sudo -n + shlex.quote, scripts via base64|bash -s, sufijo _linux,
@mcp.tool() -> str JSON. Corte-red: snapshot + consola antes de L2.
"""

import base64
import json
import logging
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_linux_path
from core.security_gate import require_double_confirm, ACK_SSH
from core.validators import validate_yaml_safe
from core.audit import audit_log

from ..network_safe import (
    POST_CHECK_HINT,
    SSH_CUT_WARNING,
    SNAPSHOT_REMINDER,
)

mcp = None

logger = logging.getLogger(__name__)

_NETPLAN_DIR = "/etc/netplan"


def _sq(text: str) -> str:
    """Comilla simple segura para shell remoto."""
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def _validate_netplan_file(path: str) -> str:
    """Valida ruta absoluta confinada a /etc/netplan/*.yaml|*.yml."""
    validate_not_empty(path, "file")
    validate_linux_path(path)
    text = str(path).strip()
    if not text.startswith(_NETPLAN_DIR + "/"):
        raise ValueError(
            f"file fuera de {_NETPLAN_DIR}: {path!r}. "
            "Solo se gestionan YAML dentro de /etc/netplan/."
        )
    if ".." in text:
        raise ValueError(f"file no valido (path traversal): {path!r}.")
    if not (text.endswith(".yaml") or text.endswith(".yml")):
        raise ValueError(
            f"file no valido: {path!r}. Debe terminar en .yaml o .yml."
        )
    return text


def register(mcp_instance):
    """Registra las herramientas Linux de Netplan."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def netplan_list_files_linux(machine: str) -> str:
        """Lista los archivos de /etc/netplan/ (L0)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = f"ls -la -- {shlex.quote(_NETPLAN_DIR)}"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("netplan_list_files_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def netplan_get_linux(machine: str, file: str = "") -> str:
        """Muestra YAML de Netplan (L0).

        Sin 'file' concatena todos los *.yaml; con 'file' solo ese
        (confinado a /etc/netplan/).
        """
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        if file:
            target = _validate_netplan_file(file)
            command = f"sudo -n cat -- {shlex.quote(target)}"
        else:
            command = (
                f"sudo -n cat -- {_NETPLAN_DIR}/*.yaml {_NETPLAN_DIR}/*.yml 2>/dev/null "
                f"|| ls -la -- {shlex.quote(_NETPLAN_DIR)}"
            )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("netplan_get_linux", machine, f"file={file or 'all'}")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def netplan_set_linux(
        machine: str,
        file: str,
        content_yaml: str,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """Escribe un YAML de Netplan con backup+generate (L2 ACK_SSH, NO aplica).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-PUEDO-PERDER-SSH'
        + eco del filename en echo_confirm. Valida YAML basico EN HOST antes
        de SSH (un YAML invalido se rechaza sin tocar la VM). Flujo remoto:
        .bak, escritura, chmod 600, netplan generate; si generate falla
        restaura .bak y aborta. Aplica despues con netplan_apply_linux (L2).
        Sin L2 completo retorna dry_run con preflight (sin SSH).
        """
        validate_not_empty(machine, "machine")
        target = _validate_netplan_file(file)
        validate_yaml_safe(content_yaml)

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_SSH, echo_confirm, target, "netplan_set_linux",
        )
        if not gate["ok"]:
            audit_log("netplan_set_linux", machine, f"dry_run file={target}")
            return json.dumps(
                {
                    **gate,
                    "tool": "netplan_set_linux",
                    "machine": machine,
                    "file": target,
                    "preflight": {
                        "checks": {"file": "ok", "yaml_valid": True},
                        "warnings": [],
                    },
                    "warning": gate["warning"] + " " + SSH_CUT_WARNING,
                    "snapshot_reminder": SNAPSHOT_REMINDER,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        content_b64 = base64.b64encode(content_yaml.encode("utf-8")).decode("ascii")
        inner_lines = [
            "set -euo pipefail",
            f"F={_sq(target)}",
            'BAK="$F.bak"',
            f"if [ ! -d {_sq(_NETPLAN_DIR)} ]; then echo 'NO_NETPLAN_DIR' >&2; exit 1; fi",
            'if [ -f "$F" ]; then sudo -n cp -a "$F" "$BAK" && echo "BACKUP_OK: $BAK"; '
            "else echo 'NEW_FILE (sin backup previo)'; fi",
            f"echo {_sq(content_b64)} | base64 -d | sudo -n tee \"$F\" > /dev/null",
            'sudo -n chmod 600 "$F"',
            "if ! sudo -n netplan generate; then "
            "echo 'NETPLAN_GENERATE_FAILED: restaurando' >&2; "
            'if [ -f "$BAK" ]; then sudo -n cp -a "$BAK" "$F"; '
            'else sudo -n rm -f "$F"; fi; exit 1; fi',
            "echo 'NETPLAN_SET_OK (pendiente netplan_apply_linux con L2)'",
        ]
        inner = "\n".join(inner_lines) + "\n"
        outer = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        command = f"echo '{outer}' | base64 -d | bash -s"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=120,
        )

        audit_log("netplan_set_linux", machine, f"file={target} L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)

    @mcp.tool()
    def netplan_apply_linux(
        machine: str,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
        echo_confirm: str = "",
    ) -> str:
        """Aplica Netplan (generate + apply) con post-check de red (L2 ACK_SSH).

        PUEDE CORTAR SSH: haz snapshot de VirtualBox AHORA y ten la consola
        abierta. Exige confirm=true + acknowledge=true +
        ack_text='SE-QUE-PUEDO-PERDER-SSH' + echo_confirm='netplan-apply'.
        Sin L2 completo retorna dry_run SIN ejecutar. Post: ip addr
        + ip route para verificar la nueva configuracion.
        """
        validate_not_empty(machine, "machine")

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_SSH, echo_confirm, "netplan-apply", "netplan_apply_linux",
        )
        if not gate["ok"]:
            audit_log("netplan_apply_linux", machine, "dry_run")
            return json.dumps(
                {
                    **gate,
                    "tool": "netplan_apply_linux",
                    "machine": machine,
                    "preflight": {
                        "checks": {"target": "netplan-apply"},
                        "warnings": [],
                    },
                    "warning": gate["warning"] + " " + SSH_CUT_WARNING,
                    "snapshot_reminder": SNAPSHOT_REMINDER,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        command = (
            "sudo -n netplan generate && sudo -n netplan apply && echo 'NETPLAN_APPLIED_OK'; "
            "echo '--- ADDR ---'; ip addr show; "
            "echo '--- ROUTE ---'; ip route show"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=120,
        )

        audit_log("netplan_apply_linux", machine, "applied L2-ACK-SSH")
        out = clean_output(result)
        out["post_check_hint"] = POST_CHECK_HINT
        return json.dumps(out, ensure_ascii=False, indent=2)
