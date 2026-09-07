"""
tools/linux/samba.py - File server Samba real (Fase 3).

Endurece tools/linux/security.py (listado basico + create simple) SIN
duplicar nombres: aqui van versiones con validacion y seguridad real.
- samba_list_shares_linux (L0): testparm -s + smbstatus.
- samba_create_share_linux (L2): backup .bak + testparm ANTES de
  restart smbd; valida share/path/usuarios; ya-existe es ok.
- samba_set_perms_linux (L2): chmod/chown/setfacl con shlex.quote.

Patron: get_machine + build_ssh_args + run_process + clean_output,
sudo -n + shlex.quote, scripts via base64|bash -s, sufijo _linux,
@mcp.tool() -> str JSON.
"""

import base64
import json
import logging
import re
import shlex

from core.config import get_machine
from core.ssh import build_ssh_args, run_process, clean_output
from core.validation import validate_not_empty, validate_linux_path, require_confirmation
from core.security_gate import require_double_confirm, ACK_IRREVERSIBLE
from core.validators import validate_share_name, validate_sam
from core.audit import audit_log

mcp = None

logger = logging.getLogger(__name__)

_MODE_RE = re.compile(r"^0?[0-7]{3,4}$")


def _sq(text: str) -> str:
    """Comilla simple segura para shell remoto."""
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def _parse_samba_users(valid_users: str) -> str:
    """Valida lista 'user,@grupo,...' y la normaliza separada por espacios."""
    tokens = [t for t in re.split(r"[,\s;]+", str(valid_users).strip()) if t]
    if not tokens:
        raise ValueError(
            "valid_users no puede estar vacio (ej. 'alu01,@ventas'). "
            "Un share sin usuarios validos quedaria publico."
        )
    clean = []
    for token in tokens:
        name = token[1:] if token.startswith("@") else token
        validate_sam(name)
        clean.append(("@" if token.startswith("@") else "") + name)
    return " ".join(clean)


def register(mcp_instance):
    """Registra las herramientas Linux de Samba."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def samba_list_shares_linux(machine: str) -> str:
        """Lista shares Samba (testparm -s + smbstatus, L0)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)

        command = (
            "echo '--- TESTPARM ---'; "
            "sudo -n testparm -s 2>/dev/null || testparm -s 2>/dev/null "
            "|| cat /etc/samba/smb.conf 2>/dev/null || echo 'NO_SAMBA_CONFIG'; "
            "echo '--- SMBSTATUS ---'; "
            "smbstatus --shares 2>/dev/null || sudo -n smbstatus --shares 2>/dev/null "
            "|| echo 'SMBSTATUS_UNAVAILABLE'"
        )

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=30,
        )

        audit_log("samba_list_shares_linux", machine, "ok" if result["ok"] else "failed")
        return json.dumps(clean_output(result, 30000), ensure_ascii=False, indent=2)

    @mcp.tool()
    def samba_create_share_linux(
        machine: str,
        name: str,
        path: str,
        valid_users: str = "",
        read_only: bool = False,
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Crea un share Samba real (smb.conf + testparm + restart smbd, L2).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-ES-IRREVERSIBLE'.
        Sin L2 completo retorna dry_run SIN tocar SSH. Flujo remoto: backup
        .bak, mkdir -p, append del bloque, testparm (si falla restaura .bak
        y aborta), restart smbd, verificacion. Si el share ya existe retorna
        ok con already_exists=true sin modificar nada.
        """
        validate_not_empty(machine, "machine")
        validate_share_name(name)
        if "[" in name or "]" in name:
            raise ValueError(
                f"share_name no valido para smb.conf: {name!r} (sin corchetes)."
            )
        validate_not_empty(path, "path")
        validate_linux_path(path)
        users = _parse_samba_users(valid_users)

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_IRREVERSIBLE, name, name, "samba_create_share_linux",
        )
        if not gate["ok"]:
            audit_log("samba_create_share_linux", machine, f"dry_run share={name}")
            return json.dumps(
                {
                    **gate,
                    "tool": "samba_create_share_linux",
                    "machine": machine,
                    "share": name,
                    "path": path,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        ro = "yes" if read_only else "no"
        block = [
            f"[{name}]",
            f"   path = {path}",
            f"   valid users = {users}",
            f"   read only = {ro}",
            "   browseable = yes",
        ]
        printf_lines = "; ".join(f"printf '%s\\n' {_sq(line)}" for line in block)

        inner_lines = [
            "set -euo pipefail",
            "CONF='/etc/samba/smb.conf'",
            "BAK='/etc/samba/smb.conf.bak'",
            f"SHARE={_sq(name)}",
            f"SHARE_PATH={_sq(path)}",
            'if [ ! -f "$CONF" ]; then echo "NO_SAMBA_CONFIG: $CONF" >&2; exit 1; fi',
            'if grep -qF "[$SHARE]" "$CONF" 2>/dev/null || '
            f"grep -qF {_sq('[' + name + ']')} \"$CONF\"; then "
            f"echo 'SHARE_ALREADY_EXISTS: {name}'; exit 0; fi",
            'sudo -n cp -a "$CONF" "$BAK" && echo "BACKUP_OK: $BAK"',
            'sudo -n mkdir -p "$SHARE_PATH"',
            'TMP="$(mktemp /tmp/mcp-samba.XXXXXX)"',
            f"( {printf_lines}; ) > \"$TMP\"",
            'sudo -n tee -a "$CONF" < "$TMP" > /dev/null',
            'rm -f "$TMP"',
            "if ! sudo -n testparm -s > /dev/null 2>&1; then "
            "echo 'TESTPARM_FAILED: restaurando .bak' >&2; "
            'sudo -n cp -a "$BAK" "$CONF"; exit 1; fi',
            "sudo -n systemctl restart smbd 2>/dev/null || sudo -n service smbd restart",
            f"sudo -n testparm -s 2>/dev/null | grep -A5 -F {_sq('[' + name + ']')} || true",
            "echo 'SHARE_CREATED_OK'",
        ]
        inner = "\n".join(inner_lines) + "\n"
        outer = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        command = f"echo '{outer}' | base64 -d | bash -s"

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=120,
        )
        out = clean_output(result)
        if "SHARE_ALREADY_EXISTS" in str(out.get("stdout", "")):
            out["already_exists"] = True

        audit_log(
            "samba_create_share_linux",
            machine,
            f"share={name} path={path} users={users} ro={ro} L2-ACK",
        )
        return json.dumps(out, ensure_ascii=False, indent=2)

    @mcp.tool()
    def samba_set_perms_linux(
        machine: str,
        path: str,
        owner: str = "",
        group: str = "",
        mode: str = "",
        use_acl: bool = False,
        acl_users: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Ajusta permisos del path de un share (chown/chmod/setfacl, L2).

        Exige confirm=true + acknowledge=true + ack_text='SE-QUE-ES-IRREVERSIBLE'.
        Al menos un cambio (owner/group/mode/acl) es obligatorio. Todo
        interpolado con shlex.quote.
        """
        validate_not_empty(machine, "machine")
        validate_not_empty(path, "path")
        validate_linux_path(path)
        if owner:
            validate_sam(owner)
        if group:
            validate_sam(group)
        acl_list = []
        if acl_users:
            acl_list = [
                t for t in re.split(r"[,\s;]+", str(acl_users).strip()) if t
            ]
            for token in acl_list:
                validate_sam(token)
        if mode and not _MODE_RE.match(str(mode).strip()):
            raise ValueError(
                f"mode no valido: {mode!r}. Usa octal 3-4 digitos (ej. 2770, 0750)."
            )
        if not owner and not group and not mode and not use_acl and not acl_list:
            raise ValueError(
                "Sin cambios: aporta al menos owner, group, mode o acl (use_acl/acl_users)."
            )

        gate = require_double_confirm(
            confirm, acknowledge, ack_text,
            ACK_IRREVERSIBLE, path, path, "samba_set_perms_linux",
        )
        if not gate["ok"]:
            audit_log("samba_set_perms_linux", machine, f"dry_run path={path}")
            return json.dumps(
                {
                    **gate,
                    "tool": "samba_set_perms_linux",
                    "machine": machine,
                    "path": path,
                },
                ensure_ascii=False,
                indent=2,
            )
        data = get_machine(machine)

        q_path = shlex.quote(path)
        parts = []
        if owner or group:
            who = (owner or "") + (":" + group if group else "")
            parts.append(f"sudo -n chown {shlex.quote(who)} {q_path}")
        if mode:
            parts.append(f"sudo -n chmod {shlex.quote(str(mode).strip())} {q_path}")
        if use_acl or acl_list:
            parts.append(
                "command -v setfacl >/dev/null 2>&1 || "
                "{ echo 'NO_SETFACL: instala el paquete acl' >&2; exit 1; }"
            )
            for token in acl_list:
                parts.append(f"sudo -n setfacl -m u:{shlex.quote(token)}:rwX {q_path}")
            if use_acl and not acl_list:
                parts.append(f"sudo -n setfacl -b {q_path} && echo 'ACL_CLEARED'")
            parts.append(f"getfacl -- {q_path} 2>/dev/null || true")
        parts.append("echo 'PERMS_SET_OK'")
        parts.append(f"ls -ld -- {q_path}")
        command = "; ".join(parts)

        result = run_process(
            build_ssh_args(data["ssh_host"], command),
            timeout=60,
        )

        audit_log(
            "samba_set_perms_linux",
            machine,
            f"path={path} owner={owner or '-'} group={group or '-'} "
            f"mode={mode or '-'} acl={acl_list or use_acl} L2-ACK",
        )
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
