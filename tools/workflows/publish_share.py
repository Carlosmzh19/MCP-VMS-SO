"""
tools/workflows/publish_share.py - Workflow publish_share (FASE 5, L2).

Orquesta share_create + ntfs_grant + share_get_effective +
share_test_from_client como pasos idempotentes (base64 UTF-16LE):
1. share (New-Item + New-SmbShare + Grant de accesos faltantes),
2. ntfs (icacls /grant + verify Get-Acl),
3. efectivo (Share vs NTFS, regla más restrictivo),
4. prueba desde el cliente (Test-Path UNC).
Prohíbe Everyone; L2 ACK_IRREVERSIBLE; sin secretos en retorno.
"""

import json
import logging

from core.audit import audit_log
from core.config import SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, require_double_confirm
from core.ssh import clean_output
from core.validation import validate_not_empty
from core.validators import validate_sam, validate_share_name, validate_unc

from ._common import (
    EVIDENCE_DIR_HINT,
    SNAPSHOT_REMINDER_L2,
    _invoke_ps_b64,
    parse_steps,
    preflight_ssh,
)

mcp = None

logger = logging.getLogger(__name__)

EVERYONE_ALIASES = ("everyone", "todos", "todo el mundo", "authenticated users")
SHARE_ACCESS = ("Full", "Change", "Read")
NTFS_RIGHTS = ("F", "M", "RX")


def parse_groups_json(groups_json: str) -> list:
    """Acepta array de {"account","access"} o array plano de cuentas.

    El array plano otorga Change. Valida cuentas (no Everyone) y accesos.
    """
    text = (groups_json or "").strip()
    if not text:
        raise ValueError(
            "groups_json no puede estar vacío: indica al menos 1 grupo "
            "(ej. [{\"account\": \"DOM\\\\Ventas-RW\", \"access\": \"Change\"}]). "
            "Everyone está prohibido."
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"groups_json no es JSON válido: {exc}."
        ) from None
    if not isinstance(data, list) or not data:
        raise ValueError("groups_json debe ser un array no vacío.")
    groups = []
    for i, item in enumerate(data, start=1):
        if isinstance(item, str):
            account, access = item.strip(), "Change"
        elif isinstance(item, dict):
            account = str(item.get("account", "")).strip()
            access = str(item.get("access", "Change")).strip()
        else:
            raise ValueError(f"groups_json[{i}]: debe ser objeto o texto.")
        if not account:
            raise ValueError(f"groups_json[{i}]: account vacío.")
        if account.strip().lower() in EVERYONE_ALIASES:
            raise ValueError(
                f"groups_json[{i}]: cuenta prohibida {account!r}. "
                "Everyone:Full está prohibido; usa grupos de dominio."
            )
        if access not in SHARE_ACCESS:
            raise ValueError(
                f"groups_json[{i}]: access no válido {access!r}. "
                f"Valores: {', '.join(SHARE_ACCESS)}."
            )
        groups.append({"account": account, "access": access})
    return groups


def _ps_array(values: list) -> str:
    items = ",".join(f"'{escape_ps_single_quote(v)}'" for v in values)
    return f"@({items})"


def _share_script(share: str, path: str, groups: list, description: str) -> str:
    full = [g["account"] for g in groups if g["access"] == "Full"]
    change = [g["account"] for g in groups if g["access"] == "Change"]
    read = [g["account"] for g in groups if g["access"] == "Read"]
    params = ""
    if full:
        params += f" -FullAccess {_ps_array(full)}"
    if change:
        params += f" -ChangeAccess {_ps_array(change)}"
    if read:
        params += f" -ReadAccess {_ps_array(read)}"
    grants = []
    for g in groups:
        a = escape_ps_single_quote(g["account"])
        grants.append(
            "  $have=Get-SmbShareAccess -Name $n -ErrorAction SilentlyContinue "
            f"| Where-Object {{ $_.AccountName -eq '{a}' -and $_.AccessRight -eq '{g['access']}' }};"
            "  if($have){ Write-Output (\"STEP|share_access|\"+$n+\":"
            + a + "|True|exists\") }"
            f"  else {{ Grant-SmbShareAccess -Name $n -AccountName '{a}' "
            f"-AccessRight {g['access']} -Force; Write-Output (\"STEP|share_access|\"+$n+\":"
            + a + "|False|granted\") }"
        )
    return " ".join(
        [
            "$ErrorActionPreference='Stop';",
            f"$n='{escape_ps_single_quote(share)}';",
            f"$p='{escape_ps_single_quote(path)}';",
            f"$desc='{escape_ps_single_quote(description)}';",
            "New-Item -ItemType Directory -Force -Path $p | Out-Null;",
            "Write-Output (\"STEP|folder|\"+$p+\"|True|ensured\");",
            "$s=Get-SmbShare -Name $n -ErrorAction SilentlyContinue;",
            "if(-not $s){",
            f"  New-SmbShare -Name $n -Path $p{params} -FolderEnumerationMode AccessBased -Description $desc | Out-Null;",
            "  Write-Output (\"STEP|share|\"+$n+\"|False|created\") }",
            "else { Write-Output (\"STEP|share|\"+$n+\"|True|exists\") }",
            *grants,
            "$hn=$env:COMPUTERNAME;",
            "Write-Output (\"HOST|\"+$hn);",
        ]
    )


def _ntfs_script(path: str, groups: list, rights: str) -> str:
    per_acct = []
    for g in groups:
        a = escape_ps_single_quote(g["account"])
        per_acct.append(
            f"$a='{a}';"
            "  $r=icacls $p /grant \"\"$a\"\":(OI)(CI)" + rights + "\" 2>&1 | Out-String;"
            "  Write-Output (\"STEP|ntfs|\"+$p+\":"
            + a + "|False|\"+($r.Trim().Split(\"`n\") | Select-Object -First 1));"
        )
    return " ".join(
        [
            "$ErrorActionPreference='Stop';",
            f"$p='{escape_ps_single_quote(path)}';",
            *per_acct,
            "$acl=(Get-Acl -LiteralPath $p).Access | Select-Object IdentityReference,FileSystemRights,AccessControlType;",
            "Write-Output 'ACL-BEGIN';",
            "$acl | ForEach-Object { Write-Output ($_.IdentityReference.ToString()+\"=\"+$_.FileSystemRights.ToString()) };",
            "Write-Output 'ACL-END';",
        ]
    )


def _effective_script(share: str, path: str) -> str:
    return " ".join(
        [
            "$ErrorActionPreference='Stop';",
            f"$s='{escape_ps_single_quote(share)}';",
            f"$p='{escape_ps_single_quote(path)}';",
            "$share=Get-SmbShareAccess -Name $s | Select-Object AccountName,AccessRight,AccessControlType;",
            "$ntfs=(Get-Acl -LiteralPath $p).Access | Select-Object IdentityReference,FileSystemRights,AccessControlType;",
            "[pscustomobject]@{ShareAccess=$share; NtfsAccess=$ntfs;",
            " Rule='Efectivo = el mas restrictivo entre Share y NTFS'} | ConvertTo-Json -Depth 4",
        ]
    )


def _client_test_script(unc: str) -> str:
    return " ".join(
        [
            "$ErrorActionPreference='Stop';",
            f"$u='{escape_ps_single_quote(unc)}';",
            "$ok=Test-Path -LiteralPath $u;",
            "$t=if($ok){'True'}else{'False'};",
            "Write-Output (\"STEP|client_test|\"+$u+\"|\"+$t+\"|reachable=\"+$ok);",
            "[pscustomobject]@{UNC=$u; Reachable=[bool]$ok} | ConvertTo-Json -Compress",
        ]
    )


def register_publish_share(mcp_instance):
    """Registra el workflow publish_share con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def publish_share(
        machine_dc: str,
        machine_client: str,
        share_name: str,
        path: str,
        groups_json: str = "",
        ntfs_rights: str = "RX",
        description: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Publica un share SMB+NTFS y lo prueba desde el cliente. L2.

        Pasos idempotentes: share_create (+Grant faltantes) > ntfs_grant
        icacls (OI)(CI) > efectivo Share vs NTFS > Test-Path UNC cliente.
        groups_json: [{"account":"DOM\\G","access":"Full|Change|Read"}].
        ntfs_rights: F|M|RX. L2 ACK_IRREVERSIBLE.
        """
        validate_not_empty(machine_dc, "machine_dc")
        validate_not_empty(machine_client, "machine_client")
        validate_share_name(share_name)
        validate_not_empty(path, "path")
        groups = parse_groups_json(groups_json)
        rights = (ntfs_rights or "").strip().upper()
        if rights not in NTFS_RIGHTS:
            raise ValueError(
                f"ntfs_rights no válido: {ntfs_rights!r}. "
                f"Valores: {', '.join(NTFS_RIGHTS)}."
            )
        # Validación temprana de cuentas con forma sam simple.
        for g in groups:
            short = g["account"].split("\\")[-1]
            if short and short.lower() not in EVERYONE_ALIASES:
                try:
                    validate_sam(short)
                except ValueError:
                    pass  # Cuentas DOM\\Nombre Largo se validan en la VM.

        plan = [
            f"share {share_name!r} en {path!r} (+Grant accesos faltantes, ABE)",
            f"NTFS icacls {rights} (OI)(CI) para {len(groups)} cuenta(s)",
            "efectivo Share vs NTFS (regla: más restrictivo)",
            "Test-Path UNC desde el cliente",
        ]
        gate = require_double_confirm(
            confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, "", "", "publish_share"
        )
        if not gate["ok"]:
            gate["machine"] = machine_dc
            gate["plan"] = plan
            gate["snapshot_reminder"] = SNAPSHOT_REMINDER_L2
            gate["evidence_hint"] = EVIDENCE_DIR_HINT
            audit_log(
                "publish_share", machine_dc,
                f"dry_run share={share_name} missing={','.join(gate.get('missing', []))}",
            )
            return json.dumps(gate, ensure_ascii=False, indent=2)

        data_dc, err = preflight_ssh(machine_dc)
        if err is not None:
            audit_log("publish_share", machine_dc, "abortado: test_ssh DC falló")
            return err
        data_cli, err = preflight_ssh(machine_client)
        if err is not None:
            audit_log("publish_share", machine_client, "abortado: test_ssh CLI falló")
            return err

        steps: list = []
        res1 = _invoke_ps_b64(
            data_dc,
            _share_script(share_name.strip(), path.strip(), groups, description or ""),
            SSH_TIMEOUT_DEFAULT,
        )
        if not res1.get("ok"):
            res1["machine"] = machine_dc
            res1["steps"] = parse_steps(res1.get("stdout", "") or "")
            res1["snapshot_reminder"] = SNAPSHOT_REMINDER_L2
            audit_log("publish_share", machine_dc, f"falló paso share {share_name}")
            return json.dumps(clean_output(res1), ensure_ascii=False, indent=2)
        steps += parse_steps(res1.get("stdout", "") or "")
        host_lines = [
            line.split("|", 1)[1].strip()
            for line in (res1.get("stdout", "") or "").splitlines()
            if line.strip().startswith("HOST|")
        ]
        dc_host = host_lines[-1] if host_lines else machine_dc
        unc = f"\\\\{dc_host}\\{share_name.strip()}"
        validate_unc(unc)

        res2 = _invoke_ps_b64(
            data_dc, _ntfs_script(path.strip(), groups, rights), SSH_TIMEOUT_DEFAULT
        )
        steps += parse_steps(res2.get("stdout", "") or "")

        res3 = _invoke_ps_b64(
            data_dc,
            _effective_script(share_name.strip(), path.strip()),
            SSH_TIMEOUT_DEFAULT,
        )
        steps.append(
            {
                "step": "effective",
                "target": share_name.strip(),
                "already_exists": True,
                "status": "read",
                "detail": "Share vs NTFS lado a lado",
            }
        )

        res4 = _invoke_ps_b64(data_cli, _client_test_script(unc), SSH_TIMEOUT_DEFAULT)
        for s in parse_steps(res4.get("stdout", "") or ""):
            s["status"] = "tested"
            steps.append(s)
        client_ok = '"Reachable":true' in (res4.get("stdout", "") or "").replace(" ", "")

        out = {
            "ok": res2.get("ok", False)
            and res3.get("ok", False)
            and res4.get("ok", False)
            and client_ok,
            "machine_dc": machine_dc,
            "machine_client": machine_client,
            "share": share_name.strip(),
            "path": path.strip(),
            "unc": unc,
            "steps": steps,
            "effective": (res3.get("stdout", "") or "")[:4000],
            "client_reachable": client_ok,
            "snapshot_reminder": SNAPSHOT_REMINDER_L2,
            "evidence_hint": EVIDENCE_DIR_HINT,
        }
        audit_log(
            "publish_share", machine_dc,
            f"L2-ACK share={share_name} unc={unc} reachable={client_ok}",
        )
        return json.dumps(out, ensure_ascii=False, indent=2)
