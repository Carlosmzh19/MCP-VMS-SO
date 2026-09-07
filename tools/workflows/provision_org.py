"""
tools/workflows/provision_org.py - Workflow provision_org (FASE 5, L2).

Compone la lógica de ad_create_ou/group/user + Add-ADGroupMember en un
plan ordenado OU raíz > sub-OUs > grupos > usuarios CSV > membresías,
ejecutado vía run_powershell_script idempotente (base64 UTF-16LE).
Idempotencia already_exists por paso; sin secretos en retorno.
"""

import base64
import csv
import io
import json
import logging

from core.audit import audit_log
from core.config import SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, require_double_confirm
from core.ssh import clean_output
from core.validation import validate_not_empty
from core.validators import validate_password_b64, validate_sam

from ._common import (
    EVIDENCE_DIR_HINT,
    SNAPSHOT_REMINDER_L2,
    _invoke_ps_b64,
    parse_steps,
    preflight_ssh,
)

mcp = None

logger = logging.getLogger(__name__)

_DEFAULT_OUS = ["Users", "Groups", "Computers"]

# Nombre de OU: no vacío, máx 64, sin caracteres de inyección LDAP.
_OU_FORBIDDEN = set("*()\\\x00\n\r")


def _validate_ou_name(name: str, label: str) -> str:
    if not name or not str(name).strip():
        raise ValueError(f"{label} no puede estar vacío (ej. Ventas).")
    text = str(name).strip()
    if len(text) > 64:
        raise ValueError(f"{label} demasiado largo (máx 64): {name!r}.")
    if "," in text and "=" in text:
        raise ValueError(
            f"{label} debe ser solo el nombre (ej. Ventas), no un DN: {name!r}."
        )
    if any(c in _OU_FORBIDDEN for c in text):
        raise ValueError(
            f"{label} no válido: {name!r}. Prohibidos *, paréntesis, backslash o saltos."
        )
    return text


def parse_users_csv_json(users_csv_json: str) -> list:
    """Acepta JSON array o CSV con columnas sam,upn,pw_b64[,full_name,group].

    Valida sam/upn/password_b64. Retorna lista de dicts
    {sam, upn, full_name, password_b64, group}. Nunca loguear el resultado.
    """
    text = (users_csv_json or "").strip()
    if not text:
        return []
    rows: list = []
    if text.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "users_csv_json no es JSON válido: "
                f"{exc}. Debe ser array de objetos {sam,upn,pw_b64} o CSV."
            ) from None
        if not isinstance(data, list):
            raise ValueError("users_csv_json JSON debe ser un array de objetos.")
        rows = data
    else:
        try:
            reader = csv.DictReader(io.StringIO(text))
            rows = list(reader)
        except csv.Error as exc:
            raise ValueError(f"users_csv_json CSV no parseable: {exc}.") from None
        if not rows or not {"sam", "upn", "pw_b64"} <= set(rows[0].keys() or []):
            raise ValueError(
                "users_csv_json CSV debe tener cabecera sam,upn,pw_b64 "
                "(opcionales: full_name,group)."
            )
    users = []
    for i, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"users_csv_json fila {i}: debe ser un objeto.")
        sam = str(row.get("sam", "")).strip()
        upn = str(row.get("upn", "")).strip()
        pw_b64 = str(row.get("pw_b64", "") or row.get("password_b64", "")).strip()
        full_name = str(row.get("full_name", "") or sam).strip()
        group = str(row.get("group", "") or "").strip()
        validate_sam(sam)
        validate_not_empty(upn, f"users_csv_json fila {i} upn")
        if "@" not in upn:
            raise ValueError(
                f"users_csv_json fila {i}: upn no válido {upn!r} (forma usuario@dominio)."
            )
        validate_password_b64(pw_b64)
        validate_not_empty(full_name, f"users_csv_json fila {i} full_name")
        if group:
            validate_sam(group)
        users.append(
            {
                "sam": sam,
                "upn": upn,
                "full_name": full_name,
                "password_b64": pw_b64,
                "group": group,
            }
        )
    return users


def _plan(org_name: str, ous: list, groups: list, users: list) -> list:
    """Plan de pasos (sin secretos) para dry_run y auditoría."""
    plan = [f"OU raíz {org_name!r} en la raíz del dominio (idempotente)"]
    plan += [f"sub-OU {ou!r} bajo OU={org_name} (idempotente)" for ou in ous]
    plan += [f"grupo Global {g!r} en sub-OU Groups (idempotente)" for g in groups]
    for u in users:
        plan.append(
            f"usuario {u['sam']!r} ({u['upn']}) en sub-OU Users"
            + (f" + miembro de {u['group']!r}" if u["group"] else "")
            + " (idempotente)"
        )
    return plan


def build_provision_script(org: str, ous: list, groups: list, users: list) -> str:
    """Script PS idempotente OU > sub-OUs > grupos > usuarios > membresías."""
    org_q = escape_ps_single_quote(org)
    subs_ps = ",".join(f"'{escape_ps_single_quote(o)}'" for o in ous)
    groups_ps = ",".join(f"'{escape_ps_single_quote(g)}'" for g in groups)
    users_json = json.dumps(
        [
            {
                "sam": u["sam"],
                "upn": u["upn"],
                "full": u["full_name"],
                "pw": u["password_b64"],
                "grp": u["group"],
            }
            for u in users
        ]
    )
    # b64 del JSON de usuarios para no pelear con comillas en el script.
    users_b64 = base64.b64encode(users_json.encode("utf-8")).decode("ascii")
    lines = [
        "$ErrorActionPreference='Stop';",
        f"$org='{org_q}';",
        f"$subs=@({subs_ps});" if subs_ps else "$subs=@();",
        f"$groups=@({groups_ps});" if groups_ps else "$groups=@();",
        f"$usersB64='{users_b64}';",
        "$usersJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($usersB64));",
        "$users=@($usersJson | ConvertFrom-Json);",
        "$domain=(Get-ADDomain).DistinguishedName;",
        "$orgDN=\"OU=$org,$domain\";",
        "function Ensure-OU { param([string]$Name,[string]$Path)",
        "  $dn=\"OU=$Name,$Path\";",
        "  $f=Get-ADOrganizationalUnit -Identity $dn -ErrorAction SilentlyContinue;",
        "  if($f){ Write-Output (\"STEP|ou|\"+$dn+\"|True|exists\") }",
        "  else { New-ADOrganizationalUnit -Name $Name -Path $Path;",
        "    Write-Output (\"STEP|ou|\"+$dn+\"|False|created\") } };",
        "Ensure-OU -Name $org -Path $domain;",
        "foreach($s in $subs){ Ensure-OU -Name $s -Path $orgDN; }",
        "$groupsPath=\"OU=Groups,$orgDN\";" if "Groups" in ous else "$groupsPath=$orgDN;",
        "$usersPath=\"OU=Users,$orgDN\";" if "Users" in ous else "$usersPath=$orgDN;",
        "foreach($g in $groups){",
        "  $f=Get-ADGroup -Filter \"Name -eq '$g'\" -ErrorAction SilentlyContinue | Select-Object -First 1;",
        "  if($f){ Write-Output (\"STEP|group|\"+$g+\"|True|exists\") }",
        "  else { New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -GroupCategory Security -Path $groupsPath;",
        "    Write-Output (\"STEP|group|\"+$g+\"|False|created\") } }",
        "foreach($u in $users){",
        "  $plain=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u.pw));",
        "  $sec=ConvertTo-SecureString $plain -AsPlainText -Force; $plain=$null;",
        "  $f=Get-ADUser -Identity $u.sam -ErrorAction SilentlyContinue;",
        "  if($f){ Write-Output (\"STEP|user|\"+$u.sam+\"|True|exists\") }",
        "  else { New-ADUser -Name $u.full -SamAccountName $u.sam -UserPrincipalName $u.upn -Path $usersPath -Enabled:$true -AccountPassword $sec -PasswordNeverExpires:$false;",
        "    Write-Output (\"STEP|user|\"+$u.sam+\"|False|created\") }",
        "  $sec=$null;",
        "  if($u.grp -and $u.grp.Trim() -ne ''){",
        "    $m=Get-ADGroupMember -Identity $u.grp -ErrorAction SilentlyContinue | Where-Object { $_.SamAccountName -eq $u.sam };",
        "    if($m){ Write-Output (\"STEP|member|\"+$u.sam+\"->\"+$u.grp+\"|True|exists\") }",
        "    else { Add-ADGroupMember -Identity $u.grp -Members $u.sam;",
        "      Write-Output (\"STEP|member|\"+$u.sam+\"->\"+$u.grp+\"|False|added\") } } }",
        "[pscustomobject]@{OrgDN=$orgDN} | ConvertTo-Json -Compress",
    ]
    return " ".join(lines)


def register_provision_org(mcp_instance):
    """Registra el workflow provision_org con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def provision_org(
        machine_dc: str,
        org_name: str,
        ous: list | None = None,
        groups: list | None = None,
        users_csv_json: str = "",
        confirm: bool = False,
        acknowledge: bool = False,
        ack_text: str = "",
    ) -> str:
        """Aprovisiona una organización AD: OU + sub-OUs + grupos + usuarios CSV.

        Orden: OU=org en raíz del dominio > sub-OUs > grupos Global en
        Groups > usuarios en Users (sam,upn,pw_b64) > Add-ADGroupMember.
        Idempotente already_exists por paso. L2 ACK_IRREVERSIBLE.
        """
        validate_not_empty(machine_dc, "machine_dc")
        org = _validate_ou_name(org_name, "org_name")
        ous_list = list(ous) if ous else list(_DEFAULT_OUS)
        ous_list = [_validate_ou_name(o, f"ous[{i}]") for i, o in enumerate(ous_list)]
        groups_list = [str(g).strip() for g in (groups or []) if str(g).strip()]
        for g in groups_list:
            validate_sam(g)
        users = parse_users_csv_json(users_csv_json)
        for u in users:
            if u["group"] and u["group"] not in groups_list:
                raise ValueError(
                    f"users_csv_json: el grupo {u['group']!r} del usuario {u['sam']!r} "
                    f"no está en groups={groups_list}."
                )

        plan = _plan(org, ous_list, groups_list, users)
        gate = require_double_confirm(
            confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, "", "", "provision_org"
        )
        if not gate["ok"]:
            gate["machine"] = machine_dc
            gate["plan"] = plan
            gate["snapshot_reminder"] = SNAPSHOT_REMINDER_L2
            gate["evidence_hint"] = EVIDENCE_DIR_HINT
            audit_log(
                "provision_org", machine_dc,
                f"dry_run org={org} missing={','.join(gate.get('missing', []))}",
            )
            return json.dumps(gate, ensure_ascii=False, indent=2)

        data, preflight_err = preflight_ssh(machine_dc)
        if preflight_err is not None:
            audit_log("provision_org", machine_dc, "abortado: test_ssh falló")
            return preflight_err

        script = build_provision_script(org, ous_list, groups_list, users)
        result = _invoke_ps_b64(data, script, timeout=SSH_TIMEOUT_DEFAULT)
        steps = parse_steps(result.get("stdout", "") or "")
        result["machine"] = machine_dc
        result["os"] = data.get("os", "unknown")
        result["command"] = "[redacted provision_org]"
        result["steps"] = steps
        result["evidence"] = {
            "org": org,
            "plan": plan,
            "summary": {
                k: sum(1 for s in steps if s["step"] == k and not s["already_exists"])
                for k in ("ou", "group", "user", "member")
            },
            "already_existed": sum(1 for s in steps if s["already_exists"]),
        }
        result["snapshot_reminder"] = SNAPSHOT_REMINDER_L2
        result["evidence_hint"] = EVIDENCE_DIR_HINT
        audit_log(
            "provision_org", machine_dc,
            f"L2-ACK org={org} ous={len(ous_list)} groups={len(groups_list)} "
            f"users={len(users)} steps={len(steps)}",
        )
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
