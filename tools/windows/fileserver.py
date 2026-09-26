"""
tools/windows/fileserver.py - Shares SMB + NTFS + efectivo (FASE 2D).

Lectura L0: share_list, share_get_effective (Share vs NTFS lado a lado +
regla "efectivo = más restrictivo"), share_test_from_client (Test-Path UNC).
Escritura L2 (ACK_IRREVERSIBLE): share_create, share_grant_access,
share_revoke_access, ntfs_grant (icacls (OI)(CI) + verify Get-Acl).

Seguridad: prohibido Everyone:Full por defecto — cualquier cuenta
Everyone/Todos se rechaza y se exige al menos 1 grupo. Valida share/UNC.
"""

import base64
import json
import logging

from core.audit import audit_log
from core.config import get_machine, SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, require_double_confirm
from core.ssh import build_ssh_args, clean_output, run_process
from core.validation import validate_not_empty
from core.validators import validate_sam, validate_share_name, validate_unc

mcp = None

logger = logging.getLogger(__name__)

EVERYONE_ALIASES = ("everyone", "todos", "todo el mundo", "authenticated users")


def _invoke_ps_b64(data: dict, script: str, timeout: int = SSH_TIMEOUT_DEFAULT) -> dict:
    """Ejecuta un script PS multilínea vía base64 UTF-16LE (EncodedCommand)."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = (
        f"$b64='{encoded}'; "
        f"$bytes=[Convert]::FromBase64String($b64); "
        f"$code=[Text.Encoding]::Unicode.GetString($bytes); "
        f"Invoke-Expression $code"
    )
    return run_process(build_ssh_args(data["ssh_host"], command), timeout=timeout)


def _dry_run(machine: str, confirm: bool, acknowledge: bool, ack_text: str, tool: str):
    """Gate L2 ACK_IRREVERSIBLE: JSON dry_run si falta, None si OK."""
    gate = require_double_confirm(
        confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, "", "", tool)
    if gate["ok"]:
        return None
    gate["machine"] = machine
    audit_log(tool, machine, f"dry_run missing={','.join(gate.get('missing', []))}")
    return json.dumps(gate, ensure_ascii=False, indent=2)


def _ps_array(values: list[str]) -> str:
    """Array PS @('a','b') con literales escapados."""
    items = ",".join(f"'{escape_ps_single_quote(v.strip())}'" for v in values)
    return f"@({items})"


def _validate_share_acls(full: list[str], change: list[str], read: list[str]) -> None:
    """Prohíbe Everyone y exige al menos 1 grupo; valida tipos."""
    for label, lst in (("full", full), ("change", change), ("read", read)):
        if lst is None:
            continue
        if not isinstance(lst, list):
            raise ValueError(f"{label} debe ser una lista de cuentas (ej. ['DOM\\Grupo']).")
        for acct in lst:
            if not acct or not str(acct).strip():
                raise ValueError(f"{label} contiene una cuenta vacía.")
            if str(acct).strip().lower() in EVERYONE_ALIASES:
                raise ValueError(
                    f"Cuenta prohibida en {label}: {acct!r}. "
                    "Everyone:Full está prohibido por defecto; usa grupos de dominio.")
    if not (full or change or read):
        raise ValueError(
            "Debes indicar al menos 1 grupo en full/change/read "
            "(ej. full=['DOM\\Ventas-RW']). Nada de Everyone.")


def register_fileserver(mcp_instance):
    """Registra las herramientas de file server con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def share_list(machine: str) -> str:
        """Lista shares SMB (Get-SmbShare). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-SmbShare "
                  "| Select-Object Name,Path,Description | ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("share_list", machine, "list shares SMB")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def share_get_effective(machine: str, share_name: str,
                            folder_path: str, sam: str) -> str:
        """Permiso efectivo Share vs NTFS lado a lado (regla: más restrictivo). L0."""
        validate_not_empty(machine, "machine")
        validate_share_name(share_name)
        validate_not_empty(folder_path, "folder_path")
        validate_sam(sam)
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$s='{escape_ps_single_quote(share_name.strip())}'; "
            f"$p='{escape_ps_single_quote(folder_path.strip())}'; "
            f"$u='{escape_ps_single_quote(sam)}'; "
            "$share=Get-SmbShareAccess -Name $s "
            "| Select-Object Name,AccountName,AccessRight,AccessControlType; "
            "$ntfs=(Get-Acl -LiteralPath $p).Access "
            "| Select-Object IdentityReference,FileSystemRights,AccessControlType; "
            "[pscustomobject]@{User=$u; ShareAccess=$share; NtfsAccess=$ntfs; "
            "Rule='Efectivo = el mas restrictivo entre Share y NTFS'} "
            "| ConvertTo-Json -Depth 4"
        )
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("share_get_effective", machine,
                  f"efectivo share={share_name} sam={sam}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def share_test_from_client(machine_client: str, unc: str) -> str:
        """Prueba acceso a un UNC desde el cliente (Test-Path). L0."""
        validate_not_empty(machine_client, "machine_client")
        validate_unc(unc)
        data = get_machine(machine_client)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$u='{escape_ps_single_quote(unc.strip())}'; "
                  "$ok=Test-Path -LiteralPath $u; "
                  "[pscustomobject]@{UNC=$u; Reachable=[bool]$ok} "
                  "| ConvertTo-Json -Compress")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine_client
        result["os"] = data.get("os", "unknown")
        audit_log("share_test_from_client", machine_client, f"Test-Path {unc}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def share_create(machine: str, share_name: str, folder_path: str,
                     full: list[str] | None = None, change: list[str] | None = None,
                     read: list[str] | None = None, description: str = "",
                     encrypt: bool = False, abe: bool = True,
                     confirm: bool = False, acknowledge: bool = False,
                     ack_text: str = "") -> str:
        """Crea carpeta + share SMB (AccessBased, sin Everyone). Idempotente. L2."""
        validate_not_empty(machine, "machine")
        validate_share_name(share_name)
        validate_not_empty(folder_path, "folder_path")
        _validate_share_acls(full or [], change or [], read or [])
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "share_create")
        if dry is not None:
            return dry
        data = get_machine(machine)
        s = escape_ps_single_quote(share_name.strip())
        p = escape_ps_single_quote(folder_path.strip())
        d = escape_ps_single_quote(description or "")
        mode = "AccessBased" if abe else "Unrestricted"
        enc = "$true" if encrypt else "$false"
        acl_lines = ""
        if full:
            acl_lines += f" $p2['FullAccess']={_ps_array(full)};"
        if change:
            acl_lines += f" $p2['ChangeAccess']={_ps_array(change)};"
        if read:
            acl_lines += f" $p2['ReadAccess']={_ps_array(read)};"
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$s='{s}'; $path='{p}'; "
            f"if(-not (Test-Path -LiteralPath $path)) "
            "{ New-Item -ItemType Directory -Path $path -Force | Out-Null }; "
            "$ex=Get-SmbShare -Name $s -ErrorAction SilentlyContinue; "
            "if($ex){ Write-Output '__ALREADY_EXISTS__'; "
            "$ex | Select-Object Name,Path,Description | ConvertTo-Json -Compress } "
            "else { $p2=@{Name=$s; Path=$path; Description="
            f"'{d}'; FolderEnumerationMode='{mode}'; EncryptData:{enc}}};"
            + acl_lines +
            " New-SmbShare @p2 | Select-Object Name,Path,Description "
            "| ConvertTo-Json -Compress; Write-Output '__CREATED__' }"
        )
        result = _invoke_ps_b64(data, script)
        result["already_exists"] = "__ALREADY_EXISTS__" in (result.get("stdout", "") or "")
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("share_create", machine,
                  f"L2-ACK share={share_name} path={folder_path} abe={abe}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def share_grant_access(machine: str, share_name: str, account: str,
                           access_right: str = "Read",
                           confirm: bool = False, acknowledge: bool = False,
                           ack_text: str = "") -> str:
        """Otorga acceso Share (Grant-SmbShareAccess Full|Change|Read). L2."""
        validate_not_empty(machine, "machine")
        validate_share_name(share_name)
        validate_not_empty(account, "account")
        if account.strip().lower() in EVERYONE_ALIASES:
            raise ValueError(
                f"Cuenta prohibida: {account!r}. Usa grupos de dominio, no Everyone.")
        if access_right not in ("Full", "Change", "Read"):
            raise ValueError(
                f"access_right no válido: {access_right!r}. Usa Full|Change|Read.")
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "share_grant_access")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$s='{escape_ps_single_quote(share_name.strip())}'; "
                  f"$a='{escape_ps_single_quote(account.strip())}'; "
                  f"Grant-SmbShareAccess -Name $s -AccountName $a "
                  f"-AccessRight {access_right} -Force; "
                  "Get-SmbShareAccess -Name $s "
                  "| Select-Object AccountName,AccessRight | ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("share_grant_access", machine,
                  f"L2-ACK grant share={share_name} account={account} right={access_right}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def share_revoke_access(machine: str, share_name: str, account: str,
                            confirm: bool = False, acknowledge: bool = False,
                            ack_text: str = "") -> str:
        """Revoca acceso Share (Revoke-SmbShareAccess). L2."""
        validate_not_empty(machine, "machine")
        validate_share_name(share_name)
        validate_not_empty(account, "account")
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "share_revoke_access")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$s='{escape_ps_single_quote(share_name.strip())}'; "
                  f"$a='{escape_ps_single_quote(account.strip())}'; "
                  "Revoke-SmbShareAccess -Name $s -AccountName $a -Force; "
                  "Write-Output '__SHARE_ACCESS_REVOKED__'")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("share_revoke_access", machine,
                  f"L2-ACK revoke share={share_name} account={account}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def ntfs_grant(machine: str, folder_path: str, identity: str, rights: str = "RX",
                   confirm: bool = False, acknowledge: bool = False,
                   ack_text: str = "") -> str:
        """Otorga permiso NTFS (icacls (OI)(CI)) + verify Get-Acl. L2."""
        validate_not_empty(machine, "machine")
        validate_not_empty(folder_path, "folder_path")
        validate_not_empty(identity, "identity")
        if rights not in ("F", "M", "RX"):
            raise ValueError(
                f"rights no válido: {rights!r}. Usa F (full), M (modify) o RX (lectura).")
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "ntfs_grant")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$p='{escape_ps_single_quote(folder_path.strip())}'; "
                  f"$i='{escape_ps_single_quote(identity.strip())}'; "
                  f"icacls $p /grant \"$i:(OI)(CI){rights}\" | Out-Null; "
                  "(Get-Acl -LiteralPath $p).Access "
                  "| Where-Object { $_.IdentityReference -like \"*$i*\" } "
                  "| Select-Object IdentityReference,FileSystemRights "
                  "| ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("ntfs_grant", machine,
                  f"L2-ACK ntfs path={folder_path} identity={identity} rights={rights}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
