"""
tools/windows/ad_org.py - OUs/grupos/usuarios/equipos/join (FASE 2B, genérico).

Lectura L0 sin confirm: ad_list_ou/users/groups/computers (Get-AD*, con
search_base DN opcional).
Escritura L2 (ACK_IRREVERSIBLE, sin eco en firma): ad_create_ou/group/user,
ad_set_password/enable/disable_user, ad_add/remove_group_member.
ad_join_domain: L2 ACK_IRREVERSIBLE con eco domain_name (domain_name_confirm).

Idempotencia: Get antes de New -> ok:true, already_exists:true.
Passwords/credenciales como password_b64 (b64 efímero del usuario);
SecureString vía FromBase64String en remoto. Nunca en logs ni en JSON
(command redactado).
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
from core.validators import (
    validate_dn,
    validate_domain_fqdn,
    validate_dns_ip,
    validate_group_scope,
    validate_password_b64,
    validate_sam,
)

mcp = None

logger = logging.getLogger(__name__)

MARK_EXISTS = "__ALREADY_EXISTS__"
MARK_CREATED = "__CREATED__"


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


def _dry_run(machine: str, confirm: bool, acknowledge: bool, ack_text: str,
             echo: str, expected_echo: str, tool: str):
    """Gate L2 ACK_IRREVERSIBLE: JSON dry_run si falta, None si OK."""
    gate = require_double_confirm(
        confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, echo, expected_echo, tool)
    if gate["ok"]:
        return None
    gate["machine"] = machine
    audit_log(tool, machine, f"dry_run missing={','.join(gate.get('missing', []))}")
    return json.dumps(gate, ensure_ascii=False, indent=2)


def _finish(result: dict, machine: str, os_type: str, tool: str,
            detail: str, redact: bool = False) -> str:
    """Añade already_exists, redacta secreto, audita y serializa."""
    out = result.get("stdout", "") or ""
    result["already_exists"] = MARK_EXISTS in out
    result["machine"] = machine
    result["os"] = os_type
    if redact:
        result["command"] = f"[redacted {tool}]"
    audit_log(tool, machine, detail)
    return json.dumps(clean_output(result), ensure_ascii=False, indent=2)


def _searchbase_clause(search_base: str) -> str:
    """Cláusula -SearchBase escapada, o cadena vacía si no se pide."""
    if search_base and search_base.strip():
        validate_dn(search_base)
        return f" -SearchBase '{escape_ps_single_quote(search_base.strip())}'"
    return ""


def register_ad_org(mcp_instance):
    """Registra las herramientas de organización AD con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def ad_list_ou(machine: str, search_base: str = "") -> str:
        """Lista OUs (Get-ADOrganizationalUnit). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-ADOrganizationalUnit -Filter *"
                  + _searchbase_clause(search_base)
                  + " | Select-Object Name,DistinguishedName | ConvertTo-Json -Depth 3")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_list_ou",
                       f"list OU base={search_base or 'dominio'}")

    @mcp.tool()
    def ad_list_users(machine: str, search_base: str = "") -> str:
        """Lista usuarios AD (Get-ADUser). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-ADUser -Filter * "
                  "-Properties Enabled,SamAccountName,UserPrincipalName"
                  + _searchbase_clause(search_base)
                  + " | Select-Object Name,SamAccountName,UserPrincipalName,"
                  "Enabled,DistinguishedName | ConvertTo-Json -Depth 3")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_list_users",
                       f"list users base={search_base or 'dominio'}")

    @mcp.tool()
    def ad_list_groups(machine: str, search_base: str = "") -> str:
        """Lista grupos AD (Get-ADGroup). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-ADGroup -Filter * "
                  "-Properties GroupScope,GroupCategory"
                  + _searchbase_clause(search_base)
                  + " | Select-Object Name,SamAccountName,GroupScope,"
                  "GroupCategory,DistinguishedName | ConvertTo-Json -Depth 3")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_list_groups",
                       f"list groups base={search_base or 'dominio'}")

    @mcp.tool()
    def ad_list_computers(machine: str, search_base: str = "") -> str:
        """Lista equipos AD (Get-ADComputer). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; Get-ADComputer -Filter * "
                  "-Properties Enabled,OperatingSystem"
                  + _searchbase_clause(search_base)
                  + " | Select-Object Name,Enabled,OperatingSystem,"
                  "DistinguishedName | ConvertTo-Json -Depth 3")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_list_computers",
                       f"list computers base={search_base or 'dominio'}")

    @mcp.tool()
    def ad_create_ou(machine: str, ou_name: str, path_dn: str,
                     confirm: bool = False, acknowledge: bool = False,
                     ack_text: str = "") -> str:
        """Crea OU (idempotente: already_exists). L2."""
        validate_not_empty(machine, "machine")
        validate_not_empty(ou_name, "ou_name")
        validate_dn(path_dn)
        dry = _dry_run(machine, confirm, acknowledge, ack_text, "", "", "ad_create_ou")
        if dry is not None:
            return dry
        data = get_machine(machine)
        ou = escape_ps_single_quote(ou_name.strip())
        path = escape_ps_single_quote(path_dn.strip())
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$ou='{ou}'; $path='{path}'; "
            "$found=Get-ADOrganizationalUnit -Filter \"Name -eq '$ou'\" "
            "-SearchBase $path -ErrorAction SilentlyContinue "
            "| Select-Object -First 1; "
            f"if($found){{ Write-Output '{MARK_EXISTS}'; "
            "$found | Select-Object Name,DistinguishedName "
            "| ConvertTo-Json -Compress }} "
            "else { New-ADOrganizationalUnit -Name $ou -Path $path "
            "-ProtectedFromAccidentalDeletion:$false; "
            f"Write-Output '{MARK_CREATED}'; "
            "Get-ADOrganizationalUnit -Identity (\"OU=$ou,$path\") "
            "| Select-Object Name,DistinguishedName | ConvertTo-Json -Compress }"
        )
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_create_ou",
                       f"L2-ACK create OU={ou_name} path={path_dn}")

    @mcp.tool()
    def ad_create_group(machine: str, group_name: str, scope: str = "Global",
                        category: str = "Security", path_dn: str = "",
                        confirm: bool = False, acknowledge: bool = False,
                        ack_text: str = "") -> str:
        """Crea grupo AD (idempotente). scope Global|DomainLocal|Universal. L2."""
        validate_not_empty(machine, "machine")
        validate_not_empty(group_name, "group_name")
        validate_group_scope(scope)
        if category not in ("Security", "Distribution"):
            raise ValueError(
                f"category no válida: {category!r}. Usa Security o Distribution.")
        if path_dn and path_dn.strip():
            validate_dn(path_dn)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_create_group")
        if dry is not None:
            return dry
        data = get_machine(machine)
        grp = escape_ps_single_quote(group_name.strip())
        path_clause = ""
        if path_dn and path_dn.strip():
            path_clause = f" -Path '{escape_ps_single_quote(path_dn.strip())}'"
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$g='{grp}'; "
            "$found=Get-ADGroup -Filter \"Name -eq '$g'\" "
            "-ErrorAction SilentlyContinue | Select-Object -First 1; "
            f"if($found){{ Write-Output '{MARK_EXISTS}'; "
            "$found | Select-Object Name,SamAccountName,GroupScope,"
            "GroupCategory | ConvertTo-Json -Compress }} "
            f"else {{ New-ADGroup -Name $g -SamAccountName $g "
            f"-GroupScope {scope} -GroupCategory {category}{path_clause}; "
            f"Write-Output '{MARK_CREATED}'; "
            "Get-ADGroup -Identity $g | Select-Object Name,SamAccountName,"
            "GroupScope,GroupCategory | ConvertTo-Json -Compress }"
        )
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_create_group",
                       f"L2-ACK create group={group_name} scope={scope}")

    @mcp.tool()
    def ad_create_user(machine: str, full_name: str, sam: str, upn: str, ou_dn: str,
                       password_b64: str, enabled: bool = True,
                       confirm: bool = False, acknowledge: bool = False,
                       ack_text: str = "") -> str:
        """Crea usuario AD (idempotente, SecureString b64). L2 + secreto."""
        validate_not_empty(machine, "machine")
        validate_not_empty(full_name, "full_name")
        validate_sam(sam)
        validate_not_empty(upn, "upn")
        if "@" not in upn:
            raise ValueError(f"upn no válido: {upn!r}. Debe tener forma usuario@dominio.")
        validate_dn(ou_dn)
        validate_password_b64(password_b64)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_create_user")
        if dry is not None:
            return dry
        data = get_machine(machine)
        fn = escape_ps_single_quote(full_name.strip())
        up = escape_ps_single_quote(upn.strip())
        ou = escape_ps_single_quote(ou_dn.strip())
        en = "$true" if enabled else "$false"
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$sam='{escape_ps_single_quote(sam)}'; $fn='{fn}'; "
            f"$upn='{up}'; $ou='{ou}'; $en={en}; "
            f"$pwB64='{password_b64.strip()}'; "
            "$plain=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String($pwB64)); "
            "$sec=ConvertTo-SecureString $plain -AsPlainText -Force; "
            "$plain=$null; "
            "$found=Get-ADUser -Identity $sam -ErrorAction SilentlyContinue; "
            f"if($found){{ Write-Output '{MARK_EXISTS}'; "
            "$found | Select-Object Name,SamAccountName,Enabled "
            "| ConvertTo-Json -Compress }} "
            "else { New-ADUser -Name $fn -SamAccountName $sam "
            "-UserPrincipalName $upn -Path $ou -Enabled:$en "
            "-AccountPassword $sec -PasswordNeverExpires:$false; "
            f"Write-Output '{MARK_CREATED}'; "
            "Get-ADUser -Identity $sam -Properties Enabled "
            "| Select-Object Name,SamAccountName,Enabled "
            "| ConvertTo-Json -Compress }"
        )
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_create_user",
                       f"L2-ACK create user sam={sam} ou={ou_dn}", redact=True)

    @mcp.tool()
    def ad_set_password(machine: str, sam: str, password_b64: str,
                        confirm: bool = False, acknowledge: bool = False,
                        ack_text: str = "") -> str:
        """Restablece password AD (Set-ADAccountPassword -Reset). L2 + secreto."""
        validate_not_empty(machine, "machine")
        validate_sam(sam)
        validate_password_b64(password_b64)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_set_password")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$sam='{escape_ps_single_quote(sam)}'; "
            f"$pwB64='{password_b64.strip()}'; "
            "$plain=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String($pwB64)); "
            "$sec=ConvertTo-SecureString $plain -AsPlainText -Force; "
            "$plain=$null; "
            "Set-ADAccountPassword -Identity $sam -NewPassword $sec -Reset; "
            "Write-Output '__PASSWORD_RESET__'"
        )
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_set_password",
                       f"L2-ACK set password sam={sam}", redact=True)

    @mcp.tool()
    def ad_enable_user(machine: str, sam: str,
                       confirm: bool = False, acknowledge: bool = False,
                       ack_text: str = "") -> str:
        """Habilita cuenta AD (Enable-ADAccount). L2."""
        validate_not_empty(machine, "machine")
        validate_sam(sam)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_enable_user")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$sam='{escape_ps_single_quote(sam)}'; "
                  "Enable-ADAccount -Identity $sam; "
                  "Get-ADUser -Identity $sam -Properties Enabled "
                  "| Select-Object SamAccountName,Enabled | ConvertTo-Json -Compress")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_enable_user",
                       f"L2-ACK enable sam={sam}")

    @mcp.tool()
    def ad_disable_user(machine: str, sam: str,
                        confirm: bool = False, acknowledge: bool = False,
                        ack_text: str = "") -> str:
        """Deshabilita cuenta AD (Disable-ADAccount). L2."""
        validate_not_empty(machine, "machine")
        validate_sam(sam)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_disable_user")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$sam='{escape_ps_single_quote(sam)}'; "
                  "Disable-ADAccount -Identity $sam; "
                  "Get-ADUser -Identity $sam -Properties Enabled "
                  "| Select-Object SamAccountName,Enabled | ConvertTo-Json -Compress")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_disable_user",
                       f"L2-ACK disable sam={sam}")

    @mcp.tool()
    def ad_add_group_member(machine: str, group_sam: str, member_sam: str,
                            confirm: bool = False, acknowledge: bool = False,
                            ack_text: str = "") -> str:
        """Agrega miembro a grupo AD (Add-ADGroupMember). L2."""
        validate_not_empty(machine, "machine")
        validate_sam(group_sam)
        validate_sam(member_sam)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_add_group_member")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$g='{escape_ps_single_quote(group_sam)}'; "
                  f"$m='{escape_ps_single_quote(member_sam)}'; "
                  "Add-ADGroupMember -Identity $g -Members $m; "
                  "Get-ADGroupMember -Identity $g "
                  "| Select-Object Name,SamAccountName | ConvertTo-Json -Depth 3")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_add_group_member",
                       f"L2-ACK add member={member_sam} group={group_sam}")

    @mcp.tool()
    def ad_remove_group_member(machine: str, group_sam: str, member_sam: str,
                               confirm: bool = False, acknowledge: bool = False,
                               ack_text: str = "") -> str:
        """Quita miembro de grupo AD (Remove-ADGroupMember). L2."""
        validate_not_empty(machine, "machine")
        validate_sam(group_sam)
        validate_sam(member_sam)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       "", "", "ad_remove_group_member")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"$g='{escape_ps_single_quote(group_sam)}'; "
                  f"$m='{escape_ps_single_quote(member_sam)}'; "
                  "Remove-ADGroupMember -Identity $g -Members $m -Confirm:$false; "
                  "Write-Output '__MEMBER_REMOVED__'")
        return _finish(_invoke_ps_b64(data, script), machine,
                       data.get("os", "unknown"), "ad_remove_group_member",
                       f"L2-ACK remove member={member_sam} group={group_sam}")

    @mcp.tool()
    def ad_join_domain(machine_client: str, domain_name: str, domain_name_confirm: str = "",
                       ou_dn: str = "", domain_cred_user: str = "",
                       domain_cred_pw_b64: str = "", set_dns_to_dc_ip: str = "",
                       confirm: bool = False, acknowledge: bool = False,
                       ack_text: str = "") -> str:
        """Une equipo al dominio (Add-Computer, sin reboot: reboot_required). L2 con eco domain."""
        validate_not_empty(machine_client, "machine_client")
        validate_domain_fqdn(domain_name)
        validate_not_empty(domain_cred_user, "domain_cred_user")
        validate_password_b64(domain_cred_pw_b64)
        if ou_dn and ou_dn.strip():
            validate_dn(ou_dn)
        if set_dns_to_dc_ip and set_dns_to_dc_ip.strip():
            validate_dns_ip(set_dns_to_dc_ip.strip())
        dry = _dry_run(machine_client, confirm, acknowledge, ack_text,
                       domain_name_confirm, domain_name, "ad_join_domain")
        if dry is not None:
            return dry
        data = get_machine(machine_client)
        dom = escape_ps_single_quote(domain_name.strip())
        user = escape_ps_single_quote(domain_cred_user.strip())
        ou_clause = ""
        if ou_dn and ou_dn.strip():
            ou_clause = (f" -OUPath '{escape_ps_single_quote(ou_dn.strip())}'")
        dns_block = ""
        if set_dns_to_dc_ip and set_dns_to_dc_ip.strip():
            ip = escape_ps_single_quote(set_dns_to_dc_ip.strip())
            dns_block = (
                f"$dcIp='{ip}'; "
                "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "
                "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex "
                "-ServerAddresses $dcIp }; "
                "Test-Connection -ComputerName $dcIp -Count 2 | Out-Null; "
            )
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$domain='{dom}'; $user='{user}'; "
            f"$pwB64='{domain_cred_pw_b64.strip()}'; "
            + dns_block +
            "$plain=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String($pwB64)); "
            "$sec=ConvertTo-SecureString $plain -AsPlainText -Force; "
            "$plain=$null; "
            "$cred=New-Object System.Management.Automation.PSCredential($user,$sec); "
            f"Add-Computer -DomainName $domain{ou_clause} "
            "-Credential $cred -Restart:$false -Force; "
            "Write-Output '__JOIN_OK__ reboot_required:true'"
        )
        result = _invoke_ps_b64(data, script, timeout=300)
        result["reboot_required"] = True
        return _finish(result, machine_client, data.get("os", "unknown"),
                       "ad_join_domain",
                       f"L2-ACK join domain={domain_name} "
                       f"dns_dc={set_dns_to_dc_ip or 'sin-cambio'}",
                       redact=True)
