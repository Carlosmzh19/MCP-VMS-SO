"""
tools/windows/ad_forest.py - Bosque/dominio AD (FASE 2A, genérico).

Tools L0 (lectura): ad_check_prereq, ad_get_domain.
Tools L2 (doble confirmación, sin auto-reboot):
  ad_install_roles (ACK_ROLES, timeout 600),
  ad_install_forest (ACK_IRREVERSIBLE + eco domain_name, timeout 600,
    devuelve reboot_required:true),
  ad_restart_after_promote (ACK_SSH: el reinicio corta SSH temporalmente).

Nada hardcodeado: el nombre de dominio es parámetro (validate_domain_fqdn).
El password DSRM viaja como password_b64 (b64 efímero del usuario) y en la VM
se convierte a SecureString vía FromBase64String; nunca en claro, nunca en
logs ni en el JSON de retorno (command redactado).
Scripts largos via base64 UTF-16LE (patrón tools/advanced.py).
"""

import base64
import json
import logging

from core.audit import audit_log
from core.config import get_machine, SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, ACK_ROLES, ACK_SSH, require_double_confirm
from core.ssh import build_ssh_args, clean_output, run_process
from core.validation import validate_not_empty
from core.validators import validate_domain_fqdn, validate_password_b64

mcp = None

logger = logging.getLogger(__name__)

TIMEOUT_ROLES = 600
TIMEOUT_FOREST = 600


def _invoke_ps_b64(data: dict, script: str, timeout: int) -> dict:
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
             expected_ack: str, echo: str, expected_echo: str, tool: str):
    """Gate L2: retorna JSON dry_run si falta confirmación, None si OK."""
    gate = require_double_confirm(
        confirm, acknowledge, ack_text, expected_ack, echo, expected_echo, tool)
    if gate["ok"]:
        return None
    gate["machine"] = machine
    audit_log(tool, machine, f"dry_run missing={','.join(gate.get('missing', []))}")
    return json.dumps(gate, ensure_ascii=False, indent=2)


def register_ad_forest(mcp_instance):
    """Registra las herramientas de bosque/dominio con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def ad_check_prereq(machine: str) -> str:
        """Precheck AD: rol/instalación, módulo ActiveDirectory, dominio/bosque actual (L0)."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Continue'; "
            "$feat=Get-WindowsFeature -Name AD-Domain-Services "
            "| Select-Object Name,Installed,InstallState; "
            "$mod=Get-Module -ListAvailable -Name ActiveDirectory "
            "| Select-Object Name,Version | Select-Object -First 1; "
            "$dom=$null; $for=$null; $domErr=$null; "
            "try { $dom=Get-ADDomain "
            "| Select-Object DNSRoot,NetBIOSName,DomainMode } "
            "catch { $domErr=$_.Exception.Message }; "
            "try { $for=Get-ADForest "
            "| Select-Object Name,ForestMode } catch {}; "
            "$role=(Get-ComputerInfo -Property CsDomainRole).CsDomainRole; "
            "[pscustomobject]@{Feature=$feat; ADModule=$mod; Domain=$dom; "
            "DomainError=$domErr; Forest=$for; CsDomainRole=$role} "
            "| ConvertTo-Json -Depth 4"
        )
        result = _invoke_ps_b64(data, script, SSH_TIMEOUT_DEFAULT)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("ad_check_prereq", machine, "precheck AD DS/dominio/bosque")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def ad_install_roles(machine: str, confirm: bool = False,
                         acknowledge: bool = False, ack_text: str = "") -> str:
        """Instala rol AD-Domain-Services + RSAT-AD-PowerShell. L2 ACK_ROLES, timeout 600."""
        validate_not_empty(machine, "machine")
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       ACK_ROLES, "", "", "ad_install_roles")
        if dry is not None:
            return dry
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            "Install-WindowsFeature -Name AD-Domain-Services "
            "-IncludeManagementTools "
            "| Select-Object Success,RestartNeeded | ConvertTo-Json -Compress; "
            "try { Add-WindowsFeature -Name RSAT-AD-PowerShell "
            "| Out-Null } catch {}; "
            "Get-WindowsFeature -Name AD-Domain-Services "
            "| Select-Object Name,Installed | ConvertTo-Json -Compress"
        )
        result = _invoke_ps_b64(data, script, TIMEOUT_ROLES)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("ad_install_roles", machine, "L2-ACK instala rol AD-DS+RSAT")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def ad_install_forest(machine: str, domain_name: str, safe_mode_pw_b64: str,
                          install_dns: bool = True, domain_name_confirm: str = "",
                          confirm: bool = False, acknowledge: bool = False,
                          ack_text: str = "") -> str:
        """Crea bosque/dominio nuevo (IRREVERSIBLE). L2 ACK_IRREVERSIBLE + eco domain_name. Sin auto-reboot: devuelve reboot_required."""
        validate_not_empty(machine, "machine")
        validate_domain_fqdn(domain_name)
        validate_password_b64(safe_mode_pw_b64)
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       ACK_IRREVERSIBLE, domain_name_confirm, domain_name,
                       "ad_install_forest")
        if dry is not None:
            return dry
        data = get_machine(machine)
        dom = escape_ps_single_quote(domain_name.strip())
        dns_flag = "$true" if install_dns else "$false"
        script = (
            "$ErrorActionPreference='Stop'; "
            f"$domain='{dom}'; "
            f"$pwB64='{safe_mode_pw_b64.strip()}'; "
            "$plain=[Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String($pwB64)); "
            "$sec=ConvertTo-SecureString $plain -AsPlainText -Force; "
            "$plain=$null; "
            # -Force requerido en sesión SSH no interactiva (sin consola para
            # confirmar); -NoRebootOnCompletion evita el reboot automático.
            f"Install-ADDSForest -DomainName $domain "
            f"-SafeModeAdministratorPassword $sec -InstallDns:{dns_flag} "
            "-Force -NoRebootOnCompletion:$true -Confirm:$false; "
            "Write-Output '__FOREST_INSTALLED__ reboot_required:true'"
        )
        result = _invoke_ps_b64(data, script, TIMEOUT_FOREST)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        result["reboot_required"] = True
        result["command"] = "[redacted ad_install_forest]"
        audit_log("ad_install_forest", machine,
                  f"L2-ACK bosque nuevo domain={domain_name} install_dns={install_dns}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def ad_get_domain(machine: str) -> str:
        """Muestra dominio/bosque actual del DC (Get-ADDomain/Get-ADForest). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Stop'; "
            "$dom=Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,"
            "DomainControllersContainer,UsersContainer,ComputersContainer; "
            "$for=Get-ADForest | Select-Object Name,ForestMode,Domains; "
            "[pscustomobject]@{Domain=$dom; Forest=$for} | ConvertTo-Json -Depth 4"
        )
        result = _invoke_ps_b64(data, script, SSH_TIMEOUT_DEFAULT)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("ad_get_domain", machine, "lectura dominio/bosque")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def ad_restart_after_promote(machine: str, confirm: bool = False,
                                 acknowledge: bool = False, ack_text: str = "") -> str:
        """Reinicia la VM tras promover (nunca automático). L2 ACK_SSH. Post: test_ssh + ad_get_domain."""
        validate_not_empty(machine, "machine")
        dry = _dry_run(machine, confirm, acknowledge, ack_text,
                       ACK_SSH, "", "", "ad_restart_after_promote")
        if dry is not None:
            return dry
        data = get_machine(machine)
        result = run_process(
            build_ssh_args(data["ssh_host"], "Restart-Computer -Force"),
            timeout=60,
        )
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        result["note"] = ("Reinicio ordenado: SSH se cortará. "
                          "Verifica con test_ssh y luego ad_get_domain.")
        audit_log("ad_restart_after_promote", machine, "L2-ACK reboot post-promote")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
