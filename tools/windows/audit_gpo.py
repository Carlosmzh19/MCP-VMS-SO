"""
tools/windows/audit_gpo.py - Auditoría y GPO (FASE 2E).

Lectura L0: get_audit_policy (auditpol), get_security_events
(4624|4625|4663|5140), get_gpo_report (gpresult + Get-GPOReport).
Escritura L2 (ACK_IRREVERSIBLE + aviso "en dominio preferir GPO"):
enable_audit_subcategory (auditpol /set).
"""

import base64
import json
import logging

from core.audit import audit_log
from core.config import get_machine, SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.security_gate import ACK_IRREVERSIBLE, require_double_confirm
from core.ssh import build_ssh_args, clean_output, run_process
from core.validation import validate_lines, validate_not_empty

mcp = None

logger = logging.getLogger(__name__)

ALLOWED_EVENT_IDS = (4624, 4625, 4663, 5140)
GPO_WARNING = ("Aviso: en dominio la auditoría se gobierna por GPO; "
               "auditpol local es validación rápida y puede ser sobrescrito.")


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


def register_audit_gpo(mcp_instance):
    """Registra las herramientas de auditoría/GPO con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def get_audit_policy(machine: str) -> str:
        """Muestra la política de auditoría (auditpol /get /category:*). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        result = run_process(
            build_ssh_args(data["ssh_host"], "auditpol /get /category:*"),
            timeout=SSH_TIMEOUT_DEFAULT,
        )
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("get_audit_policy", machine, "lectura auditpol")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_security_events(machine: str, event_id: int = 4624,
                            lines: int = 50) -> str:
        """Eventos Security 4624|4625|4663|5140 (Get-WinEvent). L0."""
        validate_not_empty(machine, "machine")
        if int(event_id) not in ALLOWED_EVENT_IDS:
            raise ValueError(
                f"event_id no válido: {event_id!r}. "
                f"Usa uno de {list(ALLOWED_EVENT_IDS)}.")
        validate_lines(lines)
        data = get_machine(machine)
        script = ("$ErrorActionPreference='Stop'; "
                  f"Get-WinEvent -LogName Security -MaxEvents {int(lines)} "
                  f"-FilterXPath \"*[System[EventID={int(event_id)}]]\" "
                  "| Select-Object TimeCreated,Id,LevelDisplayName,Message "
                  "| ConvertTo-Json -Depth 3")
        result = _invoke_ps_b64(data, script)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("get_security_events", machine,
                  f"event_id={event_id} lines={lines}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def get_gpo_report(machine: str) -> str:
        """Reporte GPO (gpresult /r + Get-GPOReport HTML si hay GPMC). L0."""
        validate_not_empty(machine, "machine")
        data = get_machine(machine)
        script = (
            "$ErrorActionPreference='Continue'; "
            "gpresult /r /scope computer; "
            "try { Get-GPOReport -All -ReportType Html "
            "-Path 'C:\\Temp\\gpo_all.html'; "
            "Write-Output '__GPO_HTML__:C:\\Temp\\gpo_all.html' } "
            "catch { Write-Output ('__GPO_HTML_ERROR__:'+$_.Exception.Message) }"
        )
        result = _invoke_ps_b64(data, script, timeout=120)
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        audit_log("get_gpo_report", machine, "reporte gpresult+GPOReport")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)

    @mcp.tool()
    def enable_audit_subcategory(machine: str, subcategory: str,
                                 success: bool = True, failure: bool = True,
                                 confirm: bool = False, acknowledge: bool = False,
                                 ack_text: str = "") -> str:
        """Activa subcategoría auditpol + aviso GPO. L2 ACK_IRREVERSIBLE."""
        validate_not_empty(machine, "machine")
        validate_not_empty(subcategory, "subcategory")
        gate = require_double_confirm(
            confirm, acknowledge, ack_text, ACK_IRREVERSIBLE, "", "",
            "enable_audit_subcategory")
        if not gate["ok"]:
            gate["machine"] = machine
            audit_log("enable_audit_subcategory", machine,
                      f"dry_run missing={','.join(gate.get('missing', []))}")
            return json.dumps(gate, ensure_ascii=False, indent=2)
        data = get_machine(machine)
        sub = escape_ps_single_quote(subcategory.strip())
        s_flag = "enable" if success else "disable"
        f_flag = "enable" if failure else "disable"
        result = run_process(
            build_ssh_args(
                data["ssh_host"],
                f"auditpol /set /subcategory:'{sub}' "
                f"/success:{s_flag} /failure:{f_flag}"),
            timeout=SSH_TIMEOUT_DEFAULT,
        )
        result["machine"] = machine
        result["os"] = data.get("os", "unknown")
        result["gpo_warning"] = GPO_WARNING
        audit_log("enable_audit_subcategory", machine,
                  f"L2-ACK subcategory={subcategory} success={success} failure={failure}")
        return json.dumps(clean_output(result), ensure_ascii=False, indent=2)
