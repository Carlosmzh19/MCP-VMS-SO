"""
tools/workflows/evidence.py - Workflow collect_evidence (FASE 5, L0).

Solo lectura: compone ad_get_domain + dns_list + auditpol + GPO +
eventos 4624/4625 en una sola pasada (base64 UTF-16LE) y devuelve el
paquete de evidencia inline + hint de download_file para traer
ficheros al host (logs/evidence/). Sin confirm, sin secretos.
"""

import json
import logging

from core.audit import audit_log
from core.config import SSH_TIMEOUT_DEFAULT
from core.ps_escape import escape_ps_single_quote
from core.validation import validate_not_empty
from core.validators import validate_domain_fqdn

from ._common import (
    EVIDENCE_DIR_HINT,
    SNAPSHOT_REMINDER_L0,
    _invoke_ps_b64,
    preflight_ssh,
)

mcp = None

logger = logging.getLogger(__name__)


def _evidence_script(domain: str) -> str:
    d = escape_ps_single_quote(domain)
    return " ".join(
        [
            "$ErrorActionPreference='Continue';",
            f"$dom='{d}';",
            "function E($n,$obj){",
            "  Write-Output (\"EVID-BEGIN|\"+$n);",
            "  if($null -eq $obj){ Write-Output '(sin datos)' }",
            "  else { $obj | ConvertTo-Json -Depth 4 -Compress | Write-Output };",
            "  Write-Output (\"EVID-END|\"+$n) };",
            "try { $ad=Get-ADDomain -ErrorAction Stop | Select-Object DNSRoot,NetBIOSName,DomainMode,DistinguishedName;",
            "  $fo=Get-ADForest -ErrorAction Stop | Select-Object Name,ForestMode;",
            "  E 'domain' ([pscustomobject]@{Domain=$ad; Forest=$fo}) }",
            "catch { E 'domain' ([pscustomobject]@{Error=$_.Exception.Message}) };",
            "try { $zones=Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName,ZoneType,IsAutoCreated,IsDsIntegrated;",
            "  $recs=Get-DnsServerResourceRecord -ZoneName $dom -ErrorAction Stop | Select-Object -First 50 HostName,RecordType,RecordData;",
            "  E 'dns' ([pscustomobject]@{Zones=$zones; Records=$recs}) }",
            "catch { E 'dns' ([pscustomobject]@{Error=$_.Exception.Message}) };",
            "try { $ap=auditpol /get /category:* 2>&1 | Out-String;",
            "  E 'auditpol' ([pscustomobject]@{Policy=($ap.Trim().Split(\"`n\") | Select-Object -First 60)}) }",
            "catch { E 'auditpol' ([pscustomobject]@{Error=$_.Exception.Message}) };",
            "try { $gpos=Get-GPO -All -ErrorAction Stop | Select-Object -First 20 DisplayName,GpoStatus,CreationTime;",
            "  E 'gpo' ([pscustomobject]@{GPOs=$gpos; Note='Detalle HTML con get_gpo_report'}) }",
            "catch { try { $gr=gpresult /r 2>&1 | Out-String;",
            "  E 'gpo' ([pscustomobject]@{Fallback='gpresult /r'; Report=($gr.Trim().Split(\"`n\") | Select-Object -First 60)}) }",
            "  catch { E 'gpo' ([pscustomobject]@{Error=$_.Exception.Message}) } };",
            "foreach($id in @(4624,4625)){",
            "  try { $ev=Get-WinEvent -LogName Security -FilterXPath (\"*[System[EventID=\"+$id+\"]]\") -MaxEvents 10 -ErrorAction Stop",
            "    | Select-Object TimeCreated,Id,Message;",
            "    E (\"events_\"+$id) ([pscustomobject]@{Count=$ev.Count; Events=$ev}) }",
            "  catch { E (\"events_\"+$id) ([pscustomobject]@{Error=$_.Exception.Message}) } }",
        ]
    )


def parse_evidence(stdout: str) -> dict:
    """Convierte bloques EVID-BEGIN|n ... EVID-END|n en dict."""
    evidence: dict = {}
    current = None
    buf: list = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if s.startswith("EVID-BEGIN|"):
            current = s.split("|", 1)[1]
            buf = []
        elif s.startswith("EVID-END|"):
            if current:
                evidence[current] = "\n".join(buf)[:8000]
            current = None
            buf = []
        elif current is not None:
            buf.append(line.rstrip())
    return evidence


def register_collect_evidence(mcp_instance):
    """Registra el workflow collect_evidence con el servidor MCP."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def collect_evidence(machine: str, domain_name: str) -> str:
        """Recolecta evidencia AD/DNS/auditoría/GPO/eventos 4624-4625. L0.

        Solo lectura. Devuelve el paquete inline + hint de download_file
        para traer ficheros (gpo.html, etc.) al host en logs/evidence/.
        """
        validate_not_empty(machine, "machine")
        validate_domain_fqdn(domain_name)
        domain = domain_name.strip()

        data, err = preflight_ssh(machine)
        if err is not None:
            audit_log("collect_evidence", machine, "abortado: test_ssh falló")
            return err

        result = _invoke_ps_b64(data, _evidence_script(domain), SSH_TIMEOUT_DEFAULT)
        evidence = parse_evidence(result.get("stdout", "") or "")
        out = {
            "ok": result.get("ok", False),
            "machine": machine,
            "domain": domain,
            "evidence": evidence,
            "sections": sorted(evidence.keys()),
            "download_hint": (
                "Para traer ficheros remotos al host usa download_file "
                "(machine, remote_path, local_path) con destino logs/evidence/ "
                "(ej. el gpo.html generado por get_gpo_report). "
                "Formato aceptado por cátedra: HTML/TXT/JSON."
            ),
            "snapshot_reminder": SNAPSHOT_REMINDER_L0,
            "evidence_hint": EVIDENCE_DIR_HINT,
        }
        audit_log(
            "collect_evidence", machine,
            f"evidence {domain} sections={','.join(sorted(evidence.keys()))}",
        )
        return json.dumps(out, ensure_ascii=False, indent=2)
