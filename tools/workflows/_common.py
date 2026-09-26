"""
tools/workflows/_common.py - Helpers compartidos de workflows (FASE 5).

Sin VMs en esta fase: todo el código sigue el patrón base64 UTF-16LE
(EncodedCommand, como tools/advanced.py:65) y nunca ejecuta nada en
importación. Uso solo interno del paquete workflows.
"""

import base64
import json

from core.ssh import SSH_TEST_TIMEOUT, build_ssh_args, clean_output, run_process

# Marcadores idempotentes (Get antes de New): el PS los emite y el
# host los convierte en steps[] con already_exists por paso.
MARK_EXISTS = "__ALREADY_EXISTS__"
MARK_CREATED = "__CREATED__"

# Prefijo de líneas de paso estructuradas: STEP|<kind>|<target>|<True|False>|<detail>
STEP_PREFIX = "STEP|"

# Hints obligatorios en toda respuesta de workflow.
SNAPSHOT_REMINDER_L2 = (
    "Haz snapshot de VirtualBox AHORA y ten la consola de la VM abierta "
    "antes de aplicar cambios L2. Tras aplicar, verifica con test_ssh "
    "(y check_domain_health si toca dominio). Guarda evidencias en logs/evidence/."
)
SNAPSHOT_REMINDER_L0 = (
    "Lectura L0: no cambia nada en la VM (no requiere snapshot). "
    "Antes de cualquier cambio L2 posterior, haz snapshot de VirtualBox "
    "y guarda evidencias en logs/evidence/."
)
EVIDENCE_DIR_HINT = (
    "Guarda este JSON en logs/evidence/<nombre>-<fecha>.json. "
    "Para traer ficheros remotos al host usa download_file "
    "(machine, remote_path, local_path) hacia logs/evidence/."
)


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


def preflight_ssh(machine: str):
    """Preflight lógico test_ssh.

    Returns:
        Tupla (data, error_json): data es el dict de get_machine si el
        SSH responde; si falla, data es None y error_json es el JSON
        de aborto (sin tocar nada más).
    """
    from core.config import get_machine

    data = get_machine(machine)
    result = run_process(
        build_ssh_args(data["ssh_host"], "echo MCP_SSH_OK"),
        timeout=SSH_TEST_TIMEOUT,
    )
    if result.get("ok"):
        return data, None
    abort = {
        "ok": False,
        "preflight": "test_ssh",
        "machine": machine,
        "error": "test_ssh falló: la VM no responde por SSH. Workflow abortado sin cambios.",
        "hint": "Verifica ~/.ssh/config + config/machines.json y que la VM esté encendida.",
        "detail": clean_output(result),
        "snapshot_reminder": SNAPSHOT_REMINDER_L2,
    }
    return None, json.dumps(abort, ensure_ascii=False, indent=2)


def parse_steps(stdout: str) -> list:
    """Convierte líneas STEP|kind|target|already|detail en steps[].

    already: "True" si el recurso ya existía (idempotente), "False" si
    se creó/aplicó ahora.
    """
    steps = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith(STEP_PREFIX):
            continue
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        _, kind, target, already, detail = parts
        steps.append(
            {
                "step": kind,
                "target": target,
                "already_exists": already.strip().lower() == "true",
                "status": "exists" if already.strip().lower() == "true" else "applied",
                "detail": detail.strip(),
            }
        )
    return steps
