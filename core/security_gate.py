"""
core/security_gate.py - Doble confirmación para tools L2 (Fase 1).

Sin romper `require_confirmation` actual (L1): este módulo añade el
contrato L2 del plan (§3.1) más un decorador único @destructive.

Sin L2 completo la tool NO toca SSH: retorna dry_run con warning
(snapshot VirtualBox + consola) y would_run resumido sin secretos.
"""

import functools

from .validation import require_confirmation

# =============================================================================
# FRASES DE CONFIRMACIÓN (case-sensitive, exactas)
# =============================================================================

ACK_IRREVERSIBLE = "SE-QUE-ES-IRREVERSIBLE"
ACK_SSH = "SE-QUE-PUEDO-PERDER-SSH"
ACK_ROLES = "SE-QUE-INSTALA-ROLES"


# =============================================================================
# CONTRATO L2
# =============================================================================

def require_double_confirm(
    confirm: bool,
    acknowledge: bool,
    ack_text: str,
    expected_ack: str,
    echo: str,
    expected_echo: str,
    tool_name: str,
) -> dict:
    """
    Exige doble confirmación para tools irreversibles o con corte-red.

    Si falta algo retorna {"ok": False, "dry_run": True, "warning": ...,
    "would_run": ...} SIN ejecutar SSH. Con L2 completo retorna
    {"ok": True, "dry_run": False, ...} y el llamador puede ejecutar.

    Args:
        confirm: Primer freno (confirm=true).
        acknowledge: Segundo freno (acknowledge=true).
        ack_text: Frase aportada por el usuario.
        expected_ack: Frase exacta exigida (ACK_*).
        echo: Valor que el usuario repite (ej. domain_name, ip nueva).
        expected_echo: Valor esperado del eco.
        tool_name: Nombre de la tool (para would_run/auditoría).

    Returns:
        Dict con ok/dry_run (+ warning/would_run/missing si incompleto).
    """
    missing: list[str] = []
    if not confirm:
        missing.append("confirm=true")
    if not acknowledge:
        missing.append("acknowledge=true")
    if ack_text != expected_ack:
        missing.append(f"ack_text={expected_ack!r} exacto")
    if echo != expected_echo:
        missing.append("eco del objetivo idéntico")

    if missing:
        return {
            "ok": False,
            "dry_run": True,
            "warning": (
                f"'{tool_name}' es IRREVERSIBLE o puede cortar SSH. "
                "Haz snapshot de VirtualBox AHORA y ten la consola de la VM "
                "abierta antes de reintentar. Faltante: "
                + ", ".join(missing)
                + "."
            ),
            "would_run": f"{tool_name} (objetivo={expected_echo!r})",
            "missing": missing,
        }
    return {"ok": True, "dry_run": False, "tool": tool_name}


# =============================================================================
# DECORADOR ÚNICO
# =============================================================================

def destructive(level: str = "L1", expected_ack: str | None = None):
    """
    Decorador único para tools destructivas.

    - level="L1": usa require_confirmation (ValueError si falta confirm).
    - level="L2": usa require_double_confirm con confirm/acknowledge/
      ack_text de los kwargs y expected_ack del decorador (por defecto
      ACK_IRREVERSIBLE). El eco (kwargs echo/expected_echo) solo se exige
      si la función declara ambos; si no, se omite ese check aquí (la
      tool debe llamar require_double_confirm con su objetivo).
      En fallo L2 lanza ValueError con el warning (sin tocar SSH).

    Args:
        level: "L1" o "L2".
        expected_ack: Frase exacta exigida en L2.
    """
    if level not in ("L1", "L2"):
        raise ValueError(f"Nivel no válido: {level!r}. Usa 'L1' o 'L2'.")
    ack = expected_ack or ACK_IRREVERSIBLE

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            tool = fn.__name__
            if level == "L1":
                require_confirmation(kwargs.get("confirm", False), tool)
            else:
                if "echo" in kwargs or "expected_echo" in kwargs:
                    echo = kwargs.get("echo", "")
                    expected_echo = kwargs.get("expected_echo", "")
                else:
                    # Sin eco declarado: solo frenos confirm/ack.
                    echo = expected_echo = ""
                gate = require_double_confirm(
                    confirm=kwargs.get("confirm", False),
                    acknowledge=kwargs.get("acknowledge", False),
                    ack_text=kwargs.get("ack_text", ""),
                    expected_ack=ack,
                    echo=echo,
                    expected_echo=expected_echo,
                    tool_name=tool,
                )
                if not gate["ok"]:
                    raise ValueError(gate["warning"])
            return fn(*args, **kwargs)

        return wrapper

    return decorator
