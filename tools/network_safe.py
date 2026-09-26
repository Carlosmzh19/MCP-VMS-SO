"""
tools/network_safe.py - Preflight de red segura (Fase 4).

Tool L0 `network_preflight`: valida en HOST (sin SSH, sin cambios) los
parámetros de un futuro cambio de red y devuelve checks + warnings +
recordatorio de snapshot. Usado también por set_ip/dns[_linux] y
netplan_set/apply para enriquecer su dry_run L2.
"""

import ipaddress
import json
import logging

from core.audit import audit_log
from core.config import get_machine
from core.validation import validate_not_empty
from core.validators import (
    validate_dns_ip,
    validate_gateway_in_subnet,
    validate_ip,
    validate_prefix,
)

mcp = None

logger = logging.getLogger(__name__)

SNAPSHOT_REMINDER = "haz snapshot VirtualBox + consola abierta"

POST_CHECK_HINT = (
    "verifica con test_ssh + get_network_config en 60s; "
    "si no vuelve revierte por consola (.bak netplan / ip anterior)"
)

SSH_CUT_WARNING = (
    "ADVERTENCIA corte-SSH: un cambio de IP/gateway/DNS o Netplan "
    "erróneo puede aislar la VM. Sin L2 completo NO se ejecuta nada."
)

PUBLIC_DNS = frozenset({
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "192.168.1.1",
})


def build_preflight(
    new_ip: str = "",
    prefix=None,
    gateway: str = "",
    new_dns: str = "",
) -> dict:
    """Calcula checks + warnings de un cambio de red (solo host, sin SSH).

    No lanza: cada validación fallida se registra en checks y genera un
    warning accionable. No ejecuta ningún cambio.
    """
    checks: dict = {}
    warnings: list = []

    ip_ok = False
    prefix_ok = False
    prefix_val = None

    if new_ip:
        try:
            validate_ip(new_ip.strip())
            checks["new_ip"] = "ok"
            ip_ok = True
        except ValueError as exc:
            checks["new_ip"] = str(exc)
            warnings.append(str(exc))

    if prefix is not None and str(prefix).strip() != "" and str(prefix) != "0":
        try:
            validate_prefix(prefix)
            prefix_val = int(prefix)  # type: ignore[arg-type]
            checks["prefix"] = "ok"
            prefix_ok = True
        except ValueError as exc:
            checks["prefix"] = str(exc)
            warnings.append(str(exc))

    if ip_ok and prefix_ok:
        try:
            network = ipaddress.ip_network(
                f"{new_ip.strip()}/{prefix_val}", strict=False
            )
            checks["network"] = str(network)
            checks["same_subnet_calc"] = (
                f"{new_ip.strip()}/{prefix_val} -> red {network}"
            )
        except ValueError as exc:
            checks["network"] = str(exc)
            warnings.append(str(exc))

    if gateway:
        try:
            validate_ip(gateway.strip())
            checks["gateway_format"] = "ok"
        except ValueError as exc:
            checks["gateway_format"] = str(exc)
            warnings.append(str(exc))
        else:
            if ip_ok and prefix_ok:
                try:
                    validate_gateway_in_subnet(
                        new_ip.strip(), prefix_val, gateway.strip()
                    )
                    checks["gateway_in_subnet"] = "ok"
                except ValueError as exc:
                    checks["gateway_in_subnet"] = str(exc)
                    warnings.append(
                        str(exc)
                        + " Si se aplica igual, la VM puede perder "
                        "su ruta por defecto (corte SSH)."
                    )
            else:
                warnings.append(
                    "gateway aportado pero sin new_ip/prefix válidos: "
                    "no se pudo comprobar misma subred."
                )

    if new_dns:
        try:
            validate_dns_ip(new_dns.strip())
            checks["new_dns"] = "ok"
        except ValueError as exc:
            checks["new_dns"] = str(exc)
            warnings.append(str(exc))
        else:
            if new_dns.strip() in PUBLIC_DNS:
                warnings.append(
                    f"dns {new_dns.strip()!r} parece público/residencial. "
                    "Si el objetivo es unir a dominio, apunta al DC en vez "
                    "del DNS público: con 8.8.8.8/1.1.1.1/192.168.1.1 el "
                    "dominio dejará de resolver."
                )

    if not new_ip and not gateway and not new_dns:
        checks["empty"] = (
            "sin new_ip/gateway/new_dns: solo recordatorio de snapshot."
        )

    return {"checks": checks, "warnings": warnings}


def register(mcp_instance):
    """Registra la herramienta L0 network_preflight."""
    global mcp
    mcp = mcp_instance

    @mcp.tool()
    def network_preflight(
        machine: str,
        new_ip: str = "",
        prefix: int = 0,
        gateway: str = "",
        new_dns: str = "",
    ) -> str:
        """Preflight de cambio de red (L0, sin SSH ni cambios).

        Valida con validators (ip/prefix/gateway_in_subnet/dns), calcula
        la subred resultante y avisa si el gateway queda fuera de subred
        o si el DNS es público cuando el objetivo parece un dominio.
        No ejecuta ningún cambio en la VM.
        """
        validate_not_empty(machine, "machine")
        # Solo lectura de config local (existencia); sin SSH.
        get_machine(machine)

        real_prefix = prefix if prefix else None
        preflight = build_preflight(
            new_ip=new_ip or "",
            prefix=real_prefix,
            gateway=gateway or "",
            new_dns=new_dns or "",
        )

        audit_log("network_preflight", machine, "preflight L0 sin SSH")
        return json.dumps(
            {
                "ok": True,
                "dry_run": True,
                "tool": "network_preflight",
                "machine": machine,
                **preflight,
                "snapshot_reminder": SNAPSHOT_REMINDER,
            },
            ensure_ascii=False,
            indent=2,
        )
