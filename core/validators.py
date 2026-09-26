"""
core/validators.py - Validadores estrictos para parámetros de tools (Fase 1).

Convención: cada validador no retorna nada en éxito y lanza ValueError
con mensaje accionable en fallo. Excepción: validate_password_b64 retorna
el secreto decodificado (solo en memoria, nunca loguearlo).

Usar en: ad_* (dominio/DN/sam), dns_*, share_*/ntfs_*, set_ip/dns,
netplan_*, realm_*.
"""

import base64
import binascii
import ipaddress
import re

# =============================================================================
# RED
# =============================================================================

_IPV4_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4_RE = re.compile(rf"^{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}\.{_IPV4_OCTET}$")


def validate_ip(ip: str) -> None:
    """
    Valida una IPv4 (4 octetos 0-255).

    Raises:
        ValueError: Si no es una IPv4 válida.
    """
    if not ip or not isinstance(ip, str) or not _IPV4_RE.match(ip.strip()):
        raise ValueError(
            f"IP no válida: {ip!r}. Debe ser IPv4 con 4 octetos 0-255 "
            "(ej. 192.168.10.20)."
        )


def validate_prefix(prefix: int) -> None:
    """
    Valida un prefijo de red IPv4 (1-32).

    Raises:
        ValueError: Si está fuera de rango.
    """
    try:
        value = int(prefix)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError(
            f"Prefijo no válido: {prefix!r}. Debe ser un entero 1-32 (ej. 24)."
        ) from None
    if value < 1 or value > 32:
        raise ValueError(
            f"Prefijo no válido: {prefix!r}. Debe estar entre 1 y 32 (ej. 24)."
        )


def validate_gateway_in_subnet(ip: str, prefix: int, gateway: str) -> None:
    """
    Valida que el gateway esté en la misma subred que ip/prefix.

    Raises:
        ValueError: Con mensaje accionable si no comparten subred.
    """
    validate_ip(ip)
    validate_ip(gateway)
    validate_prefix(prefix)
    network = ipaddress.ip_network(f"{ip.strip()}/{int(prefix)}", strict=False)
    if ipaddress.ip_address(gateway.strip()) not in network:
        raise ValueError(
            f"Gateway {gateway!r} fuera de la subred de {ip!r}/{prefix} "
            f"(red {network}). Ajusta gateway o prefijo; un gateway erróneo "
            "puede aislar la VM (corte SSH)."
        )


def validate_dns_ip(ip: str) -> None:
    """
    Valida una IP de servidor DNS (IPv4 válida, no 0.0.0.0).

    Raises:
        ValueError: Si no es válida o es 0.0.0.0.
    """
    validate_ip(ip)
    if ip.strip() == "0.0.0.0":
        raise ValueError(
            "DNS no válido: 0.0.0.0. Usa la IP del DC para unir a dominio "
            "o un DNS alcanzable (ej. 192.168.1.10)."
        )


# =============================================================================
# IDENTIDAD / DIRECTORIO
# =============================================================================

_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def validate_domain_fqdn(name: str) -> None:
    """
    Valida un nombre de dominio FQDN (ej. lab.test).

    Raises:
        ValueError: Si no cumple el formato.
    """
    if not name or not isinstance(name, str) or not _FQDN_RE.match(name.strip()):
        raise ValueError(
            f"Dominio no válido: {name!r}. Debe ser un FQDN "
            "(ej. lab.test, corp.ejemplo.com)."
        )


_LDAP_FORBIDDEN_RE = re.compile(r"[\*\(\)\\\x00\n\r]")


def validate_dn(dn: str) -> None:
    """
    Valida un Distinguished Name (ej. OU=Ventas,DC=lab,DC=test).

    Exige contenido DC= y rechaza caracteres básicos de inyección LDAP.

    Raises:
        ValueError: Si está vacío, no contiene DC= o trae caracteres
            prohibidos (*, paréntesis, backslash, NUL, saltos de línea).
    """
    if not dn or not str(dn).strip():
        raise ValueError(
            "DN no puede estar vacío (ej. OU=Ventas,DC=lab,DC=test)."
        )
    text = str(dn).strip()
    if "DC=" not in text.upper():
        raise ValueError(
            f"DN no válido: {dn!r}. Debe contener al menos un componente DC= "
            "(ej. OU=Ventas,DC=lab,DC=test)."
        )
    if _LDAP_FORBIDDEN_RE.search(text):
        raise ValueError(
            f"DN no válido: {dn!r}. Contiene caracteres prohibidos "
            "(*, paréntesis, backslash o saltos de línea)."
        )


_SAM_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")


def validate_sam(sam: str) -> None:
    """
    Valida un sAMAccountName (máx. 20 caracteres).

    Raises:
        ValueError: Si no cumple ^[A-Za-z0-9._-]{1,20}$.
    """
    if not sam or not isinstance(sam, str) or not _SAM_RE.match(sam):
        raise ValueError(
            f"sAMAccountName no válido: {sam!r}. Solo [A-Za-z0-9._-], "
            "máximo 20 caracteres (ej. alu01)."
        )


_GROUP_SCOPES = ("Global", "DomainLocal", "Universal")


def validate_group_scope(scope: str) -> None:
    """
    Valida el ámbito de un grupo AD (Global|DomainLocal|Universal).

    Raises:
        ValueError: Si no es uno de los valores permitidos.
    """
    if scope not in _GROUP_SCOPES:
        raise ValueError(
            f"Ámbito de grupo no válido: {scope!r}. "
            f"Valores válidos: {', '.join(_GROUP_SCOPES)}."
        )


# =============================================================================
# FILE SERVER
# =============================================================================

_SHARE_RE = re.compile(r"^[^\\/:*?\"<>|]{1,80}$")


def validate_share_name(name: str) -> None:
    """
    Valida un nombre de recurso compartido (máx. 80 caracteres).

    Raises:
        ValueError: Si contiene \\/:*?"<>| o es . / ..
    """
    if not name or not isinstance(name, str):
        raise ValueError("share_name no puede estar vacío (ej. Datos).")
    text = name.strip()
    if text in (".", ".."):
        raise ValueError(f"share_name no válido: {name!r}.")
    if text != name or name != name.strip() or text.endswith((".", " ")):
        raise ValueError(
            f"share_name no válido: {name!r}. Sin espacios al inicio/fin "
            "ni punto/espacio final."
        )
    if not _SHARE_RE.match(text):
        raise ValueError(
            f"share_name no válido: {name!r}. Prohibidos "
            r"\\ / : * ? \" < > |, máximo 80 caracteres."
        )


_UNC_RE = re.compile(r"^\\\\[^\\]+\\[^\\]+.*$")


def validate_unc(unc: str) -> None:
    """
    Valida una ruta UNC (ej. \\\\SRV\\Datos).

    Raises:
        ValueError: Si no tiene forma \\\\servidor\\recurso.
    """
    if not unc or not isinstance(unc, str) or not _UNC_RE.match(unc.strip()):
        raise ValueError(
            r"UNC no válida: {!r}. Debe tener forma \\servidor\recurso "
            r"(ej. \\SRV\Datos).".format(unc)
        )


# =============================================================================
# NETPLAN / YAML (sin pyyaml: validación básica)
# =============================================================================

def validate_yaml_safe(text: str) -> None:
    """
    Validación básica de YAML de Netplan sin pyyaml.

    Prohíbe tabs, exige indentación con espacios en múltiplos de 2 y
    al menos un par clave: valor. No sustituye a `netplan generate`
    en la VM, solo evita subir YAML roto.

    Raises:
        ValueError: Con número de línea si el texto no es YAML plausible.
    """
    if not text or not isinstance(text, str) or not text.strip():
        raise ValueError("El contenido YAML no puede estar vacío.")
    if "\t" in text:
        raise ValueError(
            "YAML no válido: contiene tabuladores. Usa espacios "
            "(indentación de 2 espacios, estilo Netplan)."
        )
    has_mapping = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if indent % 2 != 0:
            raise ValueError(
                f"YAML no válido en línea {lineno}: indentación de {indent} "
                "espacios (debe ser múltiplo de 2)."
            )
        if ":" in stripped or stripped.startswith("- "):
            has_mapping = True
    if not has_mapping:
        raise ValueError(
            "YAML no válido: no contiene ningún par 'clave: valor'. "
            "Revisa la sintaxis de Netplan."
        )


# =============================================================================
# DOBLE CONFIRMACIÓN
# =============================================================================

def validate_ack_text(ack_text: str, expected: str) -> None:
    """
    Valida que la frase de confirmación sea exacta (case-sensitive).

    Raises:
        ValueError: Si no coincide exactamente.
    """
    if ack_text != expected:
        raise ValueError(
            f"ack_text incorrecto. Debes repetir exactamente {expected!r} "
            "(sensible a mayúsculas)."
        )


# =============================================================================
# PASSWORDS (Decisión 3: b64 aportado por el usuario, nunca en claro)
# =============================================================================

def validate_password_b64(password_b64: str, min_length: int = 8) -> str:
    """
    Valida un password en base64: b64 válido, decodificable a UTF-8 y
    con longitud mínima (8 por defecto; en DC se advierte si <12).

    Args:
        password_b64: Secreto en base64 (UTF-8).
        min_length: Longitud mínima del secreto decodificado.

    Returns:
        El secreto decodificado (solo en memoria; nunca loguearlo).

    Raises:
        ValueError: Si no es base64 válido, no es UTF-8 o es corto.
    """
    if not password_b64 or not str(password_b64).strip():
        raise ValueError("password_b64 no puede estar vacío.")
    try:
        raw = base64.b64decode(str(password_b64).strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("password_b64 no es base64 válido.") from None
    try:
        secret = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "password_b64 no decodifica a UTF-8 válido."
        ) from None
    if len(secret) < min_length:
        raise ValueError(
            f"password_b64 demasiado corto: {len(secret)} caracteres, "
            f"mínimo {min_length}."
        )
    return secret
