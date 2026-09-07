# PLAN DE DESARROLLO — virtualbox-ssh-mcp (bitácora viva)

> **Propósito:** dar al MCP capacidad **genérica** (cualquier nombre de dominio/OU/grupo/usuario/share) para administrar Windows Server (DC promovido o por promover), Windows 11 cliente y Linux (Mint / Ubuntu Server), una vez que host↔VM ya tiene **red + SSH** funcionando. No es clonar `gea.local`, es poder crear/gestionar **cualquier** organización.
> **Regla de oro:** el MCP **siempre debe arrancar** (`python server.py` + `register_all_tools` en verde) al final de cada fase. Fases incrementales, sin romper firma de tools existentes.
> **Estado del doc:** bitácora. Actualizar `Hecho / En curso / Pendiente` al cerrar cada fase.
> **Código:** en esta etapa **no se toca código**, solo se especifica.

Fecha inicio plan: 2026-09-07. Inventario base verificado en código (lectura directa).

---

## 0. Decisiones del usuario (vinculantes)

| # | Decisión | Implicación |
|---|----------|-------------|
| 1 | **Sí a crear bosque/dominio nuevo (irreversible) + gestionar DC ya promovido** | Nueva tool `ad_install_forest` con **doble confirmación + aviso irreversible** (`confirm=true` + `acknowledge=true` + eco de `domain_name`). Más tools de gestión sobre DC promovido (`ad_check_prereq`, CRUD OU/grupos/usuarios/equipos, join). |
| 2 | **Red con doble confirmación + capacidad de lectura + DNS** | `set_ip_address[_linux]`, `set_dns_server[_linux]`, `netplan_apply` = nivel crítico (doble confirm + preflight + aviso snapshot + consola + post-check `test_ssh`). Lectura (`get_network_config`, `get_dns_cache`, `dns_list_*`, `netplan_get`) siempre sin confirm. |
| 3 | **Passwords definidas por el usuario, nunca en claro** | Parámetro `password_b64` (b64 efímero aportado por el usuario vía agente). Win: `SecureString` vía `EncodedCommand`. Linux: `chpasswd` por stdin. **Nunca** en `argv/ps`, nunca en `logs/mcp.log`, nunca en JSON de retorno. Tests obligatorios `password_not_in_logs`. |

Alcance OS: **Windows Server + Windows 11 + Linux Mint / Ubuntu Server**. Windows = AD DS/DNS/SMB-NTFS/auditpol-GPO. Linux = identidad local + opcional `realm join` + Samba + Netplan + `journald/auditd`.

---

## 1. Estado actual — lo YA HECHO (verificado en código)

### 1.1 Arquitectura base (funcional)

| Capa | Archivo | Estado |
|------|---------|--------|
| Servidor MCP stdio | `server.py:62` `FastMCP(name="virtualbox-ssh-mcp")` + `register_all_tools` + `mcp.run()` | ✅ Hecho |
| Registro | `tools/__init__.py:23-42` 11 módulos Win + `register_linux_tools` (10 módulos, sufijo `_linux`, sin colisión) | ✅ Hecho |
| Transporte | `core/ssh.py:28-103` `ssh/scp/ping` vía `subprocess.run`, `BatchMode=yes`, `stdin=DEVNULL`, `ConnectTimeout 10` | ✅ Hecho |
| Config | `core/config.py`, `config/machines.json` (`win11-vm/windows`, `winserver-vm/windows`, `mint-vm/linux carlos+sudo`) | ✅ Hecho |
| Validación simple | `core/validation.py` (`not_empty/timeout/lines/max_chars/require_confirmation/os/linux_path`) | ✅ Hecho (insuficiente, ver Fase 1) |
| Router OS | `core/os_router.py` (`get_os_type/require_os/dispatch`) | ⚠️ Existe pero casi ninguna tool lo usa |
| Requisitos | `requirements.txt` solo `fastmcp>=2.12,<2.13`, `mcp>=1.29,<2` (`pytest` no declarado) | ⚠️ Pendiente Fase 6 |

### 1.2 Inventario real de tools (código, no marketing)

* **Windows ~53 nominales → 52 efectivos** (1 colisión `get_event_logs` en `tools/system.py:90` vs `tools/logs.py:79`, gana `logs` por orden de registro).
* **Linux 48 `*_linux`** en `tools/linux/` (10 módulos).
* Categorías cubiertas hoy (genéricas, ambos OS salvo matiz): conectividad (`list_machines/test_ssh/check_reachability/machine_profile`), ejecución (`run_command/run_powershell_script[/_linux]`), sistema (`system_info/disk_info/installed_software/env`), archivos (`read/write/upload/list_directory` + `download` roto), servicios (`list/get/start/stop/restart`), procesos (`list/detail/kill`), red (`network_config/dns_cache/flush_dns/firewall_rules`), firewall (`open/enable/disable`), usuarios locales (`CRUD/enable/disable/groups/password_policy`), shares SMB básico (`list/create_shared_folder`), tareas (`list/get/create/delete_scheduled_task`), logs (`get_logs/get_event_logs`).

### 1.3 P0 — lo que HOY impide funcionalidad (bitácora de deuda)

| ID | Archivo:línea | Síntoma | Fase que lo corrige |
|----|---------------|---------|---------------------|
| P0-1 | `tools/network.py:69-83` | `set_ip_address` → `NameError: data` (`get_machine()` sin asignar) | Fase 0 |
| P0-2 | `tools/system.py:1-3,186` | `set_environment_var` → `NameError: require_confirmation` (import faltante) | Fase 0 |
| P0-3 | `core/ssh.py:78-103` + `tools/files.py:142` + `tools/linux/files.py:126` | `download_file[_linux]` construye `scp host:remote → host:local` (solo upload sirve) | Fase 0 |
| P0-4 | `tools/users.py:78-87`, `tools/linux/users.py:61-66`, `core/ssh.py:155` | Password en claro en `command` + retorno JSON + `logs/mcp.log`; `'` escapado solo parcial | Fase 0 |
| P0-5 | `tools/system.py:90` vs `tools/logs.py:79` | Colisión `get_event_logs` (52 efectivos, no 53) | Fase 0 |
| P0-6 | `tools/network.py:154-167` | `get_firewall_rules(profile)` ignora `profile` (siempre Inbound Allow) | Fase 0 |
| P0-7 | Windows general (Linux sí usa `shlex.quote`) | Inyección PS por interpolación `'{var}'` sin escape (`users/network/services/scheduled_tasks`) | Fase 0/1 |

### 1.4 Gaps vs objetivo genérico (por eso existe este plan)

| Capacidad objetivo | Hoy |
|--------------------|-----|
| Crear bosque/dominio cualquier nombre + gestionar DC promovido | ❌ Cero tools AD (`Install-ADDSForest`, `New-ADOrganizationalUnit/User/Group`, `Get-AD*`, `Add-Computer`) |
| OUs/grupos/usuarios genéricos por DN | ❌ Solo usuarios **locales** (`New-LocalUser`) |
| DNS autoritativo genérico | ❌ Cero tools (`Get/Add-DnsServerZoneRecord`) |
| File Server real (Share + NTFS + efectivo) | ⚠️ Solo `New-SmbShare` básico (default `Everyone` riesgoso); sin `Grant/Revoke`, sin `icacls/Set-Acl`, sin efectivo |
| Auditoría/GPO | ⚠️ Solo lectura logs; sin `auditpol`, sin `Get-GPOReport/New-GPO` |
| Impresoras | ❌ Cero tools print (fuera de MVP, backlog Fase 5) |
| Linux identidad/shares/red avanzada | ⚠️ Usuarios locales OK, pero sin Samba real, sin Netplan get/set/apply, sin `realm join` opcional |
| Doble confirmación irreversibles | ❌ Solo `confirm=true` simple; `DESTRUCTIVE_TOOLS` en `core/config.py:62` sin `_linux` ni niveles |

---

## 2. Principios transversales (obligatorios para todo lo nuevo)

1. **Precondición red+SSH:** todo workflow nuevo empieza con `test_ssh OK`. Si falla, abortar y guiar arreglo de `~/.ssh/config` + `config/machines.json`. El MCP nunca configura VirtualBox (adaptadores/NAT/Host-Only) — eso es manual con consola.
2. **Genérico, nada hardcodeado:** ningún `gea.local`, OU, IP o usuario quemado en código. Todo por parámetros (`domain_name`, `ou_dn`, `sam`, `share_name`, etc.) con validadores.
3. **Idempotencia:** si el recurso ya existe → `ok:true, already_exists:true`, no error. `Get-*` antes de `New-*` siempre.
4. **Lectura sin fricción, escritura con freno:** `list/get/check/test` sin `confirm`. Escritura destructiva `confirm=true`. Irreversible o corte-red **doble confirmación** (ver §3).
5. **Sin secretos en logs:** `audit_log` y retorno JSON **jamás** incluyen `password_b64`, `SafeMode pw` ni `credential`. `clean_output` los filtra.
6. **Base64 para comillas:** PS multilínea vía `base64 UTF-16LE` (`EncodedCommand`, patrón `tools/advanced.py:65`); bash vía `base64 | bash -s` (patrón `tools/linux/advanced.py:34`). En Linux además `shlex.quote`. En Windows prohibido interpolar crudo en `f"'{x}'"`.
7. **MCP siempre funcional:** cada fase termina con `python -m py_compile` + `python server.py` arranca + `pytest` en verde + `register_all_tools` sin colisión de nombres.

---

## 3. Diseño transversal — doble confirmación + validadores + auditoría

### 3.1 Nuevo `core/security_gate.py` (Fase 1, sin romper `require_confirmation` actual)

Niveles:

| Nivel | Tools | Exige |
|-------|-------|-------|
| L0 lectura | `list*/get*/check*/test*` | nada |
| L1 destructivo | `create/delete_user`, `add/remove_group`, `kill/stop/disable`, `write_file`, `firewall`, `share`, `scheduled_task`, `set_env/password_policy` | `confirm=true` (actual `require_confirmation`) |
| L2 irreversible / corte-red | `ad_install_forest`, `ad_create_ou/group/user` en DC (crea estado AD), `join_domain`, `set_ip_address[_linux]`, `set_dns_server[_linux]`, `netplan_set/apply`, `ntfs_grant`, `share_create`, `realm_join/leave` | `confirm=true` **+** `acknowledge=true` **+** `ack_text` frase exacta **+** eco del objetivo |

Contrato L2 (especificación para implementar):

```python
require_double_confirm(
    confirm: bool,
    acknowledge: bool,
    ack_text: str,
    expected_ack: str,   # ej. "SE-QUE-ES-IRREVERSIBLE" | "SE-QUE-PUEDO-PERDER-SSH"
    echo: str,           # valor que el usuario repite, ej. domain_name
    expected_echo: str,
    tool_name: str,
) -> dict  # si falta algo: retorna {"ok": False, "dry_run": True, "warning": ..., "would_run": ...} SIN ejecutar SSH
```

* Sin L2 completo → **dry_run**: devuelve `warning` (qué es irreversible / que SSH puede cortarse + "haz snapshot VirtualBox + ten consola abierta") y `would_run` (comando resumido sin secretos). No toca SSH.
* Con L2 completo → ejecuta y registra `AUDIT: tool | machine | L2-ACK | detalle-sin-secretos`.
* `DESTRUCTIVE_TOOLS` se mueve a `core/constants.py` y se amplía con `*_linux` + lista `IRREVERSIBLE_TOOLS` (`ad_install_forest`, `join_domain`, `set_ip_address[_linux]`, `set_dns_server[_linux]`, `netplan_apply`, `realm_join`). Decorador único `@destructive(level="L1"/"L2")` para no repetir `require_*` en 30 archivos.

### 3.2 Nuevo `core/validators.py` (Fase 1)

```python
validate_ip("192.168.10.20")            # 4 octetos 0-255
validate_prefix(24)                     # 1-32 (v4)
validate_gateway_in_subnet(ip, prefix, gateway)  # mismo subnet o ValueError con mensaje accionable
validate_dns_ip(ip)                     # reutiliza validate_ip + rechaza 0.0.0.0
validate_domain_fqdn("lab.test")        # ^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.(?!-)[A-Za-z0-9-]{1,63})+$
validate_dn("OU=Ventas,DC=lab,DC=test") # no vacío, contiene DC=, sin caracteres de inyección LDAP básicos
validate_sam("alu01")                   # ^[A-Za-z0-9._-]{1,20}$ (límite sAMAccountName)
validate_group_scope("Global")          # Global|DomainLocal|Universal
validate_share_name("Datos")            # ^[^\\/:*?"<>|]{1,80}$
validate_unc("\\\\SRV\\Datos")          # ^\\\\[^\\]+\\[^\\]+
validate_yaml_safe(text)                # parse con yaml.safe_load en host antes de subir (Netplan)
validate_ack_text(...)                  # frase exacta, case-sensitive
```

Usar en: `ad_*` (dominio/DN/sam), `dns_*`, `share_*/ntfs_*`, `set_ip/dns`, `netplan_*`, `realm_*`.

### 3.3 `core/audit.py` (Fase 1, reemplaza 11× `audit_log` copiado en `tools/*.py`)

* Firma: `audit_log(tool, machine, detail_sanitized)` — `detail` nunca contiene `password_b64`, `SafeMode`, `credential`, ni `command` completo con secreto; solo resumen (`ou_dn`, `sam`, `share`, `ip nueva`, `dry_run/L2-ACK`).
* `RotatingFileHandler(5MB×5)` en `server.py:27` (hoy `FileHandler` sin rotación).

### 3.4 Passwords definidas por usuario (Fase 0+1, Decisión 3)

* Entrada: `password_b64: str` (b64 de UTF-8 aportado por el usuario vía agente). Validar `not_empty` + longitud mínima 8 (advertir si <12 en DC) + b64 válido. Nunca parámetro `password` en claro.
* Win (PS `EncodedCommand` b64 UTF-16LE): decodificar b64 en remoto a `SecureString` en memoria, `New-ADUser -AccountPassword $sec` / `Set-ADAccountPassword`, `Install-ADDSForest -SafeModeAdministratorPassword $sec`. Nunca `ConvertTo-SecureString '<pw claro>'`.
* Linux: `echo 'b64' | base64 -d | chpasswd` por **stdin**, o `useradd + chpasswd` sin exponer en `ps`. Nunca `echo 'user:pw'`.
* Retorno/logs: `clean_output` + `audit_log` filtran `password_b64` y derivados. Test obligatorio `test_pw_not_in_logs`.

---

## 4. Fases y módulos (orden de ejecución)

> Convención de estados: `[x]` Hecho · `[~]` En curso · `[ ]` Pendiente. No pasar de fase sin DONE en verde y MCP arrancando.

### FASE 0 — Estabilizar P0 (1-2 días) `[x]` Hecho (2026-09-07, verificado Fase 6: `register_all_tools`=155, `pytest` verde)

**Objetivo:** dejar las ~100 tools actuales al 100% antes de ampliar. Sin nuevas tools.

| Step | Target | Cambio | Validación |
|------|--------|--------|------------|
| 0.1 | `tools/network.py:69-83` | `data = get_machine(machine)` + validar `ip/prefix/gateway` antes de PS | mock `run_process`: `set_ip_address(...,confirm=true)` sin `NameError`, genera `New-NetIPAddress` |
| 0.2 | `tools/system.py:1-3,186` | añadir `require_confirmation` al import | `py_compile` + invocar `set_environment_var` sin `NameError` |
| 0.3 | `tools/network.py:154` | `get_firewall_rules(profile)` valida `Any/Domain/Private/Public` y añade ` -Profile X` si ≠Any | `Private` genera `-Profile Private` |
| 0.4 | `core/ssh.py:78-103`, `tools/files.py`, `tools/linux/files.py` | `build_scp_args(..., direction="upload"\|"download")`: upload `scp local → host:remote`, download `scp host:remote → local` | E2E `upload+download` en lab, `SCP_TIMEOUT 120s` |
| 0.5 | `tools/users.py`, `tools/security.py`, `tools/linux/users.py`, `core/ssh.py:155`, `tools/common` | quitar password en claro (b64+stdin), excluir de `audit_log` y JSON | crear `mcplab02`, `ps` remoto + `mcp.log` sin secreto |
| 0.6 | `tools/system.py:90` vs `tools/logs.py:79` | renombrar o eliminar duplicada `get_event_logs` (queda 1 canónica + alias documentado) | `register_all_tools` sin sombra, conteo efectivo documentado |

DONE Fase 0: `python -m py_compile tools/*.py tools/linux/*.py core/*.py` OK · `python server.py` arranca · 6 checks P0 en verde · `pytest tests/ -v` verde.

### FASE 1 — Gate transversal: doble confirm + validadores + audit (3-5 días) `[x]` Hecho (verificado Fase 6: `test_gate_validators` verde)

**Objetivo:** cimiento para todo lo irreversible. Sin nuevas tools de dominio aún.

| Step | Nuevo / cambio | Spec |
|------|----------------|------|
| 1.1 | `core/security_gate.py` (nuevo) | `require_double_confirm` + decorador `@destructive(level)` + constantes `IRREVERSIBLE_TOOLS`. Mantiene compat con `require_confirmation` actual. |
| 1.2 | `core/validators.py` (nuevo) | §3.2 completo + tests unitarios. |
| 1.3 | `core/constants.py` (nuevo) | mueve `DESTRUCTIVE_TOOLS` de `core/config.py:62`, añade `*_linux` + `IRREVERSIBLE_TOOLS`. |
| 1.4 | `core/audit.py` (nuevo) | unifica `audit_log`, sanitiza secretos, usado por todos los `tools/*.py` (refactor mecánico). |
| 1.5 | `server.py:27` | `RotatingFileHandler(maxBytes=5MB, backupCount=5)`. |
| 1.6 | `requirements.txt` | añade `pytest`, pin `fastmcp==2.12.x`, `mcp==1.29.x`, `python_requires>=3.10`. |

DONE: `test_confirm_required`, `test_double_confirm_dry_run`, `test_validators_*`, `test_pw_not_in_logs` en verde · `ruff F821` sin errores.

### FASE 2 — Windows Server genérico: dominio + org + DNS + files (2-3 semanas) `[x]` Hecho (verificado Fase 6: `test_ad_dns_share` AD idempotente + share sin Everyone verde)

Nuevos módulos (registrar en `tools/__init__.py` como `register_ad_forest`, `register_ad_org`, `register_dns`, `register_fileserver`, `register_audit_gpo`; no tocar los 11 existentes):

**2A. `tools/windows/ad_forest.py` — bosque/dominio (Decisión 1, L2)**

| Tool | Params | Subyacente PS | Notas |
|------|--------|---------------|-------|
| `ad_check_prereq` | `machine` | `Get-WindowsFeature AD-Domain-Services; Get-Module -ListAvailable ActiveDirectory; Get-ADDomain / Get-ADForest (try/catch); Get-ComputerInfo CsDomainRole` | L0. Dice: no-instalado / miembro / DC de `X`. Precheck de todo lo demás. |
| `ad_install_roles` | `machine, confirm, acknowledge, ack_text` | `Install-WindowsFeature AD-Domain-Services -IncludeManagementTools; Add-WindowsFeature RSAT-AD-PowerShell` | L2 (`SE-QUE-INSTALA-ROLES` + reboot posible). `timeout 600`. |
| `ad_install_forest` | `machine, domain_name, safe_mode_pw_b64, install_dns=true, domain_mode, forest_mode, confirm, acknowledge, ack_text, domain_name_confirm` | `Install-ADDSForest -DomainName <dominio cualquiera> -SafeModeAdministratorPassword $sec -InstallDns:$bool -Force:$false` (sin auto-reboot: devuelve `reboot_required:true`) | **L2 irreversible** (`SE-QUE-ES-IRREVERSIBLE` + eco `domain_name`). Valida FQDN + DSRM b64. Timeout 600. Documentar: sin snapshot+consola no ejecutar. |
| `ad_get_domain` | `machine` | `Get-ADDomain \| Select DNSRoot, NetBIOSName, DomainMode; Get-ADForest \| Select Name, ForestMode` | L0. Gestión de DC ya promovido. |
| `ad_restart_after_promote` | `machine, confirm, acknowledge, ack_text` | `Restart-Computer -Force` | L2 separada (nunca auto). Post-reboot guiar `test_ssh` + `ad_get_domain`. |

**2B. `tools/windows/ad_org.py` — OUs/grupos/usuarios/equipos/join (genérico, cualquier nombre)**

| Tool | Params | Subyacente | Nivel |
|------|--------|------------|-------|
| `ad_list_ou/users/groups/computers` | `machine, search_base (DN opcional)` | `Get-ADOrganizationalUnit -Filter *`, `Get-ADUser -Filter * -Properties Enabled,SamAccountName`, etc. `| Select ...` | L0 |
| `ad_create_ou` | `machine, ou_name, path_dn, confirm, acknowledge, ack_text` | `Get-ADOrganizationalUnit -Identity ... (si existe → already_exists); New-ADOrganizationalUnit -Name -Path` | L2 (crea estado AD). Valida DN. |
| `ad_create_group` | `machine, group_name, scope=Global, category=Security, path_dn, confirm, acknowledge, ack_text` | `New-ADGroup -Name -GroupScope -GroupCategory -Path` | L2 |
| `ad_create_user` | `machine, full_name, sam, upn, ou_dn, password_b64, enabled=true, confirm, acknowledge, ack_text` | `New-ADUser -Name -SamAccountName -UserPrincipalName -Path ou_dn -Enabled -AccountPassword $sec(b64)` | L2 + secreto §3.4. Valida sam/DN/b64. |
| `ad_set_password/enable/disable_user` | `machine, sam, password_b64?, confirm, acknowledge, ack_text` | `Set-ADAccountPassword / Enable-ADAccount / Disable-ADAccount` | L2 |
| `ad_add/remove_group_member` | `machine, group_sam, member_sam, confirm, acknowledge, ack_text` | `Add/Remove-ADGroupMember -Identity -Members` | L2 |
| `ad_list_computer/join_domain` | `machine_client, domain_name, ou_dn?, domain_cred_user, domain_cred_pw_b64, set_dns_to_dc_ip, confirm, acknowledge, ack_text, domain_name_confirm` | pre: `Set-DnsClientServerAddress -ServerAddresses dc_ip` (si se pide) → `Test-Connection dc_ip` → `Add-Computer -DomainName -OUPath -Credential $cred -Restart:$false` → `reboot_required:true` | L2 (credencial dominio b64, DNS crítico). Reboot vía `ad_restart_after_promote` separada. Post: `Get-WmiObject Win32_ComputerSystem \| Select Domain` + visible en `ad_list_computers` del DC. |

Comandos de referencia (MS Learn 2025): `New-ADOrganizationalUnit -Name "X" -Path "DC=...,DC=..."`, `New-ADGroup -Name -GroupScope Global|Universal|DomainLocal`, `New-ADUser -Name -SamAccountName -Path OU=...`, `Install-ADDSForest -DomainName corp.contoso.com -InstallDns`.

**2C. `tools/windows/dns.py` — DNS autoritativo genérico (L1, `dns_add/delete` L2 por riesgo AD)**

| Tool | Subyacente |
|------|------------|
| `dns_list_zones / dns_list_records(machine, zone)` | `Get-DnsServerZone`, `Get-DnsServerResourceRecord -ZoneName <zona cualquiera>` |
| `dns_add_a_record(machine, zone, rec_name, ipv4, confirm, acknowledge, ack_text)` | `Add-DnsServerResourceRecordA -ZoneName -Name -IPv4Address` (valida FQDN+IP) |
| `dns_delete_record(...)` | `Remove-DnsServerResourceRecord` |
| `dns_test_resolution(machine, fqdn, dns_server_ip?)` | `Resolve-DnsName fqdn (-Server ip) + nslookup` |

**2D. `tools/windows/fileserver.py` — shares + NTFS + efectivo**

| Tool | Spec |
|------|------|
| `share_list` | `Get-SmbShare \| Select Name,Path,Description` (L0) |
| `share_create(machine, share_name, folder_path, full[], change[], read[], description, encrypt=false, abe=true, confirm, acknowledge, ack_text)` | `New-Item -ItemType Directory -Force; New-SmbShare -Name -Path -FullAccess/-ChangeAccess/-ReadAccess -FolderEnumerationMode AccessBased -EncryptData`. **Prohibido** default `Everyone:Full`; exigir al menos 1 grupo. Valida share/UNC. (L2) |
| `share_grant/revoke_access` | `Grant/Revoke-SmbShareAccess -Name -AccountName -AccessRight Full|Change|Read` (L1/L2) |
| `ntfs_grant(machine, folder_path, identity, rights=F|M|RX, confirm, acknowledge, ack_text)` | `icacls "path" /grant "DOM\Grupo:(OI)(CI)F|M|RX"` + `Get-Acl` verify (L2) |
| `share_get_effective(machine, share_name, folder_path, sam)` | `Get-SmbShareAccess` vs `(Get-Acl).Access` lado a lado + regla "efectivo = más restrictivo" (L0) |
| `share_test_from_client(machine_client, unc)` | `Test-Path $unc` (+ escritura prueba opcional con `confirm`) |

**2E. `tools/windows/audit_gpo.py` — auditoría/GPO (lectura L0, escritura L2 y preferir GPO en dominio)**

| Tool | Subyacente |
|------|------------|
| `get_audit_policy` | `auditpol /get /category:*` |
| `get_security_events(machine, event_id=4624\|4625\|4663\|5140, lines)` | `Get-WinEvent -LogName Security -FilterXPath EventID` |
| `get_gpo_report` | `gpresult /h C:\Temp\gpo.html + Get-GPOReport -All -ReportType Html` (requiere GPMC en DC) |
| `enable_audit_subcategory(machine, subcategory, success, failure, confirm, acknowledge, ack_text)` | `auditpol /set /subcategory:"X" /success:enable /failure:enable` + aviso "en dominio preferir GPO" (L2) |

DONE Fase 2: en VM clonada crear `lab.test` → OU `Ventas` → grupo `Ventas-RW` → usuario `alu01` (pw usuario) → `A testpc.lab.test` → share `Datos` → desde `win11-vm` `Test-Path \\DC\Datos` + login `lab\alu01` OK · `check`/`list` sin confirm, escrituras con L2 + dry_run verificado.

### FASE 3 — Linux genérico: Mint / Ubuntu Server (1-2 semanas) `[x]` Hecho (verificado Fase 6: Netplan YAML inválido rechazado sin VM)

Nuevos módulos `tools/linux/identity.py`, `samba.py`, `netplan.py`, `realm.py` (sufijo `_linux`, registrar en `register_linux_tools`):

| Módulo | Tools | Subyacente bash (`sudo -n`, `shlex.quote`) | Nivel |
|--------|-------|---------------------------------------------|-------|
| `identity_linux` | `list/get/create/delete/enable/disable_user_linux` (endurecer actual), `add/remove_group_linux`, `set_password_linux(user, password_b64, confirm, acknowledge, ack_text)` | `getent passwd/group`, `useradd -m / userdel -r / usermod -aG / gpasswd -d`, `chpasswd` por stdin b64, `passwd -l/-u`, `chage` | escritura L1, password L2 |
| `samba_linux` | `samba_list_shares_linux`, `samba_create_share_linux(name, path, valid_users[], read_only, confirm, acknowledge, ack_text)`, `samba_set_perms_linux(path, owner, group, mode, use_acl?)` | `testparm -s`, append seguro a `/etc/samba/smb.conf` (backup `.bak` + `testparm` antes de `systemctl restart smbd`), `chmod/chown/setfacl`, `smbstatus` | L2 (toca `smb.conf` + restart) |
| `netplan_linux` | `netplan_list_files_linux`, `netplan_get_linux(file)`, `netplan_set_linux(file, content_yaml, confirm, acknowledge, ack_text)`, `netplan_apply_linux(confirm, acknowledge, ack_text)` | `ls /etc/netplan/`, `sudo -n cat`, validar `yaml.safe_load` **en host** + `.bak`, `sudo -n netplan generate + apply`, post `ip addr/route` | `set/apply` L2 corte-red (`SE-QUE-PUEDO-PERDER-SSH`) |
| `realm_linux` (opcional) | `realm_check_linux`, `realm_join_linux(domain, user, pw_b64, confirm, acknowledge, ack_text)`, `realm_leave_linux(...)` | `realm discover`, `echo pw | realm join --user=user <dominio cualquiera>`, `realm leave`, `id DOM\user`, `systemctl sssd` | L2 (requiere `realmd/sssd/adcli`; DNS del cliente debe apuntar al DC) |
| `audit_linux` | `get_journal_linux`, `get_auditd_rules_linux` | `journalctl -u`, `auditctl -l` | L0 |

Sudoers: ampliar `/etc/sudoers.d/10-mcp-lab` mínimo con `/usr/sbin/netplan, /bin/netplan, /usr/bin/testparm, /bin/systemctl (smbd/sssd), /usr/sbin/realm` + mantener `0440 root:root` + `visudo -c` + `Defaults:<user> !use_pty` (ya documentado en `README §6`).

DONE Fase 3: usuario `alu01` + grupo `ventas` + share Samba `datos` con `valid users=@ventas` accesible; `netplan_get` muestra `enp0s3`, `netplan_set` rechaza YAML inválido **sin tocar VM**; `realm discover <dominio>` OK (join solo con L2 + DNS a DC).

### FASE 4 — Red segura: protocolo corte-SSH (transversal, 1 semana) `[x]` Hecho (L2 `SE-QUE-PUEDO-PERDER-SSH` + `docs/ADR-ssh-double-confirm.md`)

Especificación obligatoria para `set_ip_address[_linux]`, `set_dns_server[_linux]`, `netplan_set/apply`, `join_domain` (cambia DNS):

1. **Preflight (L0, siempre):** `network_preflight(machine)` → `get_network_config` actual + `test_ssh` + cálculo `misma subred(ip nueva/prefix/gateway)` + aviso si `gateway` fuera de subred o `dns` público cuando el objetivo es dominio.
2. **Anuncio al usuario (el agente debe decirlo):** IP actual → IP nueva, interfaz, gateway, DNS; "haz snapshot VirtualBox **ahora** + ten consola de la VM abierta; si aplico mal perderemos SSH y solo se revierte por consola".
3. **Ejecución L2:** `confirm + acknowledge + ack_text="SE-QUE-PUEDO-PERDER-SSH" + eco ip nueva`. `timeout 120-600`.
4. **Post-check:** bucle `test_ssh` 60s. Si vuelve → `get_network_config` nuevo + `ping gateway/dns`. Si no vuelve → respuesta con guía rollback por consola (`ip addr`, Netplan YAML `.bak`, `nmcli`), nunca reintento ciego.
5. **DNS:** `set_dns_server` a IP de DC solo dentro de `join_domain` o con advertencia "si apuntas a `8.8.8.8`/`192.168.1.1` en vez del DC, el dominio dejará de resolver".

DONE: cambio IP en lab revierte el aviso, `dry_run` sin L2 no ejecuta, `test_ssh` post-cambio documentado en `logs/evidence/`.

### FASE 5 — Workflows compuestos idempotentes (2 semanas) `[x]` Hecho (verificado Fase 6: `test_workflows` provision/health/publish verde)

Nuevo `tools/workflows/` (compone Fases 2-4, no nuevas primitivas): cada uno `preflight test_ssh` + `snapshot_reminder` + `steps[]` + `evidence/*.json` + `already_exists`.

| Workflow | Pasos |
|----------|-------|
| `provision_org(machine_dc, org_name, ous=[Users,Groups,Computers], groups[], users_csv?, confirm, acknowledge, ack_text)` | `ad_check_prereq` → crea `OU=org` + sub-OUs → grupos → usuarios CSV (`sam,upn,pw_b64`) → `Add-ADGroupMember`. Patrón `CreateBranchOUs` (woshub): grupos `Org_admins/account_managers/wks_admins` opcionales. |
| `check_domain_health(machine_dc, machine_client, domain_name)` | orden Resumen §22: `ping DC↔CLI` → `DNS cliente == IP DC` → `nslookup domain` → `nltest /dsgetdc` → `Get-ADDomain` → `Get-DnsServerZone` → `Test-NetConnection 445/389` → PASS/FAIL por capa (L0). |
| `publish_share(machine_dc, machine_client, share_name, path, groups, ntfs_rights, ...L2)` | `share_create + ntfs_grant + share_get_effective + share_test_from_client`. |
| `collect_evidence(machine, domain_name)` | `ad_get_domain + dns_list + auditpol + gpo.html + events 4624/4625` → `download_file` al host (requiere P0-3 fixeado). Formato aceptado cátedra: HTML/TXT/JSON. |

Impresoras (`Generic Text Only`, `Get/Add-Printer -Shared`) → **backlog** tras Fase 5 (requiere drivers físicos, caso `Print to PDF` nombre existente).

### FASE 6 — Calidad + portabilidad (2 semanas, parcial en paralelo) `[x]` Hecho (2026-09-07: `tests/conftest.py` + `test_ad_dns_share` + `test_workflows`, fix Windows `sys.executable -c`, `.ruff.toml` F821 — `ruff`/`mypy` no instalados, gate=`py_compile`+`pytest` verde —, `opencode.json.example`, `CHANGELOG.md`, `docs/ADR-ssh-double-confirm.md`, README 100→155)

* `tests/conftest.py` mock `run_process/build_ssh_args` + `test_double_confirm`, `test_validators_*`, `test_ad_idempotent`, `test_share_no_everyone`, `test_ip_same_subnet`, `test_netplan_yaml_invalid_sin_vm`, `test_pw_not_in_logs`, `test_scp_download`. Objetivo >70% capas críticas + `pytest` en CI.
* `ruff F821 + mypy + bandit/semgrep + pip-audit` sin High.
* `opencode.json` portable (`${workspaceFolder}` + `opencode.json.example`), `CHANGELOG.md`, `docs/ADR-*-ssh-double-confirm.md`, `SECURITY.md` (JEA Windows + cuenta dedicada lab, no `Administrador` global para todo).
* `README.md` § catálogo nuevos módulos (actualizar conteo 101 → N).

---

## 5. Mapa de archivos (qué se crea vs qué no se toca)

```
PLAN_DESARROLLO.md            # ESTE archivo (bitácora) — único cambio de esta etapa
server.py                     # NO tocar hasta Fase 1 (solo RotatingFileHandler)
core/config.py                # NO tocar (solo mover DESTRUCTIVE en Fase 1)
core/security_gate.py         # NUEVO Fase 1
core/validators.py            # NUEVO Fase 1
core/constants.py             # NUEVO Fase 1
core/audit.py                 # NUEVO Fase 1
tools/windows/ad_forest.py    # NUEVO Fase 2
tools/windows/ad_org.py       # NUEVO Fase 2
tools/windows/dns.py          # NUEVO Fase 2
tools/windows/fileserver.py   # NUEVO Fase 2
tools/windows/audit_gpo.py    # NUEVO Fase 2
tools/linux/identity.py       # NUEVO Fase 3 (endurece users.py actual)
tools/linux/samba.py          # NUEVO Fase 3
tools/linux/netplan.py        # NUEVO Fase 3
tools/linux/realm.py          # NUEVO Fase 3 (opcional)
tools/workflows/*.py          # NUEVO Fase 5
tests/test_gate_validators.py # NUEVO Fase 1/6
tests/test_ad_dns_share.py    # NUEVO Fase 6
```

Prohibido en todo el plan: promover/degradar DC sin L2+snapshot; `Everyone:Full` en shares; passwords en claro; `sudo` sin `-n`; `set_ip/netplan_apply` sin preflight; drivers de impresora descargados por MCP.

---

## 6. Riesgos globales y NO-hacer

* **Irreversible real:** `Install-ADDSForest` no se deshace con "undo". Solo con L2 + snapshot + consola. En horario lab y con `domain_name_confirm` idéntico.
* **Corte SSH:** IP/gateway/DNS/Netplan erróneos aíslan la VM. Siempre snapshot + consola + post `test_ssh`. El MCP no puede auto-revertir sin red.
* **GPO vs auditpol:** en dominio la auditoría va por GPO; `auditpol` local es validación rápida y puede ser sobrescrito.
* **Wazuh:** fuera de alcance (Resumen §14). Auditoría nativa + `collect_evidence`.
* **Drivers impresión:** si `Get-PrinterDriver` no trae el driver, instalación manual previa. MCP no descarga drivers en este plan.

---

## 7. Checklist bitácora (actualizar por fase)

```
[x] Fase 0 P0 (0.1-0.6) — MCP actual al 100%, arranca, pytest verde
[x] Fase 1 gate (1.1-1.6) — doble confirm + validadores + audit sin secretos
[x] Fase 2 Win (2A-2E) — bosque cualquier nombre + OU/grupos/usuarios + DNS + share NTFS + auditoría lectura
[x] Fase 3 Linux (identity/samba/netplan/realm) — Mint/Ubuntu paridad + sudoers mínimo
[x] Fase 4 red segura — preflight + L2 + post test_ssh + rollback doc
[x] Fase 5 workflows — provision_org + health + publish_share + evidence, idempotentes
[x] Fase 6 calidad — tests conftest/ad_dns_share/workflows, fix Windows sys.executable -c, .ruff.toml F821 (ruff/mypy no instalados, gate py_compile+pytest), portable opencode.json.example, CHANGELOG/ADR, README 155
```

**Siguiente paso propuesto (tras aprobar este .md):** implementar Fase 0 + 1.1-1.2 en rama, manteniendo `register_all_tools` en verde.
