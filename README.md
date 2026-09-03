# VirtualBox SSH MCP — Administración de VMs Windows vía SSH para OpenCode

> **MCP local `stdio` que convierte a OpenCode en administrador de VMs VirtualBox sin exponer puertos ni copiar claves.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastMCP 2.12](https://img.shields.io/badge/FastMCP-2.12-green)](https://github.com/jlowin/fastmcp)
[![MCP SDK 1.29](https://img.shields.io/badge/MCP_SDK-1.29-orange)](https://modelcontextprotocol.io/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows%20Host-lightgrey)](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)
[![License Lab](https://img.shields.io/badge/License-Lab--Only-red)](#seguridad)

---

## 1. ¿Qué es?

**`virtualbox-ssh-mcp`** es un servidor MCP (`server.py:62` `FastMCP(name="virtualbox-ssh-mcp")`) que expone **~37 herramientas tipadas** para administrar VMs Windows desde OpenCode (o cualquier cliente MCP) **reusando el `ssh.exe`/`scp.exe` nativo del host**.

```
┌─────────────┐      stdio (JSON-RPC)      ┌──────────────────┐      subprocess      ┌─────────────┐
│  OpenCode   │ ────────────────────────► │  FastMCP         │ ──────────────────► │  ssh.exe    │ ──TCP 22──► VM Windows
│  (cliente)  │ ◄──────────────────────── │  server.py       │ ◄────────────────── │  scp.exe    │            (PowerShell)
└─────────────┘                           └──────────────────┘                     └─────────────┘
                                                   │  core/ + tools/*
                                                   │  config/machines.json
                                                   └─ logs/mcp.log
```

**Principios:**
- **Sin HTTP, sin daemon residente:** OpenCode lanza `python server.py` por `stdio` (`opencode.json:3`).
- **Sin secretos en el repo:** la clave `~/.ssh/id_rsa` se queda en el host; el MCP solo usa alias SSH (`~/.ssh/config`).
- **Misma ruta SSH que ya funciona manual:** `ssh win11-vm "echo OK"` → `test_ssh("win11-vm")`.

>Inventario actual (`config/machines.json:1`): `win11-vm` (192.168.10.10) y `winserver-vm` (192.168.10.20), ambas `os: windows`, `ssh_user: Administrador`.

---

## 2. Tecnologías

| Capa | Tecnología | Archivo clave | Notas |
|------|------------|---------------|-------|
| **Protocolo** | Model Context Protocol (MCP) stdio | `server.py:1` | Transporte `stdin/stdout`, sin puerto |
| **Framework MCP** | `fastmcp>=2.12,<2.13` + `mcp>=1.29,<2` | `requirements.txt:1` | `FastMCP` con `instructions` + `mcp.run()` |
| **Transporte SSH** | OpenSSH nativo Windows (`ssh.exe`, `scp.exe`, `ping.exe`) | `core/ssh.py:261` | `ConnectTimeout 10`, `BatchMode=yes`, `ServerAliveInterval 15/CountMax 3` |
| **Shell remoto** | PowerShell 5.1 ( `DefaultShell` opcional) | `tools/advanced.py:100` | `run_powershell_script` via `base64 UTF-16LE EncodedCommand` |
| **Core** | Python 3.10+ stdlib (`subprocess`, `pathlib`, `platform`, `json`, `base64`) | `core/config.py:117`, `core/validation.py:99` | Detección `HOST_OS`, validadores, límites |
| **Config** | `machines.json` + `opencode.json` | `core/config.py:90` `load_machines_config()` | Sin DB, sin .env |
| **Observabilidad** | Dual logging `logs/mcp.log` + `stderr` | `server.py:27` | `logging.INFO`, formato `asctime | level | name | message` |

**Timeouts y límites centralizados (`core/config.py:40`):**

| Constante | Valor | Uso |
|-----------|-------|-----|
| `SSH_TIMEOUT_DEFAULT` | 60s | `run_command` por defecto |
| `SSH_CONNECT_TIMEOUT` | 10s | `ssh -o ConnectTimeout` |
| `SSH_MAX_TIMEOUT` | 600s | Tope validado por `validate_timeout()` |
| `SSH_TEST_TIMEOUT` | 20s | `test_ssh` |
| `SSH_PING_TIMEOUT` | 10s | `check_reachability` |
| `SCP_TIMEOUT` | 120s | `upload/download` |
| `MAX_OUTPUT_CHARS` | 10k | Truncado `clean_output()` |
| `MAX_EVENT_LOG_CHARS` | 50k | `get_event_logs` |
| `MAX_EVENT_LOG_LINES` | 1000 | `get_logs` |

Seguridad por diseño: `DESTRUCTIVE_TOOLS = frozenset(21 tools)` (`core/config.py:62`) — toda herramienta destructiva exige `confirm=true` (`core/validation.py:99` `require_confirmation()`).

---

## 3. Funcionalidades — lo que SÍ sabe hacer hoy

Todas las herramientas siguen el contrato `tools/__init__.py:22` `register_all_tools(mcp)` → `@mcp.tool() -> str (JSON)` y retornan `json.dumps(clean_output(...))`.

### 3.1 Conectividad y diagnóstico
| Tool | Params | Descripción |
|------|--------|-------------|
| `list_machines` | — | Lista inventario (`name`, `ssh_host`, `ip`, `os`, `ssh_user`, `description`) |
| `machine_profile` | `machine` | Perfil estático resuelto de `machines.json` |
| `test_ssh` | `machine` | `echo MCP_SSH_OK` + `diagnose_ssh_error()` si falla |
| `check_reachability` | `machine` | Resuelve IP vía `ssh -G host` → `ping -n 1` (Windows) / `-c 1` (Linux) |

### 3.2 Ejecución remota (puerta administrativa)
| Tool | Params | Descripción |
|------|--------|-------------|
| `run_command` | `machine`, `command`, `timeout_seconds=60`, `confirm=true` | Comando directo vía `ssh` — *requiere confirmación* |
| `run_powershell_script` | `machine`, `script`, `timeout_seconds`, `confirm=true` | Script multilínea codificado `base64(UTF-16LE)` → `Invoke-Expression` — evita problemas de comillas |

### 3.3 Sistema operativo
| Tool | Descripción |
|------|-------------|
| `get_system_info` | `Win32_OperatingSystem` + `Win32_Processor` + `Get-PSDrive` + `hostname/uptime` |
| `get_disk_info` | `Get-PSDrive -PSProvider FileSystem | ConvertTo-Json` |
| `get_event_logs` / `get_logs` | `Get-WinEvent -LogName System -MaxEvents 100` (Windows) / `journalctl -u` (Linux) |
| `get_installed_software` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| `get_hotfixes` | `Get-HotFix | Sort InstalledOn` |
| `get_environment_vars` / `set_environment_var` | `Get-ChildItem Env:` / `[Environment]::SetEnvironmentVariable(target: Machine/User/Process)` |

### 3.4 Archivos y transferencia
| Tool | Descripción |
|------|-------------|
| `read_file` | `Get-Content -Raw -LiteralPath` (Windows) / `cat` (Linux), `max_chars 1-100000` |
| `write_file` | Base64 → `Set-Content -LiteralPath` / `sudo tee`, `confirm=true` |
| `upload_file` / `download_file` | `scp.exe` host↔VM (`120s` timeout) |
| `list_directory` | `Get-ChildItem` / `ls -la`, default `C:\` |

### 3.5 Servicios y procesos
| Tool | Descripción |
|------|-------------|
| `list_services`, `get_service_status`, `start_service`, `stop_service(confirm)`, `restart_service` | `Get-Service | Select Name,DisplayName,Status,StartType` |
| `list_processes`, `get_process_detail`, `kill_process(confirm)` | `Get-Process` / `Stop-Process -Force` |

### 3.6 Red y firewall
| Tool | Descripción |
|------|-------------|
| `get_network_config` | `Get-NetIPConfiguration` |
| `set_ip_address` | `New-NetIPAddress -InterfaceAlias -IPAddress -PrefixLength -DefaultGateway` (`confirm`) |
| `set_dns_server` | `Set-DnsClientServerAddress` (`confirm`) |
| `get_dns_cache` / `flush_dns` | `Get-DnsClientCache` / `Clear-DnsClientCache` |
| `get_firewall_rules` | `Get-NetFirewallRule -Direction Inbound -Enabled True` |
| `open_firewall_port` / `enable/disable_firewall_rule` | `New-NetFirewallRule` / `Enable/Disable-NetFirewallRule` (`confirm`) |

### 3.7 Seguridad y administración
| Tool | Descripción |
|------|-------------|
| `get_password_policy` / `set_password_policy` | `net accounts /MINPWLEN /MAXPWAGE ...` (`confirm`) |
| `list_shared_folders` / `create_shared_folder` | `Get/New-SmbShare` (`confirm`) |
| `list_users`, `list_groups`, `create_user`, `delete_user`, `enable/disable_user`, `add/remove_user_from_group` | `Get/New-LocalUser`, `Get-LocalGroup` (`create/delete` con `confirm`) |
| `list_scheduled_tasks`, `get_task_detail`, `create/delete_scheduled_task` | `Get/Register/Unregister-ScheduledTask` (`create/delete` con `confirm`, `trigger_time HH:mm`) |

> **Estado del proyecto:** 2 incidencias menores conocidas en capa gestión — ver `docs/plan-correctivo.md` — no afectan el uso de las 35+ herramientas restantes. El README documenta el comportamiento diseñado.

---

## 4. Requisitos

**Host Windows:**
- Windows 10/11 con OpenSSH Client (`ssh.exe`, `scp.exe` en `PATH`) — verificar `Get-Command ssh; ssh -V`
- Python 3.10+ (`python --version` o `py --version`)
- Claves `~/.ssh/id_rsa` + `id_rsa.pub` con `Test-Path "$env:USERPROFILE\.ssh\id_rsa"` → `True`
- Conectividad `ping 192.168.10.10` / `ping 192.168.10.20` y `Test-NetConnection -Port 22` → `TcpTestSucceeded: True`

**VMs:**
- Linux (192.168.10.10) `sshd` + `~/.ssh/authorized_keys` (`chmod 600`) + UFW `allow 22/tcp`
- Windows (192.168.10.20) `sshd Running` + `administrators_authorized_keys` (`icacls SYSTEM:F Administrators:F`) + firewall `OpenSSH-Server-In-TCP` — ver `GUIA_MCP_SSH_VirtualBox_OpenCode.txt §6-9`

**Red VirtualBox recomendada (si aún no está):** Adaptador1 NAT (salida internet) + Adaptador2 Host-Only (Host↔VM1↔VM2, `192.168.10.0/24`).

---

## 5. Instalación

```powershell
# 1. Clonar / ubicar proyecto
cd C:\Users\ASUS\Desktop\DEVPROJETS\MCPVMS

# 2. Entorno virtual
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3. Verificar dependencias
python -c "import fastmcp, mcp; print('ok')"

# 4. Probar MCP sin OpenCode (debe quedar esperando stdio — Ctrl+C para salir)
python server.py
# Logs en logs/mcp.log
```

---

## 6. Configuración

### 6.1 Alias SSH (imprescindible)

`%USERPROFILE%\.ssh\config`:

```
Host win11-vm
    HostName 192.168.10.10
    User Administrador
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new

Host winserver-vm
    HostName 192.168.10.20
    User Administrador
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
```

Verificar:
```powershell
ssh -G win11-vm
ssh -o BatchMode=yes win11-vm "echo SSH_OK"
ssh -o BatchMode=yes winserver-vm "echo SSH_OK"
```

### 6.2 Inventario `config/machines.json:1`

```json
{
  "machines": {
    "win11-vm": {
      "ssh_host": "win11-vm",
      "os": "windows",
      "ip": "192.168.10.10",
      "description": "Windows 11 - Estacion de trabajo",
      "ssh_user": "Administrador"
    },
    "winserver-vm": {
      "ssh_host": "winserver-vm",
      "os": "windows",
      "ip": "192.168.10.20",
      "description": "Windows Server - Servidor",
      "ssh_user": "Administrador"
    }
  }
}
```
> `ssh_host` debe coincidir con el alias de `~/.ssh/config`. No se guardan claves ni puertos aquí.

### 6.3 Wiring OpenCode

`opencode.json:3` (proyecto o `%USERPROFILE%\.config\opencode\opencode.jsonc`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "virtualbox_ssh": {
      "type": "local",
      "command": [
        "C:\\Users\\ASUS\\Desktop\\DEVPROJETS\\MCPVMS\\.venv\\Scripts\\python.exe",
        "C:\\Users\\ASUS\\Desktop\\DEVPROJETS\\MCPVMS\\server.py"
      ],
      "cwd": "C:\\Users\\ASUS\\Desktop\\DEVPROJETS\\MCPVMS",
      "enabled": true,
      "timeout": 120000
    }
  }
}
```
> `timeout 120000` es **discovery de tools** (no el timeout SSH). El timeout real por tool es `timeout_seconds` (1-600s).

Verificar: `opencode mcp list` → `virtualbox_ssh` conectado.

---

## 7. Uso

### 7.1 Pruebas rápidas con OpenCode

```
Lista las máquinas disponibles (virtualbox_ssh.list_machines)
Comprueba SSH contra win11-vm (test_ssh)
Obtén info del sistema de win11-vm (get_system_info)
Muestra servicios de winserver-vm (list_services)
Lee C:\Windows\System32\drivers\etc\hosts (read_file)
```

### 7.2 Ejemplos por categoría

**Conectividad:**
```text
check_reachability("win11-vm")  → { resolved_host: "192.168.10.10", ok: true }
machine_profile("winserver-vm") → { ssh_host, ip, os, description }
```

**Ejecución:**
```text
run_command("win11-vm", "hostname; Get-Date", 30, confirm=true)
run_powershell_script("winserver-vm", "Get-Service sshd | Format-List", 30, confirm=true)
```

**Sistema:**
```text
get_disk_info("win11-vm")
get_event_logs("win11-vm", "System", 50)
get_installed_software("winserver-vm")
get_hotfixes("winserver-vm")
set_environment_var("win11-vm", "MY_VAR", "valor", "Machine", confirm=true)
```

**Archivos:**
```text
read_file("win11-vm", "C:\\Temp\\app.log", 20000)
write_file("win11-vm", "C:\\Temp\\hola.txt", "Hola MCP", confirm=true)
upload_file("win11-vm", "C:\\local\\app.exe", "C:\\Temp\\app.exe")
list_directory("win11-vm", "C:\\Temp")
```

**Red:**
```text
get_network_config("win11-vm")
get_firewall_rules("win11-vm", "Private")
open_firewall_port("win11-vm", "MiApp", 8080, "TCP", confirm=true)
```

### 7.3 Buenas prácticas

- **Prefiere tools específicas** a `run_command`: `get_service_status("win11-vm","sshd")` en vez de `run_command("systemctl status sshd")`.
- **Usa `confirm=true`** explícito en toda operación destructiva — sin él el MCP rechaza con `ValueError`.
- **Para scripts complejos** usa `run_powershell_script` (base64) en vez de escapar comillas manuales.

---

## 8. Seguridad

- **Solo VMs de laboratorio:** `run_command`/`run_powershell_script`/`write_file`/`set_ip_address` otorgan control total. No apuntar a producción sin hardening.
- **Principio de menor privilegio:** usa cuenta SSH dedicada con `sudo` limitado (Linux) o `JEA` (Windows) en vez de `Administrador` global. Ver `GUIA_MCP...txt §30-31`.
- **Gate `confirm`:** `core/validation.py:99` exige `confirm=true` para 21 tools (`core/config.py:62`). Sin confirm → error tipado.
- **No versionar secretos:** `.gitignore:22` ignora `.venv/`, `__pycache__/`, `logs/*.log`, `*.pem/*.key`, `id_rsa`, `authorized_keys`.
- **Opcional:** `ssh-agent` si `id_rsa` tiene passphrase (`Get-Service ssh-agent | Set-Service -StartupType Automatic; ssh-add`).

---

## 9. Troubleshooting

| Síntoma | Causa probable | Fix |
|---------|----------------|-----|
| `opencode mcp list` no muestra `virtualbox_ssh` | JSONC mal formado, ruta `command` errónea | Validar JSON, probar `.\.venv\Scripts\python.exe server.py` manual |
| `test_ssh` → `Permission denied` | Alias SSH mal, clave no cargada | `ssh -vvv win11-vm "echo OK"` → `Offering public key` |
| `check_reachability` falla pero `test_ssh` OK | Firewall ICMP bloquea ping | No bloqueante; SSH es la verdad |
| `run_command` timeout | `timeout_seconds` < duración real | Subir a `120` o `600` (máx `SSH_MAX_TIMEOUT`) |
| `write_file` en Linux pide password | `sudo tee` sin NOPASSWD | Configurar `visudo` granular o usar `upload_file` |

**Logs:** `Get-Content .\logs\mcp.log -Tail 100` — cada tool audita `AUDIT: tool machine detail`.

---

## 10. Desarrollo

```powershell
# Tests (mocks de ssh, no necesitan VM real)
pytest tests/ -v

# Lint
ruff check .
mypy core/ tools/

# Estructura
server.py              # FastMCP + register_all_tools
core/config.py         # Rutas, timeouts, DESTRUCTIVE_TOOLS, get_machine()
core/ssh.py            # build_ssh_args, run_process, diagnose_ssh_error
core/validation.py     # validate_not_empty/timeout/lines, require_confirmation
tools/*.py             # 11 módulos, 37 tools
config/machines.json   # Inventario
```

Ver `docs/plan-correctivo.md` y `docs/recomendaciones.md` para roadmap.

---

## 11. Estado del proyecto

| Versión | Estado | Notas |
|---------|--------|-------|
| **v0.9 lab** | Funcional, 35+ tools estables | 2 incidencias aisladas en `docs/plan-correctivo.md` — no bloquean uso normal |
| **v1.0** | Roadmap | Fix P0 + rotación logs + `opencode.json` portable + tests >70% |

---

*Guía extendida de instalación SSH/VirtualBox: `GUIA_MCP_SSH_VirtualBox_OpenCode.txt` (61 pág., §§0-35).*
