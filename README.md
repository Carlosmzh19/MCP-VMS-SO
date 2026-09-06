# VirtualBox SSH MCP — Administración de VMs Windows y Linux vía SSH

> **MCP local `stdio` que convierte a tu agente (OpenCode, Claude Code o cualquier cliente MCP) en administrador de VMs VirtualBox sin exponer puertos ni copiar claves.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastMCP 2.12](https://img.shields.io/badge/FastMCP-2.12-green)](https://github.com/jlowin/fastmcp)
[![MCP SDK 1.29](https://img.shields.io/badge/MCP_SDK-1.29-orange)](https://modelcontextprotocol.io/)
[![VMs Windows + Linux](https://img.shields.io/badge/VMs-Windows%20%2B%20Linux-green)](https://www.virtualbox.org/)
[![License Lab](https://img.shields.io/badge/License-Lab--Only-red)](#10-seguridad)

> **Convención de esta guía:** todo lo que veas como `<TU_USUARIO>`, `<IP_VM>`, `<TU_VM>` es un valor que **vos** elegís. Los bloques con IPs `192.168.10.x` y nombres `win11-vm` / `mint-vm` son **ejemplos** de un laboratorio real — adaptalos a tu red.

---

## 1. ¿Qué es?

**`virtualbox-ssh-mcp`** es un servidor MCP (`server.py:62` `FastMCP(name="virtualbox-ssh-mcp")`) que expone **101 herramientas tipadas** (~53 para Windows + 48 para Linux) para administrar VMs VirtualBox desde tu agente de IA, **reusando el `ssh`/`scp` nativo del host**.

```
┌──────────────┐   stdio (JSON-RPC)    ┌──────────────────┐   subprocess    ┌──────────┐   TCP 22   ┌──────────────┐
│ OpenCode /   │ ────────────────────► │  FastMCP         │ ──────────────► │ ssh/scp  │ ─────────► │ VM Windows   │
│ Claude / otro│ ◄──────────────────── │  server.py       │ ◄────────────── │ ping     │            │ VM Linux     │
└──────────────┘                       └──────────────────┘                └──────────┘            │ (PS / bash)  │
                                                        │  core/ + tools/windows + tools/linux    └──────────────┘
                                                        │  config/machines.json
                                                        └─ logs/mcp.log (auditoría)
```

**Principios:**

- **Sin HTTP, sin daemon residente:** el cliente lanza `python server.py` por `stdio` (`opencode.json:3`). Nada escucha en ningún puerto.
- **Sin secretos en el repo:** tu clave privada (`~/.ssh/id_rsa`) se queda en el host; el MCP solo usa **alias SSH** (`~/.ssh/config`). `.gitignore` excluye `.venv/`, `logs/*.log`, `*.pem/*.key`, `id_rsa`, `known_hosts`.
- **Misma ruta SSH que ya funciona manual:** si `ssh <TU_VM> "echo OK"` anda en tu terminal, `test_ssh("<TU_VM>")` anda en el agente.
- **Separación por SO:** `tools/windows/*` (PowerShell) y `tools/linux/*` (bash/systemd, sufijo `_linux`) con router `core/os_router.py`. Lo agnóstico (`test_ssh`, `upload/download`, `read/write_file`, `get_logs`) resuelve el SO solo.

---

## 2. Tecnologías

| Capa | Tecnología | Archivo clave | Notas |
|------|------------|---------------|-------|
| **Protocolo** | Model Context Protocol (MCP) `stdio` | `server.py:1` | `stdin/stdout`, sin puerto ni `.env` |
| **Framework** | `fastmcp>=2.12,<2.13` + `mcp>=1.29,<2` | `requirements.txt:1` | `FastMCP` con `instructions` + `mcp.run()` |
| **Transporte** | OpenSSH nativo del host (`ssh`, `scp`, `ping`) | `core/ssh.py:45` | `ConnectTimeout 10`, `BatchMode=yes`, `ServerAlive 15/3`, `stdin=DEVNULL` |
| **Shell Windows** | PowerShell 5.1 (`DefaultShell` opcional) | `tools/advanced.py:65` | `run_powershell_script` vía `base64 UTF-16LE` |
| **Shell Linux** | bash + systemd | `tools/linux/advanced.py:34` | `run_bash_script_linux` vía `base64 \| bash -s`, `sudo -n` |
| **Core** | Python 3.10+ stdlib | `core/config.py`, `core/ssh.py`, `core/os_router.py`, `core/validation.py` | Detección `HOST_OS`, router `windows\|linux`, 8 validadores |
| **Config** | `machines.json` + alias SSH | `core/config.py:90` `load_machines_config()` | Sin DB; `ssh_host` debe existir en `~/.ssh/config` |
| **Observabilidad** | `logs/mcp.log` + `stderr` | `server.py:27` | `AUDIT: herramienta | máquina | ok/failed` |

**Timeouts y límites (`core/config.py:40`):**

| Constante | Valor | Uso |
|-----------|-------|-----|
| `SSH_TIMEOUT_DEFAULT` | 60s | `run_command` por defecto |
| `SSH_CONNECT_TIMEOUT` | 10s | `ssh -o ConnectTimeout` |
| `SSH_MAX_TIMEOUT` | 600s | Tope de `validate_timeout()` |
| `SSH_TEST_TIMEOUT` | 20s | `test_ssh` |
| `SSH_PING_TIMEOUT` | 10s | `check_reachability` |
| `SCP_TIMEOUT` | 120s | `upload/download` |
| `MAX_OUTPUT_CHARS` / `MAX_LOG_CHARS` / `MAX_EVENT_LOG_CHARS` | 10k / 30k / 50k | Truncado `clean_output()` |
| `MAX_EVENT_LOG_LINES` | 1000 | Tope `lines` |

**Seguridad por diseño:** `DESTRUCTIVE_TOOLS = frozenset(20 tools)` (`core/config.py:62`) + `require_confirmation()` (`core/validation.py:71`): toda herramienta destructiva (Windows y `_linux`) exige `confirm=true` o falla con `ValueError` antes de tocar SSH.

---

## 3. Requisitos del host

Funciona en **Windows, Linux o macOS** (`core/config.py:31` `HOST_OS`; `core/ssh.py:116` elige `ssh.exe`/`ping -n` o `ssh`/`ping -c` según el host).

- **Python 3.10+**: `python --version` (o `py --version` en Windows).
- **OpenSSH Client** en el `PATH`: `ssh`, `scp` (+ `ping`).
  - Windows: `Get-Command ssh; ssh -V` (OpenSSH Client de Windows 10/11).
  - Linux/macOS: `which ssh scp; ssh -V`.
- **Par de claves** en `~/.ssh/`:
  ```powershell
  # Windows
  Test-Path "$env:USERPROFILE\.ssh\id_rsa"
  # Linux/macOS
  test -f ~/.ssh/id_rsa && echo OK
  ```
  Si no existe: `ssh-keygen -t rsa -b 3072 -f ~/.ssh/id_rsa` (o `ed25519`).
- **Red hacia las VMs**: `ping <IP_VM>` y puerto 22 abierto (`Test-NetConnection <IP_VM> -Port 22` / `nc -zv <IP_VM> 22`).

---

## 4. Red VirtualBox recomendada

> Si tus VMs ya se ven entre sí y desde el host, **no cambies nada**. Esto es solo el diseño sugerido para un laboratorio.

| Adaptador | Tipo | Rol | Ejemplo |
|-----------|------|-----|---------|
| 1 | **Solo-anfitrión (Host-Only)** | Host ↔ VM1 ↔ VM2 (gestión/SSH) | `192.168.10.0/24` |
| 2 | **NAT** | Salida a internet de la VM | `10.0.x.x` (DHCP VirtualBox) |

- Crea la red Host-Only si no existe (*Archivo → Herramientas → Administrador de red*), ej. `192.168.10.1/24`, DHCP desactivado (usarás IPs fijas).
- Por VM (*Configuración → Red*): Adaptador 1 = Solo-anfitrión + ✔ Cable conectado; Adaptador 2 = NAT + ✔ Cable conectado.
- El orden puede variar (`enp0s3`/`enp0s8` en Linux): identifica cada interfaz con `ip -4 addr show` y configura la IP fija **en la Host-Only**.

---

## 5. Preparar una VM Windows (guía genérica)

Asumimos: IP Host-Only `<IP_VM>` (ej. `192.168.10.20`), usuario `<TU_USUARIO>` (ej. `Administrador`), OpenSSH Server.

```powershell
# En la VM Windows (PowerShell elevado):
# 1. Servidor SSH activo y automático
Get-Service sshd
Set-Service -Name sshd -StartupType Automatic; Start-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen

# 2. Firewall para SSH (si falta la regla)
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP"
# New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
#   -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# 3. Clave pública del HOST en la VM
#    Copia el contenido de ~/.ssh/id_rsa.pub DEL HOST.
#    Si <TU_USUARIO> es administrador, el archivo válido es:
#      C:\ProgramData\ssh\administrators_authorized_keys
#    (OpenSSH usa ese archivo para miembros de Administrators, no ~/.ssh/authorized_keys)
#    Si NO es administrador: C:\Users\<TU_USUARIO>\.ssh\authorized_keys
#    Pega la línea ssh-rsa/ssh-ed25519 y ajusta ACL (elevado):
icacls.exe "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"

# 4. (Recomendado) PowerShell como shell SSH por defecto
$P = @{ Path = "HKLM:\SOFTWARE\OpenSSH"; Name = "DefaultShell";
        Value = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        PropertyType = "String"; Force = $true }
New-ItemProperty @P
Restart-Service sshd
```

Verificación desde el host: `ssh <TU_USUARIO>@<IP_VM> "whoami"` → sin pedir contraseña.

---

## 6. Preparar una VM Linux (guía genérica, Mint/Ubuntu/Debian)

Asumimos: IP Host-Only `<IP_VM>` (ej. `192.168.10.30`), usuario de laboratorio `<TU_USUARIO>` (ej. `carlos`, con `sudo`), clave del host reusada. **Modelo de acceso del MCP: entra como `<TU_USUARIO>` por clave y escala con `sudo -n` granular** (nunca `root` directo; `root` queda como escape con `prohibit-password`).

```bash
# En la VM Linux:
# 1. SSH + IP fija en la interfaz Host-Only (identifícala con: ip -4 addr show)
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo ss -tlnp | grep :22   # debe escuchar en 0.0.0.0:22
sudo nmcli con add type ethernet ifname <IF_HOSTONLY> con-name HostOnly \
  ipv4.addresses <IP_VM>/24 ipv4.method manual \
  ipv6.method disabled connection.autoconnect yes
sudo nmcli con up HostOnly
ping -c 2 192.168.10.1   # gateway del host
ping -c 2 8.8.8.8        # internet vía NAT

# 2. Clave pública DEL HOST en ambos usuarios (la privada NUNCA viaja a la VM)
#    En el HOST: cat ~/.ssh/id_rsa.pub  (copiar la línea completa)
mkdir -p ~/.ssh && chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys            # pegar la línea
chmod 600 ~/.ssh/authorized_keys && chown -R $USER:$USER ~/.ssh
sudo mkdir -p /root/.ssh
sudo nano /root/.ssh/authorized_keys   # pegar la MISMA línea
sudo chmod 700 /root/.ssh && sudo chmod 600 /root/.ssh/authorized_keys
sudo chown -R root:root /root/.ssh

# 3. Endurecer sshd (drop-in, sin tocar sshd_config principal)
sudo tee /etc/ssh/sshd_config.d/50-lab.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
EOF
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|pubkeyauth'
sudo systemctl restart ssh

# 4. Firewall: SSH solo desde la red lab
sudo ufw allow from 192.168.10.0/24 to any port 22 proto tcp
sudo ufw enable && sudo ufw status numbered

# 5. Sudo granular para el MCP (¡NO uses NOPASSWD:ALL!)
#    Revertí cualquier regla amplia previa: sudo rm -f /etc/sudoers.d/<TU_USUARIO>-nopasswd
sudo visudo -f /etc/sudoers.d/10-mcp-lab   # pegar:
# Defaults:<TU_USUARIO> !use_pty
# <TU_USUARIO> ALL=(root) NOPASSWD: /usr/bin/tee, /bin/cat, /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod, /usr/bin/chpasswd, /bin/systemctl, /usr/bin/systemctl, /usr/bin/journalctl, /usr/sbin/ufw, /sbin/ip, /usr/bin/nmcli, /bin/mkdir, /bin/chmod, /bin/chown, /bin/cp, /bin/mv, /bin/rm, /bin/kill, /usr/bin/pkill, /usr/bin/crontab, /usr/bin/true, /bin/ps
sudo chmod 0440 /etc/sudoers.d/10-mcp-lab && sudo chown root:root /etc/sudoers.d/10-mcp-lab
sudo visudo -c   # debe decir "análisis OK" para 10-mcp-lab
sudo -n /usr/bin/true && echo SUDO_OK
```

> Detalles que muerden (aprendidos a los golpes):
>
> - `Defaults:<TU_USUARIO> !use_pty` es **obligatorio**: sin tty, `sudo` con `use_pty` cuelga la sesión SSH.
> - `tee` crea el archivo en `640`: `sudo` **ignora** sudoers que no sean `0440 root:root`.
> - `sudo -n true` solo pasa si `/usr/bin/true` está en la lista: incluilo para poder testear.
> - En el MCP usá siempre `sudo -n` (nunca `sudo` a secas): sin `-n` espera contraseña y cuelga.
> - `df` en Mint toca `fuse.gvfsd-fuse`: preferí `df --local` en scripts.

---

## 7. Instalación del proyecto

```powershell
# 1. Ubicar el proyecto (o clonarlo) — ajustá la ruta a tu PC
cd <RUTA_AL_PROYECTO>   # ej. C:\Users\<VOS>\MCPVMS

# 2. Entorno virtual + dependencias
py -3.11 -m venv .venv            # Windows  |  python3 -m venv .venv  (Linux/macOS)
.\.venv\Scripts\Activate.ps1      # Windows  |  source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt   # fastmcp + mcp

# 3. Verificar
python -c "import fastmcp, mcp; print('ok')"

# 4. Probar el servidor sin cliente (queda esperando stdio — Ctrl+C para salir)
python server.py                  # logs en logs/mcp.log
```

---

## 8. Configuración

### 8.1 Alias SSH en el host (imprescindible)

El MCP **nunca** recibe IPs, usuarios ni claves: todo eso vive en `~/.ssh/config`. Cada entrada de `config/machines.json` (`ssh_host`) debe ser un `Host` de este archivo.

Plantilla por VM Windows (`%USERPROFILE%\.ssh\config` o `~/.ssh/config`):

```
Host <ALIAS_VM>
    HostName <IP_VM>
    User <TU_USUARIO>
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
```

Plantilla por VM Linux (igual, con tu usuario de laboratorio):

```
Host <ALIAS_VM>
    HostName <IP_VM>
    User <TU_USUARIO>
    IdentityFile ~/.ssh/id_rsa
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
```

Verificar cada alias (el segundo comando simula exactamente lo que hace el MCP):

```powershell
ssh -G <ALIAS_VM>                                   # debe mostrar hostname <IP_VM> / user <TU_USUARIO>
ssh -o BatchMode=yes <ALIAS_VM> "echo SSH_OK"       # debe imprimir SSH_OK sin pedir nada
ssh -o BatchMode=yes <ALIAS_VM> "sudo -n /usr/bin/true && echo SUDO_OK"   # solo Linux
```

Si cambiaste hardware/VM y aparece `Host key verification failed`: `ssh-keygen -R <IP_VM>` y aceptá la huella una vez con `ssh <ALIAS_VM> "hostname"`.

### 8.2 Inventario `config/machines.json`

```json
{
  "machines": {
    "<ALIAS_WIN>": {
      "ssh_host": "<ALIAS_WIN>",
      "os": "windows",
      "ip": "<IP_VM_WIN>",
      "description": "Windows - <rol>",
      "ssh_user": "<TU_USUARIO_WIN>"
    },
    "<ALIAS_LINUX>": {
      "ssh_host": "<ALIAS_LINUX>",
      "os": "linux",
      "ip": "<IP_VM_LINUX>",
      "description": "Linux - <rol>",
      "ssh_user": "<TU_USUARIO_LINUX>"
    }
  }
}
```

Reglas: `os` solo admite `windows` o `linux` (`core/os_router.py:19`); `ssh_host` = alias del §8.1; el campo `ip` es informativo (el ping usa lo resuelto por `ssh -G`).

### 8.3 Conectar tu agente (OpenCode, Claude Code o genérico)

El servidor es **stdio estándar**: cualquier cliente MCP que soporte `command + cwd` sirve. El `timeout` del cliente es **discovery de tools**, no el timeout SSH (ese es `timeout_seconds` por herramienta, 1–600s).

**OpenCode** (por proyecto: `opencode.json`; global: `~/.config/opencode/opencode.jsonc`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "virtualbox_ssh": {
      "type": "local",
      "command": [
        "<RUTA_ABS>/.venv/Scripts/python.exe",
        "<RUTA_ABS>/server.py"
      ],
      "cwd": "<RUTA_ABS>",
      "enabled": true,
      "timeout": 120000
    }
  }
}
```

> En Linux/macOS el ejecutable es `<RUTA_ABS>/.venv/bin/python`. Verificar: `opencode mcp list` → `virtualbox_ssh` conectado.

**Claude Code CLI:**

```bash
claude mcp add virtualbox-ssh -- <RUTA_ABS>/.venv/Scripts/python.exe <RUTA_ABS>/server.py
# verificar:
claude mcp list
```

**Otro cliente MCP genérico:** transporte `stdio`, comando `<python del .venv> <RUTA_ABS>/server.py`, directorio `<RUTA_ABS>`. Requisitos: `ssh/scp/ping` en el `PATH`, alias SSH del §8.1 y `requirements.txt` instalado.

---

## 9. Catálogo de herramientas

Contrato común (`tools/__init__.py:23`): `@mcp.tool() -> str (JSON)` con `json.dumps(clean_output(...))`. Las destructivas exigen `confirm=true`.

> Nota: `get_event_logs` existe en `tools/system.py:90` y `tools/logs.py:79`; gana la de `logs.py` por orden de registro.

### 9.1 Conectividad (agnósticas, ambas)

| Tool | Params | Descripción |
|------|--------|-------------|
| `list_machines` | — | Inventario (`name`, `ssh_host`, `ip`, `os`, `ssh_user`) |
| `machine_profile` | `machine` | Perfil de una VM |
| `test_ssh` | `machine` | `echo MCP_SSH_OK` + `diagnose_ssh_error()` si falla |
| `check_reachability` | `machine` | IP vía `ssh -G` → `ping` |

### 9.2 Ejecución remota

| Tool | Params | Descripción |
|------|--------|-------------|
| `run_command` | `machine`, `command`, `timeout_seconds=60`, `confirm=true` | Comando directo (ideal Windows/PowerShell) |
| `run_powershell_script` | `machine`, `script`, `timeout_seconds`, `confirm=true` | Multilínea PS vía `base64 UTF-16LE` |
| `run_command_linux` | `machine`, `command`, `timeout_seconds=60`, `confirm=true` | Comando bash (sin `sudo` automático: anteponé `sudo -n`) |
| `run_bash_script_linux` | `machine`, `script`, `timeout_seconds`, `confirm=true` | Multilínea bash vía `base64 \| bash -s` |

### 9.3 Sistema (Windows / `_linux`)

| Windows | Linux | Detalle |
|---------|-------|---------|
| `get_system_info` | `get_system_info_linux` | CIM+CPU+disco / `hostnamectl`, `lsb_release`, `free`, `df` |
| `get_disk_info` | `get_disk_info_linux` | `Get-PSDrive` / `df -hT` + `lsblk` |
| `get_event_logs` / `get_logs` | `get_logs_linux` / `get_event_logs_linux` | `Get-WinEvent` / `journalctl -u`, syslog |
| `get_installed_software` | `get_installed_software_linux` | Registro Uninstall / `dpkg -l` (o `rpm -qa`) |
| `get_hotfixes` | — | `Get-HotFix` (sin equivalente Linux) |
| `get_environment_vars` / `set_environment_var(target)` | `get_environment_vars_linux` / `set_environment_var_linux` | `Env:` / `printenv`; persiste en `/etc/environment` (`confirm`) |

### 9.4 Archivos (agnósticas + `_linux`)

| Tool | Detalle |
|------|---------|
| `read_file` / `read_file_linux` | `Get-Content` / `cat` (`sudo -n cat` en `/etc/*`), `max_chars` 1–100000 |
| `write_file` / `write_file_linux` | Base64 → `Set-Content` / `sudo -n tee` (`confirm`) |
| `upload_file` / `download_file` (+`_linux`) | `scp` host↔VM (120s) |
| `list_directory` / `list_directory_linux` | `Get-ChildItem` (def. `C:\`) / `ls -la` (def. home del usuario) |

### 9.5 Servicios y procesos

| Windows | Linux | Detalle |
|---------|-------|---------|
| `list_services`, `get_service_status`, `start/stop(confirm)/restart_service` | `*_service_linux` | `Get-Service` / `systemctl` (`sudo -n` para cambios) |
| `list_processes`, `get_process_detail`, `kill_process(confirm)` | `*_process*_linux` | `Get-Process` / `ps`, `pkill` (acepta PID o nombre) |

### 9.6 Red y firewall

| Windows | Linux | Detalle |
|---------|-------|---------|
| `get_network_config` | `get_network_config_linux` | `Get-NetIPConfiguration` / `ip addr+route`, `resolvectl` |
| `set_ip_address` | `set_ip_address_linux` | ⚠️ puede aislar la VM: siempre `confirm` + consola a mano |
| `set_dns_server` | `set_dns_server_linux` | `Set-DnsClientServerAddress` / `resolvectl`+`nmcli` |
| `get_dns_cache` / `flush_dns` | `*_dns*_linux` | Caché DNS / `resolvectl flush-caches` |
| `get_firewall_rules` | `get_firewall_rules_linux` / `get_firewall_status_linux` | `Get-NetFirewallRule` / `ufw status` |
| `open_firewall_port`, `enable/disable_firewall_rule` | `*_firewall_*_linux` | `New-NetFirewallRule` / `ufw allow` (`confirm`) |

### 9.7 Usuarios, seguridad y tareas

| Windows | Linux | Detalle |
|---------|-------|---------|
| `list/create(confirm)/delete(confirm)/enable/disable(confirm)_user`, `list_groups`, `add/remove_user_from_group(confirm)` | `*_user*_linux`, `*_group*_linux` | `LocalUser/LocalGroup` / `useradd/userdel/usermod/chpasswd/gpasswd` (`sudo -n`) |
| `get/set_password_policy(confirm)` | `*_password_policy_linux` | `net accounts` / `chage`, `login.defs` |
| `list/create_shared_folder(confirm)` | `list/create_shared_folder_linux` | `SmbShare` / `smb.conf` + `smbstatus` |
| `list/get/create(confirm)/delete(confirm)_scheduled_task` | `*_scheduled_task*_linux` | Tareas programadas / `cron` (`trigger_time HH:mm` → `m h * * *`) + `systemd timers` |

### 9.8 Ejemplos por categoría

```text
# Conectividad
list_machines()  → [{ name, ssh_host, os, ip, ssh_user }]
test_ssh("<TU_VM>")  → { ok: true, stdout: "MCP_SSH_OK" }

# Sistema
get_system_info("<WIN>")            get_system_info_linux("<LINUX>")
get_disk_info("<WIN>")              get_installed_software_linux("<LINUX>")

# Archivos
read_file("<WIN>", "C:\\Temp\\app.log")
write_file_linux("<LINUX>", "/tmp/hola.txt", "Hola MCP", confirm=true)
upload_file("<WIN>", "<LOCAL>/app.exe", "C:\\Temp\\app.exe")
list_directory_linux("<LINUX>", "/home/<TU_USUARIO>")

# Servicios / procesos
get_service_status("<WIN>", "sshd")        get_service_status_linux("<LINUX>", "ssh")
restart_service("<WIN>", "sshd")           restart_service_linux("<LINUX>", "ssh")
kill_process("<WIN>", "notepad", confirm=true)

# Red
open_firewall_port("<WIN>", "MiApp", 8080, "TCP", confirm=true)
open_firewall_port_linux("<LINUX>", "miapp", 8080, "tcp", confirm=true)

# Usuarios lab (Linux)
create_user_linux("<LINUX>", "alumno01", "<PASSWORD>", confirm=true)
add_user_to_group_linux("<LINUX>", "alumno01", "sudo", confirm=true)
delete_user_linux("<LINUX>", "alumno01", confirm=true)
```

**Buenas prácticas:** preferí tools específicas a `run_command`; `confirm=true` siempre explícito; scripts largos por `run_powershell_script` / `run_bash_script_linux` (base64 evita infiernos de comillas).

---

## 10. Seguridad

- **Solo laboratorio:** `run_command*`, `write_file*`, `set_ip_address*` dan control total. Nada de producción sin hardening.
- **Menor privilegio:** SSH como usuario de laboratorio + `sudo` granular (Linux, §6) o cuenta dedicada/`JEA` (Windows). Nada de `root` directo ni `NOPASSWD: ALL`.
- **Gate `confirm`:** `core/validation.py:71` lo exige en 20+ herramientas; sin él, error tipado antes de SSH.
- **Claves:** nunca en el repo; `IdentityFile` + `IdentitiesOnly yes`; con passphrase usá `ssh-agent` (`ssh-add ~/.ssh/id_rsa`).
- **Auditoría:** todo queda en `logs/mcp.log` (`AUDIT: herramienta | máquina | detalle`).

---

## 11. Troubleshooting

| Síntoma | Causa probable | Fix |
|---------|----------------|-----|
| Cliente no lista `virtualbox_ssh` | JSON mal formado / ruta `command` mala | Validar JSON; correr `python server.py` manual (debe esperar en stdio) |
| `test_ssh` → `Permission denied (publickey)` | Alias mal / clave no autorizada | `ssh -vvv <ALIAS> "echo OK"` → buscar `Offering public key` / `Server accepts key` |
| `Host key verification failed` | Huella vieja en `known_hosts` | `ssh-keygen -R <IP_VM>` y aceptar una vez |
| `check_reachability` falla pero `test_ssh` OK | ICMP bloqueado | No bloqueante: SSH manda |
| Todo SSH vía MCP da `timeout` con stdout OK/vacío | `ssh` hereda stdin del servidor stdio | Ya fixeado (`core/ssh.py` `stdin=DEVNULL`); actualizar código + reiniciar cliente |
| `sudo: se requiere una contraseña` (Linux) | Comando fuera de la lista NOPASSWD | Ampliar `10-mcp-lab` vía `visudo`, `chmod 0440`, `visudo -c` |
| `sudo` cuelga la sesión (Linux) | `use_pty` sin tty | `Defaults:<TU_USUARIO> !use_pty` en sudoers |
| `sudo` ignora tu archivo sudoers | Permisos ≠ `0440 root:root` | `chmod 0440` + `chown root:root` + `visudo -c` |
| `write_file_linux` en `/etc/*` falla | Falta `tee`/`cat` en sudoers o path con `\` | `validate_linux_path`: rutas Linux empiezan con `/` |
| `set_ip_address*` dejó la VM muda | IP/gateway mal en la interfaz de gestión | Entrar por consola VirtualBox y revertir; snapshot antes |
| `run_command` timeout | `timeout_seconds` corto | Subir a `120`–`600` (máx `SSH_MAX_TIMEOUT`) |

**Logs:** `Get-Content .\logs\mcp.log -Tail 100` (o `tail -n 100 logs/mcp.log`).

---

## 12. Desarrollo

```powershell
# Tests (mocks + binarios reales; sin VM necesaria para la mayoría)
pytest tests/ -v              # test_config / test_ssh / test_validation

# Estructura actual
server.py                    # FastMCP + register_all_tools
core/config.py               # Rutas, timeouts, DESTRUCTIVE_TOOLS, get_machine()
core/ssh.py                  # build_ssh_args/scp/ping, run_process, wrap_sudo, diagnose_ssh_error
core/os_router.py            # get_os_type, require_os, dispatch windows|linux
core/validation.py           # 8 validadores (not_empty, timeout, lines, max_chars, confirm, os, linux_path)
tools/__init__.py            # register_all_tools: 11 módulos Windows + register_linux_tools
tools/windows… -> tools/*.py # 53 tools (PowerShell)
tools/linux/*.py             # 48 tools *_linux (bash/systemd/sudo -n/ufw/cron)
tools/common/                # audit_log compartido
config/machines.json         # Inventario (ssh_host = alias SSH, os = windows|linux)
```

Convenciones: `@mcp.tool() -> str (JSON)`, docstrings en español, `sudo -n` + `shlex.quote` en Linux, `confirm=true` en destructivas, `clean_output()` trunca a la cola.

---

## 13. Estado del proyecto

| Versión | Estado | Notas |
|---------|--------|-------|
| **v1.0-lab** | Funcional: 100 tools únicas (52 Windows + 48 Linux) | Validado contra Windows + Linux Mint 22.1 (batería 10/10: sistema, disco, servicios, logs, red, firewall, archivos, usuarios) |
| Conocido | `get_event_logs` duplicada (`system.py:90` vs `logs.py:79`, gana `logs`) | Limpieza pendiente, sin impacto |
| Roadmap | Tests >70%, `opencode.json` portable, rotación de logs | |
