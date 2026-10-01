# VirtualBox SSH MCP — Administración de VMs Windows y Linux vía SSH

> **Convertí a tu agente de IA (OpenCode, Claude Code o cualquier cliente MCP) en administrador de VMs VirtualBox, sin abrir puertos ni copiar claves privadas.**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![FastMCP 2.12](https://img.shields.io/badge/FastMCP-2.12-green)](https://github.com/jlowin/fastmcp)
[![MCP SDK 1.29](https://img.shields.io/badge/MCP_SDK-1.29-orange)](https://modelcontextprotocol.io/)
[![156 herramientas](https://img.shields.io/badge/Tools-156-green)](#10-catálogo-de-herramientas)
[![Solo laboratorio](https://img.shields.io/badge/Uso-Solo_Laboratorio-red)](#11-seguridad)

---

## Cómo leer esta guía

Este es un tutorial **lineal**. Seguí las secciones de arriba hacia abajo y vas a terminar con el MCP funcionando. Cada sección depende de la anterior.

**Convenciones:**

| Notación | Significa |
|----------|-----------|
| `<ALIAS_VM>` | Un nombre corto que inventás (ej. `mi-win11`). Lo vas a usar en varios sitios. |
| `<IP_VM>` | La IP fija de la VM en la red Host-Only (ej. `192.168.10.20`). |
| `<TU_USUARIO>` | Tu usuario en la VM (ej. `carlos`, `miusuario`, `Administrador`). |
| `<RUTA_AL_PROYECTO>` | Dónde clonaste el repo (ej. `C:\Users\vos\MCPVMS`). |

**Ejemplo de laboratorio que usa esta guía:** dos VMs en la red `192.168.10.0/24` — una Windows en `192.168.10.20` y una Linux en `192.168.10.30`. Adaptalos a tu red.

> ⚠️ **Solo laboratorio y educación.** Este MCP le da a un agente de IA control casi total sobre tus VMs: puede ejecutar comandos, escribir archivos, cambiar IPs y crear usuarios. **No lo uses contra producción, servidores de clientes ni máquinas con datos importantes** sin un hardening adicional. La sección [Seguridad](#11-seguridad) explica los frenos y sus límites reales.

---

## 1. Qué es y cómo funciona

`virtualbox-ssh-mcp` es un servidor MCP (`server.py`) que expone **156 herramientas tipadas** para administrar VMs desde tu agente de IA. Lo clave: **reutiliza el `ssh` / `scp` nativo de tu sistema operativo**, el mismo que ya usás en la terminal. No hay SDK de VirtualBox, ni API, ni puertos abiertos.

```
┌──────────────┐   stdio (JSON-RPC)    ┌──────────────────┐   subprocess    ┌──────────┐   TCP 22   ┌──────────────┐
│ OpenCode /   │ ────────────────────► │  FastMCP         │ ──────────────► │ ssh/scp  │ ─────────► │ VM Windows   │
│ Claude / otro│ ◄──────────────────── │  server.py       │ ◄────────────── │ ping     │            │ VM Linux     │
└──────────────┘                       └──────────────────┘                └──────────┘            │ (PS / bash)  │
                                                        │  core/ + tools/windows + tools/linux    └──────────────┘
                                                        │  config/machines.json
                                                        └─ logs/mcp.log (auditoría)
```

### El modelo mental que tenés que entender

Esto es lo único que hace falta tener claro para no perderse después:

1. **El alias de SSH es la fuente de verdad.** Definís la conexión a cada VM en tu `~/.ssh/config` con un alias corto (`mi-win11`). IP, usuario y clave viven **solo ahí**.
2. **`machines.json` es un índice.** Solo mapea "nombre amigable" → sistema operativo + alias SSH. No guarda IPs ni usuarios reales.
3. **El MCP nunca ve tu clave privada.** La clave privada se queda en tu host. A la VM viaja únicamente la **pública** (`id_ed25519.pub`).
4. **Todas las herramientas se invocan por `machine`**, que es la clave de `machines.json` (ej. `list_machines` te dice cuáles existen, y después usás ese nombre).

> **La prueba de oro:** si `ssh <ALIAS_VM> "echo OK"` funciona en tu terminal, entonces `test_ssh("<ALIAS_VM>")` va a funcionar en el agente. Mismo camino de código, exactamente.

### Otros principios de diseño

- **Sin HTTP, sin daemon residente.** Tu cliente lanza `python server.py` por `stdio`. Nada escucha en ningún puerto; el proceso muere con el cliente.
- **Separación por sistema operativo.** Las herramientas de Windows usan PowerShell y las de Linux usan bash/systemd, con sufijo `_linux`. Las agnósticas (`test_ssh`, `upload_file`, `read_file`, `get_logs`) resuelven el SO solas desde `machines.json`.
- **Secretos como base64.** Las contraseñas viajan siempre en base64 (`password_b64`), nunca en claro en logs ni argumentos de proceso.
- **Auditoría de todo.** Cada invocación queda registrada en `logs/mcp.log`.

---

## 2. Requisitos del host

Funciona en **Windows, Linux o macOS**. El MCP detecta el SO del host y elige `ssh.exe`/`ping -n` o `ssh`/`ping -c` según corresponda.

Verificá cada requisito antes de seguir:

| Requisito | Versión mínima | Cómo verificarlo |
|-----------|-----------------|------------------|
| Python | 3.10 | `python --version` (Linux/macOS) · `py --version` (Windows) |
| OpenSSH Client | cualquiera reciente | `ssh -V` (Windows: `Get-Command ssh`) |
| `scp` | — | Windows: `Get-Command scp` · Linux/macOS: `which scp` |
| Clave SSH ed25519 | — | `test -f ~/.ssh/id_ed25519` (Unix) · `Test-Path "$env:USERPROFILE\.ssh\id_ed25519"` (Windows) |

Si no tenés la clave, generá el par ahora (te va a hacer falta en la sección [Preparar la VM Windows](#4-preparar-una-vm-windows) y [Linux](#5-preparar-una-vm-linux)):

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/id_ed25519
```

Te va a pedir un *passphrase*. Si lo ponés, más adelante vas a necesitar `ssh-agent` (ver [sección 6.3](#63-la-conexión-como-agente) ).

> **¿Usás RSA?** Si tu clave se llama `id_rsa` en lugar de `id_ed25519`, mantenela, pero recordá que **hay que cambiar el nombre en 4 lugares** de esta guía: los bloques de clave pública (secciones 4 y 5), el `IdentityFile` del alias SSH, y el `ssh-add` de la sección 6.3.

---

## 3. Paso 0 — Crear las VMs y la red

Este paso es previo a todo lo demás. Si ya tenés VMs accesibles por SSH desde el host, **saltalo**.

### Red recomendada

Dos adaptadores por VM:

| Adaptador | Tipo | Rol | Ejemplo |
|-----------|------|-----|---------|
| 1 | **Solo-anfitrión (Host-Only)** | Host ↔ VM, gestión por SSH | `192.168.10.0/24` |
| 2 | **NAT** | Salida a internet de la VM | `10.0.2.x` (DHCP) |

Crear la red Host-Only si no existe: *VirtualBox → Archivo → Herramientas → Administrador de red → Redes de solo-anfitrión → Crear*. Configurala en `192.168.10.1/24` y **desactivá el DHCP** (vamos a usar IPs fijas).

Por cada VM (*Configuración → Red*): Adaptador 1 = Solo-anfitrión con ✔ Cable conectado, Adaptador 2 = NAT con ✔ Cable conectado.

Creá las VMs, instalá Windows o una distro Linux, y montá **Guest Additions** (en Linux: `sudo apt install virtualbox-guest-utils`).

---

## 4. Preparar una VM Windows

Objetivo: que el host pueda entrar por clave sin escribir contraseña.

```powershell
# En la VM Windows (PowerShell ELEVADO):

# 1. Servidor SSH activo y automático
Get-Service sshd
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
Get-NetTCPConnection -LocalPort 22 -State Listen   # debe escuchar en 0.0.0.0:22

# 2. Firewall: verificar la regla de SSH
Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP"
# Si no existe, creala:
# New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' `
#   -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# 3. PowerShell como shell SSH por defecto (muy recomendado: hace que
#    run_command devuelva JSON en vez de texto plano)
$P = @{
    Path         = "HKLM:\SOFTWARE\OpenSSH"
    Name         = "DefaultShell"
    Value        = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    PropertyType = "String"
    Force        = $true
}
New-ItemProperty @P
Restart-Service sshd
```

### Instalar la clave pública del host

Este paso es donde casi todos se tropiezan. Windows tiene **dos archivos distintos** según tu usuario sea administrador o no:

| Tu usuario en la VM es... | Archivo que OpenSSH lee |
|---------------------------|-------------------------|
| Miembro de **Administradores** | `C:\ProgramData\ssh\administrators_authorized_keys` |
| Usuario **normal** | `C:\Users\<TU_USUARIO>\.ssh\authorized_keys` |

El paso 4.1 muestra cómo elegir. En ambos casos pegás **una sola línea** que empieza con `ssh-ed25519` (la pública del host, nunca la privada).

**Paso 4.1 — Pasá la clave al host.** En tu **host**, no en la VM:

```bash
# Linux/macOS
cat ~/.ssh/id_ed25519.pub
# Windows (PowerShell)
Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub"
```

Copiá esa línea completa. Es algo así de largo:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... tu@hostname
```

**Paso 4.2 — Pegala en la VM.** Conectate por consola a la VM y abrí **PowerShell ELEVADO**:

```powershell
# CASO A: tu usuario es Administrador
$Key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... tu@hostname'   # <- pegá tu línea
$Path = "C:\ProgramData\ssh\administrators_authorized_keys"
Add-Content -Path $Path -Value $Key
icacls.exe $Path /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
icacls.exe $Path   # debe mostrar solo Administrators y SYSTEM

# CASO B: tu usuario NO es administrador
$Key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... tu@hostname'   # <- pegá tu línea
$Path = "$env:USERPROFILE\.ssh\authorized_keys"
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.ssh" | Out-Null
Add-Content -Path $Path -Value $Key
icacls.exe $Path /inheritance:r /grant "$env:USERNAME:F"
```

> **Por qué los permisos importan:** si el archivo de claves no tiene los ACL correctos, OpenSSH en Windows lo rechaza en silencio y el error que ves es `Permission denied (publickey)`. Es la causa número uno de ese error.

**Paso 4.3 — Verificá desde el host:**

```bash
ssh <TU_USUARIO>@<IP_VM> "whoami"
```

Debe devolver tu usuario **sin pedir contraseña**.

---

## 5. Preparar una VM Linux

**Modelo de acceso:** el MCP entra como `<TU_USUARIO>` por clave y escala con `sudo -n` **granular** (comando por comando). Nunca como `root` directo.

```bash
# En la VM Linux:

# 1. OpenSSH
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo ss -tlnp | grep :22          # debe escuchar en 0.0.0.0:22

# 2. IP fija en la interfaz Host-Only.
#    Primero identificá cuál es (lo típico es enp0s3 / enp0s8):
ip -4 addr show
#   Luego creá la conexión con el nombre real de tu interfaz:
sudo nmcli con add type ethernet ifname <IF_HOSTONLY> con-name HostOnly \
  ipv4.addresses <IP_VM>/24 ipv4.method manual \
  ipv6.method disabled connection.autoconnect yes
sudo nmcli con up HostOnly
ping -c 2 192.168.10.1            # gateway del host (Host-Only)
ping -c 2 8.8.8.8                 # internet (vía NAT)

# 3. Clave pública del host
mkdir -p ~/.ssh && chmod 700 ~/.ssh
nano ~/.ssh/authorized_keys       # pegá la línea ssh-ed25519 del host
chmod 600 ~/.ssh/authorized_keys
chown -R $USER:$USER ~/.ssh

# 4. Endurecer sshd (drop-in: NO tocas el sshd_config principal)
sudo tee /etc/ssh/sshd_config.d/50-lab.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
EOF
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauth|pubkeyauth'
sudo systemctl restart ssh

# 5. Firewall: SSH solo desde la red de laboratorio
sudo ufw allow from 192.168.10.0/24 to any port 22 proto tcp
sudo ufw enable
sudo ufw status numbered
```

### 5.1 Permisos de sudo para el MCP (el paso que más se olvida)

El MCP corre `sudo -n <comando>` con los comandos que cada herramienta necesita. Sin una lista explícita, todo falla con `sudo: se requiere una contraseña`. **Nunca uses `NOPASSWD: ALL`.**

Creá `/etc/sudoers.d/10-mcp-lab` con `visudo` y pegá este bloque, reemplazando `<TU_USUARIO>`:

```bash
# Revisá y eliminá cualquier regla amplia que haya quedado de antes:
sudo rm -f /etc/sudoers.d/<TU_USUARIO>-nopasswd

sudo visudo -f /etc/sudoers.d/10-mcp-lab
```

```sudoers
Defaults:<TU_USUARIO> !use_pty
<TU_USUARIO> ALL=(root) NOPASSWD: \
  /usr/bin/tee, /bin/tee, /usr/bin/cat, /bin/cat, \
  /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod, /usr/sbin/chpasswd, \
  /usr/bin/gpasswd, /usr/bin/passwd, /usr/bin/chage, \
  /usr/bin/systemctl, /bin/systemctl, /usr/sbin/service, /bin/service, \
  /usr/bin/sed, /bin/sed, \
  /usr/sbin/ip, /sbin/ip, /usr/bin/nmcli, \
  /usr/bin/resolvectl, /bin/resolvectl, /usr/bin/systemd-resolve, /bin/systemd-resolve, \
  /usr/sbin/netplan, /usr/bin/netplan, \
  /usr/sbin/ufw, /sbin/ufw, /usr/sbin/iptables, /sbin/iptables, \
  /usr/bin/mkdir, /bin/mkdir, /usr/bin/chmod, /bin/chmod, /usr/bin/chown, /bin/chown, \
  /usr/bin/cp, /bin/cp, /usr/bin/rm, /bin/rm, \
  /usr/bin/setfacl, /bin/setfacl, \
  /usr/bin/testparm, /bin/testparm, /usr/bin/smbstatus, /bin/smbstatus, \
  /usr/sbin/auditctl, /sbin/auditctl, /usr/sbin/realm, /sbin/realm, \
  /usr/bin/true
```

Activá y verificá:

```bash
sudo chmod 0440 /etc/sudoers.d/10-mcp-lab
sudo chown root:root /etc/sudoers.d/10-mcp-lab
sudo visudo -c                                   # debe decir "análisis OK"
sudo -n /usr/bin/true && echo SUDO_OK            # debe imprimir SUDO_OK
```

> **Por qué están duplicados los paths (`/bin/tee` y `/usr/bin/tee`)?** Porque `sudo` compara el path **exacto** que aparece en la línea de comando. En las distros modernas `/bin` es un symlink a `/usr/bin`, pero según la distro y el binario la resolución puede caer a cualquiera de las dos formas. Listar ambas es la forma barata de que funcione en todos los casos.

> **Cuatro detalles que muerden (aprendidos a los golpes):**
>
> - `Defaults:<TU_USUARIO> !use_pty` es **obligatorio**. Sin él, `sudo` con `use_pty` intenta abrir una pseudo-terminal que no existe en una sesión SSH y la sesión queda colgada para siempre.
> - El archivo debe ser `0440` y `root:root`. `sudo` **ignora en silencio** cualquier archivo de sudoers con otros permisos, sin avisar. `tee` crea el archivo en `640`, por eso el `chmod` no es opcional.
> - `/usr/bin/true` está en la lista a propósito: es lo que usás para testear que el `sudo -n` funciona.
> - En el MCP **siempre `sudo -n`**, nunca `sudo` a secas. Sin `-n` el comando espera una contraseña interactiva que nunca va a llegar y cuelga hasta el timeout.

**Verificá desde el host:**

```bash
ssh -o BatchMode=yes <TU_USUARIO>@<IP_VM> "sudo -n /usr/bin/true && echo SUDO_OK"
```

### Supuestos de distribución

El código fue escrito para **Debian / Ubuntu / Mint** con `systemd`:

| Herramienta | Necesita | Si falta |
|-------------|----------|----------|
| `netplan_*` | netplan | no funciona |
| `samba_*` | samba (`smbd`, `testparm`, `smbstatus`) | no funciona |
| `realm_*` | `realmd` + `sssd` | no funciona |
| `samba_set_perms_linux` con ACL | paquete `acl` | `setfacl` no encontrado |
| `get_auditd_rules_linux` | `auditd` | devuelve `AUDITCTL_UNAVAILABLE` |
| `*_firewall_*_linux` | `ufw` | cae a `iptables` (solo lectura) |

**`firewalld` no está soportado.** Tampoco las distros sin `systemd`.

Además: los logs del sistema (`journalctl`, `/var/log/syslog`) se leen **sin sudo**, así que para verlos completos agregá tu usuario a los grupos `adm` y `systemd-journal`:

```bash
sudo usermod -aG adm,systemd-journal $USER
```

---

## 6. Instalar el MCP

### 6.1 Entorno virtual y dependencias

```powershell
# Windows (PowerShell)
cd <RUTA_AL_PROYECTO>
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -c "import fastmcp, mcp; print('ok')"
```

```bash
# Linux / macOS
cd <RUTA_AL_PROYECTO>
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -c "import fastmcp, mcp; print('ok')"
```

> **Windows: `Activate.ps1` bloqueado.** Si ves un error de ExecutionPolicy, no hace falta que cambies la política del sistema. Llamá al Python directamente, sin activar nada:
> ```powershell
> <RUTA_AL_PROYECTO>\.venv\Scripts\python.exe -m pip install -r requirements.txt
> ```
> De hecho, es así como el MCP se lanza en la [sección 6.3](#63-la-conexión-como-agente), así que el venv nunca necesita estar "activado".

### 6.2 Probar el servidor sin cliente

```bash
python server.py
```

**Comportamiento esperado:** el proceso se queda esperando entrada por `stdio`, sin imprimir nada nuevo y sin abrir puertos. Eso es correcto. `Ctrl+C` para salir. Cada arranque deja una línea en `logs/mcp.log`.

### 6.3 La conexión como agente

El servidor habla `stdio` estándar, así que sirve cualquier cliente MCP que soporte `command` + `cwd`.

**OpenCode** — por proyecto en `opencode.json`; global en `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "virtualbox_ssh": {
      "type": "local",
      "command": [
        ".venv\\Scripts\\python.exe",
        "server.py"
      ],
      "cwd": ".",
      "enabled": true,
      "timeout": 120000
    }
  }
}
```

**Las rutas son relativas a propósito.** `cwd: "."` hace que OpenCode resuelva el directorio del proyecto y ejecute el comando desde ahí, así que el mismo `opencode.json` funciona en cualquier máquina sin editar nada, sin rutas absolutas ni datos tuyo en el repo.

> `${workspaceFolder}` **no funciona**: es sintaxis de VS Code. OpenCode solo expande `{env:VAR}` y `{file:path}`. Si necesitás una ruta absoluta, definí `MCPVMS_HOME` y usá `{env:MCPVMS_HOME}`.

En Linux/macOS el ejecutable es `.venv/bin/python` (sin `\Scripts\`), y conviene usar `/` como separador para que la config sirva en ambos sistemas.

> **`timeout: 120000` no es opcional.** El default de OpenCode para traer la lista de herramientas es **5000 ms**. Con 156 herramientas, el discovery no llega a tiempo y el servidor simplemente no aparece en el cliente. 120 s le da margen de sobra.

> ⚠️ **`opencode.json` está versionado y es seguro commitearlo.** Solo contiene rutas relativas al proyecto, así que no filtra nada de tu máquina y un `git clone` funciona directo sin editar nada.

> ⚠️ **`config/machines.json` NO está versionado** (está en `.gitignore`). Contiene tu topología real de VMs: IPs, usuarios y alias SSH. El repo trae `config/machines.example.json` como plantilla — copiala y editá (ver [sección 7.2](#72-inventario-de-máquinas)).

Verificá la conexión con `opencode mcp list` — debería aparecer `virtualbox_ssh` conectado. Las herramientas se exponen con prefijo, o sea `virtualbox_ssh_list_machines`, `virtualbox_ssh_test_ssh`, etc.

**Claude Code CLI:**

```powershell
# Windows
claude mcp add virtualbox-ssh -- <RUTA_AL_PROYECTO>/.venv/Scripts/python.exe <RUTA_AL_PROYECTO>/server.py
claude mcp list
```

```bash
# Linux / macOS
claude mcp add virtualbox-ssh -- <RUTA_AL_PROYECTO>/.venv/bin/python <RUTA_AL_PROYECTO>/server.py
claude mcp list
```

**Otro cliente MCP genérico:** transporte `stdio`, comando `[<python del .venv>, <RUTA_AL_PROYECTO>/server.py]`, directorio `<RUTA_AL_PROYECTO>`, timeout de discovery ≥ 30000. Necesitás `ssh`/`scp`/`ping` en el `PATH` y el alias SSH de la [sección 7.1](#71-alias-ssh-en-el-host).

---

## 7. Configurar

Son tres pasos, en este orden. El primero es el que más se subestima.

### 7.1 Alias SSH en el host

El MCP **nunca** recibe IPs, usuarios ni claves. Todo eso vive en tu `~/.ssh/config`, y cada VM tiene un alias corto. Creá un bloque **por VM** en `%USERPROFILE%\.ssh\config` (Windows) o `~/.ssh/config` (Linux/macOS):

```
Host <ALIAS_VM>
    HostName <IP_VM>
    User <TU_USUARIO>
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
```

Ejemplo con dos VMs:

```
Host mi-win11
    HostName 192.168.10.20
    User miusuario
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new

Host mi-linux
    HostName 192.168.10.30
    User miusuario
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    PreferredAuthentications publickey
    PasswordAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    StrictHostKeyChecking accept-new
```

Verificá cada alias **antes** de seguir. Estos comandos simulan exactamente lo que hace el MCP:

```bash
ssh -G <ALIAS_VM>                             # 1. debe mostrar "hostname <IP_VM>" y "user <TU_USUARIO>"
ssh -o BatchMode=yes <ALIAS_VM> "echo SSH_OK"  # 2. debe imprimir SSH_OK, sin pedir nada
ssh -o BatchMode=yes <ALIAS_VM> "sudo -n /usr/bin/true && echo SUDO_OK"  # 3. solo Linux
```

Si el paso 2 te pide contraseña, el problema está en la clave pública de la VM (secciones 4 o 5), no acá. Volvé para atrás.

> **Cambiaste de VM o de hardware y aparece `Host key verification failed`:** la huella quedó vieja en `known_hosts`. Corré `ssh-keygen -R <IP_VM>` y aceptá la huella una vez con `ssh <ALIAS_VM> "hostname"`.

> **Con passphrase en la clave:** cargala en el agente para que el MCP no te la pregunte:
> ```powershell
> # Windows
> Get-Service ssh-agent | Set-Service -StartupType Automatic
> Start-Service ssh-agent
> ssh-add "$env:USERPROFILE\.ssh\id_ed25519"
> ```
> ```bash
> # Linux/macOS
> eval "$(ssh-agent -s)"
> ssh-add ~/.ssh/id_ed25519
> ```

### 7.2 Inventario de máquinas

`config/machines.json` mapea nombre amigable → sistema operativo + alias SSH. Copiá la plantilla y editá:

```bash
cp config/machines.example.json config/machines.json
```

```json
{
  "machines": {
    "mi-win11": {
      "ssh_host": "mi-win11",
      "os": "windows",
      "ip": "192.168.10.20",
      "description": "Windows 11 - estacion de trabajo",
      "ssh_user": "miusuario"
    },
    "mi-linux": {
      "ssh_host": "mi-linux",
      "os": "linux",
      "ip": "192.168.10.30",
      "description": "Linux Mint - laboratorio",
      "ssh_user": "miusuario"
    }
  }
}
```

| Campo | Obligatorio | Significado |
|-------|-------------|-------------|
| `ssh_host` | sí | **Debe** existir como `Host` en tu `~/.ssh/config` |
| `os` | sí | Solo `windows` o `linux`. Decide qué herramientas se ofrecen |
| `ip` | no | **Informativo.** El ping real usa la IP que resuelve `ssh -G` |
| `description` | no | Texto libre que ve el agente como contexto |
| `ssh_user` | no | **Informativo.** El usuario real sale del alias SSH |

> ⚠️ **Reemplazá las entradas de ejemplo.** El `config/machines.json` que viene en el repo trae 4 VMs de un laboratorio previo (`win11-vm`, `winserver-vm`, `mint-vm`, `ubuntu-vm`, con IPs `192.168.10.x` y usuarios que no existen en tu máquina). Borrá las que no tengas y agregá las tuyas. Si no lo hacés, `list_machines` va a listar máquinas fantasma y cualquier agente que las use va a fallar.

### 7.3 Conectar el agente

Ya lo tenés en la [sección 6.3](#63-la-conexión-como-agente). Asegurate de tener `opencode.json` editado con tu ruta y `timeout: 120000`.

---

## 8. Verificación end-to-end

Con el cliente conectado, pedile al agente estas cinco cosas **en orden**. Es la secuencia de diagnóstico completa: si las cinco pasan, el MCP está 100% operativo.

| # | Pedí al agente | Resultado esperado |
|---|---------------|--------------------|
| 1 | `list_machines()` | Tus máquinas, con `name`, `ssh_host`, `os`, `ip`, `ssh_user` |
| 2 | `machine_profile("<ALIAS_VM>")` | El mismo dato de esa VM sola |
| 3 | `test_ssh("<ALIAS_VM>")` | `"ok": true` y `stdout` con `MCP_SSH_OK` |
| 4 | `get_system_info_linux("<ALIAS>")` o `get_system_info("<ALIAS>")` | Datos del sistema de la VM |
| 5 | `run_command_linux("<ALIAS>", "sudo -n /usr/bin/true && echo SUDO_OK", confirm=true)` | `SUDO_OK` (solo Linux) |

Si algo falla, el campo `diagnosis` de `test_ssh` suele decirte el motivo exacto. La [sección 12](#12-troubleshooting) mapea cada síntoma a su solución.

> **Sanity check por línea de comandos:** si preferís verificar sin pasar por el agente,
> ```powershell
> # Windows: ver las últimas líneas del log
> Get-Content .\logs\mcp.log -Tail 50
> ```
> ```bash
> # Linux/macOS
> tail -n 50 logs/mcp.log
> ```
> Cada invocación queda registrada como `AUDIT: <herramienta> | <máquina> | <detalle>`.

---

## 9. Uso diario

Una vez verificado, así es como se usa en la práctica. Los prompts de abajo son en lenguaje natural; tu agente los traduce a las herramientas.

**Primeros pasos con una VM nueva**

```
Conectate a mi-linux y decime el hostname, la cantidad de CPUs, la memoria
y cuánto disco libre hay.
```

```
Listame los servicios de mi-linux que están corriendo, y decime cuál no
está arranca después de un reboot.
```

```
Mostrame los últimos 50 eventos del log System de mi-win11.
```

**Archivos**

```
Leé el archivo /var/log/auth.log de mi-linux y decime si hubo intentos
de acceso fallidos.
```

```
Subí el archivo C:\Temp\instalador.exe de mi PC a mi-win11 en C:\Temp\.
```

**Diagnóstico**

```
mi-linux no responde a ping. Decime si el problema es de red o de servicio
SSH, y revisá la configuración de red.
```

**Cosas que cambian estado** (recordá que el agente te va a pedir confirmación)

```
Creá el usuario "alumno01" en mi-linux con el password que te paso, y
agregalo al grupo sudo.
```

```
Abrí el puerto 8080 TCP en el firewall de mi-win11.
```

```
Reiniciá el servicio ssh de mi-linux.
```

**Buenas prácticas que te van a ahorrar errores**

- **Preferí la herramienta específica** (`get_service_status`) sobre el comodín (`run_command`): devuelve JSON estructurado en vez de texto para parsear.
- **Para scripts largos o con comillas**, usá `run_powershell_script` / `run_bash_script_linux`. Viajan en base64 y evitás infiernos de escapado.
- **Verificá antes de agir.** `test_ssh` y `get_network_config` son gratis (solo lectura) y te ahorran un debug painful después de un cambio.
- **Sacá snapshots de VirtualBox** antes de cualquier tarea de red, AD o netplan. Es la red de seguridad cuando algo sale mal.
- **Siempre `confirm=true` explícito**: si el agente no lo pide, asumí que la herramienta es de solo lectura y andá bien.

---

## 10. Catálogo de herramientas

**156 herramientas**: 93 de Windows/agnósticas/workflows y 63 de Linux (sufijo `_linux`).

Todas devuelven **texto JSON**. Contrato común: `@mcp.tool() -> str` con `json.dumps(clean_output(...))`.

### Niveles de protección

Cada herramienta tiene un nivel. La explicación completa está en la [sección 11](#11-seguridad), pero la columna **Nivel** te dice de una vistazo si podés llamarla sin pensar:

| Nivel | Significado |
|-------|-------------|
| **L0** | Solo lectura. Sin confirmación. Llamala tranquilo. |
| **L1** | Cambia algo. Exige `confirm=true`. |
| **L2** | Irreversible o puede cortar SSH. Exige `confirm` + `acknowledge` + `ack_text` + eco del valor. **Leé la [sección 11](#11-seguridad) antes.** |

### 10.1 Conectividad

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `list_machines` | L0 | Lista las VMs del inventario |
| `machine_profile` | L0 | Perfil de una VM |
| `test_ssh` | L0 | Prueba SSH; si falla, incluye un diagnóstico |
| `check_reachability` | L0 | Resuelve la IP vía `ssh -G` y hace ping |

### 10.2 Ejecución remota

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `run_command` | L1 | Comando directo (Windows / PowerShell) |
| `run_powershell_script` | L1 | Script multilínea PowerShell (base64 UTF-16LE) |
| `run_command_linux` | L1 | Comando bash directo. **No** pone `sudo` solo: anteponé `sudo -n` vos |
| `run_bash_script_linux` | L1 | Script bash multilínea (base64 piped a `bash -s`) |

`timeout_seconds` va de 1 a 600. Default 60.

### 10.3 Inventario del sistema

| Windows | Linux | Nivel | Qué hace |
|---------|-------|-------|----------|
| `get_system_info` | `get_system_info_linux` | L0 | SO, CPU, memoria, uptime |
| `get_disk_info` | `get_disk_info_linux` | L0 | Unidades, tipo, espacio usado |
| `get_installed_software` | `get_installed_software_linux` | L0 | Registro de Windows / `dpkg -l` (con fallback a `rpm -qa`) |
| `get_hotfixes` | — | L0 | Parches instalados (solo Windows) |
| `get_environment_vars` | `get_environment_vars_linux` | L0 | Variables de entorno |
| `set_environment_var` | `set_environment_var_linux` | L1 | Define una variable. En Linux persiste en `/etc/environment` |

### 10.4 Logs y eventos

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `get_event_logs` | L0 | Event log de Windows (`Get-WinEvent`). `log_name` + `lines` |
| `get_system_event_logs` | L0 | Alias explícito del anterior, sin colisión de registro |
| `get_logs` | L0 | Logs de un servicio o fuente |
| `get_event_logs_linux` | L0 | `journalctl` por unidad o syslog |
| `get_logs_linux` | L0 | Logs de un servicio systemd |
| `get_journal_linux` | L0 | Journal completo, con filtro por prioridad |
| `get_auditd_rules_linux` | L0 | Reglas de auditoría del kernel (`auditctl -l`) |

`lines` va de 1 a 1000. La salida se trunca a la cola (30k para logs, 50k para event logs).

### 10.5 Archivos

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `read_file` / `read_file_linux` | L0 | Lee texto. `max_chars` 1–100000. En Linux usa `sudo -n cat` para rutas `/etc/*` |
| `list_directory` / `list_directory_linux` | L0 | Lista un directorio. Default `C:\` (Windows) y `/home` (Linux) |
| `upload_file` / `upload_file_linux` | L0 | `scp` host → VM. Timeout 120s |
| `download_file` / `download_file_linux` | L0 | `scp` VM → host. Timeout 120s |
| `write_file` / `write_file_linux` | L1 | Escribe texto (base64 → `Set-Content` / `sudo -n tee`) |

> ⚠️ **Cuidado con el default de `list_directory_linux`:** el código usa `/home` como valor por defecto. **Pasá la ruta explícitamente** para no listar un directorio distinto del que esperás.

### 10.6 Procesos

| Windows | Linux | Nivel | Qué hace |
|---------|-------|-------|----------|
| `list_processes` | `list_processes_linux` | L0 | Procesos activos (`Get-Process` / `ps aux`) |
| `get_process_detail` | `get_process_detail_linux` | L0 | Detalle de un proceso por nombre o PID |
| `kill_process` | `kill_process_linux` | L1 | Termina un proceso. En Linux acepta PID o nombre |

### 10.7 Servicios

| Windows | Linux | Nivel | Qué hace |
|---------|-------|-------|----------|
| `list_services` | `list_services_linux` | L0 | Servicios y estado |
| `get_service_status` | `get_service_status_linux` | L0 | Estado de uno |
| `start_service` | `start_service_linux` | L0 | Inicia un servicio parado |
| `restart_service` | `restart_service_linux` | L0 | Reinicia un servicio |
| `stop_service` | `stop_service_linux` | L1 | Detiene un servicio |

### 10.8 Red

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `get_network_config` / `get_network_config_linux` | L0 | Interfaces, IPs, rutas, DNS |
| `get_dns_cache` / `get_dns_cache_linux` | L0 | Caché DNS |
| `flush_dns` / `flush_dns_linux` | L0 | Vacía la caché DNS |
| `network_preflight` | L0 | Simula un cambio de red **sin aplicarlo** y valida subred, gateway y DNS |
| `set_ip_address` / `set_ip_address_linux` | **L2** | Cambia la IP. **Puede dejarte la VM inaccesible.** Requiere eco de la IP nueva |
| `set_dns_server` / `set_dns_server_linux` | **L2** | Cambia el DNS. Requiere eco del DNS nuevo |

> **Usá `network_preflight` antes de cualquier `set_ip_address`.** Te dice si el gateway cae fuera de la subred y si el DNS es coherente, sin tocar nada. Está diseñado justamente para eso.

### 10.9 Firewall

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `get_firewall_rules` | L0 | Reglas de Windows |
| `get_firewall_rules_linux` | L0 | `ufw status verbose` (fallback a `iptables`) |
| `get_firewall_status_linux` | L0 | Estado resumido de `ufw` |
| `open_firewall_port` / `open_firewall_port_linux` | L1 | Abre un puerto |
| `enable_firewall_rule` / `enable_firewall_rule_linux` | L1 | Habilita una regla existente |
| `disable_firewall_rule` / `disable_firewall_rule_linux` | L1 | Deshabilita una regla |

### 10.10 DNS (servidor Windows)

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `dns_list_zones` | L0 | Zonas DNS |
| `dns_list_records` | L0 | Registros de una zona |
| `dns_test_resolution` | L0 | Resuelve un FQDN |
| `dns_add_a_record` | **L2** | Crea un registro A (idempotente) |
| `dns_delete_record` | **L2** | Borra un registro |

### 10.11 Usuarios y grupos

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `list_users` / `list_users_linux` | L0 | Usuarios locales |
| `list_groups` / `list_groups_linux` | L0 | Grupos |
| `get_user_linux` | L0 | Detalle de un usuario (grupos, expiración) |
| `enable_user` / `enable_user_linux` | L0 | Habilita una cuenta |
| `create_user` / `create_user_linux` | L1 | Crea un usuario |
| `delete_user` / `delete_user_linux` | L1 | Elimina un usuario (y su home en Linux) |
| `disable_user` / `disable_user_linux` | L1 | Deshabilita una cuenta |
| `add_user_to_group` / `add_user_to_group_linux` | L1 | Agrega a un grupo |
| `remove_user_from_group` / `remove_user_from_group_linux` | L1 | Saca de un grupo |

### 10.12 Contraseñas

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `get_password_policy` | L0 | Política de contraseñas |
| `get_password_policy_linux` | L0 | Política de Linux (`chage` + `login.defs`) |
| `set_password_policy` / `set_password_policy_linux` | L1 | Ajusta longitud, expiración, unicidad |
| `set_password_expiry_linux` | L1 | Cambia la expiración de una cuenta |
| `set_password_linux` | **L2** | Cambia la contraseña de un usuario |

### 10.13 Shares y archivos compartidos

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `list_shared_folders` | L0 | Shares de Windows |
| `list_shared_folders_linux` | L0 | Shares Samba |
| `samba_list_shares_linux` | L0 | Shares Samba (`testparm` + `smbstatus`) |
| `share_list` | L0 | Shares SMB de Windows |
| `share_get_effective` | L0 | Permiso **efectivo** combinando Share y NTFS (el más restrictivo gana) |
| `share_test_from_client` | L0 | Prueba acceso a un UNC desde otra máquina |
| `create_shared_folder` / `create_shared_folder_linux` | L1 | Crea un share |
| `share_create` | **L2** | Share + permisos completos (AccessBased, sin `Everyone`) |
| `share_grant_access` | **L2** | Da acceso a un share |
| `share_revoke_access` | **L2** | Revoca acceso |
| `ntfs_grant` | **L2** | Otorga permiso NTFS con `icacls` |
| `samba_create_share_linux` | **L2** | Crea share Samba (valida con `testparm`, rollback si falla) |
| `samba_set_perms_linux` | **L2** | Dueños, grupo, modo y ACLs de un share |

### 10.14 Tareas programadas

| Windows | Linux | Nivel | Qué hace |
|---------|-------|-------|----------|
| `list_scheduled_tasks` | `list_scheduled_tasks_linux` | L0 | Lista tareas |
| `get_task_detail` | `get_task_detail_linux` | L0 | Detalle de una tarea |
| `create_scheduled_task` | `create_scheduled_task_linux` | L1 | Crea una tarea. `trigger_time` en `HH:mm` |
| `delete_scheduled_task` | `delete_scheduled_task_linux` | L1 | Elimina una tarea |

En Linux, `trigger_time` en formato `HH:mm` se traduce a cron (`m h * * *`). Si pasás una expresión cron completa de 5 campos, se usa tal cual.

### 10.15 Active Directory (Windows)

**Solo lectura (L0):**

| Tool | Qué hace |
|------|----------|
| `ad_check_prereq` | Verifica rol AD-Domain-Services, módulo ActiveDirectory, dominio/bosque actual |
| `ad_get_domain` | Dominio y bosque actual del DC |
| `ad_list_computers` | Equipos del dominio |
| `ad_list_users` | Usuarios del dominio |
| `ad_list_groups` | Grupos del dominio |
| `ad_list_ou` | Unidades organizativas |
| `get_audit_policy` | Política de auditoría del DC |
| `get_security_events` | Eventos 4624/4625/4663/5140 |
| `get_gpo_report` | Reporte de GPOs |

**Escritura (L2 — requieren doble confirmación):**

| Tool | Qué hace |
|------|----------|
| `ad_install_roles` | Instala AD-Domain-Services + RSAT. **Reinicia en algún momento** |
| `ad_install_forest` | Crea un bosque/dominio nuevo. **Irreversible.** Requiere eco del nombre de dominio |
| `ad_restart_after_promote` | Reinicia la VM tras promover a DC. **Corta SSH** |
| `ad_create_ou` | Crea una OU |
| `ad_create_group` | Crea un grupo (Global / DomainLocal / Universal) |
| `ad_create_user` | Crea un usuario en el dominio |
| `ad_create_computer` | Crea un equipo en el directorio |
| `ad_set_password` | Resetea la contraseña de un usuario |
| `ad_enable_user` / `ad_disable_user` | Habilita / deshabilita un usuario |
| `ad_add_group_member` / `ad_remove_group_member` | Agrega / quita un miembro de un grupo |
| `ad_join_domain` | Une un equipo al dominio. **Requiere eco del nombre de dominio** |
| `enable_audit_subcategory` | Activa una subcategoría de auditoría |

### 10.16 Identidad y red Linux (avanzado)

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `netplan_list_files_linux` | L0 | Lista los archivos de `/etc/netplan/` |
| `netplan_get_linux` | L0 | Muestra el YAML de un archivo de netplan |
| `netplan_set_linux` | **L2** | Escribe un YAML de netplan (valida en host, backup + `netplan generate`, **no aplica**). Requiere eco del nombre de archivo |
| `netplan_apply_linux` | **L2** | Aplica netplan. **Puede cortar SSH.** Requiere eco del literal `netplan-apply` |
| `realm_check_linux` | L0 | Estado de realm y `sssd` |
| `realm_join_linux` | **L2** | Une la VM a un dominio (realm join) |
| `realm_leave_linux` | **L2** | Saca la VM del dominio |

### 10.17 Workflows (alto nivel)

Estas herramientas componen varias de las anteriores en una operación idempotente. Son la forma más eficiente de hacer tareas grandes.

| Tool | Nivel | Qué hace |
|------|-------|----------|
| `check_domain_health` | L0 | Salud del dominio por capas: ping, DNS, `dsgetdc`, AD, puertos 445/389 |
| `collect_evidence` | L0 | Recolecta evidencia AD/DNS/auditoría/GPO. Solo lectura |
| `provision_org` | **L2** | Aprovisiona una org completa: OU + sub-OUs + grupos + usuarios. Idempotente |
| `publish_share` | **L2** | Publica un share SMB + NTFS y lo prueba desde un cliente. Idempotente |

---

## 11. Seguridad

### Los tres niveles de protección

El MCP tiene tres capas de freno. Entendelas antes de la primera tarea destructiva.

**L0 — Sin freno.** Solo lectura. No cambia el estado de la VM. Llamalas sin miedo.

**L1 — Un freno: `confirm=true`.** 40 herramientas. Si la llamás sin `confirm=true`, el MCP **lanza un error** antes de conectarse por SSH:

```
La herramienta 'run_command' es potencialmente destructiva.
Debes pasar confirm=true para ejecutarla.
```

**L2 — Tres frenos más el eco.** 33 herramientas irreversibles o que pueden cortar tu SSH. Necesitan las cuatro cosas:

1. `confirm=true`
2. `acknowledge=true`
3. `ack_text` con la frase **exacta** (distingue mayúsculas)
4. **El eco del valor peligroso** (la IP, el dominio, el nombre de archivo...)

Si falta cualquiera de las cuatro, el MCP **no lanza error: devuelve un JSON `dry_run` y no toca SSH**. Algo así:

```json
{
  "ok": false,
  "dry_run": true,
  "warning": "'set_ip_address' es IRREVERSIBLE o puede cortar SSH. Haz snapshot de VirtualBox AHORA y ten la consola de la VM abierta antes de reintentar. Faltante: acknowledge=true, ack_text='SE-QUE-PUEDO-PERDER-SSH' exacto.",
  "would_run": "set_ip_address (objetivo='192.168.10.50')",
  "missing": ["acknowledge=true", "ack_text='SE-QUE-PUEDO-PERDER-SSH' exacto"]
}
```

> El `dry_run` es tu **simulador**: dice exactamente qué falta y qué haría. Completá lo que pida y reintentá.

### Las tres frases de confirmación

| Frase exacta | Cuándo |
|---------------|--------|
| `SE-QUE-ES-IRREVERSIBLE` | El cambio no se puede deshacer (25 herramientas: AD, DNS, shares, realm) |
| `SE-QUE-PUEDO-PERDER-SSH` | El cambio puede dejarte sin conexión a la VM (7 herramientas: red, netplan, reinicio post-promoción) |
| `SE-QUE-INSTALA-ROLES` | Instala un rol de Windows que después reinicia (1 herramienta: `ad_install_roles`) |

El `ack_text` es **case-sensitive**. `se-que-es-irreversible` no funciona.

### Herramientas que exigen eco del valor

Cinco herramientas (más dos con dominio) necesitan que repitas el valor peligroso en un parámetro aparte. Es una confirmación deliberada de que no mandaste el valor sin querer.

| Tool | Parámetro | Valor exacto esperado |
|------|-----------|-----------------------|
| `set_ip_address` / `set_ip_address_linux` | `echo_confirm` | La IP nueva, exacta |
| `set_dns_server` / `set_dns_server_linux` | `echo_confirm` | El DNS nuevo, exacto |
| `netplan_set_linux` | `echo_confirm` | El nombre del archivo |
| `netplan_apply_linux` | `echo_confirm` | El literal `netplan-apply` |
| `ad_install_forest` / `ad_join_domain` | `domain_name_confirm` | El nombre de dominio |

### Reglas del juego

- **Solo laboratorio.** `run_command*`, `write_file*` y `set_ip_address*` dan control total de la VM. Nada de producción sin hardening adicional.
- **Menor privilegio.** SSH como usuario de laboratorio + `sudo` granular (sección 5.1) o cuenta dedicada. Nunca `root` directo, nunca `NOPASSWD: ALL`.
- **Snapshot antes de L2.** Antes de cualquier herramienta que pueda cortar SSH (netplan, IP, DNS, reinicio), tené un snapshot de VirtualBox y la consola abierta. El `dry_run` te lo recuerda.
- **El gate corre antes que SSH.** Los validadores de entrada se ejecutan antes que el gate, así que un dato inválido (IP mal formada, DN inválido) lanza `ValueError` en vez de devolver `dry_run`.
- **Claves fuera del repo.** La privada nunca viaja. `IdentityFile` + `IdentitiesOnly yes`. Con passphrase, `ssh-agent`.
- **Auditoría completa.** Todo queda en `logs/mcp.log` con el formato `AUDIT: <herramienta> | <máquina> | <detalle>`. Los secretos se redactan automáticamente.

---

## 12. Troubleshooting

| Síntoma | Causa probable | Fix |
|---------|----------------|-----|
| El cliente no lista `virtualbox_ssh` | Discovery excedió el timeout (default 5000 ms con 156 tools) | Agregar `"timeout": 120000` en la config del MCP |
| El cliente no lista `virtualbox_ssh` | `command` apunta a una ruta literal con `${workspaceFolder}` | OpenCode no expande esa variable. Usá rutas relativas con `cwd: "."`, o `{env:MCPVMS_HOME}` |
| El cliente no lista `virtualbox_ssh` | Faltó crear el venv (`.venv` no existe tras un clone) | Repetir la sección 6.1: `py -3.11 -m venv .venv` + `pip install -r requirements.txt` |
| El cliente no lista `virtualbox_ssh` | Corriendo en Linux/macOS con la ruta de Windows | Usar `.venv/bin/python` (sin `\Scripts\`) |
| El cliente no lista `virtualbox_ssh` | JSON mal formado o `python` mal apuntado | Validar el JSON; correr `python server.py` a mano (debe esperar en stdio) |
| `list_machines` muestra VMs que no existen | Copiaste `machines.example.json` sin editarlo | Reemplazar las entradas de ejemplo por las tuyas (sección 7.2) |
| `test_ssh` → `Permission denied (publickey)` | Alias mal, o clave no autorizada en la VM | `ssh -vvv <ALIAS> "echo OK"` → buscar `Offering public key` / `Server accepts key`. En Windows, revisar los ACL de `administrators_authorized_keys` |
| `Host key verification failed` | Huella vieja en `known_hosts` | `ssh-keygen -R <IP_VM>` y aceptar una vez |
| `check_reachability` falla pero `test_ssh` sí | ICMP bloqueado por el firewall de la VM | No es bloqueante: si SSH funciona, el MCP trabaja igual |
| `sudo: se requiere una contraseña` | El comando no está en la lista NOPASSWD | Ampliar `/etc/sudoers.d/10-mcp-lab`, `chmod 0440`, `visudo -c` |
| `sudo: se requiere una contraseña` en `netplan_*`, `samba_*`, `realm_*`, `set_dns_server_linux` | Faltan binarios en la sudoers | Usar la sudoers completa de la sección 5.1 (incluye `netplan`, `testparm`, `smbstatus`, `realm`, `resolvectl`, `setfacl`, `auditctl`, `sed`, `service`, `iptables`) |
| `get_password_policy_linux` no cambia nada | Falta `sed` en la sudoers | Agregar `/usr/bin/sed` y `/bin/sed` a la lista |
| `sudo` cuelga la sesión (Linux) | `use_pty` activado sin tty real | Agregar `Defaults:<TU_USUARIO> !use_pty` en sudoers |
| `sudo` ignora tu archivo sudoers | Permisos distintos de `0440 root:root` | `chmod 0440` + `chown root:root` + `visudo -c` |
| `write_file_linux` en `/etc/*` falla | Falta `tee`/`cat` en sudoers, o la ruta tiene `\` | Las rutas Linux arrancan con `/`. Verificá la sudoers |
| `set_ip_address*` dejó la VM muda | IP o gateway mal en la interfaz de gestión | Entrar por consola de VirtualBox y revertir. **Hacé snapshot antes** |
| `run_command` da timeout | `timeout_seconds` muy corto | Subirlo entre 120 y 600 (máximo) |
| `journalctl` o `/var/log/syslog` salEN vacíos | El usuario no está en `adm`/`systemd-journal` | `sudo usermod -aG adm,systemd-journal $USER` y reconectar |
| `df` se cuelga o tarda en Mint | Toca el filesystem `fuse.gvfsd-fuse` | Usá `df --local` en scripts |
| PowerShell `Activate.ps1` bloqueado | ExecutionPolicy del sistema | No hace falta activar: usá `.venv\Scripts\python.exe` directo |
| Todo SSH vía MCP da `timeout` con stdout vacío | `ssh` heredando el stdin del servidor stdio | Ya está corregido (`stdin=DEVNULL` en `core/ssh.py`); si te pasa, actualizá el código y reiniciá el cliente |

**Logs del servidor:**

```powershell
# Windows
Get-Content .\logs\mcp.log -Tail 100
```

```bash
# Linux/macOS
tail -n 100 logs/mcp.log
```

---

## Apéndice — Referencia para quien mantiene el MCP

> Esta sección es para desarrollo. Si solo querés usar el MCP, las secciones 1 a 12 te alcanzan.

### Stack tecnológico

| Capa | Tecnología | Archivo |
|------|------------|---------|
| Protocolo | MCP `stdio` | `server.py` |
| Framework | `fastmcp==2.12.*` + `mcp==1.29.*` | `requirements.txt` |
| Transporte | OpenSSH nativo del host | `core/ssh.py` |
| Shell Windows | PowerShell 5.1 (vía `DefaultShell`) | `tools/advanced.py` |
| Shell Linux | bash + systemd, con `sudo -n` | `tools/linux/advanced.py` |
| Core | Python 3.10+ stdlib | `core/` |
| Config | `machines.json` + alias SSH | `core/config.py` |
| Observabilidad | `logs/mcp.log` + `stderr` | `server.py`, `core/audit.py` |

### Timeouts y límites (`core/config.py`)

| Constante | Valor | Uso |
|-----------|-------|-----|
| `SSH_TIMEOUT_DEFAULT` | 60s | `run_command` por defecto |
| `SSH_CONNECT_TIMEOUT` | 10s | `ssh -o ConnectTimeout` |
| `SSH_MAX_TIMEOUT` | 600s | Tope de `validate_timeout()` |
| `SSH_TEST_TIMEOUT` | 20s | `test_ssh` |
| `SSH_PING_TIMEOUT` | 10s | `check_reachability` |
| `SCP_TIMEOUT` | 120s | `upload/download` |
| `MAX_OUTPUT_CHARS` | 10k | Truncado de salida |
| `MAX_LOG_CHARS` | 30k | Truncado de logs |
| `MAX_EVENT_LOG_CHARS` | 50k | Truncado de event logs |
| `MAX_EVENT_LOG_LINES` | 1000 | Tope del parámetro `lines` |

### Estructura del proyecto

```
server.py                    # FastMCP + register_all_tools (156 tools)
core/config.py               # Rutas, HOST_OS, timeouts, load_machines_config, get_machine
core/constants.py            # DESTRUCTIVE_TOOLS (40), IRREVERSIBLE_TOOLS
core/ssh.py                  # build_ssh_args/scp/ping, run_process, wrap_sudo, diagnose_ssh_error
core/os_router.py            # get_os_type, require_os, dispatch windows|linux
core/validation.py           # 8 validadores + require_confirmation (L1)
core/validators.py           # IP, prefijo, gateway, DNS, FQDN, DN, sam, share, UNC, YAML, ack, password_b64
core/security_gate.py        # require_double_confirm (L2), ACK_IRREVERSIBLE / ACK_SSH / ACK_ROLES
core/ps_escape.py            # escape_ps_single_quote (literales PowerShell)
core/audit.py                # audit_log + sanitize_detail (redacta secretos)
tools/__init__.py            # register_all_tools
tools/*.py                   # 93 herramientas Windows/agnósticas (PowerShell)
tools/linux/*.py             # 63 herramientas *_linux (bash/systemd/sudo -n)
tools/workflows/*.py         # provision_org, check_domain_health, publish_share, collect_evidence
tools/common/                # audit_log compartido
config/machines.json         # Inventario (ssh_host = alias SSH, os = windows|linux)
config/machines.example.json # Plantilla limpia de ejemplo
```

### Tests

```bash
pytest tests/ -v
```

Tests incluidos: `test_config`, `test_ssh`, `test_validation`, `test_gate_validators`, `test_ad_dns_share`, `test_workflows`. La mayoría usa mocks y **no necesita VMs**.

Verificación sintáctica:

```bash
python -m py_compile server.py tools/__init__.py tools/*.py tools/*/*.py core/*.py
```

### Convenciones de código

- Contrato de tools: `@mcp.tool() -> str` devolviendo JSON con `json.dumps(clean_output(...))`
- Docstrings en español
- En Linux: siempre `sudo -n` + `shlex.quote` para interpolar valores
- Destructivas (L1) llaman `require_confirmation()`; irreversibles (L2) llaman `require_double_confirm()`
- Secretos como `*_b64` (base64 UTF-8), nunca en claro en logs, argumentos de proceso o JSON
- Operaciones idempotentes devuelven `already_exists: true` en vez de reintentar
- Los reinicios que no se pueden hacer automáticamente devuelven `reboot_required: true`
- `clean_output()` trunca a la cola del buffer
