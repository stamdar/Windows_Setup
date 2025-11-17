# Windows Workstation Bootstrap Script

## Quick Usage Examples (Most Important — Read First)

### Run directly from the internet (PowerShell 7 recommended)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm "https://raw.githubusercontent.com/stamdar/Windows_Setup/main/windows-bootstrap.ps1" | iex
````

### Run from internet with args
```
iex "& { $(irm 'https://raw.githubusercontent.com/stamdar/Windows_Setup/main/windows-bootstrap.ps1') } -SkipDebloat -SkipPackages"
```

### Run after cloning the repo

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\windows-bootstrap.ps1
```

### Skip Windows 11 debloat

```powershell
.\windows-bootstrap.ps1 -SkipDebloat
```

### Skip Chocolatey package installs (keep tweaks, profile, etc.)

```powershell
.\windows-bootstrap.ps1 -SkipPackages
```

### Skip all theming (Catppuccin, Obsidian/Sublime/VS Code themes)

```powershell
.\windows-bootstrap.ps1 -SkipTheming
```

### Combine switches

```powershell
.\windows-bootstrap.ps1 -SkipDebloat -SkipPackages -SkipTheming
```

---

## Overview

A comprehensive and idempotent Windows workstation bootstrap script aimed at developers, security researchers, and engineers.

This script:

* Prepares and hardens the OS
* Installs and updates core tooling via Chocolatey
* Applies UI/Explorer and privacy tweaks
* Configures PowerShell (modules, profile, theming)
* Optionally provisions WSL + Ubuntu with security tooling
* Optionally applies Catppuccin Mocha theming across major applications
* Summarizes approximate disk usage and total runtime at the end

---

## Parameters

All parameters are optional switches; combine them as needed.

* `-SkipDebloat`
  Skip the Windows 11 debloat step (Raphire / Win11Debloat).

* `-SkipPackages`
  Skip all Chocolatey package installation/updates, plus pip/pipx setup and Sysinternals.
  OS tweaks, profile, WSL provisioning, and theming still run where possible.

* `-SkipTheming`
  Skip Windows Terminal / VS Code / Sublime / Obsidian Catppuccin theming and Obsidian vault customization.
  Core PowerShell profile and modules still install.

---

## Features

### System Preparation

* Auto-elevates to Administrator (re-launches itself with `runas` when needed)
* Detects OS version (Windows 10, 11, Server)
* Optional Windows 11 debloat using [Raphire/Win11Debloat](https://debloat.raphi.re/)
* **OneDrive hardening/removal (early in the script):**

  * Stops the OneDrive process
  * Invokes `OneDriveSetup.exe /uninstall` (both 32- and 64-bit where present)
  * Sets policies to disable sync and block OneDrive traffic before sign-in
* Infers OneDrive desktop redirection and adapts desktop shortcut cleanup
* Privacy hardening:

  * Telemetry level minimized
  * Disables Tailored Experiences and Spotlight content
  * Disables Bing / web search in Start
  * Disables Cortana
  * Disables lock-screen tips / ads
* Explorer/UI enhancements:

  * Show file extensions
  * Show hidden & protected OS files
  * Remove **“3D Objects”** from *This PC*
  * Dark theme system-wide (apps + system)
  * Classic right-click menu on Windows 11
  * Explorer opens to **This PC**, not Quick Access
  * Hides “Recommended” section in Start (where supported)
* Windows Terminal auto-start at login
* Best-effort deterministic taskbar ordering:

  * Unpins some default junk (Edge, Store, Mail, Calendar where possible)
  * Pins, in order (after File Explorer):

    * Windows Terminal
    * Sublime Text
    * Visual Studio Code
    * Obsidian
    * Firefox
    * Chrome

> Taskbar pin/unpin behavior is best-effort and may vary across Windows builds / languages.

---

## Application Installation via Chocolatey

> Skipped entirely when `-SkipPackages` is used.

Installs or updates (idempotent):

* Windows Terminal
* Sublime Text 4
* Visual Studio Code
* Obsidian
* Google Chrome
* Mozilla Firefox
* Python 3, pip, pipx
* Go, Rust (rustup)
* Git
* Nmap, Wireshark
* jq
* Everything Search
* Process Hacker
* Sysinternals Suite (with `--ignore-checksums` best-effort)
* 7-Zip
* Adobe Reader
* GNU Coreutils (GOW)
* SetUserFTA
* fzf

Additional behavior:

* Installs Chocolatey itself if missing, and refreshes `PATH` in the current session.
* Automatically removes any **new** desktop shortcuts created during package installation so your desktop isn’t cluttered.
* At the end of the run, the script:

  * Approximates **disk space consumed by the Chocolatey-installed packages on this run** (in GB)
  * Prints **total runtime** in `hh:mm:ss` plus approximate minutes/seconds

---

## Default File Associations (SetUserFTA)

Uses `SetUserFTA` (installed via Chocolatey) to assign sane defaults:

* **Sublime Text** → `.txt`, `.log`, `.ini`, `.cfg`, `.conf`
* **VS Code** → `.c`, `.h`, `.hpp`, `.cpp`, `.cc`, `.py`, `.ps1`, `.js`, `.ts`, `.json`, `.yml`, `.yaml`, `.go`, `.rs`, `.lua`, `.rb`
* **Adobe Reader** → `.pdf`
* **Wireshark** → `.pcap`, `.pcapng`
* **Obsidian** → `.md`
* **Chrome** → `http`, `https`, `.htm`, `.html`

> ProgIDs may vary between installs/locales; these are tuned for a default US Windows install and can be edited in the script.

---

## Theming (Catppuccin Mocha)

> Entire section is skipped when `-SkipTheming` is used.
> Many theming steps are best-effort and only run when the relevant app is installed.

### Windows Terminal

* Locates `settings.json` for Windows Terminal.
* Downloads Catppuccin **Mocha** scheme.
* Injects / replaces the Mocha scheme in `schemes`.
* Applies Mocha to PowerShell-related profiles (pwsh and Windows PowerShell where detected).

### PowerShell

* Installs Catppuccin module by cloning into `PSModulePath`.
* The profile imports Catppuccin and uses the **Mocha** flavor for prompt colors.
* Uses PSReadLine for syntax coloring and history.

### VS Code

* Installs:

  * `Catppuccin.catppuccin-vsc` (theme)
  * `Catppuccin.catppuccin-vsc-icons` (icon theme)
* Updates `settings.json`:

  * `workbench.colorTheme = "Catppuccin Mocha"`
  * `workbench.iconTheme = "Catppuccin Icons Macchiato"`

### Sublime Text

* Starts Sublime once to ensure config folders exist.
* Clones Catppuccin Sublime theme into `Packages/Catppuccin`.
* Sets:

  * `color_scheme = "Packages/Catppuccin/Catppuccin Mocha.sublime-color-scheme"`
  * `theme = "Adaptive.sublime-theme"`

### Obsidian

* Creates vault at:

  ```text
  C:\Users\<User>\Documents\Obsidiant_Vault
  ```

* Creates `.obsidian` config folder and:

  * Clones Catppuccin Obsidian theme.
  * Sets `appearance.json` to:

    * `theme = "Catppuccin"`
    * `baseColorScheme = "dark"`

* Installs and enables community plugins:

  * `advanced-cursors`
  * `cm-editor-syntax-highlight-obsidian`
  * `obsidian-smarter-md-hotkeys`

* Updates global `obsidian.json` under `%APPDATA%\Obsidian` so this vault is registered and opened by default.

> For Firefox and Chrome Catppuccin browser themes, the script simply points you at the theme pages; you click **Add** manually.

---

## PowerShell Profile Enhancements

Modules auto-installed (AllUsers scope where possible):

* `PSReadLine`
* `Terminal-Icons`
* `posh-git`
* `PSFzf`
* `Catppuccin` (via git clone)

Additional modules installed:

* `PowerForensics`
* `HAWK`
* `Pester`
* `ImportExcel`

The profile:

* Imports the modules (best-effort, non-fatal on failure).

* Removes the `grep` alias so **real** `grep.exe` is used if present (e.g., via GOW).

* Defines useful aliases:

  * `ifconfig` → `ipconfig`
  * `ll` → `ls`
  * `reboot` → `Restart-Computer`
  * `c` → `Clear-And-Banner`
  * `shell` → `PowerShell`
  * `profile-help` → `Show-ProfileHelp`
  * `cd..` → go up two directories

* Defines helper functions:

  * `explore [path]` — open Explorer at current or specified path
  * `pkill <name>` — wrapper over `taskkill /f /im <name>`
  * `Clear-And-Banner` — clears the console, prints an ASCII banner, system date, hostname, primary IPv4, and public IP (best-effort)
  * `Add-Path <path> [-Scope User|Machine]` — safely add a directory to PATH and refresh the current session’s PATH
  * `sign <file>` — sign a script with the auto-generated code-signing certificate
  * `Show-ProfileHelp` — quick summary of profile features

### Script-Signing Certificate

* Automatically checks for a code signing cert with subject:

  ```text
  CN=Script Signing - <USERNAME>
  ```

* If missing, creates a new self-signed code signing certificate in `Cert:\CurrentUser\My`.

* The `sign` function uses this certificate.

---

## WSL + Ubuntu Provisioning

> WSL provisioning runs at the **end** of the script and only on client OS builds.
> If WSL/VM Platform features are not enabled, the script offers to reboot and asks you to re-run afterward.

Behavior:

1. Ensures these Windows optional features are enabled (no restart automatically forced):

   * `Microsoft-Windows-Subsystem-Linux`
   * `VirtualMachinePlatform`
2. Installs **Ubuntu** via `wsl --install -d Ubuntu` if no Ubuntu distro is present.
3. Once Ubuntu exists, runs a provisioning script inside WSL that:

   * `apt update && apt upgrade -y`
   * Installs a curated toolset, including (non-exhaustive):

     * `build-essential`, `curl`, `wget`, `git`
     * `python3`, `python3-pip`, `python3-venv`, `pipx`
     * `tmux`, `neovim`, `htop`, `ncdu`
     * `nmap`, `netcat-openbsd`, `tcpdump`, `traceroute`, `dnsutils`
     * `jq`, `ripgrep`, `fd-find`, `bat`, `fzf`
     * `radare2`, `binwalk`, `gdb`, `valgrind`
     * `hashcat`, `hydra`, `john`, `sqlmap`, `nikto`, `dnsrecon`, `steghide`
   * Installs Python tooling via `pipx`:

     * `poetry`, `black`, `ruff`, `bandit`, `scrapy`, `pwntools` (best-effort)

Many of these installs are best-effort; failures are logged but don’t stop the entire Windows script.

---

## ASCII Diagram of Script Flow

```text
    +-------------------------------------------------------------+
    |                  Windows Bootstrap Script                   |
    +-------------------------------------------------------------+
                    |
                    v
           +------------------------+
           | Admin Elevation Check  |
           +------------------------+
                    |
                    v
           +------------------------+
           | OS Detection           |
           +------------------------+
                    |
                    v
           +------------------------+
           | OneDrive Disable       |
           +------------------------+
                    |
                    v
           +------------------------+
           | Optional Debloat       |
           +------------------------+
                    |
                    v
           +------------------------------+
           | Install/Update Applications  |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Remove Desktop Shortcuts     |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Default File Associations    |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Explorer & UI Tweaks         |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Taskbar Configuration        |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | PowerShell Profile Setup     |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Catppuccin App Theming       |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Obsidian Vault Setup         |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | WSL + Ubuntu Provisioning    |
           +------------------------------+
                    |
                    v
           +------------------------------+
           | Runtime & Disk Usage Summary |
           +------------------------------+
```

---

## Troubleshooting

### Profile didn’t load

```powershell
Test-Path $PROFILE
New-Item -ItemType File -Path $PROFILE -Force
. $PROFILE
```

### Explorer changes didn’t apply

```powershell
Stop-Process -Name explorer -Force
Start-Process explorer
```

### WSL installation failed

1. Ensure features are enabled:

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All
   Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All
   ```

2. Reboot if prompted.

3. Ensure virtualization is enabled in BIOS.

4. Update the WSL kernel:

   ```powershell
   wsl --update
   ```

5. If Ubuntu already exists, just run:

   ```powershell
   wsl -d Ubuntu
   ```

---

## Repository Layout

```text
Windows_Setup/
│
├── README.md
└── windows-bootstrap.ps1
```

---

## License

MIT License — free to modify and adapt.
