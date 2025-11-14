# Windows Workstation Bootstrap Script

## 🔧 Quick Usage Examples (Most Important — Read First)

### **Run directly from the internet (PowerShell 7 recommended)**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
irm "https://raw.githubusercontent.com/stamdar/Windows_Setup/main/windows-bootstrap.ps1" | iex
```

### **Run after cloning the repo**

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\windows-bootstrap.ps1
```

### **Skip Windows 11 debloat**

```powershell
.\windows-bootstrap.ps1 -SkipDebloat
```

---

# Overview

A comprehensive and idempotent Windows workstation bootstrap script aimed at developers, security researchers, and engineers.  
This script configures the operating system, installs and updates software, applies UI/Explorer and privacy tweaks, configures PowerShell, provisions WSL, and applies consistent Catppuccin Mocha theming across major applications.

---

# 📦 Features

## System Preparation
- Auto‐elevates to Administrator  
- Detects OS version (Windows 10, 11, Server)  
- Optional Windows 11 debloat using **Raphire/Win11Debloat**  
- Infers OneDrive presence and adapts desktop cleanup  
- Privacy hardening (Disable telemetry, Spotlight, Start web search, lock screen ads)  
- Explorer/UI enhancements:
  - Show file extensions  
  - Show hidden & protected OS files  
  - Remove “3D Objects”  
  - Dark theme system-wide  
  - Classic right-click (Win11)  
- Windows Terminal Auto-start at login  
- Deterministic taskbar ordering  

---

# 📦 Application Installation via Chocolatey

Installs or updates:

- Windows Terminal  
- Sublime Text  
- Visual Studio Code  
- Obsidian  
- Chrome, Firefox  
- Python3, pip, pipx  
- Go, Rust  
- Git  
- Nmap, Npcap, Wireshark  
- jq, Everything Search  
- Process Hacker  
- Sysinternals Suite  
- 7zip, Adobe Reader  
- GNU Coreutils (GOW)  
- SetUserFTA  
- fzf  

Desktop shortcuts created during installation are automatically removed.

---

# Default File Associations (SetUserFTA)

- Sublime → .txt, .ini, .cfg  
- VSCode → .c, .cpp, .py, .json, .yaml, .ps1  
- Adobe Reader → .pdf  
- Wireshark → .pcap/.pcapng  
- Obsidian → .md  
- Chrome → http/https/.htm/.html  

---

# 🎨 Theming (Catppuccin Mocha)

### Windows Terminal
- Full Catppuccin Mocha scheme injected and applied.

### PowerShell
- Catppuccin module installed  
- Automatically themed banners and prompts  

### VS Code
- Installs Catppuccin theme + icons  
- Forces Mocha  

### Sublime Text
- Auto-launch to create config folders  
- Installs Catppuccin theme  
- Applies Mocha scheme  

### Obsidian
- Creates vault at `C:\Users\<User>\Documents\Obsidiant_Vault`  
- Catppuccin theme auto-applied  
- Plugins auto-installed:
  - Advanced Cursors  
  - Editor Syntax Highlight  
  - Smarter Markdown Hotkeys  

---

# 🧰 PowerShell Profile Enhancements

Modules auto-installed and auto-imported:
- PSReadLine  
- Terminal-Icons  
- posh-git  
- PSFzf  
- Catppuccin  

Additional modules installed:
- PowerForensics  
- HAWK  
- Pester  
- ImportExcel  

Custom functions:
- `explore`  
- `pkill`  
- `Add-Path`  
- `Clear-And-Banner`  
- `sign`  
- `profile-help`  

Script-signing certificate is automatically generated and integrated.

---

# 🐧 WSL + Ubuntu Provisioning

Installs Ubuntu and provisions:
- build-essential  
- python3, pip, pipx  
- tmux, neovim, htop  
- nmap, netcat-openbsd, tcpdump  
- jq, ripgrep, fd, bat  
- radare2, gdb, valgrind, binwalk  
- hydra, john, sqlmap, steghide, nikto  
- Multiple pipx cyber tools (pwntools, ruff, black, scrapy, etc.)

---

# 📊 ASCII Diagram of Script Flow

```
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
   | Catppuccin App Theming      |
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
   |        Script Complete       |
   +------------------------------+
```

---

# 🛠 Troubleshooting

## Profile didn’t load
```powershell
Test-Path $PROFILE
New-Item -ItemType File -Path $PROFILE -Force
. $PROFILE
```

## Explorer changes didn’t apply
```powershell
Stop-Process -Name explorer -Force
Start-Process explorer
```

## WSL installation failed
### 1. Ensure features enabled
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All
```

### 2. Reboot required  
### 3. BIOS virtualization disabled  
### 4. Update kernel
```powershell
wsl --update
```

### 5. Ubuntu already exists → run:
```powershell
wsl -d Ubuntu
```

---

# 📁 Repository Layout

```
Windows_Setup/
│
├── README.md
└── windows-bootstrap.ps1
```

---

# 📜 License

MIT License — free to modify and adapt.
