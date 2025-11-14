<# 
Windows Workstation Bootstrap Script
- Elevation check & re-launch as admin
- Optional Win11 debloat
- Chocolatey + package installs/updates
- Desktop shortcut cleanup
- Default app associations with SetUserFTA
- Privacy & UI/Explorer tweaks
- PowerShell theming & profile
- Obsidian vault + plugins
- Sublime theming
- WSL + Ubuntu provisioning (at end)
#>

param(
    [switch]$SkipDebloat
)

$ScriptStart = Get-Date

# -----------------------------
#  Elevation / Admin Check
# -----------------------------

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[*] Not running as Administrator, attempting to elevate..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        if (-not $p) {
            Write-Error "Elevation failed or was cancelled. Please re-run this script from an elevated PowerShell session."
        }
    }
    catch {
        Write-Error "Elevation failed or was cancelled. Please re-run this script from an elevated PowerShell session."
    }
    exit
}

Write-Host "[+] Running as Administrator." -ForegroundColor Green

# -----------------------------
#  OS Detection Helpers
# -----------------------------

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $version = [Version]$os.Version
    $productType = $os.ProductType # 1=Workstation, 2=Domain Controller, 3=Server
    [PSCustomObject]@{
        Caption     = $os.Caption
        Version     = $version
        ProductType = $productType
        IsServer    = ($productType -ne 1)
        IsWin11     = ($version.Build -ge 22000 -and $productType -eq 1)
        IsClient    = ($productType -eq 1)
    }
}

$OS = Get-OSInfo
Write-Host "[*] Detected OS: $($OS.Caption) ($($OS.Version))" -ForegroundColor Cyan

# -----------------------------
#  Optional Win11 Debloat
# -----------------------------

if ($OS.IsWin11 -and -not $SkipDebloat) {
    Write-Host "[*] Windows 11 detected, running Win11Debloat step..." -ForegroundColor Yellow
    try {
        $tempDir = Join-Path $env:TEMP "Win11Debloat"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

        $debloatScript = Join-Path $tempDir "Win11Debloat.ps1"
        $debloatUrl = "https://raw.githubusercontent.com/Raphire/Win11Debloat/main/Win11Debloat.ps1"

        Invoke-WebRequest -Uri $debloatUrl -OutFile $debloatScript -UseBasicParsing

        Write-Host "[*] Running Win11Debloat script..." -ForegroundColor Yellow
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $debloatScript -ErrorAction Stop
        Write-Host "[+] Win11Debloat completed." -ForegroundColor Green

    } catch {
        Write-Warning "Win11Debloat failed: $($_.Exception.Message). Continuing without debloat."
    }
} elseif (-not $OS.IsWin11) {
    Write-Host "[*] Not Windows 11, skipping Win11Debloat." -ForegroundColor DarkYellow
} elseif ($SkipDebloat) {
    Write-Host "[*] SkipDebloat specified, skipping Win11Debloat." -ForegroundColor DarkYellow
}

# -----------------------------
#  Chocolatey Install / PATH
# -----------------------------

function Install-Chocolatey {
    if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
        Write-Host "[+] Chocolatey is already installed." -ForegroundColor Green
        return
    }

    Write-Host "[*] Installing Chocolatey..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        $chocoInstallCmd = @"
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'));
"@

        powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command $chocoInstallCmd

        if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
            Write-Host "[+] Chocolatey installed successfully." -ForegroundColor Green
        } else {
            throw "Chocolatey installation completed, but choco.exe not found."
        }
    } catch {
        Write-Error "Failed to install Chocolatey: $($_.Exception.Message)"
        exit 1
    }
}

function Refresh-Path {
    Write-Host "[*] Refreshing PATH for current session..." -ForegroundColor Cyan
    try {
        $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $userPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
        $env:Path    = "$machinePath;$userPath"
        Write-Host "[+] PATH refreshed." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to refresh PATH: $($_.Exception.Message)"
    }
}

Install-Chocolatey
Refresh-Path

# -----------------------------
#  Chocolatey Package Management
# -----------------------------

function Get-ChocoLocalVersion {
    param(
        [Parameter(Mandatory)][string]$Id
    )
    $result = choco list --local-only --exact --limit-output $Id 2>$null
    if (-not $result) { return $null }
    $parts = $result -split '\|'
    if ($parts.Length -ge 2) { return $parts[1] }
    return $null
}

function Ensure-ChocoPackage {
    param(
        [Parameter(Mandatory)][string]$Id,
        [string]$Name
    )

    if (-not $Name) { $Name = $Id }

    $existingVersion = Get-ChocoLocalVersion -Id $Id
    if ($existingVersion) {
        Write-Host "[*] $Name is installed (version $existingVersion). Checking for updates..." -ForegroundColor Cyan
        choco upgrade $Id -y --no-progress
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] $Name upgraded or already up to date." -ForegroundColor Green
        } else {
            Write-Warning "Upgrade for $Name failed with exit code $LASTEXITCODE."
        }
    } else {
        Write-Host "[*] Installing $Name ($Id)..." -ForegroundColor Yellow
        choco install $Id -y --no-progress
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] $Name installed successfully." -ForegroundColor Green
        } else {
            Write-Warning "Installation for $Name failed with exit code $LASTEXITCODE."
        }
    }
}

function Get-DesktopShortcuts {
    $candidatePaths = @(
        "$env:PUBLIC\Desktop",
        "$env:USERPROFILE\Desktop"
    )

    # If OneDrive is redirecting Desktop, include that too
    if ($env:OneDrive) {
        $candidatePaths += (Join-Path $env:OneDrive "Desktop")
    }

    $paths = $candidatePaths | Where-Object { Test-Path $_ }

    $shortcuts = @()
    foreach ($p in $paths) {
        $shortcuts += Get-ChildItem -Path $p -Filter *.lnk -ErrorAction SilentlyContinue
    }

    return $shortcuts.FullName | Sort-Object -Unique
}

# Package list (order matters for some packages)
$ChocoPackages = @(
    @{ Id = "microsoft-windows-terminal"; Name = "Windows Terminal" },
    @{ Id = "vim";                        Name = "Vim" },
    @{ Id = "nmap";                       Name = "Nmap" },
    @{ Id = "obsidian";                   Name = "Obsidian" },
    @{ Id = "wireshark";                  Name = "Wireshark" },
    @{ Id = "vscode";                     Name = "Visual Studio Code" },
    @{ Id = "sublimetext4";               Name = "Sublime Text 4" },
    @{ Id = "python";                     Name = "Python 3" },
    @{ Id = "googlechrome";               Name = "Google Chrome" },
    @{ Id = "firefox";                    Name = "Mozilla Firefox" },
    @{ Id = "7zip";                       Name = "7-Zip" },
    @{ Id = "processhacker";              Name = "Process Hacker" },
    @{ Id = "jq";                         Name = "jq" },
    @{ Id = "openssl.light";              Name = "OpenSSL (light)" },
    @{ Id = "openssh";                    Name = "OpenSSH" },
    @{ Id = "git";                        Name = "Git" },
    @{ Id = "everything";                 Name = "Everything Search" },
    @{ Id = "golang";                     Name = "Go" },
    @{ Id = "rustup.install";             Name = "Rust (rustup)" },
    @{ Id = "gow";                        Name = "GNU coreutils (Gow)" },
    @{ Id = "adobereader";                Name = "Adobe Reader" },
    @{ Id = "setuserfta";                 Name = "SetUserFTA" },
    @{ Id = "powershell";                 Name = "PowerShell 7" },
    @{ Id = "fzf";                        Name = "fzf" }
)

Write-Host "[*] Taking snapshot of existing desktop shortcuts..." -ForegroundColor Cyan
$ExistingShortcuts = Get-DesktopShortcuts

foreach ($pkg in $ChocoPackages) {
    Ensure-ChocoPackage -Id $pkg.Id -Name $pkg.Name
}

# -----------------------------
#  Ensure pip and pipx on Windows
# -----------------------------

Write-Host "[*] Ensuring pip and pipx (Windows)..." -ForegroundColor Cyan
try {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Warning "Python executable not found on PATH; skipping pip/pipx setup."
    } else {
        Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
        python -m pip install --upgrade pip --disable-pip-version-check

        Write-Host "[*] Installing/upgrading pipx via pip..." -ForegroundColor Yellow
        python -m pip install --user pipx --upgrade

        Write-Host "[*] Running pipx ensurepath..." -ForegroundColor Yellow
        python -m pipx ensurepath

        Write-Host "[+] pip and pipx are now installed/upgraded (user scope)." -ForegroundColor Green
    }
} catch {
    Write-Warning "pip/pipx setup failed: $($_.Exception.Message)"
}

Write-Host "[*] Installing Sysinternals Suite (ignoring checksums, best effort)..." -ForegroundColor Cyan
try {
    choco install sysinternals -y --no-progress --ignore-checksums
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Sysinternals Suite installed (checksums ignored)." -ForegroundColor Green
    } else {
        Write-Warning "Sysinternals install failed with exit code $LASTEXITCODE (even with --ignore-checksums)."
    }
} catch {
    Write-Warning "Sysinternals installation threw an exception: $($_.Exception.Message)"
}


Write-Host "[*] Cleaning up newly created desktop shortcuts..." -ForegroundColor Cyan
$FinalShortcuts = Get-DesktopShortcuts
$NewShortcuts = $FinalShortcuts | Where-Object { $_ -notin $ExistingShortcuts }
foreach ($lnk in $NewShortcuts) {
    try {
        Remove-Item -LiteralPath $lnk -Force -ErrorAction Stop
        Write-Host "[+] Removed new desktop shortcut: $lnk" -ForegroundColor DarkGreen
    } catch {
        Write-Warning "Failed to remove shortcut ${lnk}: $($_.Exception.Message)"
    }
}

# -----------------------------
#  Default App Associations via SetUserFTA
# -----------------------------

function Invoke-SetUserFTA {
    param(
        [Parameter(Mandatory)][string]$Extension,
        [Parameter(Mandatory)][string]$ProgId
    )

    $setUserFtaPath = Get-ChildItem "$env:ProgramData\chocolatey\lib\setuserfta" -Recurse -Filter "SetUserFTA.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName

    if (-not $setUserFtaPath) {
        Write-Warning "SetUserFTA.exe not found; skipping default app associations."
        return
    }

    & $setUserFtaPath $Extension $ProgId
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "SetUserFTA failed for: $Extension -> $ProgId (exit $LASTEXITCODE)"
    } else {
        Write-Host "[+] SetUserFTA: $Extension -> $ProgId" -ForegroundColor Green
    }
}

Write-Host "[*] Configuring default applications with SetUserFTA..." -ForegroundColor Cyan

# Note: ProgIDs may vary by install; adjust if needed.
# Sublime via Applications ProgID
$SublimeProgId = "Applications\sublime_text.exe"
# VS Code via Applications ProgID
$VSCodeProgId = "Applications\Code.exe"
# Adobe Reader DC
$AdobePdfProgId = "AcroExch.Document.DC"
# Wireshark pcap
$WiresharkProgId = "Wireshark.pcap"
# Chrome
$ChromeProgId = "ChromeHTML"
# Obsidian (may need adjustment)
$ObsidianProgId = "Obsidian.md"

# Sublime for text-ish
".txt",".log",".ini",".cfg",".conf" | ForEach-Object {
    Invoke-SetUserFTA $_ $SublimeProgId
}

# VS Code for code-ish
".c",".h",".hpp",".cpp",".cc",".py",".ps1",".js",".ts",".json",".yml",".yaml",".go",".rs",".lua",".rb" | ForEach-Object {
    Invoke-SetUserFTA $_ $VSCodeProgId
}

# Adobe for PDFs
Invoke-SetUserFTA ".pdf"   $AdobePdfProgId

# Wireshark for captures
Invoke-SetUserFTA ".pcap"  $WiresharkProgId
Invoke-SetUserFTA ".pcapng" $WiresharkProgId

# Chrome as default browser
Invoke-SetUserFTA "http"   $ChromeProgId
Invoke-SetUserFTA "https"  $ChromeProgId
Invoke-SetUserFTA ".htm"   $ChromeProgId
Invoke-SetUserFTA ".html"  $ChromeProgId

# Obsidian for markdown
Invoke-SetUserFTA ".md"    $ObsidianProgId

# -----------------------------
#  Privacy / Telemetry / Search / Lock Screen
# -----------------------------

function Set-RegistryDwordIfNeeded {
    param(
        [Parameter(Mandatory)][ValidateSet("HKLM","HKCU")] [string]$Hive,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [string]$Description
    )

    $base = "$Hive" + ':\'
    $regPath = Join-Path $base $Path
    $current = $null
    try {
        $current = (Get-ItemProperty -Path $regPath -Name $Name -ErrorAction SilentlyContinue).$Name
    } catch { }

    if ($null -ne $current -and $current -eq $Value) {
        if ($Description) { Write-Host "[=] $Description already set ($Value)." -ForegroundColor DarkGray }
        return
    }

    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    if ($Description) { Write-Host "[+] $Description set to $Value." -ForegroundColor Green }
}

Write-Host "[*] Applying privacy / telemetry tweaks..." -ForegroundColor Cyan

# Telemetry minimum
Set-RegistryDwordIfNeeded -Hive HKLM -Path "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Description "Telemetry level (AllowTelemetry)"

# Tailored experiences & Spotlight
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Description "Disable tailored experiences"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1 -Description "Disable Windows Spotlight features"

# Start menu / search Bing/web
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Description "Disable Start search web suggestions"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Description "Disable Bing in Start search"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Description "Disable Cortana"

# Lock screen tips / suggestions
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0 -Description "Disable rotating lock screen"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0 -Description "Disable lock screen overlays"

# -----------------------------
#  Explorer / UI Tweaks
# -----------------------------

Write-Host "[*] Applying Explorer / UI tweaks..." -ForegroundColor Cyan

# Show hidden files, system files, and file extensions
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Description "Show hidden files"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Description "Show protected OS files"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Description "Show file extensions"

# Explorer opens to This PC and not Quick Access
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Description "Explorer opens to This PC"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value 0 -Description "Disable recent files in Quick Access"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 -Description "Disable frequent folders in Quick Access"

# Remove 3D Objects from This PC only
try {
    $clsid = "{31C0DD25-9439-4F12-BF41-7FF4EDA38722}"
    $keys = @(
        "Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$clsid",
        "Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\DelegateFolders\$clsid"
    )
    foreach ($key in $keys) {
        $full = "HKCU:\$key"
        if (Test-Path $full) {
            Remove-Item -Path $full -Recurse -Force
            Write-Host "[+] Removed 3D Objects from This PC ($key)." -ForegroundColor Green
        }
    }
} catch {
    Write-Warning "Failed to remove 3D Objects from This PC: $($_.Exception.Message)"
}

# Dark theme for apps and system
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Description "Use dark theme for apps"
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Description "Use dark theme for system"

# Classic context menu (Win11 only)
if ($OS.IsWin11) {
    try {
        $key = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        New-ItemProperty -Path $key -Name "(default)" -Value "" -PropertyType String -Force | Out-Null
        Write-Host "[+] Enabled classic context menu on Windows 11." -ForegroundColor Green
    } catch {
        Write-Warning "Failed to set classic context menu: $($_.Exception.Message)"
    }
} else {
    Write-Host "[*] Not Windows 11, skipping classic context menu tweak." -ForegroundColor DarkYellow
}

# Disable Start recommended / suggested content (where supported)
Set-RegistryDwordIfNeeded -Hive HKCU -Path "Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedSection" -Value 1 -Description "Hide Recommended section in Start (where supported)"

# Restart Explorer to apply
Write-Host "[*] Restarting Explorer..." -ForegroundColor Cyan
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Process explorer.exe

# -----------------------------
#  Taskbar Layout (Win10/11 client only)
# -----------------------------

function Get-AppsFolderItem {
    param(
        [Parameter(Mandatory)][string]$AppIdOrName
    )
    $shell = New-Object -ComObject Shell.Application
    $appsFolder = $shell.Namespace("shell:AppsFolder")
    foreach ($item in $appsFolder.Items()) {
        if ($item.Name -eq $AppIdOrName -or $item.Path -like "*$AppIdOrName*") {
            return $item
        }
    }
    return $null
}

function Pin-AppToTaskbar {
    param(
        [Parameter(Mandatory)][string]$AppName
    )
    try {
        $item = Get-AppsFolderItem -AppIdOrName $AppName
        if (-not $item) {
            Write-Warning "AppsFolder item not found for $AppName, skipping pin."
            return
        }
        $verb = $item.Verbs() | Where-Object { $_.Name.Replace('&','') -match 'Pin to taskbar' }
        if ($verb) {
            $verb.DoIt()
            Write-Host "[+] Pinned $AppName to taskbar." -ForegroundColor Green
        } else {
            Write-Warning "PinToTaskbar verb not found for $AppName."
        }
    } catch {
        Write-Warning "Failed to pin ${AppName}: $($_.Exception.Message)"
    }
}

function Unpin-AppFromTaskbar {
    param(
        [Parameter(Mandatory)][string]$AppName
    )
    try {
        $item = Get-AppsFolderItem -AppIdOrName $AppName
        if (-not $item) { return }
        $verb = $item.Verbs() | Where-Object { $_.Name.Replace('&','') -match 'Unpin from taskbar' }
        if ($verb) {
            $verb.DoIt()
            Write-Host "[+] Unpinned $AppName from taskbar." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to unpin ${AppName}: $($_.Exception.Message)"
    }
}

if ($OS.IsClient) {
    Write-Host "[*] Customizing taskbar layout..." -ForegroundColor Cyan

    # Unpin common default apps (best effort)
    $DefaultUnpins = @(
        "Microsoft Edge",
        "Microsoft Store",
        "Mail",
        "Calendar"
    )
    foreach ($name in $DefaultUnpins) {
        Unpin-AppFromTaskbar -AppName $name
    }

    # Desired order after Explorer:
    # Windows Terminal, Sublime, VSCode, Obsidian, Firefox, Chrome

    # Best-effort unpin & re-pin in order
    $PinOrder = @(
        "Windows Terminal",
        "Sublime Text",
        "Visual Studio Code",
        "Obsidian",
        "Mozilla Firefox",
        "Google Chrome"
    )

    foreach ($name in $PinOrder) {
        Unpin-AppFromTaskbar -AppName $name
        Start-Sleep -Milliseconds 200
        Pin-AppToTaskbar -AppName $name
        Start-Sleep -Milliseconds 200
    }
} else {
    Write-Host "[*] Non-client OS detected; skipping taskbar layout customization." -ForegroundColor DarkYellow
}

# -----------------------------
#  PowerShell Modules & Profile
# -----------------------------

Write-Host "[*] Installing core PowerShell modules..." -ForegroundColor Cyan

# Make sure NuGet provider / PSGallery are available
try {
    # Ensure TLS 1.2 so NuGet download doesn't choke on older defaults
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget) {
        Write-Host "[*] Installing NuGet package provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -Confirm:$false | Out-Null
    }

    # Trust PSGallery so Install-Module doesn't prompt
    $repo = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction Stop
    }

    Write-Host "[+] NuGet and PSGallery configured." -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure PSGallery/NuGet: $($_.Exception.Message)"
}

$CoreModules = @(
    "PSReadLine",
    "Terminal-Icons",
    "posh-git",
    "PSFzf"
)

$ExtraModules = @(
    "PowerForensics",
    "HAWK",
    "Pester",
    "ImportExcel"
)

foreach ($m in $CoreModules + $ExtraModules) {
    try {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "[*] Installing module $m from PSGallery..." -ForegroundColor Yellow
            Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -Confirm:$false -ErrorAction Stop
        } else {
            Write-Host "[=] Module $m already available." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Failed to install module ${m}: $($_.Exception.Message)"
    }
}

# Install Catppuccin PowerShell module (clone into PSModulePath)
Write-Host "[*] Installing Catppuccin PowerShell module..." -ForegroundColor Cyan
try {
    $moduleBase = ($env:PSModulePath -split ';' | Where-Object { Test-Path $_ } | Select-Object -First 1)
    if ($moduleBase) {
        $catDir = Join-Path $moduleBase "Catppuccin"
        if (-not (Test-Path $catDir)) {
            git clone "https://github.com/catppuccin/powershell.git" $catDir 2>$null
            Write-Host "[+] Catppuccin module cloned to $catDir" -ForegroundColor Green
        } else {
            Write-Host "[=] Catppuccin module folder already exists at $catDir" -ForegroundColor DarkGray
        }
    } else {
        Write-Warning "No PSModulePath entry found to place Catppuccin module."
    }
} catch {
    Write-Warning "Failed to install Catppuccin module: $($_.Exception.Message)"
}

# Create / update user PowerShell profile
Write-Host "[*] Configuring user PowerShell profile..." -ForegroundColor Cyan
$profilePath = $PROFILE
if (-not (Test-Path (Split-Path $profilePath))) {
    New-Item -ItemType Directory -Path (Split-Path $profilePath) -Force | Out-Null
}
if (-not (Test-Path $profilePath)) {
    New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

# Create self-signed code signing cert if not present
Write-Host "[*] Ensuring script signing certificate exists..." -ForegroundColor Cyan
$certSubject = "CN=Script Signing - $env:USERNAME"
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
if (-not $cert) {
    try {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $certSubject -CertStoreLocation "Cert:\CurrentUser\My"
        Write-Host "[+] Created new code signing certificate: $($cert.Thumbprint)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to create code signing certificate: $($_.Exception.Message)"
    }
} else {
    Write-Host "[=] Found existing code signing certificate: $($cert.Thumbprint)" -ForegroundColor DarkGray
}

# Profile content
$profileContent = @'
# ================================
#  Custom Bootstrap Profile
# ================================

# Import core modules
Import-Module PSReadLine -ErrorAction SilentlyContinue
Import-Module Terminal-Icons -ErrorAction SilentlyContinue
Import-Module posh-git -ErrorAction SilentlyContinue
Import-Module PSFzf -ErrorAction SilentlyContinue

# Import Catppuccin (if available) and set Mocha flavor
try {
    Import-Module Catppuccin -ErrorAction Stop
    $Flavor = $Catppuccin['Mocha']
} catch { }

# Use real GNU grep instead of Select-String alias if available
if (Get-Command grep.exe -ErrorAction SilentlyContinue) {
    if (Get-Item Alias:grep -ErrorAction SilentlyContinue) {
        Remove-Item Alias:grep -ErrorAction SilentlyContinue
    }
}

# Aliases
Set-Alias -Name ifconfig -Value ipconfig -ErrorAction SilentlyContinue
Set-Alias -Name ll       -Value ls       -ErrorAction SilentlyContinue
Set-Alias -Name reboot   -Value Restart-Computer -ErrorAction SilentlyContinue
Set-Alias -Name c        -Value Clear-And-Banner -ErrorAction SilentlyContinue
Set-Alias -Name shell    -Value PowerShell -ErrorAction SilentlyContinue

function cd.. {
    Set-Location "..\.."
}

function explore {
    param(
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $target = (Get-Location).Path
    } else {
        try {
            $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
            $target = $resolved.Path
        } catch {
            Write-Warning "Path not found: $Path"
            return
        }
    }
    Start-Process explorer.exe -ArgumentList $target
}

function pkill {
    param(
        [Parameter(Mandatory)][string]$procName
    )
    try {
        taskkill /f /im $procName 2>$null
    } catch {
        Write-Warning "Failed to kill process ${procName}: $($_.Exception.Message)"
    }
}

function Clear-And-Banner {
    $banner = @"
  _____ __                           ____ __         ____
 / ___// /_ ____ ________  ____     / __// /_  ___  / / /
 \__ \/ __/ __  / __  __ \/ __ \    \__ \/ __ \/ _ \/ / /
 __/ / /_/ /_/ / / / / / / /_/ /   __/ / / / /  __/ / /
/___/\__/\__,_/_/ /_/ /_/ .___/   /___/_/ /_/\___/_/_/
                       /_/
"@

    function Get-PrimaryIPv4 {
        try {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop |
                            Sort-Object -Property RouteMetric, InterfaceMetric |
                            Select-Object -First 1
            if ($defaultRoute) {
                $ifIndex = $defaultRoute.InterfaceIndex
                $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ifIndex -ErrorAction Stop |
                     Where-Object { $_.IPAddress -notlike "169.254.*" } |
                     Select-Object -First 1 -ExpandProperty IPAddress
                return $ip
            }
        } catch { }
        try {
            $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                  Where-Object { $_.IPAddress -notlike "169.254.*" } |
                  Select-Object -First 1 -ExpandProperty IPAddress
            return $ip
        } catch { }
        return $null
    }

    $ip = Get-PrimaryIPv4
    $ipText = if ($ip) { $ip } else { "(none)" }
    $ipStr = "IPv4 addr: " + $ipText

    $pubStr = "Public IP: (unavailable)"
    try {
        $resp = Invoke-WebRequest "https://ifconfig.me/ip" -UseBasicParsing -TimeoutSec 3
        if ($resp -and $resp.Content) {
            $pubStr = "Public IP: " + $resp.Content.Trim()
        }
    } catch { }

    $hn = $env:COMPUTERNAME
    $hnStr = "HN: $hn"

    Clear-Host
    Write-Output $banner
    Get-Date
    Write-Output $hnStr
    Write-Output $ipStr
    Write-Host $pubStr -NoNewline
}

function Add-Path {
    param(
        [Parameter(Mandatory)][string]$NewPath,
        [ValidateSet('User','Machine')][string]$Scope = 'Machine'
    )
    if (-not (Test-Path $NewPath)) {
        Write-Warning "Path does not exist: $NewPath"
        return
    }

    $targetScope = $Scope
    try {
        $current = [Environment]::GetEnvironmentVariable('Path', $targetScope)
    } catch {
        Write-Warning "Failed to read $targetScope PATH, falling back to User."
        $targetScope = 'User'
        $current = [Environment]::GetEnvironmentVariable('Path', $targetScope)
    }

    if ($current -and $current -match [Regex]::Escape($NewPath)) {
        Write-Host "[=] $NewPath already in $targetScope PATH."
    } else {
        $sep = if ([string]::IsNullOrEmpty($current) -or $current.TrimEnd().EndsWith(';')) { '' } else { ';' }
        [Environment]::SetEnvironmentVariable('Path', "$current$sep$NewPath", $targetScope)
        Write-Host "[+] Added $NewPath to $targetScope PATH."
    }

    # Refresh current session PATH
    $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('Path','User')
    $env:Path    = "$machinePath;$userPath"
}

function sign {
    param(
        [Parameter(Mandatory)][string]$FilePath
    )
    $resolved = Resolve-Path -LiteralPath $FilePath -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Write-Error "File not found: $FilePath"
        return
    }

    $CertSubject = "CN=Script Signing - $env:USERNAME"
    $Certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
                   Where-Object { $_.Subject -eq $CertSubject } |
                   Select-Object -First 1

    if (-not $Certificate) {
        Write-Error "Script signing certificate not found for subject: $CertSubject"
        return
    }

    try {
        Set-AuthenticodeSignature -FilePath $resolved.Path -Certificate $Certificate | Out-Null
        Write-Host "[+] Signed $($resolved.Path) with certificate subject $CertSubject" -ForegroundColor Green
    } catch {
        Write-Error "Failed to sign file: $($_.Exception.Message)"
    }
}

function Show-ProfileHelp {
    Write-Host "=== Custom Profile Features ===" -ForegroundColor Cyan

    Write-Host "`nAliases:" -ForegroundColor Yellow
    Write-Host "  ifconfig -> ipconfig"
    Write-Host "  ll       -> ls"
    Write-Host "  reboot   -> Restart-Computer"
    Write-Host "  c        -> Clear-And-Banner"
    Write-Host "  shell    -> PowerShell"
    Write-Host "  cd..     -> go up two directories"
    Write-Host "  grep     -> GNU grep (binary), not Select-String"

    Write-Host "`nFunctions:" -ForegroundColor Yellow
    Write-Host "  explore [path]       : Open current or specified directory in Explorer"
    Write-Host "  pkill <name>         : taskkill /f /im <name> (with safer handling)"
    Write-Host "  Clear-And-Banner     : Clear screen + banner + host/IP info"
    Write-Host "  Add-Path <path>      : Add to PATH (Machine by default), auto-refresh session"
    Write-Host "  sign <file>          : Sign a single script with your signing certificate"
    Write-Host "  Show-ProfileHelp     : Show this help"

    Write-Host "`nTheming & shell goodies:" -ForegroundColor Yellow
    Write-Host "  - Catppuccin Mocha prompt & PSReadLine colors (if Catppuccin module available)"
    Write-Host "  - Terminal-Icons for ls output"
    Write-Host "  - posh-git for git status/prompt integration"
    Write-Host "  - PSFzf + fzf for fuzzy history/path search"

    Write-Host "`nTip: Customize this profile at `"$PROFILE`"."
}

Set-Alias -Name profile-help -Value Show-ProfileHelp -ErrorAction SilentlyContinue

function Prompt {
    # Figure out time of last completed command (or now if none)
    $timeText = ""
    $hist = Get-History -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($hist -and $hist.EndExecutionTime) {
        $timeText = $hist.EndExecutionTime.ToString("HH:mm:ss")
    } else {
        $timeText = (Get-Date).ToString("HH:mm:ss")
    }

    $path = (Get-Location).Path

    # Decide if we should use ANSI colors (only in pwsh 7+ with PSStyle)
    $useColor = $false
    if ($PSVersionTable.PSVersion.Major -ge 7 -and $PSStyle) {
        $useColor = $true
    }

    $reset = ""
    $timeColor = ""
    $pathColor = ""
    $promptColor = ""

    if ($useColor -and $Flavor) {
        $reset      = $PSStyle.Reset
        $timeColor   = $Flavor.Teal.Foreground()
        $pathColor   = $Flavor.Yellow.Foreground()
        $promptColor = $Flavor.Green.Foreground()
    }

    Write-Host "[" -NoNewline

    if ($useColor -and $timeColor) {
        Write-Host "$timeColor$timeText$reset" -NoNewline
    } else {
        Write-Host "$timeText" -NoNewline
    }

    Write-Host "] " -NoNewline

    if ($useColor -and $pathColor) {
        Write-Host "$pathColor$path$reset" -NoNewline
    } else {
        Write-Host "$path" -NoNewline
    }

    if ($useColor -and $promptColor) {
        Write-Host " $promptColor> $reset" -NoNewline
    } else {
        Write-Host " > " -NoNewline
    }

    return " "
}
'@

Set-Content -Path $profilePath -Value $profileContent -Encoding UTF8
Write-Host "[+] Updated profile at $profilePath" -ForegroundColor Green


# -----------------------------
#  Windows Terminal Catppuccin Mocha (best-effort)
# -----------------------------

Write-Host "[*] Attempting to configure Windows Terminal with Catppuccin Mocha..." -ForegroundColor Cyan
try {
    $wtSettingsRoot = Join-Path $env:LOCALAPPDATA "Packages"
    $wtSettingsPath = Get-ChildItem $wtSettingsRoot -Recurse -Filter "settings.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like "*Microsoft.WindowsTerminal_*" } |
        Select-Object -First 1 -ExpandProperty FullName

    if ($wtSettingsPath) {
        $settingsJson = Get-Content $wtSettingsPath -Raw | ConvertFrom-Json

        # Download Mocha scheme from Catppuccin/windows-terminal
        $tempDir = Join-Path $env:TEMP "Catppuccin-WT"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }
        $mochaUrl = "https://raw.githubusercontent.com/catppuccin/windows-terminal/main/mocha.json"
        $mochaPath = Join-Path $tempDir "mocha.json"
        Invoke-WebRequest -Uri $mochaUrl -OutFile $mochaPath -UseBasicParsing

        $mocha = Get-Content $mochaPath -Raw | ConvertFrom-Json

        # Merge schemes
        if (-not $settingsJson.schemes) { $settingsJson | Add-Member -MemberType NoteProperty -Name schemes -Value @() }
        $existing = $settingsJson.schemes | Where-Object { $_.name -eq $mocha.name }
        if ($existing) {
            # replace
            $settingsJson.schemes = @($settingsJson.schemes | Where-Object { $_.name -ne $mocha.name }) + $mocha
        } else {
            $settingsJson.schemes += $mocha
        }

        # Set default profile's colorScheme if it's a PowerShell profile
        if ($settingsJson.profiles -and $settingsJson.profiles.list) {
            foreach ($p in $settingsJson.profiles.list) {
                if ($p.commandline -like "*pwsh*" -or $p.name -like "*PowerShell*") {
                    $p.colorScheme = $mocha.name
                }
            }
        }

        $settingsJson | ConvertTo-Json -Depth 100 | Set-Content -Path $wtSettingsPath -Encoding UTF8
        Write-Host "[+] Windows Terminal Catppuccin Mocha scheme applied." -ForegroundColor Green
    } else {
        Write-Warning "Windows Terminal settings.json not found; skipping WT theme."
    }
} catch {
    Write-Warning "Failed to configure Windows Terminal theme: $($_.Exception.Message)"
}

# -----------------------------
#  VS Code Catppuccin Mocha
# -----------------------------

Write-Host "[*] Configuring VS Code Catppuccin Mocha theme..." -ForegroundColor Cyan
try {
    $codeCmd = Get-Command code -ErrorAction SilentlyContinue
    if ($codeCmd) {
        code --install-extension Catppuccin.catppuccin-vsc --force 2>$null
        code --install-extension Catppuccin.catppuccin-vsc-icons --force 2>$null
        Write-Host "[+] Catppuccin VS Code theme and icons installed." -ForegroundColor Green

        $settingsDir = Join-Path $env:APPDATA "Code\User"
        $settingsFile = Join-Path $settingsDir "settings.json"
        if (-not (Test-Path $settingsDir)) {
            New-Item -ItemType Directory -Path $settingsDir -Force | Out-Null
        }
        $settings = @{}
        if (Test-Path $settingsFile) {
            try {
                $json = Get-Content $settingsFile -Raw
                if ($json.Trim()) {
                    $settings = $json | ConvertFrom-Json
                }
            } catch { }
        }

        $settings."workbench.colorTheme" = "Catppuccin Mocha"
        $settings."workbench.iconTheme" = "Catppuccin Icons Macchiato"

        $settings | ConvertTo-Json -Depth 20 | Set-Content -Path $settingsFile -Encoding UTF8
        Write-Host "[+] VS Code configured to use Catppuccin Mocha." -ForegroundColor Green
    } else {
        Write-Warning "code.exe not found; skipping VS Code theme config."
    }
} catch {
    Write-Warning "Failed to configure VS Code theme: $($_.Exception.Message)"
}

# -----------------------------
#  Sublime Text Catppuccin
# -----------------------------

Write-Host "[*] Configuring Sublime Text Catppuccin Mocha..." -ForegroundColor Cyan
try {
    $sublimeExe = Get-Command sublime_text -ErrorAction SilentlyContinue
    if (-not $sublimeExe) { $sublimeExe = Get-Command "sublime_text.exe" -ErrorAction SilentlyContinue }
    if ($sublimeExe) {
        # Launch Sublime once to create config dirs
        Start-Process $sublimeExe.Path -WindowStyle Minimized
        Start-Sleep -Seconds 5
        Get-Process sublime_text -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

        $sublimeConfig = Join-Path $env:APPDATA "Sublime Text"
        $packagesDir   = Join-Path $sublimeConfig "Packages"
        $userDir       = Join-Path $packagesDir "User"
        if (-not (Test-Path $userDir)) {
            New-Item -ItemType Directory -Path $userDir -Force | Out-Null
        }

        # Install Catppuccin theme into Packages\Catppuccin
        $catPackDir = Join-Path $packagesDir "Catppuccin"
        if (-not (Test-Path $catPackDir)) {
            git clone "https://github.com/catppuccin/sublime-text.git" $catPackDir 2>$null
            Write-Host "[+] Cloned Catppuccin Sublime theme." -ForegroundColor Green
        }

        $prefsFile = Join-Path $userDir "Preferences.sublime-settings"
        $prefs = @{}
        if (Test-Path $prefsFile) {
            try {
                $pjson = Get-Content $prefsFile -Raw
                if ($pjson.Trim()) { $prefs = $pjson | ConvertFrom-Json }
            } catch { }
        }
        # Scheme name may differ; this is a best guess
        $prefs."color_scheme" = "Packages/Catppuccin/Catppuccin Mocha.sublime-color-scheme"
        $prefs."theme"        = "Adaptive.sublime-theme"

        $prefs | ConvertTo-Json -Depth 20 | Set-Content -Path $prefsFile -Encoding UTF8
        Write-Host "[+] Sublime configured with Catppuccin Mocha (best effort)." -ForegroundColor Green
    } else {
        Write-Warning "Sublime Text not found; skipping Sublime theming."
    }
} catch {
    Write-Warning "Failed to configure Sublime theme: $($_.Exception.Message)"
}

# -----------------------------
#  Obsidian Vault + Plugins + Theme
# -----------------------------

Write-Host "[*] Configuring Obsidian vault and Catppuccin theme..." -ForegroundColor Cyan

$vaultRoot = Join-Path $env:USERPROFILE "Documents"
$vaultPath = Join-Path $vaultRoot "Obsidiant_Vault"
$obsidianDir = Join-Path $vaultPath ".obsidian"

try {
    if (-not (Test-Path $vaultPath)) {
        New-Item -ItemType Directory -Path $vaultPath -Force | Out-Null
        Write-Host "[+] Created Obsidian vault folder at $vaultPath" -ForegroundColor Green
    }
    if (-not (Test-Path $obsidianDir)) {
        New-Item -ItemType Directory -Path $obsidianDir -Force | Out-Null
    }

    # Themes
    $themesDir = Join-Path $obsidianDir "themes"
    if (-not (Test-Path $themesDir)) {
        New-Item -ItemType Directory -Path $themesDir -Force | Out-Null
    }
    $catThemeDir = Join-Path $themesDir "Catppuccin"
    if (-not (Test-Path $catThemeDir)) {
        git clone "https://github.com/catppuccin/obsidian.git" $catThemeDir 2>$null
        Write-Host "[+] Cloned Catppuccin Obsidian theme." -ForegroundColor Green
    }

    # appearance.json
    $appearanceFile = Join-Path $obsidianDir "appearance.json"
    $appearance = @{}
    if (Test-Path $appearanceFile) {
        try {
            $aj = Get-Content $appearanceFile -Raw
            if ($aj.Trim()) { $appearance = $aj | ConvertFrom-Json }
        } catch { }
    }
    $appearance.theme = "Catppuccin"
    $appearance.baseColorScheme = "dark"
    $appearance | ConvertTo-Json -Depth 20 | Set-Content -Path $appearanceFile -Encoding UTF8

    # Plugins
    $pluginsDir = Join-Path $obsidianDir "plugins"
    if (-not (Test-Path $pluginsDir)) {
        New-Item -ItemType Directory -Path $pluginsDir -Force | Out-Null
    }

    $pluginRepos = @(
        @{ Id = "advanced-cursors"; Repo = "https://github.com/SkepticMystic/advanced-cursors.git" },
        @{ Id = "cm-editor-syntax-highlight-obsidian"; Repo = "https://github.com/deathau/cm-editor-syntax-highlight-obsidian.git" },
        @{ Id = "obsidian-smarter-md-hotkeys"; Repo = "https://github.com/chrisgrieser/obsidian-smarter-md-hotkeys.git" }
    )

    foreach ($p in $pluginRepos) {
        $pDir = Join-Path $pluginsDir $p.Id
        if (-not (Test-Path $pDir)) {
            git clone $p.Repo $pDir 2>$null
            Write-Host "[+] Cloned Obsidian plugin $($p.Id)." -ForegroundColor Green
        } else {
            Write-Host "[=] Obsidian plugin $($p.Id) directory already exists." -ForegroundColor DarkGray
        }
    }

    # Enable plugins
    $communityFile = Join-Path $obsidianDir "community-plugins.json"
    $enabled = @()
    if (Test-Path $communityFile) {
        try {
            $cj = Get-Content $communityFile -Raw
            if ($cj.Trim()) { $enabled = $cj | ConvertFrom-Json }
        } catch { }
    }
    foreach ($p in $pluginRepos) {
        if ($p.Id -notin $enabled) {
            $enabled += $p.Id
        }
    }
    $enabled | ConvertTo-Json -Depth 5 | Set-Content -Path $communityFile -Encoding UTF8

    # Make this vault the default in global obsidian.json
    $appDataObsidian = Join-Path $env:APPDATA "Obsidian"
    if (-not (Test-Path $appDataObsidian)) {
        New-Item -ItemType Directory -Path $appDataObsidian -Force | Out-Null
    }
    $globalConfigFile = Join-Path $appDataObsidian "obsidian.json"
    $globalCfg = @{}
    if (Test-Path $globalConfigFile) {
        try {
            $gj = Get-Content $globalConfigFile -Raw
            if ($gj.Trim()) { $globalCfg = $gj | ConvertFrom-Json }
        } catch { }
    }
    if (-not $globalCfg.vaults) {
        $globalCfg.vaults = @{}
    }
    # generate id
    $vaultId = [Guid]::NewGuid().ToString("N")
    $globalCfg.vaults.Clear()
    $globalCfg.vaults.$vaultId = @{
        path = $vaultPath
        ts   = [int64]([DateTimeOffset]::Now.ToUnixTimeMilliseconds())
        open = $true
    }
    $globalCfg | ConvertTo-Json -Depth 20 | Set-Content -Path $globalConfigFile -Encoding UTF8
    Write-Host "[+] Obsidian vault configured as default." -ForegroundColor Green

} catch {
    Write-Warning "Failed to configure Obsidian vault/theme/plugins: $($_.Exception.Message)"
}

Write-Host "[*] For Firefox and Chrome Catppuccin themes, the script can open their theme pages for you to click 'Add'." -ForegroundColor Yellow
Write-Host "    (Run these manually if desired.)" -ForegroundColor Yellow

# -----------------------------
#  WSL + Ubuntu Provisioning (END)
# -----------------------------

Write-Host "`n[*] WSL / Ubuntu provisioning is handled at the end of this script." -ForegroundColor Cyan

function Ensure-WSLAndUbuntu {
    # Only meaningful on Windows client with WSL support
    if (-not $OS.IsClient) {
        Write-Host "[*] Non-client OS; skipping WSL setup." -ForegroundColor DarkYellow
        return
    }

    $wslFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
    $vmFeature  = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue

    $needEnable = $false
    if (-not $wslFeature -or $wslFeature.State -ne "Enabled") { $needEnable = $true }
    if (-not $vmFeature -or $vmFeature.State -ne "Enabled") { $needEnable = $true }

    if ($needEnable) {
        Write-Host "[*] Enabling WSL and VirtualMachinePlatform features..." -ForegroundColor Yellow
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction SilentlyContinue | Out-Null

        Write-Host "[!] A reboot may be required before WSL can be used." -ForegroundColor Yellow
        $resp = Read-Host "Reboot now to complete WSL feature enablement? (Y/N)"
        if ($resp -match '^[Yy]') {
            Write-Host "[*] Rebooting now..." -ForegroundColor Yellow
            Restart-Computer
            return
        } else {
            Write-Host "[*] Skipping WSL provisioning for this run. Re-run script after reboot to complete WSL setup." -ForegroundColor DarkYellow
            return
        }
    }

    # Install Ubuntu if missing
    $distros = wsl --list --quiet 2>$null
    if (-not ($distros -match "^Ubuntu$")) {
        Write-Host "[*] Installing Ubuntu in WSL..." -ForegroundColor Yellow
        wsl --install -d Ubuntu
        Write-Host "[!] Ubuntu installation may require a reboot or first-run initialization. Re-run this script after that if needed." -ForegroundColor Yellow
        return
    }

    Write-Host "[*] Provisioning Ubuntu environment in WSL..." -ForegroundColor Cyan

    $aptPackages = @(
        # Essentials
        "build-essential","curl","wget","git","python3","python3-pip","python3-venv","pipx","jq","net-tools",
        "htop","ncdu","tmux","neovim",
        # Networking
        "nmap","netcat-openbsd","tcpdump","traceroute","iputils-ping","whois","dnsutils","iptables","mtr",
        # Security tools
        "gpg","openssl","hashcat","hydra","john","sqlmap","nikto","dnsrecon","steghide",
        # RE / debugging
        "strace","ltrace","radare2","binwalk","gdb","valgrind",
        # Convenience
        "zsh","ripgrep","fd-find","bat","fzf"
    )

    $wslScript = @'
echo "[*] Updating apt..."
sudo apt update
echo "[*] Upgrading packages..."
sudo apt upgrade -y
echo "[*] Installing security tooling..."
sudo apt install -y @APT_PACKAGES@
echo "[*] Ensuring pipx installed..."
python3 -m pip install --user pipx || true
python3 -m pipx ensurepath || true
echo "[*] Installing Python tools via pipx..."
pipx install poetry   || true
pipx install black    || true
pipx install ruff     || true
pipx install bandit   || true
pipx install scrapy   || true
pipx install pwntools || true
'@

    $joined    = ($aptPackages -join " ")
    $wslScript = $wslScript.Replace("@APT_PACKAGES@", $joined)

    # Turn newlines into ; so we can shove it into a single bash -lc string
    $escaped = $wslScript -replace "`r?`n", "; "

    wsl -d Ubuntu -- bash -lc "$escaped"
    Write-Host "[+] Ubuntu provisioning complete (best effort)." -ForegroundColor Green
}

Ensure-WSLAndUbuntu

Write-Host "`n[+] Bootstrap script completed. Open a new PowerShell session to enjoy your profile changes." -ForegroundColor Green
