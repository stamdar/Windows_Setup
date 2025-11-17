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
    [switch]$SkipDebloat,
    [switch]$SkipPackages,
    [switch]$SkipTheming
)

# --- Timing: record script start ---
$ScriptStartTime = Get-Date

# -----------------------------
#  Elevation / Admin Check
# -----------------------------

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[*] Not running as Administrator." -ForegroundColor Yellow

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        Write-Error "This script is not running from a file, so it cannot auto-elevate. Please open PowerShell as Administrator and run the script again."
        return
    }

    Write-Host "[*] Attempting to relaunch script as Administrator..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = (Get-Process -Id $PID).Path
    $psi.Arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb      = "runas"

    try {
        [void][System.Diagnostics.Process]::Start($psi)
    } catch {
        Write-Error "Elevation failed or was cancelled. Please re-run this script from an elevated PowerShell session."
    }

    # Important: just return from the script, do NOT exit the host
    return
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

function Get-SystemDriveFreeGB {
    # Adjust "C:" if you want a different/system drive
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if (-not $disk) { return $null }

    # Return free space in GiB with a couple decimals
    return [math]::Round($disk.FreeSpace / 1GB, 2)
}

# Snapshot free space at start (before we install stuff)
$InitialFreeGB = Get-SystemDriveFreeGB
Write-Host "[*] Initial free space on C:: $InitialFreeGB GB" -ForegroundColor Cyan

# -----------------------------
#  OneDrive Disable (early, idempotent)
# -----------------------------
function Disable-OneDrive {
    Write-Host "[*] Disabling OneDrive (best effort)..." -ForegroundColor Cyan
    try {
        # Kill running OneDrive process
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

        $od32 = Join-Path $env:SystemRoot "System32\OneDriveSetup.exe"
        $od64 = Join-Path $env:SystemRoot "SysWOW64\OneDriveSetup.exe"
        $uninstallRan = $false

        if (Test-Path $od32) {
            Write-Host "[*] Running OneDrive uninstaller (System32)..." -ForegroundColor DarkCyan
            & $od32 /uninstall | Out-Null
            $uninstallRan = $true
        }

        if (Test-Path $od64) {
            Write-Host "[*] Running OneDrive uninstaller (SysWOW64)..." -ForegroundColor DarkCyan
            & $od64 /uninstall | Out-Null
            $uninstallRan = $true
        }

        if ($uninstallRan) {
            Write-Host "[+] OneDrive uninstall invoked (may require logoff/reboot to fully disappear)." -ForegroundColor Green
        } else {
            Write-Host "[=] OneDriveSetup.exe not found; OneDrive is likely already removed." -ForegroundColor DarkGray
        }

        # Harden via policy so it doesn't come back / auto-start
        $oneDrivePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (-not (Test-Path $oneDrivePolicyPath)) {
            New-Item -Path $oneDrivePolicyPath -Force | Out-Null
        }

        # DisableFileSyncNGSC = 1 (Disable OneDrive file sync)
        $currentSync = (Get-ItemProperty -Path $oneDrivePolicyPath -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue).DisableFileSyncNGSC
        if ($currentSync -ne 1) {
            New-ItemProperty -Path $oneDrivePolicyPath -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "[+] Policy: Disable OneDrive file sync (DisableFileSyncNGSC=1)." -ForegroundColor Green
        } else {
            Write-Host "[=] OneDrive file sync already disabled by policy." -ForegroundColor DarkGray
        }

        # PreventNetworkTrafficPreUserSignIn = 1 (optional hardening)
        $currentTraffic = (Get-ItemProperty -Path $oneDrivePolicyPath -Name "PreventNetworkTrafficPreUserSignIn" -ErrorAction SilentlyContinue).PreventNetworkTrafficPreUserSignIn
        if ($currentTraffic -ne 1) {
            New-ItemProperty -Path $oneDrivePolicyPath -Name "PreventNetworkTrafficPreUserSignIn" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "[+] Policy: Block OneDrive traffic before sign-in." -ForegroundColor Green
        } else {
            Write-Host "[=] OneDrive pre-sign-in traffic already blocked by policy." -ForegroundColor DarkGray
        }

    } catch {
        Write-Warning "Failed to fully disable OneDrive: $($_.Exception.Message)"
    }
}

Disable-OneDrive

# -----------------------------
#  Code-signing certificate helpers
# -----------------------------

function Get-OrCreate-CodeSigningCert {
    [CmdletBinding()]
    param(
        [string]$Subject = "CN=StampShell Code Signing"
    )

    # Try to find an existing code-signing cert for this subject
    $existing = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Where-Object { $_.Subject -eq $Subject } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1

    if ($existing) {
        Write-Host "[=] Reusing existing code-signing certificate: $($existing.Thumbprint)" -ForegroundColor DarkGray
        return $existing
    }

    Write-Host "[*] Creating new self-signed code-signing certificate..." -ForegroundColor Yellow

    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -CertStoreLocation "Cert:\CurrentUser\My"

    Write-Host "[+] Created code-signing certificate: $($cert.Thumbprint)" -ForegroundColor Green
    return $cert
}

function Ensure-CertificateTrusted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $stores = @(
        @{ Name = "TrustedPublisher"; Location = "CurrentUser" },
        @{ Name = "Root";             Location = "CurrentUser" }
    )

    foreach ($s in $stores) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s.Name, $s.Location)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

        $existing = $store.Certificates |
            Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint }

        if (-not $existing) {
            $store.Add($Certificate)
            Write-Host "[+] Added code-signing cert to $($s.Location)\$($s.Name)." -ForegroundColor Green
        } else {
            Write-Host "[=] Code-signing cert already present in $($s.Location)\$($s.Name)." -ForegroundColor DarkGray
        }

        $store.Close()
    }
}

function Sign-FileWithCodeSigningCert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not (Test-Path $Path)) {
        Write-Warning "Cannot sign '$Path' – file not found."
        return
    }

    try {
        $sig = Set-AuthenticodeSignature -FilePath $Path -Certificate $Certificate -ErrorAction Stop
        if ($sig.Status -eq 'Valid') {
            Write-Host "[+] Successfully signed '$Path' with code-signing certificate." -ForegroundColor Green
        } else {
            Write-Warning "Signature on '$Path' has status '$($sig.Status)'."
        }
    } catch {
        Write-Warning "Failed to sign '$Path': $($_.Exception.Message)"
    }
}

# -----------------------------
#  Optional Win11 Debloat
# -----------------------------

if ($OS.IsWin11 -and -not $SkipDebloat) {
    Write-Host "[*] Windows 11 detected, running Win11Debloat step..." -ForegroundColor Yellow
    try {
        $tempDir = Join-Path $env:TEMP "Win11Debloat"
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

        $debloatScript = Join-Path $tempDir "Win11Debloat.ps1"
        # Use maintained debloat endpoint
        $debloatUrl = "https://debloat.raphi.re/"

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

        # Run official install snippet *in this process*
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

        if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
            Write-Host "[+] Chocolatey installed successfully." -ForegroundColor Green
        } else {
            throw "Chocolatey installation completed, but choco.exe not found on PATH."
        }
    } catch {
        Write-Warning "Failed to install Chocolatey: $($_.Exception.Message)"
        Write-Warning "Skipping Chocolatey package installation for this run."
        return
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
    @{ Id = "powershell-core";            Name = "PowerShell 7" },
    @{ Id = "fzf";                        Name = "fzf" }
)

Write-Host "[*] Taking snapshot of existing desktop shortcuts..." -ForegroundColor Cyan
$ExistingShortcuts = Get-DesktopShortcuts

if ($SkipPackages) {
    Write-Host "[*] SkipPackages specified — skipping all Chocolatey package installations." -ForegroundColor Yellow
} else {
    foreach ($pkg in $ChocoPackages) {
        Ensure-ChocoPackage -Id $pkg.Id -Name $pkg.Name
    }
}

# -----------------------------
#  Ensure pip and pipx on Windows
# -----------------------------
if (-not $SkipPackages) {
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
} else {
    Write-Host "[*] Skipping pip/pipx + Sysinternals because SkipPackages is set." -ForegroundColor DarkYellow
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
#  Make PS7 the default shell (best-effort)
# -----------------------------

Write-Host "[*] Redirecting legacy 'Windows PowerShell' shortcuts to PowerShell 7..." -ForegroundColor Cyan

$pwshCmd  = Get-Command pwsh -ErrorAction SilentlyContinue
$pwshPath = $pwshCmd.Source

if ($pwshCmd -and (Test-Path $pwshPath)) {
    $shortcutDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell"

    if (Test-Path $shortcutDir) {
        $shell = New-Object -ComObject WScript.Shell
        Get-ChildItem -Path $shortcutDir -Filter *.lnk | ForEach-Object {
            try {
                $sc = $shell.CreateShortcut($_.FullName)
                $sc.TargetPath = $pwshPath
                $sc.Arguments  = ""
                $sc.Save()
                Write-Host "[+] Updated shortcut: $($_.Name)" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to update $($_.FullName): $($_.Exception.Message)"
            }
        }
    }
} else {
    Write-Warning "pwsh.exe not found; skipping legacy shortcut redirection."
}

Write-Host "[*] Creating powershell.cmd shim to redirect to PowerShell 7..." -ForegroundColor Cyan

$pwshDir = Join-Path $env:ProgramFiles "PowerShell\7"
$shim    = Join-Path $pwshDir "powershell.cmd"

if (Test-Path $pwshDir) {
    if (-not (Test-Path $shim)) {
        '@echo off
"%ProgramFiles%\PowerShell\7\pwsh.exe" %*
' | Set-Content $shim -Encoding ASCII
        Write-Host "[+] Created shim: powershell.cmd -> pwsh.exe" -ForegroundColor Green
    } else {
        Write-Host "[=] powershell.cmd shim already exists." -ForegroundColor DarkGray
    }

    # Ensure PowerShell 7 directory is in Machine PATH
    try {
        $targetScope = 'Machine'
        $current = [Environment]::GetEnvironmentVariable('Path', $targetScope)
        if ($current -and $current -match [Regex]::Escape($pwshDir)) {
            Write-Host "[=] $pwshDir already in Machine PATH." -ForegroundColor DarkGray
        } else {
            $sep = if ([string]::IsNullOrEmpty($current) -or $current.TrimEnd().EndsWith(';')) { '' } else { ';' }
            [Environment]::SetEnvironmentVariable('Path', "$current$sep$pwshDir", $targetScope)
            Write-Host "[+] Added $pwshDir to Machine PATH." -ForegroundColor Green
        }

        # Refresh PATH for current session
        $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
        $userPath    = [Environment]::GetEnvironmentVariable('Path','User')
        $env:Path    = "$machinePath;$userPath"
    } catch {
        Write-Warning "Failed to update Machine PATH for PowerShell 7: $($_.Exception.Message)"
    }
} else {
    Write-Warning "PowerShell 7 directory not found at $pwshDir; skipping shim + PATH update."
}

# -----------------------------
#  Windows Terminal autostart
# -----------------------------

Write-Host "[*] Adding Windows Terminal autostart..." -ForegroundColor Cyan

$wt = (Get-Command wt.exe -ErrorAction SilentlyContinue)
if ($wt) {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Set-ItemProperty -Path $runKey -Name "WindowsTerminal" -Value $wt.Source -Force
    Write-Host "[+] Windows Terminal will now auto-start at login." -ForegroundColor Green
} else {
    Write-Warning "wt.exe not found — skipping autostart registration."
}

# -----------------------------
#  Default App Associations via SetUserFTA
# -----------------------------

# Resolve SetUserFTA once
$script:SetUserFtaPath = Get-ChildItem "$env:ProgramData\chocolatey\lib\setuserfta" -Recurse -Filter "SetUserFTA.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $script:SetUserFtaPath) {
    Write-Host "[*] SetUserFTA.exe not found; default app associations will be skipped." -ForegroundColor DarkYellow
}

function Invoke-SetUserFTA {
    param(
        [Parameter(Mandatory)][string]$Extension,
        [Parameter(Mandatory)][string]$ProgId
    )

    if (-not $script:SetUserFtaPath) {
        # Already logged once; just bail quietly
        return
    }

    & $script:SetUserFtaPath $Extension $ProgId
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "SetUserFTA failed for: $Extension -> $ProgId (exit $LASTEXITCODE)"
    } else {
        Write-Host "[+] SetUserFTA: $Extension -> $ProgId" -ForegroundColor Green
    }
}

function Test-AnyCommandExists {
    param(
        [Parameter(Mandatory)][string[]]$Names
    )
    foreach ($n in $Names) {
        if (Get-Command $n -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    return $false
}

Write-Host "[*] Configuring default applications with SetUserFTA..." -ForegroundColor Cyan

if (-not $script:SetUserFtaPath) {
    Write-Host "[*] Skipping default app associations because SetUserFTA is not installed." -ForegroundColor DarkYellow
} else {
    # Note: ProgIDs may vary by install; adjust if needed.
    # Sublime via Applications ProgID
    $SublimeProgId    = "Applications\sublime_text.exe"
    # VS Code via Applications ProgID
    $VSCodeProgId     = "Applications\Code.exe"
    # Adobe Reader DC
    $AdobePdfProgId   = "AcroExch.Document.DC"
    # Wireshark pcap
    $WiresharkProgId  = "Wireshark.pcap"
    # Chrome
    $ChromeProgId     = "ChromeHTML"
    # Obsidian (may need adjustment)
    $ObsidianProgId   = "Obsidian.md"

    # Detect which apps are actually installed
    $HasSublime   = Test-AnyCommandExists @('sublime_text','sublime_text.exe')
    $HasVSCode    = Test-AnyCommandExists @('code','code.cmd','Code.exe')
    $HasAdobe     = Test-AnyCommandExists @('AcroRd32.exe','acrord32')
    $HasWireshark = Test-AnyCommandExists @('wireshark','wireshark.exe')
    $HasChrome    = Test-AnyCommandExists @('chrome','chrome.exe')
    $HasObsidian  = Test-AnyCommandExists @('obsidian','obsidian.exe')

    # Sublime for text-ish
    if ($HasSublime) {
        ".txt",".log",".ini",".cfg",".conf" | ForEach-Object {
            Invoke-SetUserFTA $_ $SublimeProgId
        }
    } else {
        Write-Host "[=] Sublime Text not found; skipping text file associations." -ForegroundColor DarkGray
    }

    # VS Code for code-ish
    if ($HasVSCode) {
        ".c",".h",".hpp",".cpp",".cc",".py",".ps1",".js",".ts",".json",".yml",".yaml",".go",".rs",".lua",".rb" | ForEach-Object {
            Invoke-SetUserFTA $_ $VSCodeProgId
        }
    } else {
        Write-Host "[=] VS Code not found; skipping code file associations." -ForegroundColor DarkGray
    }

    # Adobe for PDFs
    if ($HasAdobe) {
        Invoke-SetUserFTA ".pdf" $AdobePdfProgId
    } else {
        Write-Host "[=] Adobe Reader not found; skipping PDF association." -ForegroundColor DarkGray
    }

    # Wireshark for captures
    if ($HasWireshark) {
        Invoke-SetUserFTA ".pcap"   $WiresharkProgId
        Invoke-SetUserFTA ".pcapng" $WiresharkProgId
    } else {
        Write-Host "[=] Wireshark not found; skipping pcap associations." -ForegroundColor DarkGray
    }

    # Chrome as default browser
    if ($HasChrome) {
        Invoke-SetUserFTA "http"    $ChromeProgId
        Invoke-SetUserFTA "https"   $ChromeProgId
        Invoke-SetUserFTA ".htm"    $ChromeProgId
        Invoke-SetUserFTA ".html"   $ChromeProgId
    } else {
        Write-Host "[=] Chrome not found; skipping browser associations." -ForegroundColor DarkGray
    }

    # Obsidian for markdown
    if ($HasObsidian) {
        Invoke-SetUserFTA ".md" $ObsidianProgId
    } else {
        Write-Host "[=] Obsidian not found; skipping .md association." -ForegroundColor DarkGray
    }
}

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
    $shell      = New-Object -ComObject Shell.Application
    $appsFolder = $shell.Namespace("shell:AppsFolder")
    foreach ($item in $appsFolder.Items()) {
        if ($item.Name -eq $AppIdOrName -or $item.Path -like "*$AppIdOrName*") {
            return $item
        }
    }
    return $null
}

function Test-TaskbarCandidatePresent {
    param(
        [Parameter(Mandatory)][string]$AppName,
        [string]$StartMenuPattern
    )

    # First try AppsFolder
    $item = $null
    try {
        $item = Get-AppsFolderItem -AppIdOrName $AppName
    } catch { }

    if ($item) { return $true }

    # Fallback: look for Start Menu shortcut
    if (-not $StartMenuPattern) {
        $StartMenuPattern = "*$AppName*.lnk"
    }

    $startRoots = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    ) | Where-Object { Test-Path $_ }

    foreach ($root in $startRoots) {
        try {
            $lnk = Get-ChildItem -Path $root -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like $StartMenuPattern } |
                   Select-Object -First 1
            if ($lnk) { return $true }
        } catch { }
    }

    return $false
}

function Pin-AppToTaskbar {
    param(
        [Parameter(Mandatory)][string]$AppName,
        [string]$StartMenuPattern
    )

    $shell = New-Object -ComObject Shell.Application

    # ----------------------------
    # First try shell:AppsFolder
    # ----------------------------
    try {
        $item = Get-AppsFolderItem -AppIdOrName $AppName
        if ($item) {
            $verb = $item.Verbs() | Where-Object {
                $n = $_.Name.Replace('&','')
                $n -match '(?i)taskbar'
            }

            if ($verb) {
                $verb.DoIt()
                Write-Host "[+] Pinned $AppName to taskbar via AppsFolder." -ForegroundColor Green
                return
            } else {
                Write-Host "[=] 'Pin to taskbar' verb not available for $AppName in AppsFolder; trying Start Menu fallback..." -ForegroundColor DarkGray
            }
        } else {
            Write-Host "[=] AppsFolder item not found for $AppName; trying Start Menu fallback..." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "[=] AppsFolder pin attempt for $AppName failed; trying Start Menu fallback..." -ForegroundColor DarkGray
    }

    # ----------------------------
    # Fallback: search Start Menu .lnk
    # ----------------------------
    if (-not $StartMenuPattern) {
        $StartMenuPattern = "*$AppName*.lnk"
    }

    $startRoots = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    ) | Where-Object { Test-Path $_ }

    foreach ($root in $startRoots) {
        try {
            $lnk = Get-ChildItem -Path $root -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -like $StartMenuPattern } |
                   Select-Object -First 1

            if (-not $lnk) { continue }

            $folderPath = Split-Path $lnk.FullName
            $fileName   = Split-Path $lnk.FullName -Leaf

            $folderObj  = $shell.NameSpace($folderPath)
            if (-not $folderObj) { continue }

            $item2 = $folderObj.ParseName($fileName)
            if (-not $item2) { continue }

            $verb2 = $item2.Verbs() | Where-Object {
                $n = $_.Name.Replace('&','')
                $n -match '(?i)taskbar'
            }

            if ($verb2) {
                $verb2.DoIt()
                Write-Host "[+] Pinned $AppName to taskbar via Start Menu shortcut ($($lnk.Name))." -ForegroundColor Green
                return
            }
        } catch {
            # try next root
        }
    }

    Write-Host "[=] Could not pin $AppName to taskbar on this Windows build; skipping." -ForegroundColor DarkGray
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
        "Calendar",
        "Outlook",
        "Copilot"
    )
    foreach ($name in $DefaultUnpins) {
        Unpin-AppFromTaskbar -AppName $name
    }

    # Desired order after Explorer:
    # Windows Terminal, Sublime, VSCode, Obsidian, Firefox, Chrome
    $PinOrder = @(
        @{ Name = "Windows Terminal";    Pattern = "*Windows Terminal*.lnk" },
        @{ Name = "Sublime Text";        Pattern = "*Sublime Text*.lnk" },
        @{ Name = "Visual Studio Code";  Pattern = "*Visual Studio Code*.lnk" },
        @{ Name = "Obsidian";            Pattern = "*Obsidian*.lnk" },
        @{ Name = "Mozilla Firefox";     Pattern = "*Firefox*.lnk" },
        @{ Name = "Google Chrome";       Pattern = "*Chrome*.lnk" }
    )

    foreach ($app in $PinOrder) {
        if (-not (Test-TaskbarCandidatePresent -AppName $app.Name -StartMenuPattern $app.Pattern)) {
            Write-Host "[=] $($app.Name) not found (not installed or no Start Menu entry); skipping taskbar pin." -ForegroundColor DarkGray
            continue
        }

        Unpin-AppFromTaskbar -AppName $app.Name
        Start-Sleep -Milliseconds 200
        Pin-AppToTaskbar -AppName $app.Name -StartMenuPattern $app.Pattern
        Start-Sleep -Milliseconds 200
    }
} else {
    Write-Host "[*] Non-client OS detected; skipping taskbar layout customization." -ForegroundColor DarkYellow
}

# -----------------------------
#  PowerShell Modules & Remote Profile
# -----------------------------

Write-Host "[*] Installing core PowerShell modules..." -ForegroundColor Cyan

try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget) {
        Write-Host "[*] Installing NuGet package provider..." -ForegroundColor Yellow
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false | Out-Null
        $nuget = Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue
    }

    $repo = Get-PSRepository -Name "PSGallery" -ErrorAction SilentlyContinue
    if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
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
    "HAWK",
    "Pester",
    "ImportExcel"
)

foreach ($m in $CoreModules + $ExtraModules) {
    try {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "[*] Installing module $m..." -ForegroundColor Yellow
            Install-Module -Name $m -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
        } else {
            Write-Host "[=] Module $m already installed." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Failed to install module ${m}: $($_.Exception.Message)"
    }
}

# -----------------------------
#  Fetch Profile from GitHub
# -----------------------------

Write-Host "[*] Downloading remote PowerShell profile..." -ForegroundColor Cyan

try {
    $profileDir = Split-Path -Parent $PROFILE
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }

    $profileUrl = "https://raw.githubusercontent.com/stamdar/StampShell_Profile/refs/heads/main/profile.ps1"
    Invoke-WebRequest -Uri $profileUrl -OutFile $PROFILE -UseBasicParsing -ErrorAction Stop

    Write-Host "[+] Downloaded profile to $PROFILE" -ForegroundColor Green

    # --- Code-signing: create/reuse cert, trust it, and sign the profile ---
    try {
        $csCert = Get-OrCreate-CodeSigningCert
        Ensure-CertificateTrusted -Certificate $csCert
        Sign-FileWithCodeSigningCert -Path $PROFILE -Certificate $csCert
    } catch {
        Write-Warning "Failed to create/trust/sign profile with code-signing certificate: $($_.Exception.Message)"
    }

    # Optionally set CurrentUser execution policy to AllSigned so the signed profile is allowed
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
        if ($currentPolicy -ne 'AllSigned') {
            Write-Host "[*] Setting CurrentUser execution policy to AllSigned so the signed profile will load." -ForegroundColor Yellow
            Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope CurrentUser -Force
        } else {
            Write-Host "[=] CurrentUser execution policy already AllSigned." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "Failed to set execution policy to AllSigned: $($_.Exception.Message)"
    }

    # Load it immediately for current session (current process is already Bypass)
    . $PROFILE
    Write-Host "[+] Loaded profile into current session." -ForegroundColor Green
}
catch {
    Write-Warning "Failed to download or load remote profile: $($_.Exception.Message)"
}

# =============================
#  Theming (SkipTheming-aware)
# =============================

if ($SkipTheming) {
    Write-Host "[*] SkipTheming specified — skipping Windows Terminal, VS Code, Sublime, and Obsidian theming." -ForegroundColor Yellow
} else {

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

            # Ensure schemes property exists
            if (-not ($settingsJson.PSObject.Properties.Name -contains 'schemes')) {
                $settingsJson | Add-Member -MemberType NoteProperty -Name schemes -Value @()
            }

            # Replace or add Mocha scheme
            $existing = $settingsJson.schemes | Where-Object { $_.name -eq $mocha.name }
            if ($existing) {
                $settingsJson.schemes = @($settingsJson.schemes | Where-Object { $_.name -ne $mocha.name }) + $mocha
            } else {
                $settingsJson.schemes += $mocha
            }

            # Set colorScheme on PowerShell-like profiles
            if ($settingsJson.profiles -and $settingsJson.profiles.list) {
                foreach ($p in $settingsJson.profiles.list) {
                    if (-not $p) { continue }
                    $hasCmd = $p.PSObject.Properties.Name -contains 'commandline'
                    $hasName = $p.PSObject.Properties.Name -contains 'name'
                    if (($hasCmd -and $p.commandline -like "*pwsh*") -or ($hasName -and $p.name -like "*PowerShell*")) {
                        if ($p.PSObject.Properties.Name -contains 'colorScheme') {
                            $p.colorScheme = $mocha.name
                        } else {
                            $p | Add-Member -NotePropertyName colorScheme -NotePropertyValue $mocha.name
                        }
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

        # Look for an existing vault pointing at this path
        $existingKey = $null
        if ($globalCfg.vaults -is [System.Management.Automation.PSCustomObject]) {
            foreach ($prop in $globalCfg.vaults.PSObject.Properties) {
                if ($prop.Value -and $prop.Value.path -eq $vaultPath) {
                    $existingKey = $prop.Name
                    break
                }
            }
        }

        $nowTs = [int64]([DateTimeOffset]::Now.ToUnixTimeMilliseconds())

        if ($existingKey) {
            $globalCfg.vaults.$existingKey.path = $vaultPath
            $globalCfg.vaults.$existingKey.ts   = $nowTs
            $globalCfg.vaults.$existingKey.open = $true
        } else {
            $vaultId = [Guid]::NewGuid().ToString("N")
            $globalCfg.vaults.$vaultId = @{
                path = $vaultPath
                ts   = $nowTs
                open = $true
            }
        }

        $globalCfg | ConvertTo-Json -Depth 20 | Set-Content -Path $globalConfigFile -Encoding UTF8
        Write-Host "[+] Obsidian vault configured as default." -ForegroundColor Green

    } catch {
        Write-Warning "Failed to configure Obsidian vault/theme/plugins: $($_.Exception.Message)"
    }

    Write-Host "[*] For Firefox and Chrome Catppuccin themes, the script can open their theme pages for you to click 'Add'." -ForegroundColor Yellow
    Write-Host "    (Run these manually if desired.)" -ForegroundColor Yellow
}

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

    # Install Ubuntu if missing (treat any "Ubuntu*" as present)
    $distros = wsl --list --quiet 2>$null
    if (-not ($distros -match "^Ubuntu")) {
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

# --- Timing: compute script duration ---
$ScriptEndTime = Get-Date
$Duration      = $ScriptEndTime - $ScriptStartTime

$DurationHHMM = '{0:hh\:mm\:ss}' -f $Duration
$DurationMin  = [math]::Round($Duration.TotalMinutes, 1)
$DurationSec  = [math]::Round($Duration.TotalSeconds)

# --- Disk usage delta ---
$FinalFreeGB = Get-SystemDriveFreeGB
if ($null -ne $InitialFreeGB -and $null -ne $FinalFreeGB) {
    $DiskUsedGBRaw = $InitialFreeGB - $FinalFreeGB

    # If for some reason free space increased (cleanup, debloat), don't show a negative number
    if ($DiskUsedGBRaw -lt 0) { $DiskUsedGBRaw = 0 }

    $DiskUsedGB = [math]::Round($DiskUsedGBRaw, 2)
} else {
    $DiskUsedGB = "N/A"
}

# --- Script Completion prompt ---
Write-Host ""
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host " Bootstrap Nearly Complete" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host " Disk space consumed by installed packages: $DiskUsedGB GB" -ForegroundColor Green
Write-Host " Total runtime: $DurationHHMM  (~$DurationMin min, $DurationSec sec)" -ForegroundColor Green
Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host "Open a NEW PowerShell window to load the updated profile." -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting WSL installation. A reboot will be required."
Write-Host ""

Ensure-WSLAndUbuntu