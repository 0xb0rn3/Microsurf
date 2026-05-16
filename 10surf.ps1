#Requires -RunAsAdministrator
<#
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ███╗   ███╗██╗ ██████╗██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
  ████╗ ████║██║██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ██╔████╔██║██║██║     ██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗
  ██║╚██╔╝██║██║██║     ██╔══██╗██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝
  ██║ ╚═╝ ██║██║╚██████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║  ██║██║
  ╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Script  : 10surf.ps1
  Version : 2.1.0
  Target  : Windows 10 (21H2 / 22H2 / 23H2 / latest) — Chromebook aware
  Repo    : https://github.com/0xb0rn3/Microsurf
  Author  : 0xb0rn3
  Contact : 0xb0rn3@oxborn3.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Chromebook driver integration — CoolStar / driverinstallers
  https://github.com/coolstar/driverinstallers
  https://coolstar.org/chromebook
  Copyright 2024, CoolStar. All Rights Reserved.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Built for people who don't trust them with their data.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

.SYNOPSIS
    Windows 10 privacy hardening + Chromebook device-aware driver installation.

.DESCRIPTION
    Reads the Chromebook board codename from firmware (DMI / cbtable), maps it
    to the exact CoolStar driver set for that device (EC, touchpad, touchscreen,
    audio, fingerprint, CR50, Intel chipset), then downloads and silently
    installs each driver.  Runs the full Microsurf privacy hardening pipeline
    afterwards.  Everything executes via irm | iex — no local files needed.

.NOTES
    - Run as Administrator in an elevated PowerShell session
    - System Restore Point is created automatically before any changes
    - Roll back at any time: rstrui.exe
    - Quick start:
      irm https://raw.githubusercontent.com/0xb0rn3/Microsurf/main/10surf.ps1 | iex
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ███╗   ███╗██╗ ██████╗██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗" -ForegroundColor Cyan
Write-Host "  ████╗ ████║██║██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝" -ForegroundColor Cyan
Write-Host "  ██╔████╔██║██║██║     ██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗  " -ForegroundColor Cyan
Write-Host "  ██║╚██╔╝██║██║██║     ██╔══██╗██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝  " -ForegroundColor Cyan
Write-Host "  ██║ ╚═╝ ██║██║╚██████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║  ██║██║     " -ForegroundColor Cyan
Write-Host "  ╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  " -ForegroundColor Cyan
Write-Host ""
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host "   v2.1.0  |  github.com/0xb0rn3/Microsurf  |  0xb0rn3@oxborn3.com" -ForegroundColor DarkGray
Write-Host "   Chromebook driver engine: coolstar.org/chromebook" -ForegroundColor DarkGray
Write-Host "   Built for people who don't trust them with their data." -ForegroundColor DarkGray
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkCyan
Write-Host ""


# ─────────────────────────────────────────────────────────────────────────────
# OS GUARD
# ─────────────────────────────────────────────────────────────────────────────
$osInfo    = Get-CimInstance Win32_OperatingSystem
$osBuild   = [int]$osInfo.BuildNumber
$osCaption = $osInfo.Caption

if ($osBuild -ge 22000 -or $osCaption -notmatch "Windows 10") {
    Write-Host "  [!] UNSUPPORTED OS: $osCaption (Build $osBuild)" -ForegroundColor Red
    Write-Host "  [!] This script targets Windows 10 only. Exiting." -ForegroundColor Red
    exit 1
}
Write-Host "  [*] OS: $osCaption (Build $osBuild)" -ForegroundColor Green
Write-Host ""


# ─────────────────────────────────────────────────────────────────────────────
# CORE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Header { param($msg) Write-Host "`n  ┌─ $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "  │  [+] $msg" -ForegroundColor Green }
function Write-Warn   { param($msg) Write-Host "  │  [!] $msg" -ForegroundColor Yellow }
function Write-Skip   { param($msg) Write-Host "  │  [-] $msg" -ForegroundColor DarkGray }
function Write-Err    { param($msg) Write-Host "  │  [x] $msg" -ForegroundColor Red }
function Write-Footer { Write-Host "  └─────────────────────────────────────────────────" -ForegroundColor DarkCyan }

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-OK "$Name = $Value"
}

function Disable-Svc {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $Name -StartupType Disabled
        Write-OK "Service disabled: $Name"
    } else { Write-Skip "Service not found: $Name" }
}

function Confirm-Step {
    param([string]$Question)
    $r = Read-Host "  ? $Question [Y/N]"
    return $r -match "^[Yy]"
}

function Install-CbDriver {
    param([string]$Label, [string]$Url, [string]$Args = "/S")
    Write-OK "Fetching: $Label"
    $tmp = Join-Path $env:TEMP ("cb_" + [System.IO.Path]::GetRandomFileName() + ".exe")
    try {
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        if ((Get-Item $tmp).Length -lt 4096) { throw "Download too small — bad response." }
        $proc = Start-Process -FilePath $tmp -ArgumentList $Args -Wait -PassThru -ErrorAction Stop
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-OK "Installed: $Label (exit $($proc.ExitCode))"
        } else {
            Write-Warn "$Label installer exited $($proc.ExitCode)"
        }
    } catch {
        Write-Err "Failed: $Label — $_"
    } finally {
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
}


# ─────────────────────────────────────────────────────────────────────────────
# RESTORE POINT
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "System Restore Point"
Enable-ComputerRestore -Drive "$env:SystemDrive"
Checkpoint-Computer -Description "Before Microsurf 2.1.0" -RestorePointType "MODIFY_SETTINGS"
Write-OK "Restore point created — roll back anytime: rstrui.exe"
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 0 — CHROMEBOOK DEVICE DETECTION & DRIVER INSTALLATION
# ═════════════════════════════════════════════════════════════════════════════

# ── CoolStar driver base URLs (all from github.com/coolstar/driverinstallers)
$CS = "https://github.com/coolstar/driverinstallers/raw/master"

# ── Shared driver URLs (device-independent) ──────────────────────────────────
$DRV = @{
    # Core CrOS infrastructure
    CR50         = "$CS/cr50/cr50.1.0.2-installer.exe"
    CrOSEC       = "$CS/crosec/crosec.2.0.7-installer.exe"
    WilcoEC      = "$CS/wilcoec/wilcoec.1.0.2-installer.exe"
    Touchpad     = "$CS/crostouchpad/crostouchpad.4.1.6-installer.exe"
    Touchscreen  = "$CS/crostouchscreen/crostouchscreen.2.9.5-installer.exe"
    Fingerprint  = "$CS/crosfingerprint/crosfingerprint.2023.09.17-installer.exe"
    GmbusI2C     = "$CS/gmbusi2c/gmbusi2c.1.0-installer.exe"
    # Audio drivers
    Max98090     = "$CS/max98090/max98090.1.0.4-installer.exe"
    Max98090R11  = "$CS/max98090-r11/max98090-r11.1.0.0-installer.exe"
    ACP2x        = "$CS/csaudioacp2x/csaudioacp2x.1.0.0-installer.exe"
    ACP3x        = "$CS/csaudioacp3x/csaudioacp3x.1.0.4-1-installer.exe"
    SSTCatpt     = "$CS/csaudiosstcatpt/csaudiosstcatpt.1.0.1-installer.exe"
    SKLHdAudBus  = "$CS/sklhdaudbus/sklhdaudbus.1.0.1-installer.exe"
    # Visual C++ Runtime (required by several drivers)
    VCRT         = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
    # Intel chipset autoinstaller (community maintained, referenced by coolstar.org)
    IntelAuto    = "https://github.com/vibecoder2001/3rdparty-autoinstall/releases/download/v1.0.1-immutable/3rdpartyautoinstall.1.0.1-installer.exe"
}

# ── Device codename → driver profile ─────────────────────────────────────────
# Sourced from: https://coolstar.org/chromebook/windows.html
# Each entry: @{ Chip; Label; Drivers = @(...); Audio; Notes }
# Drivers list references keys from $DRV above.
# Audio = key in $DRV, or "PAID" (CoolStar SOF/cAVS — purchase required), or "NONE"
$DeviceProfiles = @{

    # ── Meteor Lake (MTL) ────────────────────────────────────────────────────
    "kanix"   = @{ Chip="MTL"; Label="Acer Plus 714";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "karis"   = @{ Chip="MTL"; Label="Acer Plus Spin 714";     Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "screebo" = @{ Chip="MTL"; Label="Asus Expertbook CX5403"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }

    # ── Alder Lake-N / Twin Lake (ADL-N) ────────────────────────────────────
    "anraggar"     = @{ Chip="ADL-N"; Label="Acer CR12";              Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "anraggar360"  = @{ Chip="ADL-N"; Label="Acer CR12 Flip";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "craask"       = @{ Chip="ADL-N"; Label="Acer Spin 512";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "cret"         = @{ Chip="JSL";   Label="Dell Chromebook 3110";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "cret360"      = @{ Chip="JSL";   Label="Dell 3110 2-in-1";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "domika"       = @{ Chip="ADL-N"; Label="HP Fortis G1i 11";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "domilly"      = @{ Chip="ADL-N"; Label="HP Fortis Flip G1i 11";  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "domiso"       = @{ Chip="ADL-N"; Label="HP Fortis G1i 14";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "uldren"       = @{ Chip="ADL-N"; Label="Dell 3120";               Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "uldrenite"    = @{ Chip="ADL-N"; Label="Dell 11 CC11260";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }

    # ── Alder Lake / Raptor Lake (ADL/RPL) ──────────────────────────────────
    "anahera"  = @{ Chip="ADL"; Label="HP Elite c640 G3";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "banshee"  = @{ Chip="ADL"; Label="Framework Chromebook";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "crota"    = @{ Chip="ADL"; Label="Dell Latitude 5430";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "dochi"    = @{ Chip="ADL"; Label="Acer Chromebook Plus Spin 514"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "felwinter"= @{ Chip="ADL"; Label="Asus CX5601 Flip";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "gimble"   = @{ Chip="ADL"; Label="HP Chromebook x360 14";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "kano"     = @{ Chip="ADL"; Label="Asus Chromebook Spin 714";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "marasov"  = @{ Chip="ADL"; Label="Asus CX3402";                Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "mithrax"  = @{ Chip="ADL"; Label="Asus Chromebook Flip CX34";  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "omnigul"  = @{ Chip="ADL"; Label="Acer Chromebook Plus 515";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "osiris"   = @{ Chip="ADL"; Label="Acer Chromebook 516GE";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "primus"   = @{ Chip="ADL"; Label="ThinkPad C14 Gen 1";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "redrix"   = @{ Chip="ADL"; Label="HP Elite Dragonfly";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "taeko"    = @{ Chip="ADL"; Label="Lenovo Flex 5i 14";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "taniks"   = @{ Chip="ADL"; Label="IdeaPad Gaming 16";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "vell"     = @{ Chip="ADL"; Label="HP Dragonfly Pro";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="NONE" }
    "volmar"   = @{ Chip="ADL"; Label="Acer Chromebook Vero 514";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "xol"      = @{ Chip="ADL"; Label="Samsung Galaxy Chromebook Plus"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "zavala"   = @{ Chip="ADL"; Label="Acer Chromebook Vero 712";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }

    # ── Tiger Lake (TGL) ────────────────────────────────────────────────────
    "chronicler"= @{ Chip="TGL"; Label="FMV Chromebook 14F";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "collis"    = @{ Chip="TGL"; Label="Asus Chromebook Flip CX3";    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "copano"    = @{ Chip="TGL"; Label="Asus Chromebook Flip CX5400"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "delbin"    = @{ Chip="TGL"; Label="Asus CX5500/CX536";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "drobit"    = @{ Chip="TGL"; Label="Asus CX9400";                 Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "eldrid"    = @{ Chip="TGL"; Label="HP Chromebook x360 14c";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "elemi"     = @{ Chip="TGL"; Label="HP Pro c640 G2";              Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "lillipup"  = @{ Chip="TGL"; Label="Lenovo IdeaPad Flex 5i";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "lindar"    = @{ Chip="TGL"; Label="Lenovo 5i-14 / Slim 5";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "voema"     = @{ Chip="TGL"; Label="Acer Chromebook Spin 514";    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "volet"     = @{ Chip="TGL"; Label="Acer Chromebook 515";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "volta"     = @{ Chip="TGL"; Label="Acer Chromebook 514";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "voxel"     = @{ Chip="TGL"; Label="Acer Spin 713 (CP713-3W)";    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }

    # ── Comet Lake (CML) ────────────────────────────────────────────────────
    "akemi"     = @{ Chip="CML"; Label="Lenovo IdeaPad Flex 5";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "dragonair" = @{ Chip="CML"; Label="HP Chromebook x360 14c (CML)";  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "drallion"  = @{ Chip="CML"; Label="Dell 7410 Enterprise";          Drivers=@("VCRT","CR50","CrOSEC","WilcoEC","Touchpad","GmbusI2C","IntelAuto"); Audio="PAID" }
    "dratini"   = @{ Chip="CML"; Label="HP Pro c640";                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","IntelAuto"); Audio="PAID" }
    "helios"    = @{ Chip="CML"; Label="Asus Chromebook Flip C436FA";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "jinlon"    = @{ Chip="CML"; Label="HP Elite c1030 / x360 13c";     Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "kindred"   = @{ Chip="CML"; Label="Acer Chromebook 712 (C871)";    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "kled"      = @{ Chip="CML"; Label="Acer Spin 713 (CP713-2W)";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "kohaku"    = @{ Chip="CML"; Label="Samsung Galaxy Chromebook";      Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }
    "nightfury" = @{ Chip="CML"; Label="Samsung Galaxy Chromebook 2";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }

    # ── Jasper Lake (JSL) ───────────────────────────────────────────────────
    "beetley"   = @{ Chip="JSL"; Label="IdeaPad Flex 3i";              Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "blipper"   = @{ Chip="JSL"; Label="Lenovo 3i-15";                 Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "bookem"    = @{ Chip="JSL"; Label="Lenovo 100e Gen 3";            Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "boten"     = @{ Chip="JSL"; Label="Lenovo 500e Gen 3";            Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "botenflex" = @{ Chip="JSL"; Label="Lenovo Flex 3i-11";            Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "bugzzy"    = @{ Chip="JSL"; Label="Samsung Galaxy Chromebook 2 360"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "drawcia"   = @{ Chip="JSL"; Label="HP Chromebook x360 11 G4 EE"; Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "drawlat"   = @{ Chip="JSL"; Label="HP Chromebook 11 G9 EE";       Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "drawman"   = @{ Chip="JSL"; Label="HP Chromebook 14 G7";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "galith"    = @{ Chip="JSL"; Label="Asus CX1500CKA";               Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "galith360" = @{ Chip="JSL"; Label="Asus CX1500GKA";               Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "gallop"    = @{ Chip="JSL"; Label="Asus CX1700";                  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "galnat"    = @{ Chip="JSL"; Label="Asus CX1 CX1102";              Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "galnat360" = @{ Chip="JSL"; Label="Asus Flip CX1 CX1102";         Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "galtic"    = @{ Chip="JSL"; Label="Asus CX1400";                  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "galtic360" = @{ Chip="JSL"; Label="Asus CX1400GKA";               Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "kracko"    = @{ Chip="JSL"; Label="CTL NL72";                     Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "kracko360" = @{ Chip="JSL"; Label="CTL NL72T";                    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "landia"    = @{ Chip="JSL"; Label="HP x360 14a-ca1";              Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "lantis"    = @{ Chip="JSL"; Label="HP Chromebook 14a";            Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "magister"  = @{ Chip="JSL"; Label="Acer Spin 314";                Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "magma"     = @{ Chip="JSL"; Label="Acer Chromebook 315";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "magneto"   = @{ Chip="JSL"; Label="Acer Chromebook 314";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "magolor"   = @{ Chip="JSL"; Label="Acer Spin 511 [R753T]";        Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }
    "magpie"    = @{ Chip="JSL"; Label="Acer Chromebook 317";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "sasuke"    = @{ Chip="JSL"; Label="Samsung Galaxy Chromebook Go";  Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "storo"     = @{ Chip="JSL"; Label="Asus Chromebook CR1100";        Drivers=@("VCRT","CR50","CrOSEC","Touchpad","IntelAuto"); Audio="PAID" }
    "storo360"  = @{ Chip="JSL"; Label="Asus Chromebook Flip CR1100";   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","IntelAuto"); Audio="PAID" }

    # ── Kaby Lake (KBL) ─────────────────────────────────────────────────────
    "akali"   = @{ Chip="KBL"; Label="Acer Chromebook 13/Spin 13";    Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","SKLHdAudBus"); Audio="PAID" }
    "bard"    = @{ Chip="KBL"; Label="Acer Chromebook 715";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","SKLHdAudBus"); Audio="PAID" }
    "ekko"    = @{ Chip="KBL"; Label="Acer Chromebook 714";           Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","SKLHdAudBus"); Audio="PAID" }
    "leona"   = @{ Chip="KBL"; Label="Asus Chromebook C425";          Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","SKLHdAudBus"); Audio="PAID" }
    "shyvana" = @{ Chip="KBL"; Label="Asus Chromebook Flip C433/C434";Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","SKLHdAudBus"); Audio="PAID" }

    # ── Apollo Lake / Skylake (Broadwell-era) ────────────────────────────────
    "kefka"   = @{ Chip="APL"; Label="Dell Chromebook 11 3189 (Kefka)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen"); Audio="SSTCatpt"
                   Notes="Your exact device. Apollo Lake. CR50 required for sleep/wake on RW_LEGACY." }

    "lars"    = @{ Chip="SKL"; Label="Dell Chromebook 13 (Lars)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","SKLHdAudBus"); Audio="SSTCatpt" }

    "cave"    = @{ Chip="SKL"; Label="Dell Chromebook 13 7310 (Cave)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","SKLHdAudBus"); Audio="SSTCatpt" }

    "cyan"    = @{ Chip="SKL"; Label="Acer Chromebook 14 CB3-431 (Cyan)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","GmbusI2C","SKLHdAudBus"); Audio="SSTCatpt" }

    "edgar"   = @{ Chip="SKL"; Label="Acer Chromebook 14 for Work (Edgar)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","SKLHdAudBus"); Audio="SSTCatpt" }

    "eve"     = @{ Chip="KBL"; Label="Google Pixelbook (Eve)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","Fingerprint","GmbusI2C","SKLHdAudBus"); Audio="PAID" }

    "nocturne"= @{ Chip="KBL"; Label="Google Pixel Slate (Nocturne)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","Fingerprint","GmbusI2C","SKLHdAudBus"); Audio="PAID" }

    "reef"    = @{ Chip="APL"; Label="Acer Chromebook 11 N7 / HP 11 G7 (Reef)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad"); Audio="Max98090" }

    "sand"    = @{ Chip="APL"; Label="Samsung Chromebook Plus V1 (Sand)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen"); Audio="Max98090" }

    "nami"    = @{ Chip="CML"; Label="Various 8th Gen Chromebooks (Nami)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }

    "rammus"  = @{ Chip="CML"; Label="Acer Chromebook 514 (Rammus)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad","Touchscreen","GmbusI2C","IntelAuto"); Audio="PAID" }

    "snappy"  = @{ Chip="APL"; Label="HP Chromebook 11 G6 EE (Snappy)";
                   Drivers=@("VCRT","CR50","CrOSEC","Touchpad"); Audio="Max98090R11" }
}

# ── Step 1: Read board codename from DMI / cbtable ───────────────────────────
Write-Header "Chromebook Device Detection"

$boardName = $null

# Method A: WMI BaseBoardProduct (populated by MrChromebox UEFI / coreboot)
try {
    $bios      = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    $candidate = $bios.Product.Trim().ToLower()
    if ($candidate -and $candidate.Length -gt 2 -and $candidate -ne "to be filled by o.e.m.") {
        $boardName = $candidate
        Write-OK "DMI BaseBoard product: $($bios.Product)"
    }
} catch {}

# Method B: WMI ComputerSystem Model (fallback, less reliable)
if (-not $boardName) {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $candidate = $cs.Model.Trim().ToLower()
        if ($candidate -and $candidate.Length -gt 2) {
            $boardName = $candidate
            Write-OK "DMI ComputerSystem model: $($cs.Model)"
        }
    } catch {}
}

# Method C: ACPI GPIO controller presence for generic Intel detection
$acpiGpioMap = @(
    @{ ID="ACPI\INT34BB\0"; Gen="CML"; Label="Comet Lake"  },
    @{ ID="ACPI\INT34C8\0"; Gen="JSL"; Label="Jasper Lake" },
    @{ ID="ACPI\INT34C5\0"; Gen="TGL"; Label="Tiger Lake"  },
    @{ ID="ACPI\INTC1055\0";Gen="ADL"; Label="Alder Lake"  },
    @{ ID="ACPI\INTC1056\0";Gen="ADL"; Label="Alder Lake"  },
    @{ ID="ACPI\INTC1057\0";Gen="ADL-N";Label="Alder Lake-N"},
    @{ ID="ACPI\INTC1085\0";Gen="ADL"; Label="Raptor Lake" },
    @{ ID="ACPI\INTC1083\0";Gen="MTL"; Label="Meteor Lake" }
)
$detectedGenChip = $null
$detectedGenLabel = $null
foreach ($entry in $acpiGpioMap) {
    if (Get-PnpDevice -PresentOnly -InstanceID $entry.ID 2>$null) {
        $detectedGenChip  = $entry.Gen
        $detectedGenLabel = $entry.Label
        break
    }
}
if ($detectedGenChip) {
    Write-OK "ACPI GPIO indicates: $detectedGenLabel ($detectedGenChip)"
}

# ── Step 2: Resolve profile ──────────────────────────────────────────────────
$profile = $null

if ($boardName -and $DeviceProfiles.ContainsKey($boardName)) {
    $profile = $DeviceProfiles[$boardName]
    Write-OK "Exact device match: $($profile.Label) [$boardName]"
    if ($profile.Notes) { Write-Warn "Note: $($profile.Notes)" }
} else {
    if ($boardName) {
        Write-Warn "Board name '$boardName' not in device database."
    } else {
        Write-Warn "Could not read board codename from DMI."
    }

    # Prompt for manual codename entry
    Write-Host ""
    Write-Host "  ? Enter your Chromebook board codename (e.g. kefka, eve, reef)" -ForegroundColor Yellow
    Write-Host "    Look it up at: https://www.coolstar.org/chromebook/windows.html" -ForegroundColor DarkGray
    $manualName = (Read-Host "  > Codename (leave blank to skip driver install)").Trim().ToLower()

    if ($manualName -and $DeviceProfiles.ContainsKey($manualName)) {
        $profile   = $DeviceProfiles[$manualName]
        $boardName = $manualName
        Write-OK "Profile loaded: $($profile.Label) [$boardName]"
        if ($profile.Notes) { Write-Warn "Note: $($profile.Notes)" }
    } elseif ($manualName) {
        Write-Warn "Unknown codename '$manualName' — cannot map to a driver set."
        Write-Warn "Visit https://coolstar.org/chromebook/windows-install.html?device=$manualName"
        Write-Warn "and install drivers manually."
    } else {
        Write-Skip "Driver installation skipped by user."
    }
}
Write-Footer

# ── Step 3: Install drivers for detected device ──────────────────────────────
if ($profile) {
    Write-Header "Installing CoolStar Drivers — $($profile.Label)"
    Write-OK "Chipset: $($profile.Chip)"
    Write-OK "Driver set: $($profile.Drivers -join ', ')"
    Write-Host ""

    if (Confirm-Step "Install CoolStar drivers for $($profile.Label)?") {

        # Install each driver in the profile's ordered list
        foreach ($drvKey in $profile.Drivers) {
            if ($DRV.ContainsKey($drvKey)) {
                $silentArg = if ($drvKey -eq "VCRT") { "/install /quiet /norestart" } else { "/S" }
                Install-CbDriver -Label $drvKey -Url $DRV[$drvKey] -Args $silentArg
            } else {
                Write-Skip "Unknown driver key: $drvKey"
            }
        }

        # Audio driver
        $audioKey = $profile.Audio
        if ($audioKey -eq "PAID") {
            Write-Warn "Audio driver requires a paid license from CoolStar."
            Write-Warn "Purchase at: https://coolstar.org/chromebook/driverlicense/"
        } elseif ($audioKey -eq "NONE") {
            Write-Skip "No audio driver available for this device."
        } elseif ($DRV.ContainsKey($audioKey)) {
            Install-CbDriver -Label "Audio ($audioKey)" -Url $DRV[$audioKey]
        }

        # Intel chipset CAB-based drivers (runs the autoinstaller which handles all gen)
        Write-OK "CoolStar Intel driver autoinstaller handles chipset detection internally."

        # UTC clock fix — required for dual-boot with ChromeOS
        Write-Host ""
        if (Confirm-Step "Set hardware clock to UTC? (Required if dual-booting with ChromeOS)") {
            Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" "RealTimeIsUniversal" 1
            Write-OK "RealTimeIsUniversal set. Reboot to apply."
        }

        Write-OK "CoolStar driver installation complete for $($profile.Label)."
    } else {
        Write-Skip "CoolStar driver installation skipped."
    }
    Write-Footer
}


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 1 — TELEMETRY & DATA COLLECTION
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Telemetry & Data Collection"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "AllowTelemetry"                    0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry"     0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "MaxTelemetryAllowed" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "LimitDiagnosticLogCollection"     1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "DisableOneSettingsDownloads"      1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "DoNotShowFeedbackNotifications"   1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" "ShowedToastAtLevel"   1
Disable-Svc "DiagTrack"
Disable-Svc "dmwappushservice"
Write-Footer

Write-Header "Telemetry Host Blocks"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$telHosts = @(
    "0.0.0.0 vortex.data.microsoft.com","0.0.0.0 vortex-win.data.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com","0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 oca.telemetry.microsoft.com","0.0.0.0 oca.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 sqm.telemetry.microsoft.com","0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 watson.telemetry.microsoft.com","0.0.0.0 watson.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 redir.metaservices.microsoft.com","0.0.0.0 choice.microsoft.com",
    "0.0.0.0 choice.microsoft.com.nsatc.net","0.0.0.0 df.telemetry.microsoft.com",
    "0.0.0.0 reports.wes.df.telemetry.microsoft.com","0.0.0.0 wes.df.telemetry.microsoft.com",
    "0.0.0.0 services.wes.df.telemetry.microsoft.com","0.0.0.0 sqm.df.telemetry.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com","0.0.0.0 watson.microsoft.com",
    "0.0.0.0 statsfe2.ws.microsoft.com","0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com",
    "0.0.0.0 compatible.microsoft.com","0.0.0.0 statsfe1.ws.microsoft.com",
    "0.0.0.0 feedback.windows.com","0.0.0.0 feedback.search.microsoft.com",
    "0.0.0.0 feedback.microsoft-hohm.com","0.0.0.0 settings-sandbox.data.microsoft.com",
    "0.0.0.0 i1.services.social.microsoft.com","0.0.0.0 i1.services.social.microsoft.com.nsatc.net",
    "0.0.0.0 bingads.microsoft.com","0.0.0.0 cy2.bingads.microsoft.com"
)
$hostsContent = Get-Content $hostsPath -Raw
foreach ($entry in $telHosts) {
    $h = ($entry -split " ")[1]
    if ($hostsContent -notmatch [regex]::Escape($h)) { Add-Content $hostsPath $entry; Write-OK "Blocked: $h" }
    else { Write-Skip "Already blocked: $h" }
}
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 2 — CORTANA
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Cortana"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"             0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock"    0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch"         1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb"    0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "BingSearchEnabled"        0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "CortanaConsent"           0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "HistoryViewEnabled"       0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "DeviceHistoryEnabled"     0
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 3 — ADVERTISING ID & PERSONALIZATION
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Advertising ID & Personalization"
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"         "Enabled"                    0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"               "DisabledByGroupPolicy"      1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"                 "TailoredExperiencesWithDiagnosticDataEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP"                     "CdpSessionUserAuthzPolicy"  0
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization"                           "RestrictImplicitInkCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization"                           "RestrictImplicitTextCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"          "HarvestContacts"            0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"                       "AcceptedPrivacyPolicy"      0
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 4 — ACTIVITY / TIMELINE / CLIPBOARD
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Activity History & Clipboard Sync"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed"       0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities"    0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities"     0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" "Disabled" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory"    0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" 0
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 5 — LOCATION
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Location Services"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation"          1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocationScripting" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status"            0
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 6 — APP PERMISSIONS
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "App Permissions (Camera / Mic / Location)"
$ap = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
Set-Reg $ap "LetAppsAccessCamera"      2
Set-Reg $ap "LetAppsAccessMicrophone"  2
Set-Reg $ap "LetAppsAccessLocation"    2
Set-Reg $ap "LetAppsAccessContacts"    2
Set-Reg $ap "LetAppsAccessCalendar"    2
Set-Reg $ap "LetAppsAccessCallHistory" 2
Set-Reg $ap "LetAppsAccessEmail"       2
Set-Reg $ap "LetAppsAccessMessaging"   2
Set-Reg $ap "LetAppsAccessAccountInfo" 2
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 7 — ERROR REPORTING
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Windows Error Reporting"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled"               1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"          "Disabled"               1
Disable-Svc "WerSvc"
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 8 — DELIVERY OPTIMIZATION
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Delivery Optimization"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" 0
Disable-Svc "DoSvc"
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 9 — CONTENT DELIVERY
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Cloud Content & Start Suggestions"
$cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
Set-Reg $cdm "ContentDeliveryAllowed"          0
Set-Reg $cdm "OemPreInstalledAppsEnabled"      0
Set-Reg $cdm "PreInstalledAppsEnabled"         0
Set-Reg $cdm "PreInstalledAppsEverEnabled"     0
Set-Reg $cdm "SilentInstalledAppsEnabled"      0
Set-Reg $cdm "SubscribedContent-338389Enabled" 0
Set-Reg $cdm "SubscribedContent-338388Enabled" 0
Set-Reg $cdm "SubscribedContent-353698Enabled" 0
Set-Reg $cdm "SystemPaneSuggestionsEnabled"    0
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 10 — SCHEDULED TASKS
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Telemetry Scheduled Tasks"
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
    "\Microsoft\Windows\Autochk\Proxy",
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
    "\Microsoft\Windows\Feedback\Siuf\DmClient",
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting",
    "\Microsoft\Windows\Application Experience\MareBackup",
    "\Microsoft\Windows\Application Experience\StartupAppTask",
    "\Microsoft\Windows\Maps\MapsUpdateTask",
    "\Microsoft\Windows\Maps\MapsToastTask"
)
foreach ($task in $tasks) {
    $tPath = (Split-Path $task -Parent) + "\"
    $tName = Split-Path $task -Leaf
    $t = Get-ScheduledTask -TaskPath $tPath -TaskName $tName -ErrorAction SilentlyContinue
    if ($t) { Disable-ScheduledTask -TaskPath $tPath -TaskName $tName | Out-Null; Write-OK "Disabled: $task" }
    else { Write-Skip "Not found: $task" }
}
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 11 — MISC LEAKS (font/tips/LLMNR/WiFi Sense)
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Misc Privacy (Fonts / LLMNR / WiFi Sense)"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"                       "EnableFontProviders"    0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"      "AllowOnlineTips"        0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"                 "EnableMulticast"        0
Set-Reg "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"              "AutoConnectAllowedOEM"  0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"           "fMinimizeConnections"   1
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 12 — FIREWALL RULES
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Firewall — Block Telemetry Binaries"
$blockBins = @(
    "$env:SystemRoot\System32\CompatTelRunner.exe",
    "$env:SystemRoot\System32\DeviceCensus.exe",
    "$env:SystemRoot\System32\wsqmcons.exe",
    "$env:SystemRoot\System32\MusNotification.exe",
    "$env:SystemRoot\System32\MusNotificationUx.exe"
)
foreach ($bin in $blockBins) {
    if (Test-Path $bin) {
        $rule = "Block Telemetry - $(Split-Path $bin -Leaf)"
        if (-not (Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $rule -Direction Outbound -Program $bin -Action Block -Profile Any | Out-Null
            Write-OK "Blocked outbound: $(Split-Path $bin -Leaf)"
        } else { Write-Skip "Rule exists: $rule" }
    } else { Write-Skip "Binary absent: $bin" }
}
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 13 — WINDOWS UPDATE
# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Windows Update"
Write-Host @"

  Choose what to apply:
    [1]  Fetch & install latest Cumulative Update (KB) — no sign-in
    [2]  Defer updates (feature: 365d, quality: 30d)
    [3]  Suppress forced auto-restart while signed in
    [4]  Disable Delivery Optimization bandwidth sharing
    [A]  All of the above
    [S]  Skip

"@ -ForegroundColor DarkCyan
$uc = (Read-Host "  > Choice").Trim().ToUpper()
$doKB=$uc-in@('1','A'); $doDefer=$uc-in@('2','A'); $doAR=$uc-in@('3','A'); $doDO=$uc-in@('4','A')

if ($doKB) {
    Write-OK "Querying Windows Update..."
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $sess.ClientApplicationID = "Microsurf-2.1.0"
        $sr   = $sess.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software' and IsHidden=0 and BrowseOnly=0")
        $cus  = $sr.Updates | Where-Object { $_.Title -match "Cumulative Update for Windows 10" } | Sort-Object LastDeploymentChangeTime -Descending
        if ($cus) {
            $u  = $cus | Select-Object -First 1
            $kb = if ($u.Title -match "(KB\d+)") { $Matches[1] } else { "Unknown KB" }
            Write-OK "$kb — $([math]::Round($u.MaxDownloadSize/1MB,1)) MB — $($u.LastDeploymentChangeTime)"
            $col = New-Object -ComObject Microsoft.Update.UpdateColl; $col.Add($u)|Out-Null
            $dl  = $sess.CreateUpdateDownloader(); $dl.Updates=$col; $dl.Priority=3
            Write-OK "Downloading $kb..."
            $dr = $dl.Download()
            if ($dr.ResultCode -eq 2) {
                Write-OK "$kb staged."
                if (Confirm-Step "Install $kb now?") {
                    $ic = New-Object -ComObject Microsoft.Update.UpdateColl; $ic.Add($u)|Out-Null
                    $ins = $sess.CreateUpdateInstaller(); $ins.Updates=$ic
                    $ir  = $ins.Install()
                    if ($ir.ResultCode -eq 2) { Write-OK "$kb installed." } else { Write-Warn "Install code: $($ir.ResultCode)" }
                }
            } else { Write-Warn "Download code: $($dr.ResultCode)" }
        } else { Write-Skip "No pending cumulative updates." }
    } catch { Write-Err "WUA error: $_" }
}
if ($doDefer) {
    $wp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Set-Reg $wp "DeferFeatureUpdates" 1; Set-Reg $wp "DeferFeatureUpdatesPeriodInDays" 365
    Set-Reg $wp "DeferQualityUpdates" 1; Set-Reg $wp "DeferQualityUpdatesPeriodInDays" 30
    Set-Reg "$wp\AU" "AUOptions" 2; Set-Reg "$wp\AU" "ScheduledInstallDay" 0; Set-Reg "$wp\AU" "ScheduledInstallTime" 3
    Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "ActiveHoursStart" 6
    Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "ActiveHoursEnd" 23
}
if ($doAR) {
    $wp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Set-Reg "$wp\AU" "NoAutoRebootWithLoggedOnUsers" 1
    Set-Reg $wp "SetAutoRestartNotificationConfig" 1; Set-Reg $wp "AutoRestartNotificationSchedule" 4
}
if ($doDO) {
    $dp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    Set-Reg $dp "DODownloadMode" 0; Set-Reg $dp "DOMaxUploadBandwidth" 0; Set-Reg $dp "DOUploadPolicy" 0
    Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" 0
    Disable-Svc "DoSvc"
}
if ($uc -eq 'S') { Write-Skip "Windows Update options skipped." }
Write-Footer


# ═════════════════════════════════════════════════════════════════════════════
# MODULE 14 — DEBLOAT
# ═════════════════════════════════════════════════════════════════════════════
function Remove-UWPApp {
    param([string]$AppId, [string]$Name)
    try {
        $pkg = Get-AppxPackage -Name "*$AppId*" -AllUsers -ErrorAction SilentlyContinue
        if ($pkg) { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop | Out-Null; Write-OK "Removed: $Name" }
        $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.PackageName -like "*$AppId*" }
        if ($prov) { Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null }
    } catch { Write-Skip "Skip: $Name — $_" }
}

Write-Header "Debloat — App Removal"
if (Confirm-Step "Remove pre-installed Microsoft & third-party bloatware?") {
    $bloat = @(
        @{Id="Clipchamp.Clipchamp";Name="Clipchamp"},@{Id="Microsoft.3DBuilder";Name="3D Builder"},
        @{Id="Microsoft.549981C3F5F10";Name="Cortana UWP"},@{Id="Microsoft.BingFinance";Name="Bing Finance"},
        @{Id="Microsoft.BingNews";Name="Bing News"},@{Id="Microsoft.BingSports";Name="Bing Sports"},
        @{Id="Microsoft.BingWeather";Name="Bing Weather"},@{Id="Microsoft.Copilot";Name="Copilot"},
        @{Id="Microsoft.Windows.AIHub";Name="AI Hub"},@{Id="Microsoft.PCManager";Name="PC Manager"},
        @{Id="Microsoft.Getstarted";Name="Get Started"},@{Id="Microsoft.Messaging";Name="Messaging"},
        @{Id="Microsoft.Microsoft3DViewer";Name="3D Viewer"},@{Id="Microsoft.MicrosoftJournal";Name="Journal"},
        @{Id="Microsoft.MicrosoftOfficeHub";Name="Office Hub"},@{Id="Microsoft.MicrosoftSolitaireCollection";Name="Solitaire"},
        @{Id="Microsoft.MicrosoftStickyNotes";Name="Sticky Notes"},@{Id="Microsoft.MixedReality.Portal";Name="Mixed Reality"},
        @{Id="Microsoft.NetworkSpeedTest";Name="Network Speed Test"},@{Id="Microsoft.News";Name="News"},
        @{Id="Microsoft.Office.OneNote";Name="OneNote UWP"},@{Id="Microsoft.Office.Sway";Name="Sway"},
        @{Id="Microsoft.OneConnect";Name="OneConnect"},@{Id="Microsoft.Print3D";Name="Print 3D"},
        @{Id="Microsoft.PowerAutomateDesktop";Name="Power Automate"},@{Id="Microsoft.SkypeApp";Name="Skype UWP"},
        @{Id="Microsoft.Todos";Name="To Do"},@{Id="Microsoft.Windows.DevHome";Name="Dev Home"},
        @{Id="Microsoft.WindowsAlarms";Name="Alarms"},@{Id="Microsoft.WindowsFeedbackHub";Name="Feedback Hub"},
        @{Id="Microsoft.WindowsMaps";Name="Maps"},@{Id="Microsoft.WindowsSoundRecorder";Name="Sound Recorder"},
        @{Id="Microsoft.XboxApp";Name="Xbox Companion"},@{Id="Microsoft.ZuneVideo";Name="Movies & TV"},
        @{Id="MicrosoftCorporationII.MicrosoftFamily";Name="Family Safety"},
        @{Id="MicrosoftCorporationII.QuickAssist";Name="Quick Assist"},
        @{Id="MicrosoftTeams";Name="Teams (Old)"},@{Id="MSTeams";Name="Teams (New)"},
        @{Id="AmazonVideo.PrimeVideo";Name="Prime Video"},@{Id="king.com.CandyCrushSaga";Name="Candy Crush"},
        @{Id="king.com.CandyCrushSodaSaga";Name="Candy Crush Soda"},@{Id="Netflix";Name="Netflix"},
        @{Id="Spotify";Name="Spotify"},@{Id="TikTok";Name="TikTok"},@{Id="Facebook";Name="Facebook"},
        @{Id="Instagram";Name="Instagram"},@{Id="Twitter";Name="Twitter/X"},@{Id="Flipboard";Name="Flipboard"},
        @{Id="WinZipUniversal";Name="WinZip"}
    )
    foreach ($a in $bloat) { Remove-UWPApp -AppId $a.Id -Name $a.Name }
}
if (Confirm-Step "Remove OEM bloatware (HP, Dell, Lenovo)?") {
    $oem = @(
        @{Id="AD2F1837.HPSupportAssistant";Name="HP Support Assistant"},
        @{Id="AD2F1837.HPEasyClean";Name="HP Easy Clean"},
        @{Id="AD2F1837.HPPrivacySettings";Name="HP Privacy Settings"},
        @{Id="AD2F1837.HPQuickDrop";Name="HP QuickDrop"},
        @{Id="AD2F1837.myHP";Name="myHP"},
        @{Id="E046963F.LenovoCompanion";Name="Lenovo Vantage"},
        @{Id="LenovoCompanyLimited.LenovoVantageService";Name="Lenovo Vantage Service"},
        @{Id="DellInc.DellSupportAssistforPCs";Name="Dell SupportAssist"},
        @{Id="DellInc.DellDigitalDelivery";Name="Dell Digital Delivery"},
        @{Id="DellInc.DellMobileConnect";Name="Dell Mobile Connect"}
    )
    foreach ($a in $oem) { Remove-UWPApp -AppId $a.Id -Name $a.Name }
}
if (Confirm-Step "Remove Xbox Game Bar and overlay apps?") {
    @("Microsoft.GamingApp","Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxApp") |
        ForEach-Object { Remove-UWPApp -AppId $_ -Name $_ }
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
    Set-Reg "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0
}
if (Confirm-Step "Remove OneDrive?") {
    $od = if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") { "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" } else { "$env:SystemRoot\System32\OneDriveSetup.exe" }
    if (Test-Path $od) { Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue; Start-Process $od "/uninstall" -Wait }
    Set-Reg "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    Remove-UWPApp -AppId "Microsoft.OneDrive" -Name "OneDrive UWP"
}
Write-Footer

Write-Header "System Tweaks"
if (Confirm-Step "Apply system tweaks (fast startup, mouse accel, sticky keys, storage sense)?") {
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 0
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" "PreventDeviceEncryption" 1
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseSpeed" "0" "String"
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0" "String"
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0" "String"
    Set-Reg "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506" "String"
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" "AllowStorageSenseGlobal" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapAssist" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableSharingWizard" 0
}
if (Confirm-Step "Enable dark mode?") {
    $p = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-Reg $p "AppsUseLightTheme" 0; Set-Reg $p "SystemUsesLightTheme" 0
}
if (Confirm-Step "Disable transparency and animations (better performance)?") {
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3
}
Write-Footer

Write-Header "Taskbar & Start Menu"
if (Confirm-Step "Clean up taskbar and Start menu?") {
    $adv = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-Reg $adv "ShowTaskViewButton" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
    Set-Reg $adv "TaskbarMn" 0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" "ChatIcon" 3
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" "ShellFeedsTaskbarViewMode" 2
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds" 0
    Set-Reg "$adv\TaskbarDeveloperSettings" "TaskbarEndTask" 1
    $cdmPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-Reg $cdmPath "SoftLandingEnabled" 0; Set-Reg $cdmPath "SubscribedContent-338388Enabled" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDynamicSearchBoxEnabled" 0
}
Write-Footer

Write-Header "File Explorer"
if (Confirm-Step "Improve File Explorer (show extensions, hidden files, open to This PC)?") {
    $adv = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-Reg $adv "HideFileExt" 0; Set-Reg $adv "Hidden" 1; Set-Reg $adv "LaunchTo" 1
    $p3D = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    if (Test-Path $p3D) { Remove-Item $p3D -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Footer

Write-Header "Lock Screen & Spotlight"
if (Confirm-Step "Disable lock screen tips and Windows Spotlight?") {
    $cdm = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-Reg $cdm "RotatingLockScreenOverlayEnabled" 0; Set-Reg $cdm "SubscribedContent-338387Enabled" 0
    $cc  = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Set-Reg $cc "DisableWindowsSpotlightFeatures" 1; Set-Reg $cc "DisableWindowsSpotlightOnActionCenter" 1
    Set-Reg $cc "DisableWindowsSpotlightOnSettings" 1; Set-Reg $cc "DisableTailoredExperiencesWithDiagnosticData" 1
}
Write-Footer

Write-Header "Microsoft Edge Ads"
if (Confirm-Step "Disable Edge ads, news feed (MSN), and shopping suggestions?") {
    $ep = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $ep)) { New-Item -Path $ep -Force | Out-Null }
    Set-Reg $ep "NewTabPageContentEnabled" 0; Set-Reg $ep "HubsSidebarEnabled" 0
    Set-Reg $ep "PersonalizationReportingEnabled" 0; Set-Reg $ep "ShowRecommendationsEnabled" 0
    Set-Reg $ep "ShoppingAssistantEnabled" 0; Set-Reg $ep "EdgeShoppingAssistantEnabled" 0
    Set-Reg $ep "WebWidgetAllowed" 0; Set-Reg $ep "StartupBoostEnabled" 0
    Set-Reg $ep "BackgroundModeEnabled" 0
}
Write-Footer

Write-Header "Find My Device"
if (Confirm-Step "Disable Find My Device and location history?") {
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" "AllowFindMyDevice" 0
    Set-Reg "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice"  "LocationSyncEnabled" 0
    Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged" -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Footer

# ── Restart Explorer ──────────────────────────────────────────────────────────
Write-Host "  [*] Restarting Explorer to apply visual changes..." -ForegroundColor Cyan
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Start-Process explorer.exe
Write-OK "Explorer restarted."

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
if ($profile) {
    Write-Host "   Chromebook ($($profile.Label)) drivers installed + privacy hardened." -ForegroundColor Green
} else {
    Write-Host "   Privacy hardening complete." -ForegroundColor Green
}
Write-Host "   Reboot recommended." -ForegroundColor Green
Write-Host "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
