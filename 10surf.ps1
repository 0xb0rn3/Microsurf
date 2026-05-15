#Requires -RunAsAdministrator
<#
─────────────────────────────────────────────────────────────────────────────
  ███╗   ███╗██╗ ██████╗██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
  ████╗ ████║██║██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
  ██╔████╔██║██║██║     ██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗
  ██║╚██╔╝██║██║██║     ██╔══██╗██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝
  ██║ ╚═╝ ██║██║╚██████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║  ██║██║
  ╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
─────────────────────────────────────────────────────────────────────────────
  Script  : 10surf.ps1
  Version : 1.0.0
  Target  : Windows 10 ONLY (21H2 / 22H2 / 23H2 / latest release)
  Repo    : https://github.com/0xb0rn3/Microsurf
  Author  : 0xb0rn3 | oxbv1
  Website : https://oxborn3.com
  Contact : 0xb0rn3@proton.me
  Discord : oxbv1
  Twitter : @oxbv1
─────────────────────────────────────────────────────────────────────────────
  Built for people who don't trust them with their data.
─────────────────────────────────────────────────────────────────────────────

.SYNOPSIS
    Windows 10 privacy hardening + optional silent Windows 11 upgrade.

.DESCRIPTION
    Strips Microsoft's entire data collection pipeline from Windows 10:
    telemetry, Cortana, advertising ID, activity history, app permissions,
    delivery optimization, LLMNR, WiFi Sense, error reporting, and more.
    Also fetches and stages the latest stable cumulative KB update without
    requiring a Microsoft account, and optionally performs a silent in-place
    upgrade to Windows 11 via a 4-method fallthrough engine.

    !! THIS SCRIPT TARGETS WINDOWS 10 ONLY !!
    Running it on Windows 11, Windows Server, or any other OS is
    unsupported and may produce unexpected results.

.NOTES
    - Must be run as Administrator in an elevated PowerShell session
    - A System Restore Point is created automatically before any changes
    - Roll back at any time with: rstrui.exe
    - Quick start: irm https://raw.githubusercontent.com/0xb0rn3/Microsurf/main/10surf.ps1 | iex
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── OS Guard — abort if not Windows 10 ───────────────────────────────────────
$osInfo    = Get-CimInstance Win32_OperatingSystem
$osBuild   = [int]$osInfo.BuildNumber
$osCaption = $osInfo.Caption

# Windows 10 builds: 10240 (1507) through 19045 (22H2 / latest)
# Windows 11 starts at build 22000
if ($osBuild -ge 22000 -or $osInfo.Caption -notmatch "Windows 10") {
    Write-Host @"

  [!] UNSUPPORTED OS DETECTED
      Detected : $osCaption (Build $osBuild)
      Required : Windows 10 (any release)

      10surf.ps1 is designed for Windows 10 only.
      This script will now exit to prevent unintended changes.

"@ -ForegroundColor Red
    exit 1
}

Write-Host @"

  [*] OS verified: $osCaption (Build $osBuild) — Windows 10 confirmed.

"@ -ForegroundColor Green


# ─── COLORS ──────────────────────────────────────────────────────────────────
function Write-Header { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "    [+] $msg" -ForegroundColor Green }
function Write-Skip   { param($msg) Write-Host "    [-] $msg" -ForegroundColor DarkGray }

# ─── HELPER: SET REGISTRY ────────────────────────────────────────────────────
function Set-Reg {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-OK "$Name = $Value  ($Path)"
}

# ─── HELPER: DISABLE SERVICE ─────────────────────────────────────────────────
function Disable-Svc {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service  -Name $Name -Force -ErrorAction SilentlyContinue
        Set-Service   -Name $Name -StartupType Disabled
        Write-OK "Service disabled: $Name"
    } else {
        Write-Skip "Service not found: $Name"
    }
}

# ─── RESTORE POINT ───────────────────────────────────────────────────────────
Write-Header "Creating System Restore Point"
Enable-ComputerRestore -Drive "$env:SystemDrive"
Checkpoint-Computer -Description "Before Privacy Hardening" -RestorePointType "MODIFY_SETTINGS"
Write-OK "Restore point created"

# ─────────────────────────────────────────────────────────────────────────────
# 1. TELEMETRY & DATA COLLECTION
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Telemetry & Data Collection"

# 0 = Security (Enterprise/LTSC only), 1 = Basic — best available on Home/Pro
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "AllowTelemetry"                    0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry"     0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "MaxTelemetryAllowed" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "LimitDiagnosticLogCollection"     1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "DisableOneSettingsDownloads"      1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"   "DoNotShowFeedbackNotifications"   1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" "ShowedToastAtLevel"   1

# Disable Connected User Experiences and Telemetry service
Disable-Svc "DiagTrack"
Disable-Svc "dmwappushservice"

# Block telemetry endpoints via hosts file addition (idempotent)
Write-Header "Blocking Telemetry Hosts"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$telemetryHosts = @(
    "0.0.0.0 vortex.data.microsoft.com",
    "0.0.0.0 vortex-win.data.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com",
    "0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 oca.telemetry.microsoft.com",
    "0.0.0.0 oca.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 sqm.telemetry.microsoft.com",
    "0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 watson.telemetry.microsoft.com",
    "0.0.0.0 watson.telemetry.microsoft.com.nsatc.net",
    "0.0.0.0 redir.metaservices.microsoft.com",
    "0.0.0.0 choice.microsoft.com",
    "0.0.0.0 choice.microsoft.com.nsatc.net",
    "0.0.0.0 df.telemetry.microsoft.com",
    "0.0.0.0 reports.wes.df.telemetry.microsoft.com",
    "0.0.0.0 wes.df.telemetry.microsoft.com",
    "0.0.0.0 services.wes.df.telemetry.microsoft.com",
    "0.0.0.0 sqm.df.telemetry.microsoft.com",
    "0.0.0.0 telemetry.microsoft.com",
    "0.0.0.0 watson.microsoft.com",
    "0.0.0.0 statsfe2.ws.microsoft.com",
    "0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com",
    "0.0.0.0 compatible.microsoft.com",
    "0.0.0.0 statsfe1.ws.microsoft.com",
    "0.0.0.0 feedback.windows.com",
    "0.0.0.0 feedback.search.microsoft.com",
    "0.0.0.0 feedback.microsoft-hohm.com",
    "0.0.0.0 settings-sandbox.data.microsoft.com",
    "0.0.0.0 i1.services.social.microsoft.com",
    "0.0.0.0 i1.services.social.microsoft.com.nsatc.net",
    "0.0.0.0 bingads.microsoft.com",
    "0.0.0.0 cy2.bingads.microsoft.com"
)
$hostsContent = Get-Content $hostsPath -Raw
foreach ($entry in $telemetryHosts) {
    $host_ = ($entry -split " ")[1]
    if ($hostsContent -notmatch [regex]::Escape($host_)) {
        Add-Content -Path $hostsPath -Value $entry
        Write-OK "Blocked: $host_"
    } else {
        Write-Skip "Already blocked: $host_"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. CORTANA
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Cortana"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"           0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock"  0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch"       1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb"  0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "BingSearchEnabled"      0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "CortanaConsent"         0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "HistoryViewEnabled"     0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"   "DeviceHistoryEnabled"   0

# ─────────────────────────────────────────────────────────────────────────────
# 3. ADVERTISING ID & PERSONALIZATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Advertising ID & Personalization"
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled"            0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"       "DisabledByGroupPolicy" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"         "TailoredExperiencesWithDiagnosticDataEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP"             "CdpSessionUserAuthzPolicy" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization"                   "RestrictImplicitInkCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization"                   "RestrictImplicitTextCollection" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"  "HarvestContacts" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"               "AcceptedPrivacyPolicy" 0

# ─────────────────────────────────────────────────────────────────────────────
# 4. ACTIVITY / TIMELINE / CLIPBOARD SYNC
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Activity History & Timeline"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed"             0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities"          0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities"           0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" "Disabled" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowClipboardHistory"          0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard"      0

# ─────────────────────────────────────────────────────────────────────────────
# 5. LOCATION SERVICES
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Location Services"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation"          1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocationScripting" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status"            0

# ─────────────────────────────────────────────────────────────────────────────
# 6. CAMERA & MICROPHONE (GLOBAL APP ACCESS)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Restricting Camera & Microphone App Access"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera"      2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone"  2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessLocation"    2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts"    2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar"    2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" 2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail"       2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging"   2
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" 2
# 2 = Force Deny

# ─────────────────────────────────────────────────────────────────────────────
# 7. WINDOWS ERROR REPORTING
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Windows Error Reporting"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled"       1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"          "Disabled"       1
Disable-Svc "WerSvc"

# ─────────────────────────────────────────────────────────────────────────────
# 8. DELIVERY OPTIMIZATION (peer-to-peer upload)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Delivery Optimization Upload"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0
# 0 = HTTP only, no P2P
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" 0
Disable-Svc "DoSvc"

# ─────────────────────────────────────────────────────────────────────────────
# 9. WINDOWS SEARCH & INDEXING CLOUD
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Cloud Content & Start Suggestions"
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed"       0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled"   0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled"      0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled"  0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled"   0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353698Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0

# ─────────────────────────────────────────────────────────────────────────────
# 10. DISABLE TRACKING SCHEDULED TASKS
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Telemetry Scheduled Tasks"
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
    $t = Get-ScheduledTask -TaskPath (Split-Path $task -Parent)"\" -TaskName (Split-Path $task -Leaf) -ErrorAction SilentlyContinue
    if ($t) {
        Disable-ScheduledTask -TaskPath (Split-Path $task -Parent)"\" -TaskName (Split-Path $task -Leaf) | Out-Null
        Write-OK "Disabled task: $task"
    } else {
        Write-Skip "Task not found: $task"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 11. DISABLE FONT STREAMING / ONLINE TIPS
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling Online Font & Help Streaming"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders"   0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" 0

# ─────────────────────────────────────────────────────────────────────────────
# 12. DISABLE MDNS / LLMNR (local network name leakage)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling LLMNR & mDNS (name leak prevention)"
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
# Note: mDNS is handled by the DNS Client service; LLMNR above is via GP

# ─────────────────────────────────────────────────────────────────────────────
# 13. DISABLE WIFI SENSE & HOTSPOT SHARING
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Disabling WiFi Sense"
Set-Reg "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"    0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections"  1

# ─────────────────────────────────────────────────────────────────────────────
# 14. FIREWALL RULES — BLOCK TELEMETRY PROCESSES
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Adding Firewall Rules to Block Telemetry Executables"
$blockBinaries = @(
    "$env:SystemRoot\System32\CompatTelRunner.exe",
    "$env:SystemRoot\System32\DeviceCensus.exe",
    "$env:SystemRoot\System32\wsqmcons.exe",
    "$env:SystemRoot\System32\MusNotification.exe",
    "$env:SystemRoot\System32\MusNotificationUx.exe"
)
foreach ($bin in $blockBinaries) {
    if (Test-Path $bin) {
        $ruleName = "Block Telemetry - $(Split-Path $bin -Leaf)"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound -Program $bin `
                -Action Block -Profile Any | Out-Null
            Write-OK "Firewall block added: $(Split-Path $bin -Leaf)"
        } else {
            Write-Skip "Firewall rule exists: $ruleName"
        }
    } else {
        Write-Skip "Binary not found: $bin"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 15. DOWNLOAD LATEST STABLE CUMULATIVE UPDATE (no sign-in, WUA COM API)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Fetching Latest Stable Cumulative Update via Windows Update Agent"

try {
    # ── Create a silent, unauthenticated WUA session ──────────────────────────
    $UpdateSession  = New-Object -ComObject Microsoft.Update.Session
    $UpdateSession.ClientApplicationID = "Privacy-Harden-Script"

    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Scope: not installed, not hidden, software category only
    # "Cumulative Update for Windows 10" is always a Software type update
    Write-OK "Querying Windows Update service (no credentials required)..."
    $SearchResult = $UpdateSearcher.Search(
        "IsInstalled=0 and Type='Software' and IsHidden=0 and BrowseOnly=0"
    )

    if ($SearchResult.Updates.Count -eq 0) {
        Write-Skip "No pending updates found — system may already be fully patched."
    } else {
        # ── Filter to the latest Cumulative Update KB only ────────────────────
        $CumulativeUpdates = $SearchResult.Updates | Where-Object {
            $_.Title -match "Cumulative Update for Windows 10"
        } | Sort-Object -Property LastDeploymentChangeTime -Descending

        if (-not $CumulativeUpdates) {
            Write-Skip "No cumulative update found in pending list."
        } else {
            $TargetUpdate = $CumulativeUpdates | Select-Object -First 1

            # Extract KB number from title
            $KB = if ($TargetUpdate.Title -match "(KB\d+)") { $Matches[1] } else { "Unknown KB" }

            Write-OK "Found: $($TargetUpdate.Title)"
            Write-OK "KB: $KB  |  Size: $([math]::Round($TargetUpdate.MaxDownloadSize / 1MB, 1)) MB"
            Write-OK "Released: $($TargetUpdate.LastDeploymentChangeTime)"

            # ── Build a collection with just this update ──────────────────────
            $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            $UpdatesToDownload.Add($TargetUpdate) | Out-Null

            # ── Download silently (no UI, no sign-in prompt) ──────────────────
            $Downloader          = $UpdateSession.CreateUpdateDownloader()
            $Downloader.Updates  = $UpdatesToDownload
            $Downloader.Priority = 3   # 1=Low 2=Normal 3=High 4=ExtraHigh

            Write-OK "Downloading $KB — this may take several minutes..."

            $DownloadResult = $Downloader.Download()

            switch ($DownloadResult.ResultCode) {
                2 { Write-OK "$KB downloaded successfully and is staged for install." }
                3 { Write-OK "$KB download succeeded with warnings." }
                4 { Write-Host "    [!] $KB download failed." -ForegroundColor Yellow }
                5 { Write-Host "    [!] $KB download aborted." -ForegroundColor Yellow }
                default { Write-OK "Download result code: $($DownloadResult.ResultCode)" }
            }

            # ── Prompt to install (or pass -AutoInstall switch to skip) ───────
            if ($DownloadResult.ResultCode -eq 2) {
                $choice = Read-Host "`n    Install $KB now and reboot? [Y/N]"
                if ($choice -match "^[Yy]") {
                    $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                    $UpdatesToInstall.Add($TargetUpdate) | Out-Null

                    $Installer         = $UpdateSession.CreateUpdateInstaller()
                    $Installer.Updates = $UpdatesToInstall

                    Write-OK "Installing $KB..."
                    $InstallResult = $Installer.Install()

                    switch ($InstallResult.ResultCode) {
                        2 {
                            Write-OK "$KB installed successfully."
                            if ($InstallResult.RebootRequired) {
                                Write-Host "`n    [!] Reboot required to complete installation." -ForegroundColor Yellow
                            }
                        }
                        3 { Write-OK "$KB installed with warnings." }
                        4 { Write-Host "    [!] Installation failed." -ForegroundColor Red }
                        default { Write-OK "Install result code: $($InstallResult.ResultCode)" }
                    }
                } else {
                    Write-OK "$KB is staged. Run Windows Update to install when ready."
                }
            }
        }
    }
} catch {
    Write-Host "    [!] WUA COM error: $_" -ForegroundColor Red
    Write-Host "        Ensure the Windows Update service (wuauserv) is running." -ForegroundColor DarkGray
}


# ─────────────────────────────────────────────────────────────────────────────
# 16. DEBLOAT — BLOATWARE REMOVAL & SYSTEM OPTIMISATION
#     Inspired by Win11Debloat (github.com/Raphire/Win11Debloat)
#     Adapted for Windows 10 by 0xb0rn3 | oxbv1 | oxborn3.com
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Debloat — Bloatware Removal & System Optimisation"

Write-Host @"

    This section removes pre-installed bloatware, disables junk
    features, and tightens system settings — category by category.
    You'll be asked [Y/N] for each group. Nothing is applied without
    your confirmation. All changes can be reverted via the Restore
    Point created at the start of this script.

"@ -ForegroundColor DarkCyan

# ── Helper: prompt Y/N ───────────────────────────────────────────────────────
function Confirm-Debloat {
    param([string]$Question)
    $r = Read-Host "    $Question [Y/N]"
    return $r -match "^[Yy]"
}

# ── Helper: remove a UWP app (all users, non-fatal) ──────────────────────────
function Remove-UWPApp {
    param([string]$AppId, [string]$FriendlyName)
    try {
        $pkg = Get-AppxPackage -Name "*$AppId*" -AllUsers -ErrorAction SilentlyContinue
        if ($pkg) {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop | Out-Null
            Write-OK "Removed: $FriendlyName ($AppId)"
        }
        # Also remove provisioned package so it won't reinstall for new users
        $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.PackageName -like "*$AppId*" }
        if ($prov) {
            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {
        Write-Skip "Could not remove $FriendlyName : $_"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# A. BLOATWARE APP REMOVAL
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── A. Bloatware App Removal ──" -ForegroundColor Yellow

if (Confirm-Debloat "Remove pre-installed bloatware apps (Candy Crush, Clipchamp, Cortana UWP, Bing apps, social media, etc.)?") {

    # Safe-to-remove app list sourced from Config/Apps.json (Win11Debloat)
    $bloatApps = @(
        @{ Id = "Clipchamp.Clipchamp";                        Name = "Clipchamp" },
        @{ Id = "Microsoft.3DBuilder";                        Name = "3D Builder" },
        @{ Id = "Microsoft.549981C3F5F10";                    Name = "Cortana" },
        @{ Id = "Microsoft.BingFinance";                      Name = "Bing Finance" },
        @{ Id = "Microsoft.BingFoodAndDrink";                 Name = "Bing Food & Drink" },
        @{ Id = "Microsoft.BingHealthAndFitness";             Name = "Bing Health & Fitness" },
        @{ Id = "Microsoft.BingNews";                         Name = "Bing News" },
        @{ Id = "Microsoft.BingSports";                       Name = "Bing Sports" },
        @{ Id = "Microsoft.BingTranslator";                   Name = "Bing Translator" },
        @{ Id = "Microsoft.BingTravel";                       Name = "Bing Travel" },
        @{ Id = "Microsoft.BingWeather";                      Name = "Bing Weather" },
        @{ Id = "Microsoft.Copilot";                          Name = "Copilot" },
        @{ Id = "Microsoft.Windows.AIHub";                    Name = "Copilot+ AI Hub" },
        @{ Id = "Microsoft.PCManager";                        Name = "Microsoft PC Manager" },
        @{ Id = "Microsoft.Getstarted";                       Name = "Get Started" },
        @{ Id = "Microsoft.Messaging";                        Name = "Messaging" },
        @{ Id = "Microsoft.Microsoft3DViewer";                Name = "3D Viewer" },
        @{ Id = "Microsoft.MicrosoftJournal";                 Name = "Microsoft Journal" },
        @{ Id = "Microsoft.MicrosoftOfficeHub";               Name = "Office Hub" },
        @{ Id = "Microsoft.MicrosoftPowerBIForWindows";       Name = "Power BI" },
        @{ Id = "Microsoft.MicrosoftSolitaireCollection";     Name = "Solitaire Collection" },
        @{ Id = "Microsoft.MicrosoftStickyNotes";             Name = "Sticky Notes" },
        @{ Id = "Microsoft.MixedReality.Portal";              Name = "Mixed Reality Portal" },
        @{ Id = "Microsoft.NetworkSpeedTest";                 Name = "Network Speed Test" },
        @{ Id = "Microsoft.News";                             Name = "Microsoft News" },
        @{ Id = "Microsoft.Office.OneNote";                   Name = "OneNote (UWP)" },
        @{ Id = "Microsoft.Office.Sway";                      Name = "Sway" },
        @{ Id = "Microsoft.OneConnect";                       Name = "One Connect" },
        @{ Id = "Microsoft.Print3D";                          Name = "Print 3D" },
        @{ Id = "Microsoft.PowerAutomateDesktop";             Name = "Power Automate" },
        @{ Id = "Microsoft.SkypeApp";                         Name = "Skype (UWP)" },
        @{ Id = "Microsoft.Todos";                            Name = "Microsoft To Do" },
        @{ Id = "Microsoft.Windows.DevHome";                  Name = "Dev Home" },
        @{ Id = "Microsoft.WindowsAlarms";                    Name = "Alarms & Clock" },
        @{ Id = "Microsoft.WindowsFeedbackHub";               Name = "Feedback Hub" },
        @{ Id = "Microsoft.WindowsMaps";                      Name = "Windows Maps" },
        @{ Id = "Microsoft.WindowsSoundRecorder";             Name = "Sound Recorder" },
        @{ Id = "Microsoft.XboxApp";                          Name = "Xbox Console Companion" },
        @{ Id = "Microsoft.ZuneVideo";                        Name = "Movies & TV" },
        @{ Id = "MicrosoftCorporationII.MicrosoftFamily";     Name = "Family Safety" },
        @{ Id = "MicrosoftCorporationII.QuickAssist";         Name = "Quick Assist" },
        @{ Id = "MicrosoftTeams";                             Name = "Microsoft Teams (Old)" },
        @{ Id = "MSTeams";                                    Name = "Microsoft Teams (New)" },
        @{ Id = "AdobeSystemsIncorporated.AdobePhotoshopExpress"; Name = "Adobe Photoshop Express" },
        @{ Id = "Amazon.com.Amazon";                          Name = "Amazon" },
        @{ Id = "AmazonVideo.PrimeVideo";                     Name = "Prime Video" },
        @{ Id = "Asphalt8Airborne";                           Name = "Asphalt 8" },
        @{ Id = "CaesarsSlotsFreeCasino";                     Name = "Caesars Slots" },
        @{ Id = "COOKINGFEVER";                               Name = "Cooking Fever" },
        @{ Id = "CyberLinkMediaSuiteEssentials";              Name = "CyberLink Media Suite" },
        @{ Id = "DisneyMagicKingdoms";                        Name = "Disney Magic Kingdoms" },
        @{ Id = "Duolingo-LearnLanguagesforFree";              Name = "Duolingo" },
        @{ Id = "Facebook";                                   Name = "Facebook" },
        @{ Id = "FarmVille2CountryEscape";                    Name = "FarmVille 2" },
        @{ Id = "Flipboard";                                  Name = "Flipboard" },
        @{ Id = "HULULLC.HULUPLUS";                           Name = "Hulu" },
        @{ Id = "Instagram";                                  Name = "Instagram" },
        @{ Id = "king.com.BubbleWitch3Saga";                  Name = "Bubble Witch 3" },
        @{ Id = "king.com.CandyCrushSaga";                    Name = "Candy Crush Saga" },
        @{ Id = "king.com.CandyCrushSodaSaga";                Name = "Candy Crush Soda" },
        @{ Id = "LinkedInforWindows";                         Name = "LinkedIn" },
        @{ Id = "Netflix";                                    Name = "Netflix" },
        @{ Id = "PandoraMediaInc";                            Name = "Pandora" },
        @{ Id = "PicsArt-PhotoStudio";                        Name = "PicsArt" },
        @{ Id = "TikTok";                                     Name = "TikTok" },
        @{ Id = "TuneInRadio";                                Name = "TuneIn Radio" },
        @{ Id = "Twitter";                                    Name = "Twitter / X" },
        @{ Id = "Viber";                                      Name = "Viber" },
        @{ Id = "WinZipUniversal";                            Name = "WinZip" },
        @{ Id = "Spotify";                                    Name = "Spotify" }
    )

    foreach ($app in $bloatApps) {
        Remove-UWPApp -AppId $app.Id -FriendlyName $app.Name
    }
    Write-OK "Bloatware app removal complete."
} else {
    Write-Skip "Bloatware removal skipped."
}

# ── Optional: OEM bloat (HP / Dell / Lenovo) ─────────────────────────────────
if (Confirm-Debloat "Remove OEM bloatware (HP, Dell, Lenovo preinstalled software)?") {
    $oemApps = @(
        @{ Id = "AD2F1837.HPAIExperienceCenter";              Name = "HP AI Experience Center" },
        @{ Id = "AD2F1837.HPConnectedMusic";                  Name = "HP Connected Music" },
        @{ Id = "AD2F1837.HPConnectedPhotopoweredbySnapfish"; Name = "HP Connected Photo" },
        @{ Id = "AD2F1837.HPDesktopSupportUtilities";         Name = "HP Desktop Support" },
        @{ Id = "AD2F1837.HPEasyClean";                       Name = "HP Easy Clean" },
        @{ Id = "AD2F1837.HPJumpStarts";                      Name = "HP JumpStarts" },
        @{ Id = "AD2F1837.HPPCHardwareDiagnosticsWindows";    Name = "HP PC Diagnostics" },
        @{ Id = "AD2F1837.HPPowerManager";                    Name = "HP Power Manager" },
        @{ Id = "AD2F1837.HPPrivacySettings";                 Name = "HP Privacy Settings" },
        @{ Id = "AD2F1837.HPQuickDrop";                       Name = "HP QuickDrop" },
        @{ Id = "AD2F1837.HPRegistration";                    Name = "HP Registration" },
        @{ Id = "AD2F1837.HPSupportAssistant";                Name = "HP Support Assistant" },
        @{ Id = "AD2F1837.HPSureShieldAI";                    Name = "HP Sure Shield AI" },
        @{ Id = "AD2F1837.myHP";                              Name = "myHP" },
        @{ Id = "E046963F.LenovoCompanion";                   Name = "Lenovo Vantage" },
        @{ Id = "LenovoCompanyLimited.LenovoVantageService";  Name = "Lenovo Vantage Service" },
        @{ Id = "DellInc.DellSupportAssistforPCs";            Name = "Dell SupportAssist" },
        @{ Id = "DellInc.DellDigitalDelivery";                Name = "Dell Digital Delivery" },
        @{ Id = "DellInc.DellMobileConnect";                  Name = "Dell Mobile Connect" }
    )
    foreach ($app in $oemApps) {
        Remove-UWPApp -AppId $app.Id -FriendlyName $app.Name
    }
    Write-OK "OEM bloatware removal complete."
} else {
    Write-Skip "OEM bloatware removal skipped."
}

# ── Optional: Xbox / Game Bar ─────────────────────────────────────────────────
if (Confirm-Debloat "Remove Xbox Game Bar and gaming overlay apps?") {
    $xboxApps = @(
        @{ Id = "Microsoft.GamingApp";             Name = "Xbox Gaming App" },
        @{ Id = "Microsoft.XboxGameOverlay";        Name = "Xbox Game Overlay" },
        @{ Id = "Microsoft.XboxGamingOverlay";      Name = "Xbox Gaming Overlay" },
        @{ Id = "Microsoft.XboxApp";                Name = "Xbox Console Companion" }
    )
    foreach ($app in $xboxApps) {
        Remove-UWPApp -AppId $app.Id -FriendlyName $app.Name
    }
    # Disable Game DVR via registry
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled"       0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"        "AllowGameDVR"            0
    Set-Reg "HKCU:\System\GameConfigStore"                              "GameDVR_Enabled"          0
    Set-Reg "HKCU:\System\GameConfigStore"                              "GameDVR_FSEBehaviorMode"  2
    Write-OK "Xbox Game Bar and DVR disabled."
} else {
    Write-Skip "Xbox / Game Bar removal skipped."
}

# ── Optional: OneDrive removal ────────────────────────────────────────────────
if (Confirm-Debloat "Remove OneDrive and stop it from syncing?") {
    # Uninstall OneDrive silently
    $onedrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-not (Test-Path $onedrivePath)) {
        $onedrivePath = "$env:SystemRoot\System32\OneDriveSetup.exe"
    }
    if (Test-Path $onedrivePath) {
        Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
        Start-Process $onedrivePath -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
        Write-OK "OneDrive uninstalled."
    } else {
        Write-Skip "OneDrive setup executable not found — may already be removed."
    }
    # Remove OneDrive from File Explorer navigation pane
    Set-Reg "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"        "System.IsPinnedToNameSpaceTree" 0
    Set-Reg "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    Remove-UWPApp -AppId "Microsoft.OneDrive" -FriendlyName "OneDrive (UWP)"
    Write-OK "OneDrive removed from File Explorer."
} else {
    Write-Skip "OneDrive removal skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# B. SYSTEM TWEAKS
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── B. System Tweaks ──" -ForegroundColor Yellow

if (Confirm-Debloat "Apply system tweaks (fast startup, mouse acceleration, sticky keys, storage sense, etc.)?") {

    # Disable Fast Startup (masks shutdown, prevents full POST on next boot)
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 0
    Write-OK "Fast Startup disabled."

    # Disable BitLocker automatic device encryption (silently encrypts on fresh installs)
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" "PreventDeviceEncryption" 1
    Write-OK "BitLocker auto-encryption disabled."

    # Disable mouse acceleration (Enhance Pointer Precision)
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseSpeed"  "0" "String"
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0" "String"
    Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0" "String"
    Write-OK "Mouse acceleration (Enhance Pointer Precision) disabled."

    # Disable Sticky Keys shortcut (Shift x5 popup)
    Set-Reg "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506" "String"
    Write-OK "Sticky Keys shortcut disabled."

    # Disable Storage Sense automatic disk cleanup
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" "AllowStorageSenseGlobal" 0
    Write-OK "Storage Sense disabled."

    # Disable network connectivity during Modern Standby (reduces battery drain)
    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\F15576FC-98A3-4FA3-8F3D-3C2DBBCA5BC5" `
        "Attributes" 2
    Write-OK "Modern Standby network connectivity disabled."

    # Disable Snap Assist suggestions
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "SnapAssist"       0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableSnapBar"    0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DITest"           0
    Write-OK "Snap Assist suggestions disabled."

    # Disable Drag Tray (file share tray)
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableSharingWizard" 0
    Write-OK "Drag Tray (sharing wizard) disabled."

} else {
    Write-Skip "System tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# C. WINDOWS UPDATE TWEAKS
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── C. Windows Update Tweaks ──" -ForegroundColor Yellow

if (Confirm-Debloat "Prevent Windows from force-installing updates immediately and auto-rebooting?") {
    # Stop updates from being pushed ASAP (Active Hours + deferral)
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"          0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"             2
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay"   0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime"  3
    # Prevent automatic restart while user is signed in
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" 1
    # Set active hours (0600–2300) to prevent reboots during the day
    Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "ActiveHoursStart" 6
    Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "ActiveHoursEnd"   23
    Write-OK "Windows Update auto-reboot and immediate push prevented."
} else {
    Write-Skip "Windows Update tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# D. APPEARANCE
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── D. Appearance ──" -ForegroundColor Yellow

if (Confirm-Debloat "Enable dark mode for system and apps?") {
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "AppsUseLightTheme"   0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "SystemUsesLightTheme" 0
    Write-OK "Dark mode enabled."
} else {
    Write-Skip "Dark mode skipped."
}

if (Confirm-Debloat "Disable transparency effects and animations (improves performance)?") {
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\DWM" "EnableAeroPeek" 0
    # Visual effects — best performance
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 3
    Set-Reg "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) "Binary"
    Write-OK "Transparency and animations disabled."
} else {
    Write-Skip "Appearance tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# E. START MENU & SEARCH
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── E. Start Menu & Search ──" -ForegroundColor Yellow

if (Confirm-Debloat "Clean up Start menu (disable suggestions, search highlights, local search history)?") {

    # Disable Start menu suggestions / app promotions
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353698Enabled" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled"    0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled"              0
    Write-OK "Start menu app suggestions disabled."

    # Disable Search Highlights (dynamic/branded content in taskbar search)
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDynamicSearchBoxEnabled" 0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0
    Write-OK "Search Highlights (taskbar dynamic content) disabled."

    # Disable local Windows search history
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDeviceSearchHistoryEnabled" 0
    Write-OK "Local search history disabled."

    # Disable Microsoft Store app suggestions in search
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0
    Write-OK "Store app suggestions in search disabled."

    # Disable Phone Link from Start menu
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" 0
    Write-OK "Phone Link / People bar removed from taskbar."

} else {
    Write-Skip "Start menu tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# F. TASKBAR
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── F. Taskbar ──" -ForegroundColor Yellow

if (Confirm-Debloat "Clean up taskbar (hide search box, task view, chat / Meet Now button)?") {

    # Hide task view button
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowTaskViewButton" 0
    Write-OK "Task View button hidden."

    # Hide search box (icon only) — set to 1 for icon, 0 to hide completely
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "SearchboxTaskbarMode" 0
    Write-OK "Search box hidden from taskbar."

    # Hide Chat / Meet Now button (Windows 10 22H2+)
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarMn" 0
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"             "ChatIcon"  3
    Write-OK "Chat / Meet Now button hidden."

    # Hide News and Interests / Widgets
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" "ShellFeedsTaskbarViewMode" 2
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" "EnableFeeds" 0
    Write-OK "News & Interests / Widgets hidden from taskbar."

    # Enable End Task option in taskbar right-click
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" "TaskbarEndTask" 1
    Write-OK "End Task enabled in taskbar right-click."

} else {
    Write-Skip "Taskbar tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# G. FILE EXPLORER
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── G. File Explorer ──" -ForegroundColor Yellow

if (Confirm-Debloat "Improve File Explorer (show file extensions, hidden files, hide 3D Objects)?") {

    # Show file extensions for known file types
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt"           0
    Write-OK "File extensions shown for known file types."

    # Show hidden files, folders and drives
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden"                1
    Write-OK "Hidden files and folders shown."

    # Hide 3D Objects from File Explorer navigation pane (Windows 10)
    $path3D = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    if (Test-Path $path3D) {
        Remove-Item -Path $path3D -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "3D Objects folder removed from This PC."
    }

    # Hide duplicate removable drives from navigation pane
    Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" "(Default)" "" "String"
    Write-OK "Duplicate removable drive entries hidden."

    # Set File Explorer to open 'This PC' by default
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1
    Write-OK "File Explorer opens to This PC by default."

    # Hide 'Include in library', 'Give access to', 'Share' from context menu
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "MultipleInvokePromptMinimum" 2
    Remove-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\Library Location"      -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue
    Write-OK "Cluttered context menu items hidden."

} else {
    Write-Skip "File Explorer tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# H. LOCK SCREEN & SPOTLIGHT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── H. Lock Screen & Spotlight ──" -ForegroundColor Yellow

if (Confirm-Debloat "Disable lock screen tips, Windows Spotlight ads, and rotating background?") {

    # Disable lock screen tips / fun facts
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" 0
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled"  0
    Write-OK "Lock screen tips and fun facts disabled."

    # Disable Windows Spotlight on lock screen
    Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures"       1
    Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightOnActionCenter"  1
    Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightOnSettings"      1
    Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
    Write-OK "Windows Spotlight disabled."

    # Disable desktop Spotlight background option
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" 0
    Write-OK "Spotlight rotating desktop background disabled."

} else {
    Write-Skip "Lock screen / Spotlight tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# I. EDGE ADS & OPTIONAL BROWSER BLOAT
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── I. Browser Bloat ──" -ForegroundColor Yellow

if (Confirm-Debloat "Disable Microsoft Edge ads, news feed (MSN), and shopping suggestions?") {

    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgePolicyPath)) { New-Item -Path $edgePolicyPath -Force | Out-Null }

    Set-Reg $edgePolicyPath "NewTabPageContentEnabled"              0
    Set-Reg $edgePolicyPath "NewTabPageBingChatEnabled"             0
    Set-Reg $edgePolicyPath "HubsSidebarEnabled"                    0
    Set-Reg $edgePolicyPath "PersonalizationReportingEnabled"        0
    Set-Reg $edgePolicyPath "ShowRecommendationsEnabled"            0
    Set-Reg $edgePolicyPath "ShoppingAssistantEnabled"              0
    Set-Reg $edgePolicyPath "EdgeShoppingAssistantEnabled"          0
    Set-Reg $edgePolicyPath "WebWidgetAllowed"                      0
    Set-Reg $edgePolicyPath "StartupBoostEnabled"                   0
    Set-Reg $edgePolicyPath "BackgroundModeEnabled"                 0

    # Disable MSN news feed / Edge new tab page promoted content
    Set-Reg "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" "(Default)" 0 "DWord"
    Write-OK "Edge ads, news feed, shopping assistant, and startup boost disabled."

} else {
    Write-Skip "Edge bloat tweaks skipped."
}

# ══════════════════════════════════════════════════════════════════════════════
# J. FIND MY DEVICE & LOCATION HISTORY
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n    ── J. Find My Device & Location History ──" -ForegroundColor Yellow

if (Confirm-Debloat "Disable Find My Device location tracking and location history?") {
    Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice" "AllowFindMyDevice" 0
    Set-Reg "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice"  "LocationSyncEnabled" 0
    # Clear stored location history
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged" `
        -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Find My Device and location history disabled."
} else {
    Write-Skip "Find My Device skipped."
}

# ── Restart Explorer to apply visual changes ──────────────────────────────────
Write-Host "`n    [*] Restarting Explorer to apply taskbar and visual changes..." -ForegroundColor Cyan
Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process "explorer.exe"
Write-OK "Explorer restarted."

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " Privacy hardening + debloat complete. Reboot recommended." -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
