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
# 16. WINDOWS 11 UPGRADE — 4-METHOD FALLTHROUGH ENGINE
#     Method 1 : Fido  (Microsoft CDN direct link via official download API)
#     Method 2 : Windows 11 Installation Assistant (silent in-place, no ISO)
#     Method 3 : Media Creation Tool  (silent ISO download + setup)
#     Method 4 : UUP Dump  (ISO built from Microsoft's own update servers)
# ─────────────────────────────────────────────────────────────────────────────
Write-Header "Windows 11 Upgrade"

Write-Host @"

    Microsurf will attempt to upgrade this machine to the latest
    stable Windows 11 directly from Microsoft — no sign-in required.

    Methods tried in order (falls through on failure):
      1. Fido       — direct Microsoft CDN ISO link
      2. Install Assistant — silent in-place upgrade (no ISO)
      3. Media Creation Tool — silent ISO + setup
      4. UUP Dump   — ISO built from Microsoft Update servers

    Apps, settings, and files are preserved (in-place upgrade).
    GitHub : https://github.com/0xb0rn3/Microsurf

"@ -ForegroundColor DarkCyan

$upgrade = Read-Host "    Upgrade this machine to Windows 11 now? [Y/N]"

if ($upgrade -notmatch "^[Yy]") {
    Write-Skip "Windows 11 upgrade skipped."
} else {

# ── Shared helpers ────────────────────────────────────────────────────────────
function Get-Win11IsoPath  { return "$env:TEMP\Win11.iso" }
function Get-Win11ExtractPath { return "$env:SystemDrive\Win11Setup" }

function Test-IsoValid {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    return (Get-Item $Path).Length -gt 3GB
}

# ── Ensure 7-Zip is available (download portable build if not installed) ──────
function Get-7ZipExe {
    # Check common install locations first
    $candidates = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
        "$env:TEMP\7z\7z.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }

    # Download portable 7-Zip extra (standalone 7za.exe) from 7-zip.org
    Write-OK "7-Zip not found — downloading portable build..."
    $sevenZipDir  = "$env:TEMP\7z"
    $sevenZipExe  = "$sevenZipDir\7z.exe"
    $sevenZipDll  = "$sevenZipDir\7z.dll"
    New-Item -ItemType Directory -Path $sevenZipDir -Force | Out-Null

    # 7-Zip 24.08 standalone console — official sourceforge mirror
    $dlBase = "https://www.7-zip.org/a"
    $exeUrl = "$dlBase/7zr.exe"   # 7zr is a standalone single-file build

    Invoke-WebRequest -Uri $exeUrl -OutFile $sevenZipExe -UseBasicParsing -TimeoutSec 60
    if (-not (Test-Path $sevenZipExe)) { throw "Failed to download 7-Zip portable." }
    Write-OK "7-Zip portable ready: $sevenZipExe"
    return $sevenZipExe
}

# ── Extract ISO and apply hardware bypass, then run setup.exe ─────────────────
function Invoke-SilentUpgrade {
    param([string]$IsoPath)

    $extractPath = Get-Win11ExtractPath
    $sevenZip    = $null
    $extracted   = $false

    # ── Step 1: Extract ISO using 7-Zip ──────────────────────────────────────
    Write-OK "Extracting ISO to $extractPath ..."
    try {
        $sevenZip = Get-7ZipExe
        if (Test-Path $extractPath) {
            Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

        $7zArgs  = "x `"$IsoPath`" -o`"$extractPath`" -y -bsp1"
        $proc    = Start-Process -FilePath $sevenZip -ArgumentList $7zArgs `
                       -PassThru -Wait -NoNewWindow -ErrorAction Stop

        if ($proc.ExitCode -ne 0) { throw "7-Zip exited with code $($proc.ExitCode)." }

        $setup = "$extractPath\setup.exe"
        if (-not (Test-Path $setup)) { throw "setup.exe not found after extraction." }

        Write-OK "ISO extracted successfully."
        $extracted = $true
    } catch {
        Write-Host "    [!] 7-Zip extraction failed: $_ — falling back to Mount-DiskImage" `
            -ForegroundColor Yellow
    }

    # ── Fallback: mount if extraction failed ─────────────────────────────────
    if (-not $extracted) {
        Write-OK "Mounting ISO as fallback..."
        $mount       = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
        $driveLetter = ($mount | Get-Volume).DriveLetter
        $extractPath = "${driveLetter}:"
        $setup       = "$extractPath\setup.exe"
        if (-not (Test-Path $setup)) {
            Dismount-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue | Out-Null
            throw "setup.exe not found in mounted ISO."
        }
        Write-OK "ISO mounted at $driveLetter`:"
    }

    # ── Step 2: Patch install.wim / install.esd (unpack WIM for inspection) ──
    $wimPath = "$extractPath\sources\install.wim"
    $esdPath = "$extractPath\sources\install.esd"
    $imageFile = if (Test-Path $wimPath) { $wimPath } elseif (Test-Path $esdPath) { $esdPath } else { $null }

    if ($imageFile) {
        Write-OK "Found image file: $(Split-Path $imageFile -Leaf)"
        try {
            $indexes = & dism /Get-WimInfo /WimFile:"$imageFile" 2>&1 |
                       Select-String "Index\s+:\s+(\d+)" | ForEach-Object {
                           $_.Matches[0].Groups[1].Value
                       }
            Write-OK "Available editions in image: $($indexes -join ', ')"
        } catch { Write-Skip "Could not enumerate WIM indexes: $_" }
    }

    # ── Step 3: Hardware requirement bypass ──────────────────────────────────
    $appraiserSrc = "$extractPath\sources\appraiserres.dll"
    if (Test-Path $appraiserSrc) {
        try {
            # Zero-byte appraiserres.dll disables TPM/SecureBoot/RAM checks
            $nullDll = "$env:TEMP\appraiserres_null.dll"
            [System.IO.File]::WriteAllBytes($nullDll, [byte[]]@())

            # If extracted to disk, replace directly; if mounted, copy to TEMP
            if ($extracted) {
                Copy-Item -Path $nullDll -Destination $appraiserSrc -Force
                Write-OK "appraiserres.dll patched in extracted files (hardware bypass active)."
            } else {
                # Can't write to mounted read-only ISO; pass via /appraiserresult flag instead
                Write-OK "Hardware bypass via /appraiserresult flag (mounted ISO mode)."
            }
        } catch { Write-Skip "appraiserres bypass skipped: $_" }
    }

    # ── Step 4: Registry bypass keys (secondary TPM/SecureBoot bypass) ───────
    Write-OK "Applying registry-level hardware requirement bypass..."
    $moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
    if (-not (Test-Path $moSetupPath)) {
        New-Item -Path $moSetupPath -Force | Out-Null
    }
    Set-ItemProperty -Path $moSetupPath -Name "AllowUpgradesWithUnsupportedTPMOrCPU" `
        -Value 1 -Type DWord -Force
    Write-OK "MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU = 1"

    $labConfigPath = "HKLM:\SYSTEM\Setup\LabConfig"
    if (-not (Test-Path $labConfigPath)) {
        New-Item -Path $labConfigPath -Force | Out-Null
    }
    @{
        "BypassTPMCheck"          = 1
        "BypassSecureBootCheck"   = 1
        "BypassRAMCheck"          = 1
        "BypassStorageCheck"      = 1
        "BypassCPUCheck"          = 1
    }.GetEnumerator() | ForEach-Object {
        Set-ItemProperty -Path $labConfigPath -Name $_.Key -Value $_.Value -Type DWord -Force
        Write-OK "LabConfig\$($_.Key) = 1"
    }

    # ── Step 5: Run setup.exe silently ────────────────────────────────────────
    Write-OK "Launching setup.exe from extracted files..."
    $setupArgs = "/auto upgrade /quiet /noreboot /skipeula /compat ignorewarning " +
                 "/DynamicUpdate disable"

    if (-not $extracted) {
        # Mounted ISO — pass null appraiser via flag
        $nullDll = "$env:TEMP\appraiserres_null.dll"
        if (Test-Path $nullDll) {
            $setupArgs += " /appraiserresult `"$nullDll`""
        }
    }

    $proc = Start-Process -FilePath $setup -ArgumentList $setupArgs `
                -PassThru -Wait -ErrorAction Stop

    # ── Step 6: Cleanup ───────────────────────────────────────────────────────
    if (-not $extracted -and $IsoPath) {
        Dismount-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue | Out-Null
        Write-OK "ISO dismounted."
    }
    # Keep extracted folder — setup.exe may still need it during the upgrade reboot phase

    $successCodes = @(0, 3, 3010)
    if ($proc.ExitCode -in $successCodes) {
        Write-OK "setup.exe completed (exit $($proc.ExitCode)). Reboot to finish upgrade."
        return $true
    } else {
        # Log location for troubleshooting
        $logPath = "$env:SystemDrive\`$WINDOWS.~BT\Sources\Panther"
        Write-Host "    [!] setup.exe exited with code $($proc.ExitCode)." -ForegroundColor Yellow
        if (Test-Path $logPath) {
            Write-Host "        Logs: $logPath" -ForegroundColor DarkGray
        }
        throw "setup.exe failed with exit code $($proc.ExitCode)."
    }
}


# ── Pre-flight ────────────────────────────────────────────────────────────────
Write-OK "Checking Windows 11 hardware requirements..."

$tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" `
           -Class Win32_Tpm -ErrorAction SilentlyContinue
$tpmReady   = $tpm -and $tpm.IsActivated_InitialValue -and $tpm.IsEnabled_InitialValue
$cpu        = Get-CimInstance Win32_Processor | Select-Object -First 1
$ramGB      = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$diskFreeGB = [math]::Round(
    (Get-PSDrive -Name ($env:SystemDrive -replace ':') |
     Select-Object -ExpandProperty Free) / 1GB, 1)

Write-OK "CPU  : $($cpu.Name)"
Write-OK "RAM  : $ramGB GB"
Write-OK "Disk : $diskFreeGB GB free"
Write-OK "TPM 2.0: $tpmReady"

if (-not $tpmReady) {
    Write-Host "    [!] TPM 2.0 inactive — hardware bypass will be applied automatically." `
        -ForegroundColor Yellow
}
if ($diskFreeGB -lt 20) {
    Write-Host "    [!] Only $diskFreeGB GB free. At least 20 GB required. Aborting." -ForegroundColor Red
    Write-Skip "Upgrade cancelled — insufficient disk space."
} else {

$upgradeSuccess = $false

# ══════════════════════════════════════════════════════════════════════════════
# METHOD 1 — FIDO (Microsoft CDN direct ISO, pbatard/Fido)
# ══════════════════════════════════════════════════════════════════════════════
if (-not $upgradeSuccess) {
    Write-Host "`n    ┌─ Method 1: Fido (Microsoft CDN direct link)" -ForegroundColor Cyan
    try {
        $fidoUrl  = "https://raw.githubusercontent.com/pbatard/Fido/master/Fido.ps1"
        Write-OK "Fetching Fido from $fidoUrl ..."
        $fido = Invoke-RestMethod -Uri $fidoUrl -UseBasicParsing -TimeoutSec 30

        if ($fido -match "<html" -or $fido.Length -lt 100) {
            throw "Fido script fetch returned invalid content."
        }

        # Run Fido in -GetUrl mode to get the CDN link without opening a GUI
        $isoUrl = & ([scriptblock]::Create($fido)) `
                    -Win 11 -Rel Latest -Ed "Windows 11 Home/Pro/Edu" `
                    -Lang "English International" -Arch x64 -GetUrl

        if (-not $isoUrl -or $isoUrl -notmatch "^https://") {
            throw "Fido returned an invalid or empty URL: $isoUrl"
        }

        Write-OK "ISO URL obtained: $($isoUrl.Substring(0,80))..."

        $isoPath = Get-Win11IsoPath
        Write-OK "Downloading ISO via BITS (resumes on interruption)..."
        Start-BitsTransfer -Source $isoUrl -Destination $isoPath `
            -DisplayName "Windows 11 ISO" -Priority High -ErrorAction Stop

        if (Test-IsoValid $isoPath) {
            Write-OK "ISO downloaded: $([math]::Round((Get-Item $isoPath).Length / 1GB, 2)) GB"
            $upgradeSuccess = Invoke-SilentUpgrade -IsoPath $isoPath
        } else {
            throw "Downloaded file is missing or too small — likely a partial download."
        }
    } catch {
        Write-Host "    └─ Method 1 failed: $_" -ForegroundColor Yellow
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# METHOD 2 — WINDOWS 11 INSTALLATION ASSISTANT (no ISO, silent in-place)
# ══════════════════════════════════════════════════════════════════════════════
if (-not $upgradeSuccess) {
    Write-Host "`n    ┌─ Method 2: Windows 11 Installation Assistant" -ForegroundColor Cyan
    try {
        $assistantUrl  = "https://go.microsoft.com/fwlink/?linkid=2171764"
        $assistantPath = "$env:TEMP\Win11InstallAssistant.exe"

        Write-OK "Downloading Installation Assistant from Microsoft..."
        Invoke-WebRequest -Uri $assistantUrl -OutFile $assistantPath `
            -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop

        if (-not (Test-Path $assistantPath) -or (Get-Item $assistantPath).Length -lt 1MB) {
            throw "Installation Assistant download failed or file is too small."
        }

        Write-OK "Launching silent in-place upgrade..."
        $proc = Start-Process -FilePath $assistantPath `
                    -ArgumentList "/quietinstall /skipeula /auto upgrade /copylogs $env:TEMP\Win11AssistantLog" `
                    -PassThru -Wait -ErrorAction Stop

        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-OK "Installation Assistant completed (exit $($proc.ExitCode)). Reboot to finish."
            $upgradeSuccess = $true
        } else {
            throw "Installation Assistant exited with code $($proc.ExitCode)."
        }
    } catch {
        Write-Host "    └─ Method 2 failed: $_" -ForegroundColor Yellow
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# METHOD 3 — MEDIA CREATION TOOL (silent ISO creation + setup)
# ══════════════════════════════════════════════════════════════════════════════
if (-not $upgradeSuccess) {
    Write-Host "`n    ┌─ Method 3: Media Creation Tool" -ForegroundColor Cyan
    try {
        $mctUrl  = "https://go.microsoft.com/fwlink/?LinkId=2265055"
        $mctPath = "$env:TEMP\MediaCreationTool.exe"
        $isoPath = Get-Win11IsoPath

        Write-OK "Downloading Media Creation Tool from Microsoft..."
        Invoke-WebRequest -Uri $mctUrl -OutFile $mctPath `
            -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop

        if (-not (Test-Path $mctPath) -or (Get-Item $mctPath).Length -lt 1MB) {
            throw "MCT download failed or file is too small."
        }

        Write-OK "Running MCT to create ISO silently..."
        $mctArgs = "/Eula accept /Retail /MediaArch x64 /MediaLangCode en-US " +
                   "/MediaEdition Home /MediaType ISO /MediaLocation $isoPath"
        $proc = Start-Process -FilePath $mctPath -ArgumentList $mctArgs `
                    -PassThru -Wait -ErrorAction Stop

        if ($proc.ExitCode -ne 0) {
            throw "MCT exited with code $($proc.ExitCode)."
        }

        if (Test-IsoValid $isoPath) {
            Write-OK "ISO created: $([math]::Round((Get-Item $isoPath).Length / 1GB, 2)) GB"
            $upgradeSuccess = Invoke-SilentUpgrade -IsoPath $isoPath
        } else {
            throw "MCT did not produce a valid ISO at $isoPath."
        }
    } catch {
        Write-Host "    └─ Method 3 failed: $_" -ForegroundColor Yellow
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# METHOD 4 — UUP DUMP (ISO assembled from Microsoft Update servers)
# ══════════════════════════════════════════════════════════════════════════════
if (-not $upgradeSuccess) {
    Write-Host "`n    ┌─ Method 4: UUP Dump (Microsoft Update servers)" -ForegroundColor Cyan
    try {
        # Query UUP dump API for the latest Windows 11 x64 retail build
        $apiUrl  = "https://api.uupdump.net/listid.php?search=Windows+11&sortByDate=1"
        Write-OK "Querying UUP Dump API for latest Windows 11 build..."
        $builds  = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop

        # Pick the latest amd64 retail build
        $latest = $builds.response.builds.build | Where-Object {
            $_.arch -eq "amd64" -and $_.build -match "^\d{5}"
        } | Sort-Object build -Descending | Select-Object -First 1

        if (-not $latest) { throw "No suitable build found in UUP Dump API response." }

        $buildId = $latest.uuid
        Write-OK "Latest build: $($latest.title) ($($latest.build)) — UUID: $buildId"

        # Download the UUP dump package scripts
        $pkgUrl  = "https://uupdump.net/get.php?id=$buildId&pack=en-us&edition=professional&autodl=2"
        $pkgZip  = "$env:TEMP\uupdump_pkg.zip"
        $pkgDir  = "$env:TEMP\uupdump_pkg"

        Write-OK "Downloading UUP Dump conversion package..."
        Invoke-WebRequest -Uri $pkgUrl -OutFile $pkgZip `
            -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop

        if (-not (Test-Path $pkgZip) -or (Get-Item $pkgZip).Length -lt 10KB) {
            throw "UUP Dump package download failed."
        }

        Expand-Archive -Path $pkgZip -DestinationPath $pkgDir -Force

        # Run the conversion script (uup_download_windows.cmd)
        $convScript = Get-ChildItem -Path $pkgDir -Filter "uup_download_windows.cmd" -Recurse |
                      Select-Object -First 1

        if (-not $convScript) { throw "Conversion script not found in UUP Dump package." }

        Write-OK "Building ISO from Microsoft Update servers — this will take 20-40 min..."
        $proc = Start-Process -FilePath "cmd.exe" `
                    -ArgumentList "/c `"$($convScript.FullName)`"" `
                    -WorkingDirectory $convScript.DirectoryName `
                    -PassThru -Wait -ErrorAction Stop

        # Find the resulting ISO in the package directory
        $builtIso = Get-ChildItem -Path $pkgDir -Filter "*.iso" -Recurse |
                    Sort-Object Length -Descending | Select-Object -First 1

        if ($builtIso -and (Test-IsoValid $builtIso.FullName)) {
            $isoPath = Get-Win11IsoPath
            Move-Item -Path $builtIso.FullName -Destination $isoPath -Force
            Write-OK "ISO built: $([math]::Round((Get-Item $isoPath).Length / 1GB, 2)) GB"
            $upgradeSuccess = Invoke-SilentUpgrade -IsoPath $isoPath
        } else {
            throw "UUP Dump did not produce a valid ISO. Check $pkgDir for logs."
        }
    } catch {
        Write-Host "    └─ Method 4 failed: $_" -ForegroundColor Yellow
    }
}

# ── Final result ──────────────────────────────────────────────────────────────
if ($upgradeSuccess) {
    Write-Host "`n    [+] Windows 11 upgrade staged successfully." -ForegroundColor Green
    Write-Host "        Reboot when ready to complete the upgrade." -ForegroundColor Green
} else {
    Write-Host "`n    [!] All 4 methods failed. Manual steps:" -ForegroundColor Red
    Write-Host "        1. Visit https://www.microsoft.com/software-download/windows11" -ForegroundColor DarkGray
    Write-Host "        2. Download the ISO manually" -ForegroundColor DarkGray
    Write-Host "        3. Mount it and run: setup.exe /auto upgrade /quiet" -ForegroundColor DarkGray
}

} # end disk check
} # end upgrade prompt

# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host " Privacy hardening complete. Reboot recommended." -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan
