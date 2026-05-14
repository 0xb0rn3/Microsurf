<div align="center">

```
███╗   ███╗██╗ ██████╗██████╗  ██████╗ ███████╗██╗   ██╗██████╗ ███████╗
████╗ ████║██║██╔════╝██╔══██╗██╔═══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
██╔████╔██║██║██║     ██████╔╝██║   ██║███████╗██║   ██║██████╔╝█████╗  
██║╚██╔╝██║██║██║     ██╔══██╗██║   ██║╚════██║██║   ██║██╔══██╗██╔══╝  
██║ ╚═╝ ██║██║╚██████╗██║  ██║╚██████╔╝███████║╚██████╔╝██║  ██║██║     
╚═╝     ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     
```

**Windows privacy hardening + silent Windows 11 upgrade. No sign-in required.**

[![Author](https://img.shields.io/badge/author-0xb0rn3-blueviolet?style=flat-square)](https://github.com/0xb0rn3)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=flat-square&logo=windows)](https://github.com/0xb0rn3/Microsurf)
[![Shell](https://img.shields.io/badge/shell-PowerShell-5391FE?style=flat-square&logo=powershell)](https://github.com/0xb0rn3/Microsurf)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

</div>

---

## What is Microsurf?

Microsurf is a zero-interaction Windows hardening and upgrade toolkit.  
It strips Microsoft's data collection pipeline from Windows 10 and optionally performs a silent, unauthenticated in-place upgrade to the latest stable Windows 11 — no Microsoft account, no media creation tool, no manual ISO hunting.

The main entry point is **`10surf.ps1`** — a single PowerShell script that handles everything end to end.

---

## Quick Start

Open an **elevated PowerShell** (Run as Administrator) and run:

```powershell
irm https://raw.githubusercontent.com/0xb0rn3/Microsurf/main/10surf.ps1 | iex
```

That's it. The script walks you through every step interactively.

---

## Features

### Privacy & Telemetry Hardening
- Sets `AllowTelemetry = 0` via both policy and direct registry paths
- Disables `DiagTrack`, `dmwappushservice`, and `WerSvc` services
- Blocks 30+ Microsoft telemetry endpoints in the Windows hosts file
- Adds outbound Windows Firewall rules blocking `CompatTelRunner.exe`, `DeviceCensus.exe`, and related binaries
- Disables all CEIP and feedback scheduled tasks
- Kills Cortana, Bing web search integration, and search history upload
- Disables the Advertising ID and all personalization data pipelines
- Turns off Activity History, Timeline, and cross-device clipboard sync
- Force-denies app access to camera, microphone, location, contacts, calendar, call history, email, and messaging via AppPrivacy policy
- Disables Windows Error Reporting and diagnostic log collection
- Disables Delivery Optimization peer-to-peer upload (your bandwidth stays yours)
- Kills LLMNR (also closes a credential capture vector on local networks)
- Disables WiFi Sense auto-connect and network sharing
- Disables Content Delivery Manager (silent app installs, Start suggestions)

### Latest KB Update (No Sign-In)
- Uses the **Windows Update Agent COM API** (`Microsoft.Update.Session`) — no browser, no Microsoft account, no WSUS credentials
- Searches for the latest stable Cumulative Update, displays KB number, size, and release date
- Downloads silently at high priority and prompts to install immediately or leave staged

### Windows 11 Upgrade — 4-Method Fallthrough Engine
Prompted automatically during the hardening run. Each method is tested in order; if one fails, the next is tried without user intervention.

| # | Method | How it works |
|---|---|---|
| 1 | **Fido** | Queries Microsoft's official download API via [pbatard/Fido](https://github.com/pbatard/Fido) and pulls the ISO directly from Microsoft's CDN using BITS (resumable) |
| 2 | **Installation Assistant** | Downloads Microsoft's official `Win11InstallAssistant.exe` and runs it silently — no ISO needed, upgrades in-place |
| 3 | **Media Creation Tool** | Downloads Microsoft's official MCT with silent flags to build an ISO, then mounts and runs `setup.exe` |
| 4 | **UUP Dump** | Queries the UUP Dump API for the latest build UUID, downloads the conversion package, and assembles the ISO directly from Microsoft's Update Distribution servers |

- TPM 2.0 is checked before starting; if inactive, an `appraiserres.dll` override is applied automatically so the upgrade proceeds anyway
- All ISO downloads use BITS (`Start-BitsTransfer`) where possible for resumable, throttle-aware transfers
- ISO integrity is validated by size (rejects partial downloads) before `setup.exe` is invoked
- `setup.exe` is always launched with `/auto upgrade /quiet /noreboot` — apps, settings, and files are kept
- If all 4 methods fail, the script prints manual fallback instructions

---

## Requirements

| Requirement | Minimum |
|---|---|
| OS | Windows 10 (any edition, any release) |
| PowerShell | 5.1+ (built into Windows 10) |
| Privileges | Administrator |
| Internet | Required for KB download and Win11 ISO |
| TPM | 2.0 recommended for Windows 11 upgrade (bypass available) |
| RAM | 4 GB+ |
| Free disk | 20 GB+ |

---

## What Gets Changed

A **System Restore Point** is created automatically before any changes are made.  
To roll back at any time:

```powershell
rstrui.exe
```

Or via Settings → System → Recovery → Open System Restore.

---

## Manual Clone & Run

```powershell
# Clone
git clone https://github.com/0xb0rn3/Microsurf.git
cd Microsurf

# Run elevated
Set-ExecutionPolicy Bypass -Scope Process -Force
.\10surf.ps1
```

---

## How It Works

```
10surf.ps1
 ├── Restore Point
 ├── Telemetry registry keys (HKLM + HKCU)
 ├── Service hardening (DiagTrack, WerSvc, DoSvc ...)
 ├── Hosts file (30+ telemetry endpoints → 0.0.0.0)
 ├── Firewall rules (telemetry binaries → block outbound)
 ├── Scheduled task audit (CEIP, feedback, appraiser ...)
 ├── AppPrivacy policy (camera, mic, location, contacts ...)
 ├── WUA COM API → latest cumulative KB download
 └── Microsurf Win11 upgrade engine
      ├── Hardware pre-flight (TPM, RAM, disk)
      ├── ISO fetch + SHA-256 verify
      ├── Silent setup.exe (in-place, keep everything)
      └── Post-upgrade privacy hardening pass
```

---

## Disclaimer

This tool modifies system registry keys, services, scheduled tasks, and firewall rules.  
It is intended for use on machines you own or are explicitly authorised to administer.  
The author is not responsible for any unintended system behaviour resulting from its use.  
A restore point is always created — use it if anything goes wrong.

---

## Author

**0xb0rn3 | oxbv1**  
Security tooling, privacy, and open-source automation.

- GitHub: [@0xb0rn3](https://github.com/0xb0rn3)
- Website: [oxborn3.com](https://oxborn3.com)
- Discord: `oxbv1`
- X/Twitter: [@oxbv1](https://twitter.com/oxbv1)
- Email: 0xb0rn3@proton.me

---

<div align="center">
Made in 🇹🇿 &nbsp;|&nbsp; Built for people who don't trust them with their data.
</div>
