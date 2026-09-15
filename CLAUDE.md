# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A diagnostic and deployment toolset for running **ESU LokProgrammer PC-Software V1.51**
(a 32-bit Borland Delphi application from 2002, for the discontinued LokProgrammer 50450
model-railway decoder programmer) on Windows 10 x64.

There is no build step and no application source code here. The repository contains
PowerShell analysis tooling, Windows Sandbox configurations, and VM provisioning — the
target program is a third-party binary that is deliberately **not** committed (see
*Licensing* below).

## Commands

All scripts are standalone. None require a build, install, or dependency step.

```powershell
# Deploy the program end to end (download -> verify -> classify -> place)
.\Deploy-LokProgrammer.ps1 -WhatIf          # preview, downloads nothing
.\Deploy-LokProgrammer.ps1                  # prompts before each side effect
.\Deploy-LokProgrammer.ps1 -SkipDownload    # file already present

# Static analysis of an installer/binary (reads only, executes nothing)
.\tools\Inspect-Installer.ps1

# Find out which scanner actually flagged something (Defender vs third party)
.\tools\Get-DefenderVerdict.ps1 -Days 60
.\tools\Get-DefenderVerdict.ps1 -File "C:\path\to\file.exe"

# Serial port diagnosis, host side and inside a guest
.\tools\Test-COM1.ps1
.\tools\Test-COM1.ps1 -Loopback             # needs pin 2 <-> 3 bridged

# Provision a Windows 2000 VM with physical COM1 passthrough
.\vm\New-LegacyVM.ps1 -IsoPath "D:\iso\w2k.iso" -WhatIf
```

Windows Sandbox configs are launched by double-click (`Sandbox-Analyse.wsb` for
network-on triage, `Sandbox-Isoliert.wsb` for network-off execution). The feature is
not installed by default:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All
```

### Verifying changes

There is no test suite. Validate edits with both of these before considering a change done:

```powershell
# Syntax
$e = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$e)

# XML for .wsb
[xml](Get-Content $path -Raw)
```

Syntax-checking alone has repeatedly missed real defects in this repo. Every change to an
analysis script must also be run against **real fixture files** — a 32-bit PE
(`SysWOW64\notepad.exe`), a 64-bit PE (`System32\notepad.exe`), an MSI, a CAB and a ZIP —
and the output compared against known-correct values.

## Architecture

Four layers, escalating in invasiveness. They are meant to be used in order, and most
tasks stop at layer 1.

1. **`Deploy-LokProgrammer.ps1`** — the primary path. Its central design decision is
   *extract, never execute*: a 2002 installer may carry a 16-bit stub that cannot run on
   x64 at all, and extracting also avoids running unknown code. For this particular file
   the question turned out to be moot (see *Established facts*), but the logic stays
   because it is the correct general approach.
2. **`tools/`** — read-only diagnostics. `Inspect-Installer.ps1` is the PE/container
   classifier; `Get-DefenderVerdict.ps1` answers "what did Windows actually report";
   `Test-COM1.ps1` isolates serial faults from software faults.
3. **`*.wsb`** — Windows Sandbox. Two-stage: `Sandbox-Analyse.wsb` (network on, clipboard
   on, all mounts read-only, nothing executed) then `Sandbox-Isoliert.wsb` (network off,
   clipboard off, `ProtectedClient` on, execution permitted).
4. **`vm/New-LegacyVM.ps1`** — last resort. Only this layer can drive the actual hardware.

### Why VirtualBox and not Hyper-V

Hyper-V binds VM COM ports to **named pipes only**, never to a physical host port — true
for Gen 1 and Gen 2. Windows Sandbox has no serial redirection in its config schema at
all. Driving the LokProgrammer 50450 therefore requires VirtualBox (`--uartmode1 \\.\COM1`)
or VMware (`serial0.fileType = "device"`). Do not propose Hyper-V or Sandbox for hardware
access.

## Established facts

These were determined empirically and should not be re-litigated:

- The downloaded file (`1,944,064` bytes, SHA256
  `B1D74B9CFF15FCF6FE2FE0E4A68CCDCB4E0247B64A5A0011F523E1C90C62BA16`, SHA1
  `8F0745D21BC0A4296BF6B527EC39009AD0E0BEA9`) is **not an installer**. It *is* the
  application — PE32 i386 GUI, overlay 0 bytes, Delphi.
- The original 2003 delivery *was* a WinZip self-extractor (`693,760` bytes) whose ZIP
  central directory holds exactly **one** entry: `Lokprogrammer_V151.exe`, uncompressed
  `1,944,064` bytes. ESU replaced the self-extractor with the bare application between
  Jan 2004 and Jan 2006 under the same filename and version. Nothing was left out.
- ESU's own install instruction was "unzip to a directory, default `c:\lokprogrammer`".
  There was never a setup, a registry entry, or a driver. Running it from
  `C:\LokProgrammer` is literally the vendor default, not a workaround.
- Official V1.51 requirements: Pentium 90, 32 MB RAM, one free COM port,
  Windows 98/98SE/ME/2000/**XP**, **DirectX 6.1+**, sound card with working drivers.
  The esu.eu download page understates this as "95/98/2000".
- It runs on Windows 10 x64 **unmodified**: no installation, no compatibility shim, no
  signature, no Mark-of-the-Web removal. All 20 static imports are Windows system DLLs.
- It is fully portable — writes no files and no registry keys. The only registry paths it
  reads are `Software\Borland\Delphi\*` (VCL locale lookup).
- Help and printing are absent **by design in V1.51** (the help menu item has
  `Enabled=False` and no handler; there is no `winspool.drv` import). Do not diagnose
  these as Windows 10 damage.
- The serial scan is hard-coded to **COM1–COM4** only.
- Install outside `Program Files`. The binary has no manifest, so UAC virtualization
  applies and settings would be silently redirected to `VirtualStore`.
- The 50450 programs **only LokSound "classic"** decoders. Newer decoders need the 53451.
  CVs can be set on any decoder with any DCC command station plus JMRI DecoderPro; only
  sound files and firmware require LokProgrammer hardware.

## Conventions and traps

**Scripts must stay ASCII-only.** PowerShell 5.1 reads UTF-8-without-BOM as ANSI, so
umlauts in script output become mojibake. Write `ue`, `ae`, `oe`, `ss` in `.ps1` files.
Markdown files are exempt.

**Never use `New-Item -Force` on an existing registry key.** It recreates the key and
deletes every value in it. This destroyed the user's `AppCompatFlags\Layers` entries once.
Guard with `if (-not (Test-Path $key))`, and export a `.reg` backup before writing.

**Enumerate modules of a 32-bit process from 32-bit PowerShell**
(`C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`). From 64-bit PowerShell,
`(Get-Process x).Modules` returns only the WOW64 stubs — 5 entries instead of 93 — which
reads as a catastrophically broken application when nothing is wrong.

**Check `$LASTEXITCODE` after `MpCmdRun`, never the output text.** 0 = clean, 2 = threat,
anything else = the scan failed. Text matching reports scan failures as malware hits.

**Defender is not necessarily the active scanner.** Where a third-party AV is installed,
Defender runs in `SxS Passive Mode` with real-time protection off, so `Get-MpThreat`
returns nothing regardless of what happened. Always resolve the active product from
`root\SecurityCenter2` first; an empty Defender history is not an all-clear.

**A Delphi app's runtime errors never reach the Application event log** — the VCL catches
them in `TApplication.HandleException` and shows a message box. An empty event log proves
nothing about this program.

## Licensing — do not commit the binary

ESU's download licence explicitly forbids passing the software to third parties
(§2.3: *"den Inhalt oder Teile davon an Dritte lizenzieren, kopieren, reproduzieren,
übertragen … oder anderweitig … weitergeben"*). Committing `LokProgrammer.exe` or any
extracted part of it to a repository — public or private — is redistribution.

`.gitignore` excludes it. Reproducibility is preserved instead through the documented
download URL, the expected byte size and the hashes above.

ESU publishes no checksums of its own — but an **independent historical reference exists**:
the Internet Archive's CDX index records SHA1 `8F0745D21BC0A4296BF6B527EC39009AD0E0BEA9`
(Base32 `R4DULUQ3YCSCS27WWUT6YOIATLIOBPVJ`) for
`loksound.de/download/software/50450_LoPro_V151.exe` in the captures of 2006-01-16,
2006-01-17 and 2006-02-24. The current esu.eu download matches it bit for bit. The 2003
and 2004 captures carry a different digest because they are the SFX wrapper, not the
payload. So the file *can* be verified against something other than our own baseline.

### Sound material is a separate download

The program ships without any audio content — that was true in 2003 as well. ESU's factory
sounds for LokSound "classic" are still available under Download → Geräuschdateien →
Generation 1. Without them the application runs correctly but has nothing to write to a
decoder. Do not treat "no sounds available" as a defect of the portable setup.
