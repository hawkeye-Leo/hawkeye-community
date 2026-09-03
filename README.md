# Hawkeye Community

**Official open-source edition of [Hawkeye Lab](https://hawkeye-leo.github.io/hawkeye/lab/).**  
Windows **kernel security research console** — live memory analysis, ETW sampling, symbols (`!probe`), and driver-backed inspection. **This repository is the source code and releases;** [hawkeye-Leo/hawkeye](https://github.com/hawkeye-Leo/hawkeye) is the website only.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Platform: Windows 10/11 x64](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-0078D4)

[Download](https://github.com/hawkeye-Leo/hawkeye-community/releases/latest) · [Source](https://github.com/hawkeye-Leo/hawkeye-community) · [Official website](https://hawkeye-leo.github.io/hawkeye/) · [Hawkeye Lab](https://hawkeye-leo.github.io/hawkeye/lab/) · [Community vs Lab](#community-and-lab)

Hawkeye Community is for **research and learning** on systems you administer: run it on a live Windows machine and explore how kernel and process behavior look in practice.

**Hawkeye Lab** is the subscription edition on the same foundation — automated high-risk detection, `!analyze`, and scored reports. See [Community and Lab](#community-and-lab) below.

## Authorized use only

Use this software only on systems you own or are explicitly authorized to administer. It is a research console, not a bypass kit. Do not use it against third-party software, games, or production systems without authorization.

## Requirements

- **OS:** Windows 10 or Windows 11, x64
- **Privileges:** run as Administrator (driver load)
- **Not supported:** Windows 7 / 8 / 8.1; very old Windows 10 builds
- Most current Win10 and Win11 installs are fine.
- If Hawkeye reports *this Windows build is not supported*, run `!support` and email the report.

## Download

A ready-to-run build is attached to [GitHub Releases](https://github.com/hawkeye-Leo/hawkeye-community/releases/latest).

Unzip, run `Hawkeye.exe` as Administrator, then follow **Driver setup** (or `!enable_testsigning` below). You do not need Visual Studio to use the zip.

## Driver environment

Community and Lab both test-sign `Hawkeye.exe` and `Hawkeye.sys` with the same certificate (`CN=Hawkeye Test Certificate`). The driver is not WHQL-signed. Windows will not load it until test signing is on and that certificate is trusted.

If the driver does not load, run Hawkeye Community as Administrator, then `!enable_testsigning`, reboot when Windows asks, and start Hawkeye again. Use `!disable_testsigning` later to turn test signing off and remove the certificate.

If it still fails, run `!support` and open **Driver setup** on the status bar. Memory Integrity / HVCI, Secure Boot, and signature policy are the usual blockers.

## Getting started

The first screen is **Getting started**: what Hawkeye is, what the console can do, and the steps that make it usable. If you dismissed it, `!getting-started` brings it back.

After driver setup, **`!help` is the working catalog**. Run any command with no arguments for usage.

## Probe

`!probe` is the main research entry point: attach a live symbol context to a process (or the kernel with pid `4`), load symbols, and explore.

Attach first (`!probe -pid:<pid>`), then search. Example:

```text
!probe -find:has,protect -mod:dwmredir
```

`-mod:` may download PDBs. The first time, wait; speed depends on the Microsoft symbol server.

## ETW sampling

`!etw` is the other research core. It uses Windows ETW sampled profile: over a short window it collects instruction-pointer samples for threads. That is sampled RIPs, not every instruction the thread executed, and not a stack walk. For stacks, use `-stack:1` with `-tid:`.

A first look:

```text
!etw -all -min:0 -sym:0
```

That is system-wide, keeps low-count hits, and skips symbol resolve so it returns quickly. Use `-pid:` or `-tid:` when you want one process or one thread. Run `!etw` with no arguments for the rest.

## Command reference

`!help` is the full catalog. The groups below are the rest of the Community bench.

### Inspection — live state

**Process**  
`!process` · `!modules` · `!threads`

**Integrity**  
`!check_cert` · `!check_hwnd` · `!inline_hook` · `!iguard_scan`

**Memory**  
`!pte` · `!pfn` · `!kernel_region` · `!dump` — mmcopy and map_io only

### Symbols

`!sym` — download, load, resolve, and list PDBs (with `!probe`)

### Staging

`!inject_sim` · `!inline_hook_sim` — plant a test condition; not a detector

### Housekeeping

`!getting-started` · `!support` · `!search` · `cls`  
`!enable_testsigning` · `!disable_testsigning`  
`!license` — edition and website only; Community does not accept Lab keys

## Community and Lab

This repository ships **Community** (GPL-3.0-or-later). Lab is a separate edition on the same console and driver foundation.

| Capability | Community (this repo) | Lab |
| --- | :---: | :---: |
| Live console + driver setup | ✓ | ✓ |
| `!probe`, `!etw`, memory tools | ✓ | ✓ |
| High-risk detection commands | — | ✓ |
| `!analyze` (20-check workflow) | — | ✓ |
| Scored analysis report (PDF / text) | — | ✓ |
| Lab `-demo` staging | — | ✓ |

Hawkeye Lab is a productivity tool built on a body of research. It automates high-risk behavior detection, produces an analysis report, and draws on a behavior-signature library so everything is easier. Lab includes everything in Community. That is [Hawkeye Lab](https://hawkeye-leo.github.io/hawkeye/lab/).

## Analyze plugin

A plugin is a DLL that exports `HawkHotTargetsQuery`. It fills a process id and hot addresses. Hawkeye does not invent those addresses.

The contract is [`hawk_hot_targets.h`](hawk_hot_targets.h). The sample is [`samples/HawkHotTargets`](samples/HawkHotTargets) — it opens Notepad. Lab loads the DLL with `!analyze -load`. Community does not run `!analyze`.

## Build from source

Visual Studio 2019 (MSVC v142), the Windows Driver Kit, and Qt 5.15.2 MSVC 2019 64-bit (`C:\Qt\5.15.2\msvc2019_64`).

```text
Hawkeye\Hawkeye\Hawkeye.sln     Application   Release | x64
HawkDrv\HawkDrv.sln             Driver        Release | x64
samples\HawkUnsignedStub\HawkUnsignedStub.sln
                                Unsigned stub used by !inject_sim
samples\HawkHotTargets\HawkHotTargets.sln
                                Plugin sample: exports HawkHotTargetsQuery
```

- App: `Hawkeye\Hawkeye\Hawkeye\x64\Release\Hawkeye.exe`
- Driver copy: `bin\Hawkeye.sys` (after a successful driver build)

## Third-party

This repository includes third-party components:

- **Qt 5.15** — LGPL v3, dynamically linked. Qt source is available at [qt.io/download-open-source](https://www.qt.io/download-open-source).
- **bddisasm** (Bitdefender) — Apache-2.0, vendored in [`third_party/bddisasm`](third_party/bddisasm). License and copyright notices are in that directory.

## Support

Email [hawkeye18485@gmail.com](mailto:hawkeye18485@gmail.com). For driver or compatibility issues, run `!support` in the console and include that output.

To report a security vulnerability, see [`SECURITY.md`](SECURITY.md) (do not open a public issue).

## License

GPL-3.0-or-later. See [`LICENSE`](LICENSE). The application and kernel driver in this repository are licensed under the same terms.
