# IdleServiceKiller

A tiny Windows service that finds third-party background services which are doing nothing and stops them, to give back RAM and CPU. It can also close apps you name within about a second of them opening.

Written in Rust: one 243 KB exe, no runtime. The same exe is the service, the installer and a small manager window, so everything can be done without editing files by hand.

> It starts in **dry-run**: it only logs what it *would* stop. Read the Log page for a day before turning dry-run off.

## Install

Build it (needs [Rust](https://rustup.rs) and the Visual Studio C++ Build Tools):

```powershell
cd source
powershell -File build.ps1
```

This writes the installer, `IdleServiceKiller-Setup.exe`, to the `installer` folder at the top level of this repo (git-ignored, so it is never committed). That one exe is all anyone needs. The build signs it as `pandadsgn` with a self-signed certificate that it creates once in your personal certificate store (`Cert:\CurrentUser\My`; the key is not exportable and never enters the repo). Self-signed means the name appears under Properties > Digital Signatures, but Windows still treats the publisher as unverified on other PCs. Removing that warning needs a certificate from a certificate authority; put its thumbprint in place of the self-signed one in `build.ps1`.

Double-clicking the exe shows the Windows administrator prompt, then the manager window opens. Click **Install / Update**. That copies the exe to `%ProgramFiles%\IdleServiceKiller`, registers an automatic delayed-start service (LocalSystem, restarts 60 s after a crash) and adds an entry to *Apps & features*. Installing again upgrades in place and keeps your settings. To open the manager later, run `IdleServiceKiller.exe` from the Program Files folder.

## The window

| Page | What it does |
|------|--------------|
| **Setup** | Shows whether the service is installed and running, and its mode. Buttons: Install / Update, Uninstall, Start, Stop. |
| **Settings** | Every option below as checkboxes, number boxes and lists, with **Save settings**. The running service picks changes up within a few seconds. Turning dry-run off asks you to confirm. |
| **Log** | The most recent entries of `log.txt`, with Refresh and *Open data folder*. |

Command line, from an **administrator** terminal: `IdleServiceKiller.exe --install`, `--install --live`, `--uninstall`.

## Files it creates

In `%ProgramData%\IdleServiceKiller\`:

| File | Contents |
|------|----------|
| `config.txt` | Settings (below). Saving from the Settings page rewrites the whole file (comments are not kept). |
| `log.txt` | What it found, stopped or closed. Rotates at 512 KB to `log.txt.old`. |
| `stopped.txt` | How many times each service has been stopped (survives reboots). |

## Settings

`key=value` lines in `config.txt`; `#` starts a comment. Invalid values are ignored.

| Key | Default | Meaning |
|-----|---------|---------|
| `DryRun` | `true` | `true` = log only. Does not affect `CloseApp`. |
| `IntervalSeconds` | `120` | Seconds between scans (minimum 10). |
| `IdleCycles` | `15` | Consecutive idle scans before acting (15 x 120 s = 30 min). |
| `CpuMsThreshold` | `50` | Max CPU ms per scan to count as idle. |
| `IoBytesThreshold` | `65536` | Max bytes read+written per scan to count as idle. |
| `MaxStopsPerService` | `2` | After this many stops a service is left alone. |
| `MinServiceMemoryMB` | `0` | Only consider services using at least this much RAM. |
| `TrimIdleServices` | `true` | Trim memory of idle services even before stopping them. |
| `Deny=pattern` | | Never touch matching services (name or display name, `*` and `?`). Repeatable. |
| `Only=pattern` | | If present, *only* matching services are considered. Repeatable. |
| `CloseApp=name` | | Kill this process (no `.exe`, wildcards ok) within ~1 s of it appearing. `msedge` does not match `msedgewebview2`; `msedge*` does. Repeatable. |
| `CloseAppsIntervalMs` | `1000` | How often the closer runs (minimum 250). |

## What it will and won't stop

A service is only considered if it is running, owns its process, is non-interactive and accepts a stop. It is then skipped if any of these apply:

- name matches the built-in deny list (security, VPN, remote access, databases, GPU/audio/peripherals, printing, cloud sync, password managers) or your `Deny` list;
- it has already been stopped `MaxStopsPerService` times;
- its process has a listening TCP port;
- it is disabled, lives under `C:\Windows`, or is published by Microsoft;
- another running service depends on it.

Survivors must then be idle (below the CPU and I/O thresholds) for `IdleCycles` scans in a row.

`CloseApp` never touches critical processes (`lsass`, `csrss`, `svchost`, `explorer`, ...), even with a wildcard.

**Tip:** if you go live, add `Deny=*cowork*` first. The log of a dry run shows it wants to stop `CoworkVMService`, which belongs to the Claude desktop app.

## Memory

The service is a single thread with no runtime. Measured on a real installed service: about 0.55 MB working set at its lowest, typically around 1.0 MB, and brief rises to about 1.4 MB while a scan runs (Windows keeps some shared DLL pages mapped; the process trims itself after each scan). The manager window uses more while it is open, but it is a separate process that only exists when you open it.

## Development

```powershell
cd source
cargo test --release                                  # unit tests + real Windows API checks (no admin needed)
IdleServiceKiller.exe --console --config my.txt       # run the service loop in the terminal with a custom config
IdleServiceKiller.exe --gui                           # open the window without the admin prompt (Install and Start will fail)
```

The exe is a Windows-subsystem program, so double-clicking never flashes a console. Command-line flags re-attach to your terminal, but `cmd` and PowerShell do not wait for such programs, so output can appear after the prompt returns.

`app.manifest` (themed controls, DPI awareness) is embedded by `build.rs` through the MSVC linker. The code is one file, `source/src/main.rs`.

## Known limits

- The Install, Uninstall, Start, Stop and Save buttons need an administrator session and have not been clicked end to end in testing; try dry-run first.
- Most services can only be measured with administrator/SYSTEM rights (the installed service has them).
- A stop attempt counts against `MaxStopsPerService` even if it fails.
- Stopping blocks the loop for up to 30 s, pausing the app closer.
