# IdleServiceKiller

A small Windows service that finds third-party background services which are doing nothing and stops them, to give back RAM and CPU. It can also close apps you name within about a second of them opening.

It is one native program (Rust, no runtime) in a single exe that is three things at once: the Windows service, its own installer, and a manager window.

## How it works

The service is one thread running one loop. Each tick (1 second by default) it runs the **app closer**; every `IntervalSeconds` (120 by default) it also runs a **scan**.

### Scan

Each scan lists the running services that own their own process, are non-interactive and accept a stop command. (Services sharing a process, such as most `svchost` ones, are never touched.) A service is skipped if any of these apply:

- its name or display name matches the built-in deny list (security software, VPNs, remote access, databases, GPU/audio/peripheral drivers, printing, cloud sync, password managers, and the program itself) or your own `Deny` list, or you set `Only` entries and it matches none;
- it has already been stopped `MaxStopsPerService` times;
- its process has a listening TCP port;
- it is disabled, its exe is under the Windows folder, or its publisher is Microsoft;
- another running service depends on it;
- it uses less RAM than `MinServiceMemoryMB`.

For the services left, it measures CPU time and disk bytes each scan and compares with the previous scan. A scan is **idle** if CPU used is at most `CpuMsThreshold` and bytes moved at most `IoBytesThreshold`; any busier scan resets the streak. While a service is idle its memory is trimmed (`TrimIdleServices`). After `IdleCycles` idle scans in a row (15 x 120 s = 30 minutes by default) it is stopped.

### Stopping and dry-run

In **dry-run** (the default) nothing is stopped; the log only says `DRY-RUN would stop ...`. With dry-run off, it sends the service a stop request and waits up to 30 seconds for it to finish (the loop pauses meanwhile). Every stop attempt, successful or not, counts against `MaxStopsPerService`; the counts are saved so a service that keeps coming back is eventually left alone, even after a reboot.

### App closer

Each tick, if `CloseApp` entries exist, running processes whose name matches are terminated. Names have no `.exe`; `*` and `?` wildcards work, and `msedge` does not match `msedgewebview2` while `msedge*` does. Critical Windows processes (`lsass`, `csrss`, `svchost`, `explorer`, ...) are never touched, even by a wildcard. The closer ignores dry-run. With no `CloseApp` entries it does nothing.

### Staying small

One thread, no runtime, no regex library, and a hand-written wildcard matcher. The process trims its own working set after every scan, so it stays at roughly 1 MB of RAM.

## The manager window

Double-click the exe. Windows asks for administrator approval, then a window opens with three pages:

| Page | What it does |
|------|--------------|
| **Setup** | Shows whether the service is installed and running, and its mode. Buttons: Install / Update, Uninstall, Start, Stop. |
| **Settings** | Every option below as checkboxes, number boxes and lists. Save applies it; the running service picks changes up within a few seconds. Turning dry-run off asks for confirmation. |
| **Log** | The most recent entries of the log, with Refresh and a button that opens the data folder. |

**Install / Update** copies the exe to `%ProgramFiles%\IdleServiceKiller`, registers a delayed-start automatic service (LocalSystem, restarted 60 s after a crash), and adds an *Apps & features* entry. A fresh install starts in dry-run. Installing again upgrades in place and keeps your settings. **Uninstall** removes the service and the program folder but keeps the settings and log.

From an administrator terminal: `IdleServiceKiller.exe --install`, `--install --live`, `--uninstall`.

## Settings

Stored as `key=value` lines in `config.txt`; `#` starts a comment; invalid values are ignored.

| Key | Default | Meaning |
|-----|---------|---------|
| `DryRun` | `true` | `true` = only log. Does not affect `CloseApp`. |
| `IntervalSeconds` | `120` | Seconds between scans (minimum 10). |
| `IdleCycles` | `15` | Consecutive idle scans before stopping. |
| `CpuMsThreshold` | `50` | Max CPU ms per scan to count as idle. |
| `IoBytesThreshold` | `65536` | Max bytes read + written per scan to count as idle. |
| `MaxStopsPerService` | `2` | Stops allowed per service before it is left alone. |
| `MinServiceMemoryMB` | `0` | Only consider services using at least this much RAM (0 = any). |
| `TrimIdleServices` | `true` | Trim the memory of idle services before they are stopped. |
| `Deny=pattern` | | Never touch matching services (name or display name; `*` and `?`). Repeatable. |
| `Only=pattern` | | If any are set, only matching services are considered. Repeatable. |
| `CloseApp=name` | | Terminate this process when it appears. Repeatable. |
| `CloseAppsIntervalMs` | `1000` | How often the app closer runs (minimum 250). |

## Files

In `%ProgramData%\IdleServiceKiller\`:

| File | Contents |
|------|----------|
| `config.txt` | The settings. Saving from the window rewrites the whole file. |
| `log.txt` | What it found, stopped or closed. Rotates at 512 KB to `log.txt.old`. |
| `stopped.txt` | How many times each service has been stopped. |

## Build

Needs [Rust](https://rustup.rs) and the Visual Studio C++ Build Tools.

```powershell
cd source
powershell -File build.ps1
```

The code is `source/src/main.rs`. The build writes the signed installer to a git-ignored `installer` folder at the top level.
