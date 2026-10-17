// IdleServiceKiller - stops background Windows services that are demonstrably idle.
#![cfg_attr(not(test), windows_subsystem = "windows")]
// One thread, no runtime, no regex: the resident set stays around 1 MB (trimmed after every scan).
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write;
use std::mem::{size_of, zeroed};
use std::os::windows::io::IntoRawHandle;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};
use std::{env, fs, thread};

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable;
use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows_sys::Win32::Graphics::Gdi::{CreateFontW, GetDC, GetDeviceCaps, ReleaseDC, UpdateWindow, COLOR_BTNFACE, HBRUSH, HFONT, LOGPIXELSX};
use windows_sys::Win32::System::Console::{AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{InitCommonControlsEx, BST_CHECKED, BST_UNCHECKED, EM_SCROLLCARET, EM_SETLIMITTEXT, EM_SETSEL, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::ProcessStatus::*;
use windows_sys::Win32::System::Registry::{RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegSetValueExW, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_SZ};
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Threading::*;

const SVC: &str = "IdleServiceKiller";

// Matched against service name AND display name. Deliberately conservative.
const BUILT_IN_DENY: &[&str] = &[
    "*defender*", "*antivirus*", "*anti-virus*", "*security*", "*firewall*", "*malware*", "*endpoint*",
    "*mcafee*", "*norton*", "*kaspersky*", "*avast*", "*avg*", "*eset*", "*bitdefender*", "*sophos*",
    "*crowdstrike*", "*sentinel*", "*vpn*", "*wireguard*", "*tailscale*", "*zerotier*",
    "*ssh*", "*remote*", "*anydesk*", "*teamviewer*", "*docker*", "*vmware*", "*virtualbox*", "*vbox*",
    "*hyper-v*", "*sql*", "*backup*", "*nvidia*", "*intel*", "*amd*", "*realtek*", "*razer*",
    "*logitech*", "*corsair*", "*steelseries*", "*audio*", "*bluetooth*", "*print*",
    "*onedrive*", "*dropbox*", "*sync*", "*password*", "*bitwarden*", "*1password*", "*lastpass*",
    "idleservicekiller",
];

// CloseApp wildcards must never be able to take the machine down.
const PROTECTED_PROCS: &[&str] = &[
    "system", "registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "fontdrvhost",
    "dwm", "explorer", "idleservicekiller",
];

const DEFAULT_TEXT: &str = "\
# IdleServiceKiller configuration (re-read automatically, no restart needed)
#
# DryRun=true only logs what WOULD be stopped. Set to false to actually stop services.
DryRun=true
IntervalSeconds=120
# A service must be idle for this many samples in a row before it is stopped.
IdleCycles=15
CpuMsThreshold=50
IoBytesThreshold=65536
# If a service keeps coming back after being stopped this many times, leave it alone.
MaxStopsPerService=2
# Only consider services whose process uses at least this much RAM (MB). 0 = any size.
MinServiceMemoryMB=0
# Trim the working set of services that are idle but not (yet) stopped.
TrimIdleServices=true

# Never touch services whose name or display name matches (wildcards ok). Repeat the line as needed.
# Built-in protections (Microsoft services, anything under C:\\Windows, security software, VPNs,
# hardware vendors, services with a listening port or running dependents) always apply.
#Deny=MyImportantService
#Deny=*plex*

# If you add any 'Only' lines, ONLY services matching them are ever considered.
#Only=GoogleUpdater*
#Only=Adobe*

# Processes (name without .exe, wildcards ok) that are killed within ~1 second of appearing.
# Independent of DryRun. 'msedge' does not touch 'msedgewebview2'; 'msedge*' does.
#CloseApp=msedge
#CloseAppsIntervalMs=1000
";

// ---- config ------------------------------------------------------------------------------

#[derive(Clone)]
struct Cfg {
    dry: bool,
    interval: u64,
    idle_cycles: u32,
    cpu_ms: u64,
    io_bytes: u64,
    max_stops: u32,
    min_mb: u64,
    trim: bool,
    close_ms: u64,
    deny: Vec<String>,
    only: Vec<String>,
    close: Vec<String>,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg {
            dry: true, interval: 120, idle_cycles: 15, cpu_ms: 50, io_bytes: 65536, max_stops: 2, min_mb: 0,
            trim: true, close_ms: 1000, deny: vec![], only: vec![], close: vec![],
        }
    }
}

fn parse_cfg(text: &str) -> Cfg {
    let mut c = Cfg::default();
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let line = raw.trim();
        let Some((k, v)) = line.split_once('=') else { continue };
        if line.starts_with('#') || k.trim().is_empty() {
            continue;
        }
        let v = v.trim();
        let n = v.parse::<u64>().ok();
        match k.trim().to_lowercase().as_str() {
            "dryrun" => c.dry = !v.eq_ignore_ascii_case("false"),
            "trimidleservices" => c.trim = !v.eq_ignore_ascii_case("false"),
            "intervalseconds" => if let Some(n) = n.filter(|&n| n >= 10) { c.interval = n },
            "idlecycles" => if let Some(n) = n.filter(|&n| n >= 1) { c.idle_cycles = n as u32 },
            "cpumsthreshold" => if let Some(n) = n { c.cpu_ms = n },
            "iobytesthreshold" => if let Some(n) = n { c.io_bytes = n },
            "maxstopsperservice" => if let Some(n) = n.filter(|&n| n >= 1) { c.max_stops = n as u32 },
            "minservicememorymb" => if let Some(n) = n { c.min_mb = n },
            "closeappsintervalms" => if let Some(n) = n.filter(|&n| n >= 250) { c.close_ms = n },
            "deny" if !v.is_empty() => c.deny.push(v.to_lowercase()),
            "only" if !v.is_empty() => c.only.push(v.to_lowercase()),
            "closeapp" => {
                let v = v.to_lowercase();
                let v = v.strip_suffix(".exe").unwrap_or(&v);
                if !v.is_empty() {
                    c.close.push(v.to_string());
                }
            }
            _ => {}
        }
    }
    c
}

fn load_cfg(path: &PathBuf) -> Cfg {
    match fs::read(path) {
        Ok(b) => parse_cfg(&String::from_utf8_lossy(&b)),
        Err(_) => {
            let _ = fs::write(path, DEFAULT_TEXT);
            Cfg::default()
        }
    }
}

// ---- small helpers -----------------------------------------------------------------------

// Case-sensitive wildcard match (* and ?) on bytes; callers lowercase both sides.
fn glob(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, usize::MAX, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn any_match<S: AsRef<str>>(pats: &[S], texts: &[&str]) -> bool {
    pats.iter().any(|p| texts.iter().any(|t| glob(p.as_ref().as_bytes(), t.as_bytes())))
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

unsafe fn from_w(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

// "\"C:\\x y\\a.exe\" -arg", "\\??\\C:\\a.sys", "%SystemRoot%\\a.exe /k" -> the bare exe path.
fn exe_path(raw: &str) -> String {
    let src = w(raw.trim());
    let mut buf = [0u16; 1024];
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let mut s = if n > 0 && n <= buf.len() { String::from_utf16_lossy(&buf[..n - 1]) } else { raw.trim().to_string() };
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    }
    if let Some(r) = s.strip_prefix('"') {
        return r.split('"').next().unwrap_or("").to_string();
    }
    match s.to_ascii_lowercase().find(".exe") {
        Some(i) => s[..i + 4].to_string(),
        None => s,
    }
}

unsafe fn company(exe: &str) -> String {
    let f = w(exe);
    let mut h = 0u32;
    let size = GetFileVersionInfoSizeW(f.as_ptr(), &mut h);
    if size == 0 {
        return String::new();
    }
    let mut buf = vec![0u8; size as usize];
    if GetFileVersionInfoW(f.as_ptr(), 0, size, buf.as_mut_ptr() as *mut c_void) == 0 {
        return String::new();
    }
    let (mut p, mut len): (*mut c_void, u32) = (null_mut(), 0);
    let lang = w("\\VarFileInfo\\Translation");
    if VerQueryValueW(buf.as_ptr() as *const c_void, lang.as_ptr(), &mut p, &mut len) == 0 || len < 4 {
        return String::new();
    }
    let t = p as *const u16;
    let key = w(&format!("\\StringFileInfo\\{:04x}{:04x}\\CompanyName", *t, *t.add(1)));
    if VerQueryValueW(buf.as_ptr() as *const c_void, key.as_ptr(), &mut p, &mut len) == 0 {
        return String::new();
    }
    from_w(p as *const u16)
}

fn listener_pids() -> HashSet<u32> {
    let mut set = HashSet::new();
    for (af, row) in [(2u32, 24usize), (23, 56)] {
        unsafe {
            let mut size = 0u32;
            GetExtendedTcpTable(null_mut(), &mut size, 0, af, 3, 0); // 3 = TCP_TABLE_OWNER_PID_LISTENER
            if size == 0 {
                continue;
            }
            let mut buf = vec![0u32; (size as usize + 4096) / 4];
            size = (buf.len() * 4) as u32;
            if GetExtendedTcpTable(buf.as_mut_ptr() as *mut c_void, &mut size, 0, af, 3, 0) != 0 {
                continue;
            }
            // Row = fixed DWORDs, PID last: the table is dwNumEntries followed by `row`-byte rows.
            for i in 0..buf[0] as usize {
                set.insert(buf[1 + i * row / 4 + row / 4 - 1]);
            }
        }
    }
    set
}

fn trim_working_set(h: HANDLE) {
    unsafe { SetProcessWorkingSetSize(h, usize::MAX, usize::MAX) };
}

struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

struct Ph(HANDLE);
impl Drop for Ph {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn ft(f: FILETIME) -> u64 {
    ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64
}

struct Svc {
    name: String,
    display: String,
    pid: u32,
}

// Running, own-process, non-interactive services that accept a stop request.
unsafe fn enum_services(scm: SC_HANDLE) -> Vec<Svc> {
    let mut out = Vec::new();
    let mut buf = vec![0u64; 2048];
    let mut resume = 0u32;
    loop {
        let (mut need, mut count) = (0u32, 0u32);
        let ok = EnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buf.as_mut_ptr() as *mut u8,
            (buf.len() * 8) as u32, &mut need, &mut count, &mut resume, null(),
        );
        if ok == 0 && GetLastError() != ERROR_MORE_DATA {
            break;
        }
        let items = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..count as usize {
            let e = &*items.add(i);
            let s = &e.ServiceStatusProcess;
            if s.dwServiceType == SERVICE_WIN32_OWN_PROCESS && s.dwCurrentState == SERVICE_RUNNING
                && s.dwControlsAccepted & SERVICE_ACCEPT_STOP != 0
            {
                out.push(Svc { name: from_w(e.lpServiceName), display: from_w(e.lpDisplayName), pid: s.dwProcessId });
            }
        }
        if ok != 0 {
            break;
        }
        if count == 0 {
            buf.resize(need as usize / 8 + 2, 0);
        }
    }
    out
}

// (start type, image path)
unsafe fn svc_config(h: SC_HANDLE) -> Option<(u32, String)> {
    let mut need = 0u32;
    QueryServiceConfigW(h, null_mut(), 0, &mut need);
    if need == 0 {
        return None;
    }
    let mut buf = vec![0u64; need as usize / 8 + 1];
    if QueryServiceConfigW(h, buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW, need, &mut need) == 0 {
        return None;
    }
    let c = &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW);
    Some((c.dwStartType, from_w(c.lpBinaryPathName)))
}

unsafe fn has_active_dependents(h: SC_HANDLE) -> bool {
    let (mut need, mut count) = (0u32, 0u32);
    // FALSE + ERROR_MORE_DATA means there are dependents; TRUE with a null buffer means none.
    EnumDependentServicesW(h, SERVICE_ACTIVE, null_mut(), 0, &mut need, &mut count) == 0
        && GetLastError() == ERROR_MORE_DATA
}

// (cpu 100ns ticks, read+write bytes, working set bytes)
unsafe fn usage(p: HANDLE) -> Option<(u64, u64, u64)> {
    let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = zeroed();
    if GetProcessTimes(p, &mut c, &mut e, &mut k, &mut u) == 0 {
        return None;
    }
    let mut io: IO_COUNTERS = zeroed();
    if GetProcessIoCounters(p, &mut io) == 0 {
        return None;
    }
    let mut m: PROCESS_MEMORY_COUNTERS = zeroed();
    if K32GetProcessMemoryInfo(p, &mut m, size_of::<PROCESS_MEMORY_COUNTERS>() as u32) == 0 {
        return None;
    }
    Some((ft(k) + ft(u), io.ReadTransferCount + io.WriteTransferCount, m.WorkingSetSize as u64))
}

// ---- killer ------------------------------------------------------------------------------

struct Track {
    pid: u32,
    cpu: u64,
    io: u64,
    streak: u32,
}

struct Killer {
    cfg_path: PathBuf,
    log_path: PathBuf,
    state_path: PathBuf,
    echo: bool,
    cfg: Cfg,
    stamp: Option<SystemTime>,
    tracks: HashMap<String, Track>,
    stops: HashMap<String, u32>,
    last_close_log: HashMap<String, Instant>,
    windir: String,
}

impl Killer {
    fn new(cfg_path: PathBuf, echo: bool) -> Killer {
        let dir = cfg_path.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let _ = fs::create_dir_all(&dir);
        let state_path = dir.join("stopped.txt");
        let stops = fs::read_to_string(&state_path)
            .map(|t| {
                t.lines()
                    .filter_map(|l| l.rsplit_once('\t').and_then(|(k, n)| Some((k.to_string(), n.trim().parse().ok()?))))
                    .collect()
            })
            .unwrap_or_default();
        let windir = env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()).to_lowercase() + "\\";
        let mut r = Killer {
            log_path: dir.join("log.txt"), state_path, echo, cfg: Cfg::default(), stamp: None, stops, windir,
            tracks: HashMap::new(), last_close_log: HashMap::new(), cfg_path,
        };
        r.reload();
        r
    }

    fn reload(&mut self) {
        let m = fs::metadata(&self.cfg_path).and_then(|m| m.modified()).ok();
        if m.is_none() || m != self.stamp {
            self.stamp = m;
            self.cfg = load_cfg(&self.cfg_path);
        }
    }

    fn log(&self, msg: &str) {
        let t = unsafe {
            let mut t = zeroed();
            GetLocalTime(&mut t);
            t
        };
        let line = format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}  {}",
            t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, msg
        );
        if self.echo {
            println!("{line}");
        }
        if fs::metadata(&self.log_path).map(|m| m.len() > 512 * 1024).unwrap_or(false) {
            let old = self.log_path.with_extension("txt.old");
            let _ = fs::remove_file(&old);
            let _ = fs::rename(&self.log_path, old);
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&self.log_path) {
            let _ = writeln!(f, "{line}");
        }
    }

    fn save_stops(&self) {
        let text: String = self.stops.iter().map(|(k, n)| format!("{k}\t{n}\n")).collect();
        let _ = fs::write(&self.state_path, text);
    }

    // ---- fast app closer ----
    fn close_apps(&mut self) {
        self.reload();
        if self.cfg.close.is_empty() {
            return;
        }
        let mut killed: HashMap<String, u32> = HashMap::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return;
            }
            let snap = Ph(snap);
            let mut e: PROCESSENTRY32W = zeroed();
            e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
            let me = GetCurrentProcessId();
            let mut more = Process32FirstW(snap.0, &mut e);
            while more != 0 {
                let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                let lower = String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase();
                let name = lower.strip_suffix(".exe").unwrap_or(&lower);
                if e.th32ProcessID != me && !PROTECTED_PROCS.contains(&name) {
                    if let Some(pat) = self.cfg.close.iter().find(|p| glob(p.as_bytes(), name.as_bytes())) {
                        let h = OpenProcess(PROCESS_TERMINATE, 0, e.th32ProcessID);
                        if !h.is_null() {
                            let h = Ph(h);
                            if TerminateProcess(h.0, 1) != 0 {
                                *killed.entry(pat.clone()).or_default() += 1;
                            }
                        }
                    }
                }
                more = Process32NextW(snap.0, &mut e);
            }
        }
        for (name, n) in killed {
            let due = self.last_close_log.get(&name).map_or(true, |t| t.elapsed().as_secs() > 60);
            if due {
                self.log(&format!("Closed {name} ({n} process{})", if n == 1 { "" } else { "es" }));
                self.last_close_log.insert(name, Instant::now());
            }
        }
    }

    // ---- one scan ----
    fn scan(&mut self) {
        self.reload();
        let cfg = self.cfg.clone();
        let listeners = listener_pids();
        let mut seen = HashSet::new();
        let mut companies: HashMap<String, String> = HashMap::new();
        unsafe {
            let scm = OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE);
            if scm.is_null() {
                self.log("error: cannot open the service manager (run as administrator / SYSTEM)");
                return;
            }
            let scm = Sc(scm);
            for s in enum_services(scm.0) {
                self.evaluate(&scm, &s, &cfg, &listeners, &mut seen, &mut companies);
            }
        }
        self.tracks.retain(|k, _| seen.contains(k));
        trim_working_set(unsafe { GetCurrentProcess() });
    }

    unsafe fn evaluate(
        &mut self, scm: &Sc, s: &Svc, cfg: &Cfg, listeners: &HashSet<u32>, seen: &mut HashSet<String>,
        companies: &mut HashMap<String, String>,
    ) {
        let key = s.name.to_lowercase();
        let names = [key.as_str(), &s.display.to_lowercase()];
        if any_match(BUILT_IN_DENY, &names) || any_match(&cfg.deny, &names) {
            return;
        }
        if !cfg.only.is_empty() && !any_match(&cfg.only, &names) {
            return;
        }
        let stop_count = self.stops.get(&key).copied().unwrap_or(0);
        if stop_count >= cfg.max_stops || s.pid == 0 || listeners.contains(&s.pid) {
            return;
        }

        let h = OpenServiceW(
            scm.0, w(&s.name).as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_ENUMERATE_DEPENDENTS,
        );
        if h.is_null() {
            return;
        }
        let svc = Sc(h);
        let Some((start, image)) = svc_config(svc.0) else { return };
        if start == SERVICE_DISABLED {
            return;
        }
        let exe = exe_path(&image);
        if exe.to_lowercase().starts_with(&self.windir) {
            return;
        }
        let co = companies.entry(exe.clone()).or_insert_with(|| company(&exe));
        if co.to_lowercase().contains("microsoft") || has_active_dependents(svc.0) {
            return;
        }

        let Ok(p) = (match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, 0, s.pid) {
            h if h.is_null() => Err(()),
            h => Ok(Ph(h)),
        }) else { return };
        let Some((cpu, io, ws)) = usage(p.0) else { return };
        if ws < cfg.min_mb << 20 {
            return;
        }

        seen.insert(key.clone());
        let t = match self.tracks.get_mut(&key) {
            Some(t) if t.pid == s.pid => t,
            _ => {
                // First sample is the baseline.
                self.tracks.insert(key, Track { pid: s.pid, cpu, io, streak: 0 });
                return;
            }
        };
        let idle = cpu.saturating_sub(t.cpu) / 10_000 <= cfg.cpu_ms && io.saturating_sub(t.io) <= cfg.io_bytes;
        (t.cpu, t.io) = (cpu, io);
        t.streak = if idle { t.streak + 1 } else { 0 };
        let streak = t.streak;

        if idle && cfg.trim {
            trim_working_set(p.0);
        }
        if streak < cfg.idle_cycles {
            return;
        }
        let desc = format!("{} ({}, {})", s.name, s.display, exe);
        if cfg.dry {
            if streak == cfg.idle_cycles {
                self.log(&format!("DRY-RUN would stop {desc} [{} MB]", ws >> 20));
            }
            return;
        }

        self.log(&format!("Stopping idle service {desc} [{} MB]", ws >> 20));
        let h = OpenServiceW(scm.0, w(&s.name).as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if h.is_null() {
            self.log(&format!("Cannot open {} for stop (access denied?)", s.name));
            return;
        }
        let svc = Sc(h);
        let mut st: SERVICE_STATUS = zeroed();
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st);
        // shortcut: blocks the loop up to 30 s while the service stops, move to a worker if that ever matters.
        for _ in 0..120 {
            if QueryServiceStatus(svc.0, &mut st) == 0 || st.dwCurrentState == SERVICE_STOPPED {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        self.stops.insert(key.clone(), stop_count + 1);
        self.save_stops();
        self.tracks.remove(&key);
        self.log(&format!("Stopped {} (stop #{})", s.name, stop_count + 1));
    }
}

// ---- main loop + service plumbing ---------------------------------------------------------

// `wait(ms)` returns true when it is time to quit.
fn run(r: &mut Killer, first_scan_in: Duration, wait: impl Fn(u64) -> bool) {
    let mut next_scan = Instant::now() + first_scan_in;
    loop {
        if wait(r.cfg.close_ms) {
            return;
        }
        r.close_apps();
        if Instant::now() >= next_scan {
            r.scan();
            next_scan = Instant::now() + Duration::from_secs(r.cfg.interval);
        }
    }
}

static CFG_PATH: OnceLock<PathBuf> = OnceLock::new();
static STOP_EVT: AtomicUsize = AtomicUsize::new(0);
static STATUS_H: AtomicUsize = AtomicUsize::new(0);

unsafe fn set_status(state: u32, accept: u32) {
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS, dwCurrentState: state, dwControlsAccepted: accept,
        dwWin32ExitCode: 0, dwServiceSpecificExitCode: 0, dwCheckPoint: 0, dwWaitHint: 0,
    };
    SetServiceStatus(STATUS_H.load(Relaxed) as _, &st);
}

unsafe extern "system" fn ctrl_handler(ctrl: u32, _: u32, _: *mut c_void, _: *mut c_void) -> u32 {
    if ctrl == SERVICE_CONTROL_STOP {
        set_status(SERVICE_STOP_PENDING, 0);
        SetEvent(STOP_EVT.load(Relaxed) as _);
    }
    0
}

unsafe extern "system" fn service_main(_: u32, _: *mut PWSTR) {
    let h = RegisterServiceCtrlHandlerExW(w(SVC).as_ptr(), Some(ctrl_handler), null());
    if h.is_null() {
        return;
    }
    STATUS_H.store(h as usize, Relaxed);
    let evt = CreateEventW(null(), 1, 0, null());
    STOP_EVT.store(evt as usize, Relaxed);
    set_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP);

    let mut r = Killer::new(CFG_PATH.get().unwrap().clone(), false);
    r.log(&format!("Service started. DryRun={}", r.cfg.dry));
    trim_working_set(GetCurrentProcess());
    run(&mut r, Duration::from_secs(30), |ms| WaitForSingleObject(evt, ms as u32) == WAIT_OBJECT_0);
    r.log("Service stopped.");
    set_status(SERVICE_STOPPED, 0);
}

// ---- self-installer (double-click the exe, or --install / --uninstall) -------------------------

fn data_cfg_path() -> PathBuf {
    PathBuf::from(env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join(SVC).join("config.txt")
}

fn program_dir() -> PathBuf {
    PathBuf::from(env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into())).join(SVC)
}

const ARP: &str = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IdleServiceKiller";

// "Apps & features" entry; its Uninstall button opens the manager window (which elevates itself).
fn set_arp(dir: &PathBuf, exe: &PathBuf) {
    unsafe {
        let mut k = null_mut();
        if RegCreateKeyExW(HKEY_LOCAL_MACHINE, w(ARP).as_ptr(), 0, null(), 0, KEY_WRITE, null(), &mut k, null_mut()) != 0 {
            return;
        }
        let exe = exe.to_string_lossy();
        for (name, val) in [
            ("DisplayName", "Idle Service Killer".to_string()),
            ("DisplayVersion", env!("CARGO_PKG_VERSION").to_string()),
            ("InstallLocation", dir.to_string_lossy().into_owned()),
            ("DisplayIcon", exe.to_string()),
            ("UninstallString", format!("\"{exe}\"")),
        ] {
            let v = w(&val);
            RegSetValueExW(k, w(name).as_ptr(), 0, REG_SZ, v.as_ptr() as *const u8, (v.len() * 2) as u32);
        }
        RegCloseKey(k);
    }
}

fn is_admin() -> bool {
    unsafe {
        let mut t = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) == 0 {
            return false;
        }
        let t = Ph(t);
        let (mut e, mut n) = (TOKEN_ELEVATION { TokenIsElevated: 0 }, 0u32);
        GetTokenInformation(t.0, TokenElevation, &mut e as *mut _ as *mut c_void, size_of::<TOKEN_ELEVATION>() as u32, &mut n) != 0
            && e.TokenIsElevated != 0
    }
}

// Stops (waiting up to 30 s) and deletes the service if it exists. Returns whether it existed.
unsafe fn remove_service(scm: &Sc) -> bool {
    let h = OpenServiceW(scm.0, w(SVC).as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if h.is_null() {
        return false;
    }
    let svc = Sc(h);
    let mut st: SERVICE_STATUS = zeroed();
    ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st);
    for _ in 0..120 {
        if QueryServiceStatus(svc.0, &mut st) == 0 || st.dwCurrentState == SERVICE_STOPPED {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    DeleteService(svc.0);
    true
}

fn set_dry_run(path: &PathBuf, dry: bool) {
    let text = fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let line = format!("DryRun={dry}");
    let mut found = false;
    let mut out: Vec<String> = text
        .trim_start_matches('\u{feff}')
        .lines()
        .map(|l| {
            if l.trim().to_lowercase().starts_with("dryrun=") {
                found = true;
                line.clone()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        out.push(line);
    }
    let _ = fs::write(path, out.join("\r\n") + "\r\n");
}

fn install(live: bool) -> Result<String, String> {
    let dir = program_dir();
    let target = dir.join(format!("{SVC}.exe"));
    let cfg = data_cfg_path();
    unsafe {
        let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS));
        if scm.0.is_null() {
            return Err(format!("cannot open the service manager (error {})", GetLastError()));
        }
        remove_service(&scm); // upgrade in place: the old exe must be stopped before it can be replaced

        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let me = env::current_exe().map_err(|e| e.to_string())?;
        if !me.to_string_lossy().eq_ignore_ascii_case(&target.to_string_lossy()) {
            fs::copy(&me, &target).map_err(|e| format!("copy to {}: {e}", target.display()))?;
        }

        // A fresh install is dry-run; an existing setting is only changed by --live.
        let fresh = !cfg.exists();
        Killer::new(cfg.clone(), false); // creates the default config
        if live || fresh {
            set_dry_run(&cfg, !live);
        }

        let bin = w(&format!("\"{}\"", target.display()));
        let mut h = null_mut();
        // The previous service may still be marked for deletion for a moment.
        for _ in 0..20 {
            h = CreateServiceW(
                scm.0, w(SVC).as_ptr(), w("Idle Service Killer").as_ptr(), SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin.as_ptr(), null(), null_mut(), null(), null(), null(),
            );
            if !h.is_null() || GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        if h.is_null() {
            return Err(format!("cannot create the service (error {})", GetLastError()));
        }
        let svc = Sc(h);
        set_arp(&dir, &target);

        // Delayed start keeps boot fast; restart 60 s after a crash, resetting the failure count daily.
        let delayed = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: 1 };
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed as *const _ as *const c_void);
        let mut desc = w("Stops idle third-party background services to save RAM/CPU.");
        let d = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, &d as *const _ as *const c_void);
        let mut act = SC_ACTION { Type: SC_ACTION_RESTART, Delay: 60_000 };
        let f = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86_400, lpRebootMsg: null_mut(), lpCommand: null_mut(), cActions: 1, lpsaActions: &mut act,
        };
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_FAILURE_ACTIONS, &f as *const _ as *const c_void);

        if StartServiceW(svc.0, 0, null()) == 0 {
            return Err(format!("installed, but the service did not start (error {})", GetLastError()));
        }
    }
    let dry = parse_cfg(&String::from_utf8_lossy(&fs::read(&cfg).unwrap_or_default())).dry;
    Ok(format!(
        "Installed and started.\n  Mode:   {}\n  Config: {}\n  Log:    {}\n  Exe:    {}",
        if dry { "DRY-RUN (log only)" } else { "LIVE" }, cfg.display(), cfg.with_file_name("log.txt").display(), target.display()
    ))
}

fn uninstall() -> Result<String, String> {
    unsafe {
        let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS));
        if scm.0.is_null() {
            return Err(format!("cannot open the service manager (error {})", GetLastError()));
        }
        let existed = remove_service(&scm);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, w(ARP).as_ptr());
        if !existed {
            return Ok("Not installed - nothing to remove.".into());
        }
    }
    // Fails harmlessly if this very exe is the installed copy; the folder is then just left behind.
    let _ = fs::remove_dir_all(program_dir());
    Ok(format!("Removed. Config and logs kept in {} (delete by hand if unwanted).", data_cfg_path().parent().unwrap().display()))
}

// ---- manager window (double-click the exe): Setup / Settings / Log ---------------------------

const ID_INSTALL: usize = 103;
const ID_UNINSTALL: usize = 104;
const ID_CLOSE: usize = 105;
const ID_START: usize = 106;
const ID_STOP: usize = 107;
const ID_SAVE: usize = 108;
const ID_REFRESH: usize = 109;
const ID_OPEN: usize = 113;
const ID_PAGE: usize = 120; // 120, 121, 122 = Setup, Settings, Log

struct Ui {
    pages: [Vec<HWND>; 3],
    status: HWND,
    result: HWND,
    setup_btns: Vec<HWND>,
    dry: HWND,
    trim: HWND,
    nums: Vec<HWND>,  // interval, idle cycles, cpu, io, max stops, min MB, closer ms
    lists: Vec<HWND>, // deny, only, close
    saved: HWND,
    log: HWND,
}

thread_local! { static UI: RefCell<Option<Ui>> = const { RefCell::new(None) }; }

fn ui<R>(f: impl FnOnce(&Ui) -> R) -> R {
    UI.with(|u| f(u.borrow().as_ref().expect("window not built yet")))
}

unsafe fn set_text(h: HWND, s: &str) {
    SetWindowTextW(h, w(&s.replace('\n', "\r\n")).as_ptr());
}

unsafe fn get_text(h: HWND) -> String {
    let n = GetWindowTextLengthW(h) as usize;
    let mut b = vec![0u16; n + 1];
    let r = GetWindowTextW(h, b.as_mut_ptr(), (n + 1) as i32) as usize;
    String::from_utf16_lossy(&b[..r])
}

fn cfg_now() -> Cfg {
    parse_cfg(&String::from_utf8_lossy(&fs::read(data_cfg_path()).unwrap_or_default()))
}

fn cfg_is_dry() -> bool {
    cfg_now().dry
}

// The settings window rewrites the whole file from its fields (explanatory comments are not preserved).
fn cfg_to_text(c: &Cfg) -> String {
    let mut t = format!(
        "# IdleServiceKiller configuration, written by the settings window.\nDryRun={}\nIntervalSeconds={}\nIdleCycles={}\n\
         CpuMsThreshold={}\nIoBytesThreshold={}\nMaxStopsPerService={}\nMinServiceMemoryMB={}\nTrimIdleServices={}\nCloseAppsIntervalMs={}\n",
        c.dry, c.interval, c.idle_cycles, c.cpu_ms, c.io_bytes, c.max_stops, c.min_mb, c.trim, c.close_ms
    );
    for (k, list) in [("Deny", &c.deny), ("Only", &c.only), ("CloseApp", &c.close)] {
        for v in list {
            t += &format!("{k}={v}\n");
        }
    }
    t
}

unsafe fn refresh_status() {
    let mut text = "Status: not installed".to_string();
    let scm = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
    if !scm.is_null() {
        let scm = Sc(scm);
        let h = OpenServiceW(scm.0, w(SVC).as_ptr(), SERVICE_QUERY_STATUS);
        if !h.is_null() {
            let svc = Sc(h);
            let mut st: SERVICE_STATUS = zeroed();
            QueryServiceStatus(svc.0, &mut st);
            text = format!(
                "Status: installed, {} ({})",
                if st.dwCurrentState == SERVICE_RUNNING { "running" } else { "stopped" },
                if cfg_is_dry() { "dry-run" } else { "live" }
            );
        }
    }
    set_text(ui(|u| u.status), &text);
}

unsafe fn start_stop(start: bool) -> Result<String, String> {
    let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT));
    let h = if scm.0.is_null() { null_mut() } else { OpenServiceW(scm.0, w(SVC).as_ptr(), SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS) };
    if h.is_null() {
        return Err("the service is not installed, or this needs administrator rights".into());
    }
    let svc = Sc(h);
    let mut st: SERVICE_STATUS = zeroed();
    if start {
        if StartServiceW(svc.0, 0, null()) == 0 && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(format!("could not start (error {})", GetLastError()));
        }
    } else {
        ControlService(svc.0, SERVICE_CONTROL_STOP, &mut st);
    }
    let want = if start { SERVICE_RUNNING } else { SERVICE_STOPPED };
    for _ in 0..40 {
        if QueryServiceStatus(svc.0, &mut st) == 0 || st.dwCurrentState == want {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    Ok(if start { "Service started." } else { "Service stopped." }.into())
}

unsafe fn gui_task(f: impl FnOnce() -> Result<String, String>, working: &str) {
    let (btns, result) = ui(|u| (u.setup_btns.clone(), u.result));
    for &b in &btns {
        EnableWindow(b, 0);
    }
    set_text(result, working);
    UpdateWindow(result); // repaint now: some tasks block for up to 30 s
    set_text(result, &f().unwrap_or_else(|e| format!("Failed: {e}")));
    for &b in &btns {
        EnableWindow(b, 1);
    }
    refresh_status();
}

unsafe fn fill_settings(c: &Cfg) {
    let (dry, trim, nums, lists) = ui(|u| (u.dry, u.trim, u.nums.clone(), u.lists.clone()));
    SendMessageW(dry, BM_SETCHECK, (if c.dry { BST_CHECKED } else { BST_UNCHECKED }) as usize, 0);
    SendMessageW(trim, BM_SETCHECK, (if c.trim { BST_CHECKED } else { BST_UNCHECKED }) as usize, 0);
    let vals = [c.interval, c.idle_cycles as u64, c.cpu_ms, c.io_bytes, c.max_stops as u64, c.min_mb, c.close_ms];
    for (h, v) in nums.iter().zip(vals) {
        set_text(*h, &v.to_string());
    }
    for (h, l) in lists.iter().zip([&c.deny, &c.only, &c.close]) {
        set_text(*h, &l.join("\n"));
    }
}

unsafe fn save_settings(hwnd: HWND) {
    let (dry, trim, nums, lists, saved) = ui(|u| (u.dry, u.trim, u.nums.clone(), u.lists.clone(), u.saved));
    let chk = |h: HWND| SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED as isize;
    if !chk(dry) && cfg_is_dry() {
        let msg = w("Dry-run is off: idle services will really be stopped.\n\nSave these settings?");
        if MessageBoxW(hwnd, msg.as_ptr(), w("Idle Service Killer").as_ptr(), 0x34) != 6 {
            return;
        }
    }
    let mut t = format!("DryRun={}\nTrimIdleServices={}\n", chk(dry), chk(trim));
    let keys = ["IntervalSeconds", "IdleCycles", "CpuMsThreshold", "IoBytesThreshold", "MaxStopsPerService", "MinServiceMemoryMB", "CloseAppsIntervalMs"];
    for (k, h) in keys.iter().zip(&nums) {
        t += &format!("{k}={}\n", get_text(*h).trim());
    }
    for (k, h) in ["Deny", "Only", "CloseApp"].iter().zip(&lists) {
        for l in get_text(*h).lines().map(str::trim).filter(|l| !l.is_empty()) {
            t += &format!("{k}={l}\n");
        }
    }
    let c = parse_cfg(&t); // clamps invalid numbers back to valid ones
    let path = data_cfg_path();
    let res = fs::create_dir_all(path.parent().unwrap()).and_then(|_| fs::write(&path, cfg_to_text(&c)));
    fill_settings(&c);
    set_text(saved, &match res {
        Ok(_) => "Saved. The running service picks this up within a few seconds.".to_string(),
        Err(e) => format!("Could not save: {e}"),
    });
    refresh_status();
}

unsafe fn refresh_log() {
    let h = ui(|u| u.log);
    let text = match fs::read(data_cfg_path().with_file_name("log.txt")) {
        Ok(b) => {
            let tail = &b[b.len().saturating_sub(64 * 1024)..];
            let s = String::from_utf8_lossy(tail).into_owned();
            if tail.len() < b.len() { s.split_once('\n').map(|x| x.1.to_string()).unwrap_or(s) } else { s }
        }
        Err(_) => "No log yet. It appears once the service has run.".to_string(),
    };
    set_text(h, &text);
    let n = GetWindowTextLengthW(h) as usize;
    SendMessageW(h, EM_SETSEL, n, n as isize);
    SendMessageW(h, EM_SCROLLCARET, 0, 0);
}

unsafe fn show_page(n: usize) {
    let pages = ui(|u| u.pages.clone());
    for (i, p) in pages.iter().enumerate() {
        for &h in p {
            ShowWindow(h, if i == n { SW_SHOW } else { SW_HIDE });
        }
    }
    if n == 2 {
        refresh_log();
    }
}

unsafe extern "system" fn gui_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            match wp & 0xffff {
                ID_INSTALL => gui_task(|| install(false), "Installing..."),
                ID_UNINSTALL => gui_task(uninstall, "Removing..."),
                ID_START => gui_task(|| start_stop(true), "Starting..."),
                ID_STOP => gui_task(|| start_stop(false), "Stopping..."),
                ID_SAVE => save_settings(hwnd),
                ID_REFRESH => refresh_log(),
                ID_OPEN => {
                    let dir = data_cfg_path().parent().unwrap().to_path_buf();
                    let _ = fs::create_dir_all(&dir);
                    ShellExecuteW(null_mut(), w("open").as_ptr(), w(&dir.to_string_lossy()).as_ptr(), null(), null(), SW_SHOWNORMAL);
                }
                ID_CLOSE => {
                    DestroyWindow(hwnd);
                }
                id if (ID_PAGE..ID_PAGE + 3).contains(&id) => show_page(id - ID_PAGE),
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

unsafe fn gui() {
    InitCommonControlsEx(&INITCOMMONCONTROLSEX { dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32, dwICC: ICC_STANDARD_CLASSES });
    let hinst = GetModuleHandleW(null());
    let dc = GetDC(null_mut());
    let dpi = GetDeviceCaps(dc, LOGPIXELSX as i32);
    ReleaseDC(null_mut(), dc);
    let s = |v: i32| v * dpi / 96;
    let font = |pt: i32, weight: i32, face: &str| CreateFontW(-(pt * dpi / 72), 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, w(face).as_ptr());
    let (normal, big, mono) = (font(9, 400, "Segoe UI"), font(16, 700, "Segoe UI"), font(9, 400, "Consolas"));

    let cls = w("IdleServiceKillerSetup");
    let wc = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32, style: 0, lpfnWndProc: Some(gui_proc), cbClsExtra: 0, cbWndExtra: 0,
        hInstance: hinst, hIcon: null_mut(), hCursor: LoadCursorW(null_mut(), IDC_ARROW),
        hbrBackground: (COLOR_BTNFACE + 1) as usize as HBRUSH, lpszMenuName: null(), lpszClassName: cls.as_ptr(),
        hIconSm: null_mut(),
    };
    RegisterClassExW(&wc);

    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    let mut rc = RECT { left: 0, top: 0, right: s(560), bottom: s(510) };
    AdjustWindowRect(&mut rc, style, 0);
    let (ww, wh) = (rc.right - rc.left, rc.bottom - rc.top);
    let hwnd = CreateWindowExW(
        0, cls.as_ptr(), w("Idle Service Killer").as_ptr(), style,
        (GetSystemMetrics(SM_CXSCREEN) - ww) / 2, (GetSystemMetrics(SM_CYSCREEN) - wh) / 2, ww, wh,
        null_mut(), null_mut(), hinst, null(),
    );

    // mk(class, text, style, x, y, width, height, id, font); coordinates are in 96-dpi units.
    let mk = |class: &str, text: &str, st: u32, x: i32, y: i32, wd: i32, ht: i32, id: usize, f: HFONT| -> HWND {
        let ex = if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 };
        let h = CreateWindowExW(
            ex, w(class).as_ptr(), w(&text.replace('\n', "\r\n")).as_ptr(), WS_CHILD | WS_VISIBLE | st, s(x), s(y), s(wd), s(ht),
            hwnd, id as HMENU, hinst, null(),
        );
        SendMessageW(h, WM_SETFONT, f as usize, 1);
        h
    };
    let (push, def, tab) = (0u32, BS_DEFPUSHBUTTON as u32, WS_TABSTOP);
    let (check, nav) = (BS_AUTOCHECKBOX as u32 | WS_TABSTOP, BS_AUTORADIOBUTTON as u32 | BS_PUSHLIKE as u32);
    let (edit_line, edit_multi) = (ES_AUTOHSCROLL as u32 | ES_NUMBER as u32 | WS_TABSTOP, (ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN) as u32 | WS_VSCROLL | WS_TABSTOP);

    let mut pg: [Vec<HWND>; 3] = Default::default();
    let mut reg = |p: usize, h: HWND| -> HWND {
        pg[p].push(h);
        h
    };

    // Page buttons (always visible), and Close.
    let first = mk("BUTTON", "Setup", nav | WS_GROUP | tab, 20, 14, 110, 30, ID_PAGE, normal);
    mk("BUTTON", "Settings", nav, 136, 14, 110, 30, ID_PAGE + 1, normal);
    mk("BUTTON", "Log", nav, 252, 14, 110, 30, ID_PAGE + 2, normal);
    SendMessageW(first, BM_SETCHECK, BST_CHECKED as usize, 0);
    mk("BUTTON", "Close", push | tab, 430, 466, 110, 30, ID_CLOSE, normal);

    // Page 0: Setup
    reg(0, mk("STATIC", "Idle Service Killer", 0, 20, 64, 520, 30, 0, big));
    reg(0, mk("STATIC", "Stops idle third-party background services to save RAM and CPU. It runs as an automatic Windows service \
        using well under 1 MB of memory. Use Settings to choose what it may stop, and Log to see what it did.", 0, 20, 100, 520, 52, 0, normal));
    let status = reg(0, mk("STATIC", "", 0, 20, 158, 520, 20, 0, normal));
    let b_install = reg(0, mk("BUTTON", "Install / Update", def | tab, 20, 188, 140, 32, ID_INSTALL, normal));
    let b_uninstall = reg(0, mk("BUTTON", "Uninstall", push | tab, 168, 188, 110, 32, ID_UNINSTALL, normal));
    let b_start = reg(0, mk("BUTTON", "Start", push | tab, 286, 188, 90, 32, ID_START, normal));
    let b_stop = reg(0, mk("BUTTON", "Stop", push | tab, 384, 188, 90, 32, ID_STOP, normal));
    let note = if is_admin() { "" } else { "Not running as administrator, so these buttons will fail.\nClose this window and double-click the exe to get the approval prompt." };
    let result = reg(0, mk("EDIT", note, (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL, 20, 232, 520, 150, 0, normal));

    // Page 1: Settings
    let dry = reg(1, mk("BUTTON", "Dry-run: only log what would be stopped (untick to really stop idle services)", check, 20, 64, 520, 22, 0, normal));
    let trim = reg(1, mk("BUTTON", "Trim the memory of idle services even before they are stopped", check, 20, 88, 520, 22, 0, normal));
    let labels = ["Scan every (seconds)", "Idle scans before stopping", "Idle if CPU below (ms/scan)", "Idle if disk I/O below (bytes)",
                  "Max stops per service", "Only if service uses (MB)", "App closer interval (ms)"];
    let mut nums = Vec::new();
    for (i, l) in labels.iter().enumerate() {
        let (col, row) = (if i < 4 { 0 } else { 1 }, (if i < 4 { i } else { i - 4 }) as i32);
        let (lx, ex) = (20 + col * 270, 196 + col * 270);
        reg(1, mk("STATIC", l, 0, lx, 122 + row * 30 + 3, 170, 20, 0, normal));
        nums.push(reg(1, mk("EDIT", "", edit_line, ex, 122 + row * 30, 70, 24, 0, normal)));
    }
    let mut lists = Vec::new();
    for (i, l) in ["Never touch (Deny)", "Only touch (Only)", "Close these apps (CloseApp)"].iter().enumerate() {
        let x = 20 + i as i32 * 176;
        reg(1, mk("STATIC", l, 0, x, 250, 168, 18, 0, normal));
        lists.push(reg(1, mk("EDIT", "", edit_multi, x, 270, 168, 120, 0, normal)));
    }
    reg(1, mk("STATIC", "One entry per line; * and ? wildcards work. Leave 'Only' empty for no restriction. App names have no .exe.", 0, 20, 396, 520, 34, 0, normal));
    reg(1, mk("BUTTON", "Save settings", def | tab, 20, 434, 130, 32, ID_SAVE, normal));
    let saved = reg(1, mk("STATIC", "", 0, 160, 442, 260, 20, 0, normal));

    // Page 2: Log
    let log = reg(2, mk("EDIT", "", (ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL) as u32 | WS_VSCROLL | WS_HSCROLL, 20, 64, 520, 350, 0, mono));
    SendMessageW(log, EM_SETLIMITTEXT, 200_000, 0);
    reg(2, mk("BUTTON", "Refresh", push | tab, 20, 424, 110, 30, ID_REFRESH, normal));
    reg(2, mk("BUTTON", "Open data folder", push | tab, 138, 424, 150, 30, ID_OPEN, normal));

    UI.with(|u| {
        *u.borrow_mut() = Some(Ui {
            pages: pg, status, result, setup_btns: vec![b_install, b_uninstall, b_start, b_stop], dry, trim, nums, lists, saved, log,
        })
    });
    fill_settings(&cfg_now());
    refresh_status();
    show_page(0);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    let mut msg: MSG = zeroed();
    while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
        if IsDialogMessageW(hwnd, &mut msg) == 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

// Re-launches this exe through the UAC prompt. False if the user declined.
fn relaunch_elevated() -> bool {
    let exe = w(&env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
    unsafe { ShellExecuteW(null_mut(), w("runas").as_ptr(), exe.as_ptr(), null(), null(), SW_SHOWNORMAL) as usize > 32 }
}

// ---- command line (--install / --uninstall / --console) -------------------------------------

// The exe is a GUI-subsystem program (no console flash on double-click); give command-line runs their terminal back.
fn attach_console() {
    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        for (std, name) in [(STD_INPUT_HANDLE, "CONIN$"), (STD_OUTPUT_HANDLE, "CONOUT$"), (STD_ERROR_HANDLE, "CONOUT$")] {
            let h = GetStdHandle(std);
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                if let Ok(f) = fs::OpenOptions::new().read(true).write(true).open(name) {
                    SetStdHandle(std, f.into_raw_handle() as _);
                }
            }
        }
    }
}

fn cli_task(remove: bool, live: bool) {
    if !is_admin() {
        println!("This needs an administrator terminal. Or double-click the exe for the installer window.");
        return;
    }
    match if remove { uninstall() } else { install(live) } {
        Ok(m) => println!("{m}"),
        Err(e) => eprintln!("Failed: {e}"),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if !args.is_empty() {
        attach_console();
    }
    let mut cfg = data_cfg_path();
    let (mut console, mut install_, mut uninstall_, mut live, mut window) = (false, false, false, false, false);
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--console" => console = true,
            "--install" => install_ = true,
            "--uninstall" => uninstall_ = true,
            "--live" => live = true,
            "--gui" => window = true, // show the window without elevating (development)
            "--config" => cfg = it.next().map(PathBuf::from).unwrap_or(cfg),
            _ => {}
        }
    }

    if install_ || uninstall_ {
        cli_task(uninstall_, live);
    } else if window {
        unsafe { gui() };
    } else if console {
        let mut r = Killer::new(cfg.clone(), true);
        r.log(&format!("Console mode. Config: {}  DryRun={}. Ctrl+C to quit.", cfg.display(), r.cfg.dry));
        run(&mut r, Duration::ZERO, |ms| {
            thread::sleep(Duration::from_millis(ms));
            false
        });
    } else {
        let _ = CFG_PATH.set(cfg);
        let mut name = w(SVC);
        let table = [
            SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
            SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
        ];
        // Fails immediately when a person (not the service manager) launched the exe: show the installer window.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            if is_admin() {
                unsafe { gui() };
            } else if !relaunch_elevated() {
                unsafe {
                    MessageBoxW(null_mut(), w("Administrator approval is required to install or remove the service.").as_ptr(),
                                w("Idle Service Killer").as_ptr(), 0x40);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches() {
        assert!(glob(b"*vpn*", b"my vpn client"));
        assert!(glob(b"msedge", b"msedge"));
        assert!(!glob(b"msedge", b"msedgewebview2"));
        assert!(glob(b"msedge*", b"msedgewebview2"));
        assert!(glob(b"a?c*d", b"abcxxd"));
        assert!(!glob(b"a?c", b"ac"));
    }

    #[test]
    fn config_parses_and_clamps() {
        let c = parse_cfg("\u{feff}# x\nDryRun=false\nIntervalSeconds=5\nIdleCycles=3\nCloseApp=Foo.EXE\nDeny=*Bar*\nMinServiceMemoryMB=20");
        assert!(!c.dry);
        assert_eq!(c.interval, 120); // below the 10 s floor: ignored
        assert_eq!(c.idle_cycles, 3);
        assert_eq!((c.close, c.deny, c.min_mb), (vec!["foo".to_string()], vec!["*bar*".to_string()], 20));
    }

    // Real Windows APIs; none of these need administrator rights.
    #[test]
    fn windows_apis_work() {
        unsafe {
            let scm = Sc(OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE));
            assert!(!scm.0.is_null());
            let all = enum_services(scm.0);
            assert!(all.len() > 3, "found {} services", all.len());
            let (mut ok, mut dep_checked) = (0, 0);
            for s in all.iter().take(40) {
                let h = OpenServiceW(scm.0, w(&s.name).as_ptr(), SERVICE_QUERY_CONFIG | SERVICE_ENUMERATE_DEPENDENTS);
                if h.is_null() {
                    continue;
                }
                let svc = Sc(h);
                if let Some((start, image)) = svc_config(svc.0) {
                    assert!(start <= 4 && exe_path(&image).to_lowercase().contains(".exe"), "{image}");
                    ok += 1;
                }
                has_active_dependents(svc.0);
                dep_checked += 1;
            }
            assert!(ok > 0 && dep_checked > 0);
            let c = company(r"C:\Windows\System32\notepad.exe");
            assert!(c.contains("Microsoft"), "company = {c:?}");
            listener_pids();
        }
    }

    #[test]
    fn set_dry_run_edits_or_appends() {
        let p = env::temp_dir().join("idlekiller_test_cfg.txt");
        fs::write(&p, "\u{feff}# hi\r\nDryRun=true\r\nIdleCycles=3\r\n").unwrap();
        set_dry_run(&p, false);
        let c = parse_cfg(&fs::read_to_string(&p).unwrap());
        assert!(!c.dry && c.idle_cycles == 3);
        fs::write(&p, "IdleCycles=3\n").unwrap();
        set_dry_run(&p, false);
        assert!(!parse_cfg(&fs::read_to_string(&p).unwrap()).dry);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn settings_text_round_trips() {
        let c = parse_cfg("DryRun=false\nIntervalSeconds=30\nIdleCycles=4\nMinServiceMemoryMB=7\nTrimIdleServices=false\nDeny=*Foo*\nOnly=bar\nCloseApp=Baz.exe");
        let d = parse_cfg(&cfg_to_text(&c));
        assert_eq!((d.dry, d.interval, d.idle_cycles, d.min_mb, d.trim), (false, 30, 4, 7, false));
        assert_eq!((d.deny, d.only, d.close), (vec!["*foo*".to_string()], vec!["bar".to_string()], vec!["baz".to_string()]));
    }

    #[test]
    fn exe_path_forms() {
        assert_eq!(exe_path("\"C:\\a b\\x.exe\" -k"), "C:\\a b\\x.exe");
        assert_eq!(exe_path("C:\\x\\y.EXE /svc"), "C:\\x\\y.EXE");
    }
}
