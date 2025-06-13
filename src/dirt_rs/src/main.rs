// --- IMPORTANT BUILD NOTE ---
// This program relies on a pre-compiled eBPF object file specified by `BPF_OBJECT_PATH`.
// The original C BPF code (`src/dirt.bpf.c`) requires `vmlinux.h` for CO-RE capabilities.
// If `/sys/kernel/btf/vmlinux` is not available on the build system, `vmlinux.h`
// may need to be generated or obtained via other means (e.g., from kernel development
// headers or a pre-built vmlinux.h provided with the original project's source tree
// in a `../vmlinux/$(ARCH)/` directory, which is currently not available here).
// Without a correctly compiled `dirt.bpf.o` that matches the running kernel and
// contains all necessary maps and programs, the eBPF parts of this application
// will likely fail at runtime during BPF object loading or attaching.
// The placeholder `dirt.bpf.o` used for development allows Rust code compilation only.

// --- Constants ---
const JSON_FULL_STR: &str = "json";
const JSON_MIN_STR: &str = "json-min";

const FILENAME_LEN_MAX: usize = 32;
const FILEPATH_LEN_MAX: usize = 96;
pub const FS_EVENT_MAX: usize = 15; // Made pub for tests
const UNIX_SOCKET_PATH_MAX: usize = 108;
const TOKEN_LEN_MAX: usize = 64;
const DBG_LEN_MAX: usize = 16;
const BPF_OBJECT_PATH: &str = "src/dirt_rs/dirt.bpf.o";

const KERNEL_VERSION_MIN: u32 = 5;
const KERNEL_MAJOR_MIN: u32 = 10;
const SYS_FILE_VMLINUX: &str = "/sys/kernel/btf/vmlinux";
const SYS_FILE_JIT_ENABLE: &str = "/proc/sys/net/core/bpf_jit_enable";

const TITLE_STR: &str = r#"
   .     .                                 ..              .
    .  . . ..              :+.=-.     .:.           -.-.. .  .     .  .  ...
      . ..:.         .  ...:+*+:.:-:. : : .  ...    :-:  .  . .     .     .
       . : :  ..      ....      .-.-. .:.    . .  .  ..      .     .  .    .
 .       .:. ....     . .   .::-=.-:. .  .   ...   . ...        .    .  . .
   .    .   .  .      .......-=**#+=:           .    .:.   .          . ....
           .:.      ..:..::..-=--+**++#*..  :*@@*::: :.:.....    .     ...
    ....   :...:--::-==-.:::::-**=--+@@@=...:*##%+%@#++*=....  .  ...      .
    .:..:=*+=++===-:::::.-+%@@@@@@@@@@@@@%-:.+@@#=-:-:++#-#@*:. .:-:.
 .. ..:.:++%@@@@@@@@@@%==*@@@@@@@@@@@@@@@@@@@@@@@@:=*+**+:#-#@@=.::#@@:    .
 .:-+**%%=+====*@%#*%@@@@@@@#:-:+%-=:--+@@@@@@@@@@@%#++==+*::+@@@@@+.@-
 .:+@@@#*#:**#@@@@@@@#@@@@@#:::=#@:++--**#=+=#+%*@#%@#+%@@@@@+=::@@@*@+.
 .:*###%@#++-:.=@@@@@@-:-:-#@@@@@=+=*-*@*=@@@@@@@@:+%*+@@:..##*%#@#@@@*.
   =#@%*+=-*#%%@@%*#@@*@@@==·▄▄▄▄  ▪  ▄▄▄  ▄▄▄▄▄:=:=*#*+**=%@#@@@@*:-%@+%@@@#@@@@@#%@@%@@@+.
  .   :.#@@@+:=#@@@@@@@==@@%██▪ ██ ██ ▀▄ █·•██  #*#=-:-==:.-@@@@@@@%.+===%#=#@@@%*+@@@@=@@+.
    . .:@@%@@%---#@@@@@@%@%#▐█· ▐█▌▐█·▐▀▀▄  ▐█.▪++*=-+****#@@@@##**@#@@@@@@@%%*:  ..*@@@@@+..
   ...:.*@@@@@*--==%@@*@*%.*██. ██ ▐█▌▐█•█▌ ▐█▌·%%*-:-==+***=.-=+=+@@%@@+:%@@@@=..  :*@@@%-....
  .  :.......+%@@*==@@#*=*@@▀▀▀▀▀• ▀▀▀.▀  ▀ ▀▀▀ %+-++=-=++--+==:=+**@=*%@:==+%#=:.      ...*@@#=
     .:..::.--::.-*@@@@@@@@*:..:.:::--==+:-+##%@@+*@@@%%@@%=.. .   .  -@@@@+.
 .    ..  :::.:...:-#@@@*@@#%@@@@@@@@@@@@@@@@@*=-+#@@@@@@@@@=         :@@@@%
    ..    .:-=--::.:%@@@@%@@@@@@@@@@@@@@@@@@@@@@#@@@@@:**.:%+*#**#=   .=@@@*
 .  ..    ......:-=+#@@@@@@@=@@@#@*==*+#@@@@#-@@@@=@@@@@@@@**@#+-:* .      .
   . .     .....   =+*%@@@@@@**:@@**-.=:..:=#-*%@@@@@@@=:..-**@#*#=
    ..    .....   .:-+*=--=%@@@@@@:=%@@@@@@@*-.%@#@@=  .::-+@@#-...        ..
.   .     ....         .:-=+++=:.   . ....-=+--.@*@*  ........   .     ... .
.  ......  .   .           . . .      ......-==-%@@=   .. ....       ... ...
  ......    .               .         . .  ................        .   ..  .
.    ...           +%##@@%+%@%##%@@@#%@@@@*=%%#@@%%%*:**=.       .      . .
"#;

const HEADER_STR: &str = "\x1b[1;33mdirt -- (c) 2024 Tarsal, Inc\x1b[0m";

const DOC_STR: &str = "dirt-rs provides an eBPF program running in Kernel context and its control application running in userspace.\n\
                        The eBPF program traces kernel functions to monitor processes based on filesystem events.\n\
                        Events are aggregated and submitted into a ringbuffer where they are polled by the userspace\n\
                        control application and converted into messages in json output format.\n\
                        Messages are printed to stdout console and can be sent via Unix domain socket to a specified path.\n";

// --- FS Event Type Constants (from dirt.h, ensure these match RecordFS event indices) ---
pub const EVT_IDX_CREATE: usize = 0; // Made pub for tests
pub const EVT_IDX_MOVED_TO: usize = 9; // Made pub for tests
// Add other EVT_IDX_* constants here if needed by tests, making them pub

// --- Imports ---
use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use clap::{CommandFactory, Parser};
use log::{debug, error, info, warn, LevelFilter};
use nix::sys::utsname;
use nix::unistd;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::Bytes;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::UnixDatagram;
use tokio::signal::unix::{signal, SignalKind};

use libbpf_rs::{MapCore, Object, ObjectBuilder, PrintLevel, RingBufferBuilder};

static RUNNING: AtomicBool = AtomicBool::new(true);
static GLOBAL_CONFIG: std::sync::OnceLock<Config> = std::sync::OnceLock::new();

// --- Structs for deserialization and config ---
#[derive(Debug, Serialize, Deserialize, Clone, Copy)] // Removed Default
#[repr(C)]
struct Record { record_type: u32, ts: u64, }

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, Copy)] // Removed Default
#[repr(C)]
struct RecordFs {
    rc: Record, events: u32, event: [u32; FS_EVENT_MAX], ino: u32, imode: u32, inlink: u32,
    isize: u64, atime_nsec: u64, mtime_nsec: u64, ctime_nsec: u64, isize_first: u64,
    #[serde_as(as = "Bytes")] filepath: [u8; FILEPATH_LEN_MAX],
    #[serde_as(as = "Bytes")] filename: [u8; FILENAME_LEN_MAX],
    #[serde_as(as = "Bytes")] filename_from: [u8; FILENAME_LEN_MAX / 2],
    #[serde_as(as = "Bytes")] filename_to: [u8; FILENAME_LEN_MAX / 2],
}

fn cstr_to_string(bytes: &[u8]) -> String {
    CStr::from_bytes_until_nul(bytes).unwrap_or_else(|_| CStr::from_bytes_with_nul(b"\0").unwrap()).to_string_lossy().into_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum OutputType { Json, JsonMin, }

impl FromStr for OutputType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            JSON_FULL_STR => Ok(OutputType::Json), JSON_MIN_STR => Ok(OutputType::JsonMin),
            _ => Err(format!("Invalid output type: {}. Must be '{}' or '{}'", s, JSON_FULL_STR, JSON_MIN_STR)),
        }
    }
}

fn parse_positive_u32(s: &str) -> Result<u32, String> {
    let val = s.parse::<u32>().map_err(|_| format!("'{}' is not a valid u32 number", s))?;
    if val > 0 { Ok(val) } else { Err("EVENTS must be a positive number".to_string()) }
}
fn parse_socket_path(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() < UNIX_SOCKET_PATH_MAX { Ok(s.to_string()) } else { Err(format!("SOCKET_PATH too long (max {} chars)", UNIX_SOCKET_PATH_MAX)) }
}
fn parse_token(s: &str) -> Result<String, String> {
    if s.len() < TOKEN_LEN_MAX { Ok(s.to_string()) } else { Err(format!("TOKEN too long (max {} chars)", TOKEN_LEN_MAX)) }
}
fn parse_debug_filter(s: &str) -> Result<String, String> {
    if s.len() < DBG_LEN_MAX { Ok(s.to_string()) } else { Err(format!("PROCESS filter too long (max {} chars)", DBG_LEN_MAX)) }
}

#[derive(Parser, Debug, Serialize, Deserialize, Clone)]
#[clap(name="dirt-rs", author = "Tarsal, Inc.", version = env!("CARGO_PKG_VERSION"), about = DOC_STR, long_about = None, help_template = "{about-with-newline}\n{usage-heading} {usage}\n\n{all-args}{after-help}")]
struct Config {
    #[clap(skip)] monitor_bpf_val: u32,
    #[clap(short = 'e', long = "events", name = "EVENTS", value_parser = parse_positive_u32, help = "Max number of filesystem events per aggregated record until export (default: disabled, '1': no aggregation)")]
    agg_events_max: Option<u32>,
    #[clap(short = 'o', long = "output", name = "FORMAT", default_value = JSON_FULL_STR, value_parser = clap::value_parser!(OutputType), help = "Output format ('json' or 'json-min')")]
    output_type: OutputType,
    #[clap(short = 'x', long = "unix-socket", name = "SOCKET_PATH", default_value = "", value_parser = parse_socket_path, help = "Unix domain socket path to send json output to.")]
    output_unix_socket_path: String,
    #[clap(short = 'q', long = "quiet", help = "Quiet mode to suppress output to stdout console")]
    output_quiet: bool,
    #[clap(short = 'd', long = "daemon", help = "Daemonize program to run in background")]
    mode_daemon: bool,
    #[clap(short = 'v', long = "verbose", help = "Verbose output. Print eBPF load and co-re messages on start of eBPF program to stderr console")]
    verbose: bool,
    #[clap(short = 'T', long = "token", name = "TOKEN", default_value = "", value_parser = parse_token, help = "Token specified on host to be included in json output")]
    token: String,
    #[clap(short = 'D', long = "debug", name = "PROCESS", default_value = "", value_parser = parse_debug_filter, help = "Debug. Print ebpf kernel log messages of process to kernel trace pipe.")]
    debug: String,
    #[clap(short = 'l', long = "legend", help = "Show legend")]
    show_legend: bool,
}

// --- JSON Output Structs and Helpers ---
#[derive(Serialize, Debug, PartialEq)]
struct DirtEventJson {
    #[serde(rename = "InfoTimestamp")] info_timestamp: String,
    #[serde(rename = "FilePath")] file_path: String,
    #[serde(rename = "File")] file: String,
    #[serde(rename = "FileMode")] file_mode: String,
    #[serde(rename = "FileEventCount")] file_event_count: u32,
    #[serde(rename = "FileEvents")] file_events: BTreeMap<String, u32>,
    #[serde(rename = "FileInode")] file_inode: u32,
    #[serde(rename = "FileInodeLinkCount")] file_inode_link_count: u32,
    #[serde(rename = "FileSize")] file_size: u64,
    #[serde(rename = "FileSizeChange")] file_size_change: i64,
    #[serde(rename = "FileAccessTime")] file_access_time: String,
    #[serde(rename = "FileStatusChangeTime")] file_status_change_time: String,
    #[serde(rename = "FileModificationTime")] file_modification_time: String,
    #[serde(skip_serializing_if = "Option::is_none")] #[serde(rename = "Token")] token: Option<String>,
}

const FS_EVENT_NAMES: [&str; FS_EVENT_MAX] = [
    "CREATE", "OPEN", "OPEN_EXEC", "ACCESS", "ATTRIB", "MODIFY",
    "CLOSE_WRITE", "CLOSE_NOWRITE", "MOVED_FROM", "MOVED_TO",
    "DELETE", "DELETE_SELF", "MOVE_SELF", "UNMOUNT", "Q_OVERFLOW"
];

fn format_timestamp_ns(ns: u64) -> String {
    if ns == 0 { return "".to_string(); }
    let secs = (ns / 1_000_000_000) as i64;
    let nanos_remainder = (ns % 1_000_000_000) as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos_remainder)
        .map_or_else(|| "InvalidTimestamp".to_string(), |dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}

// --- Legend Data Structs ---
struct SubKeyDetail { key: &'static str, legend: &'static str, }
struct JsonKeyInfo { key_name: &'static str, legend: &'static str, sub_keys: Option<&'static [SubKeyDetail]>, }

static LEGEND_DATA: &[JsonKeyInfo] = &[
    JsonKeyInfo { key_name: "InfoTimestamp", legend: "Message timestamp in UTC datetime format with nanoseconds", sub_keys: None },
    JsonKeyInfo { key_name: "FilePath", legend: "Directory path name of file", sub_keys: None },
    // ... (Full data as before)
    JsonKeyInfo { key_name: "File", legend: "File name", sub_keys: None },
    JsonKeyInfo { key_name: "FileMode", legend: "Regular file, symbolic link or hard link", sub_keys: None },
    JsonKeyInfo { key_name: "FileEventCount", legend: "File event count", sub_keys: None },
    JsonKeyInfo { key_name: "FileEvents", legend: "File event types and count", sub_keys: Some(&[
        SubKeyDetail { key: "CREATE", legend: "File created" },
        SubKeyDetail { key: "MODIFY", legend: "File modified" },
        SubKeyDetail { key: "MOVED_FROM", legend: "File moved or renamed from original name" },
        SubKeyDetail { key: "MOVED_TO", legend: "File moved or renamed to new name" },
        SubKeyDetail { key: "DELETE", legend: "File deleted" },
    ])},
    JsonKeyInfo { key_name: "FileInode", legend: "Inode number of File", sub_keys: None },
    JsonKeyInfo { key_name: "FileInodeLinkCount", legend: "Symbolic link count for inode", sub_keys: None },
    JsonKeyInfo { key_name: "FileSize", legend: "File size in bytes", sub_keys: None },
    JsonKeyInfo { key_name: "FileSizeChange", legend: "File size change in bytes after modification (can be negative)", sub_keys: None },
    JsonKeyInfo { key_name: "FileAccessTime", legend: "Access timestamp in UTC", sub_keys: None },
    JsonKeyInfo { key_name: "FileStatusChangeTime", legend: "Status change timestamp in UTC", sub_keys: None },
    JsonKeyInfo { key_name: "FileModificationTime", legend: "Modification timestamp in UTC", sub_keys: None },
];

// --- Helper Functions for printing ---
fn print_header() {
    println!("{}", HEADER_STR);
}

#[allow(dead_code)]
fn print_usage(error_msg: Option<&str>) {
    print_header();
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("\n{}", DOC_STR);
    Config::command().print_long_help().unwrap_or_default();
    if let Some(msg) = error_msg {
        eprintln!("\n\x1b[1;91mError:\x1b[0m {}", msg);
    }
}

fn print_legend_details() {
    print_header();
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    let mut total_subkeys = 0;
    for item in LEGEND_DATA.iter() {
        if let Some(sub_keys) = item.sub_keys {
            total_subkeys += sub_keys.len();
        }
    }
    println!("\nLegend ({} keys, {} subkeys):", LEGEND_DATA.len(), total_subkeys);
    for item in LEGEND_DATA.iter() {
        println!("  {: <26}  {}", item.key_name, item.legend);
        if let Some(sub_keys) = item.sub_keys {
            for sub_item in sub_keys.iter() {
                println!("   └─ {: <23} {}", sub_item.key, sub_item.legend);
            }
        }
    }
}

fn print_legend() { print_legend_details(); }

// --- BPF Interaction Callbacks & Main Logic ---
fn libbpf_print_callback(level: PrintLevel, msg: String) {
    let trimmed_msg = msg.trim_end_matches('\n');
    match level {
        PrintLevel::Debug => debug!("[libbpf] {}", trimmed_msg),
        PrintLevel::Info => info!("[libbpf] {}", trimmed_msg),
        PrintLevel::Warn => warn!("[libbpf] {}", trimmed_msg),
    };
}

async fn send_to_unix_socket(json_string: String, socket_path: String) {
    match UnixDatagram::unbound() {
        Ok(socket) => {
            match socket.send_to(json_string.as_bytes(), &socket_path).await {
                Ok(bytes_sent) => debug!("Sent {} bytes to Unix socket {}", bytes_sent, socket_path),
                Err(e) => error!("Failed to send to Unix socket {}: {}", socket_path, e),
            }
        }
        Err(e) => error!("Failed to create unbound UnixDatagram socket: {}", e),
    }
}

// Helper for inode mode string conversion (for tests and main logic)
fn get_file_mode_str(imode: u32, inlink: u32) -> String {
    if (imode & 0o120000) == 0o120000 { "symlink".to_string() }
    else if inlink > 1 { "hardlink".to_string() }
    else { "regular".to_string() }
}

// Helper for filename logic (for tests and main logic)
fn determine_filename(event_flags: &[u32; FS_EVENT_MAX], filename_c: &[u8], filename_from_c: &[u8], filename_to_c: &[u8]) -> String {
    let mut p_filename = cstr_to_string(filename_c);
    if event_flags[EVT_IDX_MOVED_TO] > 0 {
        let from = cstr_to_string(filename_from_c);
        let to = cstr_to_string(filename_to_c);
        if !from.is_empty() && !to.is_empty() { p_filename = format!("{}->{}", from, to); }
        else if !to.is_empty() { p_filename = to; }
    }
    p_filename
}

// Core processing logic, now testable
fn process_record_to_json_string(rf: &RecordFs, config: &Config) -> Result<String, String> {
    let mut file_events_map = BTreeMap::new();
    for (i, &count) in rf.event.iter().enumerate() {
        if count > 0 && i < FS_EVENT_NAMES.len() { file_events_map.insert(FS_EVENT_NAMES[i].to_string(), count); }
    }

    let file_mode_str = get_file_mode_str(rf.imode, rf.inlink);
    let p_filename = determine_filename(&rf.event, &rf.filename, &rf.filename_from, &rf.filename_to);

    let output_event = DirtEventJson {
        info_timestamp: format_timestamp_ns(rf.rc.ts), file_path: cstr_to_string(&rf.filepath),
        file: p_filename, file_mode: file_mode_str, file_event_count: rf.events,
        file_events: file_events_map, file_inode: rf.ino, file_inode_link_count: rf.inlink,
        file_size: rf.isize, file_size_change: rf.isize as i64 - rf.isize_first as i64,
        file_access_time: format_timestamp_ns(rf.atime_nsec),
        file_status_change_time: format_timestamp_ns(rf.ctime_nsec),
        file_modification_time: format_timestamp_ns(rf.mtime_nsec),
        token: if !config.token.is_empty() { Some(config.token.clone()) } else { None },
    };

    match config.output_type {
        OutputType::JsonMin => serde_json::to_string(&output_event).map_err(|e| e.to_string()),
        OutputType::Json => serde_json::to_string_pretty(&output_event).map_err(|e| e.to_string()),
    }
}

fn handle_event(data: &[u8]) -> i32 {
    if data.len() < std::mem::size_of::<RecordFs>() { error!("Data too short for RecordFs: {} bytes", data.len()); return 1; }
    let rf = unsafe { &*(data.as_ptr() as *const RecordFs) };
    // It's guaranteed that GLOBAL_CONFIG is set by main before this callback is invoked.
    let config = GLOBAL_CONFIG.get().expect("Config not initialized in handle_event");

    match process_record_to_json_string(rf, config) {
        Ok(json_s) => process_output_string(json_s, config),
        Err(e) => error!("Failed to process record to JSON: {}", e),
    }
    0
}

fn process_output_string(json_string: String, config: &Config) {
    if !config.mode_daemon && (!config.output_unix_socket_path.is_empty() && !config.output_quiet || config.output_unix_socket_path.is_empty()) {
        println!("{}", json_string);
        println!("{}", std::char::from_u32(0x1e).unwrap_or(' '));
    }
    if !config.output_unix_socket_path.is_empty() {
        let socket_path_clone = config.output_unix_socket_path.clone();
        tokio::spawn(async move { send_to_unix_socket(json_string, socket_path_clone).await; });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_mut = Config::parse();
    config_mut.monitor_bpf_val = 1 << 1;

    GLOBAL_CONFIG.set(config_mut.clone()).expect("Failed to set global config");
    let config = GLOBAL_CONFIG.get().unwrap();

    let log_level = if config.verbose { LevelFilter::Debug } else { LevelFilter::Info };
    env_logger::Builder::new().filter_level(log_level).init();

    if !unistd::getuid().is_root() {
        print_usage(Some("dirt-rs must be run as root."));
        std::process::exit(1);
    }

    libbpf_rs::set_print(Some((PrintLevel::Warn, libbpf_print_callback)));

    if config.mode_daemon {
        info!("Daemonizing...");
        if let Err(e) = nix::unistd::daemon(true, true) { error!("Daemonization failed: {}", e); bail!("Daemonization error: {}", e); }
    }

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = sigint.recv() => { info!("Received SIGINT, exiting..."); RUNNING.store(false, Ordering::SeqCst); },
            _ = sigterm.recv() => { info!("Received SIGTERM, exiting..."); RUNNING.store(false, Ordering::SeqCst); },
        }
    });

    if !config.output_quiet && !config.mode_daemon {
        println!("{}", TITLE_STR);
        print_header();
        println!("Kernel-based Process Monitoring via eBPF ({})", env!("CARGO_PKG_VERSION"));
        println!("\nRuntime Requirements:");
    }

    let mut all_checks_ok = true;
    match utsname::uname() {
        Ok(uts) => {
            let release = uts.release().to_string_lossy();
            let parts: Vec<&str> = release.split('.').collect();
            if parts.len() >= 2 {
                let k_ver = parts[0].parse::<u32>().unwrap_or(0);
                let k_maj = parts[1].parse::<u32>().unwrap_or(0);
                if k_ver < KERNEL_VERSION_MIN || (k_ver == KERNEL_VERSION_MIN && k_maj < KERNEL_MAJOR_MIN) {
                    if !config.output_quiet && !config.mode_daemon {eprintln!("\x1b[0;31m[fail]\x1b[0m Kernel version {}.{}+ required -> Kernel {} installed", KERNEL_VERSION_MIN, KERNEL_MAJOR_MIN, release);}
                    all_checks_ok = false;
                } else { if !config.output_quiet && !config.mode_daemon {println!("\x1b[0;32m[ok]\x1b[0m   Kernel version {}.{}+ required -> Kernel {} installed", KERNEL_VERSION_MIN, KERNEL_MAJOR_MIN, release);} }
            } else { if !config.output_quiet && !config.mode_daemon {eprintln!("\x1b[0;31m[fail]\x1b[0m Could not parse kernel version from: {}", release);} all_checks_ok = false; }
        }
        Err(e) => { if !config.output_quiet && !config.mode_daemon {eprintln!("\x1b[0;31m[fail]\x1b[0m Could not determine kernel version: {}", e);} all_checks_ok = false; }
    }

    if Path::new(SYS_FILE_VMLINUX).exists() && fs::metadata(SYS_FILE_VMLINUX)?.len() > 1 {
        if !config.output_quiet && !config.mode_daemon { println!("\x1b[0;32m[ok]\x1b[0m   vmlinux (BTF & CO-RE) -> Available at {}", SYS_FILE_VMLINUX); }
    } else { if !config.output_quiet && !config.mode_daemon {eprintln!("\x1b[0;31m[fail]\x1b[0m vmlinux (BTF & CO-RE) -> Not available at {}", SYS_FILE_VMLINUX);} all_checks_ok = false; }

    match fs::read_to_string(SYS_FILE_JIT_ENABLE) {
        Ok(s) => {
            let jit_status = s.trim();
            if jit_status == "1" { if !config.output_quiet && !config.mode_daemon {println!("\x1b[0;32m[ok]\x1b[0m   JIT Compiler -> Enabled (net.core.bpf_jit_enable={})", jit_status);} }
            else { if !config.output_quiet && !config.mode_daemon {println!("\x1b[0;33m[warn]\x1b[0m JIT Compiler -> Status: {} (net.core.bpf_jit_enable={})", jit_status, jit_status);} }
        }
        Err(e) => { if !config.output_quiet && !config.mode_daemon {println!("\x1b[0;33m[warn]\x1b[0m JIT Compiler -> Could not read status: {}", e);} }
    }
    if !config.output_quiet && !config.mode_daemon { println!(); }

    if !all_checks_ok {
        let msg = "Runtime requirements not met.";
        if !config.mode_daemon { print_usage(Some(msg)); }
        else { error!("{}", msg); }
        std::process::exit(1);
    }

    if config.show_legend { print_legend_details(); return Ok(()); }

    info!("Opening BPF object from: {}", BPF_OBJECT_PATH);
    let mut obj_builder = ObjectBuilder::default();
    let open_obj = obj_builder.open_file(BPF_OBJECT_PATH)?;
    warn!("BPF global variable initialization relies on BPF program defaults or automatic libbpf extern handling.");
    let loaded_obj: Object = open_obj.load()?; // No longer mutable

    for prog in loaded_obj.progs_mut() { // prog does not need to be mutable for attach()
        match prog.attach() {
            Ok(_) => info!("Attached BPF program: {:?}", prog.name().to_string_lossy()),
            Err(e) => warn!("Failed to attach BPF program {:?}: {}", prog.name().to_string_lossy(), e),
        }
    }

    let ringbuf_map_handle = loaded_obj.maps()
        .find(|map| map.name() == "ringbuf_records")
        .ok_or_else(|| anyhow!("Failed to find 'ringbuf_records' map"))?;

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&ringbuf_map_handle, handle_event)?;
    let ringbuf = rb_builder.build()?;

    if !config.output_quiet && !config.mode_daemon {
        println!("Configuration:");
        println!("\x1b[0;32m[+]\x1b[0m Monitored kernel subsystem(s)");
        let hash_map_max_entries = loaded_obj.maps()
            .find(|map| map.name() == "hash_records")
            .map_or(0, |m| m.max_entries());
        println!("\x1b[0;32m[+]\x1b[0m   File System: {} max records", hash_map_max_entries);
        let agg_status_color = if config.agg_events_max.is_some() && config.agg_events_max.unwrap_or(0) > 1 {"32"} else {"33"};
        let agg_status_char = if agg_status_color == "32" {"+"} else {"-"};
        println!("\x1b[0;{}m[{}]\x1b[0m Filesystem aggregation by PID+Inode until", agg_status_color, agg_status_char);
        println!("\x1b[0;32m[+]\x1b[0m   Finished file operation");
        if let Some(max_evts) = config.agg_events_max { if max_evts > 0 { println!("\x1b[0;32m[+]\x1b[0m   Max number of {} event{}", max_evts, if max_evts == 1 {""} else {"s"}); } }
        let output_dest_str = if config.output_unix_socket_path.is_empty() {"stdout"} else {&config.output_unix_socket_path};
        let output_type_str = if config.output_type == OutputType::Json {"json"} else {"json-min"};
        println!("\x1b[0;32m[+]\x1b[0m Output as {} to {}", output_type_str, output_dest_str);
        if config.verbose { println!("\x1b[0;32m[+]\x1b[0m Verbose mode for userspace app enabled"); }
        if !config.debug.is_empty() { println!("\x1b[0;32m[+]\x1b[0m Debug mode for kernel eBPF program enabled for '{}'", config.debug); }
        println!("\ndirt-rs ({}) with PID {} successfully started in {} mode\n", env!("CARGO_PKG_VERSION"), std::process::id(), if config.mode_daemon {"daemon"} else {"terminal"});
    }

    if !config.mode_daemon && (!config.output_unix_socket_path.is_empty() && !config.output_quiet || config.output_unix_socket_path.is_empty()) {
        if !config.output_quiet {
            print!("Press <RETURN> key for output");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            print!("\x1B[A\x1B[2K\x1B[A\x1B[2K\r");
            io::stdout().flush()?;
        }
    }

    RUNNING.store(true, Ordering::SeqCst);
    info!("Starting eBPF monitoring loop...");
    while RUNNING.load(Ordering::SeqCst) {
        match ringbuf.poll(std::time::Duration::from_millis(100)) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == libbpf_rs::ErrorKind::Interrupted { debug!("Ringbuffer poll interrupted, continuing."); continue; }
                warn!("Ringbuffer poll error: {:?}", e);
            }
        }
    }

    info!("Exiting dirt-rs...");
    Ok(())
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    fn make_cstr_array<const N: usize>(s: &str) -> [u8; N] {
        let mut arr = [0u8; N];
        let bytes = s.as_bytes();
        let len = std::cmp::min(bytes.len(), N);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    }

    fn default_record_fs() -> RecordFs {
        RecordFs {
            rc: Record { record_type: 0, ts: 0 },
            events: 0,
            event: [0; FS_EVENT_MAX],
            ino: 0, imode: 0, inlink: 0,
            isize: 0, atime_nsec: 0, mtime_nsec: 0, ctime_nsec: 0, isize_first: 0,
            filepath: [0; FILEPATH_LEN_MAX],
            filename: [0; FILENAME_LEN_MAX],
            filename_from: [0; FILENAME_LEN_MAX / 2],
            filename_to: [0; FILENAME_LEN_MAX / 2],
        }
    }

    impl Default for Config { // For tests
        fn default() -> Self {
            Config {
                monitor_bpf_val: 0, agg_events_max: None, output_type: OutputType::JsonMin,
                output_unix_socket_path: String::new(), output_quiet: false, mode_daemon: false,
                verbose: false, token: String::new(), debug: String::new(), show_legend: false,
            }
        }
    }

    #[test]
    fn test_format_timestamp_ns() {
        assert_eq!(format_timestamp_ns(0), "");
        let ts_ns = 1672574400_123456789;
        assert_eq!(format_timestamp_ns(ts_ns), "2023-01-01T12:00:00.123456789Z");
        let ts_secs_ns = 1672574400_000000000;
        assert_eq!(format_timestamp_ns(ts_secs_ns), "2023-01-01T12:00:00.000000000Z");
    }

    #[test]
    fn test_config_parsing_basic() {
        let config = Config::try_parse_from(&["dirt_rs", "-e", "10", "-v"]).unwrap();
        assert_eq!(config.agg_events_max, Some(10));
        assert!(config.verbose);
    }

    #[test]
    fn test_config_parsing_invalid_events() {
        assert!(Config::try_parse_from(&["dirt_rs", "-e", "foo"]).is_err());
        assert!(Config::try_parse_from(&["dirt_rs", "-e", "0"]).is_err());
    }

    #[test]
    fn test_config_parsing_socket_path_too_long() {
        let long_path = "a".repeat(UNIX_SOCKET_PATH_MAX + 1);
        assert!(Config::try_parse_from(&["dirt_rs", "-x", &long_path]).is_err());
    }

    #[test]
    fn test_get_file_mode_str() {
        assert_eq!(get_file_mode_str(0o120000, 1), "symlink"); // S_IFLNK
        assert_eq!(get_file_mode_str(0o100000, 2), "hardlink"); // S_IFREG, nlink > 1
        assert_eq!(get_file_mode_str(0o100000, 1), "regular"); // S_IFREG, nlink = 1
    }

    #[test]
    fn test_determine_filename() {
        let mut event_flags = [0u32; FS_EVENT_MAX];
        let filename_bytes = make_cstr_array::<FILENAME_LEN_MAX>("test.txt");
        let from_bytes = make_cstr_array::<{FILENAME_LEN_MAX / 2}>("old.txt");
        let to_bytes = make_cstr_array::<{FILENAME_LEN_MAX / 2}>("new.txt");

        assert_eq!(determine_filename(&event_flags, &filename_bytes, &from_bytes, &to_bytes), "test.txt");

        event_flags[EVT_IDX_MOVED_TO] = 1;
        assert_eq!(determine_filename(&event_flags, &filename_bytes, &from_bytes, &to_bytes), "old.txt->new.txt");

        let empty_from = make_cstr_array::<{FILENAME_LEN_MAX / 2}>("");
        assert_eq!(determine_filename(&event_flags, &filename_bytes, &empty_from, &to_bytes), "new.txt");
    }

    #[test]
    fn test_process_record_to_json() {
        let mut rf = default_record_fs();
        rf.rc.ts = 1672574400_123456789;
        rf.filepath = make_cstr_array("/tmp/file.txt");
        rf.filename = make_cstr_array("file.txt");
        rf.imode = 0o100644;
        rf.inlink = 1;
        rf.events = 1;
        rf.event[EVT_IDX_CREATE] = 1; // Use the pub const
        rf.isize = 1024; rf.isize_first = 512;
        rf.atime_nsec = 1672574401_000000000; rf.mtime_nsec = 1672574402_000000000; rf.ctime_nsec = 1672574403_000000000;

        let mut config = Config::default();
        config.output_type = OutputType::JsonMin;

        let result = process_record_to_json_string(&rf, &config);
        assert!(result.is_ok(), "JSON processing failed: {:?}", result.err());
        let json_str = result.unwrap();

        assert!(json_str.contains("\"InfoTimestamp\":\"2023-01-01T12:00:00.123456789Z\""));
        assert!(json_str.contains("\"FilePath\":\"/tmp/file.txt\""));
        assert!(json_str.contains("\"File\":\"file.txt\""));
        assert!(json_str.contains("\"FileMode\":\"regular\""));
        assert!(json_str.contains("\"FileEventCount\":1"));
        assert!(json_str.contains("\"FileEvents\":{\"CREATE\":1}"));
        assert!(json_str.contains("\"FileSizeChange\":512"));
    }
}

// Definitions for JsonKey, JsonSubKey, SubKeyInfo for legend are now only the static LEGEND_DATA.
// The structs JsonKeyRust, JsonSubKeyRust, SubKeyInfoRust are removed as they were placeholders.
// The actual structs for legend data are JsonKeyInfo and SubKeyDetail.
