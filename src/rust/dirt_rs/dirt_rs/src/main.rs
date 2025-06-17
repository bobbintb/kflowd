use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::{KProbe, KRetProbe};
use aya::{Ebpf};
use aya_log::EbpfLogger;
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use clap::Parser;
use dirt_rs_common::*;
use log::{info, warn, error, debug};
use nix::libc::{RLIMIT_MEMLOCK, rlimit, setrlimit}; // geteuid will be used from libc directly
use libc::geteuid; // Use libc::geteuid directly
use serde::Serialize;
use serde_json::json;
use std::ffi::CStr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixDatagram;
use tokio::signal;


const VERSION: &str = env!("CARGO_PKG_VERSION");
const LEGEND_INFO: &str = "Dirt-rs: Data Integrity Rekognition Tool (Rust port)";
const RECORD_SEPARATOR: char = '\x1e'; // RS character

// Re-define FsEvent for userspace, copying from dirt_rs_common
// This is needed to map event values back to names in userspace.
// Ensure FS_EVENT_MAX in common.rs matches the count here (15)
// And that dirt_rs_common::FsEvent is pub with pub fields.
static FSEVT_USER: [dirt_rs_common::FsEvent; FS_EVENT_MAX] = [
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_CREATE as u16, value: FS_CREATE, name: *b"CREATE          ", shortname: *b"CRE ", shortname2: *b"CR  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_OPEN as u16, value: FS_OPEN, name: *b"OPEN            ", shortname: *b"OPN ", shortname2: *b"OP  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_OPEN_EXEC as u16, value: FS_OPEN_EXEC, name: *b"OPEN_EXEC       ", shortname: *b"OPX ", shortname2: *b"OX  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_ACCESS as u16, value: FS_ACCESS, name: *b"ACCESS          ", shortname: *b"ACC ", shortname2: *b"AC  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_ATTRIB as u16, value: FS_ATTRIB, name: *b"ATTRIB          ", shortname: *b"ATT ", shortname2: *b"AT  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_MODIFY as u16, value: FS_MODIFY, name: *b"MODIFY          ", shortname: *b"MOD ", shortname2: *b"MO  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_CLOSE_WRITE as u16, value: FS_CLOSE_WRITE, name: *b"CLOSE_WRITE     ", shortname: *b"CLW ", shortname2: *b"CW  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_CLOSE_NOWRITE as u16, value: FS_CLOSE_NOWRITE, name: *b"CLOSE_NOWRITE   ", shortname: *b"CLN ", shortname2: *b"CN  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_MOVED_FROM as u16, value: FS_MOVED_FROM, name: *b"MOVED_FROM      ", shortname: *b"MVF ", shortname2: *b"MF  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_MOVED_TO as u16, value: FS_MOVED_TO, name: *b"MOVED_TO        ", shortname: *b"MVT ", shortname2: *b"MT  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_DELETE as u16, value: FS_DELETE, name: *b"DELETE          ", shortname: *b"DEL ", shortname2: *b"DE  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_DELETE_SELF as u16, value: FS_DELETE_SELF, name: *b"DELETE_SELF     ", shortname: *b"DSF ", shortname2: *b"DS  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_MOVE_SELF as u16, value: FS_MOVE_SELF, name: *b"MOVE_SELF       ", shortname: *b"MSF ", shortname2: *b"MS  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_UNMOUNT as u16, value: FS_UNMOUNT, name: *b"UNMOUNT         ", shortname: *b"UNM ", shortname2: *b"UM  " },
    dirt_rs_common::FsEvent { index: INDEX_FS_EVENT::I_Q_OVERFLOW as u16, value: FS_Q_OVERFLOW, name: *b"Q_OVERFLOW      ", shortname: *b"QOF ", shortname2: *b"QO  " },
];


#[derive(Debug, Parser)]
#[clap(author, version = VERSION, about = LEGEND_INFO)]
struct Cli {
    #[clap(short, long, default_value_t = 10, help = "Maximum aggregated events before sending")]
    agg_events_max: u32,

    #[clap(short = 'o', long, default_value = "json", value_parser = clap::builder::PossibleValuesParser::new(["json", "json-min"]))]
    output_format: String,

    #[clap(short = 'x', long, help = "Unix domain socket path")]
    unix_socket: Option<PathBuf>,

    #[clap(short, long, help = "Suppress stdout output")]
    quiet: bool,

    #[clap(short = 'd', long, help = "Daemonize (placeholder, not implemented)")]
    daemon: bool, // Actual daemonization is complex

    #[clap(short = 'V', long, help = "Verbose eBPF logs")]
    verbose: bool,

    #[clap(short = 'T', long, help = "Token for JSON output (placeholder)")]
    token: Option<String>,

    #[clap(short = 'D', long, help = "Debug process filter string for eBPF (placeholder)")]
    debug_process: Option<String>, // This will be copied to ProgConfig.debug_str

    #[clap(long, help = "Print legend information and exit")]
    legend: bool,
}

#[derive(Debug, Serialize)]
struct OutputRecord<'a> {
    #[serde(rename = "InfoTimestamp")]
    info_timestamp: String,
    #[serde(rename = "FilePath")]
    filepath: &'a str,
    #[serde(rename = "File")]
    file: &'a str, // or from/to for renames
    #[serde(rename = "FileMode")]
    file_mode: String, // e.g. "drwxr-xr-x"
    #[serde(rename = "FileEventCount")]
    file_event_count: u32,
    #[serde(rename = "FileEvents")]
    file_events: serde_json::Value, // JSON object like {"CREATE": 1, "MODIFY": 1}
    #[serde(rename = "FileInode")]
    file_inode: u32,
    #[serde(rename = "FileInodeLinkCount")]
    file_inode_link_count: u32,
    #[serde(rename = "FileSize")]
    file_size: u64,
    #[serde(rename = "FileSizeChange")]
    file_size_change: i64, // isize - isize_first
    #[serde(rename = "FileAccessTime")]
    file_access_time: String,
    #[serde(rename = "FileStatusChangeTime")]
    file_status_change_time: String,
    #[serde(rename = "FileModificationTime")]
    file_modification_time: String,
    #[serde(rename = "Token", skip_serializing_if = "Option::is_none")]
    token: &'a Option<String>,
}


fn format_timestamp(nanos_since_epoch: u64) -> String {
    if nanos_since_epoch == 0 {
        return "N/A".to_string();
    }
    let secs = nanos_since_epoch / 1_000_000_000;
    let nanos = (nanos_since_epoch % 1_000_000_000) as u32;
    match NaiveDateTime::from_timestamp_opt(secs as i64, nanos) {
        Some(naive_dt) => {
            let dt: DateTime<Local> = Local.from_utc_datetime(&naive_dt);
            dt.format("%Y-%m-%d %H:%M:%S.%6f").to_string()
        }
        None => "Invalid Timestamp".to_string(),
    }
}

// Mode to string conversion (e.g., "drwxr-xr-x")
fn format_file_mode(mode: u32) -> String {
    let type_char = match mode & S_IFMT {
        S_IFREG => '-',
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFCHR => 'c',
        S_IFBLK => 'b',
        S_IFIFO => 'p',
        S_IFSOCK => 's',
        _ => '?',
    };

    let mut perms = ['-'; 9];
    if mode & S_IRUSR != 0 { perms[0] = 'r'; }
    if mode & S_IWUSR != 0 { perms[1] = 'w'; }
    if mode & S_IXUSR != 0 { perms[2] = 'x'; }
    if mode & S_IRGRP != 0 { perms[3] = 'r'; }
    if mode & S_IWGRP != 0 { perms[4] = 'w'; }
    if mode & S_IXGRP != 0 { perms[5] = 'x'; }
    if mode & S_IROTH != 0 { perms[6] = 'r'; }
    if mode & S_IWOTH != 0 { perms[7] = 'w'; }
    if mode & S_IXOTH != 0 { perms[8] = 'x'; }

    // Handle SUID, SGID, Sticky bit
    if mode & S_ISUID != 0 { perms[2] = if perms[2] == 'x' { 's' } else { 'S' }; }
    if mode & S_ISGID != 0 { perms[5] = if perms[5] == 'x' { 's' } else { 'S' }; }
    if mode & S_ISVTX != 0 { perms[8] = if perms[8] == 'x' { 't' } else { 'T' }; }

    format!("{}{}", type_char, perms.iter().collect::<String>())
}

// Constants for mode formatting (inspired by nix::sys::stat, but defined locally for u32)
// These are equivalent to S_IF* and permission constants usually found in libc or nix.
const S_IFMT: u32 = 0o0170000; // type of file mask
const S_IFSOCK: u32 = 0o140000; // socket
const S_IFLNK: u32 = 0o120000; // symbolic link
const S_IFREG: u32 = 0o100000; // regular file
const S_IFBLK: u32 = 0o060000; // block device
const S_IFDIR: u32 = 0o040000; // directory
const S_IFCHR: u32 = 0o020000; // character device
const S_IFIFO: u32 = 0o010000; // FIFO

const S_ISUID: u32 = 0o4000; // set-user-ID bit
const S_ISGID: u32 = 0o2000; // set-group-ID bit
const S_ISVTX: u32 = 0o1000; // sticky bit

const S_IRUSR: u32 = 0o0400; // owner has read permission
const S_IWUSR: u32 = 0o0200; // owner has write permission
const S_IXUSR: u32 = 0o0100; // owner has execute permission
const S_IRGRP: u32 = 0o0040; // group has read permission
const S_IWGRP: u32 = 0o0020; // group has write permission
const S_IXGRP: u32 = 0o0010; // group has execute permission
const S_IROTH: u32 = 0o0004; // others have read permission
const S_IWOTH: u32 = 0o0002; // others have write permission
const S_IXOTH: u32 = 0o0001; // others have execute permission


// Convert [u8] to String, stopping at null byte or array end
fn u8_array_to_string(arr: &[u8]) -> String {
    let len = arr.iter().position(|&b| b == 0).unwrap_or(arr.len());
    String::from_utf8_lossy(&arr[..len]).to_string()
}


async fn process_event(record: RECORD_FS, cli: &Cli, socket: Option<&UnixDatagram>) -> anyhow::Result<()> {
    let file_events_json = {
        let mut map = serde_json::Map::new();
        let mut count = 0;
        for i in 0..FS_EVENT_MAX {
            if record.event[i] == 0 { // No more events in this record
                break;
            }
            let event_val = record.event[i];
            count +=1;
            for fsevt_def in FSEVT_USER.iter() {
                if fsevt_def.value == event_val {
                    let name_str = u8_array_to_string(&fsevt_def.name).trim().to_string();
                    // Increment count for this event name
                    let current_val = map.get(&name_str).and_then(|v| v.as_u64()).unwrap_or(0);
                    map.insert(name_str, json!(current_val + 1));
                    break;
                }
            }
        }
        json!(map)
    };

    let (file_str, filepath_str) = if record.name_union.filename[0] != 0 {
        // Check if it's a rename by looking for MOVED_FROM or MOVED_TO
        let is_rename = record.event.iter().any(|&ev_val| ev_val == FS_MOVED_FROM || ev_val == FS_MOVED_TO);
        if is_rename {
            let from = u8_array_to_string(unsafe { &record.name_union.filenames.filename_from });
            let to = u8_array_to_string(unsafe { &record.name_union.filenames.filename_to });
            (format!("{} -> {}", from, to), u8_array_to_string(&record.filepath))
        } else {
            (u8_array_to_string(unsafe { &record.name_union.filename }), u8_array_to_string(&record.filepath))
        }
    } else {
        ("N/A".to_string(), u8_array_to_string(&record.filepath))
    };


    let output_data = OutputRecord {
        info_timestamp: format_timestamp(record.rc.ts),
        filepath: &filepath_str,
        file: &file_str,
        file_mode: format_file_mode(record.imode),
        file_event_count: record.events,
        file_events: file_events_json,
        file_inode: record.ino,
        file_inode_link_count: record.inlink,
        file_size: record.isize,
        file_size_change: record.isize as i64 - record.isize_first as i64,
        file_access_time: format_timestamp(record.atime_nsec),
        file_modification_time: format_timestamp(record.mtime_nsec),
        file_status_change_time: format_timestamp(record.ctime_nsec),
        token: &cli.token,
    };

    let json_output = if cli.output_format == "json-min" {
        serde_json::to_string(&output_data)?
    } else {
        serde_json::to_string_pretty(&output_data)?
    };

    if let Some(sock) = socket {
        // For UnixDatagram, send_to requires a path.
        if let Some(socket_path) = &cli.unix_socket {
            match sock.send_to(json_output.as_bytes(), socket_path).await {
                Ok(bytes_sent) => debug!("Sent {} bytes to UDS: {:?}", bytes_sent, socket_path),
                Err(e) => warn!("Failed to send event to UDS {:?}: {}", socket_path, e),
            }
        }
    }

    if !cli.quiet && !cli.daemon {
        println!("{}{}", json_output, RECORD_SEPARATOR);
    }

    Ok(())
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if cli.legend {
        println!("{}", LEGEND_INFO);
        println!("Version: {}", VERSION);
        println!("\nEvent Legend (from FSEVT_USER array):");
        for event_def in FSEVT_USER.iter() {
            println!("  Event: {:<16} Value: {:#010x} ShortName: {:<4} AltName: {:<4}",
                u8_array_to_string(&event_def.name).trim(),
                event_def.value,
                u8_array_to_string(&event_def.shortname).trim(),
                u8_array_to_string(&event_def.shortname2).trim()
            );
        }
        return Ok(());
    }
    // Clap handles --version automatically due to `version = VERSION` in `#[clap()]`
    // No need for cli.version_short()

    if unsafe { geteuid() } != 0 { // Using libc::geteuid directly
        error!("You must be root to use dirt_rs.");
        // Using a specific exit code might be good, e.g. std::process::exit(1)
        return Err(anyhow::anyhow!("Permission denied: must be root."));
    }

    // Increase memlock rlimit
    let rlim = rlimit {
        rlim_cur: 128 * 1024 * 1024, // 128 MB
        rlim_max: 128 * 1024 * 1024,
    };
    if unsafe { setrlimit(RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("Failed to increase RLIMIT_MEMLOCK. eBPF loading might fail.");
    } else {
        info!("RLIMIT_MEMLOCK increased.");
    }

    // Load eBPF object
    #[cfg(debug_assertions)]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/dirt_rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/dirt_rs"
    ))?;

    if cli.verbose {
        // Configure logger level for aya specific logs if needed, or just use RUST_LOG=aya=debug
        // EbpfLogger::init will use RUST_LOG by default.
         match EbpfLogger::init(&mut ebpf) {
            Ok(_) => info!("eBPF logger initialized."),
            Err(e) => warn!("Failed to initialize eBPF logger: {}", e),
        }
    } else {
        // Could potentially set a higher filter for aya logs if not verbose
        // For now, rely on global RUST_LOG or default info.
         match EbpfLogger::init(&mut ebpf) { // Still init, but RUST_LOG will control verbosity
            Ok(_) => debug!("eBPF logger initialized (non-verbose)."), // Use debug for this message
            Err(e) => warn!("Failed to initialize eBPF logger: {}", e),
        }
    }


    // Populate CONFIG_MAP
    let mut config_map = aya::maps::Array::try_from(ebpf.map_mut("CONFIG_MAP")?)?;
    let mut prog_config = ProgConfig::default();
    prog_config.monitor_flags = MONITOR_FILE; // Default to file monitoring
    prog_config.pid_self = std::process::id();
    prog_config.pid_shell = 0; // Set to 0 for now. C version tried to get parent PID.
                               // Consider making pid_shell an optional CLI arg if needed for precise filtering.
    prog_config.agg_events_max = cli.agg_events_max;
    if let Some(dbg_proc_str) = &cli.debug_process {
        let bytes = dbg_proc_str.as_bytes();
        let len = bytes.len().min(DBG_LEN_MAX -1);
        prog_config.debug_str[..len].copy_from_slice(&bytes[..len]);
    }
    config_map.set(0, prog_config, 0)?;
    info!("CONFIG_MAP populated.");

    // Attach Kprobes
    // Probe names must match those in the eBPF ELF file (symbols)
    // Example: "do_filp_open_kretprobe" if that's the #[kretprobe(name="do_filp_open")] function name.
    // The build script usually ensures the ELF symbol is just "do_filp_open".
    // Let's assume direct function names for now based on aya examples.
    let kprobe_fns = [
        ("do_filp_open", true), // true for kretprobe
        ("security_inode_link", false),
        ("security_inode_symlink", false),
        ("dput", false),
        ("notify_change", false),
        ("__fsnotify_parent", false),
        ("security_inode_rename", false),
        ("security_inode_unlink", false),
    ];

    for (fn_name, is_retprobe) in kprobe_fns.iter() {
        if *is_retprobe {
            let prog: &mut KRetProbe = ebpf.program_mut(fn_name)
                .ok_or_else(|| anyhow::anyhow!("failed to find kretprobe {}", fn_name))?
                .try_into()?;
            prog.load()?;
            prog.attach(fn_name, 0) // Assuming fn_name is also the kernel symbol
                .with_context(|| format!("failed to attach kretprobe {}", fn_name))?;
            info!("Attached kretprobe: {}", fn_name);
        } else {
            let prog: &mut KProbe = ebpf.program_mut(fn_name)
                .ok_or_else(|| anyhow::anyhow!("failed to find kprobe {}", fn_name))?
                .try_into()?;
            prog.load()?;
            prog.attach(fn_name, 0) // Assuming fn_name is also the kernel symbol
                 .with_context(|| format!("failed to attach kprobe {}", fn_name))?;
            info!("Attached kprobe: {}", fn_name);
        }
    }


    let mut ringbuf_records = RingBuf::try_from(ebpf.map_mut("ringbuf_records")?)?;
    let mut record_buf_array = [RECORD_FS::default(); 10]; // Buffer for batch reading

    let socket: Option<UnixDatagram> = if let Some(socket_path) = &cli.unix_socket {
        // UnixDatagram::unbound needs to be connected or send_to used.
        // For sending, it might be better to connect if it's a single destination.
        // Or, create it here and pass it to send_to.
        // Let's try unbound and use send_to.
        Some(UnixDatagram::unbound()?)
    } else {
        None
    };


    info!("Waiting for events... Press Ctrl-C to exit.");
    let mut ctrl_c_received = false;
    while !ctrl_c_received {
        tokio::select! {
            _ = signal::ctrl_c() => {
                ctrl_c_received = true;
            }
            result = ringbuf_records.read_async(&mut record_buf_array, Duration::from_millis(100)) => {
                match result {
                    Ok(events_read) => {
                        if events_read > 0 {
                            for i in 0..events_read {
                                if let Err(e) = process_event(record_buf_array[i], &cli, socket.as_ref()).await {
                                    warn!("Error processing event: {}", e);
                                }
                            }
                        }
                    }
                    Err(aya::maps::AsyncReadError::Timeout) => {
                        // Expected timeout, continue loop
                        continue;
                    }
                    Err(e) => {
                        warn!("Error reading from ring buffer: {}", e);
                        // Potentially break or handle specific errors
                    }
                }
            }
        }
    }

    info!("Exiting...");
    Ok(())
}

// Removed VersionShort trait and its implementation as clap handles --version automatically.
