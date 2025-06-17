//! User-space application for DIRT-rs (Dynamic Information Reporting Tool - Rust version).
//!
//! This program is responsible for:
//! - Parsing command-line arguments.
//! - Loading and initializing the eBPF program (`dirt_rs-ebpf`).
//! - Configuring the eBPF program via the `EBPF_SETTINGS` BPF map.
//! - Attaching all defined kprobes from the eBPF program to their respective kernel functions.
//! - Setting up a Unix domain socket for output if specified.
//! - Optionally daemonizing the process.
//! - Reading file system event data (`RecordFs`) from the eBPF program via a ring buffer.
//! - Formatting the event data as JSON (either pretty or minified).
//! - Outputting the JSON data to the configured Unix domain socket or to standard output,
//!   respecting quiet and daemon mode flags.
//! - Handling graceful shutdown on Ctrl-C or other signals (basic Ctrl-C for now).

use aya::include_bytes_aligned;
use aya::programs::KProbe;
use aya::{Ebpf, maps::{Array, AsyncRingBuffer}};
use aya_log::EbpfLogger;
use dirt_rs_common::{Stats, EbpfSettings, MONITOR_FILE, RecordFs}; // Shared types from common crate
use log::{debug, info, warn, error};
use tokio::{signal, task, net::UnixDatagram, io::{self, AsyncWriteExt}};
use clap::Parser;
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::process::parent_id; // For getting parent PID, more robust than shell `getppid`
use bytes::BytesMut;
use std::mem;
use std::sync::Arc;
use serde_json;
use daemonize::Daemonize;

/// Defines the command-line arguments accepted by the DIRT-rs user-space application.
/// Uses the `clap` crate for parsing and automatic help/version generation.
#[derive(Parser, Debug)]
#[command(author = "Dirt Inc.", version, about = "Dynamic Information Reporting Tool (Rust version)", long_about = None, name="dirt-rs")]
struct CliArgs {
    /// Maximum number of filesystem events to aggregate into a single record before sending.
    /// Default is disabled (0), meaning aggregation is primarily time-based or by event type.
    /// A value of '1' means no event aggregation (each event is a separate record).
    #[arg(short, long, value_name = "EVENTS", help = "Max number of filesystem events per aggregated record (default: disabled, '1': no aggregation)")]
    agg_events: Option<u32>,

    /// Specifies the output format for event records.
    /// "json" produces pretty-printed JSON.
    /// "json-min" produces minified (compact) JSON.
    #[arg(short, long, value_name = "FORMAT", default_value = "json", help = "Output format: json, json-min")]
    output_format: String,

    /// Path to a Unix domain socket to which JSON output will be sent.
    /// If not provided, output goes to stdout (unless quiet/daemon mode modifies this).
    #[arg(short = 'x', long = "unix-socket", value_name = "SOCKET_PATH", help = "Unix domain socket path to send json output to")]
    socket_path: Option<String>,

    /// Suppresses all output to the stdout console.
    /// Particularly useful when outputting to a socket or running as a daemon.
    #[arg(short, long, help = "Quiet mode to suppress output to stdout console")]
    quiet: bool,

    /// Detaches the program from the terminal and runs it in the background as a daemon.
    /// Requires a Unix domain socket path (`-x`) for output.
    #[arg(short, long, help = "Daemonize program to run in background")]
    daemon: bool,

    /// Enables verbose logging output, including eBPF loading messages and CO-RE relocations
    /// (if Aya's logging level is also configured appropriately, e.g., via RUST_LOG=aya=debug).
    #[arg(short = 'V', long, help = "Verbose output (eBPF load/co-re messages)")]
    verbose: bool,

    /// An optional token string that will be included in the JSON output.
    /// Useful for tagging or identifying event streams.
    #[arg(short = 'T', long, value_name = "TOKEN", help = "Token specified on host to be included in json output")]
    token: Option<String>,

    /// Displays a legend of event types and output fields, then exits.
    #[arg(short, long, alias = "legend", help = "Show legend")]
    show_legend: bool,

    /// For debugging eBPF: filters kernel trace pipe messages to a specific process.
    /// Not yet fully implemented in terms of passing to eBPF settings.
    #[arg(short = 'D', long, value_name = "PROCESS_FILTER", help = "Debug: Print eBPF kernel log messages of process to kernel trace pipe ('*' for any)")]
    debug_process_filter: Option<String>,
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logger (env_logger). Default log level is `info`.
    // `RUST_LOG` environment variable can override this (e.g., `RUST_LOG=debug` or `RUST_LOG=aya=debug`).
    env_logger::Builder::from_default_env()
        .format_timestamp_nanos()
        .init();

    // Parse command-line arguments
    let cli = CliArgs::parse();
    // Wrap CLI arguments in an Arc for safe sharing across asynchronous tasks.
    let cli_arc = Arc::new(cli);

    // Handle --legend flag: print legend and exit.
    if cli_arc.show_legend {
        println!("Legend for DIRT (Dynamic Information Reporting Tool):");
        println!("----------------------------------------------------");
        println!("Event Types (Subject to kernel hook availability):");
        println!("  CREATE      - File or directory creation");
        println!("  OPEN        - File or directory opened");
        println!("  OPEN_EXEC   - File opened for execution");
        println!("  ACCESS      - File or directory accessed (read)");
        println!("  ATTRIB      - Metadata change (chmod, chown, timestamps)");
        println!("  MODIFY      - File modified (written to)");
        println!("  CLOSE_WRITE - File closed after writing");
        println!("  CLOSE_NOWRITE - File closed without writing");
        println!("  MOVED_FROM  - File renamed/moved from this name/path");
        println!("  MOVED_TO    - File renamed/moved to this name/path");
        println!("  DELETE      - File or directory deleted");
        println!("\nOutput Fields (JSON format):");
        println!("  rc.type     - Record type (e.g., 1 for FS event)");
        println!("  rc.ts       - Timestamp of the event (nanoseconds since boot)");
        println!("  events      - Total aggregated event operations for this record");
        println!("  event_counts - Map of specific event types and their counts in this record (e.g., {{\\\"CREATE\\\":1, \\\"MODIFY\\\":2}})");
        println!("  ino         - Inode number");
        println!("  imode       - Inode mode (permissions and file type)");
        println!("  inlink      - Number of hard links");
        println!("  isize       - File size");
        println!("  atime_nsec  - Last access time");
        println!("  mtime_nsec  - Last modification time");
        println!("  ctime_nsec  - Last status change time");
        println!("  isize_first - File size at first event in aggregation period");
        println!("  filepath    - Full path to the file/directory");
        println!("  filename    - Name of the file/directory (context-dependent for renames)");
        println!("  filename_from - Original filename for MOVED_TO events");
        println!("  filename_to   - New filename for MOVED_FROM events (if part of a rename pair processed together)");
        println!("  token       - User-supplied token (if provided via -T)");
        println!("----------------------------------------------------");
        return Ok(());
    }

    info!("Parsed arguments: {:#?}", cli_arc);
    if cli_arc.verbose {
        info!("Verbose mode enabled. More detailed eBPF loading logs might be available if RUST_LOG for Aya is also set (e.g., RUST_LOG=aya=debug).");
    }

    // Setup Unix Domain Socket for output if a path is provided via CLI.
    // This is done before potential daemonization so any setup errors are reported to the original terminal.
    let unix_socket_arc: Option<Arc<UnixDatagram>> = if let Some(socket_path_str) = &cli_arc.socket_path {
        match UnixDatagram::unbound() {
            Ok(socket) => {
                info!("Successfully created unbound UnixDatagram socket for output to: {}", socket_path_str);
                Some(Arc::new(socket))
            },
            Err(e) => {
                warn!("Failed to create unbound UnixDatagram socket for path '{}': {}. Output to socket will be disabled.", socket_path_str, e);
                None
            }
        }
    } else {
        None
    };

    // Increase memlock rlimit for eBPF map creation.
    // This is essential for older kernels that don't use cgroup-based memory accounting for BPF.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("Failed to remove limit on locked memory (RLIMIT_MEMLOCK), return code: {}. This might cause issues on older kernels.", ret);
    }

    // Load the eBPF bytecode.
    // The path depends on whether it's a debug or release build.
    #[cfg(debug_assertions)]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/debug/dirt_rs-ebpf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/dirt_rs-ebpf"
    ))?;
    info!("eBPF program loaded successfully.");

    // Initialize the eBPF logger, which forwards bpf_printk messages from eBPF to the user-space logger.
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}. This can happen if the eBPF program has no log statements.", e);
    }

    // Populate `EbpfSettings` struct with values from CLI arguments and system info.
    let current_time_ns = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("SystemTime is before UNIX EPOCH: {}",e))?
        .as_nanos() as u64;

    let settings = EbpfSettings {
        ts_start: current_time_ns,
        agg_events_max: cli_arc.agg_events.unwrap_or(0),
        pid_self: std::process::id(),
        pid_shell: parent_id(), // Get parent process ID.
        monitor_mode: MONITOR_FILE, // Currently, only file monitoring is implemented.
        // TODO: Populate debug_filter from cli_arc.debug_process_filter if/when EbpfSettings includes it.
    };

    // Write the settings to the `EBPF_SETTINGS` BPF map.
    let mut settings_map: Array<_, EbpfSettings> = Array::try_from(ebpf.map_mut("EBPF_SETTINGS")?)?;
    settings_map.set(0, settings, 0)?;
    info!("eBPF settings configured and written to map: {:?}", settings);

    // Define the mapping of eBPF program names (in the object file) to kernel function names to hook.
    let kprobes_to_attach: &[(&str, &str)] = &[
        ("kretprobe_do_filp_open", "do_filp_open"),
        ("kprobe_security_inode_link", "security_inode_link"),
        ("kprobe_security_inode_symlink", "security_inode_symlink"),
        ("kprobe_dput", "dput"),
        ("kprobe_notify_change", "notify_change"),
        ("kprobe_fsnotify_parent", "__fsnotify_parent"),
        ("kprobe_security_inode_rename", "security_inode_rename"),
        ("kprobe_security_inode_unlink", "security_inode_unlink"),
    ];

    // Load and attach each kprobe.
    for (program_name, target_fn_name) in kprobes_to_attach.iter() {
        info!("Loading and attaching kprobe: {} to kernel fn: {}", program_name, target_fn_name);
        let prog: &mut KProbe = ebpf.program_mut(program_name)
            .ok_or_else(|| anyhow::anyhow!("Failed to find program {} in eBPF object", program_name))?
            .try_into()?;
        prog.load()?;
        prog.attach(target_fn_name, 0)?;
        info!("Successfully attached kprobe '{}' to kernel function '{}'", program_name, target_fn_name);
    }

    info!("Successfully loaded and attached all eBPF kprobes.");

    // Daemonization logic: If requested, detach from terminal and run in background.
    if cli_arc.daemon {
        // Daemon mode requires a socket path for output, as stdout/stderr will be redirected.
        if cli_arc.socket_path.is_none() {
            eprintln!("Error: Daemon mode (-d, --daemon) requires a Unix domain socket path (-x, --unix-socket) to be specified for output.");
            error!("Daemon mode requires a socket path for output. Please specify with -x or --unix-socket.");
            return Err(anyhow::anyhow!("Daemon mode requires a socket path."));
        }
        info!("Attempting to daemonize...");
        let pid_file_path = format!("/tmp/dirt_rs_{}.pid", std::process::id());
        let daemonize = Daemonize::new()
            .pid_file(&pid_file_path)
            .chown_pid_file(false)
            .working_directory("/")
            .umask(0o027); // Set a restrictive umask for files created by the daemon.

        match daemonize.start() {
            Ok(_) => {
                info!("Successfully daemonized. Process running in background. PID file: {}", pid_file_path);
                // The parent process exits here. The child (daemon) continues.
                // Logging from this point in the daemon will typically go to syslog or be lost
                // if stdout/stderr are redirected to /dev/null by daemonize (default).
            }
            Err(e) => {
                error!("Error daemonizing: {}", e);
                return Err(anyhow::anyhow!("Daemonization failed: {}", e));
            }
        }
    }

    // Open the ring buffer for receiving events from eBPF.
    let mut ringbuf = AsyncRingBuffer::try_from(ebpf.map_mut("RINGBUF_RECORDS")?)?;
    info!("Starting to listen for events from eBPF program via RINGBUF_RECORDS...");

    // Spawn a Tokio task for each online CPU to process events from its corresponding ring buffer.
    for cpu_id in aya::util::online_cpus()? {
        let mut buf = ringbuf.open(cpu_id, None)?;
        info!("Opened ring buffer for CPU ID: {}", cpu_id);
        let task_cli_arc = Arc::clone(&cli_arc);
        let task_socket_arc = unix_socket_arc.clone(); // Clone Arc for socket

        task::spawn(async move {
            // Pre-allocate buffers for reading events.
            let mut buffers = Vec::with_capacity(10); // Capacity for 10 events per read_events call
            for _ in 0..10 {
                // Size of RecordFs plus some headroom.
                buffers.push(BytesMut::with_capacity(mem::size_of::<RecordFs>() + 1024));
            }

            loop { // Main event reading loop for this CPU task.
                match buf.read_events(&mut buffers).await {
                    Ok(num_events) => {
                        if num_events == 0 { // No events read, sleep briefly to avoid busy loop.
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            continue;
                        }
                        for i in 0..num_events { // Process each received event.
                            let event_data = &buffers[i];
                            if event_data.len() >= mem::size_of::<RecordFs>() {
                                // Safely cast raw bytes to RecordFs due to Pod trait.
                                let record_ptr = event_data.as_ptr() as *const RecordFs;
                                let record = unsafe { &*record_ptr };

                                // Serialize record to JSON based on CLI format.
                                let json_string = if task_cli_arc.output_format == "json-min" {
                                    match serde_json::to_string(record) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            warn!("CPU[{}]: Failed to serialize record to json-min: {}", cpu_id, e);
                                            continue; // Skip this record
                                        }
                                    }
                                } else { // Default to pretty json
                                    match serde_json::to_string_pretty(record) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            warn!("CPU[{}]: Failed to serialize record to json: {}", cpu_id, e);
                                            continue; // Skip this record
                                        }
                                    }
                                };

                                // Output handling: socket and/or stdout.
                                let mut sent_to_socket_and_quiet = false;
                                // Attempt socket output if socket and path are configured.
                                if let (Some(socket), Some(path_str)) = (&task_socket_arc, &task_cli_arc.socket_path) {
                                    match socket.send_to(json_string.as_bytes(), path_str).await {
                                        Ok(bytes_sent) => {
                                            debug!("CPU[{}]: Sent {} bytes to unix socket '{}'", cpu_id, bytes_sent, path_str);
                                            if task_cli_arc.quiet { // If quiet mode, socket output is enough.
                                                sent_to_socket_and_quiet = true;
                                            }
                                        }
                                        Err(e) => warn!("CPU[{}]: Failed to send to unix socket '{}': {}", cpu_id, path_str, e),
                                    }
                                }

                                // Stdout output logic, respecting daemon and quiet flags.
                                if !sent_to_socket_and_quiet {
                                    // Condition from C: if (!daemon_mode && (!unix_socket || (unix_socket && !quiet_mode)))
                                    if !task_cli_arc.daemon && (task_cli_arc.socket_path.is_none() || !task_cli_arc.quiet) {
                                        let mut stdout = io::stdout();
                                        if let Err(e) = stdout.write_all(json_string.as_bytes()).await {
                                            warn!("CPU[{}]: Failed to write JSON to stdout: {}", cpu_id, e);
                                        }
                                        // Record separator: newline, RS (0x1e), newline.
                                        if let Err(e) = stdout.write_all(b"\n\x1e\n").await {
                                            warn!("CPU[{}]: Failed to write record separator to stdout: {}", cpu_id, e);
                                        }
                                        if let Err(e) = stdout.flush().await { // Ensure data is written.
                                             warn!("CPU[{}]: Failed to flush stdout: {}", cpu_id, e);
                                        }
                                    }
                                }
                            } else { // Data received is smaller than expected RecordFs size.
                                warn!("CPU[{}]: Received undersized event data ({} bytes, expected at least {} bytes)",
                                      cpu_id, event_data.len(), mem::size_of::<RecordFs>());
                            }
                        }
                    }
                    Err(e) => { // Error reading from the ring buffer.
                        warn!("CPU[{}]: Error reading from ring buffer: {}", cpu_id, e);
                        if !e.is_recoverable() { // Non-recoverable error, exit this CPU task.
                             error!("CPU[{}]: Non-recoverable error reading ring buffer, exiting task.", cpu_id);
                            break;
                        }
                        // For recoverable errors, pause briefly before retrying.
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    if cli_arc.daemon {
        info!("Daemon process started. Ring buffer listeners are active in background tasks.");
        // In daemon mode, the main thread can either exit (if tasks are truly detached)
        // or enter a state awaiting a shutdown signal. Tokio tasks will continue.
        // The Ctrl-C handler below is primarily for non-daemon foreground operation.
    }

    info!("Application operational. Waiting for Ctrl-C to exit foreground process (if not daemonized)...");
    signal::ctrl_c().await?; // Wait for Ctrl-C signal.
    info!("Ctrl-C received. Exiting..."); // This log might not be seen if daemonized & stdout is /dev/null

    Ok(())
}
