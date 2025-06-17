//! eBPF program for DIRT-rs (Dynamic Information Reporting Tool - Rust version)
//!
//! This program attaches to various kernel functions (kprobes) to monitor
//! file system events. It collects information about these events, aggregates
//! them if configured, and sends the data to a user-space application via
//! a ring buffer.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, kprobe},
    programs::ProbeContext,
    maps::{RingBuf, LruHashMap, PerCpuArray, Array},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes, bpf_core_read},
    bindings::{dentry, file, inode, iattr, linux_id::FMODE_CREATED},
};
use aya_log_ebpf::info;
use core::ffi::c_char;

use dirt_rs_common::*; // Import shared structs and constants

// Constants for BPF map sizes. These mirror definitions from the original C version of DIRT.
const MAP_RECORDS_MAX: u32 = 65536; // Max entries for HASH_RECORDS
const RINGBUF_TOTAL_BYTE_SIZE: u32 = 8192 * 256; // Total size for the ring buffer (e.g., 2MB)
const PENDING_SYMLINKS_MAX_ENTRIES: u32 = 1024; // Max entries for PENDING_SYMLINKS

// BPF Maps Definitions
// --------------------

/// Ring buffer for sending collected `RecordFs` event data to user-space.
#[map]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_max_entries(RINGBUF_TOTAL_BYTE_SIZE, 0);

/// Hash map to store and aggregate file system event records (`RecordFs`).
/// Keyed by `key_pid_ino` (a combination of PID and inode number).
/// Uses LRU (Least Recently Used) eviction strategy.
#[map]
static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::with_max_entries(MAP_RECORDS_MAX, 0);

/// Per-CPU array used as temporary storage for `RecordFs` structs before they are
/// committed to `HASH_RECORDS` or the ring buffer. This helps avoid needing locks
/// for shared data structures by providing each CPU with its own scratch space.
#[map]
static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

/// Array map to store global statistics (`Stats` struct) for the eBPF program.
/// Only one entry (index 0) is used.
#[map]
static mut STATS_MAP: Array<Stats> = Array::with_max_entries(1, 0);

/// LRU Hash map to temporarily store dentry addresses for symlink creation.
/// Keyed by PID. Used to correlate `security_inode_symlink` (where dentry is created)
/// with `dput` (where inode information becomes available for the symlink).
#[map]
static mut PENDING_SYMLINKS: LruHashMap<u32, u64> = LruHashMap::with_max_entries(PENDING_SYMLINKS_MAX_ENTRIES, 0);

/// Configuration structure loaded from user-space.
/// This struct holds settings that control the behavior of the eBPF program,
/// such as event aggregation limits, PIDs to ignore, and monitoring modes.
/// TODO: Consider adding `debug_filter` field here if eBPF-side filtering for debug messages is needed.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct EbpfSettings {
    /// Timestamp (nanoseconds since boot) when the user-space program started.
    pub ts_start: u64,
    /// Maximum number of events to aggregate in a single `RecordFs` before sending.
    /// 0 typically means aggregation is primarily time/event-type based rather than count based.
    /// 1 means no event aggregation (each event is a separate record).
    pub agg_events_max: u32,
    /// PID of the user-space DIRT-rs process itself, to avoid self-monitoring.
    pub pid_self: u32,
    /// PID of the shell process from which DIRT-rs was launched (often the parent of pid_self).
    pub pid_shell: u32,
    /// Bitmask to control monitoring modes (e.g., file monitoring, network monitoring).
    pub monitor_mode: u32,
    // pub debug_filter: [u8; DBG_LEN_MAX], // TODO: For eBPF side debug filtering if needed.
}

impl Default for EbpfSettings {
    fn default() -> Self {
        EbpfSettings {
            ts_start: 0,
            agg_events_max: 0,
            pid_self: 0,
            pid_shell: 0,
            monitor_mode: MONITOR_NONE, // Default to no monitoring
        }
    }
}

/// Array map to hold the `EbpfSettings` instance provided by user-space.
/// Only one entry (index 0) is used.
#[map]
static mut EBPF_SETTINGS: Array<EbpfSettings> = Array::with_max_entries(1, 0);

/// Temporary struct to pass detailed event information from kprobes to `handle_fs_event`.
/// This simplifies the argument list for `handle_fs_event` and centralizes data extraction
/// logic within the kprobes.
#[derive(Copy, Clone)]
struct FsEventInfo {
    event_type: FsEvent,    // The type of filesystem event (e.g., Create, Modify, Delete).
    pid: u32,               // PID of the process that triggered the event.
    inode_number: u32,      // Inode number of the affected file/directory.
    file_mode: u32,         // File mode (permissions and type, e.g., S_IFREG, S_ISLNK).
    filename: [u8; FILENAME_LEN_MAX], // Filename (UTF-8 bytes, null-terminated).
    new_filename_if_moved: Option<[u8; FILENAME_LEN_MAX]>, // For MovedTo events, the new filename.
    filepath: [u8; FILEPATH_LEN_MAX], // Full path to the file/directory.
    size: u64,              // File size.
    atime_nsec: u64,        // Last access time (nanoseconds).
    mtime_nsec: u64,        // Last modification time (nanoseconds).
    ctime_nsec: u64,        // Last status change time (nanoseconds).
    nlink: u32,             // Number of hard links.
}

/// Core event handling function for file system events.
///
/// This function is called by various kprobes that detect file system activity.
/// It performs the following main tasks:
/// 1. Retrieves current settings from the `EBPF_SETTINGS` map.
/// 2. Filters out events from the DIRT-rs process itself.
/// 3. Generates a unique key for the event based on PID and inode number.
/// 4. Checks `HASH_RECORDS` for an existing record for this key:
///    - If a record exists (event aggregation): Updates the existing record's timestamps,
///      metadata (size, mode, link count, times), increments event counters.
///      For `MovedTo` events, it updates the `filename_to` field in the record's union.
///    - If no record exists: Creates a new `RecordFs` instance using `HEAP_RECORD_FS`
///      as temporary storage. Initializes it with event details from `FsEventInfo`
///      (type, timestamp, inode info, filename, filepath, initial event counts).
///      Inserts the new record into `HASH_RECORDS`. Increments `fs_records` stat.
/// 5. Determines if event aggregation should end based on:
///    - Event type (e.g., close, delete, move).
///    - For `Create` events: if it's a symlink or has multiple hard links.
///    - If `agg_events_max` from settings is reached.
/// 6. If aggregation ends:
///    - Sends the `RecordFs` to user-space via `RINGBUF_RECORDS`.
///    - If sending fails, increments `fs_records_dropped` stat.
///    - Removes the record from `HASH_RECORDS`.
///    - Increments `fs_records_deleted` stat.
/// 7. Increments the global `fs_events` counter in `STATS_MAP`.
fn handle_fs_event(
    ctx: &ProbeContext,
    event_info: FsEventInfo,
) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;

    if settings.pid_self == event_info.pid {
        return Ok(());
    }

    let key = key_pid_ino(event_info.pid, event_info.inode_number);
    let mut existing_record_opt = unsafe { HASH_RECORDS.get_mut(&key) };

    let ts_event = bpf_ktime_get_ns();

    if let Some(record_fs) = existing_record_opt.as_mut() {
        record_fs.rc.ts = ts_event;
        record_fs.imode = event_info.file_mode;
        record_fs.isize = event_info.size;
        record_fs.inlink = event_info.nlink;
        record_fs.atime_nsec = event_info.atime_nsec;
        record_fs.mtime_nsec = event_info.mtime_nsec;
        record_fs.ctime_nsec = event_info.ctime_nsec;
        record_fs.events += 1;
        record_fs.event[event_info.event_type as usize] += 1;

        if event_info.event_type == FsEvent::MovedTo {
            if let Some(new_name) = event_info.new_filename_if_moved {
                unsafe {
                    record_fs.union_filenames.filenames_from_to.filename_to = new_name;
                }
            }
        }

    } else {
        let mut new_record_fs_ptr = unsafe {HEAP_RECORD_FS.get_ptr_mut(&zero)}.ok_or(2i32)?;

        unsafe {
            (*new_record_fs_ptr).rc.type_ = RECORD_TYPE_FILE;
            (*new_record_fs_ptr).rc.ts = ts_event;
            (*new_record_fs_ptr).ino = event_info.inode_number;
            (*new_record_fs_ptr).imode = event_info.file_mode;
            (*new_record_fs_ptr).isize_first = event_info.size;
            (*new_record_fs_ptr).isize = event_info.size;
            (*new_record_fs_ptr).inlink = event_info.nlink;
            (*new_record_fs_ptr).atime_nsec = event_info.atime_nsec;
            (*new_record_fs_ptr).mtime_nsec = event_info.mtime_nsec;
            (*new_record_fs_ptr).ctime_nsec = event_info.ctime_nsec;
            (*new_record_fs_ptr).events = 1;

            for i in 0..FS_EVENT_MAX {
                (*new_record_fs_ptr).event[i] = 0;
            }
            (*new_record_fs_ptr).event[event_info.event_type as usize] = 1;

            (*new_record_fs_ptr).union_filenames.filename = event_info.filename;
            (*new_record_fs_ptr).filepath = event_info.filepath;

            if event_info.event_type == FsEvent::MovedFrom {
                 (*new_record_fs_ptr).union_filenames.filenames_from_to.filename_from = event_info.filename;
                 (*new_record_fs_ptr).union_filenames.filenames_from_to.filename_to = [0u8; FILENAME_LEN_MAX / 2];
            }
        }

        if unsafe { HASH_RECORDS.insert(&key, &*new_record_fs_ptr, 0).is_err() } {
            return Err(3i32);
        }
        if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(&zero) } {
            unsafe { (*stats).fs_records = (*stats).fs_records.wrapping_add(1); }
        }
    }

    let mut agg_end = false;
    match event_info.event_type {
        FsEvent::CloseWrite |
        FsEvent::CloseNowrite |
        FsEvent::Delete |
        FsEvent::MovedTo => agg_end = true,
        FsEvent::Create => {
            if let Some(record_fs) = unsafe { HASH_RECORDS.get(&key) } {
                 if (record_fs.imode & 0o120000 == 0o120000) /* S_ISLNK */ || record_fs.inlink > 1 {
                    agg_end = true;
                 }
            }
        }
        _ => {}
    }

    if !agg_end && settings.agg_events_max > 0 {
        if let Some(record_fs) = unsafe { HASH_RECORDS.get(&key) } {
            if record_fs.events >= settings.agg_events_max {
                agg_end = true;
            }
        }
    }

    if agg_end {
        if let Some(record_fs_to_send) = unsafe { HASH_RECORDS.get(&key) } {
            let result = unsafe { RINGBUF_RECORDS.output(record_fs_to_send, 0) };
            if result.is_err() {
                if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(&zero) } {
                    unsafe { (*stats).fs_records_dropped = (*stats).fs_records_dropped.wrapping_add(1); }
                }
            }
        }
        if unsafe { HASH_RECORDS.remove(&key).is_err() } {
            // This is not necessarily an error if the entry was already evicted by LRU logic.
        }
        if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(&zero) } {
            unsafe { (*stats).fs_records_deleted = (*stats).fs_records_deleted.wrapping_add(1); }
        }
    }

    if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(&zero) } {
        unsafe { (*stats).fs_events = (*stats).fs_events.wrapping_add(1); }
    }

    Ok(())
}

/// Helper function to construct the full file path from a dentry.
/// Traverses parent dentries until the root is reached, prepending component names.
/// Handles path length limits and component separation.
fn get_file_path_from_dentry(dentry_ptr: *const dentry) -> Result<[u8; FILEPATH_LEN_MAX], i32> {
    let mut path_bytes = [0u8; FILEPATH_LEN_MAX];
    let mut current_dentry_ptr = dentry_ptr;
    let mut current_offset = FILEPATH_LEN_MAX; // Start writing from the end of the buffer
    let mut total_len = 0;

    // Iterate upwards through the dentry tree.
    // FILEPATH_NODE_MAX provides a safeguard against excessively deep or circular paths.
    for _ in 0..FILEPATH_NODE_MAX {
        if current_dentry_ptr.is_null() {
            break;
        }

        // Read d_name.name (filename component) from the current dentry.
        // This relies on CO-RE to correctly access `d_name.name`.
        // `bpf_probe_read_kernel_str_bytes` is used for safe string reading from kernel space.
        let name_src_ptr = unsafe { bpf_core_read!((*current_dentry_ptr).d_name.name) } as *const c_char;

        let mut name_bytes_temp = [0u8; DNAME_INLINE_LEN]; // Max length for a single path component
        let len_read = match unsafe { bpf_probe_read_kernel_str_bytes(name_src_ptr, &mut name_bytes_temp) } {
            Ok(l) if l > 0 => l as usize,
            Ok(_) => break,
            Err(e) => return Err(e as i32),
        };

        let actual_len = name_bytes_temp.iter().position(|&x| x == 0).unwrap_or(len_read.min(DNAME_INLINE_LEN));
        if actual_len == 0 { break; }


        // Check if there's enough space in path_bytes to prepend this component and a separator.
        if total_len + actual_len + (if total_len > 0 {1} else {0}) > FILEPATH_LEN_MAX {
            break;
        }

        // Prepend the component name.
        current_offset -= actual_len;
        if current_offset < 0 { break; } // Should be caught by space check, but good for safety.
        unsafe {
            core::ptr::copy_nonoverlapping(name_bytes_temp.as_ptr(), path_bytes.as_mut_ptr().add(current_offset), actual_len);
        }
        total_len += actual_len;

        // Read the parent dentry.
        let parent_dentry_ptr = unsafe { bpf_core_read!((*current_dentry_ptr).d_parent) };

        // If current dentry is its own parent, it's the root of this path segment.
        if current_dentry_ptr == parent_dentry_ptr {
             // Add leading '/' if it's the root and path has content.
            if total_len > 0 && current_offset > 0 {
                current_offset -= 1;
                path_bytes[current_offset] = b'/';
                total_len += 1;
            }
            break;
        }
        current_dentry_ptr = parent_dentry_ptr;

        // Prepend '/' separator if not the very first component added (which would be the root '/').
        if total_len > 0 && current_offset > 0 {
            current_offset -= 1;
            path_bytes[current_offset] = b'/';
            total_len += 1;
        }
    }

    // Shift the constructed path to the beginning of the buffer if it wasn't fully filled.
    if current_offset > 0 && total_len > 0 {
        unsafe {
            core::ptr::copy(path_bytes.as_ptr().add(current_offset), path_bytes.as_mut_ptr(), total_len);
        }
    }
    // Null-terminate the rest of the buffer.
    for i in total_len..FILEPATH_LEN_MAX {
        path_bytes[i] = 0;
    }

    Ok(path_bytes)
}

// Kprobe Implementations
// ----------------------

/// Kretprobe for `do_filp_open`. Handles `FsEvent::Create` for regular files if `FMODE_CREATED` is set.
#[kretprobe]
pub fn kretprobe_do_filp_open(ctx: ProbeContext) -> u32 {
    match try_kretprobe_do_filp_open(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kretprobe_do_filp_open(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    let filp_ptr = ctx.retval() as *const file;
    if filp_ptr.is_null() {
        return Err(2i32);
    }

    let f_mode: u32 = unsafe { bpf_core_read!((*filp_ptr).f_mode) };

    if f_mode & FMODE_CREATED == FMODE_CREATED { // Check if the file was created during this open operation.
        let dentry_ptr = unsafe { bpf_core_read!((*filp_ptr).f_path.dentry) };
        if dentry_ptr.is_null() {
            return Err(3i32);
        }

        let inode_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_inode) };
        if inode_ptr.is_null() {
            return Err(4i32);
        }

        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;

        if settings.pid_self == pid || settings.pid_shell == pid {
            return Ok(());
        }

        let i_mode: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
        let s_ifmt = 0o170000u32;
        let s_ifreg = 0o100000u32;
        let s_iflnk = 0o120000u32;

        if !((i_mode & s_ifmt) == s_ifreg || (i_mode & s_ifmt) == s_iflnk) { // Only regular files or symlinks.
            return Ok(());
        }

        let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
        let d_name_char_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
        match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
            Ok(len) if len > 0 => {},
            Ok(_) => return Err(5i32),
            Err(e) => return Err(e as i32),
        }

        let filepath_bytes = match get_file_path_from_dentry(dentry_ptr) {
            Ok(path) => path,
            Err(e) => return Err(e),
        };

        let event_info = FsEventInfo {
            event_type: FsEvent::Create,
            pid,
            inode_number: unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32,
            file_mode: i_mode,
            filename: filename_bytes,
            new_filename_if_moved: None,
            filepath: filepath_bytes,
            size: unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64,
            atime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
            mtime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
            ctime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
            nlink: unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32,
        };
        handle_fs_event(&ctx, event_info)?;
    }
    Ok(())
}

/// Kprobe for `security_inode_link`. Handles `FsEvent::Create` for hard links.
#[kprobe]
pub fn kprobe_security_inode_link(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_link(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_security_inode_link(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    // Args: old_dentry (arg0), dir_inode (arg1), new_dentry (arg2)
    // We are interested in new_dentry as it represents the created link.
    let new_dentry_ptr = ctx.arg::<*const dentry>(2).ok_or(11i32)?;

    if new_dentry_ptr.is_null() {
        return Err(3i32);
    }

    let inode_ptr = unsafe { bpf_core_read!((*new_dentry_ptr).d_inode) };
    if inode_ptr.is_null() {
        return Err(4i32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if settings.pid_self == pid || settings.pid_shell == pid {
        return Ok(());
    }

    let i_mode: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
    let s_ifmt = 0o170000u32;
    let s_ifreg = 0o100000u32;
    let s_iflnk = 0o120000u32;
    if !((i_mode & s_ifmt) == s_ifreg || (i_mode & s_ifmt) == s_iflnk) { // Target of link should be file/symlink
        return Ok(());
    }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { bpf_core_read!((*new_dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(len) if len > 0 => {},
        Ok(_) => return Err(5i32),
        Err(e) => return Err(e as i32),
    }
    let filepath_bytes = match get_file_path_from_dentry(new_dentry_ptr) {
        Ok(path) => path,
        Err(e) => return Err(e),
    };

    let event_info = FsEventInfo {
        event_type: FsEvent::Create,
        pid,
        inode_number: unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32,
        file_mode: i_mode,
        filename: filename_bytes,
        new_filename_if_moved: None,
        filepath: filepath_bytes,
        size: unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64,
        atime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
        mtime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
        ctime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
        nlink: unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32, // nlink will be > 1 for new hard link
    };

    handle_fs_event(&ctx, event_info)?;
    Ok(())
}

/// Kprobe for `security_inode_symlink`. Stores the dentry address of the new symlink
/// in `PENDING_SYMLINKS` map, keyed by PID. This is used by `kprobe_dput` to finalize
/// the symlink creation event when its inode information is available.
#[kprobe]
pub fn kprobe_security_inode_symlink(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_symlink(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_security_inode_symlink(ctx: ProbeContext) -> Result<(), i32> {
    // Args: dir_inode (arg0), dentry (arg1), symlink_target_path (arg2)
    let dentry_ptr = ctx.arg::<*const dentry>(1).ok_or(20i32)?;
    if dentry_ptr.is_null() {
        return Err(21i32);
    }
    let dentry_addr = dentry_ptr as u64;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    unsafe {
        PENDING_SYMLINKS.insert(&pid, &dentry_addr, 0).map_err(|e| e as i32)?;
    }
    Ok(())
}

/// Kprobe for `dput`. This function is called when a dentry's reference count is decremented.
/// It's used here to finalize `FsEvent::Create` for symbolic links by correlating with
/// entries in `PENDING_SYMLINKS`.
#[kprobe]
pub fn kprobe_dput(ctx: ProbeContext) -> u32 {
    match try_kprobe_dput(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_dput(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    let dentry_arg_ptr = ctx.arg::<*const dentry>(0).ok_or(30i32)?;
    if dentry_arg_ptr.is_null() {
        return Ok(());
    }
    let dentry_arg_addr = dentry_arg_ptr as u64;

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    let stored_dentry_addr_opt = unsafe { PENDING_SYMLINKS.get(&pid) };

    if let Some(stored_dentry_addr) = stored_dentry_addr_opt {
        if *stored_dentry_addr == dentry_arg_addr { // Matched a dentry from security_inode_symlink

            unsafe { PENDING_SYMLINKS.remove(&pid).map_err(|e| e as i32)?; }

            let inode_ptr = unsafe { bpf_core_read!((*dentry_arg_ptr).d_inode) };
            if inode_ptr.is_null() { // Can happen if symlink creation failed after security_inode_symlink
                return Ok(());
            }

            let i_mode: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
            let s_ifmt = 0o170000u32;
            let s_iflnk = 0o120000u32;

            if (i_mode & s_ifmt) == s_iflnk { // Confirmed it's a symlink
                if settings.pid_self == pid || settings.pid_shell == pid {
                    return Ok(());
                }

                let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
                let d_name_char_ptr = unsafe { bpf_core_read!((*dentry_arg_ptr).d_name.name) } as *const c_char;
                match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
                    Ok(len) if len > 0 => {},
                    Ok(_) => return Err(32i32),
                    Err(e) => return Err(e as i32),
                }

                let filepath_bytes = match get_file_path_from_dentry(dentry_arg_ptr) {
                     Ok(path) => path,
                     Err(e) => return Err(e),
                };

                let event_info = FsEventInfo {
                    event_type: FsEvent::Create,
                    pid,
                    inode_number: unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32,
                    file_mode: i_mode,
                    filename: filename_bytes,
                    new_filename_if_moved: None,
                    filepath: filepath_bytes,
                    size: unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64,
                    atime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
                    mtime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
                    ctime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
                    nlink: unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32,
                };
                handle_fs_event(&ctx, event_info)?;
            }
        }
    }
    Ok(())
}

// ATTR_* constants used by notify_change to interpret iattr->ia_valid flags.
// These values mirror those in <linux/fs.h>.
const ATTR_MODE: u32 = 1 << 0;  // S_IWOTH | S_ISVTX | S_ISGID | S_ISUID | S_IWGRP | S_IRGRP | S_IWUSR | S_IRUSR
const ATTR_UID: u32 = 1 << 1;   // User ID changed.
const ATTR_GID: u32 = 1 << 2;   // Group ID changed.
const ATTR_SIZE: u32 = 1 << 3;  // File size changed (truncate).
const ATTR_ATIME: u32 = 1 << 4; // Access time changed.
const ATTR_MTIME: u32 = 1 << 5; // Modification time changed.
// const ATTR_CTIME: u32 = 1 << 6; // Change time changed (not directly used in DIRT's mask logic for notify_change).

/// Kprobe for `notify_change`. Handles `FsEvent::Attrib`, `FsEvent::Modify`, and `FsEvent::Access`
/// based on the `ia_valid` field of `struct iattr`.
/// Note: `FsEvent::Access` and `FsEvent::Attrib` are currently filtered out before calling `handle_fs_event`
/// to match original C DIRT behavior where `handle_fs_event` itself filtered them.
#[kprobe]
pub fn kprobe_notify_change(ctx: ProbeContext) -> u32 {
    match try_kprobe_notify_change(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_notify_change(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    // Args: dentry (arg0), iattr (arg1)
    let dentry_ptr = ctx.arg::<*const dentry>(0).ok_or(40i32)?;
    let attr_ptr = ctx.arg::<*const iattr>(1).ok_or(41i32)?;

    if dentry_ptr.is_null() || attr_ptr.is_null() {
        return Err(42i32);
    }

    let inode_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() {
        return Err(43i32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if settings.pid_self == pid || settings.pid_shell == pid {
        return Ok(());
    }

    let i_mode_val: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
    let s_ifmt = 0o170000u32;
    let s_ifreg = 0o100000u32;
    let s_iflnk = 0o120000u32;
    if !((i_mode_val & s_ifmt) == s_ifreg || (i_mode_val & s_ifmt) == s_iflnk) {
        return Ok(());
    }

    let ia_valid = unsafe { bpf_core_read!((*attr_ptr).ia_valid) };
    let mut triggered_events: [(FsEvent, bool); 3] = [
        (FsEvent::Access, false),
        (FsEvent::Modify, false),
        (FsEvent::Attrib, false),
    ];

    if (ia_valid & ATTR_UID != 0) || (ia_valid & ATTR_GID != 0) || (ia_valid & ATTR_MODE != 0) {
        triggered_events[2].1 = true; // FsEvent::Attrib
    }
    if ia_valid & ATTR_SIZE != 0 { // Typically means truncate
        triggered_events[1].1 = true; // FsEvent::Modify
    }

    if (ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME) { // Both atime and mtime changed
        triggered_events[2].1 = true; // Considered FsEvent::Attrib
    } else if (ia_valid & ATTR_ATIME != 0) { // Only atime changed
        triggered_events[0].1 = true; // FsEvent::Access
    } else if (ia_valid & ATTR_MTIME != 0) { // Only mtime changed
        triggered_events[1].1 = true; // FsEvent::Modify
    }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(len) if len > 0 => {},
        Ok(_) => return Err(44i32),
        Err(e) => return Err(e as i32),
    }

    let filepath_bytes = match get_file_path_from_dentry(dentry_ptr) {
        Ok(path) => path,
        Err(e) => return Err(e),
    };

    let current_size = unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64;
    let current_atime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) };
    let current_mtime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) };
    let current_ctime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };
    let current_nlink = unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32;
    let current_inode_number = unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32;

    for (event_type, should_trigger) in triggered_events.iter() {
        if *should_trigger {
            // To match C DIRT behavior, Access and Attrib events are not processed by handle_fs_event.
            if *event_type == FsEvent::Access || *event_type == FsEvent::Attrib {
                 continue;
            }

            let event_info = FsEventInfo {
                event_type: *event_type,
                pid,
                inode_number: current_inode_number,
                file_mode: i_mode_val,
                filename: filename_bytes,
                new_filename_if_moved: None,
                filepath: filepath_bytes,
                size: current_size,
                atime_nsec: current_atime_nsec,
                mtime_nsec: current_mtime_nsec,
                ctime_nsec: current_ctime_nsec,
                nlink: current_nlink,
            };
            handle_fs_event(&ctx, event_info)?;
        }
    }
    Ok(())
}

// FS_EVENT bitmask constants from original dirt.h FS_* definitions, used by __fsnotify_parent.
const FS_ACCESS_MASK: u32 = 0x00000001; // File was accessed (read)
const FS_MODIFY_MASK: u32 = 0x00000002; // File was modified (written)
const FS_ATTRIB_MASK: u32 = 0x00000004; // Metadata changed

/// Kprobe for `__fsnotify_parent`. This function is called by the fsnotify mechanism
/// when an event occurs on a dentry that has a parent with a watch.
/// The `mask` argument directly indicates the type of event.
/// Note: `FsEvent::Access` and `FsEvent::Attrib` are currently filtered out before calling `handle_fs_event`
/// to match original C DIRT behavior.
#[kprobe]
pub fn kprobe_fsnotify_parent(ctx: ProbeContext) -> u32 {
    match try_kprobe_fsnotify_parent(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_fsnotify_parent(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    // Args: dentry (arg0), mask (arg1), data (arg2), data_type (arg3)
    let dentry_ptr = ctx.arg::<*const dentry>(0).ok_or(50i32)?;
    let mask = ctx.arg::<u32>(1).ok_or(51i32)?;

    if dentry_ptr.is_null() {
        return Err(52i32);
    }

    let inode_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() {
        return Err(53i32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if settings.pid_self == pid || settings.pid_shell == pid {
        return Ok(());
    }

    let i_mode_val: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
    let s_ifmt = 0o170000u32;
    let s_ifreg = 0o100000u32;
    let s_iflnk = 0o120000u32;
    if !((i_mode_val & s_ifmt) == s_ifreg || (i_mode_val & s_ifmt) == s_iflnk) {
        return Ok(());
    }

    let mut triggered_events: [(FsEvent, bool); 3] = [
        (FsEvent::Access, false),
        (FsEvent::Modify, false),
        (FsEvent::Attrib, false),
    ];

    if mask & FS_ACCESS_MASK != 0 {
        triggered_events[0].1 = true;
    }
    if mask & FS_MODIFY_MASK != 0 {
        triggered_events[1].1 = true;
    }
    if mask & FS_ATTRIB_MASK != 0 {
        triggered_events[2].1 = true;
    }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(len) if len > 0 => {},
        Ok(_) => return Err(54i32),
        Err(e) => return Err(e as i32),
    }

    let filepath_bytes = match get_file_path_from_dentry(dentry_ptr) {
        Ok(path) => path,
        Err(e) => return Err(e),
    };

    let current_size = unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64;
    let current_atime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) };
    let current_mtime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) };
    let current_ctime_nsec = unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };
    let current_nlink = unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32;
    let current_inode_number = unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32;

    for (event_type, should_trigger) in triggered_events.iter() {
        if *should_trigger {
            if *event_type == FsEvent::Access || *event_type == FsEvent::Attrib {
                continue;
            }

            let event_info = FsEventInfo {
                event_type: *event_type,
                pid,
                inode_number: current_inode_number,
                file_mode: i_mode_val,
                filename: filename_bytes,
                new_filename_if_moved: None,
                filepath: filepath_bytes,
                size: current_size,
                atime_nsec: current_atime_nsec,
                mtime_nsec: current_mtime_nsec,
                ctime_nsec: current_ctime_nsec,
                nlink: current_nlink,
            };
            handle_fs_event(&ctx, event_info)?;
        }
    }
    Ok(())
}

/// Kprobe for `security_inode_rename`. Handles `FsEvent::MovedFrom` and `FsEvent::MovedTo`.
/// It generates two events: one for the source (old name/path) and one for the
/// destination (new name/path).
#[kprobe]
pub fn kprobe_security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_unlink(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

/// Kprobe for `security_inode_unlink`. Handles `FsEvent::Delete`.
fn try_kprobe_security_inode_unlink(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(&zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    // Args: dir_inode (arg0), dentry (arg1)
    let dentry_ptr = ctx.arg::<*const dentry>(1).ok_or(70i32)?;

    if dentry_ptr.is_null() {
        return Err(71i32);
    }

    let inode_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() { // Can happen if dentry is negative or inode already gone
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if settings.pid_self == pid || settings.pid_shell == pid {
        return Ok(());
    }

    let i_mode_val: u32 = unsafe { bpf_core_read!((*inode_ptr).i_mode) };
    let s_ifmt = 0o170000u32;
    let s_ifreg = 0o100000u32;
    let s_iflnk = 0o120000u32;
    if !((i_mode_val & s_ifmt) == s_ifreg || (i_mode_val & s_ifmt) == s_iflnk) {
        return Ok(());
    }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(len) if len > 0 => {},
        Ok(_) => return Err(72i32),
        Err(e) => return Err(e as i32),
    }

    let filepath_bytes = get_file_path_from_dentry(dentry_ptr)?;

    let event_info = FsEventInfo {
        event_type: FsEvent::Delete,
        pid,
        inode_number: unsafe { bpf_core_read!((*inode_ptr).i_ino) } as u32,
        file_mode: i_mode_val,
        filename: filename_bytes,
        new_filename_if_moved: None,
        filepath: filepath_bytes,
        size: unsafe { bpf_core_read!((*inode_ptr).i_size) } as u64,
        atime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
        mtime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
        ctime_nsec: unsafe { (bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
        nlink: unsafe { bpf_core_read!((*inode_ptr).i_nlink) } as u32, // nlink will be decremented by unlink
    };

    handle_fs_event(&ctx, event_info)?;
    Ok(())
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { aya_ebpf::helpers::bpf_trace_printk(b"eBPF panic handler triggered.\0", 30) };
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
