//! eBPF program for DIRT-rs (Dynamic Information Reporting Tool - Rust version)
//!
//! This program attaches to various kernel functions (kprobes) to monitor
//! file system events. It collects information about these events, aggregates
//! them if configured, and sends the data to a user-space application via
//! a ring buffer.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, kprobe, kretprobe},
    programs::ProbeContext,
    maps::{RingBuf, LruHashMap, PerCpuArray, Array},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes, bpf_trace_printk_unsafe},
    bindings::{dentry, file, inode, iattr}, // Removed linux_id::FMODE_CREATED
};
use aya_log_ebpf::info;
use core::ffi::c_char;

use dirt_rs_common::*; // Import shared structs and constants

// Manually define FMODE_CREATED if not reliably available through aya_ebpf::bindings::linux_id
// Value from <uapi/linux/fcntl.h> and confirmed via dirt.h (0x0100000)
const FMODE_CREATED: u32 = 0x0100000;

// Custom error code for bpf_probe_read_kernel_str_bytes failure if 0 bytes read.
// Negative values are typical for eBPF helper error returns that are not direct syscall errnos.
const ERR_BPF_PROBE_READ_STR_FAILED: i32 = -2; // Example error code


// Constants for BPF map sizes. These mirror definitions from the original C version of DIRT.
const MAP_RECORDS_MAX: u32 = 65536; // Max entries for HASH_RECORDS
const RINGBUF_TOTAL_BYTE_SIZE: u32 = 8192 * 256; // Total size for the ring buffer (e.g., 2MB)
const PENDING_SYMLINKS_MAX_ENTRIES: u32 = 1024; // Max entries for PENDING_SYMLINKS

// BPF Maps Definitions
// --------------------

/// Ring buffer for sending collected `RecordFs` event data to user-space.
#[map]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_TOTAL_BYTE_SIZE, 0);

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
/// (Detailed comments for this function exist above its previous definition, not repeated here for brevity)
fn handle_fs_event(
    ctx: &ProbeContext,
    event_info: FsEventInfo,
) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;

    if settings.pid_self == event_info.pid {
        return Ok(());
    }

    let key = key_pid_ino(event_info.pid, event_info.inode_number);
    let mut existing_record_opt = unsafe { HASH_RECORDS.get_ptr_mut(&key) };

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
        let mut new_record_fs_ptr = unsafe {HEAP_RECORD_FS.get_ptr_mut(zero)}.ok_or(2i32)?;

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

            // Correctly handle filename_from for MovedFrom event
            if event_info.event_type == FsEvent::MovedFrom {
                 let mut temp_filename_from = [0u8; FILENAME_LEN_MAX / 2];
                 temp_filename_from.copy_from_slice(&event_info.filename[..(FILENAME_LEN_MAX / 2)]);
                 (*new_record_fs_ptr).union_filenames.filenames_from_to.filename_from = temp_filename_from;
                 (*new_record_fs_ptr).union_filenames.filenames_from_to.filename_to = [0u8; FILENAME_LEN_MAX / 2]; // Clear 'to' field
            } else {
                // For other events, or if it's a MovedTo where filename is the old name and new_filename_if_moved has the new.
                // The current FsEventInfo puts old_name into .filename for MovedTo, so this is fine.
                (*new_record_fs_ptr).union_filenames.filename = event_info.filename;
            }
            (*new_record_fs_ptr).filepath = event_info.filepath;
        }

        if unsafe { HASH_RECORDS.insert(&key, &*new_record_fs_ptr, 0).is_err() } {
            return Err(3i32);
        }
        if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(zero) } {
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
                if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(zero) } {
                    unsafe { (*stats).fs_records_dropped = (*stats).fs_records_dropped.wrapping_add(1); }
                }
            }
        }
        if unsafe { HASH_RECORDS.remove(&key).is_err() } {
            // This is not necessarily an error if the entry was already evicted by LRU logic.
        }
        if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(zero) } {
            unsafe { (*stats).fs_records_deleted = (*stats).fs_records_deleted.wrapping_add(1); }
        }
    }

    if let Some(stats) = unsafe { STATS_MAP.get_ptr_mut(zero) } {
        unsafe { (*stats).fs_events = (*stats).fs_events.wrapping_add(1); }
    }

    Ok(())
}

/// Helper function to construct the full file path from a dentry.
/// (Detailed comments for this function exist above its previous definition, not repeated here for brevity)
fn get_file_path_from_dentry(dentry_ptr: *const dentry) -> Result<[u8; FILEPATH_LEN_MAX], i32> {
    let mut path_bytes = [0u8; FILEPATH_LEN_MAX];
    let mut current_dentry_ptr = dentry_ptr;
    let mut current_offset = FILEPATH_LEN_MAX;
    let mut total_len = 0;

    for _ in 0..FILEPATH_NODE_MAX {
        if current_dentry_ptr.is_null() {
            break;
        }
        let name_src_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*current_dentry_ptr).d_name.name) } as *const c_char;

        let mut name_bytes_temp = [0u8; DNAME_INLINE_LEN];
        let len_read = match unsafe { bpf_probe_read_kernel_str_bytes(name_src_ptr, &mut name_bytes_temp) } {
            Ok(length) => length,
            Err(e_code) => return Err(e_code as i32),
        };

        if len_read == 0 { break; }

        let actual_len = name_bytes_temp.iter().position(|&x| x == 0).unwrap_or(len_read.min(DNAME_INLINE_LEN));
        if actual_len == 0 { break; }

        if total_len + actual_len + (if total_len > 0 {1} else {0}) > FILEPATH_LEN_MAX {
            break;
        }

        current_offset -= actual_len;
        if current_offset < 0 { break; }
        unsafe {
            core::ptr::copy_nonoverlapping(name_bytes_temp.as_ptr(), path_bytes.as_mut_ptr().add(current_offset), actual_len);
        }
        total_len += actual_len;

        let parent_dentry_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*current_dentry_ptr).d_parent) };

        if current_dentry_ptr == parent_dentry_ptr {
            if total_len > 0 && current_offset > 0 {
                current_offset -= 1;
                path_bytes[current_offset] = b'/';
                total_len += 1;
            }
            break;
        }
        current_dentry_ptr = parent_dentry_ptr;

        if total_len > 0 && current_offset > 0 {
            current_offset -= 1;
            path_bytes[current_offset] = b'/';
            total_len += 1;
        }
    }

    if current_offset > 0 && total_len > 0 {
        unsafe {
            core::ptr::copy(path_bytes.as_ptr().add(current_offset), path_bytes.as_mut_ptr(), total_len);
        }
    }
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
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    let filp_ptr = ctx.ret() as *const file;
    if filp_ptr.is_null() {
        return Err(2i32);
    }

    let f_mode: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*filp_ptr).f_mode) };

    if f_mode & FMODE_CREATED == FMODE_CREATED {
        let dentry_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*filp_ptr).f_path.dentry) };
        if dentry_ptr.is_null() {
            return Err(3i32);
        }

        let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_inode) };
        if inode_ptr.is_null() {
            return Err(4i32);
        }

        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;

        if settings.pid_self == pid || settings.pid_shell == pid {
            return Ok(());
        }

        let i_mode: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
        let s_ifmt = 0o170000u32;
        let s_ifreg = 0o100000u32;
        let s_iflnk = 0o120000u32;

        if !((i_mode & s_ifmt) == s_ifreg || (i_mode & s_ifmt) == s_iflnk) {
            return Ok(());
        }

        let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
        let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
        match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
            Ok(bytes_read) => {
                if bytes_read == 0 || bytes_read > filename_bytes.len() {
                    return Err(ERR_BPF_PROBE_READ_STR_FAILED);
                }
            },
            Err(e) => return Err(e as i32),
        }

        let filepath_bytes = match get_file_path_from_dentry(dentry_ptr) {
            Ok(path) => path,
            Err(e) => return Err(e),
        };

        let event_info = FsEventInfo {
            event_type: FsEvent::Create,
            pid,
            inode_number: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32,
            file_mode: i_mode,
            filename: filename_bytes,
            new_filename_if_moved: None,
            filepath: filepath_bytes,
            size: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64,
            atime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
            mtime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
            ctime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
            nlink: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32,
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
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }
    let new_dentry_ptr = ctx.arg::<*const dentry>(2).ok_or(11i32)?;

    if new_dentry_ptr.is_null() {
        return Err(3i32);
    }

    let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*new_dentry_ptr).d_inode) };
    if inode_ptr.is_null() {
        return Err(4i32);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if settings.pid_self == pid || settings.pid_shell == pid {
        return Ok(());
    }

    let i_mode: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
    let s_ifmt = 0o170000u32;
    let s_ifreg = 0o100000u32;
    let s_iflnk = 0o120000u32;
    if !((i_mode & s_ifmt) == s_ifreg || (i_mode & s_ifmt) == s_iflnk) {
        return Ok(());
    }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*new_dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(bytes_read) => {
            if bytes_read == 0 || bytes_read > filename_bytes.len() {
                return Err(ERR_BPF_PROBE_READ_STR_FAILED);
            }
        },
        Err(e) => return Err(e as i32),
    }
    let filepath_bytes = match get_file_path_from_dentry(new_dentry_ptr) {
        Ok(path) => path,
        Err(e) => return Err(e),
    };

    let event_info = FsEventInfo {
        event_type: FsEvent::Create,
        pid,
        inode_number: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32,
        file_mode: i_mode,
        filename: filename_bytes,
        new_filename_if_moved: None,
        filepath: filepath_bytes,
        size: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64,
        atime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
        mtime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
        ctime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
        nlink: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32,
    };

    handle_fs_event(&ctx, event_info)?;
    Ok(())
}

/// Kprobe for `security_inode_symlink`.
/// (Detailed comments for this function exist above its previous definition, not repeated here for brevity)
#[kprobe]
pub fn kprobe_security_inode_symlink(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_symlink(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_security_inode_symlink(ctx: ProbeContext) -> Result<(), i32> {
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

/// Kprobe for `dput`.
/// (Detailed comments for this function exist above its previous definition, not repeated here for brevity)
#[kprobe]
pub fn kprobe_dput(ctx: ProbeContext) -> u32 {
    match try_kprobe_dput(ctx) {
        Ok(_) => 0,
        Err(ret) => ret as u32,
    }
}

fn try_kprobe_dput(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 {
        return Ok(());
    }

    let dentry_arg_ptr = ctx.arg::<*const dentry>(0).ok_or(30i32)?;
    if dentry_arg_ptr.is_null() { return Ok(()); }
    let dentry_arg_addr = dentry_arg_ptr as u64;
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if let Some(stored_dentry_addr) = unsafe { PENDING_SYMLINKS.get(&pid) } {
        if *stored_dentry_addr == dentry_arg_addr {
            unsafe { PENDING_SYMLINKS.remove(&pid).map_err(|e| e as i32)?; }
            let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_arg_ptr).d_inode) };
            if inode_ptr.is_null() { return Ok(()); }

            let i_mode: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
            if (i_mode & 0o170000u32) == 0o120000u32 { /* S_IFLNK */
                if settings.pid_self == pid || settings.pid_shell == pid { return Ok(()); }

                let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
                let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_arg_ptr).d_name.name) } as *const c_char;
                match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
                    Ok(bytes_read) => {
                        if bytes_read == 0 || bytes_read > filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); }
                    },
                    Err(e) => return Err(e as i32),
                }
                let filepath_bytes = get_file_path_from_dentry(dentry_arg_ptr)?;
                let event_info = FsEventInfo {
                    event_type: FsEvent::Create, pid,
                    inode_number: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32,
                    file_mode: i_mode, filename: filename_bytes, new_filename_if_moved: None,
                    filepath: filepath_bytes,
                    size: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64,
                    atime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
                    mtime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
                    ctime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
                    nlink: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32,
                };
                handle_fs_event(&ctx, event_info)?;
            }
        }
    }
    Ok(())
}

const ATTR_MODE: u32 = 1 << 0;
const ATTR_UID: u32 = 1 << 1;
const ATTR_GID: u32 = 1 << 2;
const ATTR_SIZE: u32 = 1 << 3;
const ATTR_ATIME: u32 = 1 << 4;
const ATTR_MTIME: u32 = 1 << 5;

#[kprobe]
pub fn kprobe_notify_change(ctx: ProbeContext) -> u32 {
    match try_kprobe_notify_change(ctx) { Ok(_) => 0, Err(ret) => ret as u32 }
}

fn try_kprobe_notify_change(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 { return Ok(()); }

    let dentry_ptr = ctx.arg::<*const dentry>(0).ok_or(40i32)?;
    let attr_ptr = ctx.arg::<*const iattr>(1).ok_or(41i32)?;
    if dentry_ptr.is_null() || attr_ptr.is_null() { return Err(42i32); }
    let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() { return Err(43i32); }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if settings.pid_self == pid || settings.pid_shell == pid { return Ok(()); }

    let i_mode_val: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
    if !(((i_mode_val & 0o170000u32) == 0o100000u32) || ((i_mode_val & 0o170000u32) == 0o120000u32)) { return Ok(()); }

    let ia_valid = unsafe { aya_ebpf::macros::bpf_core_read!((*attr_ptr).ia_valid) };
    let mut triggered_events: [(FsEvent, bool); 3] = [(FsEvent::Access, false), (FsEvent::Modify, false), (FsEvent::Attrib, false)];
    if (ia_valid & ATTR_UID != 0) || (ia_valid & ATTR_GID != 0) || (ia_valid & ATTR_MODE != 0) { triggered_events[2].1 = true; }
    if ia_valid & ATTR_SIZE != 0 { triggered_events[1].1 = true; }
    if (ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME) { triggered_events[2].1 = true; }
    else if (ia_valid & ATTR_ATIME != 0) { triggered_events[0].1 = true; }
    else if (ia_valid & ATTR_MTIME != 0) { triggered_events[1].1 = true; }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(bytes_read) => { if bytes_read == 0 || bytes_read > filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); } },
        Err(e) => return Err(e as i32),
    }
    let filepath_bytes = get_file_path_from_dentry(dentry_ptr)?;
    let current_size = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64;
    let current_atime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) };
    let current_mtime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) };
    let current_ctime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };
    let current_nlink = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32;
    let current_inode_number = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32;

    for (event_type, should_trigger) in triggered_events.iter() {
        if *should_trigger {
            if *event_type == FsEvent::Access || *event_type == FsEvent::Attrib { continue; }
            let event_info = FsEventInfo {
                event_type: *event_type, pid, inode_number: current_inode_number, file_mode: i_mode_val,
                filename: filename_bytes, new_filename_if_moved: None, filepath: filepath_bytes,
                size: current_size, atime_nsec: current_atime_nsec, mtime_nsec: current_mtime_nsec,
                ctime_nsec: current_ctime_nsec, nlink: current_nlink,
            };
            handle_fs_event(&ctx, event_info)?;
        }
    }
    Ok(())
}

const FS_ACCESS_MASK: u32 = 0x00000001;
const FS_MODIFY_MASK: u32 = 0x00000002;
const FS_ATTRIB_MASK: u32 = 0x00000004;

#[kprobe]
pub fn kprobe_fsnotify_parent(ctx: ProbeContext) -> u32 {
    match try_kprobe_fsnotify_parent(ctx) { Ok(_) => 0, Err(ret) => ret as u32 }
}

fn try_kprobe_fsnotify_parent(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 { return Ok(()); }

    let dentry_ptr = ctx.arg::<*const dentry>(0).ok_or(50i32)?;
    let mask = ctx.arg::<u32>(1).ok_or(51i32)?;
    if dentry_ptr.is_null() { return Err(52i32); }
    let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() { return Err(53i32); }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if settings.pid_self == pid || settings.pid_shell == pid { return Ok(()); }

    let i_mode_val: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
    if !(((i_mode_val & 0o170000u32) == 0o100000u32) || ((i_mode_val & 0o170000u32) == 0o120000u32)) { return Ok(()); }

    let mut triggered_events: [(FsEvent, bool); 3] = [(FsEvent::Access, false), (FsEvent::Modify, false), (FsEvent::Attrib, false)];
    if mask & FS_ACCESS_MASK != 0 { triggered_events[0].1 = true; }
    if mask & FS_MODIFY_MASK != 0 { triggered_events[1].1 = true; }
    if mask & FS_ATTRIB_MASK != 0 { triggered_events[2].1 = true; }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(bytes_read) => { if bytes_read == 0 || bytes_read > filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); } },
        Err(e) => return Err(e as i32),
    }
    let filepath_bytes = get_file_path_from_dentry(dentry_ptr)?;
    let current_size = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64;
    let current_atime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) };
    let current_mtime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) };
    let current_ctime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };
    let current_nlink = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32;
    let current_inode_number = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32;

    for (event_type, should_trigger) in triggered_events.iter() {
        if *should_trigger {
            if *event_type == FsEvent::Access || *event_type == FsEvent::Attrib { continue; }
            let event_info = FsEventInfo {
                event_type: *event_type, pid, inode_number: current_inode_number, file_mode: i_mode_val,
                filename: filename_bytes, new_filename_if_moved: None, filepath: filepath_bytes,
                size: current_size, atime_nsec: current_atime_nsec, mtime_nsec: current_mtime_nsec,
                ctime_nsec: current_ctime_nsec, nlink: current_nlink,
            };
            handle_fs_event(&ctx, event_info)?;
        }
    }
    Ok(())
}

#[kprobe]
pub fn kprobe_security_inode_rename(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_rename(ctx) { Ok(_) => 0, Err(ret) => ret as u32 }
}

fn try_kprobe_security_inode_rename(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 { return Ok(()); }

    let old_dentry_ptr = ctx.arg::<*const dentry>(1).ok_or(60i32)?;
    let new_dentry_ptr = ctx.arg::<*const dentry>(3).ok_or(61i32)?;
    if old_dentry_ptr.is_null() || new_dentry_ptr.is_null() { return Err(62i32); }
    let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*old_dentry_ptr).d_inode) };
    if inode_ptr.is_null() { return Ok(()); }

    let i_mode_val: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
    if (i_mode_val & 0o170000u32) == 0o040000u32 { return Ok(()); } /* S_IFDIR */
    if !(((i_mode_val & 0o170000u32) == 0o100000u32) || ((i_mode_val & 0o170000u32) == 0o120000u32)) { return Ok(()); }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if settings.pid_self == pid || settings.pid_shell == pid { return Ok(()); }

    let common_inode_number = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32;
    let common_size = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64;
    let common_atime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) };
    let common_mtime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) };
    let pre_op_ctime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };
    let common_nlink = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32;

    let mut old_filename_bytes = [0u8; FILENAME_LEN_MAX];
    let old_d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*old_dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(old_d_name_char_ptr, &mut old_filename_bytes) } {
        Ok(bytes_read) => { if bytes_read == 0 || bytes_read > old_filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); } },
        Err(e) => return Err(e as i32),
    }
    let old_filepath_bytes = get_file_path_from_dentry(old_dentry_ptr)?;

    let event_info_from = FsEventInfo {
        event_type: FsEvent::MovedFrom, pid, inode_number: common_inode_number, file_mode: i_mode_val,
        filename: old_filename_bytes, new_filename_if_moved: None, filepath: old_filepath_bytes,
        size: common_size, atime_nsec: common_atime_nsec, mtime_nsec: common_mtime_nsec,
        ctime_nsec: pre_op_ctime_nsec, nlink: common_nlink,
    };
    handle_fs_event(&ctx, event_info_from)?;

    let mut new_filename_bytes = [0u8; FILENAME_LEN_MAX];
    let new_d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*new_dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(new_d_name_char_ptr, &mut new_filename_bytes) } {
        Ok(bytes_read) => { if bytes_read == 0 || bytes_read > new_filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); } },
        Err(e) => return Err(e as i32),
    }
    let new_filepath_bytes = get_file_path_from_dentry(new_dentry_ptr)?;
    let updated_ctime_nsec = unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) };

    let event_info_to = FsEventInfo {
        event_type: FsEvent::MovedTo, pid, inode_number: common_inode_number, file_mode: i_mode_val,
        filename: old_filename_bytes, new_filename_if_moved: Some(new_filename_bytes),
        filepath: new_filepath_bytes, size: common_size, atime_nsec: common_atime_nsec,
        mtime_nsec: common_mtime_nsec, ctime_nsec: updated_ctime_nsec, nlink: common_nlink,
    };
    handle_fs_event(&ctx, event_info_to)?;
    Ok(())
}

/// Kprobe for `security_inode_unlink`. Handles `FsEvent::Delete`.
#[kprobe]
pub fn kprobe_security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_kprobe_security_inode_unlink(ctx) { Ok(_) => 0, Err(ret) => ret as u32 }
}

fn try_kprobe_security_inode_unlink(ctx: ProbeContext) -> Result<(), i32> {
    let zero: u32 = 0;
    let settings = unsafe { EBPF_SETTINGS.get(zero) }.ok_or(1i32)?;
    if settings.monitor_mode & MONITOR_FILE == 0 { return Ok(()); }

    let dentry_ptr = ctx.arg::<*const dentry>(1).ok_or(70i32)?;
    if dentry_ptr.is_null() { return Err(71i32); }
    let inode_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_inode) };
    if inode_ptr.is_null() { return Ok(()); }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if settings.pid_self == pid || settings.pid_shell == pid { return Ok(()); }

    let i_mode_val: u32 = unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mode) };
    if !(((i_mode_val & 0o170000u32) == 0o100000u32) || ((i_mode_val & 0o170000u32) == 0o120000u32)) { return Ok(()); }

    let mut filename_bytes = [0u8; FILENAME_LEN_MAX];
    let d_name_char_ptr = unsafe { aya_ebpf::macros::bpf_core_read!((*dentry_ptr).d_name.name) } as *const c_char;
    match unsafe { bpf_probe_read_kernel_str_bytes(d_name_char_ptr, &mut filename_bytes) } {
        Ok(bytes_read) => { if bytes_read == 0 || bytes_read > filename_bytes.len() { return Err(ERR_BPF_PROBE_READ_STR_FAILED); } },
        Err(e) => return Err(e as i32),
    }
    let filepath_bytes = get_file_path_from_dentry(dentry_ptr)?;

    let event_info = FsEventInfo {
        event_type: FsEvent::Delete, pid,
        inode_number: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ino) } as u32,
        file_mode: i_mode_val, filename: filename_bytes, new_filename_if_moved: None,
        filepath: filepath_bytes,
        size: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_size) } as u64,
        atime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_atime.tv_nsec) as u64) },
        mtime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_mtime.tv_nsec) as u64) },
        ctime_nsec: unsafe { (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_sec) as u64 * 1_000_000_000) + (aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_ctime.tv_nsec) as u64) },
        nlink: unsafe { aya_ebpf::macros::bpf_core_read!((*inode_ptr).i_nlink) } as u32,
    };
    handle_fs_event(&ctx, event_info)?;
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { bpf_trace_printk_unsafe(b"eBPF panic handler triggered.\0", 30) };
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
