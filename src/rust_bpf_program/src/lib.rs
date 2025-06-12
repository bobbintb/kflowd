#![no_std]

// We'll need this for C types if not already covered by Aya's prelude or bindings
use aya_bpf::cty;

// --- START: Translated from dirt.h ---

// Constants for max sizes
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
// FS_EVENT_MAX was calculated as (int)(sizeof(fsevt) / sizeof(struct FS_EVENT))
// From dirt.h, enum INDEX_FS_EVENT has I_Q_OVERFLOW as the last event, which is 14.
// So, FS_EVENT_MAX should be 15.
pub const FS_EVENT_MAX: usize = 15;

// Record type
pub const RECORD_TYPE_FILE: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Record {
    pub type_: u32, // Renamed from 'type' to 'type_' to avoid Rust keyword clash
    pub ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct RecordFsRenameInfo {
    pub filename_from: [u8; FILENAME_LEN_MAX / 2],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union RecordFsFilenames {
    pub rename_info: RecordFsRenameInfo, // struct is 32 bytes
    pub filename: [u8; FILENAME_LEN_MAX], // array is 32 bytes
}

impl Default for RecordFsFilenames {
    fn default() -> Self {
        RecordFsFilenames {
            filename: [0u8; FILENAME_LEN_MAX],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RecordFs {
    pub rc: Record,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX],
    pub ino: u32,
    pub imode: u32, // Corrected: removed trailing comma if any was here
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub names: RecordFsFilenames,
}

impl Default for RecordFs {
    fn default() -> Self {
        RecordFs {
            rc: Record::default(),
            events: 0,
            event: [0; FS_EVENT_MAX],
            ino: 0,
            imode: 0,
            inlink: 0,
            isize: 0,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
            isize_first: 0,
            filepath: [0u8; FILEPATH_LEN_MAX],
            names: RecordFsFilenames::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IndexFsEvent {
    ICreate = 0,
    IOpen = 1,
    IOpenExec = 2,
    IAccess = 3,
    IAttrib = 4,
    IModify = 5,
    ICloseWrite = 6,
    ICloseNowrite = 7,
    IMovedFrom = 8,
    IMovedTo = 9,
    IDelete = 10,
    IDeleteSelf = 11,
    IMoveSelf = 12,
    IUnmount = 13,
    IQOverflow = 14,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FsEventInfo {
    pub index: IndexFsEvent,
    pub dentry: *const cty::c_void,
    pub dentry_old: *const cty::c_void,
    pub func_name: *const cty::c_char,
}

pub const MAP_RECORDS_MAX: u32 = 65536;

pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

const S_IFMT: u16 = 0o0170000; // Octal prefix is 0o in Rust
const S_IFLNK: u16 = 0o0120000;
const S_IFREG: u16 = 0o0100000;

#[inline]
pub fn s_islnk(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

#[inline]
pub fn s_isreg(mode: u16) -> bool {
    (mode & S_IFMT) == S_IFREG
}

#[inline]
pub fn key_pid_ino(pid: u32, ino: u32) -> u64 {
    ((pid as u64) << 32) | (ino as u64)
}

pub const DBG_LEN_MAX: usize = 16;
pub const MAX_STACK_TRACE_DEPTH: usize = 16;
pub const DNAME_INLINE_LEN: usize = 32;
pub const FILEPATH_NODE_MAX: usize = 16;

// --- END: Translated from dirt.h ---

// --- START: BPF Map Definitions ---
use aya_bpf::maps::{Array, LruHashMap, PerCpuArray, RingBuf};
// Structs RecordFs and Stats are defined above in this file.

// Ring buffer for sending records to userspace
// C name: ringbuf_records
// Max entries in C: sizeof(struct RECORD_FS) * 8192. This is total bytes.
// Approx 256 bytes/record * 8192 records = 2MB (2 * 1024 * 1024 bytes).
#[map(name = "ringbuf_records")]
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_max_entries(2 * 1024 * 1024, 0);

// Hash map for aggregating file system event records
// C name: hash_records
// Key: u64 (pid_t << 32 | ino_t)
// Value: RecordFs
#[map(name = "hash_records")]
pub static mut HASH_RECORDS: LruHashMap<u64, RecordFs> =
    LruHashMap::with_max_entries(MAP_RECORDS_MAX, 0); // MAP_RECORDS_MAX is 65536

// Per-CPU array for temporary RecordFs storage before insertion into hash_records
// C name: heap_record_fs
// Key: u32 (array index, effectively 0)
// Value: RecordFs
#[map(name = "heap_record_fs")]
pub static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> =
    PerCpuArray::with_max_entries(1, 0);

// Array for storing global statistics
// C name: stats
// Key: u32 (array index, effectively 0)
// Value: Stats struct
#[map(name = "stats")]
pub static mut STATS: Array<Stats> = Array::with_max_entries(1, 0);

// --- END: BPF Map Definitions ---

// --- START: Global Variables (Loader Initialized) ---
// TODO: These need proper initialization mechanism via Aya (e.g. loader writes, or global data map)
static mut PID_SELF: u32 = 0;
static mut AGG_EVENTS_MAX: u32 = 0;
// MONITOR_FILE should already be defined as a const from previous steps.
static mut MONITOR: u32 = MONITOR_FILE; // Default to MONITOR_FILE

// Add new global variables:
static mut TS_START: u64 = 0;
static mut DEBUG_MSG: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX]; // DBG_LEN_MAX defined in Step 2

// --- END: Global Variables ---

// --- START: Dummy Bindings (Temporary for handle_fs_event structure) ---
// In a real setup, bindings are generated by aya-gen and included.
pub mod bindings {
    #[repr(C)]
    pub struct dentry { pub _unused: [u8; 0] }
    #[repr(C)]
    pub struct inode { pub _unused: [u8; 0] }
    #[repr(C)]
    pub struct qstr {
        pub name: *const aya_bpf::cty::c_char,
    }
}
// --- END: Dummy Bindings ---

// --- START: Core eBPF Program Logic (handle_fs_event) ---

use aya_bpf::{
    BpfContext,
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel_str},
};
use aya_bpf::bindings::BPF_ANY;
use crate::bindings::{dentry, inode}; // Use the local dummy bindings


#[inline]
fn read_kernel_str(src: *const cty::c_char, buf: &mut [u8]) -> Result<usize, i64> {
    if buf.is_empty() {
        return Err(1);
    }
    let len = unsafe {
        bpf_probe_read_kernel_str(
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            src as *const _,
        )
    };
    if len < 0 {
        Err(len)
    } else {
        Ok(len as usize)
    }
}

#[inline]
#[allow(unused_variables, clippy::collapsible_else_if, clippy::manual_memcpy)]
fn handle_fs_event(event_info: &FsEventInfo) -> Result<(), i64> {
    if event_info.index == IndexFsEvent::IAccess || event_info.index == IndexFsEvent::IAttrib {
        return Ok(());
    }

    let pid_tgid = unsafe { aya_bpf::helpers::bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;

    if unsafe { PID_SELF } == pid {
        return Ok(());
    }

    let index = event_info.index;
    let dentry_ptr = event_info.dentry as *const dentry;
    let dentry_old_ptr = event_info.dentry_old as *const dentry;

    let current_dentry_ptr = if dentry_old_ptr.is_null() { dentry_ptr } else { dentry_old_ptr };
    if current_dentry_ptr.is_null() { return Ok(()); }

    // --- Start of CO-RE Placeholder Block ---
    // These are placeholders and require real CO-RE reads based on aya-gen bindings.
    let inode_ptr_from_dentry: *const inode = unsafe { (*current_dentry_ptr)._unused.as_ptr() as *const inode };
    let filename_src_ptr_from_dentry: *const cty::c_char = unsafe { (*dentry_ptr)._unused.as_ptr() as *const cty::c_char };

    let ino_val: u32 = 0; // Placeholder: unsafe { (*inode_ptr_from_dentry).i_ino.read_kernel() }?;
    let imode_val: u16 = 0; // Placeholder: unsafe { (*inode_ptr_from_dentry).i_mode.read_kernel() }?;
    let isize_val: u64 = 0; // Placeholder: unsafe { (*inode_ptr_from_dentry).i_size.read_kernel() }?;
    let inlink_val: u32 = 0; // Placeholder: unsafe { (*inode_ptr_from_dentry).i_nlink.read_kernel() }?;
    let atime_sec_val: u64 = 0; // Placeholder for inode->i_atime.tv_sec
    let atime_nsec_val: u64 = 0; // Placeholder for inode->i_atime.tv_nsec
    let mtime_sec_val: u64 = 0; // Placeholder for inode->i_mtime.tv_sec
    let mtime_nsec_val: u64 = 0; // Placeholder for inode->i_mtime.tv_nsec
    let ctime_sec_val: u64 = 0; // Placeholder for inode->i_ctime.tv_sec
    let ctime_nsec_val: u64 = 0; // Placeholder for inode->i_ctime.tv_nsec
    // --- End of CO-RE Placeholder Block ---

    if inode_ptr_from_dentry.is_null() { return Ok(()); }

    let mut filename_buf = [0u8; FILENAME_LEN_MAX];
    if !filename_src_ptr_from_dentry.is_null() {
         match read_kernel_str(filename_src_ptr_from_dentry, &mut filename_buf) {
            Ok(0) | Err(_) => return Ok(()),
            Ok(len) if len == 0 => return Ok(()),
            Ok(_) => {}
        }
    } else {
        return Ok(());
    }
    if filename_buf[0] == 0 { return Ok(()); }


    if !(s_isreg(imode_val) || s_islnk(imode_val)) {
        return Ok(());
    }

    let key = key_pid_ino(pid, ino_val);
    let ts_event = unsafe { bpf_ktime_get_ns() };
    let zero_key: u32 = 0;

    let r_for_aggregation_logic: RecordFs;

    if let Some(mut r_existing) = unsafe { HASH_RECORDS.get(&key).copied() } {
        if index == IndexFsEvent::IMovedTo {
            unsafe {
                let dest_slice = &mut r_existing.names.rename_info.filename_to[..];
                let src_len = filename_buf.iter().position(|&x| x == 0).unwrap_or(FILENAME_LEN_MAX / 2);
                let len_to_copy = core::cmp::min(src_len, FILENAME_LEN_MAX / 2);
                dest_slice[0..len_to_copy].copy_from_slice(&filename_buf[0..len_to_copy]);
                if len_to_copy < FILENAME_LEN_MAX / 2 {
                    dest_slice[len_to_copy] = 0;
                }
            }
        }
        r_existing.rc.ts = ts_event;

        r_existing.imode = imode_val as u32;
        r_existing.isize = isize_val;
        r_existing.inlink = inlink_val;
        if index == IndexFsEvent::ICreate && !dentry_old_ptr.is_null() {
             r_existing.inlink = r_existing.inlink.saturating_add(1);
        }
        r_existing.atime_nsec = atime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(atime_nsec_val);
        r_existing.mtime_nsec = mtime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(mtime_nsec_val);
        r_existing.ctime_nsec = ctime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(ctime_nsec_val);
        r_existing.events = r_existing.events.saturating_add(1);
        if (index as usize) < FS_EVENT_MAX {
            r_existing.event[index as usize] = r_existing.event[index as usize].saturating_add(1);
        }

        unsafe { HASH_RECORDS.insert(&key, &r_existing, BPF_ANY as u64) }?;
        r_for_aggregation_logic = r_existing;
    } else {
        if let Some(heap_record_ptr) = unsafe { HEAP_RECORD_FS.get_ptr_mut(zero_key) } {
            let mut r_current = unsafe {core::ptr::read(heap_record_ptr)};

            r_current.rc.ts = ts_event;
            r_current.ino = ino_val;
            unsafe { r_current.names.filename.copy_from_slice(&filename_buf) };
            r_current.isize_first = isize_val;
            r_current.filepath = [0u8; FILEPATH_LEN_MAX];
            // TODO: Port the filepath construction loop.

            r_current.events = 0;
            r_current.event = [0u32; FS_EVENT_MAX];

            r_current.imode = imode_val as u32;
            r_current.isize = isize_val;
            r_current.inlink = inlink_val;
             if index == IndexFsEvent::ICreate && !dentry_old_ptr.is_null() {
                r_current.inlink = r_current.inlink.saturating_add(1);
            }
            r_current.atime_nsec = atime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(atime_nsec_val);
            r_current.mtime_nsec = mtime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(mtime_nsec_val);
            r_current.ctime_nsec = ctime_sec_val.wrapping_mul(1_000_000_000).wrapping_add(ctime_nsec_val);

            r_current.events = r_current.events.saturating_add(1);
            if (index as usize) < FS_EVENT_MAX {
                 r_current.event[index as usize] = r_current.event[index as usize].saturating_add(1);
            }

            unsafe { HASH_RECORDS.insert(&key, &r_current, BPF_ANY as u64) }?;
            r_for_aggregation_logic = r_current;

            if let Some(stats_val) = unsafe { STATS.get_mut(zero_key) } {
                stats_val.fs_records = stats_val.fs_records.saturating_add(1);
            }
        } else {
            return Err(1);
        }
    }

    let mut agg_end = false;
    match index {
        IndexFsEvent::ICloseWrite | IndexFsEvent::ICloseNowrite | IndexFsEvent::IDelete | IndexFsEvent::IMovedTo => {
            agg_end = true;
        }
        IndexFsEvent::ICreate => {
            if s_islnk(imode_val) || r_for_aggregation_logic.inlink > 1 {
                agg_end = true;
            }
        }
        _ => {}
    }

    let current_agg_events_max = unsafe { AGG_EVENTS_MAX };
    if !agg_end && current_agg_events_max > 0 {
        if r_for_aggregation_logic.events >= current_agg_events_max {
            agg_end = true;
        }
    }

    if agg_end {
        let mut r_to_send = r_for_aggregation_logic;
        r_to_send.rc.type_ = RECORD_TYPE_FILE;

        let result = unsafe { RINGBUF_RECORDS.output(&r_to_send, 0) };
        if result.is_err() {
            if let Some(stats_val) = unsafe { STATS.get_mut(zero_key) } {
                stats_val.fs_records_dropped = stats_val.fs_records_dropped.saturating_add(1);
            }
        }

        if unsafe { HASH_RECORDS.remove(&key) }.is_ok() {
            if let Some(stats_val) = unsafe { STATS.get_mut(zero_key) } {
                stats_val.fs_records_deleted = stats_val.fs_records_deleted.saturating_add(1);
            }
        }
    }

    if let Some(stats_val) = unsafe { STATS.get_mut(zero_key) } {
        let record_fs_size = core::mem::size_of::<RecordFs>();
        if record_fs_size > 0 {
            let rsz_aligned = (record_fs_size + 7) & !7;
            if rsz_aligned > 0 && stats_val.fs_records == 1 {
                stats_val.fs_records_rb_max = (2 * 1024 * 1024) / rsz_aligned as u64;
            }
        }
    }

    Ok(())
}
// --- END: Core eBPF Program Logic (handle_fs_event) ---

// --- START: Kprobe Definitions ---
use aya_bpf::macros::{kprobe, kretprobe};
use aya_bpf::programs::ProbeContext;
// Bindings are from the dummy module defined near handle_fs_event
// FsEventInfo, IndexFsEvent etc. are from the current crate (lib.rs)

// KPROBE_SWITCH logic helper
#[inline]
fn should_skip_kprobe(monitor_type: u32) -> bool {
    // MONITOR is a static mut global variable
    (unsafe { MONITOR } & monitor_type) == 0
}

// For security_inode_symlink and dput interaction
static mut DENTRY_SYMLINK_TEMP: *const bindings::dentry = core::ptr::null_mut();


#[kretprobe(name="do_filp_open")]
pub fn do_filp_open(ctx: ProbeContext) -> u32 {
    match try_do_filp_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Non-zero on error
    }
}

fn try_do_filp_open(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }

    let filp_ptr = ctx.ret_ptr() as *const bindings::file;
    if filp_ptr.is_null() { return Ok(0); }

    // Placeholder CO-RE reads (actual reads require real bindings)
    let f_mode_val: u32 = 0; // e.g., unsafe { (*filp_ptr).f_mode.read_kernel() }?;
    let f_path_dentry_ptr: *const bindings::dentry = core::ptr::null(); // e.g., unsafe { (*filp_ptr).f_path.dentry.read_kernel() }?;

    const FMODE_CREATED: u32 = 0x0100000; // Defined in dirt.h
    if (f_mode_val & FMODE_CREATED) != 0 {
        let event_info = FsEventInfo {
            index: IndexFsEvent::ICreate,
            dentry: f_path_dentry_ptr as *const cty::c_void,
            dentry_old: core::ptr::null(),
            func_name: b"do_filp_open\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}

#[kprobe(name="security_inode_link")]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    match try_security_inode_link(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_inode_link(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }

    let old_dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*const bindings::dentry>(2).ok_or(1i64)?;

    let event_info = FsEventInfo {
        index: IndexFsEvent::ICreate,
        dentry: new_dentry_ptr as *const cty::c_void,
        dentry_old: old_dentry_ptr as *const cty::c_void,
        func_name: b"security_inode_link\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_info)?;
    Ok(0)
}

#[kprobe(name="security_inode_symlink")]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_symlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_inode_symlink(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr_arg = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;
    unsafe { DENTRY_SYMLINK_TEMP = dentry_ptr_arg };
    Ok(0)
}

#[kprobe(name="dput")]
pub fn dput(ctx: ProbeContext) -> u32 {
    match try_dput(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_dput(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr_arg = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;

    if unsafe { DENTRY_SYMLINK_TEMP.is_null() || DENTRY_SYMLINK_TEMP != dentry_ptr_arg } {
        return Ok(0);
    }

    // Placeholder CO-RE reads
    let imode_val: u16 = 0; // e.g., unsafe { (*dentry_ptr_arg).d_inode.i_mode.read_kernel() }?;
    let ino_val: u32 = 0;   // e.g., unsafe { (*dentry_ptr_arg).d_inode.i_ino.read_kernel() }?;

    if !(s_islnk(imode_val) && ino_val != 0) {
        return Ok(0);
    }

    unsafe { DENTRY_SYMLINK_TEMP = core::ptr::null_mut() };

    let event_info = FsEventInfo {
        index: IndexFsEvent::ICreate,
        dentry: dentry_ptr_arg as *const cty::c_void,
        dentry_old: core::ptr::null(),
        func_name: b"dput+security_inode_symlink\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_info)?;
    Ok(0)
}


#[kprobe(name="notify_change")]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    match try_notify_change(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_notify_change(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let iattr_ptr = ctx.arg::<*const cty::c_void>(1).ok_or(1i64)?; // Placeholder for struct iattr*

    // Placeholder CO-RE read
    let ia_valid_val: u32 = 0; // e.g., unsafe { (*iattr_ptr).ia_valid.read_kernel() }?;

    // ATTR_* constants should be defined globally from Step 2.
    // These are local consts for clarity, assuming global ones like crate::ATTR_UID exist.
    const ATTR_UID_FLAG: u32 = (1 << 1); const ATTR_GID_FLAG: u32 = (1 << 2); const ATTR_SIZE_FLAG: u32 = (1 << 3);
    const ATTR_ATIME_FLAG: u32 = (1 << 4); const ATTR_MTIME_FLAG: u32 = (1 << 5); const ATTR_MODE_FLAG: u32 = (1 << 0);

    let calls_attrib = (ia_valid_val & (ATTR_UID_FLAG | ATTR_GID_FLAG | ATTR_MODE_FLAG)) != 0 ||
                       ((ia_valid_val & (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG)) == (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG));
    let calls_modify = (ia_valid_val & ATTR_SIZE_FLAG) != 0 ||
                       ((ia_valid_val & (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG)) != (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG) && (ia_valid_val & ATTR_MTIME_FLAG) != 0);
    let calls_access = (ia_valid_val & (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG)) != (ATTR_ATIME_FLAG | ATTR_MTIME_FLAG) && (ia_valid_val & ATTR_ATIME_FLAG) != 0;

    if calls_attrib {
        let event_info = FsEventInfo {
            index: IndexFsEvent::IAttrib,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"notify_change_attrib\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    if calls_modify {
         let event_info = FsEventInfo {
            index: IndexFsEvent::IModify,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"notify_change_modify\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    if calls_access {
        let event_info = FsEventInfo {
            index: IndexFsEvent::IAccess,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"notify_change_access\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}

#[kprobe(name="__fsnotify_parent")]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    match try___fsnotify_parent(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try___fsnotify_parent(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }

    let dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let fs_mask = ctx.arg::<u32>(1).ok_or(1i64)?;

    // FS_* constants should be globally defined from Step 2.
    const FS_ATTRIB_CONST: u32 = 0x00000004;
    const FS_MODIFY_CONST: u32 = 0x00000002;
    const FS_ACCESS_CONST: u32 = 0x00000001;

    if (fs_mask & FS_ATTRIB_CONST) != 0 {
        let event_info = FsEventInfo {
            index: IndexFsEvent::IAttrib,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"__fsnotify_parent_attrib\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    if (fs_mask & FS_MODIFY_CONST) != 0 {
        let event_info = FsEventInfo {
            index: IndexFsEvent::IModify,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"__fsnotify_parent_modify\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    if (fs_mask & FS_ACCESS_CONST) != 0 {
        let event_info = FsEventInfo {
            index: IndexFsEvent::IAccess,
            dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(),
            func_name: b"__fsnotify_parent_access\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}


#[kprobe(name="security_inode_rename")]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    match try_security_inode_rename(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_inode_rename(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let old_dentry_ptr = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*const bindings::dentry>(3).ok_or(1i64)?;

    // Placeholder CO-RE read
    let d_flags_val: u32 = 0; // e.g., unsafe { (*old_dentry_ptr).d_flags.read_kernel() }?;
    // DCACHE_* constants should be globally defined from Step 2
    const DCACHE_ENTRY_TYPE_CONST: u32 = 0x00700000;
    const DCACHE_DIRECTORY_TYPE_CONST: u32 = 0x00200000;
    const DCACHE_AUTODIR_TYPE_CONST: u32 = 0x00300000;

    if ((d_flags_val & DCACHE_ENTRY_TYPE_CONST) == DCACHE_DIRECTORY_TYPE_CONST) ||
       ((d_flags_val & DCACHE_ENTRY_TYPE_CONST) == DCACHE_AUTODIR_TYPE_CONST) {
        return Ok(0);
    }

    let event_from = FsEventInfo {
        index: IndexFsEvent::IMovedFrom,
        dentry: old_dentry_ptr as *const cty::c_void,
        dentry_old: core::ptr::null(),
        func_name: b"security_inode_rename_from\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_from)?;

    let event_to = FsEventInfo {
        index: IndexFsEvent::IMovedTo,
        dentry: new_dentry_ptr as *const cty::c_void,
        dentry_old: old_dentry_ptr as *const cty::c_void,
        func_name: b"security_inode_rename_to\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_to)?;

    Ok(0)
}

#[kprobe(name="security_inode_unlink")]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_unlink(ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;

    let event_info = FsEventInfo {
        index: IndexFsEvent::IDelete,
        dentry: dentry_ptr as *const cty::c_void,
        dentry_old: core::ptr::null(),
        func_name: b"security_inode_unlink\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_info)?;
    Ok(0)
}

// --- END: Kprobe Definitions ---

// Example of how aya-gen might be invoked (as a comment, not executed):
// aya-gen generate --header vmlinux/x86/vmlinux.h --target-arch x86_64 > src/bindings.rs
// Or, if BTF is available on the system:
// aya-gen generate --btf /sys/kernel/btf/vmlinux > src/bindings.rs

// This is where BPF program code (kprobes, helpers) will go.
// We'll need to include our bindings:
// pub mod bindings {
//     // This will be automatically populated by #include_generated bindings from Aya
//     // For now, it refers to the placeholder bindings.rs
//     #![allow(non_upper_case_globals)]
//     #![allow(non_snake_case)]
//     #![allow(non_camel_case_types)]
//     #![allow(dead_code)]
//     // For manual aya-gen: include!("../../../vmlinux/x86/bindings.rs");
//     // For aya cargo build with build.rs: include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
// }
// use crate::bindings::*; // If types are needed globally here.

// Placeholder for actual BPF functions
fn placeholder_bpf_func() {
    // BPF functions will use types from `bindings` and `aya_bpf`
}
