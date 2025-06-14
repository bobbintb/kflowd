#![no_std]
#![allow(static_mut_refs)] // Allow static mut refs for BPF maps

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf_macros::{map, kprobe, kretprobe, info, trace, debug}; // Added logging macros
use aya_ebpf::cty;
use aya_ebpf::helpers::bpf_get_stack; // For debug_dump_stack

// --- START: Translated from dirt.h ---
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
pub const FS_EVENT_MAX: usize = 15;
pub const RECORD_TYPE_FILE: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Record {
    pub type_: u32,
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
    pub rename_info: RecordFsRenameInfo,
    pub filename: [u8; FILENAME_LEN_MAX],
}

impl Default for RecordFsFilenames {
    fn default() -> Self { RecordFsFilenames { filename: [0u8; FILENAME_LEN_MAX] } }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RecordFs {
    pub rc: Record, pub events: u32, pub event: [u32; FS_EVENT_MAX], pub ino: u32,
    pub imode: u32, pub inlink: u32, pub isize: u64, pub atime_nsec: u64,
    pub mtime_nsec: u64, pub ctime_nsec: u64, pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX], pub names: RecordFsFilenames,
}

impl Default for RecordFs {
    fn default() -> Self {
        RecordFs {
            rc: Record::default(), events: 0, event: [0; FS_EVENT_MAX], ino: 0, imode: 0,
            inlink: 0, isize: 0, atime_nsec: 0, mtime_nsec: 0, ctime_nsec: 0,
            isize_first: 0, filepath: [0u8; FILEPATH_LEN_MAX], names: RecordFsFilenames::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Stats {
    pub fs_records: u64, pub fs_records_deleted: u64, pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64, pub fs_events: u64,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IndexFsEvent {
    ICreate = 0, IOpen = 1, IOpenExec = 2, IAccess = 3, IAttrib = 4, IModify = 5,
    ICloseWrite = 6, ICloseNowrite = 7, IMovedFrom = 8, IMovedTo = 9, IDelete = 10,
    IDeleteSelf = 11, IMoveSelf = 12, IUnmount = 13, IQOverflow = 14,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FsEventInfo {
    pub index: IndexFsEvent, pub dentry: *const cty::c_void,
    pub dentry_old: *const cty::c_void, pub func_name: *const cty::c_char,
}

pub const MAP_RECORDS_MAX: u32 = 65536;
pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

pub const ATTR_UID: u32 = 1 << 1; pub const ATTR_GID: u32 = 1 << 2; pub const ATTR_SIZE: u32 = 1 << 3;
pub const ATTR_ATIME: u32 = 1 << 4; pub const ATTR_MTIME: u32 = 1 << 5; pub const ATTR_MODE: u32 = 1 << 0;

pub const FS_ATTRIB_FLAG: u32 = 0x00000004; pub const FS_MODIFY_FLAG: u32 = 0x00000002;
pub const FS_ACCESS_FLAG: u32 = 0x00000001; pub const FMODE_CREATED: u32 = 0x0100000;

pub const DCACHE_ENTRY_TYPE_CONST: u32 = 0x00700000;
pub const DCACHE_DIRECTORY_TYPE_CONST: u32 = 0x00200000;
pub const DCACHE_AUTODIR_TYPE_CONST: u32 = 0x00300000;

const S_IFMT: u16 = 0o0170000; const S_IFLNK: u16 = 0o0120000; const S_IFREG: u16 = 0o0100000;

#[inline] pub fn s_islnk(mode: u16) -> bool { (mode & S_IFMT) == S_IFLNK }
#[inline] pub fn s_isreg(mode: u16) -> bool { (mode & S_IFMT) == S_IFREG }
#[inline] pub fn key_pid_ino(pid: u32, ino: u32) -> u64 { ((pid as u64) << 32) | (ino as u64) }

pub const DBG_LEN_MAX: usize = 16; pub const MAX_STACK_TRACE_DEPTH: usize = 16;
pub const DNAME_INLINE_LEN: usize = 32; pub const FILEPATH_NODE_MAX: usize = 16;
// --- END: Translated from dirt.h ---

// --- START: BPF Map Definitions ---
use aya_ebpf::maps::{Array, LruHashMap, PerCpuArray, RingBuf};

#[map(name = "ringbuf_records")]
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);
#[map(name = "hash_records")]
pub static mut HASH_RECORDS: LruHashMap<u64, RecordFs> = LruHashMap::with_max_entries(MAP_RECORDS_MAX, 0);
#[map(name = "heap_record_fs")]
pub static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);
#[map(name = "stats")]
pub static mut STATS: Array<Stats> = Array::with_max_entries(1, 0);
// --- END: BPF Map Definitions ---

// --- START: Global Variables (Loader Initialized) ---
static mut PID_SELF: u32 = 0; static mut AGG_EVENTS_MAX: u32 = 0;
static mut MONITOR: u32 = MONITOR_FILE;
#[allow(dead_code)]
static mut TS_START: u64 = 0;
// DEBUG_MSG is now used by debug_proc
static mut DEBUG_MSG: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX];
// --- END: Global Variables ---

// --- START: Dummy Bindings (Temporary for handle_fs_event structure) ---
pub mod bindings {
    #[repr(C)] pub struct dentry { pub _unused: [u8; 0] }
    #[repr(C)] pub struct inode { pub _unused: [u8; 0] }
    #[repr(C)] pub struct file { pub _unused: [u8; 0] }
    #[repr(C)] pub struct qstr { pub name: *const aya_ebpf::cty::c_char, }
    #[repr(C)] pub struct pt_regs {
        pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64, pub rbp: u64, pub rbx: u64,
        pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64, pub rax: u64, pub rcx: u64,
        pub rdx: u64, pub rsi: u64, pub rdi: u64, pub orig_rax: u64, pub rip: u64,
        pub cs: u64, pub eflags: u64, pub rsp: u64, pub ss: u64,
    }
    // Added for debug_dump_stack
    #[repr(C)]
    pub struct bpf_stack_build_id {
        pub status: u32,
        pub offset: u32,
        pub build_id: [u8; 20], // BUILD_ID_SIZE_MAX from include/uapi/linux/bpf.h
    }

}
// --- END: Dummy Bindings ---

// --- START: Core eBPF Program Logic (handle_fs_event) ---
use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::bindings::BPF_ANY;
use crate::bindings::{dentry, inode};

#[inline]
fn try_read_kernel_str_bytes(src: *const u8, buf: &mut [u8]) -> Result<usize, i64> {
    if buf.is_empty() { return Err(1); }
    match unsafe { bpf_probe_read_kernel_str_bytes(src, buf) } {
        Ok(_) => {
            Ok(buf.iter().position(|&byte| byte == 0).unwrap_or(buf.len()))
        }
        Err(e) => Err(e as i64),
    }
}

#[inline]
#[allow(unused_variables, clippy::collapsible_else_if, clippy::manual_memcpy)]
fn handle_fs_event(event_info: &FsEventInfo) -> Result<(), i64> {
    if event_info.index == IndexFsEvent::IAccess || event_info.index == IndexFsEvent::IAttrib {
        return Ok(());
    }

    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    if unsafe { PID_SELF } == pid { return Ok(()); }

    let index = event_info.index;
    let dentry_ptr = event_info.dentry as *const dentry;
    let dentry_old_ptr = event_info.dentry_old as *const dentry;

    let current_dentry_ptr = if dentry_old_ptr.is_null() { dentry_ptr } else { dentry_old_ptr };
    if current_dentry_ptr.is_null() { return Ok(()); }

    let inode_ptr_from_dentry: *const inode = unsafe { (*current_dentry_ptr)._unused.as_ptr() as *const inode };
    let filename_src_ptr_from_dentry: *const cty::c_char = unsafe { (*dentry_ptr)._unused.as_ptr() as *const cty::c_char };
    let ino_val: u32 = 0; let imode_val: u16 = 0; let isize_val: u64 = 0; let inlink_val: u32 = 0;
    let atime_sec_val: u64 = 0; let atime_nsec_val: u64 = 0;
    let mtime_sec_val: u64 = 0; let mtime_nsec_val: u64 = 0;
    let ctime_sec_val: u64 = 0; let ctime_nsec_val: u64 = 0;

    if inode_ptr_from_dentry.is_null() { return Ok(()); }

    let mut filename_buf = [0u8; FILENAME_LEN_MAX];
    if !filename_src_ptr_from_dentry.is_null() {
        match try_read_kernel_str_bytes(filename_src_ptr_from_dentry as *const u8, &mut filename_buf) {
            Ok(0) => return Ok(()),
            Err(e) => return Err(e),
            Ok(len_read) if len_read == 0 => return Ok(()),
            Ok(_) => {}
        }
    } else { return Ok(()); }
    if filename_buf[0] == 0 { return Ok(()); }

    if !(s_isreg(imode_val) || s_islnk(imode_val)) { return Ok(()); }

    let key = key_pid_ino(pid, ino_val);
    let zero_key: u32 = 0;
    let r_for_aggregation_logic: RecordFs;

    if let Some(mut r_existing) = unsafe { HASH_RECORDS.get(&key).copied() } {
        if index == IndexFsEvent::IMovedTo {
            unsafe {
                let dest_slice = &mut r_existing.names.rename_info.filename_to[..];
                let src_len = filename_buf.iter().position(|&x| x == 0).unwrap_or(FILENAME_LEN_MAX / 2);
                let len_to_copy = core::cmp::min(src_len, FILENAME_LEN_MAX / 2);
                dest_slice[0..len_to_copy].copy_from_slice(&filename_buf[0..len_to_copy]);
                if len_to_copy < FILENAME_LEN_MAX / 2 { dest_slice[len_to_copy] = 0; }
            }
        }
        // r_existing.rc.ts = ts_event; // ts_event removed
        r_existing.imode = imode_val as u32; r_existing.isize = isize_val; r_existing.inlink = inlink_val;
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
            // r_current.rc.ts = ts_event; // ts_event removed
            r_current.ino = ino_val;
            unsafe { r_current.names.filename.copy_from_slice(&filename_buf) };
            r_current.isize_first = isize_val;
            r_current.filepath = [0u8; FILEPATH_LEN_MAX];
            r_current.events = 0; r_current.event = [0u32; FS_EVENT_MAX];
            r_current.imode = imode_val as u32; r_current.isize = isize_val; r_current.inlink = inlink_val;
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
            if let Some(stats_val_ptr) = unsafe { STATS.get_ptr_mut(zero_key) } {
                unsafe { (*stats_val_ptr).fs_records = (*stats_val_ptr).fs_records.saturating_add(1); }
            }
        } else { return Err(1); }
    }

    let mut agg_end = false;
    match index {
        IndexFsEvent::ICloseWrite | IndexFsEvent::ICloseNowrite | IndexFsEvent::IDelete | IndexFsEvent::IMovedTo => {
            agg_end = true;
        }
        IndexFsEvent::ICreate => {
            if s_islnk(imode_val) || r_for_aggregation_logic.inlink > 1 { agg_end = true; }
        }
        _ => {}
    }
    let current_agg_events_max = unsafe { AGG_EVENTS_MAX };
    if !agg_end && current_agg_events_max > 0 && r_for_aggregation_logic.events >= current_agg_events_max {
        agg_end = true;
    }

    if agg_end {
        let mut r_to_send = r_for_aggregation_logic;
        r_to_send.rc.type_ = RECORD_TYPE_FILE;
        if unsafe { RINGBUF_RECORDS.output(&r_to_send, 0) }.is_err() {
            if let Some(stats_val_ptr) = unsafe { STATS.get_ptr_mut(zero_key) } {
                unsafe { (*stats_val_ptr).fs_records_dropped = (*stats_val_ptr).fs_records_dropped.saturating_add(1); }
            }
        }
        if unsafe { HASH_RECORDS.remove(&key) }.is_ok() {
            if let Some(stats_val_ptr) = unsafe { STATS.get_ptr_mut(zero_key) } {
                unsafe { (*stats_val_ptr).fs_records_deleted = (*stats_val_ptr).fs_records_deleted.saturating_add(1); }
            }
        }
    }

    if let Some(stats_val_ptr) = unsafe { STATS.get_ptr_mut(zero_key) } {
        let stats_val = unsafe { &mut *stats_val_ptr };
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

// --- START: Debugging Utilities ---
#[allow(dead_code)] // May be unused depending on final build
fn debug_file_is_tp(ctx: ProbeContext) -> u32 {
    let filename_ptr = ctx.arg::<*const cty::c_char>(0).unwrap_or(core::ptr::null());
    if filename_ptr.is_null() {
        debug!(ctx, "debug_file_is_tp: filename_ptr is NULL");
        return 0;
    }
    let mut buf = [0u8; 64]; // Increased buffer size for safety
    let read_len = match try_read_kernel_str_bytes(filename_ptr as *const u8, &mut buf) {
        Ok(len) => len,
        Err(e) => {
            debug!(ctx, "debug_file_is_tp: read_kernel_str_bytes failed: {}", e);
            return 0;
        }
    };
    if read_len == 0 || read_len >= buf.len() { // Check if read was empty or potentially truncated
        debug!(ctx, "debug_file_is_tp: read_len invalid {} or too long for buffer", read_len);
        return 0;
    }

    // Simple check if "trace_pipe" is in the filename
    let trace_pipe_bytes = b"trace_pipe";
    if buf[..read_len].windows(trace_pipe_bytes.len()).any(|window| window == trace_pipe_bytes) {
        debug!(ctx, "debug_file_is_tp: Found trace_pipe in filename");
        return 1;
    }
    0
}

#[allow(dead_code)] // May be unused depending on final build
fn debug_proc(ctx: ProbeContext, msg_prefix: &str, value: u64) {
    let pid_tgid = aya_ebpf::helpers::bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let comm_ptr = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16].as_ptr() as *const u8);

    let mut comm_buf = [0u8; 16];
    let _ = try_read_kernel_str_bytes(comm_ptr, &mut comm_buf); // Ignore error for simplicity in debug

    // Format into DEBUG_MSG
    // This is a very basic formatting, real snprintf is not available.
    // Example: "prefix: value pid: X comm: YYY"
    // For simplicity, we'll just log the prefix and value.
    // A more robust solution would involve a ring buffer for debug messages.
    let mut cursor = 0;
    for byte in msg_prefix.as_bytes().iter() {
        if cursor < DBG_LEN_MAX -1 { unsafe { DEBUG_MSG[cursor] = *byte; } cursor += 1; } else { break; }
    }
    // Add a space or delimiter if there's room
    if cursor < DBG_LEN_MAX -1 { unsafe { DEBUG_MSG[cursor] = b':'; } cursor += 1; }
    if cursor < DBG_LEN_MAX -1 { unsafe { DEBUG_MSG[cursor] = b' '; } cursor += 1; }

    // Naive u64 to_ascii (limited length for simplicity)
    let mut temp_val = value;
    let start_cursor = cursor;
    if temp_val == 0 && cursor < DBG_LEN_MAX - 1 {
        unsafe { DEBUG_MSG[cursor] = b'0'; } cursor += 1;
    } else {
        while temp_val > 0 && cursor < DBG_LEN_MAX - 1 {
            unsafe { DEBUG_MSG[cursor] = (temp_val % 10) as u8 + b'0'; }
            temp_val /= 10;
            cursor += 1;
        }
        // Reverse the number string
        let end_cursor = cursor;
        let mut i = start_cursor;
        let mut j = end_cursor -1;
        while i < j {
            unsafe { DEBUG_MSG.swap(i,j); }
            i += 1; j -=1;
        }
    }
    if cursor < DBG_LEN_MAX { unsafe { DEBUG_MSG[cursor] = 0; } } else { unsafe { DEBUG_MSG[DBG_LEN_MAX-1] = 0; } }

    // Using info! macro which relies on aya-log-ebpf setup (e.g. bpf_printk)
    // The content of DEBUG_MSG might not be directly usable by info! if it expects format strings.
    // For a direct printk-like behavior, one would typically use a helper that formats and pushes to ring buffer
    // or directly uses bpf_trace_printk if available and appropriate (not recommended for high-frequency).
    // For this example, let's assume info! can take a byte slice or we use a simpler approach.
    // aya_log_ebpf::info!(ctx, "pid:{} comm:{} {}: {}", pid, &comm_buf[..], msg_prefix, value);
    // Since DEBUG_MSG is now populated, we could try to send it.
    // However, aya_log_ebpf macros expect format string literals.
    // A simple log for now:
    info!(ctx, "DEBUG: pid:{} value:{}", pid, value);
}


#[allow(dead_code)] // May be unused depending on final build
fn debug_dump_stack(ctx: ProbeContext) {
    const STACK_BUF_SIZE: usize = MAX_STACK_TRACE_DEPTH * core::mem::size_of::<u64>();
    let mut stack_buf = [0u8; STACK_BUF_SIZE];
    let mut build_id_buf = [0u8; core::mem::size_of::<bindings::bpf_stack_build_id>()];

    let stack_len = match unsafe { bpf_get_stack(ctx.as_ptr(), &mut stack_buf, STACK_BUF_SIZE as u32, 0) } {
        Ok(len) => len,
        Err(e) => {
            info!(ctx, "Failed to get stack: {}", e);
            return;
        }
    };

    if stack_len == 0 {
        info!(ctx, "Stack trace empty.");
        return;
    }

    info!(ctx, "Stack trace ({} bytes):", stack_len);
    // Iterate over stack addresses (assuming u64 addresses)
    let mut i = 0;
    while i < stack_len as usize && i < STACK_BUF_SIZE {
        if STACK_BUF_SIZE - i < core::mem::size_of::<u64>() { break; }
        let addr = u64::from_ne_bytes(stack_buf[i..i+core::mem::size_of::<u64>()].try_into().unwrap_or_default());
        info!(ctx, "  ip: {:#x}", addr);

        // Try to get build ID and offset for this address
        // This is a simplified version, as bpf_get_stack_build_id is not directly available in aya_ebpf::helpers
        // A real implementation would need to call the helper appropriately.
        // For now, just print the raw address.
        // Example of how one might use bpf_stack_build_id if available:
        // let build_id_ptr = build_id_buf.as_mut_ptr() as *mut bindings::bpf_stack_build_id;
        // if unsafe { bpf_get_stack_build_id_helper(ctx.as_ptr(), addr, build_id_ptr) } == 0 {
        //    let build_id_info = unsafe { &*build_id_ptr };
        //    info!(ctx, "    build_id: {:x?}, offset: {:#x}", &build_id_info.build_id[..], build_id_info.offset);
        // }
        i += core::mem::size_of::<u64>();
    }
}

// --- END: Debugging Utilities ---


// --- START: Kprobe Definitions ---
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

#[inline] fn should_skip_kprobe(monitor_type: u32) -> bool { (unsafe { MONITOR } & monitor_type) == 0 }
static mut DENTRY_SYMLINK_TEMP: *const bindings::dentry = core::ptr::null_mut();

#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    match try_do_filp_open_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}

fn try_do_filp_open_internal(ctx: RetProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let filp_ptr = unsafe { (*ctx.regs).rax as *const bindings::file };
    if filp_ptr.is_null() { return Ok(0); }
    let f_mode_val: u32 = 0;
    let f_path_dentry_ptr: *const bindings::dentry = core::ptr::null();
    if (f_mode_val & FMODE_CREATED) != 0 {
        let event_info = FsEventInfo {
            index: IndexFsEvent::ICreate, dentry: f_path_dentry_ptr as *const cty::c_void,
            dentry_old: core::ptr::null(), func_name: b"do_filp_open\0".as_ptr() as *const cty::c_char,
        };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    match try_security_inode_link_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_security_inode_link_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let old_dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*const bindings::dentry>(2).ok_or(1i64)?;
    let event_info = FsEventInfo {
        index: IndexFsEvent::ICreate, dentry: new_dentry_ptr as *const cty::c_void,
        dentry_old: old_dentry_ptr as *const cty::c_void,
        func_name: b"security_inode_link\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_info)?; Ok(0)
}

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_symlink_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_security_inode_symlink_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr_arg = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;
    unsafe { DENTRY_SYMLINK_TEMP = dentry_ptr_arg }; Ok(0)
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    match try_dput_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_dput_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr_arg = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    if unsafe { DENTRY_SYMLINK_TEMP.is_null() || DENTRY_SYMLINK_TEMP != dentry_ptr_arg } { return Ok(0); }
    let imode_val: u16 = 0; let ino_val: u32 = 0;
    if !(s_islnk(imode_val) && ino_val != 0) { return Ok(0); }
    unsafe { DENTRY_SYMLINK_TEMP = core::ptr::null_mut() };
    let event_info = FsEventInfo {
        index: IndexFsEvent::ICreate, dentry: dentry_ptr_arg as *const cty::c_void,
        dentry_old: core::ptr::null(),
        func_name: b"dput+security_inode_symlink\0".as_ptr() as *const cty::c_char,
    };
    handle_fs_event(&event_info)?; Ok(0)
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    match try_notify_change_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_notify_change_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let _iattr_ptr = ctx.arg::<*const cty::c_void>(1).ok_or(1i64)?;
    let ia_valid_val: u32 = 0;
    let calls_attrib = (ia_valid_val & (ATTR_UID | ATTR_GID | ATTR_MODE)) != 0 ||
                       ((ia_valid_val & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME));
    let calls_modify = (ia_valid_val & ATTR_SIZE) != 0 ||
                       ((ia_valid_val & (ATTR_ATIME | ATTR_MTIME)) != (ATTR_ATIME | ATTR_MTIME) && (ia_valid_val & ATTR_MTIME) != 0);
    let calls_access = (ia_valid_val & (ATTR_ATIME | ATTR_MTIME)) != (ATTR_ATIME | ATTR_MTIME) && (ia_valid_val & ATTR_ATIME) != 0;
    if calls_attrib {
        let event_info = FsEventInfo { index: IndexFsEvent::IAttrib, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"notify_change_attrib\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    if calls_modify {
         let event_info = FsEventInfo { index: IndexFsEvent::IModify, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"notify_change_modify\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    if calls_access {
        let event_info = FsEventInfo { index: IndexFsEvent::IAccess, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"notify_change_access\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    match try_fsnotify_parent_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_fsnotify_parent_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr = ctx.arg::<*const bindings::dentry>(0).ok_or(1i64)?;
    let fs_mask = ctx.arg::<u32>(1).ok_or(1i64)?;
    if (fs_mask & FS_ATTRIB_FLAG) != 0 {
        let event_info = FsEventInfo { index: IndexFsEvent::IAttrib, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"__fsnotify_parent_attrib\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    if (fs_mask & FS_MODIFY_FLAG) != 0 {
        let event_info = FsEventInfo { index: IndexFsEvent::IModify, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"__fsnotify_parent_modify\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    if (fs_mask & FS_ACCESS_FLAG) != 0 {
        let event_info = FsEventInfo { index: IndexFsEvent::IAccess, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"__fsnotify_parent_access\0".as_ptr() as *const cty::c_char, };
        handle_fs_event(&event_info)?;
    }
    Ok(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    match try_security_inode_rename_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_security_inode_rename_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let old_dentry_ptr = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*const bindings::dentry>(3).ok_or(1i64)?;
    let d_flags_val: u32 = 0;
    if ((d_flags_val & DCACHE_ENTRY_TYPE_CONST) == DCACHE_DIRECTORY_TYPE_CONST) ||
       ((d_flags_val & DCACHE_ENTRY_TYPE_CONST) == DCACHE_AUTODIR_TYPE_CONST) { return Ok(0); }
    let event_from = FsEventInfo { index: IndexFsEvent::IMovedFrom, dentry: old_dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"security_inode_rename_from\0".as_ptr() as *const cty::c_char, };
    handle_fs_event(&event_from)?;
    let event_to = FsEventInfo { index: IndexFsEvent::IMovedTo, dentry: new_dentry_ptr as *const cty::c_void, dentry_old: old_dentry_ptr as *const cty::c_void, func_name: b"security_inode_rename_to\0".as_ptr() as *const cty::c_char, };
    handle_fs_event(&event_to)?; Ok(0)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    match try_security_inode_unlink_internal(ctx) { Ok(ret) => ret, Err(_) => 1, }
}
fn try_security_inode_unlink_internal(ctx: ProbeContext) -> Result<u32, i64> {
    if should_skip_kprobe(MONITOR_FILE) { return Ok(0); }
    let dentry_ptr = ctx.arg::<*const bindings::dentry>(1).ok_or(1i64)?;
    let event_info = FsEventInfo { index: IndexFsEvent::IDelete, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"security_inode_unlink\0".as_ptr() as *const cty::c_char, };
    handle_fs_event(&event_info)?; Ok(0)
}
// --- END: Kprobe Definitions ---

// Example of how aya-gen might be invoked (as a comment, not executed):
// aya-gen generate --header vmlinux/x86/vmlinux.h --target-arch x86_64 > src/bindings.rs
// Or, if BTF is available on the system:
// aya-gen generate --btf /sys/kernel/btf/vmlinux > src/bindings.rs

#[allow(dead_code)]
fn placeholder_bpf_func() {}

```
