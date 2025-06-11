#[license = "GPL-2.0"]
#![no_std]
#![no_main]

use aya_bpf::{
    macros::map,
    // Will need these for program types later:
    // programs::ProbeContext,
    // programs::KProbeContext, // Or specific context if aya provides for kprobe etc.
    maps::*,
};
use aya_log_ebpf::{self}; // Renamed to avoid conflict, will use aya_log_ebpf::info etc.
use kflowd_common::*;
use libc::pid_t;

/*
Original C maps:
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(struct RECORD_FS) * 8192);
} ringbuf_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RECORDS_MAX);
    __type(key, __u64);
    __type(value, struct RECORD_FS);
} hash_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct RECORD_FS);
} heap_record_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct STATS);
} stats SEC(".maps");
*/

// BPF Maps translated to Aya Rust
// Note: max_entries for RingBuf in Aya is in bytes.
// sizeof(struct RECORD_FS) is not easily known at compile time here without C interop or estimation.
// Let's assume a generous size for RECORD_FS, e.g., 256 bytes.
// sizeof(RECORD_FS) * 8192 = 256 * 8192 = 2097152 (2MB)
// Aya's RingBuf::with_max_entries takes bytes.
#[map]
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_max_entries(2 * 1024 * 1024, 0); // 2MB, flags = 0

#[map]
pub static mut HASH_RECORDS: LruHashMap<u64, RecordFs> =
    LruHashMap::with_max_entries(MAP_RECORDS_MAX, 0); // MAP_RECORDS_MAX from common

#[map]
pub static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut STATS_MAP: Array<Stats> = Array::with_max_entries(1, 0); // Renamed from 'stats'

/*
Original C global variables:
const volatile __u64 ts_start;
const volatile __u32 agg_events_max;
const volatile pid_t pid_self;
const volatile pid_t pid_shell;
volatile __u32       monitor = MONITOR_NONE;
const volatile char  debug[DBG_LEN_MAX];
*/

// Global variables (configurable from user space via .bss or .data section, or specific map)
// Aya allows marking these with `#[btf_var(name = "variable_name")]` for libbpf to find them.
// Or they can be managed via a dedicated configuration map.
// For direct translation, `static mut` is the closest.
// The `volatile` keyword in C suggests they can be changed externally.
// In Aya, these would typically be managed by user-space writing to them before attaching,
// or through a designated global data map if they need to be dynamic during runtime from BPF.
// For now, just declare them. Their values would be set by a user-space loader.

// Note: Aya's recommended way for configuration is often a global data map (e.g., Array<ConfigStruct> of size 1)
// or by initializing these static mut variables from user-space before tracepoints/probes are active.
// For simplicity of translation, we'll use static mut.

#[no_mangle]
#[link_section = ".bss"] // Or .data if initialized, .bss for zero-initialized
pub static mut TS_START: u64 = 0;

#[no_mangle]
#[link_section = ".bss"]
pub static mut AGG_EVENTS_MAX: u32 = 0;

#[no_mangle]
#[link_section = ".bss"]
pub static mut PID_SELF: pid_t = 0;

#[no_mangle]
#[link_section = ".bss"]
pub static mut PID_SHELL: pid_t = 0;

#[no_mangle]
#[link_section = ".data"] // .data because it has an initial value
pub static mut MONITOR: u32 = MONITOR_NONE; // MONITOR_NONE from common

#[no_mangle]
#[link_section = ".bss"]
pub static mut DEBUG_STR: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX]; // Renamed from 'debug'

// For dentry_symlink used in symlink probes
// struct dentry *dentry_symlink = NULL;
// This needs to be a raw pointer. In Rust, this would be:
// static mut DENTRY_SYMLINK: *mut c_void = core::ptr::null_mut(); // Assuming dentry is opaque
// Or, if we have dentry definition from aya_bpf::bindings::dentry
// static mut DENTRY_SYMLINK: *mut aya_bpf::bindings::dentry = core::ptr::null_mut();
// For now, let's use c_void. It will be cast later.
use core::ffi::c_void; // This use statement is fine here or at the top.
use core::ffi::c_char; // Moved from lower down for organization
use core::mem; // Added for debug functions

pub static mut DENTRY_SYMLINK: *mut c_void = core::ptr::null_mut();


// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// Placeholder for BPF programs (probes, tracepoints) which will be added in subsequent steps.
// This file needs to be parsable as Rust. The actual BPF program functions will follow.
// For example:
// #[kprobe]
// pub fn some_kprobe_function(ctx: ProbeContext) -> u32 {
//     // ... logic ...
//     0
// }

// EOF marker not needed by tool
// Appended content starts here:
use aya_bpf::{
    BpfContext, // General context, might need more specific for kprobes
    helpers::*,
    bindings::{dentry, inode, iattr, file}, // Added file here
    macros::btf_core_read, // For BPF_CORE_READ
    programs::KProbeContext, // Specific context for kprobes
};
// use core::ffi::c_char; // Already moved to top

// The main logic function (handle_fs_event - already present from previous step)
#[inline(always)] // Mimic __always_inline
fn handle_fs_event(
    _ctx: &impl BpfContext, // Renamed ctx to _ctx as it's not used directly in this version
    event_index: IndexFsEvent,
    event_dentry_ptr: *mut dentry,
    event_dentry_old_ptr: *mut dentry,
) -> Result<(), i64> {
    if matches!(event_index, IndexFsEvent::IAccess | IndexFsEvent::IAttrib) {
        return Ok(());
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as pid_t;

    let pid_self_val = unsafe { PID_SELF };
    if pid_self_val != 0 && pid_self_val == pid { // Only filter if PID_SELF is set
        return Ok(());
    }

    let dentry_to_use_ptr: *mut dentry = if !event_dentry_old_ptr.is_null() {
        event_dentry_old_ptr
    } else {
        event_dentry_ptr
    };

    if dentry_to_use_ptr.is_null() { // If both were null (edge case)
        return Ok(());
    }

    let d_inode_ptr: *mut inode = unsafe { btf_core_read!(dentry_to_use_ptr, d_inode) };
    if d_inode_ptr.is_null() {
        return Ok(());
    }

    let mut temp_filename_buf = [0u8; FILENAME_LEN_MAX];
    let d_name_ptr: *const c_char = unsafe { btf_core_read!(event_dentry_ptr, d_name.name) };
    let len = unsafe { bpf_probe_read_kernel_str(temp_filename_buf.as_mut_ptr() as *mut _, FILENAME_LEN_MAX as u32, d_name_ptr as *const _).unwrap_or(0) };

    if len == 0 || (len > 0 && temp_filename_buf[0] == 0) {
        return Ok(());
    }

    let ino_val: u32 = unsafe { btf_core_read!(d_inode_ptr, i_ino) as u32 };
    let imode_val: umode_t = unsafe { btf_core_read!(d_inode_ptr, i_mode) };

    if !(s_isreg(imode_val) || s_islnk(imode_val)) {
        return Ok(());
    }

    let key = key_pid_ino(pid, ino_val);
    let ts_event = unsafe { bpf_ktime_get_ns() };

    let r_ptr = match unsafe { HEAP_RECORD_FS.get_ptr_mut(0) } {
        Some(ptr) => ptr,
        None => return Err(-1),
    };
    let r = unsafe { &mut *r_ptr };

    if let Some(existing_r_val) = unsafe { HASH_RECORDS.get(&key) } {
        *r = *existing_r_val;

        if event_index == IndexFsEvent::IMovedTo {
            r.filename_to = [0u8; FILENAME_LEN_MAX / 2];
            unsafe {
                bpf_probe_read_kernel_str(
                    r.filename_to.as_mut_ptr() as *mut _,
                    (FILENAME_LEN_MAX / 2) as u32,
                    d_name_ptr as *const _,
                ).map_err(|e| e as i64)?;
            }
        }
        r.rc.ts = ts_event;
    } else {
        *r = RecordFs {
            rc: RecordCommon { record_type: RECORD_TYPE_FILE, ts: ts_event },
            events: 0,
            event: [0; FS_EVENT_MAX],
            ino: ino_val,
            imode: imode_val,
            inlink: 0,
            isize: 0,
            atime_nsec: 0,
            mtime_nsec: 0,
            ctime_nsec: 0,
            isize_first: unsafe { btf_core_read!(d_inode_ptr, i_size) as u64 },
            filepath: [0u8; FILEPATH_LEN_MAX],
            filename: [0u8; FILENAME_LEN_MAX],
            filename_to: [0u8; FILENAME_LEN_MAX / 2],
        };
        unsafe {
             bpf_probe_read_kernel_str(
                r.filename.as_mut_ptr() as *mut _,
                FILENAME_LEN_MAX as u32,
                d_name_ptr as *const _,
            ).map_err(|e| e as i64)?;
        }

        const FILEPATH_NODE_MAX_USIZE: usize = 16;
        let mut pathnode: [*const c_char; FILEPATH_NODE_MAX_USIZE] = [core::ptr::null(); FILEPATH_NODE_MAX_USIZE];
        let mut current_dentry_ptr_for_path = dentry_to_use_ptr;
        let mut num_nodes_stored = 0;

        for i in 0..FILEPATH_NODE_MAX_USIZE {
            if current_dentry_ptr_for_path.is_null() { break; }
            let d_name_val: *const c_char = unsafe { btf_core_read!(current_dentry_ptr_for_path, d_name.name) };
            let d_parent_ptr: *mut dentry = unsafe { btf_core_read!(current_dentry_ptr_for_path, d_parent) };

            pathnode[i] = d_name_val;
            num_nodes_stored = i + 1;

            if current_dentry_ptr_for_path == d_parent_ptr {
                break;
            }
            current_dentry_ptr_for_path = d_parent_ptr;
        }

        let mut current_offset: usize = 0;
        if FILEPATH_LEN_MAX > 0 {
            r.filepath[0] = b'/';
            current_offset = 1;
        }

        for i in (0..num_nodes_stored).rev() {
            if pathnode[i].is_null() { continue; }
            if current_offset >= FILEPATH_LEN_MAX { break; }

            let current_d_name_first_char: u8 = unsafe { *pathnode[i] };
            if current_d_name_first_char == 0 {
                if i == 0 && num_nodes_stored == 1 && current_offset == 1 && r.filepath[0] == b'/' { }
                continue;
            }
            if (current_d_name_first_char == b'.' && unsafe { *(pathnode[i].add(1)) == 0 }) ||
               (current_d_name_first_char == b'.' && unsafe { *(pathnode[i].add(1)) == b'.' } && unsafe { *(pathnode[i].add(2)) == 0 }) ||
               (current_d_name_first_char == b'/' && unsafe { *(pathnode[i].add(1)) == 0 }) {
                if i == 0 && current_offset == 1 && r.filepath[0] == b'/' { }
                continue;
            }

            let max_seg_len = FILEPATH_LEN_MAX - current_offset;
            let len_read = unsafe {
                bpf_probe_read_kernel_str(
                    r.filepath.as_mut_ptr().add(current_offset),
                    max_seg_len as u32,
                    pathnode[i] as *const _,
                ).unwrap_or(0)
            };

            if len_read > 0 {
                let actual_len = if len_read > 0 && r.filepath[current_offset + len_read as usize - 1] == 0 {
                    len_read - 1
                } else {
                    len_read
                };
                if actual_len == 0 { continue; }
                current_offset += actual_len as usize;
                if i != 0 && current_offset < FILEPATH_LEN_MAX {
                    r.filepath[current_offset] = b'/';
                    current_offset += 1;
                }
            }
        }

        unsafe {
            if let Some(s_ptr) = STATS_MAP.get_ptr_mut(0) {
                 (*s_ptr).fs_records += 1;
            }
        }
    }

    r.imode = imode_val;
    r.isize = unsafe { btf_core_read!(d_inode_ptr, i_size) as u64 };
    r.inlink = unsafe { btf_core_read!(d_inode_ptr, i_nlink) as u32 };

    if event_index == IndexFsEvent::ICreate && !event_dentry_old_ptr.is_null() {
        r.inlink += 1;
    }

    let i_atime_sec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_atime.tv_sec) as u64 };
    let i_atime_nsec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_atime.tv_nsec) as u64 };
    r.atime_nsec = i_atime_sec.wrapping_mul(1_000_000_000).wrapping_add(i_atime_nsec);

    let i_mtime_sec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_mtime.tv_sec) as u64 };
    let i_mtime_nsec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_mtime.tv_nsec) as u64 };
    r.mtime_nsec = i_mtime_sec.wrapping_mul(1_000_000_000).wrapping_add(i_mtime_nsec);

    let i_ctime_sec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_ctime.tv_sec) as u64 };
    let i_ctime_nsec: u64 = unsafe { btf_core_read!(d_inode_ptr, i_ctime.tv_nsec) as u64 };
    r.ctime_nsec = i_ctime_sec.wrapping_mul(1_000_000_000).wrapping_add(i_ctime_nsec);

    r.events += 1;
    if (event_index as usize) < FS_EVENT_MAX {
        r.event[event_index as usize] += 1;
    }

    unsafe {
        if let Some(s_ptr) = STATS_MAP.get_ptr_mut(0) {
            (*s_ptr).fs_events += 1;
        }
    }

    unsafe { HASH_RECORDS.insert(&key, r, 0).map_err(|e| e as i64)? };

    let mut agg_end = false;
    match event_index {
        IndexFsEvent::ICloseWrite | IndexFsEvent::ICloseNowrite | IndexFsEvent::IDelete | IndexFsEvent::IMovedTo => {
            agg_end = true;
        }
        IndexFsEvent::ICreate if s_islnk(imode_val) || r.inlink > 1 => {
            agg_end = true;
        }
        _ => {}
    }

    let agg_events_max_val = unsafe { AGG_EVENTS_MAX };
    if !agg_end && agg_events_max_val > 0 {
        if r.events >= agg_events_max_val {
            agg_end = true;
        }
    }

    if agg_end {
        r.rc.record_type = RECORD_TYPE_FILE;
        if unsafe { RINGBUF_RECORDS.output(r, 0).is_err() } {
            unsafe {
                if let Some(s_ptr) = STATS_MAP.get_ptr_mut(0) {
                    (*s_ptr).fs_records_dropped += 1;
                }
            }
        }

        if unsafe { HASH_RECORDS.remove(&key).is_err() } {
            // Error on remove
        } else {
             unsafe {
                if let Some(s_ptr) = STATS_MAP.get_ptr_mut(0) {
                    (*s_ptr).fs_records_deleted += 1;
                }
            }
        }
    }

    unsafe {
        if let Some(s_ptr) = STATS_MAP.get_ptr_mut(0) {
            if (*s_ptr).fs_records_rb_max == 0 && (*s_ptr).fs_records == 1 {
                 // Skipped complex BPF-side calculation
            }
        }
    }
    Ok(())
}

// KProbe/KRetProbe functions start here
#[kretprobe(function = "do_filp_open")]
pub fn p_kret_do_filp_open(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let filp_ptr = ctx.arg::<*mut file>(0).unwrap_or(core::ptr::null_mut());
    if filp_ptr.is_null() { return 0; }

    let f_mode_val: u32 = unsafe { btf_core_read!(filp_ptr, f_mode) };
    if (f_mode_val & FMODE_CREATED) != 0 {
        let f_path_dentry_ptr: *mut dentry = unsafe { btf_core_read!(filp_ptr, f_path.dentry) };
        if f_path_dentry_ptr.is_null() { return 0; }
        let _ = handle_fs_event(&ctx, IndexFsEvent::ICreate, f_path_dentry_ptr, core::ptr::null_mut());
    }
    0
}

#[kprobe(function = "security_inode_link")]
pub fn p_sec_inode_link(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let old_dentry_ptr = ctx.arg::<*mut dentry>(0).unwrap_or(core::ptr::null_mut());
    let new_dentry_ptr = ctx.arg::<*mut dentry>(2).unwrap_or(core::ptr::null_mut());
    if new_dentry_ptr.is_null() || old_dentry_ptr.is_null() { return 0; }
    let _ = handle_fs_event(&ctx, IndexFsEvent::ICreate, new_dentry_ptr, old_dentry_ptr);
    0
}

#[kprobe(function = "security_inode_symlink")]
pub fn p_sec_inode_symlink(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let dentry_arg_ptr = ctx.arg::<*mut dentry>(1).unwrap_or(core::ptr::null_mut());
    if dentry_arg_ptr.is_null() { return 0; }
    unsafe { DENTRY_SYMLINK = dentry_arg_ptr as *mut c_void; }
    0
}

#[kprobe(function = "dput")]
pub fn p_dput(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let dentry_arg_ptr = ctx.arg::<*mut dentry>(0).unwrap_or(core::ptr::null_mut());
    if dentry_arg_ptr.is_null() || unsafe { DENTRY_SYMLINK != dentry_arg_ptr as *mut c_void } { return 0; }

    let d_inode_ptr: *mut inode = unsafe { btf_core_read!(dentry_arg_ptr, d_inode) };
    if d_inode_ptr.is_null() { return 0; }
    let imode_val: umode_t = unsafe { btf_core_read!(d_inode_ptr, i_mode) };
    let ino_val: u64 = unsafe { btf_core_read!(d_inode_ptr, i_ino) }; // Read as u64, consistent with handle_fs_event

    if !(s_islnk(imode_val) && ino_val != 0) { return 0; }

    unsafe { DENTRY_SYMLINK = core::ptr::null_mut(); }
    let _ = handle_fs_event(&ctx, IndexFsEvent::ICreate, dentry_arg_ptr, core::ptr::null_mut());
    0
}

#[kprobe(function = "notify_change")]
pub fn p_notify_change(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let dentry_arg_ptr = ctx.arg::<*mut dentry>(0).unwrap_or(core::ptr::null_mut());
    let attr_arg_ptr = ctx.arg::<*mut iattr>(1).unwrap_or(core::ptr::null_mut());
    if dentry_arg_ptr.is_null() || attr_arg_ptr.is_null() { return 0; }

    let ia_valid_val: u32 = unsafe { btf_core_read!(attr_arg_ptr, ia_valid) };
    let mut mask = 0u32;
    if (ia_valid_val & ATTR_UID) != 0 { mask |= FS_ATTRIB; }
    if (ia_valid_val & ATTR_GID) != 0 { mask |= FS_ATTRIB; }
    if (ia_valid_val & ATTR_SIZE) != 0 { mask |= FS_MODIFY; }
    if (ia_valid_val & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME) { mask |= FS_ATTRIB; }
    else if (ia_valid_val & ATTR_ATIME) != 0 { mask |= FS_ACCESS; }
    else if (ia_valid_val & ATTR_MTIME) != 0 { mask |= FS_MODIFY; }
    if (ia_valid_val & ATTR_MODE) != 0 { mask |= FS_ATTRIB; }

    if (mask & FS_ATTRIB) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IAttrib, dentry_arg_ptr, core::ptr::null_mut()); }
    if (mask & FS_MODIFY) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IModify, dentry_arg_ptr, core::ptr::null_mut()); }
    if (mask & FS_ACCESS) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IAccess, dentry_arg_ptr, core::ptr::null_mut()); }
    0
}

#[kprobe(function = "__fsnotify_parent")]
pub fn p_fsnotify_parent(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let dentry_arg_ptr = ctx.arg::<*mut dentry>(0).unwrap_or(core::ptr::null_mut());
    let mask_arg_val = ctx.arg::<u32>(1).unwrap_or(0);
    if dentry_arg_ptr.is_null() { return 0; }

    if (mask_arg_val & FS_ATTRIB) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IAttrib, dentry_arg_ptr, core::ptr::null_mut()); }
    if (mask_arg_val & FS_MODIFY) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IModify, dentry_arg_ptr, core::ptr::null_mut()); }
    if (mask_arg_val & FS_ACCESS) != 0 { let _ = handle_fs_event(&ctx, IndexFsEvent::IAccess, dentry_arg_ptr, core::ptr::null_mut()); }
    0
}

#[kprobe(function = "security_inode_rename")]
pub fn p_sec_inode_rename(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let old_dentry_ptr = ctx.arg::<*mut dentry>(1).unwrap_or(core::ptr::null_mut()); // old_dentry is PARM2 in C
    let new_dentry_ptr = ctx.arg::<*mut dentry>(3).unwrap_or(core::ptr::null_mut()); // new_dentry is PARM4 in C
    if old_dentry_ptr.is_null() || new_dentry_ptr.is_null() { return 0; }

    let d_flags_val: u32 = unsafe { btf_core_read!(old_dentry_ptr, d_flags) };
    if ((d_flags_val & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE) ||
       ((d_flags_val & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE) {
        return 0;
    }

    let _ = handle_fs_event(&ctx, IndexFsEvent::IMovedFrom, old_dentry_ptr, core::ptr::null_mut());
    let _ = handle_fs_event(&ctx, IndexFsEvent::IMovedTo, new_dentry_ptr, old_dentry_ptr);
    0
}

#[kprobe(function = "security_inode_unlink")]
pub fn p_sec_inode_unlink(ctx: KProbeContext) -> u32 {
    if unsafe { (MONITOR & MONITOR_FILE) == 0 } { return 0; }
    let dentry_arg_ptr = ctx.arg::<*mut dentry>(1).unwrap_or(core::ptr::null_mut()); // dentry is PARM2 in C
    if dentry_arg_ptr.is_null() { return 0; }
    let _ = handle_fs_event(&ctx, IndexFsEvent::IDelete, dentry_arg_ptr, core::ptr::null_mut());
    0
}

// DEBUG Helper Functions
// use core::mem; // Already added at the top

#[inline(always)]
fn debug_dump_stack(ctx: &impl BpfContext, _func_name_bytes: &[u8]) { // _func_name_bytes not used yet
    // MAX_STACK_TRACE_DEPTH is from kflowd_common (value: 16)
    let mut stack_trace_buffer = [0u64; MAX_STACK_TRACE_DEPTH]; // Array of u64 for stack addresses

    match unsafe { bpf_get_stack(ctx.as_ptr(), stack_trace_buffer.as_mut_ptr() as *mut _, (MAX_STACK_TRACE_DEPTH * mem::size_of::<u64>()) as u32 , 0) } {
        Ok(len_bytes) => {
            if len_bytes > 0 {
                // aya_log_ebpf::info!(ctx, "Stack trace captured ({} bytes) for func (name TBD)", len_bytes);
                // Logging each address or full trace is complex with aya_log_ebpf.
                // For now, this function mainly serves as a placeholder for stack trace capture.
            }
        }
        Err(_) => {
            // aya_log_ebpf::warn!(ctx, "Failed to get stack trace");
        }
    };
}

#[inline(always)]
fn debug_file_is_tp(filename_bytes: &[u8; FILENAME_LEN_MAX]) -> bool {
    const TRACE_PIPE_NAME: &[u8] = b"trace_pipe";
    const TP_LEN: usize = TRACE_PIPE_NAME.len();

    if filename_bytes.len() < TP_LEN { // Should use .get(..) for safety if FILENAME_LEN_MAX can be less than TP_LEN
        return false;
    }

    for i in 0..TP_LEN {
        if filename_bytes.get(i).map_or(true, |&c| c != TRACE_PIPE_NAME[i]) { // Check bounds and content
            return false;
        }
    }

    // Check if the match ends here (either end of filename_bytes array or null terminator)
    if filename_bytes.get(TP_LEN).map_or(true, |&c| c == 0) { // True if TP_LEN is end of array OR char at TP_LEN is null
        return true;
    }

    false
}

#[inline(always)]
fn debug_proc(comm_bytes: &[u8], current_filename_bytes: &[u8; FILENAME_LEN_MAX]) -> bool {
    let debug_filter = unsafe { &DEBUG_STR };

    if comm_bytes.is_empty() || comm_bytes[0] == 0 {
        if debug_filter.get(0) == Some(&b'q') && debug_filter.get(1).map_or(true, |&c| c == 0) {
            return true;
        } else {
            return false;
        }
    }

    if debug_filter.get(0) != Some(&b'*') {
        for i in 0..DBG_LEN_MAX {
            let filter_char = debug_filter.get(i).copied();
            if filter_char == Some(0) || filter_char == None { // End of debug_filter string
                break;
            }

            let comm_char = comm_bytes.get(i).copied();
            if comm_char == Some(0) || comm_char == None { // End of comm_bytes string
                return false; // comm_bytes is shorter than debug_filter
            }

            if comm_char != filter_char {
                return false; // Mismatch
            }
        }
    }

    if debug_file_is_tp(current_filename_bytes) {
        return false;
    }
    true
}
