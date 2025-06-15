#![no_std]
#![allow(static_mut_refs)] // Allow static mut refs for BPF maps

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

use aya_ebpf_macros::{map, kprobe, kretprobe};
use aya_ebpf::cty;
use aya_ebpf::helpers::bpf_probe_read_kernel;
// use aya_ebpf::EbpfContext as _; // Removed this unused import

// Logging macros from aya_log_ebpf
use aya_log_ebpf::{info, trace}; // trace re-added as it's used in debug_proc


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
static mut DEBUG_MSG: [u8; DBG_LEN_MAX] = [0; DBG_LEN_MAX];
// --- END: Global Variables ---

// --- START: Actual Bindings (Manual, Simplified) ---
pub mod bindings {
    #![allow(non_camel_case_types, non_snake_case)]
    #![allow(dead_code)] // Allow dead code as these are bindings

    use aya_ebpf::cty;

    // Basic type aliases based on common kernel types for x86_64
    pub type __u8 = u8;
    pub type __u16 = u16;
    pub type __u32 = u32;
    pub type __u64 = u64;
    pub type __s16 = i16;
    pub type __s32 = i32;
    pub type __s64 = i64;

    pub type umode_t = __u16;
    pub type loff_t = __s64;           // Typically signed for file offsets
    pub type kernel_ulong_t = __u64;   // unsigned long
    pub type fmode_t = __u32;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct kuid_t {
        pub val: __u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct kgid_t {
        pub val: __u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct timespec64 {
        pub tv_sec: __s64,  // time64_t (which is __s64)
        pub tv_nsec: __s64, // long (which is __s64 on x86_64)
    }

    pub type __kernel_timespec = timespec64;

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct qstr {
        pub name: *const cty::c_char, // const unsigned char*
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct dentry {
        pub d_flags: __u32,
        pub d_parent: *mut dentry,      /* parent directory */
        pub d_name: qstr,               /* dentry name */
        pub d_inode: *mut inode,        /* Where the name belongs to - Null if negative */
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct inode {
        pub i_mode: umode_t,
        pub i_opflags: __u16,
        pub i_ino: kernel_ulong_t,      // unsigned long
        pub i_nlink: __u32,             // unsigned int
        pub i_uid: kuid_t,
        pub i_gid: kgid_t,
        pub i_size: loff_t,
        pub i_atime: __kernel_timespec,
        pub i_mtime: __kernel_timespec,
        pub i_ctime: __kernel_timespec,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct path {
        pub mnt: *mut cty::c_void, // Placeholder for struct vfsmount *
        pub dentry: *mut dentry,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct file {
        pub f_path: path,
        pub f_inode: *mut inode, // struct inode * (can be NULL)
        pub f_mode: fmode_t,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct iattr {
        pub ia_valid: __u32, // unsigned int
        pub ia_mode: umode_t,
        pub ia_uid: kuid_t,
        pub ia_gid: kgid_t,
        pub ia_size: loff_t,
        pub ia_atime: __kernel_timespec,
        pub ia_mtime: __kernel_timespec,
        pub ia_ctime: __kernel_timespec,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct pt_regs {
        pub r15: __u64, pub r14: __u64, pub r13: __u64, pub r12: __u64, pub rbp: __u64, pub rbx: __u64,
        pub r11: __u64, pub r10: __u64, pub r9:  __u64, pub r8:  __u64, pub rax: __u64, pub rcx: __u64,
        pub rdx: __u64, pub rsi: __u64, pub rdi: __u64, pub orig_rax: __u64, pub rip: __u64,
        pub cs:  __u64, pub eflags: __u64, pub rsp: __u64, pub ss: __u64,
    }
}
// --- END: Actual Bindings (Manual, Simplified) ---

// --- START: Core eBPF Program Logic (handle_fs_event) ---
use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::bindings::BPF_ANY;
use crate::bindings::{self, dentry, inode}; // Added bindings prefix for clarity if needed elsewhere

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

    // Read d_inode from current_dentry_ptr
    let inode_ptr_from_dentry: *const bindings::inode = unsafe { bpf_probe_read_kernel(&(*current_dentry_ptr).d_inode)? };
    if inode_ptr_from_dentry.is_null() { return Ok(()); }

    // Read d_name.name from dentry_ptr
    let filename_src_ptr_from_dentry: *const cty::c_char = unsafe { bpf_probe_read_kernel(&(*dentry_ptr).d_name.name)? };
    if filename_src_ptr_from_dentry.is_null() { return Ok(()); } // Important check

    let mut filename_buf = [0u8; FILENAME_LEN_MAX];
    match try_read_kernel_str_bytes(filename_src_ptr_from_dentry as *const u8, &mut filename_buf) {
        Ok(0) => return Ok(()), // Empty filename
        Err(e) => return Err(e), // Error reading
        Ok(len_read) if len_read == 0 => return Ok(()), // Should be caught by Ok(0)
        Ok(_) => {} // Successfully read
    }
    if filename_buf[0] == 0 { return Ok(()); } // Double check if filename is empty after read

    // Read fields from inode_ptr_from_dentry
    let i_ino_val: bindings::kernel_ulong_t = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_ino)? };
    let ino_val: u32 = i_ino_val as u32; // Cast u64 to u32
    let imode_val: bindings::umode_t = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_mode)? };
    let i_size_val: bindings::loff_t = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_size)? };
    let isize_val: u64 = if i_size_val < 0 { 0 } else { i_size_val as u64 }; // Ensure positive for u64 record field
    let inlink_val: u32 = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_nlink)? };

    let i_atime: bindings::__kernel_timespec = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_atime)? };
    let atime_sec_val: u64 = i_atime.tv_sec as u64;
    let atime_nsec_val: u64 = i_atime.tv_nsec as u64;

    let i_mtime: bindings::__kernel_timespec = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_mtime)? };
    let mtime_sec_val: u64 = i_mtime.tv_sec as u64;
    let mtime_nsec_val: u64 = i_mtime.tv_nsec as u64;

    let i_ctime: bindings::__kernel_timespec = unsafe { bpf_probe_read_kernel(&(*inode_ptr_from_dentry).i_ctime)? };
    let ctime_sec_val: u64 = i_ctime.tv_sec as u64;
    let ctime_nsec_val: u64 = i_ctime.tv_nsec as u64;

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
        // r_existing.rc.ts not updated with current time
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
            // r_current.rc.ts not updated with current time
            r_current.ino = ino_val;
            unsafe { r_current.names.filename.copy_from_slice(&filename_buf) };
            r_current.isize_first = isize_val;

            // Initialize filepath and begin constructing it
            r_current.filepath = [0u8; FILEPATH_LEN_MAX];
            let mut current_filepath_offset: usize = 0;
            let mut path_nodes: [[u8; FILENAME_LEN_MAX]; FILEPATH_NODE_MAX] = [[0; FILENAME_LEN_MAX]; FILEPATH_NODE_MAX];
            let mut path_nodes_count: usize = 0;
            let mut dentry_iter_ptr = dentry_ptr; // Start with the current event's dentry

            for _ in 0..FILEPATH_NODE_MAX {
                if dentry_iter_ptr.is_null() { break; }

                let d_name_qstr: bindings::qstr = unsafe { bpf_probe_read_kernel(&(*dentry_iter_ptr).d_name)? };
                let name_char_ptr: *const cty::c_char = unsafe { bpf_probe_read_kernel(&d_name_qstr.name)? };
                if name_char_ptr.is_null() { break; }

                let mut temp_name_buf = [0u8; FILENAME_LEN_MAX];
                let name_len = match try_read_kernel_str_bytes(name_char_ptr as *const u8, &mut temp_name_buf) {
                    Ok(len) if len > 0 && len < FILENAME_LEN_MAX => len,
                    _ => 0, // Error or empty name
                };

                if name_len > 0 {
                    if path_nodes_count < FILEPATH_NODE_MAX {
                        path_nodes[path_nodes_count][..name_len].copy_from_slice(&temp_name_buf[..name_len]);
                        path_nodes_count = path_nodes_count.saturating_add(1);
                    } else {
                        // Max path components reached, might indicate very deep path or issue
                        break;
                    }
                } else if path_nodes_count == 0 && name_len == 0 {
                    // If the first component is empty (e.g. root "/"), store it.
                     if path_nodes_count < FILEPATH_NODE_MAX { // Should always be true here
                        path_nodes[path_nodes_count][0] = b'/'; // Store '/'
                        path_nodes_count = path_nodes_count.saturating_add(1);
                    }
                }


                let parent_dentry_ptr: *const bindings::dentry = unsafe { bpf_probe_read_kernel(&(*dentry_iter_ptr).d_parent)? };
                if parent_dentry_ptr.is_null() { break; }

                // Check for root or mount point: if dentry_iter_ptr == parent_dentry_ptr
                if dentry_iter_ptr == parent_dentry_ptr {
                    // If it's the root and we haven't added anything or last added was not already "/", add "/"
                    if path_nodes_count == 0 || (path_nodes_count > 0 && path_nodes[path_nodes_count-1][0] != b'/') {
                        if path_nodes_count < FILEPATH_NODE_MAX {
                            // Ensure we don't overwrite a valid name if path_nodes_count > 0
                            if path_nodes_count > 0 && name_len == 0 { // Current dentry is root, name is "/"
                                // It was already handled by name_len == 0 logic for root.
                            } else if name_len > 0 { // Current dentry is not root, but its parent is itself. Add current name then "/"
                                // This case should have added the name already. Now ensure a "/" is the last component if needed.
                                // This logic is tricky, the C version adds "/" if current is not "/" and parent is self.
                                // If the current name was not "/" and parent is self, it implies mount point.
                                // The existing name is already in path_nodes. We might need a trailing "/" if it's a directory.
                                // For simplicity here, if we hit root (dentry == parent), we stop.
                                // The C code adds a "/" if the last component is not already "/".
                            } else { // name_len == 0, dentry == parent.
                                path_nodes[path_nodes_count][0] = b'/';
                                path_nodes_count = path_nodes_count.saturating_add(1);
                            }
                        }
                    }
                    break;
                }
                dentry_iter_ptr = parent_dentry_ptr;
            }

            // Assemble the filepath in forward order
            // Add "/" if path is empty and we stored it due to root.
            if path_nodes_count == 1 && path_nodes[0][0] == b'/' && path_nodes[0][1] == 0 {
                 if current_filepath_offset < FILEPATH_LEN_MAX -1 {
                    r_current.filepath[current_filepath_offset] = b'/';
                    current_filepath_offset = current_filepath_offset.saturating_add(1);
                 }
            } else {
                for i in (0..path_nodes_count).rev() {
                    // Add leading '/' if not the first component and not already root, and filepath is not empty
                    if current_filepath_offset > 0 || (i < path_nodes_count -1 ) {
                         if current_filepath_offset < FILEPATH_LEN_MAX - 1 {
                            r_current.filepath[current_filepath_offset] = b'/';
                            current_filepath_offset = current_filepath_offset.saturating_add(1);
                        } else { break; } // Path too long
                    } else if path_nodes_count > 1 && i == path_nodes_count -1 && path_nodes[i][0] != b'/' {
                        // If it's the very first component of a multi-segment path, it might need a leading '/'
                        // This case handles if the traversal stopped before explicit root but implies it.
                        // For example, if FILEPATH_NODE_MAX is hit.
                        // The C code prepends "/" if the full path doesn't start with one.
                        // This is complex to get right here. A simple approach:
                        // If the very first component to be added is not "/", add a "/"
                        if path_nodes[i][0] != b'/' && current_filepath_offset == 0 {
                             if current_filepath_offset < FILEPATH_LEN_MAX - 1 {
                                r_current.filepath[current_filepath_offset] = b'/';
                                current_filepath_offset = current_filepath_offset.saturating_add(1);
                            } else { break; }
                        }
                    }


                    let component = &path_nodes[i];
                    let mut component_len = 0;
                    while component_len < FILENAME_LEN_MAX && component[component_len] != 0 {
                        component_len = component_len.saturating_add(1);
                    }

                    if component_len == 1 && component[0] == b'/' && current_filepath_offset > 0 && r_current.filepath[current_filepath_offset-1] == b'/' {
                        // Avoid double '/' if previous char was '/' and current component is just '/'
                    } else if current_filepath_offset < FILEPATH_LEN_MAX - component_len {
                        r_current.filepath[current_filepath_offset..current_filepath_offset.saturating_add(component_len)].copy_from_slice(&component[..component_len]);
                        current_filepath_offset = current_filepath_offset.saturating_add(component_len);
                    } else {
                        // Not enough space for this component, copy what fits
                        let available_space = FILEPATH_LEN_MAX.saturating_sub(current_filepath_offset).saturating_sub(1); // -1 for null terminator
                        if available_space > 0 {
                             r_current.filepath[current_filepath_offset..current_filepath_offset.saturating_add(available_space)].copy_from_slice(&component[..available_space]);
                             current_filepath_offset = current_filepath_offset.saturating_add(available_space);
                        }
                        break;
                    }
                }
            }
            // Ensure null termination if space allows
            if current_filepath_offset < FILEPATH_LEN_MAX {
                r_current.filepath[current_filepath_offset] = 0;
            } else if FILEPATH_LEN_MAX > 0 {
                r_current.filepath[FILEPATH_LEN_MAX - 1] = 0; // Truncate and null terminate
            }


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
    // Option 1: Use ctx.ret() - preferred if available and works.
    // let filp_ptr = ctx.ret().ok_or(1i64)? as *const bindings::file;
    // Option 2: Fallback to regs if ctx.ret() is problematic or not available.
    let filp_ptr = unsafe { (*ctx.regs).rax as *const bindings::file };
    if filp_ptr.is_null() { return Ok(0); }

    let f_mode_val: bindings::fmode_t = unsafe { bpf_probe_read_kernel(&(*filp_ptr).f_mode)? };
    let f_path_dentry_ptr: *const bindings::dentry = unsafe { bpf_probe_read_kernel(&(*filp_ptr).f_path.dentry)? };

    if f_path_dentry_ptr.is_null() { return Ok(0); } // Check dentry pointer

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
    if dentry_ptr_arg.is_null() { return Ok(0); } // Check dentry_ptr_arg

    if unsafe { DENTRY_SYMLINK_TEMP.is_null() || DENTRY_SYMLINK_TEMP != dentry_ptr_arg } { return Ok(0); }

    let inode_ptr: *const bindings::inode = unsafe { bpf_probe_read_kernel(&(*dentry_ptr_arg).d_inode)? };
    if inode_ptr.is_null() { return Ok(0); }

    let imode_val: bindings::umode_t = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_mode)? };
    let i_ino_val: bindings::kernel_ulong_t = unsafe { bpf_probe_read_kernel(&(*inode_ptr).i_ino)? };
    let ino_val: u32 = i_ino_val as u32;

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
    // The context argument for iattr should be *const bindings::iattr
    let iattr_ptr = ctx.arg::<*const bindings::iattr>(1).ok_or(1i64)?;
    if iattr_ptr.is_null() { return Ok(0); } // Check iattr_ptr

    let ia_valid_val: u32 = unsafe { bpf_probe_read_kernel(&(*iattr_ptr).ia_valid)? };

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
    if old_dentry_ptr.is_null() { return Ok(0); } // Check old_dentry_ptr
    let new_dentry_ptr = ctx.arg::<*const bindings::dentry>(3).ok_or(1i64)?;
    // new_dentry_ptr can be null in some cases, proceed if it is, handle_fs_event will check.

    let d_flags_val: u32 = unsafe { bpf_probe_read_kernel(&(*old_dentry_ptr).d_flags)? };

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
    // dentry_ptr can be null in some cases, handle_fs_event will check.
    let event_info = FsEventInfo { index: IndexFsEvent::IDelete, dentry: dentry_ptr as *const cty::c_void, dentry_old: core::ptr::null(), func_name: b"security_inode_unlink\0".as_ptr() as *const cty::c_char, };
    handle_fs_event(&event_info)?; Ok(0)
}
// --- END: Kprobe Definitions ---

// --- START: Debugging Utilities ---
// use aya_ebpf::helpers::bpf_get_stack; // Already imported at top of kprobe section //This was a mistake, bpf_get_stack is not imported at top of kprobe section

static mut DEBUG_STACK_BUF: [u64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[allow(dead_code)]
fn debug_dump_stack<C: aya_ebpf::EbpfContext>(ctx: &C, func_name_for_log: &str) { // Corrected to EbpfContext
    let kstacklen = unsafe {
        bpf_get_stack(
            ctx.as_ptr(),
            DEBUG_STACK_BUF.as_mut_ptr() as *mut cty::c_void,
            (MAX_STACK_TRACE_DEPTH * core::mem::size_of::<u64>()) as u32,
            0,
        )
    };

    if kstacklen > 0 {
        info!(ctx, "KERNEL STACK ({} bytes) for {}:",
            kstacklen,
            func_name_for_log
        );
        let num_frames = kstacklen as usize / core::mem::size_of::<u64>();
        for i in 0..num_frames {
            if i < MAX_STACK_TRACE_DEPTH {
                info!(ctx, "  #{} 0x{:x}", i, unsafe { DEBUG_STACK_BUF[i] });
            } else {
                break;
            }
        }
    } else {
        info!(ctx, "debug_dump_stack for {}: bpf_get_stack error or empty: {}", func_name_for_log, kstacklen);
    }
}

#[allow(dead_code)]
fn debug_file_is_tp(filename_bytes: &[u8]) -> bool {
    const TRACE_PIPE_NAME: &[u8] = b"trace_pipe";
    let len = filename_bytes.iter().position(|&b| b == 0).unwrap_or(filename_bytes.len());
    let name_slice = &filename_bytes[..len];
    name_slice == TRACE_PIPE_NAME
}

#[allow(dead_code)]
fn debug_proc<C: aya_ebpf::EbpfContext>(ctx: &C, filename_bytes: &[u8]) -> bool { // Corrected to EbpfContext
    let comm_array = match aya_ebpf::helpers::bpf_get_current_comm() {
        Ok(comm) => comm,
        Err(_) => {
            trace!(ctx, "debug_proc: failed to get current_comm");
            return true;
        }
    };
    let comm_len = comm_array.iter().position(|&b| b == 0).unwrap_or(comm_array.len());
    let comm_slice = &comm_array[..comm_len];

    let debug_filter_full = unsafe { &DEBUG_MSG[..] };
    let debug_filter_len = debug_filter_full.iter().position(|&b| b == 0).unwrap_or(DBG_LEN_MAX);
    let debug_filter = &debug_filter_full[..debug_filter_len];

    if comm_slice.is_empty() {
        return debug_filter == b"q";
    }

    if !debug_filter.is_empty() && debug_filter[0] != b'*' {
        if !comm_slice.starts_with(debug_filter) {
            return false;
        }
    }

    if debug_file_is_tp(filename_bytes) {
        return false;
    }
    true
}
// --- END: Debugging Utilities ---

// Example of how aya-gen might be invoked (as a comment, not executed):
// aya-gen generate --header vmlinux/x86/vmlinux.h --target-arch x86_64 > src/rust_bpf_program/src/bindings.rs
// Or, if BTF is available on the system:
// aya_gen generate --btf /sys/kernel/btf/vmlinux > src/bindings.rs


#[allow(dead_code)]
fn placeholder_bpf_func() {}

```
