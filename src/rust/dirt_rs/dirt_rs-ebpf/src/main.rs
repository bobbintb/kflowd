#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, BPF_F_CURRENT_CPU},
    macros::{map, kprobe, kretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes},
};
// use core::ffi::c_void; // Not needed if bpf_probe_read_kernel_str_bytes takes *const u8

// Import common types
use dirt_rs_common::*;

// Helper to create [u8; N] from a byte string literal, truncating/padding.
#[inline(always)]
fn str_to_byte_array<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut arr = [0u8; N];
    let len = s.len().min(N);
    arr[..len].copy_from_slice(&s[..len]);
    arr
}

// Basic kernel structure definitions (placeholders, need CO-RE)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qstr {
    pub name: *const u8,
    pub len: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dentry {
    pub d_parent: *mut dentry,
    pub d_name: qstr,
    pub d_inode: *mut inode,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inode {
    pub i_mode: u16,
    pub i_ino: u64,
    pub i_uid: u32,
    pub i_gid: u32,
    pub i_nlink: u32,
    pub i_size: i64,
    pub i_atime_sec: i64,
    pub i_atime_nsec: u32,
    pub i_mtime_sec: i64,
    pub i_mtime_nsec: u32,
    pub i_ctime_sec: i64,
    pub i_ctime_nsec: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct file {
    pub f_path_dentry: *mut dentry,
    pub f_inode: *mut inode,
}

// eBPF Maps
#[map]
pub static mut ringbuf_records: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
pub static mut hash_records: HashMap<u64, RECORD_FS> = HashMap::with_max_entries(MAP_RECORDS_MAX as u32, 0);

#[map]
pub static mut heap_record_fs: PerCpuArray<RECORD_FS> = PerCpuArray::with_max_entries(1, BPF_F_CURRENT_CPU as u32);

#[map]
pub static mut stats_map: Array<STATS> = Array::with_max_entries(1, 0);

#[map]
pub static mut CONFIG_MAP: Array<ProgConfig> = Array::with_max_entries(1, 0);

#[map]
pub static mut SYMLINK_DENTRIES_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

pub static FSEVT: [FsEvent; FS_EVENT_MAX] = [
    FsEvent { index: INDEX_FS_EVENT::I_CREATE as u16, value: FS_CREATE, name: *b"CREATE          ", shortname: *b"CRE ", shortname2: *b"CR  " },
    FsEvent { index: INDEX_FS_EVENT::I_OPEN as u16, value: FS_OPEN, name: *b"OPEN            ", shortname: *b"OPN ", shortname2: *b"OP  " },
    FsEvent { index: INDEX_FS_EVENT::I_OPEN_EXEC as u16, value: FS_OPEN_EXEC, name: *b"OPEN_EXEC       ", shortname: *b"OPX ", shortname2: *b"OX  " },
    FsEvent { index: INDEX_FS_EVENT::I_ACCESS as u16, value: FS_ACCESS, name: *b"ACCESS          ", shortname: *b"ACC ", shortname2: *b"AC  " },
    FsEvent { index: INDEX_FS_EVENT::I_ATTRIB as u16, value: FS_ATTRIB, name: *b"ATTRIB          ", shortname: *b"ATT ", shortname2: *b"AT  " },
    FsEvent { index: INDEX_FS_EVENT::I_MODIFY as u16, value: FS_MODIFY, name: *b"MODIFY          ", shortname: *b"MOD ", shortname2: *b"MO  " },
    FsEvent { index: INDEX_FS_EVENT::I_CLOSE_WRITE as u16, value: FS_CLOSE_WRITE, name: *b"CLOSE_WRITE     ", shortname: *b"CLW ", shortname2: *b"CW  " },
    FsEvent { index: INDEX_FS_EVENT::I_CLOSE_NOWRITE as u16, value: FS_CLOSE_NOWRITE, name: *b"CLOSE_NOWRITE   ", shortname: *b"CLN ", shortname2: *b"CN  " },
    FsEvent { index: INDEX_FS_EVENT::I_MOVED_FROM as u16, value: FS_MOVED_FROM, name: *b"MOVED_FROM      ", shortname: *b"MVF ", shortname2: *b"MF  " },
    FsEvent { index: INDEX_FS_EVENT::I_MOVED_TO as u16, value: FS_MOVED_TO, name: *b"MOVED_TO        ", shortname: *b"MVT ", shortname2: *b"MT  " },
    FsEvent { index: INDEX_FS_EVENT::I_DELETE as u16, value: FS_DELETE, name: *b"DELETE          ", shortname: *b"DEL ", shortname2: *b"DE  " },
    FsEvent { index: INDEX_FS_EVENT::I_DELETE_SELF as u16, value: FS_DELETE_SELF, name: *b"DELETE_SELF     ", shortname: *b"DSF ", shortname2: *b"DS  " },
    FsEvent { index: INDEX_FS_EVENT::I_MOVE_SELF as u16, value: FS_MOVE_SELF, name: *b"MOVE_SELF       ", shortname: *b"MSF ", shortname2: *b"MS  " },
    FsEvent { index: INDEX_FS_EVENT::I_UNMOUNT as u16, value: FS_UNMOUNT, name: *b"UNMOUNT         ", shortname: *b"UNM ", shortname2: *b"UM  " },
    FsEvent { index: INDEX_FS_EVENT::I_Q_OVERFLOW as u16, value: FS_Q_OVERFLOW, name: *b"Q_OVERFLOW      ", shortname: *b"QOF ", shortname2: *b"QO  " },
];

// Define error codes locally if not in common, or use a common error enum.
// const EBPF_READ_STR_ERR: i64 = -1; // Example, replace with actual error handling strategy

#[inline(always)]
fn handle_fs_event(ctx: &ProbeContext, event_info: &mut FS_EVENT_INFO) -> Result<(), i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };

    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;

    if pid == config.pid_self || pid == config.pid_shell {
        return Ok(());
    }

    let dentry_ptr = event_info.dentry as *const dentry;
    if dentry_ptr.is_null() { return Err(2); }

    let d_entry: dentry = unsafe { ctx.read(dentry_ptr)? };
    let i_node_ptr = d_entry.d_inode;
    if i_node_ptr.is_null() { return Err(5); }
    let i_node: inode = unsafe { ctx.read(i_node_ptr)? };

    let key = i_node.i_ino;
    let current_event_flag = FSEVT.get(event_info.index as usize).map_or(0, |e| e.value);
    if current_event_flag == 0 { return Err(6); }

    let mut send_now = false;
    let mut is_rename_event = false;
    if current_event_flag == FS_MOVED_FROM || current_event_flag == FS_MOVED_TO || current_event_flag == FS_DELETE {
        send_now = true;
        if current_event_flag == FS_MOVED_FROM || current_event_flag == FS_MOVED_TO {
            is_rename_event = true;
        }
    }

    let mut record_fs_entry: RECORD_FS = if let Some(existing_record) = unsafe { hash_records.get(&key) } {
        *existing_record
    } else {
        let new_record_template_ptr = unsafe { heap_record_fs.get_ptr_mut(0).ok_or(3i64)? };
        if new_record_template_ptr.is_null() { return Err(3); }
        let new_record_template = unsafe { &mut *new_record_template_ptr };
        *new_record_template = Default::default();

        new_record_template.rc.type_ = RECORD_TYPE_FILE;
        new_record_template.rc.ts = unsafe { bpf_ktime_get_ns() };
        new_record_template.ino = i_node.i_ino as u32;
        new_record_template.imode = i_node.i_mode as u32;
        new_record_template.inlink = i_node.i_nlink;
        new_record_template.isize = i_node.i_size as u64;
        new_record_template.isize_first = i_node.i_size as u64;
        new_record_template.atime_nsec = (i_node.i_atime_sec as u64 * 1_000_000_000) + i_node.i_atime_nsec as u64;
        new_record_template.mtime_nsec = (i_node.i_mtime_sec as u64 * 1_000_000_000) + i_node.i_mtime_nsec as u64;
        new_record_template.ctime_nsec = (i_node.i_ctime_sec as u64 * 1_000_000_000) + i_node.i_ctime_nsec as u64;

        let q_str: qstr = unsafe { ctx.read(&d_entry.d_name as *const qstr)? };
        let name_len = q_str.len as usize;
        if name_len > 0 && !q_str.name.is_null() {
            let len_to_copy = name_len.min(FILENAME_LEN_MAX -1);
            let mut target_buf = [0u8; FILENAME_LEN_MAX];
            match unsafe { bpf_probe_read_kernel_str_bytes(q_str.name as *const u8, &mut target_buf[..len_to_copy]) } {
                Ok(_) => { new_record_template.name_union.filename[..len_to_copy].copy_from_slice(&target_buf[..len_to_copy]); }
                Err(_) => { let _ = 0; /* No-op for error */ }
            }
        }

        if !d_entry.d_parent.is_null() {
            let parent_d_entry: dentry = unsafe { ctx.read(d_entry.d_parent)? };
            let parent_q_str: qstr = unsafe { ctx.read(&parent_d_entry.d_name as *const qstr)? };
            let parent_name_len = parent_q_str.len as usize;

            if parent_name_len > 0 && !parent_q_str.name.is_null() {
                let mut temp_parent_name_buf = [0u8; FILEPATH_LEN_MAX];
                let len_to_copy_parent = parent_name_len.min(FILEPATH_LEN_MAX -1);
                match unsafe { bpf_probe_read_kernel_str_bytes(
                    parent_q_str.name as *const u8,
                    &mut temp_parent_name_buf[..len_to_copy_parent]
                ) }{
                    Ok(_) => {
                        let mut current_path_len = 0;
                        for i in 0..len_to_copy_parent {
                            if current_path_len < FILEPATH_LEN_MAX -1 {
                                new_record_template.filepath[current_path_len] = temp_parent_name_buf[i];
                                current_path_len += 1;
                            } else { break; }
                        }
                        if current_path_len < FILEPATH_LEN_MAX -1 {
                            new_record_template.filepath[current_path_len] = b'/';
                            current_path_len += 1;
                        }
                        let filename_part_len = name_len.min(FILENAME_LEN_MAX-1);
                        for i in 0..filename_part_len {
                             if current_path_len < FILEPATH_LEN_MAX -1 {
                                new_record_template.filepath[current_path_len] = new_record_template.name_union.filename[i];
                                current_path_len +=1;
                             } else { break; }
                        }
                    }
                    Err(_) => { let _ = 0; /* No-op for error */ }
                }
            } else if name_len > 0 {
                 for i in 0..name_len.min(FILEPATH_LEN_MAX-1) {
                    new_record_template.filepath[i] = new_record_template.name_union.filename[i];
                 }
            }
        }
        *new_record_template
    };

    let mut event_count = 0;
    for i in 0..FS_EVENT_MAX {
        if record_fs_entry.event[i] == 0 {
            record_fs_entry.event[i] = current_event_flag;
            event_count = i + 1;
            break;
        }
        if record_fs_entry.event[i] == current_event_flag {
            event_count = i + 1;
            break;
        }
    }
    record_fs_entry.events = event_count as u32;

    if is_rename_event {
        if event_info.dentry_old != 0 {
            let other_dentry_ptr = event_info.dentry_old as *const dentry;
            let other_d_entry: dentry = unsafe { ctx.read(other_dentry_ptr)? };
            let other_q_str: qstr = unsafe { ctx.read(&other_d_entry.d_name as *const qstr)? };
            let mut other_filename_buf = [0u8; FILENAME_LEN_MAX / 2];
            let other_name_len = other_q_str.len as usize;

            if other_name_len > 0 && !other_q_str.name.is_null() {
                let len_to_copy = other_name_len.min((FILENAME_LEN_MAX / 2) -1);
                match unsafe { bpf_probe_read_kernel_str_bytes(
                    other_q_str.name as *const u8,
                    &mut other_filename_buf[..len_to_copy]
                )} {
                    Ok(_) => {},
                    Err(_) => { let _ = 0; /* No-op for error */ }
                }
            }

            let mut current_filename_backup = [0u8; FILENAME_LEN_MAX];
            current_filename_backup.copy_from_slice(unsafe{ &record_fs_entry.name_union.filename });

            if current_event_flag == FS_MOVED_FROM {
                record_fs_entry.name_union.filenames.filename_from[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&current_filename_backup[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]);
                record_fs_entry.name_union.filenames.filename_to[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&other_filename_buf[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]);
            } else {
                record_fs_entry.name_union.filenames.filename_from[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&other_filename_buf[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]);
                record_fs_entry.name_union.filenames.filename_to[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&current_filename_backup[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]);
            }
        }
    }

    if send_now || event_count >= config.agg_events_max as usize || event_count >= FS_EVENT_MAX {
        unsafe { ringbuf_records.output(&record_fs_entry, 0)? };
        unsafe { hash_records.remove(&key)? };

        let stats_ptr = unsafe { stats_map.get_ptr_mut(0).ok_or(4i64)? };
        if stats_ptr.is_null() { return Err(4); }
        let stats = unsafe { &mut *stats_ptr };
        stats.fs_records += 1;
        stats.fs_events += event_count as u64;
        if event_count >= config.agg_events_max as usize {
            stats.fs_records_deleted +=1;
        }
    } else {
        unsafe { hash_records.insert(&key, &record_fs_entry, 0)? };
    }

    Ok(())
}

macro_rules! kprobe_impl {
    ($fn_name:ident, $try_fn_name:ident, $func_to_probe:expr) => {
        #[kprobe(name = $func_to_probe)]
        pub fn $fn_name(ctx: ProbeContext) -> u32 {
            match $try_fn_name(ctx) {
                Ok(ret) => ret,
                Err(ret) => ret as u32,
            }
        }
    };
}

macro_rules! kretprobe_impl {
    ($fn_name:ident, $try_fn_name:ident, $func_to_probe:expr) => {
        #[kretprobe(name = $func_to_probe)]
        pub fn $fn_name(ctx: ProbeContext) -> u32 {
            match $try_fn_name(ctx) {
                Ok(ret) => ret,
                Err(ret) => ret as u32,
            }
        }
    };
}

fn try_do_filp_open(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 {
        return Ok(TC_ACT_OK as u32);
    }

    let file_ptr = ctx.ret::<*mut file>().ok_or(1i64)?; // Use ctx.ret() for kretprobes
    if file_ptr.is_null() {
        return Ok(TC_ACT_OK as u32);
    }

    let kernel_file: file = unsafe { ctx.read(file_ptr)? };
    let dentry_ptr = kernel_file.f_path_dentry;

    if dentry_ptr.is_null() {
        return Ok(TC_ACT_OK as u32);
    }

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_OPEN as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"do_filp_open"),
    };

    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kretprobe_impl!(do_filp_open_kretprobe, try_do_filp_open, "do_filp_open");

fn try_security_inode_link(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }
    let old_dentry_ptr = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*mut dentry>(2).ok_or(1i64)?;
    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_CREATE as i32,
        dentry: new_dentry_ptr as u64,
        dentry_old: old_dentry_ptr as u64,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"security_inode_link"),
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(security_inode_link_kprobe, try_security_inode_link, "security_inode_link");

fn try_security_inode_symlink(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }
    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    unsafe { SYMLINK_DENTRIES_MAP.insert(&pid, &(dentry_ptr as u64), 0)? };

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_CREATE as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"security_inode_symlink"),
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(security_inode_symlink_kprobe, try_security_inode_symlink, "security_inode_symlink");

fn try_dput(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }

    let dentry_ptr_arg = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;

    if let Some(saved_dentry_ptr) = unsafe { SYMLINK_DENTRIES_MAP.get(&pid) } {
        if *saved_dentry_ptr == (dentry_ptr_arg as u64) {
            unsafe { SYMLINK_DENTRIES_MAP.remove(&pid)? };
        }
    }
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(dput_kprobe, try_dput, "dput");

fn try_notify_change(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }
    let dentry_ptr = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_ATTRIB as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"notify_change"),
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(notify_change_kprobe, try_notify_change, "notify_change");

const FS_CREATE_FLAG_MASK_FOR_FSNOTIFY: u32 = FS_CREATE;
const FS_DELETE_FLAG_MASK_FOR_FSNOTIFY: u32 = FS_DELETE;
fn try_fsnotify_parent(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }

    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;
    let mask = ctx.arg::<u32>(2).ok_or(1i64)?;

    let event_idx = match mask {
        m if (m & FS_CREATE_FLAG_MASK_FOR_FSNOTIFY) != 0 => INDEX_FS_EVENT::I_CREATE,
        m if (m & FS_DELETE_FLAG_MASK_FOR_FSNOTIFY) != 0 => INDEX_FS_EVENT::I_DELETE,
        _ => return Ok(TC_ACT_OK as u32),
    };

    let mut event_info = FS_EVENT_INFO {
        index: event_idx as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"__fsnotify_parent"),
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(fsnotify_parent_kprobe, try_fsnotify_parent, "__fsnotify_parent");

fn try_security_inode_rename(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }
    let old_dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*mut dentry>(3).ok_or(1i64)?;

    let mut event_info_from = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_MOVED_FROM as i32,
        dentry: old_dentry_ptr as u64,
        dentry_old: new_dentry_ptr as u64,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"security_inode_rename_from"),
    };
    handle_fs_event(&ctx, &mut event_info_from)?;

    let mut event_info_to = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_MOVED_TO as i32,
        dentry: new_dentry_ptr as u64,
        dentry_old: old_dentry_ptr as u64,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"security_inode_rename_to"),
    };
    handle_fs_event(&ctx, &mut event_info_to)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(security_inode_rename_kprobe, try_security_inode_rename, "security_inode_rename");

fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK as u32); }
    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_DELETE as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: str_to_byte_array::<PROG_NAME_MAX>(b"security_inode_unlink"),
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK as u32)
}
kprobe_impl!(security_inode_unlink_kprobe, try_security_inode_unlink, "security_inode_unlink");

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
