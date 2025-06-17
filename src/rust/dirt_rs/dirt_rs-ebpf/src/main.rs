#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{map, kprobe, kretprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str},
    EbpfContext,
};
use core::mem;
use core::ffi::c_void;

// Import common types
use dirt_rs_common::*;

// Basic kernel structure definitions for CO-RE (highly simplified, needs real offsets)
// These are placeholders and would typically come from aya_ebpf_bindings or generated via bpftool
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qstr {
    pub name: *const u8,
    pub len: u32,
    // other fields
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct dentry {
    pub d_parent: *mut dentry,
    pub d_name: qstr,
    pub d_inode: *mut inode,
    // other fields
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct inode {
    pub i_mode: u16,
    pub i_ino: u64, // u32 or u64 depending on kernel version / config
    pub i_uid: u32, // kuid_t typically u32
    pub i_gid: u32, // kgid_t typically u32
    pub i_nlink: u32,
    pub i_size: i64,
    pub i_atime_sec: i64, // __kernel_old_time_t or timespec64
    pub i_atime_nsec: u32,
    pub i_mtime_sec: i64,
    pub i_mtime_nsec: u32,
    pub i_ctime_sec: i64,
    pub i_ctime_nsec: u32,
    // other fields
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct file {
    pub f_path_dentry: *mut dentry, // struct path path; path.dentry
    pub f_inode: *mut inode,
    // other fields
}


// eBPF Maps
#[map]
pub static mut ringbuf_records: RingBuf = RingBuf::with_max_entries(MAP_RECORDS_MAX as u32, 0);

#[map]
pub static mut hash_records: HashMap<u64, RECORD_FS> = HashMap::with_max_entries(MAP_RECORDS_MAX as u32, 0);

#[map]
pub static mut heap_record_fs: PerCpuArray<RECORD_FS> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut stats_map: Array<STATS> = Array::with_max_entries(1, 0); // Renamed from stats to stats_map

#[map]
pub static mut CONFIG_MAP: Array<ProgConfig> = Array::with_max_entries(1, 0);

// Temporary map for passing symlink dentry pointer from symlink creation to dput
// Key: pid (u32), Value: dentry_ptr (u64)
#[map]
pub static mut SYMLINK_DENTRIES_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);


// Based on fsevt from dirt.h
// Ensure FS_EVENT_MAX in common.rs matches the count here (15)
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


// Main event handling function
#[inline(always)]
fn handle_fs_event(ctx: &ProbeContext, event_info: &mut FS_EVENT_INFO) -> Result<(), i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };

    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    let tid = id as u32;

    if pid == config.pid_self || pid == config.pid_shell {
        return Ok(());
    }

    let dentry_ptr = event_info.dentry as *const dentry;
    if dentry_ptr.is_null() {
        return Err(2); // Null dentry pointer
    }

    let d_entry: dentry = unsafe { ctx.read_at(dentry_ptr)? };
    let i_node_ptr = d_entry.d_inode;
    if i_node_ptr.is_null() {
        return Err(5); // Null inode pointer
    }
    let i_node: inode = unsafe { ctx.read_at(i_node_ptr)? };

    // Use inode number as key for aggregation. This might need to include device id for uniqueness across filesystems.
    // For simplicity, using i_node.i_ino (assuming it's unique enough for this context).
    // In C, KEY_PID_INO was used, which combined pid and ino. Let's use ino for now.
    let key = i_node.i_ino;

    let current_event_flag = FSEVT
        .get(event_info.index as usize)
        .map_or(0, |e| e.value);
    if current_event_flag == 0 {
        return Err(6); // Invalid event index
    }

    let mut send_now = false;
    let mut is_rename_event = false;

    if current_event_flag == FS_MOVED_FROM || current_event_flag == FS_MOVED_TO || current_event_flag == FS_DELETE {
        send_now = true; // These events trigger immediate send of existing record if any
        if current_event_flag == FS_MOVED_FROM || current_event_flag == FS_MOVED_TO {
            is_rename_event = true;
        }
    }

    // Try to get existing record for aggregation
    let mut record_fs_entry: RECORD_FS = if let Some(existing_record) = unsafe { hash_records.get(&key) } {
        *existing_record // Make a copy to modify
    } else {
        // No existing record, create a new one from per-CPU heap
        let new_record_template = unsafe { heap_record_fs.get_mut(0).ok_or(3i64)? };
        *new_record_template = Default::default(); // Clear/reset it before use

        new_record_template.rc.type_ = RECORD_TYPE_FILE;
        new_record_template.rc.ts = unsafe { bpf_ktime_get_ns() };
        new_record_template.ino = i_node.i_ino as u32; // Assuming i_ino fits u32, adjust if needed
        new_record_template.imode = i_node.i_mode as u32;
        new_record_template.inlink = i_node.i_nlink;
        new_record_template.isize = i_node.i_size as u64;
        new_record_template.isize_first = i_node.i_size as u64;
        // Timestamps - Placeholder, direct read might not be timespec64
        new_record_template.atime_nsec = (i_node.i_atime_sec as u64 * 1_000_000_000) + i_node.i_atime_nsec as u64;
        new_record_template.mtime_nsec = (i_node.i_mtime_sec as u64 * 1_000_000_000) + i_node.i_mtime_nsec as u64;
        new_record_template.ctime_nsec = (i_node.i_ctime_sec as u64 * 1_000_000_000) + i_node.i_ctime_nsec as u64;

        // TODO: Filepath construction logic would go here.
        // For now, filepath will be empty or just the filename.
        // build_filepath(ctx, dentry_ptr, &mut new_record_template.filepath)?;

        // Read filename
        let q_str: qstr = unsafe { ctx.read_at(&d_entry.d_name as *const qstr)? };
        let name_len = q_str.len as usize;
        if name_len > 0 && !q_str.name.is_null() {
            let len_to_copy = name_len.min(FILENAME_LEN_MAX -1);
             unsafe {
                // This needs proper bpf_probe_read_kernel_str or equivalent safe read
                // For now, assuming direct read for placeholder structure.
                unsafe {
                    if bpf_probe_read_kernel_str(
                        q_str.name as *const c_void,
                        &mut new_record_template.name_union.filename as *mut _ as *mut u8,
                        len_to_copy as u32 + 1, // +1 for potential null terminator if q_str.name is null terminated
                    ).is_err() {
                        // Handle error or leave filename empty
                    }
                }
            }
        }

        // Attempt to build a simplified filepath (first component only for now)
        // A full implementation would loop d_parent.
        if !d_entry.d_parent.is_null() {
            let parent_d_entry: dentry = unsafe { ctx.read_at(d_entry.d_parent)? };
            let parent_q_str: qstr = unsafe { ctx.read_at(&parent_d_entry.d_name as *const qstr)? };
            let parent_name_len = parent_q_str.len as usize;

            if parent_name_len > 0 && !parent_q_str.name.is_null() {
                let mut temp_parent_name = [0u8; FILEPATH_LEN_MAX]; // Using FILEPATH_LEN_MAX temporarily
                let len_to_copy_parent = parent_name_len.min(FILEPATH_LEN_MAX -1);
                unsafe {
                     if bpf_probe_read_kernel_str(
                        parent_q_str.name as *const c_void,
                        &mut temp_parent_name as *mut _ as *mut u8,
                        len_to_copy_parent as u32 + 1,
                    ).is_ok() {
                        // Basic concatenation: "parent_name/filename"
                        // This is very simplified. A real version needs robust path building.
                        let mut current_path_len = 0;
                        for i in 0..len_to_copy_parent {
                            if current_path_len < FILEPATH_LEN_MAX -1 { // Check bounds for filepath
                                new_record_template.filepath[current_path_len] = temp_parent_name[i];
                                current_path_len += 1;
                            } else { break; }
                        }
                        if current_path_len < FILEPATH_LEN_MAX -1 {
                            new_record_template.filepath[current_path_len] = b'/';
                            current_path_len += 1;
                        }
                        // Append filename (already in name_union.filename)
                        let filename_part_len = name_len.min(FILENAME_LEN_MAX-1);
                        for i in 0..filename_part_len {
                             if current_path_len < FILEPATH_LEN_MAX -1 {
                                new_record_template.filepath[current_path_len] = new_record_template.name_union.filename[i];
                                current_path_len +=1;
                             } else { break; }
                        }
                    }
                }
            } else if name_len > 0 { // No parent name, just use filename as filepath
                 for i in 0..name_len.min(FILEPATH_LEN_MAX-1) {
                    new_record_template.filepath[i] = new_record_template.name_union.filename[i];
                 }
            }
        }


        *new_record_template // Return the new record
    };

    // Add current event to the record
    let mut event_count = 0;
    for i in 0..FS_EVENT_MAX {
        if record_fs_entry.event[i] == 0 {
            record_fs_entry.event[i] = current_event_flag;
            event_count = i + 1;
            break;
        }
        if record_fs_entry.event[i] == current_event_flag { // Event already present
            event_count = i + 1;
            break;
        }
    }
    record_fs_entry.events = event_count as u32;


    // Handle rename specifics for filename/filename_to
    if is_rename_event {
        // We need the other dentry's name for filename_from / filename_to
        // event_info.dentry_old should point to the "other" dentry in a rename
        if event_info.dentry_old != 0 {
            let other_dentry_ptr = event_info.dentry_old as *const dentry;
            let other_d_entry: dentry = unsafe { ctx.read_at(other_dentry_ptr)? };
            let other_q_str: qstr = unsafe { ctx.read_at(&other_d_entry.d_name as *const qstr)? };
            let mut other_filename_buf = [0u8; FILENAME_LEN_MAX / 2];
            let other_name_len = other_q_str.len as usize;

            if other_name_len > 0 && !other_q_str.name.is_null() {
                let len_to_copy = other_name_len.min((FILENAME_LEN_MAX / 2) -1);
                unsafe {
                     if bpf_probe_read_kernel_str(
                        other_q_str.name as *const c_void,
                        &mut other_filename_buf as *mut _ as *mut u8,
                        len_to_copy as u32 + 1,
                    ).is_err() {
                        // Error reading other_filename, it might remain empty or partially filled
                    }
                }
            }

            // We need to ensure the CURRENT filename is also in the correct part of the union
            // The current d_entry's name (which was read into record_fs_entry.name_union.filename initially)
            // needs to be moved to the correct field if it's a rename.
            let mut current_filename_backup = [0u8; FILENAME_LEN_MAX];
            current_filename_backup.copy_from_slice(unsafe{ &record_fs_entry.name_union.filename });

            if current_event_flag == FS_MOVED_FROM { // current dentry is source
                // filename_from is current d_entry's name
                record_fs_entry.name_union.filenames.filename_from[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&current_filename_backup[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]);
                // filename_to is other_d_entry's name
                record_fs_entry.name_union.filenames.filename_to[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&other_filename_buf[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]);
            } else { // FS_MOVED_TO, current dentry is target
                // filename_from is other_d_entry's name
                record_fs_entry.name_union.filenames.filename_from[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&other_filename_buf[..other_filename_buf.len().min(FILENAME_LEN_MAX/2)]);
                // filename_to is current d_entry's name
                record_fs_entry.name_union.filenames.filename_to[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]
                    .copy_from_slice(&current_filename_backup[..current_filename_backup.len().min(FILENAME_LEN_MAX/2)]);
            }
        }
    }


    // Decide whether to send or update map
    if send_now || event_count >= config.agg_events_max as usize || event_count >= FS_EVENT_MAX {
        // Send to ringbuffer
        unsafe { ringbuf_records.output(&record_fs_entry, 0)? };
        // Remove from hash_records
        unsafe { hash_records.delete(&key)? };

        // Update stats
        let mut stats = unsafe { stats_map.get_mut(0).ok_or(4i64)? };
        stats.fs_records += 1;
        stats.fs_events += event_count as u64;
        if event_count >= config.agg_events_max as usize {
            stats.fs_records_deleted +=1; // "deleted" here means flushed due to aggregation limit
        }

    } else {
        // Update hash_records
        unsafe { hash_records.insert(&key, &record_fs_entry, 0)? };
    }

    Ok(())
}


// Kprobe/Kretprobe stubs
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

// Example: do_filp_open (kretprobe)
fn try_do_filp_open(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 {
        return Ok(TC_ACT_OK);
    }

    let file_ptr = ctx.ret::<*mut file>().ok_or(1i64)?; // Get return value (struct file*)
    if file_ptr.is_null() {
        return Ok(TC_ACT_OK);
    }

    let kernel_file: file = unsafe { ctx.read_at(file_ptr)? };
    let dentry_ptr = kernel_file.f_path_dentry; // Accessing f_path.dentry

    if dentry_ptr.is_null() {
        return Ok(TC_ACT_OK);
    }

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_OPEN as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: *b"do_filp_open                                                      ", // 64 bytes
    };

    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kretprobe_impl!(do_filp_open_kretprobe, try_do_filp_open, "do_filp_open");


// Placeholder for other probes (to be implemented)
// security_inode_link
fn try_security_inode_link(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }
    // Args: struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry
    let old_dentry_ptr = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*mut dentry>(2).ok_or(1i64)?;
    // Logic for link: old_dentry is source, new_dentry is the link name
    // For now, report event on new_dentry as CREATE
    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_CREATE as i32, // Or a more specific LINK event if defined
        dentry: new_dentry_ptr as u64,
        dentry_old: old_dentry_ptr as u64, // Store original dentry as dentry_old
        func: *b"security_inode_link                                               ",
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(security_inode_link_kprobe, try_security_inode_link, "security_inode_link");

// security_inode_symlink
fn try_security_inode_symlink(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }
    // Args: struct inode *dir, struct dentry *dentry, const char *symname
    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;
    // The actual content of symlink (symname) is also available.
    // For now, just event on dentry.
    // Need to handle dput for symlinks: save dentry_ptr for dput
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;
    unsafe { SYMLINK_DENTRIES_MAP.insert(&pid, &(dentry_ptr as u64), 0)? };

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_CREATE as i32, // Symlink is a type of creation
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: *b"security_inode_symlink                                            ",
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(security_inode_symlink_kprobe, try_security_inode_symlink, "security_inode_symlink");

// dput (kprobe) - for symlink cleanup primarily
fn try_dput(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }

    let dentry_ptr_arg = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    let id = bpf_get_current_pid_tgid();
    let pid = (id >> 32) as u32;

    if let Some(saved_dentry_ptr) = unsafe { SYMLINK_DENTRIES_MAP.get(&pid) } {
        if *saved_dentry_ptr == (dentry_ptr_arg as u64) {
            // This dput corresponds to the dentry we saved from security_inode_symlink
            // Potentially log creation here if not done in symlink, or confirm.
            // For now, we remove it from map.
            unsafe { SYMLINK_DENTRIES_MAP.delete(&pid)? };

            // Example: Could trigger a specific symlink event here if needed
            // let mut event_info = FS_EVENT_INFO {
            //     index: INDEX_FS_EVENT::I_CREATE as i32, // Or a specific SYMLINK_RESOLVED if available
            //     dentry: dentry_ptr_arg as u64,
            //     dentry_old: 0,
            //     func: *b"dput_symlink                                                      ",
            // };
            // handle_fs_event(&ctx, &mut event_info)?;
        }
    }
    Ok(TC_ACT_OK)
}
kprobe_impl!(dput_kprobe, try_dput, "dput");


// notify_change (kprobe) - for attributes, size changes
fn try_notify_change(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }
    // Args: struct dentry *dentry, struct iattr *attr, struct inode **delegated_inode
    let dentry_ptr = ctx.arg::<*mut dentry>(0).ok_or(1i64)?;
    // struct iattr *attr = ctx.arg::<*mut iattr>(1).ok_or(1i64)?; // Contains info about what changed

    // Determine event type based on iattr if possible (e.g. ATTR_SIZE -> FS_MODIFY)
    // For now, assume generic FS_ATTRIB or FS_MODIFY
    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_ATTRIB as i32, // Or FS_MODIFY if size changed
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: *b"notify_change                                                     ",
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(notify_change_kprobe, try_notify_change, "notify_change");


// __fsnotify_parent (kprobe) - parent directory for create/delete/move in some cases
// This is complex. For now, a simple placeholder.
// Args: struct inode *inode, struct dentry *dentry, __u32 mask
fn try_fsnotify_parent(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }

    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?; // dentry of the child
    let mask = ctx.arg::<u32>(2).ok_or(1i64)?;

    // The 'mask' indicates the type of event (FS_CREATE, FS_DELETE etc.)
    // This probe can be used to get events for files when the direct inode notification point is missed.
    // We need to map the mask to our INDEX_FS_EVENT
    let event_idx = match mask {
        x if (x & FS_CREATE) != 0 => INDEX_FS_EVENT::I_CREATE,
        x if (x & FS_DELETE) != 0 => INDEX_FS_EVENT::I_DELETE,
        // Add more mappings as needed based on fsnotify.h masks
        _ => return Ok(TC_ACT_OK), // Unknown mask for now
    };

    let mut event_info = FS_EVENT_INFO {
        index: event_idx as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: *b"__fsnotify_parent                                                 ",
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(fsnotify_parent_kprobe, try_fsnotify_parent, "__fsnotify_parent");


// security_inode_rename (kprobe)
fn try_security_inode_rename(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }
    // Args: struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry
    let old_dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;
    let new_dentry_ptr = ctx.arg::<*mut dentry>(3).ok_or(1i64)?;

    // Event for MOVED_FROM on old_dentry
    let mut event_info_from = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_MOVED_FROM as i32,
        dentry: old_dentry_ptr as u64,
        dentry_old: new_dentry_ptr as u64, // new_dentry is the target of the rename
        func: *b"security_inode_rename_from                                        ",
    };
    handle_fs_event(&ctx, &mut event_info_from)?;

    // Event for MOVED_TO on new_dentry
    let mut event_info_to = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_MOVED_TO as i32,
        dentry: new_dentry_ptr as u64,
        dentry_old: old_dentry_ptr as u64, // old_dentry is the source of the rename
        func: *b"security_inode_rename_to                                          ",
    };
    handle_fs_event(&ctx, &mut event_info_to)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(security_inode_rename_kprobe, try_security_inode_rename, "security_inode_rename");


// security_inode_unlink (kprobe) - for delete
fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, i64> {
    let config = unsafe { CONFIG_MAP.get(0).ok_or(1i64)? };
    if config.monitor_flags & MONITOR_FILE == 0 { return Ok(TC_ACT_OK); }
    // Args: struct inode *dir, struct dentry *dentry
    let dentry_ptr = ctx.arg::<*mut dentry>(1).ok_or(1i64)?;

    let mut event_info = FS_EVENT_INFO {
        index: INDEX_FS_EVENT::I_DELETE as i32,
        dentry: dentry_ptr as u64,
        dentry_old: 0,
        func: *b"security_inode_unlink                                             ",
    };
    handle_fs_event(&ctx, &mut event_info)?;
    Ok(TC_ACT_OK)
}
kprobe_impl!(security_inode_unlink_kprobe, try_security_inode_unlink, "security_inode_unlink");


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// Helper to convert rust &str to [u8; N] compile time - not used currently for FsEvent names
// const fn str_to_bytes_n<const N: usize>(s: &str) -> [u8; N] {
//     let mut arr = [0u8; N];
//     let mut i = 0;
//     while i < s.len() && i < N {
//         arr[i] = s.as_bytes()[i];
//         i += 1;
//     }
//     arr
// }
