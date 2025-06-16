pub mod vmlinux;
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};
use crate::vmlinux::bindings; // bindings::c_char is used
use aya_log_ebpf::info;

// Constants from dirt.h
const RECORD_TYPE_FILE: u32 = 1;
const FILEPATH_LEN_MAX: usize = 96;
const FILENAME_LEN_MAX: usize = 32;
const DNAME_INLINE_LEN_MAX: usize = 32;
const FILEPATH_NODE_MAX: usize = 16;

const FS_EVENT_MAX: usize = 15;

const S_IFMT: u32 = 0o0170000;
const S_IFREG: u32 = 0o0100000;
const S_IFLNK: u32 = 0o0120000;
const S_IFDIR: u32 = 0o0040000;

const PID_SELF: u32 = 0;
const AGG_EVENTS_MAX: u32 = 10; // Max events before forcing output, 0 to disable

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub record_type: u32,
    pub ts: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecordFs {
    pub rc: Record,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX],
    pub ino: u32,
    pub imode: u32,
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub filename: [u8; FILENAME_LEN_MAX],
}

impl Default for RecordFs {
    fn default() -> Self {
        RecordFs {
            rc: Record { record_type: 0, ts: 0 },
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
            filepath: [0; FILEPATH_LEN_MAX],
            filename: [0; FILENAME_LEN_MAX],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            fs_records: 0,
            fs_records_deleted: 0,
            fs_records_dropped: 0,
            fs_records_rb_max: 0,
            fs_events: 0,
        }
    }
}

#[allow(dead_code)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexFsEvent {
    ICreate = 0, IOpen, IOpenExec, IAccess, IAttrib, IModify, ICloseWrite,
    ICloseNowrite, IMovedFrom, IMovedTo, IDelete, IDeleteSelf, IMoveSelf,
    IUnmount, IQOverflow,
}

#[derive(Clone, Copy, Debug)]
pub struct FsEventInfo {
    pub event_index: IndexFsEvent,
    pub dentry: *mut bindings::dentry,
    pub dentry_old: *mut bindings::dentry,
}

#[inline(always)]
fn key_pid_ino(pid: u32, ino: u32) -> u64 {
    ((pid as u64) << 32) | (ino as u64)
}

#[allow(unused_variables, unused_mut, clippy::identity_op)]
unsafe fn handle_fs_event_rs(ctx: &ProbeContext, event_info: &FsEventInfo) -> Result<u32, u32> {
    if event_info.event_index == IndexFsEvent::IAccess || event_info.event_index == IndexFsEvent::IAttrib {
        return Ok(0);
    }

    let pid = ctx.pid();
    if PID_SELF != 0 && PID_SELF == pid { return Ok(0); }
    if pid == 0 { return Ok(0); }

    let dentry_ptr = event_info.dentry;
    let dentry_old_ptr = event_info.dentry_old;

    let inode_source_dentry_ptr = if !dentry_old_ptr.is_null() {
        dentry_old_ptr
    } else {
        dentry_ptr
    };

    if inode_source_dentry_ptr.is_null() { return Err(1); }

    let inode_ptr: *mut bindings::inode = ctx.read_at(&((*inode_source_dentry_ptr).d_inode))?;
    if inode_ptr.is_null() { return Ok(0); }

    if dentry_ptr.is_null() { return Err(1); }
    let name_ptr_to_read: *const bindings::c_char = ctx.read_at(&((*dentry_ptr).d_name.name))?;

    let mut filename_buf = [0u8; FILENAME_LEN_MAX];
    let filename_len = match ctx.read_string_to_slice(name_ptr_to_read as *const u8, &mut filename_buf) {
        Ok(len) if len > 0 && filename_buf[0] != 0 => len,
        _ => return Ok(0),
    };
    let mut actual_filename_len = filename_len;
    for i in 0..filename_len {
        if filename_buf[i] == 0 {
            actual_filename_len = i;
            break;
        }
    }
    if actual_filename_len == 0 { return Ok(0); }

    let ino: u32 = ctx.read_at(&((*inode_ptr).i_ino))?;
    let imode: u32 = ctx.read_at(&((*inode_ptr).i_mode))?;

    if ino == 0 { return Ok(0); }

    let file_type = imode & S_IFMT;
    if !(file_type == S_IFREG || file_type == S_IFLNK) { return Ok(0); }

    let map_key = key_pid_ino(pid, ino);
    let ts_event = ctx.ktime_ns();

    let record_val_for_aggregation_logic_opt: Option<RecordFs>;

    if let Some(record_fs_ptr_val) = HASH_RECORDS.get_ptr_mut(&map_key) {
        let record_fs_ptr = record_fs_ptr_val as *mut RecordFs;
        let mut record_fs_val = ctx.read_at(record_fs_ptr)?;

        record_fs_val.rc.ts = ts_event;
        record_fs_val.imode = imode;
        record_fs_val.isize = ctx.read_at(&((*inode_ptr).i_size))?;
        let mut nlink: u32 = ctx.read_at(&((*inode_ptr).i_nlink))?;
        if event_info.event_index == IndexFsEvent::ICreate && !dentry_old_ptr.is_null() {
            nlink = nlink.saturating_add(1);
        }
        record_fs_val.inlink = nlink;
        let atime_sec: u64 = ctx.read_at(&((*inode_ptr).i_atime.tv_sec))? as u64;
        let atime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_atime.tv_nsec))? as u64;
        record_fs_val.atime_nsec = atime_sec.saturating_mul(1_000_000_000).saturating_add(atime_nsec_part);
        let mtime_sec: u64 = ctx.read_at(&((*inode_ptr).i_mtime.tv_sec))? as u64;
        let mtime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_mtime.tv_nsec))? as u64;
        record_fs_val.mtime_nsec = mtime_sec.saturating_mul(1_000_000_000).saturating_add(mtime_nsec_part);
        let ctime_sec: u64 = ctx.read_at(&((*inode_ptr).i_ctime.tv_sec))? as u64;
        let ctime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_ctime.tv_nsec))? as u64;
        record_fs_val.ctime_nsec = ctime_sec.saturating_mul(1_000_000_000).saturating_add(ctime_nsec_part);
        record_fs_val.events = record_fs_val.events.saturating_add(1);
        let event_idx = event_info.event_index as usize;
        if event_idx < FS_EVENT_MAX {
            record_fs_val.event[event_idx] = record_fs_val.event[event_idx].saturating_add(1);
        }

        if event_info.event_index == IndexFsEvent::IMovedTo {
            let offset_to = FILENAME_LEN_MAX / 2;
            if offset_to + actual_filename_len <= FILENAME_LEN_MAX {
                for i in offset_to..FILENAME_LEN_MAX { record_fs_val.filename[i] = 0; }
                record_fs_val.filename[offset_to..offset_to + actual_filename_len].copy_from_slice(&filename_buf[..actual_filename_len]);
            }
        }
        HASH_RECORDS.insert(&map_key, &record_fs_val, 0).map_err(|e| e as u32)?;
        record_val_for_aggregation_logic_opt = Some(record_fs_val);
    } else {
        if let Some(temp_record_fs_ptr_val) = HEAP_RECORD_FS.get_ptr_mut(&0u32) {
            let _temp_record_fs_ptr = temp_record_fs_ptr_val as *mut RecordFs; // Not directly used after getting 'r'
            let mut r = RecordFs::default();
            r.rc.ts = ts_event;
            r.ino = ino;
            r.filename[..actual_filename_len].copy_from_slice(&filename_buf[..actual_filename_len]);
            r.isize_first = ctx.read_at(&((*inode_ptr).i_size))?;
            // Filepath Construction
            let mut current_path_dentry_ptr = dentry_ptr;
            let mut path_nodes: [*const bindings::c_char; FILEPATH_NODE_MAX] = [core::ptr::null(); FILEPATH_NODE_MAX];
            let mut num_nodes = 0;
            for i in 0..FILEPATH_NODE_MAX {
                if current_path_dentry_ptr.is_null() { break; }
                let d_name_ptr: *const bindings::c_char = ctx.read_at(&((*current_path_dentry_ptr).d_name.name))?;
                if d_name_ptr.is_null() { break; }
                path_nodes[i] = d_name_ptr;
                num_nodes = i + 1;
                let parent_dentry_ptr: *mut bindings::dentry = ctx.read_at(&((*current_path_dentry_ptr).d_parent))?;
                if parent_dentry_ptr == current_path_dentry_ptr || parent_dentry_ptr.is_null() { break; }
                current_path_dentry_ptr = parent_dentry_ptr;
            }
            let mut current_filepath_offset = 0;
            r.filepath = [0u8; FILEPATH_LEN_MAX];
            for i in (0..num_nodes).rev() {
                let node_name_ptr = path_nodes[i];
                if node_name_ptr.is_null() { continue; }
                let mut temp_node_name_buf = [0u8; DNAME_INLINE_LEN_MAX];
                let node_name_len = match ctx.read_string_to_slice(node_name_ptr as *const u8, &mut temp_node_name_buf) {
                    Ok(len) if len > 0 => {
                        let mut actual_len = len;
                        for k in 0..len { if temp_node_name_buf[k] == 0 { actual_len = k; break; }}
                        if actual_len == 0 { continue; } actual_len } _ => continue, };
                if i != (num_nodes - 1) && current_filepath_offset > 0 && current_filepath_offset < FILEPATH_LEN_MAX -1 {
                    if r.filepath[current_filepath_offset-1] != b'/' {
                        r.filepath[current_filepath_offset] = b'/'; current_filepath_offset += 1; } }
                let space_left = FILEPATH_LEN_MAX - current_filepath_offset;
                let len_to_copy = if node_name_len > space_left { space_left } else { node_name_len };
                if len_to_copy > 0 {
                    r.filepath[current_filepath_offset..current_filepath_offset + len_to_copy].copy_from_slice(&temp_node_name_buf[..len_to_copy]);
                    current_filepath_offset += len_to_copy; }
                if current_filepath_offset >= FILEPATH_LEN_MAX -1 { break; } }
            if current_filepath_offset < FILEPATH_LEN_MAX { r.filepath[current_filepath_offset] = 0; }
            else if FILEPATH_LEN_MAX > 0 { r.filepath[FILEPATH_LEN_MAX - 1] = 0; }

            r.imode = imode; r.isize = ctx.read_at(&((*inode_ptr).i_size))?;
            let mut nlink: u32 = ctx.read_at(&((*inode_ptr).i_nlink))?;
            if event_info.event_index == IndexFsEvent::ICreate && !dentry_old_ptr.is_null() {
                nlink = nlink.saturating_add(1); }
            r.inlink = nlink;
            let atime_sec: u64 = ctx.read_at(&((*inode_ptr).i_atime.tv_sec))? as u64;
            let atime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_atime.tv_nsec))? as u64;
            r.atime_nsec = atime_sec.saturating_mul(1_000_000_000).saturating_add(atime_nsec_part);
            let mtime_sec: u64 = ctx.read_at(&((*inode_ptr).i_mtime.tv_sec))? as u64;
            let mtime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_mtime.tv_nsec))? as u64;
            r.mtime_nsec = mtime_sec.saturating_mul(1_000_000_000).saturating_add(mtime_nsec_part);
            let ctime_sec: u64 = ctx.read_at(&((*inode_ptr).i_ctime.tv_sec))? as u64;
            let ctime_nsec_part: u64 = ctx.read_at(&((*inode_ptr).i_ctime.tv_nsec))? as u64;
            r.ctime_nsec = ctime_sec.saturating_mul(1_000_000_000).saturating_add(ctime_nsec_part);
            r.events = 1; // First event
            let event_idx = event_info.event_index as usize;
            if event_idx < FS_EVENT_MAX { r.event[event_idx] = 1; }

            HASH_RECORDS.insert(&map_key, &r, 0).map_err(|e| e as u32)?;
            record_val_for_aggregation_logic_opt = Some(r);
        } else { return Err(3); }
    }

    if let Some(record_val_for_aggregation_logic) = record_val_for_aggregation_logic_opt {
        let mut agg_end = false;
        let current_event_index = event_info.event_index;
        let record_inlink = record_val_for_aggregation_logic.inlink;
        let record_events_count = record_val_for_aggregation_logic.events;

        if current_event_index == IndexFsEvent::ICloseWrite ||
           current_event_index == IndexFsEvent::ICloseNowrite ||
           current_event_index == IndexFsEvent::IDelete ||
           current_event_index == IndexFsEvent::IMovedTo {
            agg_end = true;
        } else if current_event_index == IndexFsEvent::ICreate {
            let file_type_check = record_val_for_aggregation_logic.imode & S_IFMT;
            if file_type_check == S_IFLNK || record_inlink > 1 {
                agg_end = true;
            }
        }

        if !agg_end && AGG_EVENTS_MAX > 0 {
            if record_events_count >= AGG_EVENTS_MAX {
                agg_end = true;
            }
        }

        if agg_end {
            let mut record_to_send = record_val_for_aggregation_logic;
            record_to_send.rc.record_type = RECORD_TYPE_FILE;

            if RINGBUF_RECORDS.output(&record_to_send, 0).is_err() {
                // Optional: Update stats for dropped records
            }
            let _ = HASH_RECORDS.delete(&map_key);
        }
    }

    info!(ctx, "FS Event Handled: PID: {}, File ({} bytes): {:?}, ino: {}, mode: {}",
        pid,
        actual_filename_len,
        &filename_buf[..actual_filename_len],
        ino,
        imode
    );

    Ok(0)
}

// BPF map definition:
const RINGBUF_MAX_ENTRIES: u32 = (core::mem::size_of::<RecordFs>() * 8192) as u32;

#[map]
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_MAX_ENTRIES, 0);

const MAP_RECORDS_MAX: u32 = 65536;

#[map]
pub static mut HASH_RECORDS: LruHashMap<u64, RecordFs> =
    LruHashMap::with_max_entries(MAP_RECORDS_MAX, 0);

#[map]
pub static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> =
    PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut STATS_MAP: Array<Stats> =
    Array::with_max_entries(1, 0);

// Dummy entry point
#[no_mangle]
pub extern "C" fn main_prog(_ctx: *const ::core::ffi::c_void) -> i32 {
    match unsafe { try_main_prog(_ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_main_prog(_ctx: *const ::core::ffi::c_void) -> Result<i32, i32> {
    Ok(0)
}

// KPROBE/KRETPROBE STUBS
#[kretprobe]
pub fn do_filp_open(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_do_filp_open(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kretprobe:do_filp_open entered"); Ok(0)
}
#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_security_inode_link(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:security_inode_link entered"); Ok(0)
}
#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_security_inode_symlink(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:security_inode_symlink entered"); Ok(0)
}
#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_dput(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:dput entered"); Ok(0)
}
#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_notify_change(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:notify_change entered"); Ok(0)
}
#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try___fsnotify_parent(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:__fsnotify_parent entered"); Ok(0)
}
#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_security_inode_rename(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:security_inode_rename entered"); Ok(0)
}
#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 { /* ... */ Ok(0)}
unsafe fn try_security_inode_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe:security_inode_unlink entered"); Ok(0)
}

// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
