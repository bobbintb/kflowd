use aya_ebpf::macros::{kprobe, kretprobe, map};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::maps::Array;
use aya_ebpf::programs::ProgramContext;
pub mod vmlinux;
use core::ffi::c_void;
#![no_std]
#![no_main]

use aya_ebpf::{macros::map, maps::RingBuf};
// Removed: use core::ffi::c_char;

// Constants from dirt.h
const RECORD_TYPE_FILE: u32 = 1;
const FILEPATH_LEN_MAX: usize = 96;
const FILENAME_LEN_MAX: usize = 32;

// Calculated from struct FS_EVENT fsevt[] in dirt.h
// struct FS_EVENT { short index; short value; char name[16]; char shortname[4]; char shortname2[4]; }; (2*2 + 16 + 4 + 4 = 28 bytes)
// There are 15 initializers for fsevt.
const FS_EVENT_MAX: usize = 15;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub record_type: u32, // Renamed from type to avoid keyword conflict
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
    // Union filename / (filename_from, filename_to)
    // For simplicity, using a single array. Application logic will handle splitting if needed.
    pub filename: [u8; FILENAME_LEN_MAX],
}

// BPF map definition:
// struct {
// __uint(type, BPF_MAP_TYPE_RINGBUF);
// __uint(max_entries, sizeof(struct RECORD_FS) * 8192);
// } ringbuf_records SEC(".maps");
//
// max_entries will be calculated using core::mem::size_of::<RecordFs>() * 8192
// However, RingBuf in Aya expects the total size in bytes directly for max_entries.
// The C definition means "number of elements" * "size of one element", which is the total buffer size.
// So, if sizeof(struct RECORD_FS) in C is, for example, 256 bytes, then max_entries is 256 * 8192.
// Aya's RingBuf max_entries is the capacity in bytes.
const RINGBUF_MAX_ENTRIES: u32 = (core::mem::size_of::<RecordFs>() * 8192) as u32;

#[map]
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_MAX_ENTRIES, 0); // Changed with_max_entries to with_byte_size

// Dummy entry point, actual BPF programs will be added later
#[no_mangle]
pub extern "C" fn main_prog(_ctx: *const ::core::ffi::c_void) -> i32 { // Changed argument type
    match unsafe { try_main_prog(_ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_main_prog(_ctx: *const ::core::ffi::c_void) -> Result<i32, i32> {
    // Actual program logic will go here. For now, it's a no-op.
    Ok(0)
}

// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // A minimal panic handler that just loops indefinitely.
    loop {}
}


#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}



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


// === KPROBE/KRETPROBE STUBS START ===

// --- kretprobe for do_filp_open ---
#[kretprobe]
pub fn do_filp_open(ctx: ProgramContext) -> u32 {
    match unsafe { try_do_filp_open(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_do_filp_open(ctx: ProgramContext) -> Result<u32, u32> {
    // Placeholder: actual logic later
    // Use ctx.ret() for return value (*const file)
    Ok(0)
}

// --- kprobe for security_inode_link ---
#[kprobe]
pub fn security_inode_link(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_link(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_link(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry
    // Use ctx.arg(0), ctx.arg(1), ctx.arg(2)
    Ok(0)
}

// --- kprobe for security_inode_symlink ---
#[kprobe]
pub fn security_inode_symlink(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_symlink(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_symlink(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *dir, struct dentry *dentry, const char *old_name
    Ok(0)
}

// --- kprobe for dput ---
#[kprobe]
pub fn dput(ctx: ProgramContext) -> u32 {
    match unsafe { try_dput(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_dput(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry
    Ok(0)
}

// --- kprobe for notify_change ---
#[kprobe]
pub fn notify_change(ctx: ProgramContext) -> u32 {
    match unsafe { try_notify_change(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_notify_change(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry, struct iattr *attr
    Ok(0)
}

// --- kprobe for __fsnotify_parent ---
#[kprobe]
pub fn __fsnotify_parent(ctx: ProgramContext) -> u32 {
    match unsafe { try___fsnotify_parent(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try___fsnotify_parent(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry, __u32 mask, const void *data, int data_type
    Ok(0)
}

// --- kprobe for security_inode_rename ---
#[kprobe]
pub fn security_inode_rename(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_rename(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_rename(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *old_dir, struct dentry *old_dentry,
    //       struct inode *new_dir, struct dentry *new_dentry
    Ok(0)
}

// --- kprobe for security_inode_unlink ---
#[kprobe]
pub fn security_inode_unlink(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_unlink(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_unlink(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *dir, struct dentry *dentry
    Ok(0)
}
// === KPROBE/KRETPROBE STUBS END ===


// === KPROBE/KRETPROBE STUBS START ===

// --- kretprobe for do_filp_open ---
#[kretprobe]
pub fn do_filp_open(ctx: ProgramContext) -> u32 {
    match unsafe { try_do_filp_open(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_do_filp_open(ctx: ProgramContext) -> Result<u32, u32> {
    // Placeholder: actual logic later
    // Use ctx.ret() for return value (*const file)
    Ok(0)
}

// --- kprobe for security_inode_link ---
#[kprobe]
pub fn security_inode_link(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_link(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_link(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry
    // Use ctx.arg(0), ctx.arg(1), ctx.arg(2)
    Ok(0)
}

// --- kprobe for security_inode_symlink ---
#[kprobe]
pub fn security_inode_symlink(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_symlink(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_symlink(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *dir, struct dentry *dentry, const char *old_name
    Ok(0)
}

// --- kprobe for dput ---
#[kprobe]
pub fn dput(ctx: ProgramContext) -> u32 {
    match unsafe { try_dput(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_dput(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry
    Ok(0)
}

// --- kprobe for notify_change ---
#[kprobe]
pub fn notify_change(ctx: ProgramContext) -> u32 {
    match unsafe { try_notify_change(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_notify_change(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry, struct iattr *attr
    Ok(0)
}

// --- kprobe for __fsnotify_parent ---
#[kprobe]
pub fn __fsnotify_parent(ctx: ProgramContext) -> u32 {
    match unsafe { try___fsnotify_parent(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try___fsnotify_parent(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct dentry *dentry, __u32 mask, const void *data, int data_type
    Ok(0)
}

// --- kprobe for security_inode_rename ---
#[kprobe]
pub fn security_inode_rename(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_rename(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_rename(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *old_dir, struct dentry *old_dentry,
    //       struct inode *new_dir, struct dentry *new_dentry
    Ok(0)
}

// --- kprobe for security_inode_unlink ---
#[kprobe]
pub fn security_inode_unlink(ctx: ProgramContext) -> u32 {
    match unsafe { try_security_inode_unlink(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_security_inode_unlink(ctx: ProgramContext) -> Result<u32, u32> {
    // Args: struct inode *dir, struct dentry *dentry
    Ok(0)
}
// === KPROBE/KRETPROBE STUBS END ===
