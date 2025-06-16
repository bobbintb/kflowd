#![no_std]
#![no_main]

use aya_ebpf::bindings::TC_ACT_OK; // Kept from previous, may be unused
use aya_ebpf::maps::{Array, LruHashMap, PerCpuArray, RingBuf};
// Pod trait import is removed again due to resolution issues with aya-ebpf v0.1.1.
// Will need to be resolved before eBPF programs can reliably use these structs in maps.
// use aya_ebpf_bindings::Pod;
use aya_ebpf_macros::map;
use aya_log_ebpf::info; // Kept for potential logging
use core::mem::size_of;

// Constants based on dirt.h
const FILENAME_LEN_MAX: usize = 32;
const FILEPATH_LEN_MAX: usize = 96;
const FS_EVENT_MAX: usize = 15;
const RECORD_TYPE_FILE: u32 = 1;

const I_CREATE: u32 = 0;
const I_OPEN: u32 = 1;
const I_OPEN_EXEC: u32 = 2;
const I_ACCESS: u32 = 3;
const I_ATTRIB: u32 = 4;
const I_MODIFY: u32 = 5;
const I_CLOSE_WRITE: u32 = 6;
const I_CLOSE_NOWRITE: u32 = 7;
const I_MOVED_FROM: u32 = 8;
const I_MOVED_TO: u32 = 9;
const I_DELETE: u32 = 10;
const I_DELETE_SELF: u32 = 11;
const I_MOVE_SELF: u32 = 12;
const I_UNMOUNT: u32 = 13;
const I_Q_OVERFLOW: u32 = 14;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Record {
    pub record_type: u32,
    pub ts: u64,
}
// NOTE: This struct is intended to be Pod.
// unsafe impl Pod for Record {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
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
// NOTE: This struct is intended to be Pod.
// unsafe impl Pod for RecordFs {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}
// NOTE: This struct is intended to be Pod.
// unsafe impl Pod for Stats {}

// Map Definitions
#[map]
pub static mut RINGBUF_RECORDS: RingBuf =
    RingBuf::with_byte_size((size_of::<RecordFs>() * 8192) as u32, 0);

#[map]
pub static mut HASH_RECORDS: LruHashMap<u64, RecordFs> =
    LruHashMap::with_max_entries(65536, 0);

#[map]
pub static mut HEAP_RECORD_FS: PerCpuArray<RecordFs> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static mut STATS_MAP: Array<Stats> = Array::with_max_entries(1, 0);

// TODO: Define eBPF programs/probes

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
