#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext, maps::RingBuf, EbpfContext}; // Added kprobe, ProbeContext, EbpfContext
use aya_log_ebpf::info; // For logging from BPF

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
pub static mut RINGBUF_RECORDS: RingBuf = RingBuf::with_byte_size(RINGBUF_MAX_ENTRIES, 0);

#[kprobe] // Define it as a kprobe
pub fn example_kprobe(ctx: ProbeContext) -> u32 {
    match unsafe { try_example_kprobe(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_example_kprobe(ctx: ProbeContext) -> Result<u32, u32> {
    // Minimal check or log to ensure map is accessed
    info!(&ctx, "Example kprobe triggered, accessing RINGBUF_RECORDS");

    // Attempt a reserve, but don't necessarily commit if it's complex.
    // The main goal is to have RINGBUF_RECORDS referenced by a program.
    let entry = RINGBUF_RECORDS.reserve::<RecordFs>(0);
    match entry {
        Some(mut _entry_data) => {
            // _entry_data.data.write(RecordFs { ... }); // Populate if needed
            // _entry_data.submit(0); // Submit data
            info!(&ctx, "Reserved entry in RINGBUF_RECORDS");
        }
        None => {
            info!(&ctx, "Failed to reserve entry in RINGBUF_RECORDS");
            return Err(1);
        }
    }
    Ok(0)
}

// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // A minimal panic handler that just loops indefinitely.
    loop {}
}
