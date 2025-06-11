#![no_std]

use aya_bpf::macros::Pod;
use libc::{pid_t, umode_t}; // For umode_t, pid_t

// Constants from kflowd.h

// define kernel subsystems and switch
pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

// define file system event values (used as masks or direct values)
pub const FS_ACCESS: u32         = 0x00000001;
pub const FS_MODIFY: u32         = 0x00000002;
pub const FS_ATTRIB: u32         = 0x00000004;
pub const FS_CLOSE_WRITE: u32    = 0x00000008;
pub const FS_CLOSE_NOWRITE: u32  = 0x00000010;
pub const FS_OPEN: u32           = 0x00000020;
pub const FS_MOVED_FROM: u32     = 0x00000040;
pub const FS_MOVED_TO: u32       = 0x00000080;
pub const FS_CREATE: u32         = 0x00000100;
pub const FS_DELETE: u32         = 0x00000200;
// ... other FS_* constants from kflowd.h if they were used by bpf program ...
// For now, including only those directly referenced or highly relevant.

// define file modes (from kflowd.h, if needed by BPF logic translated)
pub const FMODE_READ: u32     = 0x0000001;
pub const FMODE_WRITE: u32    = 0x0000002;
// pub const FMODE_OPENED: u32   = 0x0080000; // Not directly in bpf code logic
pub const FMODE_CREATED: u32  = 0x0100000; // Used in do_filp_open
// pub const FMODE_NONOTIFY: u32 = 0x4000000; // Not directly in bpf code logic

// define dcache types (from kflowd.h)
pub const DCACHE_ENTRY_TYPE: u32     = 0x00700000;
pub const DCACHE_DIRECTORY_TYPE: u32 = 0x00200000;
pub const DCACHE_AUTODIR_TYPE: u32   = 0x00300000;

// define inode mode values S_IF* (from kflowd.h)
pub const S_IFMT: umode_t  = 0o0170000; // Note: Octal representation
pub const S_IFSOCK: umode_t= 0o0140000;
pub const S_IFLNK: umode_t = 0o0120000;
pub const S_IFREG: umode_t = 0o0100000;
pub const S_IFBLK: umode_t = 0o0060000;
pub const S_IFDIR: umode_t = 0o0040000;
pub const S_IFCHR: umode_t = 0o0020000;
pub const S_IFIFO: umode_t = 0o0010000;

// S_IS* macros as functions
#[inline(always)]
pub fn s_islnk(mode: umode_t) -> bool { (mode & S_IFMT) == S_IFLNK }
#[inline(always)]
pub fn s_isreg(mode: umode_t) -> bool { (mode & S_IFMT) == S_IFREG }
#[inline(always)]
pub fn s_isdir(mode: umode_t) -> bool { (mode & S_IFMT) == S_IFDIR }
// ... other S_IS* functions if needed

// define event attribute values (from kflowd.h)
pub const ATTR_MODE: u32  = (1 << 0);
pub const ATTR_UID: u32   = (1 << 1);
pub const ATTR_GID: u32   = (1 << 2);
pub const ATTR_SIZE: u32  = (1 << 3);
pub const ATTR_ATIME: u32 = (1 << 4);
pub const ATTR_MTIME: u32 = (1 << 5);
// ... other ATTR_* constants as needed

// define filesystem event index (enum INDEX_FS_EVENT from kflowd.h)
// These are array indices for r->event[index]++
#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum IndexFsEvent {
    ICreate = 0,
    IOpen,          // Restored for compilation, filter in BPF handles it
    IOpenExec,     // Restored for compilation
    IAccess,        // Restored for compilation
    IAttrib,        // Restored for compilation
    IModify,
    ICloseWrite,   // Restored for compilation
    ICloseNowrite, // Restored for compilation
    IMovedFrom,
    IMovedTo,
    IDelete,
    IDeleteSelf,   // Not directly used in the bpf code provided, but part of enum
    IMoveSelf,     // Not directly used
    IUnmount,      // Not directly used
    IQOverflow,    // Not directly used
}

// Constants for array sizes and limits
pub const MAP_RECORDS_MAX: u32 = 65536; // From kflowd.h
pub const RECORD_TYPE_FILE: u32 = 1;    // From kflowd.h

pub const FILENAME_LEN_MAX: usize = 32;  // From kflowd.h
pub const FILEPATH_LEN_MAX: usize = 96;  // From kflowd.h
// pub const FILEPATH_NODE_MAX: usize = 16; // Used in handle_fs_event stack array for path construction
// pub const DNAME_INLINE_LEN: usize = 32; // Used in handle_fs_event path construction logic

// FS_EVENT_MAX is calculated from the size of fsevt array in C.
// Let's count the items in the C fsevt array: Create to Q_Overflow = 15 items.
// So FS_EVENT_MAX should be 15.
pub const FS_EVENT_MAX: usize = 15;


// Struct definitions

// From: struct RECORD in kflowd.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod)]
pub struct RecordCommon {
    pub record_type: u32, // Renamed from 'type' to avoid Rust keyword conflict
    pub ts: u64,
}

// From: struct RECORD_FS in kflowd.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod)]
pub struct RecordFs {
    pub rc: RecordCommon,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX], // Array for event counts
    pub ino: u32,       // In C, this is u32 (though ino_t can be u64 on some systems, BPF code uses u32)
    pub imode: umode_t, // umode_t from libc
    pub inlink: u32,
    pub isize: u64,     // loff_t is usually s64, so u64 for size is fine
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX], // Using u8 array for C-style string
    // Union for filename / filename_from, filename_to
    // In Rust, explicit unions are tricky with Pod.
    // For BPF, it's often easier to define the largest possible structure or use a simple byte array.
    // Given filename_from and filename_to are half of filename,
    // and filename is FILENAME_LEN_MAX.
    // We can represent this with a single filename field and handle logic in code.
    // Or, if the BPF program truly relies on the union structure for different interpretations,
    // we might need to use `#[repr(union)]` which has stricter rules for Pod.
    // The C code seems to use `r->filename_to` and `r->filename`.
    // Let's use a flat structure for the filenames for simplicity with Pod.
    pub filename: [u8; FILENAME_LEN_MAX],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2], // Only filename_to seems to be used from the union apart from full filename
    // If filename_from was also used, we'd add it.
    // The C code has:
    // union { struct { char filename_from[FNL/2]; char filename_to[FNL/2]; }; char filename[FNL]; };
    // The BPF code writes to `r->filename_to` and `r->filename`.
    // Let's just use the two fields it writes to: `filename` and `filename_to`.
    // `filename_from` is not written by the BPF code.
    // This means the union can be simplified to just those two overlapping fields.
    // For Pod safety, we should avoid overlapping fields if possible or use explicit `#[repr(union)]`.
    // Given `bpf_probe_read_kernel_str(&r->filename_to, sizeof(r->filename_to), ...)`
    // and `bpf_probe_read_kernel_str(&r->filename, sizeof(r->filename), ...)`
    // These are distinct operations. The union in C is a bit misleading if they are treated separately.
    // Let's check `__builtin_memset(r->filename_to - 1, 0, sizeof(r->filename_to) + 1);` - this is odd.
    // It implies `filename_to` is part of a larger structure or there's some pointer arithmetic.
    // Ah, `__builtin_memset(r->filename_to - 1, ...)` is likely a typo or misunderstanding in the C code,
    // or it implies filename_from precedes filename_to and it's clearing filename_from effectively.
    // Let's assume `filename` and `filename_to` are the primary fields.
    // For now, I'll keep them separate for Pod safety.
    // If the C code truly relies on `filename_to` being an alias for the second half of `filename`,
    // then an explicit union or careful byte array manipulation would be needed in Rust.
    // The C code does: `__builtin_memset(r->filename, 0, sizeof(r->filename));`
    // And then: `bpf_probe_read_kernel_str(&r->filename, sizeof(r->filename), ...);`
    // And for rename: `__builtin_memset(r->filename_to - 1, 0, sizeof(r->filename_to) + 1);` (still looks suspicious)
    // followed by: `bpf_probe_read_kernel_str(&r->filename_to, sizeof(r->filename_to), ...);`
    // Let's provide `filename` and `filename_to` as separate fields.
    // The original C union was:
    // union { struct { char filename_from[FILENAME_LEN_MAX / 2]; char filename_to[FILENAME_LEN_MAX / 2]; }; char filename[FILENAME_LEN_MAX]; };
    // This means `filename_from` is the first half of `filename`, and `filename_to` is the second half.
    // If `filename_to` is written, it overwrites the second half of `filename`.
    // This is a common C pattern but tricky for direct Rust Pod translation if we want named fields.
    // A `[u8; FILENAME_LEN_MAX]` for `filename_storage` and then methods to get/set parts would be safer.
    // Or, for direct translation of usage:
    // pub filename_bytes: [u8; FILENAME_LEN_MAX], // Corresponds to char filename[FILENAME_LEN_MAX]
    // And then access filename_to as a slice of filename_bytes if needed.
    // However, the C code uses `&r->filename_to` directly.
    // This implies `filename_to` has its own memory location in the union, which is true for the struct part.
    // Let's define the struct within the union as it was.
    // This will make `RecordFs` not directly `Pod` if it contains a raw union with non-Pod types or needs specific handling.
    // `aya_bpf::macros::Pod` might not work with Rust unions directly.
    // A simple solution for BPF is often to use byte arrays and accessors.
    // Given the C code's direct access to `filename_to` and `filename`,
    // let's assume they can be separate for the purpose of what the BPF program *does*.
    // The suspicious `filename_to - 1` might be an attempt to get to `filename_from`.
    // If `filename_from` is never read or written by BPF, we can simplify.
    // The BPF code only writes to `filename` and `filename_to`.
    // Let's provide distinct fields.
    // filename_from: [u8; FILENAME_LEN_MAX / 2], // Retaining for struct size matching if critical
    // filename_to: [u8; FILENAME_LEN_MAX / 2],   // This is used
    // filename_alt: [u8; FILENAME_LEN_MAX], // This is also used
    // This is not how C unions work. It's one or the other.
    // The simplest for Pod:
    // pub raw_filenames: [u8; FILENAME_LEN_MAX],
    // And then unsafe accessors.
    // Or, if the fields are truly independent in usage by BPF:
    // This seems like the most pragmatic approach if the C union is just for saving space and
    // the BPF logic doesn't rely on aliasing in a complex way.
    // The BPF code sets `r->filename` on new records.
    // It sets `r->filename_to` on `FS_MOVED_TO`. These seem like distinct conceptual fields.
}


// From: struct STATS in kflowd.h
#[repr(C)]
#[derive(Copy, Clone, Debug, Pod)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

// FS_EVENT_INFO is used as a parameter to handle_fs_event.
// It contains pointers, so it cannot be Pod if we were to put it in a map.
// As a function argument type, it's fine. We'll define it in the BPF crate itself,
// or pass its components if simpler. Given it's just a few fields, passing components might be cleaner.
// struct FS_EVENT_INFO {
//     int            index;
//     struct dentry *dentry;
//     struct dentry *dentry_old;
//     char          *func; // pointer to string literal
// };


// Helper functions from kflowd.h that are macros
#[inline(always)]
pub fn key_pid_ino(pid: pid_t, ino: u32) -> u64 {
    ((pid as u64) << 32) | (ino as u64)
}

// Debug related constants (if needed by BPF code)
pub const DBG_LEN_MAX: usize = 16;
pub const MAX_STACK_TRACE_DEPTH: usize = 16;


// Panic handler
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
// EOF marker is not needed for this tool
