// dirt.rs

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use core::ffi::{c_char, c_int};

pub const KERNEL_VERSION_MIN: u32 = 5;
pub const KERNEL_MAJOR_MIN: u32 = 10;

pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

#[macro_export]
macro_rules! kprobe_switch {
    ($monitor:expr, $monitor_type:expr) => {
        if $monitor & $monitor_type == 0 {
            return 0;
        }
    };
}

// File system event values
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
pub const FS_DELETE_SELF: u32    = 0x00000400;
pub const FS_MOVE_SELF: u32      = 0x00000800;
pub const FS_OPEN_EXEC: u32      = 0x00001000;
pub const FS_UNMOUNT: u32        = 0x00002000;
pub const FS_Q_OVERFLOW: u32     = 0x00004000;
pub const FS_ERROR: u32          = 0x00008000;
pub const FS_IN_IGNORED: u32     = 0x00008000;
pub const FS_OPEN_PERM: u32      = 0x00010000;
pub const FS_ACCESS_PERM: u32    = 0x00020000;
pub const FS_OPEN_EXEC_PERM: u32 = 0x00040000;
pub const FS_EXCL_UNLINK: u32    = 0x04000000;
pub const FS_EVENT_ON_CHILD: u32 = 0x08000000;
pub const FS_RENAME: u32         = 0x10000000;
pub const FS_DN_MULTISHOT: u32   = 0x20000000;
pub const FS_ISDIR: u32          = 0x40000000;
pub const FS_IN_ONESHOT: u32     = 0x80000000;

// File modes
pub const FMODE_READ: u32     = 0x0000001;
pub const FMODE_WRITE: u32    = 0x0000002;
pub const FMODE_OPENED: u32   = 0x0080000;
pub const FMODE_CREATED: u32  = 0x0100000;
pub const FMODE_NONOTIFY: u32 = 0x4000000;

// dcache types
pub const DCACHE_ENTRY_TYPE: u32     = 0x00700000;
pub const DCACHE_DIRECTORY_TYPE: u32 = 0x00200000;
pub const DCACHE_AUTODIR_TYPE: u32   = 0x00300000;

// inode mode values
pub const S_IFMT: u32    = 0o170000;
pub const S_IFSOCK: u32  = 0o140000;
pub const S_IFLNK: u32   = 0o120000;
pub const S_IFREG: u32   = 0o100000;
pub const S_IFBLK: u32   = 0o060000;
pub const S_IFDIR: u32   = 0o040000;
pub const S_IFCHR: u32   = 0o020000;
pub const S_IFIFO: u32   = 0o010000;
pub const S_ISUID: u32   = 0o004000;
pub const S_ISGID: u32   = 0o002000;
pub const S_ISVTX: u32   = 0o001000;

pub fn s_islnk(m: u32) -> bool  { (m & S_IFMT) == S_IFLNK }
pub fn s_isreg(m: u32) -> bool  { (m & S_IFMT) == S_IFREG }
pub fn s_isdir(m: u32) -> bool  { (m & S_IFMT) == S_IFDIR }
pub fn s_ischr(m: u32) -> bool  { (m & S_IFMT) == S_IFCHR }
pub fn s_isblk(m: u32) -> bool  { (m & S_IFMT) == S_IFBLK }
pub fn s_isfifo(m: u32) -> bool { (m & S_IFMT) == S_IFIFO }
pub fn s_issock(m: u32) -> bool { (m & S_IFMT) == S_IFSOCK }

// ATTR_* constants
pub const ATTR_MODE: u32      = 1 << 0;
pub const ATTR_UID: u32       = 1 << 1;
pub const ATTR_GID: u32       = 1 << 2;
pub const ATTR_SIZE: u32      = 1 << 3;
pub const ATTR_ATIME: u32     = 1 << 4;
pub const ATTR_MTIME: u32     = 1 << 5;
pub const ATTR_CTIME: u32     = 1 << 6;
pub const ATTR_ATIME_SET: u32 = 1 << 7;
pub const ATTR_MTIME_SET: u32 = 1 << 8;
pub const ATTR_FORCE: u32     = 1 << 9;
pub const ATTR_KILL_SUID: u32 = 1 << 11;
pub const ATTR_KILL_SGID: u32 = 1 << 12;
pub const ATTR_FILE: u32      = 1 << 13;
pub const ATTR_KILL_PRIV: u32 = 1 << 14;
pub const ATTR_OPEN: u32      = 1 << 15;
pub const ATTR_TIMES_SET: u32 = 1 << 16;
pub const ATTR_TOUCH: u32     = 1 << 17;

pub const USER_READ: i16   = 256;
pub const USER_WRITE: i16  = 128;
pub const USER_EXE: i16    = 64;
pub const GROUP_READ: i16  = 32;
pub const GROUP_WRITE: i16 = 16;
pub const GROUP_EXE: i16   = 8;
pub const OTHER_READ: i16  = 4;
pub const OTHER_WRITE: i16 = 2;
pub const OTHER_EXE: i16   = 1;

// FS_PERM
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FS_PERM {
    pub index: i16,
    pub value: i16,
    pub perm: u8,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum INDEX_FS_PERM {
    I_USER_READ,
    I_USER_WRITE,
    I_USER_EXE,
    I_GROUP_READ,
    I_GROUP_WRITE,
    I_GROUP_EXE,
    I_OTHER_READ,
    I_OTHER_WRITE,
    I_OTHER_EXE,
}

// FS_EVENT
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FS_EVENT {
    pub index: u16,
    pub value: u16,
    pub name: [c_char; 16],
    pub shortname: [c_char; 4],
    pub shortname2: [c_char; 4],
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum INDEX_FS_EVENT {
    I_CREATE,
    I_OPEN,
    I_OPEN_EXEC,
    I_ACCESS,
    I_ATTRIB,
    I_MODIFY,
    I_CLOSE_WRITE,
    I_CLOSE_NOWRITE,
    I_MOVED_FROM,
    I_MOVED_TO,
    I_DELETE,
    I_DELETE_SELF,
    I_MOVE_SELF,
    I_UNMOUNT,
    I_Q_OVERFLOW,
}

// FILESYSTEM EVENT INFO
static FSEVT: [FS_EVENT; 16] = [
    FS_EVENT {
        index: 0,
        value: FS_CREATE as u16,
        name: [b'C' as c_char, b'R' as c_char, b'E' as c_char, b'A' as c_char, b'T' as c_char, b'E' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'C' as c_char, b'R' as c_char, b'E' as c_char, 0],
        shortname2: [b'C' as c_char, b'R' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 1,
        value: FS_OPEN as u16,
        name: [b'O' as c_char, b'P' as c_char, b'E' as c_char, b'N' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'O' as c_char, b'P' as c_char, b'N' as c_char, 0],
        shortname2: [b'O' as c_char, b'P' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 2,
        value: FS_OPEN_EXEC as u16,
        name: [b'O' as c_char, b'P' as c_char, b'E' as c_char, b'N' as c_char, b'_' as c_char, b'E' as c_char, b'X' as c_char, b'E' as c_char, b'C' as c_char, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'O' as c_char, b'P' as c_char, b'X' as c_char, 0],
        shortname2: [b'O' as c_char, b'X' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 3,
        value: FS_ACCESS as u16,
        name: [b'A' as c_char, b'C' as c_char, b'C' as c_char, b'E' as c_char, b'S' as c_char, b'S' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'A' as c_char, b'C' as c_char, b'C' as c_char, 0],
        shortname2: [b'A' as c_char, b'C' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 4,
        value: FS_ATTRIB as u16,
        name: [b'A' as c_char, b'T' as c_char, b'T' as c_char, b'R' as c_char, b'I' as c_char, b'B' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'A' as c_char, b'T' as c_char, b'T' as c_char, 0],
        shortname2: [b'A' as c_char, b'T' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 5,
        value: FS_MODIFY as u16,
        name: [b'M' as c_char, b'O' as c_char, b'D' as c_char, b'I' as c_char, b'F' as c_char, b'Y' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'M' as c_char, b'O' as c_char, b'D' as c_char, 0],
        shortname2: [b'M' as c_char, b'O' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 6,
        value: FS_CLOSE_WRITE as u16,
        name: [b'C' as c_char, b'L' as c_char, b'O' as c_char, b'S' as c_char, b'E' as c_char, b'_' as c_char, b'W' as c_char, b'R' as c_char, b'I' as c_char, b'T' as c_char, b'E' as c_char, 0, 0, 0, 0, 0],
        shortname: [b'C' as c_char, b'L' as c_char, b'W' as c_char, 0],
        shortname2: [b'C' as c_char, b'W' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 7,
        value: FS_CLOSE_NOWRITE as u16,
        name: [b'C' as c_char, b'L' as c_char, b'O' as c_char, b'S' as c_char, b'E' as c_char, b'_' as c_char, b'N' as c_char, b'O' as c_char, b'W' as c_char, b'R' as c_char, b'I' as c_char, b'T' as c_char, b'E' as c_char, 0, 0, 0],
        shortname: [b'C' as c_char, b'L' as c_char, b'N' as c_char, 0],
        shortname2: [b'C' as c_char, b'N' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 8,
        value: FS_MOVED_FROM as u16,
        name: [b'M' as c_char, b'O' as c_char, b'V' as c_char, b'E' as c_char, b'D' as c_char, b'_' as c_char, b'F' as c_char, b'R' as c_char, b'O' as c_char, b'M' as c_char, 0, 0, 0, 0, 0, 0],
        shortname: [b'M' as c_char, b'O' as c_char, b'F' as c_char, 0],
        shortname2: [b'M' as c_char, b'F' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 9,
        value: FS_MOVED_TO as u16,
        name: [b'M' as c_char, b'O' as c_char, b'V' as c_char, b'E' as c_char, b'D' as c_char, b'_' as c_char, b'T' as c_char, b'O' as c_char, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'M' as c_char, b'O' as c_char, b'T' as c_char, 0],
        shortname2: [b'M' as c_char, b'T' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 10,
        value: FS_DELETE as u16,
        name: [b'D' as c_char, b'E' as c_char, b'L' as c_char, b'E' as c_char, b'T' as c_char, b'E' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'D' as c_char, b'E' as c_char, b'L' as c_char, 0],
        shortname2: [b'D' as c_char, b'L' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 11,
        value: FS_DELETE_SELF as u16,
        name: [b'D' as c_char, b'E' as c_char, b'L' as c_char, b'E' as c_char, b'T' as c_char, b'E' as c_char, b'_' as c_char, b'S' as c_char, b'E' as c_char, b'L' as c_char, b'F' as c_char, 0, 0, 0, 0, 0],
        shortname: [b'D' as c_char, b'L' as c_char, b'S' as c_char, 0],
        shortname2: [b'D' as c_char, b'S' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 12,
        value: FS_MOVE_SELF as u16,
        name: [b'M' as c_char, b'O' as c_char, b'V' as c_char, b'E' as c_char, b'_' as c_char, b'S' as c_char, b'E' as c_char, b'L' as c_char, b'F' as c_char, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'M' as c_char, b'S' as c_char, b'L' as c_char, 0],
        shortname2: [b'M' as c_char, b'S' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 13,
        value: FS_UNMOUNT as u16,
        name: [b'U' as c_char, b'N' as c_char, b'M' as c_char, b'O' as c_char, b'U' as c_char, b'N' as c_char, b'T' as c_char, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        shortname: [b'U' as c_char, b'M' as c_char, b'T' as c_char, 0],
        shortname2: [b'U' as c_char, b'M' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 14,
        value: FS_Q_OVERFLOW as u16,
        name: [b'Q' as c_char, b'_' as c_char, b'O' as c_char, b'V' as c_char, b'E' as c_char, b'R' as c_char, b'F' as c_char, b'L' as c_char, b'O' as c_char, b'W' as c_char, 0, 0, 0, 0, 0, 0],
        shortname: [b'Q' as c_char, b'O' as c_char, b'F' as c_char, 0],
        shortname2: [b'Q' as c_char, b'O' as c_char, 0, 0],
    },
    FS_EVENT {
        index: 15,
        value: 0,
        name: [0; 16],
        shortname: [0; 4],
        shortname2: [0; 4],
    },
];


fn tolower_str(s: &mut [u8]) {
    for b in s.iter_mut() {
        if *b == 0 {
            break;
        }
        *b = b.to_ascii_lowercase();
    }
}

pub const MAX_STACK_TRACE_DEPTH: usize = 16;
pub const SYS_FILE_JIT_ENABLE: &str = "/proc/sys/net/core/bpf_jit_enable";
pub const SYS_FILE_VMLINUX: &str = "/sys/kernel/btf/vmlinux";
pub const CACHE_ENTRIES_MAX: usize = 65536;
pub const MAP_RECORDS_MAX: usize = 65536;
pub const MAP_PIDS_MAX: usize = 8192;
pub const RECORD_TYPE_FILE: u32 = 1;
pub const TASK_COMM_LEN: usize = 32;
pub const TASK_COMM_SHORT_LEN: usize = 16;
pub const DNAME_INLINE_LEN: usize = 32;
pub const VERSION_LEN_MAX: usize = 16;
pub const IF_MAC_LEN_MAX: usize = 20;
pub const IF_INDEX_LEN_MAX: usize = 8;
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
pub const FILEPATH_NODE_MAX: usize = 16;
pub const FILE_READ_LEN_MAX: usize = 4096;
pub const FILE_EVENTS_LEN_MAX: usize = 256;
pub const FILE_PERMS_LEN_MAX: usize = 32;
pub const CMD_LEN_MAX: usize = 512;
pub const CMD_OUTPUT_LEN_MAX: usize = 1024;
pub const JSON_OUT_LEN_MAX: usize = 8192;
pub const FS_EVENT_MAX: usize = 16;
pub const MODE_LEN_MAX: usize = 12;
pub const DATETIME_LEN_MAX: usize = 64;
pub const DEV_NAME_LEN_MAX: usize = 32;
pub const DEV_FSTYPE_LEN_MAX: usize = 8;
pub const TOKEN_LEN_MAX: usize = 64;
pub const DBG_LEN_MAX: usize = 16;
pub const UNIX_SOCKET_PATH_MAX: usize = 108;

pub const fn key_pid_ino(p: u64, i: u64) -> u64 {
    (p << 32) | i
}

pub const fn getdev(dev: u64) -> u32 {
    ((dev >> 20) as u32) << 8 | (dev & ((1u64 << 20) - 1)) as u32
}

// define macros for startup requirement checks
pub const CHECK_MAX: usize = 3;
pub const CHECK_MSG_LEN_MAX: usize = 64;

#[derive(Debug)]
enum Check {
    Fail,
    Ok,
    Warn,
}

// define filesystem event info for ringbuffer event handler
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FsEventInfo {
    pub index: c_int,
    pub dentry: *mut core::ffi::c_void,
    pub dentry_old: *mut core::ffi::c_void,
    pub func: *mut c_char,
}

// define common record sent to ringbuffer for user
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Record {
    pub r#type: u32,
    pub ts: u64,
}

#[repr(C)]
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
    pub filename: FileNameUnion,
}

// define ringbuffer stats collected on records
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

// define output types
pub const JSON_SUB_KEY_MAX: usize = 16;
pub const JSON_KEY_LEN_MAX: usize = 32;
pub const JSON_LEGEND_LEN_MAX: usize = 128;
pub const JSON_TYPE_MAX: usize = 3;
pub const JSON_FULL: usize = 0;
pub const JSON_MIN: usize = 1;
pub const TABLE_OUTPUT: usize = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JsonKey {
    pub index: usize,
    pub jtypekey: [[u8; JSON_KEY_LEN_MAX]; JSON_TYPE_MAX],
    pub jlegend: [u8; JSON_LEGEND_LEN_MAX],
}

#[repr(C)]
pub struct JsonSubKey {
    pub index: usize,
    pub sub: [JsonSubKeyEntry; JSON_SUB_KEY_MAX],
}

// define json key index
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IndexJsonKey {
    InfoTimestamp,
    FilePath,
    File,
    FileMode,
    FileEventCount,
    FileEvents,
    FileInode,
    FileInodeLinkCount,
    FileSize,
    FileSizeChange,
    FileAccessTime,
    FileStatusChangeTime,
    FileModificationTime,
    Max,
}

#[repr(C)]
pub struct JsonSubKeyEntry {
    pub jkey: [u8; JSON_KEY_LEN_MAX],
    pub jlegend: [u8; JSON_LEGEND_LEN_MAX],
}

#[repr(C)]
pub union FileNameUnion {
    pub split: core::mem::ManuallyDrop<FileNameSplit>,
    pub full: [u8; FILENAME_LEN_MAX],
}

#[repr(C)]
pub struct FileNameSplit {
    pub filename_from: [u8; FILENAME_LEN_MAX / 2],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2],
}

// JSON container types
#[derive(Debug)]
enum MkjsonContainerType {
    Arr,
    Obj,
}

// JSON data types
#[derive(Debug)]
enum MkjsonValueType {
    String,
    Timestamp,
    Json,
    JsonFree,
    Int,
    LlInt,
    UInt,
    LlUInt,
    Double,
    LDouble,
    SciDouble,
    SciLDouble,
    Bool,
    Null,
    IgnString,
    IgnTimestamp,
    IgnJson,
    IgnInt,
    IgnLlInt,
    IgnUInt,
    IgnLlUInt,
    IgnDouble,
    IgnLDouble,
    IgnBool,
    IgnNull,
}

// define json output messages
#[derive(Debug)]
enum JsonObj {
    Info,
    File,
    Max,
}

pub fn crc64(mut crc: u64, s: &[u8]) -> u64 {
    const CRC64_TAB: &[u64; 256] = &[
    0x0000000000000000, 0x7ad870c830358979, 0xf5b0e190606b12f2, 0x8f689158505e9b8b, 0xc038e5739841b68f,
    0xbae095bba8743ff6, 0x358804e3f82aa47d, 0x4f50742bc81f2d04, 0xab28ecb46814fe75, 0xd1f09c7c5821770c,
    0x5e980d24087fec87, 0x24407dec384a65fe, 0x6b1009c7f05548fa, 0x11c8790fc060c183, 0x9ea0e857903e5a08,
    0xe478989fa00bd371, 0x7d08ff3b88be6f81, 0x07d08ff3b88be6f8, 0x88b81eabe8d57d73, 0xf2606e63d8e0f40a,
    0xbd301a4810ffd90e, 0xc7e86a8020ca5077, 0x4880fbd87094cbfc, 0x32588b1040a14285, 0xd620138fe0aa91f4,
    0xacf86347d09f188d, 0x2390f21f80c18306, 0x594882d7b0f40a7f, 0x1618f6fc78eb277b, 0x6cc0863448deae02,
    0xe3a8176c18803589, 0x997067a428b5bcf0, 0xfa11fe77117cdf02, 0x80c98ebf2149567b, 0x0fa11fe771117cdf0,
    0x75796f2f41224489, 0x3a291b04893d698d, 0x40f16bccb908e0f4, 0xcf99fa94e9567b7f, 0xb5418a5cd963f206,
    0x513912c379682177, 0x2be1620b495da80e, 0xa489f35319033385, 0xde51839b2936bafc, 0x9101f7b0e12997f8,
    0xebd98778d11c1e81, 0x64b116208142850a, 0x1e6966e8b1770c73, 0x8719014c99c2b083, 0xfdc17184a9f739fa,
    0x72a9e0dcf9a9a271, 0x08719014c99c2b08, 0x4721e43f0183060c, 0x3df994f731b68f75, 0xb29105af61e814fe,
    0xc849756751dd9d87, 0x2c31edf8f1d64ef6, 0x56e99d30c1e3c78f, 0xd9810c6891bd5c04, 0xa3597ca0a188d57d,
    0xec09088b6997f879, 0x96d1784359a27100, 0x19b9e91b09fcea8b, 0x636199d339c963f2, 0xdf7adabd7a6e2d6f,
    0xa5a2aa754a5ba416, 0x2aca3b2d1a053f9d, 0x50124be52a30b6e4, 0x1f423fcee22f9be0, 0x659a4f06d21a1299,
    0xeaf2de5e82448912, 0x902aae96b271006b, 0x74523609127ad31a, 0x0e8a46c1224f5a63, 0x81e2d7997211c1e8,
    0xfb3aa75142244891, 0xb46ad37a8a3b6595, 0xceb2a3b2ba0eecec, 0x41da32eaea507767, 0x3b024222da65fe1e,
    0xa2722586f2d042ee, 0xd8aa554ec2e5cb97, 0x57c2c41692bb501c, 0x2d1ab4dea28ed965, 0x624ac0f56a91f461,
    0x1892b03d5aa47d18, 0x97fa21650afae693, 0xed2251ad3acf6fea, 0x095ac9329ac4bc9b, 0x7382b9faaaf135e2,
    0xfcea28a2faafae69, 0x8632586aca9a2710, 0xc9622c4102850a14, 0xb3ba5c8932b0836d, 0x3cd2cdd162ee18e6,
    0x460abd1952db919f, 0x256b24ca6b12f26d, 0x5fb354025b277b14, 0xd0dbc55a0b79e09f, 0xaa03b5923b4c69e6,
    0xe553c1b9f35344e2, 0x9f8bb171c366cd9b, 0x10e3202993385610, 0x6a3b50e1a30ddf69, 0x8e43c87e03060c18,
    0xf49bb8b633338561, 0x7bf329ee636d1eea, 0x012b592653589793, 0x4e7b2d0d9b47ba97, 0x34a35dc5ab7233ee,
    0xbbcbcc9dfb2ca865, 0xc113bc55cb19211c, 0x5863dbf1e3ac9dec, 0x22bbab39d3991495, 0xadd33a6183c78f1e,
    0xd70b4aa9b3f20667, 0x985b3e827bed2b63, 0xe2834e4a4bd8a21a, 0x6debdf121b863991, 0x1733afda2bb3b0e8,
    0xf34b37458bb86399, 0x8993478dbb8deae0, 0x06fbd6d5ebd3716b, 0x7c23a61ddbe6f812, 0x3373d23613f9d516,
    0x49aba2fe23cc5c6f, 0xc6c333a67392c7e4, 0xbc1b436e43a74e9d, 0x95ac9329ac4bc9b5, 0xef74e3e19c7e40cc,
    0x601c72b9cc20db47, 0x1ac40271fc15523e, 0x5594765a340a7f3a, 0x2f4c0692043ff643, 0xa02497ca54616dc8,
    0xdafce7026454e4b1, 0x3e847f9dc45f37c0, 0x445c0f55f46abeb9, 0xcb349e0da4342532, 0xb1eceec59401ac4b,
    0xfebc9aee5c1e814f, 0x8464ea266c2b0836, 0x0b0c7b7e3c7593bd, 0x71d40bb60c401ac4, 0xe8a46c1224f5a634,
    0x927c1cda14c02f4d, 0x1d148d82449eb4c6, 0x67ccfd4a74ab3dbf, 0x289c8961bcb410bb, 0x5244f9a98c8199c2,
    0xdd2c68f1dcdf0249, 0xa7f41839ecea8b30, 0x438c80a64ce15841, 0x3954f06e7cd4d138, 0xb63c61362c8a4ab3,
    0xcce411fe1cbfc3ca, 0x83b465d5d4a0eece, 0xf96c151de49567b7, 0x76048445b4cbfc3c, 0x0cdcf48d84fe7545,
    0x6fbd6d5ebd3716b7, 0x15651d968d029fce, 0x9a0d8ccedd5c0445, 0xe0d5fc06ed698d3c, 0xaf85882d2576a038,
    0xd55df8e515432941, 0x5a3569bd451db2ca, 0x20ed197575283bb3, 0xc49581ead523e8c2, 0xbe4df122e51661bb,
    0x3125607ab548fa30, 0x4bfd10b2857d7349, 0x04ad64994d625e4d, 0x7e7514517d57d734, 0xf11d85092d094cbf,
    0x8bc5f5c11d3cc5c6, 0x12b5926535897936, 0x686de2ad05bcf04f, 0xe70573f555e26bc4, 0x9ddd033d65d7e2bd,
    0xd28d7716adc8cfb9, 0xa85507de9dfd46c0, 0x273d9686cda3dd4b, 0x5de5e64efd965432, 0xb99d7ed15d9d8743,
    0xc3450e196da80e3a, 0x4c2d9f413df695b1, 0x36f5ef890dc31cc8, 0x79a59ba2c5dc31cc, 0x037deb6af5e9b8b5,
    0x8c157a32a5b7233e, 0xf6cd0afa9582aa47, 0x4ad64994d625e4da, 0x300e395ce6106da3, 0xbf66a804b64ef628,
    0xc5bed8cc867b7f51, 0x8aeeace74e645255, 0xf036dc2f7e51db2c, 0x7f5e4d772e0f40a7, 0x05863dbf1e3ac9de,
    0xe1fea520be311aaf, 0x9b26d5e88e0493d6, 0x144e44b0de5a085d, 0x6e963478ee6f8124, 0x21c640532670ac20,
    0x5b1e309b16452559, 0xd476a1c3461bbed2, 0xaeaed10b762e37ab, 0x37deb6af5e9b8b5b, 0x4d06c6676eae0222,
    0xc26e573f3ef099a9, 0xb8b627f70ec510d0, 0xf7e653dcc6da3dd4, 0x8d3e2314f6efb4ad, 0x0256b24ca6b12f26,
    0x788ec2849684a65f, 0x9cf65a1b368f752e, 0xe62e2ad306bafc57, 0x6946bb8b56e467dc, 0x139ecb4366d1eea5,
    0x5ccebf68aecec3a1, 0x2616cfa09efb4ad8, 0xa97e5ef8cea5d153, 0xd3a62e30fe90582a, 0xb0c7b7e3c7593bd8,
    0xca1fc72bf76cb2a1, 0x45775673a732292a, 0x3faf26bb9707a053, 0x70ff52905f188d57, 0x0a2722586f2d042e,
    0x854fb3003f739fa5, 0xff97c3c80f4616dc, 0x1bef5b57af4dc5ad, 0x61372b9f9f784cd4, 0xee5fbac7cf26d75f,
    0x9487ca0fff135e26, 0xdbd7be24370c7322, 0xa10fceec0739fa5b, 0x2e675fb4576761d0, 0x54bf2f7c6752e8a9,
    0xcdcf48d84fe75459, 0xb71738107fd2dd20, 0x387fa9482f8c46ab, 0x42a7d9801fb9cfd2, 0x0df7adabd7a6e2d6,
    0x772fdd63e7936baf, 0xf8474c3bb7cdf024, 0x829f3cf387f8795d, 0x66e7a46c27f3aa2c, 0x1c3fd4a417c62355,
    0x935745fc4798b8de, 0xe98f353477ad31a7, 0xa6df411fbfb21ca3, 0xdc0731d78f8795da, 0x536fa08fdfd90e51,
    0x29b7d047efec8728
];
	
    for &byte in s {
        let i = (crc as u8) ^ byte;
        crc = CRC64_TAB[i as usize] ^ (crc >> 8);
    }
    crc
}
