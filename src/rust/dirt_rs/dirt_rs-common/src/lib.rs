#![no_std]

// Kernel monitoring subsystem types
pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

// Filesystem event flags
pub const FS_ACCESS: u32 = 0x00000001;
pub const FS_MODIFY: u32 = 0x00000002;
pub const FS_ATTRIB: u32 = 0x00000004;
pub const FS_CLOSE_WRITE: u32 = 0x00000008;
pub const FS_CLOSE_NOWRITE: u32 = 0x00000010;
pub const FS_OPEN: u32 = 0x00000020;
pub const FS_MOVED_FROM: u32 = 0x00000040;
pub const FS_MOVED_TO: u32 = 0x00000080;
pub const FS_CREATE: u32 = 0x00000100;
pub const FS_DELETE: u32 = 0x00000200;
pub const FS_DELETE_SELF: u32 = 0x00000400;
pub const FS_MOVE_SELF: u32 = 0x00000800;
pub const FS_OPEN_EXEC: u32 = 0x00001000;
pub const FS_UNMOUNT: u32 = 0x00002000;
pub const FS_Q_OVERFLOW: u32 = 0x00004000;
pub const FS_ERROR: u32 = 0x00008000; // Same as FS_IN_IGNORED
pub const FS_IN_IGNORED: u32 = 0x00008000;
pub const FS_OPEN_PERM: u32 = 0x00010000;
pub const FS_ACCESS_PERM: u32 = 0x00020000;
pub const FS_OPEN_EXEC_PERM: u32 = 0x00040000;
pub const FS_EXCL_UNLINK: u32 = 0x04000000;
pub const FS_EVENT_ON_CHILD: u32 = 0x08000000;
pub const FS_RENAME: u32 = 0x10000000;
pub const FS_DN_MULTISHOT: u32 = 0x20000000;
pub const FS_ISDIR: u32 = 0x40000000;
pub const FS_IN_ONESHOT: u32 = 0x80000000; /* only send event once */

// Length/size constants
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
pub const FS_EVENT_MAX: usize = 15; // Based on the fsevt array in dirt.h
pub const TASK_COMM_LEN: usize = 32;
pub const DBG_LEN_MAX: usize = 16;

// Record types
pub const RECORD_TYPE_FILE: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub enum INDEX_FS_EVENT {
    #[default]
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

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RECORD {
    pub type_: u32, // Renamed from type to type_ to avoid Rust keyword conflict
    pub ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RECORD_FS_FILENAMES {
    pub filename_from: [u8; FILENAME_LEN_MAX / 2],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union RecordFsUnion {
    pub filenames: RECORD_FS_FILENAMES,
    pub filename: [u8; FILENAME_LEN_MAX],
}

// Default for the union needs to be handled carefully.
// One option is to pick a default variant, e.g. filename.
impl Default for RecordFsUnion {
    fn default() -> Self {
        RecordFsUnion {
            filename: [0u8; FILENAME_LEN_MAX],
        }
    }
}

// Custom Debug for RecordFsUnion
impl core::fmt::Debug for RecordFsUnion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Potentially print based on context, or just show one variant
        // For simplicity, let's assume filename is the more common case or a safe default to show
        f.debug_struct("RecordFsUnion")
         .field("filename (first 16 bytes if from/to)", unsafe { &self.filename[..core::cmp::min(self.filename.len(), 16)] }) // Show a snippet
         .finish()
    }
}


#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RECORD_FS {
    pub rc: RECORD,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX], // This was u32 in C struct, but refers to INDEX_FS_EVENT values. Let's keep u32 for direct mapping.
    pub ino: u32,
    pub imode: u32,
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub name_union: RecordFsUnion, // Contains the union
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct STATS {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FS_EVENT_INFO {
    pub index: i32, // C int is typically i32
    pub dentry: u64, // Representing void* or struct dentry* as u64
    pub dentry_old: u64, // Representing void* or struct dentry* as u64
    pub func: [u8; 64], // Representing char* func as a fixed-size buffer for the name
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ProgConfig {
    pub monitor_flags: u32,
    pub pid_self: u32,
    pub pid_shell: u32, // Assuming this is needed based on typical dirt configurations
    pub agg_events_max: u32,
    pub debug_str: [u8; DBG_LEN_MAX],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FsEvent {
    pub index: u16, // Assuming INDEX_FS_EVENT can fit in u16
    pub value: u32, // FS event flag value
    pub name: [u8; 16],
    pub shortname: [u8; 4],
    pub shortname2: [u8; 4],
}
