#![no_std]

#[cfg(feature = "user")]
use aya::Pod;
#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

// Constants from C header
pub const FILENAME_LEN_MAX: usize = 32;
pub const FILEPATH_LEN_MAX: usize = 96;
pub const FILEPATH_NODE_MAX: usize = 16;
pub const DNAME_INLINE_LEN: usize = 32;
pub const DBG_LEN_MAX: usize = 128; // Max length for debug messages

// Represents the C enum INDEX_FS_EVENT and the fsevt array
#[repr(u32)] // Ensure the enum has a C-like representation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(Serialize, Deserialize))]
pub enum FsEvent {
    Create = 0,
    Open,
    OpenExec,
    Access,
    Attrib,
    Modify,
    CloseWrite,
    CloseNowrite,
    MovedFrom,
    MovedTo,
    Delete,
    DeleteSelf,
    MoveSelf,
    Unmount,
    QOverflow,
}

// Count of variants in FsEvent
pub const FS_EVENT_MAX: usize = FsEvent::QOverflow as usize + 1;

impl FsEvent {
    pub fn from_u32(value: u32) -> Option<FsEvent> {
        match value {
            0 => Some(FsEvent::Create),
            1 => Some(FsEvent::Open),
            2 => Some(FsEvent::OpenExec),
            3 => Some(FsEvent::Access),
            4 => Some(FsEvent::Attrib),
            5 => Some(FsEvent::Modify),
            6 => Some(FsEvent::CloseWrite),
            7 => Some(FsEvent::CloseNowrite),
            8 => Some(FsEvent::MovedFrom),
            9 => Some(FsEvent::MovedTo),
            10 => Some(FsEvent::Delete),
            11 => Some(FsEvent::DeleteSelf),
            12 => Some(FsEvent::MoveSelf),
            13 => Some(FsEvent::Unmount),
            14 => Some(FsEvent::QOverflow),
            _ => None,
        }
    }

    #[cfg(feature = "user")]
    pub fn name(&self) -> &'static str {
        match self {
            FsEvent::Create => "CREATE",
            FsEvent::Open => "OPEN",
            FsEvent::OpenExec => "OPEN_EXEC",
            FsEvent::Access => "ACCESS",
            FsEvent::Attrib => "ATTRIB",
            FsEvent::Modify => "MODIFY",
            FsEvent::CloseWrite => "CLOSE_WRITE",
            FsEvent::CloseNowrite => "CLOSE_NOWRITE",
            FsEvent::MovedFrom => "MOVED_FROM",
            FsEvent::MovedTo => "MOVED_TO",
            FsEvent::Delete => "DELETE",
            FsEvent::DeleteSelf => "DELETE_SELF",
            FsEvent::MoveSelf => "MOVE_SELF",
            FsEvent::Unmount => "UNMOUNT",
            FsEvent::QOverflow => "Q_OVERFLOW",
        }
    }
}


#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Pod, Debug, Serialize, Deserialize))]
pub struct Record {
    pub type_: u32,
    pub ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Pod, Debug, Serialize, Deserialize))]
pub struct RecordFsFilenamesFromTo {
    pub filename_from: [u8; FILENAME_LEN_MAX / 2],
    pub filename_to: [u8; FILENAME_LEN_MAX / 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Debug))] // aya::Pod might need manual impl for unions. User should handle deserialization.
                                          // serde::Serialize/Deserialize might also need custom impl for unions if default doesn't work as expected.
pub union RecordFsFilenames {
    pub filename: [u8; FILENAME_LEN_MAX],
    pub filenames_from_to: RecordFsFilenamesFromTo,
}

// Manual Pod impl for the union for user space if direct map reading as Pod is needed.
// This is a basic impl; care must be taken for safety and correctness.
#[cfg(feature = "user")]
unsafe impl Pod for RecordFsFilenames {}

// Custom serde for RecordFsFilenames if needed for user-space JSON.
// For now, we rely on user parsing the [u8] or specific union member.

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "user", derive(Pod, Debug))] // Pod for the main struct.
                                                 // serde for this struct will require handling the union_filenames field.
pub struct RecordFs {
    pub rc: Record,
    pub events: u32,
    pub event: [u32; FS_EVENT_MAX], // Array of event counts, indexed by FsEvent enum values
    pub ino: u32,
    pub imode: u32,
    pub inlink: u32,
    pub isize: u64,
    pub atime_nsec: u64,
    pub mtime_nsec: u64,
    pub ctime_nsec: u64,
    pub isize_first: u64,
    pub filepath: [u8; FILEPATH_LEN_MAX],
    pub union_filenames: RecordFsFilenames,
}

#[cfg(feature = "user")]
impl Serialize for RecordFs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("RecordFs", 13)?;
        state.serialize_field("rc", &self.rc)?;
        state.serialize_field("events", &self.events)?;

        // Serialize event array as a map/object for better readability in JSON
        let mut event_map = serde_json::Map::new();
        for i in 0..FS_EVENT_MAX {
            if self.event[i] > 0 {
                if let Some(event_enum) = FsEvent::from_u32(i as u32) {
                    event_map.insert(event_enum.name().to_string(), serde_json::json!(self.event[i]));
                }
            }
        }
        state.serialize_field("event_counts", &event_map)?;

        state.serialize_field("ino", &self.ino)?;
        state.serialize_field("imode", &self.imode)?;
        state.serialize_field("inlink", &self.inlink)?;
        state.serialize_field("isize", &self.isize)?;
        state.serialize_field("atime_nsec", &self.atime_nsec)?;
        state.serialize_field("mtime_nsec", &self.mtime_nsec)?;
        state.serialize_field("ctime_nsec", &self.ctime_nsec)?;
        state.serialize_field("isize_first", &self.isize_first)?;
        state.serialize_field("filepath", &user_string_from_bytes(&self.filepath))?;

        // Determine which part of the union to serialize. This is a simplified example.
        // A common approach is to have a discriminant or rely on context (e.g., specific event type).
        // Here, we'll assume a simple heuristic: if MOVED_TO is set, use from_to. Otherwise, use filename.
        // This matches the C code's implicit logic in handle_event.
        let has_moved_to = self.event[FsEvent::MovedTo as usize] > 0;
        if has_moved_to {
             state.serialize_field("filename_from", &user_string_from_bytes(unsafe { &self.union_filenames.filenames_from_to.filename_from }))?;
             state.serialize_field("filename_to", &user_string_from_bytes(unsafe { &self.union_filenames.filenames_from_to.filename_to }))?;
        } else {
            state.serialize_field("filename", &user_string_from_bytes(unsafe { &self.union_filenames.filename }))?;
        }
        state.end()
    }
}


#[repr(C)]
#[derive(Copy, Clone, Default)]
#[cfg_attr(feature = "user", derive(Pod, Debug, Serialize, Deserialize))]
pub struct Stats {
    pub fs_records: u64,
    pub fs_records_deleted: u64,
    pub fs_records_dropped: u64,
    pub fs_records_rb_max: u64,
    pub fs_events: u64,
}

pub const MONITOR_NONE: u32 = 1;
pub const MONITOR_FILE: u32 = 2;

pub const RECORD_TYPE_FILE: u32 = 1;

#[inline]
pub fn key_pid_ino(pid: u32, ino: u32) -> u64 {
    ((pid as u64) << 32) | (ino as u64)
}

#[cfg(feature = "user")]
pub fn user_string_from_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(
        bytes.iter().take_while(|&&b| b != 0).cloned().collect::<Vec<u8>>().as_slice()
    ).into_owned()
}
