#![no_std]
#![no_main]

use dirt_common::constants::*;

use core::{mem, ptr, slice};
use core::ffi::c_void;

use aya_ebpf::{
    macros::{map, kprobe, kretprobe},
    maps::{Array, PerCpuArray, LruHashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
    bindings::*,
    helpers::{
        bpf_get_current_pid_tgid,
        bpf_get_stack,
        bpf_ktime_get_ns,
        bpf_map_lookup_elem,
        bpf_map_update_elem,
        bpf_map_delete_elem,
        bpf_probe_read_kernel_str_bytes,
        bpf_ringbuf_output,
        bpf_ringbuf_query,
        bpf_printk,
    },
};

use aya_log_ebpf::info;

use crate::{RECORD_FS, STATS};

#[map(name = "ringbuf_records")]
static mut RINGBUF_RECORDS: RingBuf = RingBuf::new();

#[map(name = "hash_records")]
static mut HASH_RECORDS: HashMap<u64, RECORD_FS> = HashMap::new();

#[map(name = "heap_record_fs")]
static mut HEAP_RECORD_FS: PerCpuArray<RECORD_FS> = PerCpuArray::new();

#[map(name = "stats")]
static mut STATS: Array<STATS> = Array::new();

#[no_mangle]
static mut ts_start: u64 = 0;

#[no_mangle]
static mut agg_events_max: u32 = 0;

#[no_mangle]
static mut pid_self: pid_t = 0;

#[no_mangle]
static mut pid_shell: pid_t = 0;

#[no_mangle]
static mut monitor: u32 = MONITOR_NONE;

#[inline(always)]
fn handle_fs_event(ctx: *mut c_void, event: *const FsEventInfo) -> i32 {
    unsafe {
        if (*event).index == I_ACCESS || (*event).index == I_ATTRIB {
            return 0;
        }

        let pid = bpf_get_current_pid_tgid() >> 32;
        if pid_self == pid {
            return 0;
        }

        let index = (*event).index;
        let mut dentry = (*event).dentry;
        let dentry_old = (*event).dentry_old;
        let func = (*event).func;

        let inode = bpf_core_read(
            if !dentry_old.is_null() { dentry_old } else { dentry },
            b"__d_inode\0",
        ) as *const Inode;

        let mut filename = [0u8; FILENAME_LEN_MAX];
        bpf_probe_read_kernel_str_bytes(&mut filename, bpf_core_read(dentry, b"d_name.name\0") as *const u8);

        if inode.is_null() || filename[0] == 0 {
            return 0;
        }

        let ino = unsafe { (*inode).i_ino };
        let imode = unsafe { (*inode).i_mode };
        if !(s_isreg(imode) || s_islnk(imode)) {
            return 0;
        }

        let key = key_pid_ino(pid, ino);
        let r = bpf_map_lookup_elem(&HASH_RECORDS, &key) as *mut RecordFs;
        let s = bpf_map_lookup_elem(&STATS, &0u32) as *mut Stats;

        if !r.is_null() {
            if fsevt[index as usize].value == FS_MOVED_TO {
                core::ptr::write_bytes((*r).filename_to.as_mut_ptr(), 0, (*r).filename_to.len());
                bpf_probe_read_kernel_str_bytes(&mut (*r).filename_to, bpf_core_read(dentry, b"d_name.name\0") as *const u8);
            }
            (*r).rc.ts = bpf_ktime_get_ns();
        } else {
            let r = bpf_map_lookup_elem(&HEAP_RECORD_FS, &0u32) as *mut RecordFs;
            if r.is_null() {
                return 0;
            }

            (*r).rc.ts = bpf_ktime_get_ns();
            (*r).ino = ino;
            core::ptr::write_bytes((*r).filename.as_mut_ptr(), 0, (*r).filename.len());
            bpf_probe_read_kernel_str_bytes(&mut (*r).filename, bpf_core_read(dentry, b"d_name.name\0") as *const u8);
            (*r).isize_first = bpf_core_read(inode, b"i_size\0") as u64;

            let mut pathnode: [*const u8; FILEPATH_NODE_MAX] = core::mem::zeroed();
            let mut cnt = 0;
            while cnt < FILEPATH_NODE_MAX {
                let dname = bpf_core_read(dentry, b"d_name.name\0") as *const u8;
                let dparent = bpf_core_read(dentry, b"d_parent\0") as *const Dentry;
                pathnode[cnt] = dname;
                if bpf_core_read(dentry, b"d_inode.i_ino\0") == bpf_core_read(dparent, b"d_inode.i_ino\0") {
                    break;
                }
                dentry = dparent;
                cnt += 1;
            }

            let num_nodes = if cnt < FILEPATH_NODE_MAX { cnt } else { 0 };
            core::ptr::write_bytes((*r).filepath.as_mut_ptr(), 0, (*r).filepath.len());

            let mut offset = 0;
            for cnt in (1..=num_nodes).rev() {
                let node = pathnode[cnt];
                if !node.is_null() && offset < ((*r).filepath.len() - DNAME_INLINE_LEN) {
                    let len = bpf_probe_read_kernel_str_bytes(
                        &mut (*r).filepath[offset..],
                        node,
                    );
                    if len > 0 && offset < ((*r).filepath.len() - len) {
                        offset += len - 1;
                        if cnt != num_nodes && offset < (*r).filepath.len() {
                            (*r).filepath[offset] = b'/';
                            offset += 1;
                        }
                    }
                }
            }

            (*r).events = 0;
            for e in (*r).event.iter_mut() {
                *e = 0;
            }
            (*r).inlink = 0;

            if !s.is_null() {
                (*s).fs_records += 1;
            }
        }

        if !s.is_null() {
            (*s).fs_events += 1;
        }

        (*r).imode = imode;
        (*r).isize = bpf_core_read(inode, b"i_size\0") as u64;
        (*r).inlink = bpf_core_read(inode, b"i_nlink\0") as u32;
        if index == I_CREATE && !dentry_old.is_null() {
            (*r).inlink += 1;
        }
        (*r).atime_nsec = (bpf_core_read(inode, b"i_atime_sec\0") as u64) * 1_000_000_000
            + (bpf_core_read(inode, b"i_atime_nsec\0") as u64);
        (*r).mtime_nsec = (bpf_core_read(inode, b"i_mtime_sec\0") as u64) * 1_000_000_000
            + (bpf_core_read(inode, b"i_mtime_nsec\0") as u64);
        (*r).ctime_nsec = (bpf_core_read(inode, b"i_ctime_sec\0") as u64) * 1_000_000_000
            + (bpf_core_read(inode, b"i_ctime_nsec\0") as u64);

        (*r).events += 1;
        (*r).event[index as usize] += 1;

        if bpf_map_update_elem(&HASH_RECORDS, &key, r as *const _, BPF_ANY) < 0 {
            return 0;
        }

        let mut agg_end = false;
        if index == I_CLOSE_WRITE || index == I_CLOSE_NOWRITE || index == I_DELETE || index == I_MOVED_TO
            || (index == I_CREATE && (s_islnk(imode) || (*r).inlink > 1)) {
            agg_end = true;
        }

        if !agg_end && agg_events_max != 0 && (*r).events >= agg_events_max {
            agg_end = true;
        }

        if agg_end {
            (*r).rc.type_ = RECORD_TYPE_FILE;
            let output_len = core::mem::size_of_val(&*r) as u32;
            if bpf_ringbuf_output(&RINGBUF_RECORDS, r as *const _, output_len, 0) != 0 {
                if !s.is_null() {
                    (*s).fs_records_dropped += 1;
                }
            }
            if bpf_map_delete_elem(&HASH_RECORDS, &key) != 0 {
                return 0;
            }
            if !s.is_null() {
                (*s).fs_records_deleted += 1;
            }
        }

        if let Some(s) = bpf_map_lookup_elem(&STATS, &0u32) {
            let mut rsz = core::mem::size_of_val(&*r) as u64;
            rsz += 8 - (rsz % 8);
            if (*s).fs_records == 1 {
                (*s).fs_records_rb_max = bpf_ringbuf_query(&RINGBUF_RECORDS, BPF_RB_RING_SIZE) / rsz;
            }
        }

        0
    }
}





#[kretprobe]
pub fn do_filp_open(ctx: RetProbeContext) -> u32 {
    try_dirt1(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_link(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_symlink(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn dput(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn notify_change(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn __fsnotify_parent(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_rename(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

#[kprobe]
pub fn security_inode_unlink(ctx: ProbeContext) -> u32 {
    try_dirt(ctx).unwrap_or(0)
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kprobe called");
    Ok(0)
}

fn try_dirt1(ctx: RetProbeContext) -> Result<u32, u32> {
    info!(&ctx, "kretprobe called");
    Ok(0)
}



static mut DEBUG_STACK: [i64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[inline(always)]
fn debug_dump_stack(ctx: *mut core::ffi::c_void, func: *const u8) {
    unsafe {
        let kstacklen = bpf_get_stack(
            ctx,
            DEBUG_STACK.as_mut_ptr() as *mut _,
            (MAX_STACK_TRACE_DEPTH * core::mem::size_of::<i64>()) as i32,
            0,
        );

        if kstacklen > 0 {
            bpf_printk!(
                b"KERNEL STACK (%u): %s\0",
                (kstacklen / core::mem::size_of::<i64>()) as u32,
                func
            );

            for cnt in 0..MAX_STACK_TRACE_DEPTH {
                if kstacklen > (cnt * core::mem::size_of::<i64>()) as i64 {
                    bpf_printk!(b"  %pB\0", DEBUG_STACK[cnt] as *const _);
                }
            }
        }
    }
}

fn debug_file_is_tp(filename: *const u8) -> bool {
    let tp = b"trace_pipe";
    unsafe {
        if !filename.is_null() {
            for cnt in 0..DBG_LEN_MAX {
                let fc = *filename.add(cnt);
                let tc = *tp.get(cnt).unwrap_or(&0);
                if fc != tc {
                    break;
                } else if cnt == tp.len() - 1 {
                    return true;
                }
            }
        }
    }
    false
}

fn debug_proc(comm: *const u8, filename: *const u8) -> bool {
    unsafe {
        if comm.is_null() {
            return debug[0] == b'q' && debug[1] == 0;
        }

        if debug[0] != b'*' {
            for cnt in 0..DBG_LEN_MAX {
                if *comm.add(0) == 0 || *comm.add(cnt) != debug[cnt] {
                    return false;
                }
            }
        }

        if debug_file_is_tp(filename) {
            return false;
        }

        true
    }
}




#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
