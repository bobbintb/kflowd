/*
 * kflowd.bpf.c
 *
 * Authors: Dirk Tennie <dirk@tarsal.co>
 *          Barrett Lyon <blyon@tarsal.co>
 *
 * Copyright 2024 (c) Tarsal, Inc
 *
 */
#include "vmlinux.h"
#include "kflowd.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL v2";

/* bpf maps */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(struct RECORD_FS) * 8192);
} ringbuf_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAP_RECORDS_MAX);
    __type(key, __u64);
    __type(value, struct RECORD_FS);
} hash_records SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct RECORD_FS);
} heap_record_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct STATS);
} stats SEC(".maps");

/* glabal variables shared with userspace */
const volatile __u64 ts_start;
const volatile __u32 agg_events_max;
const volatile pid_t pid_self;
const volatile pid_t pid_shell;
volatile __u32       monitor = MONITOR_NONE;

/* debug helpers for process debugging and kernel stack */
static __always_inline void debug_dump_stack(void *, const char *);
static __always_inline bool debug_proc(char *, char *);
static __always_inline bool debug_file_is_tp(char *);
const volatile char         debug[DBG_LEN_MAX];

/* handle all filesystem events for aggregation */
static __always_inline int handle_fs_event(void *ctx, const struct FS_EVENT_INFO *event) {
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task(); // Keep if ppid or gppid needed for pid_shell
    struct dentry      *dentry;
    struct dentry      *dentry_old;
    struct inode       *inode;
    struct dentry      *dparent;
    struct RECORD_FS   *r;
    struct STATS       *s;
    const __u8         *dname;
    const __u8         *pathnode[FILEPATH_NODE_MAX] = {0};
    char                filename[FILENAME_LEN_MAX] = {0};
    char               *func;
    bool                agg_end;
    umode_t             imode;
    // pid_t               gppid; // Potentially remove if task is removed
    // pid_t               ppid;  // Potentially remove if task is removed
    pid_t               pid;
    // pid_t               tid;   // Removed
    __u64               ts_event = bpf_ktime_get_ns(); // Renamed from ts to avoid confusion if r->rc.ts is kept for event time
    __u64               ts_now;
    __u32               num_nodes = 0;
    __u32               offset = 0;
    __u32               len = 0;
    __u64               key;
    __u32               zero = 0;
    __u32               index;
    __u32               ino;
    __u32               cnt;

    pid = bpf_get_current_pid_tgid() >> 32;

    // Simplified pid_shell check: if pid_shell is configured (>1), we might still need ppid/gppid
    // For now, assume pid_shell logic might be simplified or removed later if ppid/gppid are hard to get without task
    // If pid_shell check is vital, 'task' and ppid/gppid reads need to stay.
    // Let's assume for now the check is simplified to only use pid_self.
    // if (pid_self == pid || (pid_shell > 1 && (pid_shell == ppid || pid_shell == gppid)))
    if (pid_self == pid) // Simplified check
        return 0;


    index = event->index;
    dentry = event->dentry;
    dentry_old = event->dentry_old;
    func = event->func;

    inode = BPF_CORE_READ((dentry_old ? dentry_old : dentry), d_inode);
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    if (!inode || !filename[0])
        return 0;

    ino = BPF_CORE_READ(inode, i_ino);
    imode = BPF_CORE_READ(inode, i_mode);
    if (!(S_ISREG(imode) || S_ISLNK(imode)))
        return 0;

    key = KEY_PID_INO(pid, ino); // Still using pid from bpf_get_current_pid_tgid()
    r = bpf_map_lookup_elem(&hash_records, &key);
    s = bpf_map_lookup_elem(&stats, &zero);

    if (r) {
        if (fsevt[index].value == FS_MOVED_TO) {
            __builtin_memset(r->filename_to - 1, 0, sizeof(r->filename_to) + 1);
            bpf_probe_read_kernel_str(&r->filename_to, sizeof(r->filename_to), BPF_CORE_READ(dentry, d_name.name));
        }
        r->rc.ts = ts_event; // Update timestamp of existing record
    } else {
        r = bpf_map_lookup_elem(&heap_record_fs, &zero);
        if (!r) {
            // bpf_printk("WARNING: Failed to allocate new filesystem record for pid %u\n", pid); // pid still available
            return 0;
        }
        // r->rc.pid = pid; // Removed
        // r->rc.tid = tid; // Removed
        // r->rc.ppid = ppid; // Removed
        // r->rc.uid = bpf_get_current_uid_gid(); // Removed
        // r->rc.gid = bpf_get_current_uid_gid() >> 32; // Removed
        // __builtin_memset(r->rc.proc, 0, sizeof(r->rc.proc)); // Removed
        // bpf_get_current_comm(&r->rc.proc, sizeof(r->rc.proc)); // Removed
        // __builtin_memset(r->rc.comm, 0, sizeof(r->rc.comm)); // Removed
        // bpf_probe_read_kernel_str(&r->rc.comm, sizeof(r->rc.comm), BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name)); // Removed
        // __builtin_memset(r->rc.comm_parent, 0, sizeof(r->rc.comm_parent)); // Removed
        // bpf_probe_read_kernel_str(&r->rc.comm_parent, sizeof(r->rc.comm_parent), BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_name.name)); // Removed

        r->rc.ts = ts_event; // Set initial timestamp
        // r->rc.ts_first = ts_event; // Removed

        r->ino = ino;
        __builtin_memset(r->filename, 0, sizeof(r->filename));
        bpf_probe_read_kernel_str(&r->filename, sizeof(r->filename), BPF_CORE_READ(dentry, d_name.name));
        r->isize_first = BPF_CORE_READ(inode, i_size);
        // r->mtime_nsec_first = BPF_CORE_READ(inode, i_mtime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_mtime_nsec); // Removed

        for (cnt = 0; cnt < FILEPATH_NODE_MAX; cnt++) {
            dname = BPF_CORE_READ(dentry, d_name.name);
            dparent = BPF_CORE_READ(dentry, d_parent);
            pathnode[cnt] = dname;
            if (BPF_CORE_READ(dentry, d_inode, i_ino) == BPF_CORE_READ(dparent, d_inode, i_ino))
                break;
            dentry = dparent;
        }
        num_nodes = 0;
        if (cnt < FILEPATH_NODE_MAX)
            num_nodes = cnt;
        __builtin_memset(r->filepath, 0, sizeof(r->filepath));
        for (cnt = num_nodes; cnt > 0; cnt--) {
            if (pathnode[cnt] && offset < (sizeof(r->filepath) - DNAME_INLINE_LEN)) {
                len = bpf_probe_read_kernel_str(&r->filepath[offset], sizeof(r->filepath) - DNAME_INLINE_LEN,
                                                (void *)pathnode[cnt]);
                if (len && offset < (sizeof(r->filepath)) - len) {
                    offset += (len - 1);
                    if (cnt != num_nodes && offset < (sizeof(r->filepath))) {
                        r->filepath[offset] = '/';
                        offset++;
                    }
                }
            }
        }

        r->events = 0;
        for (cnt = 0; cnt < FS_EVENT_MAX; ++cnt)
            r->event[cnt] = 0;
        r->inlink = 0; // Initialize if it was previously relying on create event increment

        if (s)
            s->fs_records++;
    }
    if (s)
        s->fs_events++;

    // r->rc.age = r->rc.ts - BPF_CORE_READ(task, start_time); // Removed
    r->imode = imode;
    r->isize = BPF_CORE_READ(inode, i_size);
    r->inlink = BPF_CORE_READ(inode, i_nlink);
    if (index == I_CREATE && dentry_old)
        r->inlink++;
    // r->iuid = BPF_CORE_READ(inode, i_uid.val); // Removed
    // r->igid = BPF_CORE_READ(inode, i_gid.val); // Removed
    // r->idev = GETDEV(BPF_CORE_READ(inode, i_sb, s_dev)); // Removed
    r->atime_nsec = BPF_CORE_READ(inode, i_atime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_atime_nsec);
    r->mtime_nsec = BPF_CORE_READ(inode, i_mtime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_mtime_nsec);
    r->ctime_nsec = BPF_CORE_READ(inode, i_ctime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_ctime_nsec);
    r->events++;
    r->event[index]++;

    if (bpf_map_update_elem(&hash_records, &key, r, BPF_ANY) < 0) {
        // if (!debug_file_is_tp(r->filename)) // r->rc.comm removed, so debug_proc might need adjustment or removal here
            // bpf_printk("WARNING: Failed to create or update record for key %u-%u", pid, ino);
        return 0;
    }

    agg_end = false;
    if (index == I_CLOSE_WRITE || index == I_CLOSE_NOWRITE || index == I_DELETE || index == I_MOVED_TO ||
        (index == I_CREATE && (S_ISLNK(imode) || r->inlink > 1))) // r->inlink check should be fine
        agg_end = true;
    if (!agg_end && agg_events_max)
        if (r->events >= agg_events_max)
            agg_end = true;

    if (agg_end) {
        r->rc.type = RECORD_TYPE_FILE;
        __u32 output_len = sizeof(*r);
        if (bpf_ringbuf_output(&ringbuf_records, r, output_len, 0)) {
            // __u64 rbsize = bpf_ringbuf_query(&ringbuf_records, BPF_RB_RING_SIZE); // Keep for debug
            // __u64 rbdata = bpf_ringbuf_query(&ringbuf_records, BPF_RB_AVAIL_DATA); // Keep for debug
            // if (!debug_file_is_tp(r->filename)) { // Debug related
                // bpf_printk("WARNING: Failed to submit record to ringbuffer for key %u-%u", pid, ino);
                // bpf_printk("Ringbuffer size is %lu (%lu records)", rbsize, rbsize / sizeof(*r));
                // bpf_printk("Ringbuffer unconsumed data is %lu (%lu records)\n", rbdata, rbdata / sizeof(*r));
            // }
            if (s)
                s->fs_records_dropped++;
        }
        if (bpf_map_delete_elem(&hash_records, &key)) {
            // if (!debug_file_is_tp(r->filename)) // Debug related
                // bpf_printk("WARNING: Failed to delete record for key %u-%u", pid, ino);
            return 0;
        }
        if (s)
            s->fs_records_deleted++;
    }

    /* debug */
    // All debug prints using r->rc.comm, r->rc.gid, r->rc.uid, r->rc.tid, r->rc.ppid need to be removed or updated
    // if (!debug_proc(r->rc.comm, r->filename)) // r->rc.comm removed
    //     return 0;
    // bpf_printk("KPROBE:    %s", func);
    // if (S_ISLNK(imode) || r->inlink > 1)
    //     bpf_printk("FS_EVENT:  LINK_%s  %s  #%u", fsevt[index].name, r->filename, r->events);
    // else
    //     bpf_printk("FS_EVENT:  FILE_%s  %s  #%u", fsevt[index].name, r->filename, r->events);
    // bpf_printk("COMM:      %s  GID: %u  UID: %u", r->rc.comm, r->rc.gid, r->rc.uid); // Removed fields
    // bpf_printk("PID/INO:   %u/%u %s in hashmap", pid, ino, r->rc.ts ? "" : "NOT"); // pid still available
    // bpf_printk("TID:       %u  PPID: %u", r->rc.tid, r->rc.ppid); // Removed fields
    if ((s = bpf_map_lookup_elem(&stats, &zero))) {
        __u64 rsz = sizeof(*r);
        rsz += (8 - rsz % 8);
        if (s->fs_records == 1) {
            s->fs_records_rb_max = bpf_ringbuf_query(&ringbuf_records, BPF_RB_RING_SIZE) / rsz;
        }
        // __u64 records_rb_curr = bpf_ringbuf_query(&ringbuf_records, BPF_RB_AVAIL_DATA) / rsz;
        // __u64 records_rb_in = bpf_ringbuf_query(&ringbuf_records, BPF_RB_PROD_POS) / rsz;
        // __u64 records_rb_out = bpf_ringbuf_query(&ringbuf_records, BPF_RB_CONS_POS) / rsz;
        // ts_now = bpf_ktime_get_ns();
        // if ((ts_now - ts_start) > (u64)1e9) {
            // bpf_printk("RECORDS        Total (%lu sec, %lu events)", (ts_now - ts_start) / (u64)1e9, s->fs_events);
            // bpf_printk("  Created      %lu   %lu/sec", s->fs_records, (s->fs_records * (u64)1e9) / (ts_now - ts_start));
            // bpf_printk("  Deleted      %lu", s->fs_records_deleted);
            // bpf_printk("  Dropped      %lu", s->fs_records_dropped);
            // bpf_printk("  Ringbuf-in   %lu   %lu/sec", records_rb_in, (records_rb_in * (u64)1e9) / (ts_now - ts_start));
            // bpf_printk("  Ringbuf-out  %lu   %lu/sec", records_rb_out,
                       // (records_rb_out * (u64)1e9) / (ts_now - ts_start));
            // bpf_printk("  Ringbuf-@    %lu pct (%lu/%lu)", (records_rb_curr * 100) / s->fs_records_rb_max,
                       // records_rb_curr, s->fs_records_rb_max);
        // }
    }
    // debug_dump_stack(ctx, func); // This can stay if ctx and func are still valid
    // ts_now = bpf_ktime_get_ns();
    // bpf_printk("KPROBE processed in %lus %luns\n", (ts_now - ts_event) / (u64)1e9, (ts_now - ts_event) % (u64)1e9);

    return 0;
}

/* kretprobe for FS_CREATE event of regular file */
SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(do_filp_open, struct file *filp) {
    KPROBE_SWITCH(MONITOR_FILE);
    if (BPF_CORE_READ(filp, f_mode) & FMODE_CREATED) {
        struct FS_EVENT_INFO event = {I_CREATE, BPF_CORE_READ(filp, f_path.dentry), NULL, "do_filp_open"};
        handle_fs_event(ctx, &event);
    }
    return 0;
}

/* kprobe for FS_CREATE event of hard link */
SEC("kprobe/security_inode_link")
int BPF_KPROBE(security_inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_CREATE, new_dentry, old_dentry, "security_inode_link"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* dependent kprobes for FS_CREATE event of symbolic link */
struct dentry *dentry_symlink = NULL;
SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(security_inode_symlink, struct inode *dir, struct dentry *dentry, const char *old_name) {
    KPROBE_SWITCH(MONITOR_FILE);
    dentry_symlink = dentry;
    return 0;
}
SEC("kprobe/dput")
int BPF_KPROBE(dput, struct dentry *dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    int imode = BPF_CORE_READ(dentry, d_inode, i_mode);
    int ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    /* only continue for existing symbolic link */
    if (!(S_ISLNK(imode) && ino && dentry_symlink == dentry))
        return 0;
    dentry_symlink = NULL;
    struct FS_EVENT_INFO event = {I_CREATE, dentry, NULL, "dput+security_inode_symlink"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_OPEN event */
SEC("kprobe/fd_install")
int BPF_KPROBE(fd_install, unsigned int fd, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_OPEN, BPF_CORE_READ(file, f_path.dentry), NULL, "fd_install"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_OPEN_EXEC event */
SEC("kretprobe/do_open_execat")
int BPF_KRETPROBE(do_open_execat, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_OPEN_EXEC, BPF_CORE_READ(file, f_path.dentry), NULL, "do_open_execat"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_ACCESS event */
SEC("kprobe/__kernel_read")
int BPF_KPROBE(__kernel_read, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_ACCESS, BPF_CORE_READ(file, f_path.dentry), NULL, "__kernel_read"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_ATTRIB, FS_ACCESS and FS_MODIFY eventis */
SEC("kprobe/notify_change")
int BPF_KPROBE(notify_change, struct dentry *dentry, struct iattr *attr) {
    KPROBE_SWITCH(MONITOR_FILE);
    __u32 mask = 0;

    /* get attribute mask */
    int ia_valid = BPF_CORE_READ(attr, ia_valid);
    if (ia_valid & ATTR_UID)
        mask |= FS_ATTRIB;
    if (ia_valid & ATTR_GID)
        mask |= FS_ATTRIB;
    if (ia_valid & ATTR_SIZE)
        mask |= FS_MODIFY;
    if ((ia_valid & (ATTR_ATIME | ATTR_MTIME)) == (ATTR_ATIME | ATTR_MTIME))
        mask |= FS_ATTRIB;
    else if (ia_valid & ATTR_ATIME)
        mask |= FS_ACCESS;
    else if (ia_valid & ATTR_MTIME)
        mask |= FS_MODIFY;
    if (ia_valid & ATTR_MODE)
        mask |= FS_ATTRIB;

    /* handle event */
    if (mask & FS_ATTRIB) {
        struct FS_EVENT_INFO event_attrib = {I_ATTRIB, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_attrib);
    }
    if (mask & FS_MODIFY) {
        struct FS_EVENT_INFO event_modify = {I_MODIFY, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_modify);
    }
    if (mask & FS_ACCESS) {
        struct FS_EVENT_INFO event_access = {I_ACCESS, dentry, NULL, "notify_change"};
        handle_fs_event(ctx, &event_access);
    }

    return 0;
}

/* kprobe for FS_ATTRIB and FS_MODIFY events */
SEC("kprobe/__fsnotify_parent")
int BPF_KPROBE(__fsnotify_parent, struct dentry *dentry, __u32 mask, const void *data, int data_type) {
    KPROBE_SWITCH(MONITOR_FILE);
    if (mask & FS_ATTRIB) {
        struct FS_EVENT_INFO event_attrib = {I_ATTRIB, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_attrib);
    }
    if (mask & FS_MODIFY) {
        struct FS_EVENT_INFO event_modify = {I_MODIFY, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_modify);
    }
    if (mask & FS_ACCESS) {
        struct FS_EVENT_INFO event_access = {I_ACCESS, dentry, NULL, "__fsnotify_parent"};
        handle_fs_event(ctx, &event_access);
    }
    return 0;
}

/* kprobe for CLOSE_WRITE, CLOSE_NOWRITE events */
SEC("kprobe/__fput")
int BPF_KPROBE(__fput, struct file *file) {
    KPROBE_SWITCH(MONITOR_FILE);
    int                  nowrite = !(BPF_CORE_READ(file, f_mode) & FMODE_WRITE);
    struct FS_EVENT_INFO event = {nowrite ? I_CLOSE_NOWRITE : I_CLOSE_WRITE, BPF_CORE_READ(file, f_path.dentry), NULL,
                                  "__fput"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_MOVED_FROM snd FS_MOVED_TO event */
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(security_inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
               struct dentry *new_dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    /* check if dir */
    if (((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE) ||
        ((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE))
        return 0;
    /* handle both events */
    struct FS_EVENT_INFO event_from = {I_MOVED_FROM, old_dentry, NULL, "security_inode_rename"};
    handle_fs_event(ctx, &event_from);
    struct FS_EVENT_INFO event_to = {I_MOVED_TO, new_dentry, old_dentry, "security_inode_rename"};
    handle_fs_event(ctx, &event_to);
    return 0;
}

/* kprobe for FS_DELETE event */
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(security_inode_unlink, struct inode *dir, struct dentry *dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    struct FS_EVENT_INFO event = {I_DELETE, dentry, NULL, "security_inode_unlink"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* DEBUG */
/* debug helper function to dump kernel stack */
static long                 debug_stack[MAX_STACK_TRACE_DEPTH] = {0};
static __always_inline void debug_dump_stack(void *ctx, const char *func) {
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task(); // Not strictly needed for stack dump
    long                kstacklen;
    __u32               cnt;

    kstacklen = bpf_get_stack(ctx, debug_stack, MAX_STACK_TRACE_DEPTH * sizeof(long), 0);
    if (kstacklen > 0) {
        bpf_printk("KERNEL STACK (%u): %s  ", (kstacklen / sizeof(long)), func);
        for (cnt = 0; cnt < MAX_STACK_TRACE_DEPTH; cnt++) {
            if (kstacklen > cnt * sizeof(long)) /* check needed for bpf verifier */
                bpf_printk("  %pB", (void *)debug_stack[cnt]);
        }
    }
}

/* debug helper function to detect trace pipe */
bool debug_file_is_tp(char *filename) {
    char tp[] = "trace_pipe";
    int  cnt;

    /* check file for trace_pipe */
    if (filename) {
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++) /* strcmp not available */
            if (filename[cnt] != tp[cnt])
                break;
            else if (cnt == sizeof(tp) - 1)
                return true;
    }

    return false;
}

/* debug helper function to print debug messages based on process */
bool debug_proc(char *comm, char *filename) {
    int cnt;

    /* filter debug prints on queue when comm is null */
    if (!comm) { // This will be true if r->rc.comm was removed and debug_proc is called with NULL
        if (debug[0] == 'q' && !debug[1])
            return true;
        else
            return false;
    }

    /* filter debug prints on process name */
    if (debug[0] != '*')
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++) /* strcmp not available */
            if (!comm[0] || comm[cnt] != debug[cnt]) // comm[0] check might be problematic if comm is not guaranteed to be null-terminated after removal
                return false;

    /* always omit debug for trace_pipe file itself */
    if (debug_file_is_tp(filename))
        return false;

    return true;
}

#if 0
/* debug kprobe to detect file events using fsnotify userspace api */
SEC("kprobe/fsnotify")
int BPF_KPROBE(fsnotify, __u32 mask, void *data, int data_type, struct inode *inoded, const struct qstr *file_name) {
    struct inode       *inode;
    struct task_struct *task;
    struct event       *e;
    __u8                comm[TASK_COMM_LEN];
    pid_t               pid;
    __u32               uid;
    __u32               gid;
    __u32               ino;
    umode_t             imode;
    __u64               key;
    __u32               zero = 0;
    int                 index = -1;
    __u32               cnt;

    if (!(file_name && (data_type == FSNOTIFY_EVENT_INODE || data_type == FSNOTIFY_EVENT_PATH)))
        return 0;
    for (cnt = 0; cnt < FS_EVENT_MAX; ++cnt)
        if (mask & fsevt[cnt].value)
            index = cnt;
    if (index < 0)
        return 0;

    /* get comm, pid, uid and gid */
    bpf_get_current_comm(comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;
    uid = bpf_get_current_uid_gid() >> 32;
    gid = bpf_get_current_uid_gid();

    /* get inode from data */
    if (data_type == FSNOTIFY_EVENT_INODE) {
        inode = (struct inode *)data;
    } else if (data_type == FSNOTIFY_EVENT_PATH) {
        struct path *path = (struct path *)data;
        inode = BPF_CORE_READ(path, dentry, d_inode);
    }
    ino = BPF_CORE_READ(inode, i_ino);

    /* validate inode mode (file or link)) */
    imode = BPF_CORE_READ(inode, i_mode);
    if (!(S_ISREG(imode) || S_ISLNK(imode)))
        return 0;

    bpf_printk("FS_NOTIFY: %s (ino=%u)", BPF_CORE_READ(file_name, name), ino);
    debug_dump_stack(ctx, "FS_NOTIFY");

    return 0;
}
#endif
