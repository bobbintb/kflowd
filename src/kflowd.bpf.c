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
const volatile __u64 target_dev;
volatile __u32       monitor = MONITOR_NONE;

/* debug helpers for process debugging and kernel stack */
static __always_inline void debug_dump_stack(void *, const char *);
static __always_inline bool debug_proc(char *, char *);
static __always_inline bool debug_file_is_tp(char *);
const volatile char         debug[DBG_LEN_MAX];

/* handle all filesystem events for aggregation */
static __always_inline int handle_fs_event(void *ctx, const struct FS_EVENT_INFO *event) {
    // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
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
    pid_t               pid;
    __u64               ts_event = bpf_ktime_get_ns();
    __u64               ts_now;
    __u32               num_nodes = 0;
    __u32               offset = 0;
    __u32               len = 0;
    __u64               key;
    __u32               zero = 0;
    __u32               index;
    __u32               ino;
    __u32               cnt;

    // Filter out ACCESS and ATTRIB events as they are no longer needed
    if (event->index == I_ACCESS || event->index == I_ATTRIB) {
        return 0;
    }

    pid = bpf_get_current_pid_tgid() >> 32;

    if (pid_self == pid)
        return 0;

    index = event->index;
    dentry = event->dentry;
    dentry_old = event->dentry_old;
    func = event->func;

    inode = BPF_CORE_READ((dentry_old ? dentry_old : dentry), d_inode);
    bpf_probe_read_kernel_str(filename, sizeof(filename), BPF_CORE_READ(dentry, d_name.name));
    if (!inode || !filename[0])
        return 0;

    // Get the superblock from the inode
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) {
        // Optional: could add a counter for debugging if sb is unexpectedly NULL
        return 0;
    }

    // Get the device ID from the superblock
    __u64 event_dev = BPF_CORE_READ(sb, s_dev); // Assuming s_dev is compatible with __u64

    // Filter based on device ID
    if (event_dev != target_dev) {
        // Optional: could add a counter for events filtered out
        return 0;
    }

    ino = BPF_CORE_READ(inode, i_ino);
    imode = BPF_CORE_READ(inode, i_mode);
    if (!(S_ISREG(imode) || S_ISLNK(imode)))
        return 0;

    key = KEY_PID_INO(pid, ino);
    r = bpf_map_lookup_elem(&hash_records, &key);
    s = bpf_map_lookup_elem(&stats, &zero);

    if (r) {
        if (fsevt[index].value == FS_MOVED_TO) {
            __builtin_memset(r->filename_to - 1, 0, sizeof(r->filename_to) + 1);
            bpf_probe_read_kernel_str(&r->filename_to, sizeof(r->filename_to), BPF_CORE_READ(dentry, d_name.name));
        }
        r->rc.ts = ts_event;
    } else {
        r = bpf_map_lookup_elem(&heap_record_fs, &zero);
        if (!r) {
            return 0;
        }

        r->rc.ts = ts_event;

        r->ino = ino;
        __builtin_memset(r->filename, 0, sizeof(r->filename));
        bpf_probe_read_kernel_str(&r->filename, sizeof(r->filename), BPF_CORE_READ(dentry, d_name.name));
        r->isize_first = BPF_CORE_READ(inode, i_size);

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
        r->inlink = 0;

        if (s)
            s->fs_records++;
    }
    if (s)
        s->fs_events++;

    r->imode = imode;
    r->isize = BPF_CORE_READ(inode, i_size);
    r->inlink = BPF_CORE_READ(inode, i_nlink);
    if (index == I_CREATE && dentry_old)
        r->inlink++;
    r->atime_nsec = BPF_CORE_READ(inode, i_atime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_atime_nsec);
    r->mtime_nsec = BPF_CORE_READ(inode, i_mtime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_mtime_nsec);
    r->ctime_nsec = BPF_CORE_READ(inode, i_ctime_sec) * (u64)1e9 + BPF_CORE_READ(inode, i_ctime_nsec);
    r->events++;
    r->event[index]++;

    if (bpf_map_update_elem(&hash_records, &key, r, BPF_ANY) < 0) {
        return 0;
    }

    agg_end = false;
    if (index == I_CLOSE_WRITE || index == I_CLOSE_NOWRITE || index == I_DELETE || index == I_MOVED_TO ||
        (index == I_CREATE && (S_ISLNK(imode) || r->inlink > 1)))
        agg_end = true;
    if (!agg_end && agg_events_max)
        if (r->events >= agg_events_max)
            agg_end = true;

    if (agg_end) {
        r->rc.type = RECORD_TYPE_FILE;
        __u32 output_len = sizeof(*r);
        if (bpf_ringbuf_output(&ringbuf_records, r, output_len, 0)) {
            if (s)
                s->fs_records_dropped++;
        }
        if (bpf_map_delete_elem(&hash_records, &key)) {
            return 0;
        }
        if (s)
            s->fs_records_deleted++;
    }

    if ((s = bpf_map_lookup_elem(&stats, &zero))) {
        __u64 rsz = sizeof(*r);
        rsz += (8 - rsz % 8);
        if (s->fs_records == 1) {
            s->fs_records_rb_max = bpf_ringbuf_query(&ringbuf_records, BPF_RB_RING_SIZE) / rsz;
        }
    }
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
    if (!(S_ISLNK(imode) && ino && dentry_symlink == dentry))
        return 0;
    dentry_symlink = NULL;
    struct FS_EVENT_INFO event = {I_CREATE, dentry, NULL, "dput+security_inode_symlink"};
    handle_fs_event(ctx, &event);
    return 0;
}

/* kprobe for FS_ATTRIB, FS_ACCESS and FS_MODIFY eventis */
SEC("kprobe/notify_change")
int BPF_KPROBE(notify_change, struct dentry *dentry, struct iattr *attr) {
    KPROBE_SWITCH(MONITOR_FILE);
    __u32 mask = 0;

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


/* kprobe for FS_MOVED_FROM snd FS_MOVED_TO event */
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(security_inode_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,
               struct dentry *new_dentry) {
    KPROBE_SWITCH(MONITOR_FILE);
    if (((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_DIRECTORY_TYPE) ||
        ((BPF_CORE_READ(old_dentry, d_flags) & DCACHE_ENTRY_TYPE) == DCACHE_AUTODIR_TYPE))
        return 0;
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
static long                 debug_stack[MAX_STACK_TRACE_DEPTH] = {0};
static __always_inline void debug_dump_stack(void *ctx, const char *func) {
    long                kstacklen;
    __u32               cnt;

    kstacklen = bpf_get_stack(ctx, debug_stack, MAX_STACK_TRACE_DEPTH * sizeof(long), 0);
    if (kstacklen > 0) {
        bpf_printk("KERNEL STACK (%u): %s  ", (kstacklen / sizeof(long)), func);
        for (cnt = 0; cnt < MAX_STACK_TRACE_DEPTH; cnt++) {
            if (kstacklen > cnt * sizeof(long))
                bpf_printk("  %pB", (void *)debug_stack[cnt]);
        }
    }
}

bool debug_file_is_tp(char *filename) {
    char tp[] = "trace_pipe";
    int  cnt;
    if (filename) {
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++)
            if (filename[cnt] != tp[cnt])
                break;
            else if (cnt == sizeof(tp) - 1)
                return true;
    }
    return false;
}

bool debug_proc(char *comm, char *filename) {
    int cnt;
    if (!comm) {
        if (debug[0] == 'q' && !debug[1])
            return true;
        else
            return false;
    }
    if (debug[0] != '*')
        for (cnt = 0; cnt < DBG_LEN_MAX; cnt++)
            if (!comm[0] || comm[cnt] != debug[cnt])
                return false;
    if (debug_file_is_tp(filename))
        return false;
    return true;
}
