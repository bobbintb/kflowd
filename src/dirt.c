/*
 * dirt.c
 *
 * Authors: Dirk Tennie <dirk@tarsal.co>
 *          Barrett Lyon <blyon@tarsal.co>
 *
 * Copyright 2024 (c) Tarsal, Inc
 *
 */

#include <stdint.h>
#include "dirt.h"
#include "dirt.skel.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <signal.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <argp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <bpf/libbpf.h>
#include <sys/un.h> // For sockaddr_un

/* help and usage strings */
static char title_str[] = "\e[1m  _     __ _                  _\n"
                          " | | __/ _| | _____      ____| |\n"
                          " | |/ / |_| |/ _ \\ \\ /\\ / / _` |\n"
                          " |   <|  _| | (_) \\ V  V / (_| |\n"
                          " |_|\\_\\_| |_|\\___/ \\_/\\_/ \\__,_|\e[0m  by Tarsal.co\n";

static char header_str[] = "\e[1;33mdirt -- (c) 2024 Tarsal, Inc\e[0m\n"
                           "\e[0;33mKernel-based Process Monitoring via eBPF subsystem (" VERSION ")\e[0m\n";
static char usage_str[] =
    "Usage:\n"
    "  dirt [-e EVENTS] [-o json|json-min] [-x SOCKET_PATH] [-q] [-d] [-V] [-T TOKEN]\n"
    "         [-l] [--legend], [-h] [--help], [--version]\n"
    "  -e EVENTS                Max number of filesystem events per aggregated record until export\n"
    "                             (default: disabled, '1': no aggregation)\n"
    "  -o json                  Json output with formatting (default)\n"
    "     json-min              Json output with minimal formatting \n"
    "  -x SOCKET_PATH           Unix domain socket path to send json output to.\n"
    "                           Output also printed to stdout console unless quiet option -q or\n"
    "                             daemon mode -d specified\n"
    "  -q                       Quiet mode to suppress output to stdout console\n"
    "  -d                       Daemonize program to run in background\n"
    "  -V                       Verbose output\n"
    "                             Print eBPF load and co-re messages on start of eBPF program\n"
    "                             to stderr console\n"
    "  -T TOKEN                 Token specified on host to be included in json output\n"
    "  -l, --legend             Show legend\n"
    "  -h, --help               Show help\n"
    "      --version            Show version\n"
    "  -D PROCESS               Debug\n"
    "                             Print ebpf kernel log messages of process to kernel trace pipe\n"
    "                             (any process: '*', with quotes!)\n"
    "                             Use command:\n"
    "                               'sudo cat /sys/kernel/debug/tracing/trace_pipe'\n\n"
    "Examples:\n"
    "  sudo ./dirt                                                           # terminal mode\n"
    "  sudo ./dirt -x /tmp/dirt.sock -d                                    # daemon mode\n"
    "  sudo ./dirt -V -D '*'                                                 # debug mode\n"
    "  sudo ./dirt --legend                                                  # show legend\n"
    "  sudo ./dirt --version                                                 # show version\n\n";
static char doc_str[] =
    "dirt provides an eBPF program running in Kernel context and its control application running\n"
    "in userspace.\n"
    "The eBPF program traces kernel functions to monitor processes based on filesystem events.\n"
    "Events are aggregated and submitted into a ringbuffer where they are polled by the userspace\n"
    "control application and converted into messages in json output format.\n"
    "Messages are printed to stdout console and can be sent via Unix domain socket to a specified path.\n\n";

static void usage(char *msg) {
    fprintf(stdout, "%s", header_str);
    if (strlen(msg)) {
        fprintf(stdout, "%s", usage_str);
        fprintf(stdout, "\e[1;91m%s%s\e[0m\n", "Error: ", msg);
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "%s", doc_str);
    fprintf(stdout, "%s", usage_str);
    exit(EXIT_SUCCESS);
}
static bool          opt_version = false;
static struct option longopts[] = {{"legend", no_argument, NULL, 'l'},
                                   {"help", no_argument, NULL, 'h'},
                                   {"version", no_argument, (int *)&opt_version, 1},
                                   {"unix-socket", required_argument, NULL, 'x'},
                                   {0, 0, 0, 0}};

/* define globals */
static struct dirt_bpf *skel;
static struct timespec    spec_start;
static volatile bool      running = false;

#define UDP_SERVER_MAX 8

static struct CONFIG {
    int   monitor;
    bool  mode_daemon;
    int   agg_events_max;
    int   output_type;
    char  output_unix_socket_path[UNIX_SOCKET_PATH_MAX];
    bool  output_unix_socket; // Flag to indicate if socket path is set
    bool  output_quiet;       // Generic quiet flag
    bool  verbose;
    char  token[TOKEN_LEN_MAX];
    char  debug[DBG_LEN_MAX];
} config = {0};


static struct JSON_KEY jkey[] = {
    {I_INFO_TIMESTAMP, {"InfoTimestamp"}, "Message timestamp in UTC datetime format with nanoseconds"},
    {I_FILE_PATH, {"FilePath"}, "Directory path name of file"},
    {I_FILE, {"File"}, "File name"},
    {I_FILE_MODE, {"FileMode"}, "Regular file, symbolic link or hard link"},
    {I_FILE_EVENT_COUNT, {"FileEventCount"}, "File event count"},
    {I_FILE_EVENTS, {"FileEvents"}, "File event types and count"},
    {I_FILE_INODE, {"FileInode"}, "Inode number of File"},
    {I_FILE_INODE_LINK_COUNT, {"FileInodeLinkCount"}, "Symbolic link count for inode"},
    {I_FILE_SIZE, {"FileSize"}, "File size in bytes"},
    {I_FILE_SIZE_CHANGE, {"FileSizeChange"}, "File size change in bytes after modification (can be negative)"},
    {I_FILE_ACCESS_TIME, {"FileAccessTime"}, "Access timestamp in UTC"},
    {I_FILE_STATUS_CHANGE_TIME, {"FileStatusChangeTime"}, "Status change timestamp in UTC"},
    {I_FILE_MODIFICATION_TIME, {"FileModificationTime"}, "Modification timestamp in UTC"}
};


static struct JSON_SUB_KEY jsubkeys[] = {
    {I_FILE_EVENTS,
     {{"CREATE", "File created"},
      {"MODIFY", "File modified"},
      {"MOVED_FROM", "File moved or renamed from original name"},
      {"MOVED_TO", "File moved or renamed to new name"},
      {"DELETE", "File deleted"}}}
};

/* static function prototypes */
static int unix_socket_send_msg(char *msg, const char *socket_path);
static char *mkjson(enum MKJSON_CONTAINER_TYPE, int, ...);
static char *mkjson_prettify(const char *, char *);


/* handle signal */
static void sig_handler() {
    if (skel && skel->data) {
        skel->data->monitor = MONITOR_NONE;
    }
    running = false;
}

/* print legend */
static void legend(void) {
    int cntk;
    int cntk_sk;
    int cntsk;
    int nkeys;
    int nkeys_sk;
    int nskeys = 0;
    fprintf(stdout, "%s", header_str);
    nkeys = sizeof(jkey) / sizeof(struct JSON_KEY);
    nkeys_sk = sizeof(jsubkeys) / sizeof(struct JSON_SUB_KEY);

    for (cntk = 0; cntk < nkeys; cntk++)
        for (cntk_sk = 0; cntk_sk < nkeys_sk; cntk_sk++)
            if (jsubkeys[cntk_sk].index == jkey[cntk].index)
                for (cntsk = 0; cntsk < JSON_SUB_KEY_MAX; cntsk++)
                    if (jsubkeys[cntk_sk].sub[cntsk].jkey[0])
                        nskeys++;
    fprintf(stdout, "Legend (%u keys, %u subkeys):\n", nkeys, nskeys);
    for (cntk = 0; cntk < nkeys; cntk++) {
        fprintf(stdout, "  %-26s  %s\n", jkey[cntk].jtypekey[0], jkey[cntk].jlegend);
        for (cntk_sk = 0; cntk_sk < nkeys_sk; cntk_sk++)
            if (jsubkeys[cntk_sk].index == jkey[cntk].index)
                for (cntsk = 0; cntsk < JSON_SUB_KEY_MAX; cntsk++)
                    if (jsubkeys[cntk_sk].sub[cntsk].jkey[0])
                        fprintf(stdout, "   └─ %-23s %s\n", jsubkeys[cntk_sk].sub[cntsk].jkey,
                                jsubkeys[cntk_sk].sub[cntsk].jlegend);
    }
    exit(EXIT_SUCCESS);
}

/* print libbpf debug messages */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !config.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

/* callback event handler for ringbuffer records */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct RECORD      *r = data;
    struct RECORD_FS   *rf = NULL;
    struct tm          *tm;
    char                ts_event_str[DATETIME_LEN_MAX];
    char                ts_atime_str[DATETIME_LEN_MAX];
    char                ts_ctime_str[DATETIME_LEN_MAX];
    char                ts_mtime_str[DATETIME_LEN_MAX];
    char                filename_buf[FILENAME_LEN_MAX] = {0};
    char               *pfilename;
    char               *pfilepath;
    char                mode_str[MODE_LEN_MAX];
    long                time_sec_event;
    int                 events_count = 0;
    char                json_msg_final[JSON_OUT_LEN_MAX] = {0};
    char                json_msg_prettified[JSON_OUT_LEN_MAX] = {0};
    char               *json_out_final;
    int                 len;
    int                 cntf;

    (void)ctx;
    (void)data_sz;

    time_sec_event = r->ts / (uint64_t)1e9;
    tm = gmtime(&time_sec_event);
    len = strftime(ts_event_str, sizeof(ts_event_str), "%Y-%m-%dT%H:%M:%S", tm);
    snprintf(ts_event_str + len, sizeof(ts_event_str) - len,
             ".%09luZ", (r->ts % (uint64_t)1e9));


    if (!(r->type == RECORD_TYPE_FILE))
        return 0;

    rf = (struct RECORD_FS *)r;
    pfilepath = (char *)rf->filepath;

    // Updated logic for pfilename based on I_MOVED_TO event
    if (rf->event[I_MOVED_TO] && rf->filename_to[0]) {
        snprintf(filename_buf, sizeof(filename_buf), "%s>%s", rf->filename_from, rf->filename_to);
        pfilename = filename_buf;
    } else {
        strncpy(filename_buf, (char*)rf->filename, sizeof(filename_buf) - 1);
        filename_buf[sizeof(filename_buf)-1] = '\0'; // Ensure null termination
        pfilename = filename_buf;
    }

    time_sec_event = rf->atime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec_event);
    len = strftime(ts_atime_str, sizeof(ts_atime_str), "%Y-%m-%dT%H:%M:%S", tm);
    snprintf(ts_atime_str + len, sizeof(ts_atime_str) - len,
             ".%09luZ", (rf->atime_nsec % (uint64_t)1e9));

    time_sec_event = rf->mtime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec_event);
    len = strftime(ts_mtime_str, sizeof(ts_mtime_str), "%Y-%m-%dT%H:%M:%S", tm);
    snprintf(ts_mtime_str + len, sizeof(ts_mtime_str) - len,
             ".%09luZ", (rf->mtime_nsec % (uint64_t)1e9));

    time_sec_event = rf->ctime_nsec / (uint64_t)1e9;
    tm = gmtime(&time_sec_event);
    len = strftime(ts_ctime_str, sizeof(ts_ctime_str), "%Y-%m-%dT%H:%M:%S", tm);
    snprintf(ts_ctime_str + len, sizeof(ts_ctime_str) - len,
             ".%09luZ", (rf->ctime_nsec % (uint64_t)1e9));

    snprintf(mode_str, sizeof(mode_str), "%s", S_ISLNK(rf->imode) ? "symlink" : (rf->inlink > 1 ? "hardlink" : "regular"));

    char file_events_json[FILE_EVENTS_LEN_MAX] = {0};
    snprintf(file_events_json, sizeof(file_events_json), "{");
    for (cntf = 0; cntf < FS_EVENT_MAX; ++cntf) {
        if (rf->event[fsevt[cntf].index]) {
            len = strlen(file_events_json);
            snprintf(file_events_json + len, sizeof(file_events_json) - len, "\"%s\": %u, ", fsevt[cntf].name, rf->event[fsevt[cntf].index]);
            events_count += rf->event[fsevt[cntf].index];
        }
    }
    len = strlen(file_events_json);
    if(events_count)
        snprintf(file_events_json + (len - 2), sizeof(file_events_json) - (len - 2), "}");
    else
        snprintf(file_events_json + len, sizeof(file_events_json) - len, "}");

    long long file_size_change = rf->isize - rf->isize_first;

    char *temp_json_out = mkjson(MKJ_OBJ, 13,
        J_STRING, JKEY(I_INFO_TIMESTAMP), ts_event_str,
        J_STRING, JKEY(I_FILE_PATH), pfilepath,
        J_STRING, JKEY(I_FILE), pfilename,
        J_STRING, JKEY(I_FILE_MODE), mode_str,
        J_UINT, JKEY(I_FILE_EVENT_COUNT), rf->events,
        J_JSON, JKEY(I_FILE_EVENTS), file_events_json,
        J_UINT, JKEY(I_FILE_INODE), rf->ino,
        J_UINT, JKEY(I_FILE_INODE_LINK_COUNT), rf->inlink,
        J_LLUINT, JKEY(I_FILE_SIZE), rf->isize,
        J_LLINT, JKEY(I_FILE_SIZE_CHANGE), file_size_change,
        J_STRING, JKEY(I_FILE_ACCESS_TIME), ts_atime_str,
        J_STRING, JKEY(I_FILE_STATUS_CHANGE_TIME), ts_ctime_str,
        J_STRING, JKEY(I_FILE_MODIFICATION_TIME), ts_mtime_str
    );

    if (temp_json_out) {
        strncpy(json_msg_final, temp_json_out, sizeof(json_msg_final) - 1);
        json_msg_final[sizeof(json_msg_final)-1] = '\0'; // Ensure null termination
        free(temp_json_out);
    } else {
        snprintf(json_msg_final, sizeof(json_msg_final), "{\"error\":\"JSON generation failed\"}");
    }

    if(config.output_type == JSON_FULL) {
        mkjson_prettify(json_msg_final, json_msg_prettified);
        json_out_final = json_msg_prettified;
    }
    else {
        json_out_final = json_msg_final;
    }

    if (config.output_unix_socket) {
        unix_socket_send_msg(json_out_final, config.output_unix_socket_path);
        if (config.output_quiet)
            return 0;
    }

    if (!config.mode_daemon) {
        // Print to stdout if not in daemon mode AND
        // ( (unix socket is not configured) OR (unix socket is configured AND quiet mode is NOT set) )
        if (!config.output_unix_socket || (config.output_unix_socket && !config.output_quiet)) {
            fprintf(stdout, "%s", json_out_final);
            fprintf(stdout, "\n%c\n", 0x1e);
        }
        fflush(stdout);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    int                 check[CHECK_MAX] = {c_ok, c_ok, c_ok};
    char                checkmsg[CHECK_MSG_LEN_MAX];
    struct timespec     spec;
    char                cmd_output[CMD_OUTPUT_LEN_MAX] = {0};
    char                cmd[CMD_LEN_MAX] = {0};
    int                 kversion = 0;
    int                 kmajor = 0;
    int                 kminor = 0;
    struct stat         stats_check = {0};
    FILE               *fp = NULL;
    char               *token;
    bool                invalid = false;
    int                 jit_enable = 0;
    int                 err;
    long                pos;
    char               *pport;
    int                 argn = 1;
    int                 cnt;
    int                 opt;

    config.monitor = MONITOR_FILE;
    config.output_type = JSON_FULL;

    struct utsname local_utsn;
    uname(&local_utsn);


    while ((opt = getopt_long(argc, argv, ":e:o:x:qdT:lhVD:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'e':
            config.agg_events_max = atoi(optarg);
            for (cnt = 0; cnt < (int)strlen(optarg); cnt++)
                if (!isdigit(optarg[cnt]))
                    invalid = true;
            if (invalid || config.agg_events_max <= 0) {
                usage("Invalid max number of file system events specified");
            }
            argn += 2;
            break;
        case 'o':
            if (!strncmp(optarg, "json-min", strlen(optarg)))
                config.output_type = JSON_MIN;
            else if (!strncmp(optarg, "json", strlen(optarg)))
                 config.output_type = JSON_FULL;
            else
                usage("Invalid output option specified. Use 'json' or 'json-min'.");
            argn += 2;
            break;
        case 'x':
            if (strlen(optarg) >= UNIX_SOCKET_PATH_MAX)
                usage("Unix socket path too long");
            strncpy(config.output_unix_socket_path, optarg, UNIX_SOCKET_PATH_MAX -1);
            config.output_unix_socket_path[UNIX_SOCKET_PATH_MAX -1] = '\0';
            // TODO: Add a flag like config.output_unix_socket = true if needed for logic elsewhere
    config.output_unix_socket = true;
            argn += 2;
            break;
        case 'q':
    config.output_quiet = true;
            argn++;
            break;
        case 'd':
            config.mode_daemon = true;
            argn++;
            break;
        case 'T':
            if (strlen(optarg) > sizeof(config.token) - 1)
                usage("Invalid token with too many characters specified");
            strncpy(config.token, optarg, sizeof(config.token) - 1);
            argn += 2;
            break;
        case 'l':
            legend();
            break;
        case 'h':
            usage("");
            break;
        case 'V':
            config.verbose = true;
            argn++;
            break;
        case 'D':
            if (strlen(optarg) > sizeof(config.debug) - 1)
                usage("Invalid debug filter with too many characters specified");
            strncpy(config.debug, optarg, sizeof(config.debug) - 1);
            argn += 2;
            break;
        case 0:
            if (opt_version) {
                char dt[DATETIME_LEN_MAX];
                strncpy(dt, DATETIME, DATETIME_LEN_MAX);
                dt[11] = 0x20;
                fprintf(stdout, "dirt " VERSION " (built %s, Linux %s, %s, clang %s, glibc %u.%u, libbpf %s)\n", dt,
                        KERNEL, ARCH, CLANG_VERSION, __GLIBC__, __GLIBC_MINOR__, LIBBPF_VERSION);
            }
            return 0;
        case '?':
            usage("Invalid argument specified");
            break;
        }
    }

    if ((config.mode_daemon || config.output_quiet) && !config.output_unix_socket_path[0])
        usage("Invalid option -d or -q without -x specified");

    if (geteuid()) {
        fprintf(stderr, "Run this program with sudo or as root user\n");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = dirt_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    if (config.mode_daemon) {
        if (daemon(true, true)) {
            fprintf(stderr, "\nFailed to start dirt in daemon mode\n");
            return 1;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &spec);
    skel->rodata->ts_start = (uint64_t)((spec.tv_sec * (uint64_t)1e9) + spec.tv_nsec);
    skel->rodata->agg_events_max = config.agg_events_max;
    memcpy(skel->rodata->debug, config.debug, DBG_LEN_MAX);
    skel->rodata->pid_self = getpid();

    sprintf(cmd, "$(command -v cat) /proc/%u/stat | cut -d\" \" -f4", getppid());
    if ((fp = popen(cmd, "r")) && fgets(cmd_output, sizeof(cmd_output), fp)) {
        skel->rodata->pid_shell = atoi(cmd_output);
        pclose(fp);
    }

    err = dirt_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = dirt_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf_records), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    fprintf(stderr, "%s", title_str);
    fprintf(stderr, "\nRuntime Requirements:\n");
    sscanf(local_utsn.release, "%u.%u.%u", &kversion, &kmajor, &kminor);

    if (kversion < KERNEL_VERSION_MIN || (kversion == KERNEL_VERSION_MIN && kmajor < KERNEL_MAJOR_MIN))
        check[0] = c_fail;
    sprintf(checkmsg, "\e[0;%s\e[0m Kernel version %u.%u+ required", check[0] ? "32m[ok]" : "31m[fail]",
            KERNEL_VERSION_MIN, KERNEL_MAJOR_MIN);
    fprintf(stderr, "%s -> Kernel %u.%u.%u installed\n", checkmsg, kversion, kmajor, kminor);
    int msglen = strlen(checkmsg);

    check[1] = c_fail;
    if (!stat(SYS_FILE_VMLINUX, &stats_check))
        if (stats_check.st_size > 1)
            check[1] = c_ok;
    sprintf(checkmsg, "\e[0;%s\e[0m vmlinux (BTF & CO-RE)", check[1] ? "32m[ok]" : "31m[fail]");
    fprintf(stderr, "%s%*s -> %s at /sys/kernel/btf/vmlinux\n", checkmsg, msglen - (int)strlen(checkmsg), "",
            check[1] ? "Available" : "Not available");

    check[2] = c_fail;
    jit_enable = -1;
    fp = fopen(SYS_FILE_JIT_ENABLE, "r");
    if (fp) {
        if (fscanf(fp, "%u", &jit_enable) != -1) {
            if (jit_enable == 1)
                check[2] = c_ok;
            else if (jit_enable == 2)
                check[2] = c_warn;
            fclose(fp);
        }
    }
    sprintf(checkmsg, "\e[0;%s\e[0m JIT Compiler",
            check[2] == c_warn ? "33m[warn]" : (check[2] ? "32m[ok]" : "31m[fail]"));
    fprintf(stderr, "%s%*s -> %s (net.core.bpf_jit_enable=%d)\n", checkmsg, msglen - (int)strlen(checkmsg), "",
            check[2] == c_warn ? "Enabled with debug" : (check[2] ? "Enabled" : "Disabled"), jit_enable);
    fprintf(stderr, "\n");

    if (!check[0] || !check[1] || !check[2]) {
        fprintf(stderr, "\ndirt failed to start!\n\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "\n");

    fprintf(stderr, "Configuration:\n");
    fprintf(stderr, "\e[0;32m[+]\e[0m Monitored kernel subsystem(s)\n");
    fprintf(stderr, "\e[0;32m[+]\e[0m   \e[0mFile System:     %7u max records at %lu bytes \e[0m\n",
            MAP_RECORDS_MAX, sizeof(struct RECORD_FS));
    fprintf(stderr, "\e[0;%s\e[0m Filesystem aggregation by PID+Inode until\n",
            config.agg_events_max == 1 ? "33m[-]" : "32m[+]");
    fprintf(stderr, "\e[0;%s\e[0m   Finished file operation\n", "32m[+]");
    if (config.agg_events_max)
        fprintf(stderr, "\e[0;32m[+]\e[0m   \e[%sMax number of %.0u%sevent%s\e[0m\n",
                (config.agg_events_max || config.mode_daemon) ? "0m" : "0:37m", config.agg_events_max,
                config.agg_events_max ? " " : "", config.agg_events_max == 1 ? " (no aggregation)" : "s");

    fprintf(stderr, "\e[0;%s\e[0m Output as %s to stdout\n",
            (config.output_unix_socket && (config.mode_daemon || config.output_quiet)) ? "33m[-]" : "32m[+]",
            config.output_type == JSON_FULL    ? "json"
            : "json-min");
    if (config.output_unix_socket)
        fprintf(stderr, "\e[0;32m[+]\e[0m Output to Unix socket %s\n", config.output_unix_socket_path);
    if (config.verbose)
        fprintf(stderr, "\e[0;32m[+]\e[0m Verbose mode for userspace app enabled\n");
    if (config.debug[0])
        fprintf(stderr, "\e[0;32m[+]\e[0m Debug mode for kernel ebpf program enabled. Run command\n"
                        "      'sudo cat /sys/kernel/debug/tracing/trace_pipe'\n");
    fprintf(stderr, "\ndirt (" VERSION ") with PID %u successfully started in %s mode\n\n", skel->rodata->pid_self,
            config.mode_daemon ? "daemon" : "terminal");
    if (!config.mode_daemon && (!config.output_unix_socket || (config.output_unix_socket && !config.output_quiet))) {
        fprintf(stderr, "Press <RETURN> key for output\n");
        while (getchar() != '\n') {
        };
        fprintf(stderr, "\033[A\33[2K\033[A\33[2K\r");
    }

    clock_gettime(CLOCK_REALTIME, &spec_start);
    if (skel && skel->data) {
        skel->data->monitor = config.monitor;
    }
    running = true;

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ringbuffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    dirt_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

static int unix_socket_send_msg(char *msg, const char *socket_path) {
    int sock;
    struct sockaddr_un server_addr;

    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Failed to create unix socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, socket_path, sizeof(server_addr.sun_path) - 1);

    if (sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) < 0) {
        perror("Failed to send message to unix socket");
        close(sock);
        return 1;
    }

    close(sock);
    return 0;
}

static int mkjson_sprintf(char **strp, const char *fmt, ...) {
    int     len;
    va_list ap;
    char   *buf;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    if (len >= 0) {
        buf = malloc(++len);
        if (buf != NULL) {
            va_end(ap);
            va_start(ap, fmt);
            len = vsnprintf(buf, len, fmt, ap);
            if (len >= 0) {
                *strp = buf;
            } else {
                free(buf);
            }
        } else {
            len = -1;
        }
    }
    va_end(ap);
    return len;
}

static char *mkjson_prettify(const char *s, char *r) {
    int  indent = 0;
    bool array = false;
    bool quoted = false;
    bool escaped = false;
    char *start_r = r;

    for (const char *x = s; *x != '\0'; x++) {
        if (r - start_r >= JSON_OUT_LEN_MAX - 5) {
             *(r-1) = 0; *(r-2) = '}'; *(r-3) ='.'; *(r-4) ='.'; *(r-5) ='.';
            break;
        }
        if (*x == '\\' || escaped) {
            escaped = !escaped;
            *r++ = *x;
            continue;
        }
        if (*x == '"')
            quoted = !quoted;
        if (quoted) {
            *r++ = *x;
            continue;
        }
        if (*x == '{') {
            indent += 2;
            array = false;
            *r++ = *x;
            *r++ = '\n';
            for (int i = 0; i < indent; i++)
                *r++ = ' ';
        } else if (*x == '[') {
            if (array == true) {
                *r++ = '\n';
                indent += 2;
                for (int i = 0; i < indent; i++)
                    *r++ = ' ';
            }
            array = true;
            *r++ = *x;
        } else if (*x == ']') {
            if (array == false && *(r - 1) != '}') {
                *r++ = '\n';
                indent -= 2;
                for (int i = 0; i < indent; i++)
                    *r++ = ' ';
            }
            array = false;
            *r++ = *x;
        } else if (*x == '}') {
            indent -= 2;
            array = false;
            *r++ = '\n';
            for (int i = 0; i < indent; i++)
                *r++ = ' ';
            *r++ = *x;
        } else if (*x == ',' && array == false) {
            *r++ = *x;
            *r++ = '\n';
            for (int i = 0; i < indent - 1; i++)
                *r++ = ' ';
        } else if (*x == ':' && array == false) {
            *r++ = *x;
            *r++ = ' ';
        }
        else
            *r++ = *x;
    }
    *r = '\0';
    return r;
}


static char *mkjson(enum MKJSON_CONTAINER_TYPE otype, int count, ...) {
    int                    i, size, len, goodchunks = 0, failure = 0;
    char                  *json_str, *prefix, **chunks, ign_flag;
    enum MKJSON_VALUE_TYPE vtype;
    const char            *key;
    long long int          intval;
    long double            dblval;
    const char            *strval;

    if (count < 0 || (otype != MKJ_OBJ && otype != MKJ_ARR))
        return NULL;

    chunks = calloc(count, sizeof(char *));
    if (chunks == NULL)
        return NULL;

    va_list ap;
    va_start(ap, count);

    for (i = 0; i < count && !failure; i++) {
        vtype = va_arg(ap, enum MKJSON_VALUE_TYPE);
        if (otype == MKJ_OBJ) {
            key = va_arg(ap, char *);
            if (key == NULL) {
                failure = 1;
                break;
            }
        } else
            key = "";

        if (mkjson_sprintf(&prefix, "%s%s%s", otype == MKJ_OBJ ? "\"" : "", key,
                           otype == MKJ_OBJ ? "\": " : "") == -1) {
            failure = 1;
            break;
        }

        ign_flag = 0;
        switch (vtype) {
        case J_IGN_STRING: case J_IGN_TIMESTAMP: case J_IGN_JSON:
            (void)va_arg(ap, const char *); ign_flag = 1; break;
        case J_IGN_INT: case J_IGN_LLINT:
            if (vtype == J_IGN_INT) (void)va_arg(ap, int); else (void)va_arg(ap, long long int);
            ign_flag = 1; break;
        case J_IGN_UINT: case J_IGN_LLUINT:
            if (vtype == J_IGN_UINT) (void)va_arg(ap, unsigned int); else (void)va_arg(ap, unsigned long long int);
            ign_flag = 1; break;
        case J_IGN_DOUBLE: case J_IGN_LDOUBLE:
            if (vtype == J_IGN_DOUBLE) (void)va_arg(ap, double); else (void)va_arg(ap, long double);
            ign_flag = 1; break;
        case J_IGN_BOOL: (void)va_arg(ap, int); ign_flag = 1; break;
        case J_IGN_NULL: ign_flag = 1; break;
        case J_STRING:
            strval = va_arg(ap, const char *);
            if (mkjson_sprintf(chunks + i, "%s\"%s\"", prefix, strval ? strval : "null") == -1) chunks[i] = NULL;
            break;
        case J_TIMESTAMP:
            strval = va_arg(ap, const char *);
            if (mkjson_sprintf(chunks + i, "%s\"%s\"", prefix, strval ? strval : "null") == -1) chunks[i] = NULL; // Timestamps as strings in JSON
            break;
        case J_JSON:
            strval = va_arg(ap, const char *);
            if (mkjson_sprintf(chunks + i, "%s%s", prefix, strval ? strval : "null") == -1) chunks[i] = NULL;
            break;
        case J_INT: case J_LLINT:
            if (vtype == J_INT) intval = va_arg(ap, int); else intval = va_arg(ap, long long int);
            if (mkjson_sprintf(chunks + i, "%s%lld", prefix, intval) == -1) chunks[i] = NULL;
            break;
        case J_UINT: case J_LLUINT:
            if (vtype == J_UINT) intval = va_arg(ap, unsigned int); else intval = va_arg(ap, unsigned long long int);
            if (mkjson_sprintf(chunks + i, "%s%llu", prefix, (unsigned long long)intval) == -1) chunks[i] = NULL;
            break;
        case J_DOUBLE: case J_LDOUBLE:
            if (vtype == J_DOUBLE) dblval = va_arg(ap, double); else dblval = va_arg(ap, long double);
            if (mkjson_sprintf(chunks + i, "%s%Lf", prefix, dblval) == -1) chunks[i] = NULL;
            break;
        case J_SCI_DOUBLE: case J_SCI_LDOUBLE:
            if (vtype == J_SCI_DOUBLE) dblval = va_arg(ap, double); else dblval = va_arg(ap, long double);
            if (mkjson_sprintf(chunks + i, "%s%Le", prefix, dblval) == -1) chunks[i] = NULL;
            break;
        case J_BOOL:
            intval = va_arg(ap, int);
            if (mkjson_sprintf(chunks + i, "%s%s", prefix, intval ? "true" : "false") == -1) chunks[i] = NULL;
            break;
        case J_NULL:
            if (mkjson_sprintf(chunks + i, "%snull", prefix) == -1) chunks[i] = NULL;
            break;
        default: chunks[i] = NULL; break;
        }
        free(prefix);
        if (!ign_flag && chunks[i] == NULL) failure = 1;
        if (ign_flag) chunks[i] = NULL;
        else goodchunks++;
    }
    va_end(ap);

    if (!failure) {
        size = 0;
        for (i = 0; i < count; i++) if (chunks[i]) size += strlen(chunks[i]);
        if (goodchunks == 0) goodchunks = 1;
        size = size + 2 + (goodchunks > 0 ? (goodchunks - 1) * 2 : 0);
        json_str = calloc(size + 1, sizeof(char));
        if (json_str) {
            json_str[0] = otype == MKJ_OBJ ? '{' : '[';
            len = 1;
            for (i = 0; i < count; i++) {
                if (chunks[i]) {
                    if(len > 1 && json_str[len-1] != '{' && json_str[len-1] != '[') {
                         snprintf(json_str + len, size + 1 - len, ", ");
                         len += 2;
                    }
                    snprintf(json_str + len, size + 1 - len, "%s", chunks[i]);
                    len += strlen(chunks[i]);
                }
            }
            json_str[len++] = otype == MKJ_OBJ ? '}' : ']';
            json_str[len] = '\0';
        }
    } else json_str = NULL;

    for (i = 0; i < count; i++) free(chunks[i]);
    free(chunks);
    return json_str;
}
