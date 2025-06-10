/*
 * kflowd.h
 *
 * Authors: Dirk Tennie <dirk@tarsal.co>
 *          Barrett Lyon <blyon@tarsal.co>
 *
 * Copyright 2024 (c) Tarsal, Inc
 *
 */
#ifndef __KFLOWD_H
#define __KFLOWD_H

/* define minimal kernel requirement */
#define KERNEL_VERSION_MIN 5
#define KERNEL_MAJOR_MIN   10

/* define kernel subsystems and switch */
#define MONITOR_NONE 1
#define MONITOR_FILE 2
// MONITOR_SOCK 4 // Removed
#define KPROBE_SWITCH(monitor_type)                                                                                    \
    if (!(monitor & monitor_type))                                                                                     \
        return 0;

/* define file system event values */
#define FS_ACCESS         0x00000001
#define FS_MODIFY         0x00000002
#define FS_ATTRIB         0x00000004
#define FS_CLOSE_WRITE    0x00000008
#define FS_CLOSE_NOWRITE  0x00000010
#define FS_OPEN           0x00000020
#define FS_MOVED_FROM     0x00000040
#define FS_MOVED_TO       0x00000080
#define FS_CREATE         0x00000100
#define FS_DELETE         0x00000200
#define FS_DELETE_SELF    0x00000400
#define FS_MOVE_SELF      0x00000800
#define FS_OPEN_EXEC      0x00001000
#define FS_UNMOUNT        0x00002000
#define FS_Q_OVERFLOW     0x00004000
#define FS_ERROR          0x00008000
#define FS_IN_IGNORED     0x00008000
#define FS_OPEN_PERM      0x00010000
#define FS_ACCESS_PERM    0x00020000
#define FS_OPEN_EXEC_PERM 0x00040000
#define FS_EXCL_UNLINK    0x04000000
#define FS_EVENT_ON_CHILD 0x08000000
#define FS_RENAME         0x10000000
#define FS_DN_MULTISHOT   0x20000000
#define FS_ISDIR          0x40000000
#define FS_IN_ONESHOT     0x80000000 /* only send event once */

/* define file modes */
#define FMODE_READ     0x0000001
#define FMODE_WRITE    0x0000002
#define FMODE_OPENED   0x0080000
#define FMODE_CREATED  0x0100000
#define FMODE_NONOTIFY 0x4000000

/* define dcache types  */
#define DCACHE_ENTRY_TYPE     0x00700000
#define DCACHE_DIRECTORY_TYPE 0x00200000
#define DCACHE_AUTODIR_TYPE   0x00300000

/* define inode mode values */
#define S_IFMT      00170000
#define S_IFSOCK    0140000
#define S_IFLNK     0120000
#define S_IFREG     0100000
#define S_IFBLK     0060000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFIFO     0010000
#define S_ISUID     0004000
#define S_ISGID     0002000
#define S_ISVTX     0001000
#define S_ISLNK(m)  (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

/* define event attribute values */
#define ATTR_MODE      (1 << 0)
#define ATTR_UID       (1 << 1)
#define ATTR_GID       (1 << 2)
#define ATTR_SIZE      (1 << 3)
#define ATTR_ATIME     (1 << 4)
#define ATTR_MTIME     (1 << 5)
#define ATTR_CTIME     (1 << 6)
#define ATTR_ATIME_SET (1 << 7)
#define ATTR_MTIME_SET (1 << 8)
#define ATTR_FORCE     (1 << 9)
#define ATTR_KILL_SUID (1 << 11)
#define ATTR_KILL_SGID (1 << 12)
#define ATTR_FILE      (1 << 13)
#define ATTR_KILL_PRIV (1 << 14)
#define ATTR_OPEN      (1 << 15)
#define ATTR_TIMES_SET (1 << 16)
#define ATTR_TOUCH     (1 << 17)

/* define file system permission values */
#define USER_READ   256
#define USER_WRITE  128
#define USER_EXE    64
#define GROUP_READ  32
#define GROUP_WRITE 16
#define GROUP_EXE   8
#define OTHER_READ  4
#define OTHER_WRITE 2
#define OTHER_EXE   1

/* define file system permissions */
struct FS_PERM {
    short index;
    short value;
    char  perm;
};

/* define permission index */
enum INDEX_FS_PERM {
    I_USER_READ,
    I_USER_WRITE,
    I_USER_EXE,
    I_GROUP_READ,
    I_GROUP_WRITE,
    I_GROUP_EXE,
    I_OTHER_READ,
    I_OTHER_WRITE,
    I_OTHER_EXE
};

/* define filesystem events */
struct FS_EVENT {
    short index;
    short value;
    char  name[16];
    char  shortname[4];
    char  shortname2[4];
};

/* define filesystem event index */
enum INDEX_FS_EVENT {
    I_CREATE,
    I_OPEN,          // Restored for compilation, filter in BPF handles it
    I_OPEN_EXEC,     // Restored for compilation
    I_ACCESS,        // Restored for compilation
    I_ATTRIB,        // Restored for compilation
    I_MODIFY,
    I_CLOSE_WRITE,   // Restored for compilation
    I_CLOSE_NOWRITE, // Restored for compilation
    I_MOVED_FROM,
    I_MOVED_TO,
    I_DELETE,
    I_DELETE_SELF,
    I_MOVE_SELF,
    I_UNMOUNT,
    I_Q_OVERFLOW
};

/* global instance shared betwwwn user and kernel-side code */
struct FS_EVENT fsevt[] = {{I_CREATE, FS_CREATE, "CREATE", "CRE", "CR"},
                           {I_OPEN, FS_OPEN, "OPEN", "OPN", "OP"}, // Restored
                           {I_OPEN_EXEC, FS_OPEN_EXEC, "OPEN_EXEC", "OPX", "OX"}, // Restored
                           {I_ACCESS, FS_ACCESS, "ACCESS", "ACC", "AC"}, // Restored
                           {I_ATTRIB, FS_ATTRIB, "ATTRIB", "ATT", "AT"}, // Restored
                           {I_MODIFY, FS_MODIFY, "MODIFY", "MOD", "MO"},
                           {I_CLOSE_WRITE, FS_CLOSE_WRITE, "CLOSE_WRITE", "CLW", "CW"}, // Restored
                           {I_CLOSE_NOWRITE, FS_CLOSE_NOWRITE, "CLOSE_NOWRITE", "CLN", "CN"}, // Restored
                           {I_MOVED_FROM, FS_MOVED_FROM, "MOVED_FROM", "MVF", "MF"},
                           {I_MOVED_TO, FS_MOVED_TO, "MOVED_TO", "MVT", "MT"},
                           {I_DELETE, FS_DELETE, "DELETE", "DEL", "DE"},
                           {I_DELETE_SELF, FS_DELETE_SELF, "DELETE_SELF", "DSF", "DS"},
                           {I_MOVE_SELF, FS_MOVE_SELF, "MOVE_SELF", "MSF", "MS"},
                           {I_UNMOUNT, FS_UNMOUNT, "UNMOUNT", "UNM", "UM"},
                           {I_Q_OVERFLOW, FS_Q_OVERFLOW, "Q_OVERFLOW", "QOF", "QO"}};

/* define various non-kernel macros */
#define TOLOWER_STR(str)                                                                                               \
    {                                                                                                                  \
        int cnt;                                                                                                       \
        for (cnt = 0; cnt < (int)strlen(str); cnt++)                                                                   \
            str[cnt] = tolower(str[cnt]);                                                                              \
    }
#define MAX(X, Y)                 (((X) > (Y)) ? (X) : (Y))
#define MIN(X, Y)                 (((X) < (Y)) ? (X) : (Y))
#define MAX_STACK_TRACE_DEPTH     16
#define SYS_FILE_JIT_ENABLE       "/proc/sys/net/core/bpf_jit_enable"
#define SYS_FILE_VMLINUX          "/sys/kernel/btf/vmlinux"
#define CACHE_ENTRIES_MAX         65536
#define MAP_RECORDS_MAX           65536
#define MAP_PIDS_MAX              8192
#define RECORD_TYPE_FILE          1
#define TASK_COMM_LEN             32
#define TASK_COMM_SHORT_LEN       16
#define DNAME_INLINE_LEN          32
#define VERSION_LEN_MAX           16
#define IF_MAC_LEN_MAX            20
#define IF_INDEX_LEN_MAX          8
#define FILENAME_LEN_MAX          32
#define FILEPATH_LEN_MAX          96
#define FILEPATH_NODE_MAX         16
#define FILE_READ_LEN_MAX         4096
#define FILE_EVENTS_LEN_MAX       256
#define FILE_PERMS_LEN_MAX        32
#define CMD_LEN_MAX               512
#define CMD_OUTPUT_LEN_MAX        1024
#define JSON_OUT_LEN_MAX          8192
#define FS_EVENT_MAX              (int)(sizeof(fsevt) / sizeof(struct FS_EVENT))
#define MODE_LEN_MAX              12
#define DATETIME_LEN_MAX          64
#define DEV_NAME_LEN_MAX          32
#define DEV_FSTYPE_LEN_MAX        8
#define TOKEN_LEN_MAX             64
#define DBG_LEN_MAX               16
#define KEY_PID_INO(p, i)         ((__u64)p << 32 | i)
#define GETDEV(dev)               ((__u32)(dev >> 20)) << 8 | ((__u32)(dev & ((1U << 20) - 1)))

/* define macros for startup requirement checks */
#define CHECK_MAX         3
#define CHECK_MSG_LEN_MAX 64
enum check { c_fail, c_ok, c_warn };

/* define filesystem event info for ringbuffer event handler */
struct FS_EVENT_INFO {
    int            index;
    struct dentry *dentry;
    struct dentry *dentry_old;
    char          *func;
};

/* define common record sent to ringbuffer for user */
struct RECORD {
    uint32_t type;
    uint64_t ts;
};

/* define filesystem record sent to ringbuffer for user */
struct RECORD_FS {
    struct RECORD rc;
    uint32_t      events;
    uint32_t      event[FS_EVENT_MAX];
    uint32_t      ino;
    uint32_t      imode;
    uint32_t      inlink;
    uint64_t      isize;
    uint64_t      atime_nsec;
    uint64_t      mtime_nsec;
    uint64_t      ctime_nsec;
    uint64_t      isize_first;
    char          filepath[FILEPATH_LEN_MAX];
    union {
        struct {
            char filename_from[FILENAME_LEN_MAX / 2];
            char filename_to[FILENAME_LEN_MAX / 2];
        };
        char filename[FILENAME_LEN_MAX];
    };
};

/* define ringbuffer stats collected on records */
struct STATS {
    uint64_t fs_records;
    uint64_t fs_records_deleted;
    uint64_t fs_records_dropped;
    uint64_t fs_records_rb_max;
    uint64_t fs_events;
};

/* define output types */
#define JSON_SUB_KEY_MAX    16
#define JSON_KEY_LEN_MAX    32
#define JSON_LEGEND_LEN_MAX 128
#define JSON_TYPE_MAX       3
#define JSON_FULL           0
#define JSON_MIN            1
#define TABLE_OUTPUT        2

/* define json key */
struct JSON_KEY {
    int  index;
    char jtypekey[JSON_TYPE_MAX][JSON_KEY_LEN_MAX];
    char jlegend[JSON_LEGEND_LEN_MAX];
};

/* define json sub key */
struct JSON_SUB_KEY {
    int index;
    struct {
        char jkey[JSON_KEY_LEN_MAX];
        char jlegend[JSON_LEGEND_LEN_MAX];
    } sub[JSON_SUB_KEY_MAX];
};

/* define json key index */
enum INDEX_JSON_KEY {
    I_INFO_TIMESTAMP,
    I_FILE_PATH,
    I_FILE,
    I_FILE_MODE,
    I_FILE_EVENT_COUNT,
    I_FILE_EVENTS,
    I_FILE_INODE,
    I_FILE_INODE_LINK_COUNT,
    I_FILE_SIZE,
    I_FILE_SIZE_CHANGE,
    I_FILE_ACCESS_TIME,
    I_FILE_STATUS_CHANGE_TIME,
    I_FILE_MODIFICATION_TIME,
    I_MAX
};

/* JSON macro to get key */
#define JKEY(i) jkey[i].jtypekey[0]

/* JSON container types */
enum MKJSON_CONTAINER_TYPE { MKJ_ARR, MKJ_OBJ };

/* JSON data types */
enum MKJSON_VALUE_TYPE {
    J_STRING,
    J_TIMESTAMP,
    J_JSON,
    J_JSON_FREE,
    J_INT,
    J_LLINT,
    J_UINT,
    J_LLUINT,
    J_DOUBLE,
    J_LDOUBLE,
    J_SCI_DOUBLE,
    J_SCI_LDOUBLE,
    J_BOOL,
    J_NULL,
    J_IGN_STRING,
    J_IGN_TIMESTAMP,
    J_IGN_JSON,
    J_IGN_INT,
    J_IGN_LLINT,
    J_IGN_UINT,
    J_IGN_LLUINT,
    J_IGN_DOUBLE,
    J_IGN_LDOUBLE,
    J_IGN_BOOL,
    J_IGN_NULL
};

/* define json output messages  */
enum JSON_OBJ {
    J_INFO,
    J_FILE,
    JSON_OBJ_MAX
};

/* hash functions */
const uint64_t crc64_tab[256] = {
    0x0000000000000000UL, 0x7ad870c830358979UL, 0xf5b0e190606b12f2UL, 0x8f689158505e9b8bUL, 0xc038e5739841b68fUL,
    0xbae095bba8743ff6UL, 0x358804e3f82aa47dUL, 0x4f50742bc81f2d04UL, 0xab28ecb46814fe75UL, 0xd1f09c7c5821770cUL,
    0x5e980d24087fec87UL, 0x24407dec384a65feUL, 0x6b1009c7f05548faUL, 0x11c8790fc060c183UL, 0x9ea0e857903e5a08UL,
    0xe478989fa00bd371UL, 0x7d08ff3b88be6f81UL, 0x07d08ff3b88be6f8UL, 0x88b81eabe8d57d73UL, 0xf2606e63d8e0f40aUL,
    0xbd301a4810ffd90eUL, 0xc7e86a8020ca5077UL, 0x4880fbd87094cbfcUL, 0x32588b1040a14285UL, 0xd620138fe0aa91f4UL,
    0xacf86347d09f188dUL, 0x2390f21f80c18306UL, 0x594882d7b0f40a7fUL, 0x1618f6fc78eb277bUL, 0x6cc0863448deae02UL,
    0xe3a8176c18803589UL, 0x997067a428b5bcf0UL, 0xfa11fe77117cdf02UL, 0x80c98ebf2149567bUL, 0x0fa11fe771117cdf0UL,
    0x75796f2f41224489UL, 0x3a291b04893d698dUL, 0x40f16bccb908e0f4UL, 0xcf99fa94e9567b7fUL, 0xb5418a5cd963f206UL,
    0x513912c379682177UL, 0x2be1620b495da80eUL, 0xa489f35319033385UL, 0xde51839b2936bafcUL, 0x9101f7b0e12997f8UL,
    0xebd98778d11c1e81UL, 0x64b116208142850aUL, 0x1e6966e8b1770c73UL, 0x8719014c99c2b083UL, 0xfdc17184a9f739faUL,
    0x72a9e0dcf9a9a271UL, 0x08719014c99c2b08UL, 0x4721e43f0183060cUL, 0x3df994f731b68f75UL, 0xb29105af61e814feUL,
    0xc849756751dd9d87UL, 0x2c31edf8f1d64ef6UL, 0x56e99d30c1e3c78fUL, 0xd9810c6891bd5c04UL, 0xa3597ca0a188d57dUL,
    0xec09088b6997f879UL, 0x96d1784359a27100UL, 0x19b9e91b09fcea8bUL, 0x636199d339c963f2UL, 0xdf7adabd7a6e2d6fUL,
    0xa5a2aa754a5ba416UL, 0x2aca3b2d1a053f9dUL, 0x50124be52a30b6e4UL, 0x1f423fcee22f9be0UL, 0x659a4f06d21a1299UL,
    0xeaf2de5e82448912UL, 0x902aae96b271006bUL, 0x74523609127ad31aUL, 0x0e8a46c1224f5a63UL, 0x81e2d7997211c1e8UL,
    0xfb3aa75142244891UL, 0xb46ad37a8a3b6595UL, 0xceb2a3b2ba0eececUL, 0x41da32eaea507767UL, 0x3b024222da65fe1eUL,
    0xa2722586f2d042eeUL, 0xd8aa554ec2e5cb97UL, 0x57c2c41692bb501cUL, 0x2d1ab4dea28ed965UL, 0x624ac0f56a91f461UL,
    0x1892b03d5aa47d18UL, 0x97fa21650afae693UL, 0xed2251ad3acf6feaUL, 0x095ac9329ac4bc9bUL, 0x7382b9faaaf135e2UL,
    0xfcea28a2faafae69UL, 0x8632586aca9a2710UL, 0xc9622c4102850a14UL, 0xb3ba5c8932b0836dUL, 0x3cd2cdd162ee18e6UL,
    0x460abd1952db919fUL, 0x256b24ca6b12f26dUL, 0x5fb354025b277b14UL, 0xd0dbc55a0b79e09fUL, 0xaa03b5923b4c69e6UL,
    0xe553c1b9f35344e2UL, 0x9f8bb171c366cd9bUL, 0x10e3202993385610UL, 0x6a3b50e1a30ddf69UL, 0x8e43c87e03060c18UL,
    0xf49bb8b633338561UL, 0x7bf329ee636d1eeaUL, 0x012b592653589793UL, 0x4e7b2d0d9b47ba97UL, 0x34a35dc5ab7233eeUL,
    0xbbcbcc9dfb2ca865UL, 0xc113bc55cb19211cUL, 0x5863dbf1e3ac9decUL, 0x22bbab39d3991495UL, 0xadd33a6183c78f1eUL,
    0xd70b4aa9b3f20667UL, 0x985b3e827bed2b63UL, 0xe2834e4a4bd8a21aUL, 0x6debdf121b863991UL, 0x1733afda2bb3b0e8UL,
    0xf34b37458bb86399UL, 0x8993478dbb8deae0UL, 0x06fbd6d5ebd3716bUL, 0x7c23a61ddbe6f812UL, 0x3373d23613f9d516UL,
    0x49aba2fe23cc5c6fUL, 0xc6c333a67392c7e4UL, 0xbc1b436e43a74e9dUL, 0x95ac9329ac4bc9b5UL, 0xef74e3e19c7e40ccUL,
    0x601c72b9cc20db47UL, 0x1ac40271fc15523eUL, 0x5594765a340a7f3aUL, 0x2f4c0692043ff643UL, 0xa02497ca54616dc8UL,
    0xdafce7026454e4b1UL, 0x3e847f9dc45f37c0UL, 0x445c0f55f46abeb9UL, 0xcb349e0da4342532UL, 0xb1eceec59401ac4bUL,
    0xfebc9aee5c1e814fUL, 0x8464ea266c2b0836UL, 0x0b0c7b7e3c7593bdUL, 0x71d40bb60c401ac4UL, 0xe8a46c1224f5a634UL,
    0x927c1cda14c02f4dUL, 0x1d148d82449eb4c6UL, 0x67ccfd4a74ab3dbfUL, 0x289c8961bcb410bbUL, 0x5244f9a98c8199c2UL,
    0xdd2c68f1dcdf0249UL, 0xa7f41839ecea8b30UL, 0x438c80a64ce15841UL, 0x3954f06e7cd4d138UL, 0xb63c61362c8a4ab3UL,
    0xcce411fe1cbfc3caUL, 0x83b465d5d4a0eeceUL, 0xf96c151de49567b7UL, 0x76048445b4cbfc3cUL, 0x0cdcf48d84fe7545UL,
    0x6fbd6d5ebd3716b7UL, 0x15651d968d029fceUL, 0x9a0d8ccedd5c0445UL, 0xe0d5fc06ed698d3cUL, 0xaf85882d2576a038UL,
    0xd55df8e515432941UL, 0x5a3569bd451db2caUL, 0x20ed197575283bb3UL, 0xc49581ead523e8c2UL, 0xbe4df122e51661bbUL,
    0x3125607ab548fa30UL, 0x4bfd10b2857d7349UL, 0x04ad64994d625e4dUL, 0x7e7514517d57d734UL, 0xf11d85092d094cbfUL,
    0x8bc5f5c11d3cc5c6UL, 0x12b5926535897936UL, 0x686de2ad05bcf04fUL, 0xe70573f555e26bc4UL, 0x9ddd033d65d7e2bdUL,
    0xd28d7716adc8cfb9UL, 0xa85507de9dfd46c0UL, 0x273d9686cda3dd4bUL, 0x5de5e64efd965432UL, 0xb99d7ed15d9d8743UL,
    0xc3450e196da80e3aUL, 0x4c2d9f413df695b1UL, 0x36f5ef890dc31cc8UL, 0x79a59ba2c5dc31ccUL, 0x037deb6af5e9b8b5UL,
    0x8c157a32a5b7233eUL, 0xf6cd0afa9582aa47UL, 0x4ad64994d625e4daUL, 0x300e395ce6106da3UL, 0xbf66a804b64ef628UL,
    0xc5bed8cc867b7f51UL, 0x8aeeace74e645255UL, 0xf036dc2f7e51db2cUL, 0x7f5e4d772e0f40a7UL, 0x05863dbf1e3ac9deUL,
    0xe1fea520be311aafUL, 0x9b26d5e88e0493d6UL, 0x144e44b0de5a085dUL, 0x6e963478ee6f8124UL, 0x21c640532670ac20UL,
    0x5b1e309b16452559UL, 0xd476a1c3461bbed2UL, 0xaeaed10b762e37abUL, 0x37deb6af5e9b8b5bUL, 0x4d06c6676eae0222UL,
    0xc26e573f3ef099a9UL, 0xb8b627f70ec510d0UL, 0xf7e653dcc6da3dd4UL, 0x8d3e2314f6efb4adUL, 0x0256b24ca6b12f26UL,
    0x788ec2849684a65fUL, 0x9cf65a1b368f752eUL, 0xe62e2ad306bafc57UL, 0x6946bb8b56e467dcUL, 0x139ecb4366d1eea5UL,
    0x5ccebf68aecec3a1UL, 0x2616cfa09efb4ad8UL, 0xa97e5ef8cea5d153UL, 0xd3a62e30fe90582aUL, 0xb0c7b7e3c7593bd8UL,
    0xca1fc72bf76cb2a1UL, 0x45775673a732292aUL, 0x3faf26bb9707a053UL, 0x70ff52905f188d57UL, 0x0a2722586f2d042eUL,
    0x854fb3003f739fa5UL, 0xff97c3c80f4616dcUL, 0x1bef5b57af4dc5adUL, 0x61372b9f9f784cd4UL, 0xee5fbac7cf26d75fUL,
    0x9487ca0fff135e26UL, 0xdbd7be24370c7322UL, 0xa10fceec0739fa5bUL, 0x2e675fb4576761d0UL, 0x54bf2f7c6752e8a9UL,
    0xcdcf48d84fe75459UL, 0xb71738107fd2dd20UL, 0x387fa9482f8c46abUL, 0x42a7d9801fb9cfd2UL, 0x0df7adabd7a6e2d6UL,
    0x772fdd63e7936bafUL, 0xf8474c3bb7cdf024UL, 0x829f3cf387f8795dUL, 0x66e7a46c27f3aa2cUL, 0x1c3fd4a417c62355UL,
    0x935745fc4798b8deUL, 0xe98f353477ad31a7UL, 0xa6df411fbfb21ca3UL, 0xdc0731d78f8795daUL, 0x536fa08fdfd90e51UL,
    0x29b7d047efec8728UL};

static inline uint64_t crc64(uint64_t crc, const unsigned char *s, uint64_t l) {
    uint64_t j;
    for (j = 0; j < l; j++) {
        uint8_t byte = s[j];
        uint8_t i = (uint8_t)crc ^ byte;
        crc = crc64_tab[i] ^ (crc >> 8);
    }
    return crc;
}

#endif /* __KFLOWD_H */
