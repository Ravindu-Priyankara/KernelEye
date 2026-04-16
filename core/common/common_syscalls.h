#pragma once

#define DECAY_INTERVAL_NS  5000000000ULL  // 5 seconds
#define DECAY_STEP         2              // subtract 2 points per interval

// used for request types identification
typedef enum {
    OTHER = 0,
    CONNECT,
    EXECVE,
    DUP2,
}common_syscalls;

// Bitmask Flags
#define OTHER 0
/*
*   The connect syscall can be bypassed. So we decided to track the socket also.
*   The order will be changed during the code cleaning stage.
*/
#define SOCKET_SEEN                 (1 << 0)    // 0001
#define LOOPBACK_IPV4_SEEN          (1 << 1)
#define CONNECT_SEEN                (1 << 2)    // 0010
#define PRIVATE_IP_SEEN             (1 << 3)
#define SUSPICIOUS_PORT_SEEN        (1 << 4)
#define EPHEMERAL_PORT_SEEN         (1 << 5)
#define SOCKET_MATCH_SEEN           (1 << 6)
#define DUP_SEEN                    (1 << 7)
#define DUP2_SEEN                   (1 << 8)  
#define DUP3_SEEN                   (1 << 9)  
#define FCNTL_SEEN                  (1 << 10)
#define FD_REDERECTS_SEEN           (1 << 11)  
#define FD_DUPLICATION_SEEN         (1 << 12)
#define FD_REWIRING_SEEN            (1 << 13)
#define STDIO_HIJACK_SEEN           (1 << 14)
#define FORK_SEEN                   (1 << 15)
#define OPEN_SEEN                   (1 << 16)
#define OPENAT_SEEN                 (1 << 17)
#define OPENAT2_SEEN                (1 << 18) 
#define PTMX_SEEN                   (1 << 19)
#define EXECVE_SEEN                 (1 << 20)
#define INTERPRETER_REAL_SEEN       (1 << 21)
#define INTERPRETER_ARGV_SEEN       (1 << 22)
#define NETWORK_INTENT_SEEN         (1 << 23)
#define SHELL_INLINE_SEEN           (1 << 24)

// stages

enum ke_stage {
    STAGE_NORMAL = 0,
    STAGE_SUSPICIOUS = 10,
    STAGE_BEHAVIORAL = 20,
    STAGE_HIGH_RISK = 30,
    STAGE_CONFIRMED = 40,
    STAGE_BLOCKED = 50
};

// macro for only update stage is higher than current one
#define ADVANCE_STAGE(s, new) \
    do {if(*(s) < (new)) *(s) = (new); } while (0)