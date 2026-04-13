#pragma once

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
*/
#define SOCKET_SEEN     (1 << 0)    // 0001
#define CONNECT_SEEN    (1 << 1)    // 0010
#define DUP_SEEN        (1 << 2)
#define DUP2_SEEN       (1 << 3)  
#define DUP3_SEEN       (1 << 4)  
#define FCNTL_SEEN      (1 << 5)
#define FORK_SEEN       (1 << 6)
#define EXECVE_SEEN     (1 << 7)
#define OPEN_SEEN       (1 << 8)
#define OPENAT_SEEN     (1 << 9)
#define OPENAT2_SEEN    (1 << 10) 
#define PTMX_SEEN       (1 << 11)  

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
    do {if((s) < (new)) (s) = (new); } while (0)