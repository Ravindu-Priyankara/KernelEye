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
#define OPENPTY_SEEN    (1 << 7)
#define FORKPTY_SEEN    (1 << 8) 
#define EXECVE_SEEN     (1 << 9)   

// stages

enum ke_stage {
    // NEUTRAL
    STAGE_NORMAL = 0,   // NORMAL STAGE

    // SYSCALLS
    STAGE_EXEC,         // SUSPICIOUS EXEC OBSERVED
    STAGE_SOCKET,       // SOCKET CREATED
    STAGE_CONNECT,      // CONNECTION ESTABLISHED
    STAGE_REDIRECTS,    // DUP2/DUP3/FCNTL BASED FD HIJACK HAPPENED

    // FOR ACTIONS
    STAGE_CONFIRMED,    // DETECTING SUSPICIOS PROCESS
    STAGE_BLOCKED       // FOR ENFORCEMENT
};

// macro for only update stage is higher than current one
#define ADVANCE_STAGE(s, new) \
    do {if((s) < (new)) (s) = (new); } while (0)