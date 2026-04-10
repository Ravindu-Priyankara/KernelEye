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
#define SOCKET_FLAG     (1 << 0)    // 0001
#define CONNECT_FLAG    (1 << 1)    // 0010
#define DUP2_FLAG       (1 << 2)    // 0100
#define EXECVE_FLAG     (1 << 3)    // 1000

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