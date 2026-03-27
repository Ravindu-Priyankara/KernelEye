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
#define CONNECT_FLAG    (1 << 0)    // 0001
#define DUP2_FLAG       (1 << 1)    // 0010
#define EXECVE_FLAG     (1 << 2)    // 0100