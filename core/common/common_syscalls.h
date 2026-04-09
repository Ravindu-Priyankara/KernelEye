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

#define normal 0
#define suspicious 1
#define confirmed_revsh 2
#define blocked 3