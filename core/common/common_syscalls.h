#pragma once

// used for request types identification
typedef enum {
    OTHER = 0,
    CONNECT,
    EXECVE,
    DUP2,
}common_syscalls;