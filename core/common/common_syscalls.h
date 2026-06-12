#pragma once

#define KE_WINDOW_NS  5000000000ULL  // 5 seconds
#define SIGKILL 9

// used for request types identification
typedef enum {
    OTHER = 0,
    CONNECT,
    EXECVE,
    DUP2,
}common_syscalls;


// macro for only update stage is higher than current one
#define ADVANCE_STAGE(s, new) \
    do {if(*(s) < (new)) *(s) = (new); } while (0)