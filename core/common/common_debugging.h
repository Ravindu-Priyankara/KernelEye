#pragma once

// Define DEBUG_MODE=1 to enable prints, 0 to disable {Usage -DDEBUG_MODE=1}
#ifndef DEBUG_MODE
#define DEBUG_MODE 0
#endif

typedef enum debug_categories {
    CONNECT = 0,
    EXECVE,
} debug_categories_t;

static __always_inline void debugging(debug_categories_t category, __u32 pid) {
#if DEBUG_MODE
    switch(category) {
        case CONNECT: {
            bpf_printk("connect called pid=%d\n", pid);
            break;
        }
        case EXECVE: {
            bpf_printk("execve called pid=%d\n", pid);
            break;
        }
        default: {
            break; // do nothing
        }
    }
#endif
}

// Avoid debug categories reordering
_Static_assert(CONNECT == 0, "CONNECT enum changed!");
_Static_assert(EXECVE == 1, "EXECVE enum changed!");