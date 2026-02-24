#pragma once

#include <stddef.h>

/*************************************
******* Events Holding Structs *******
**************************************/

// This struct use for tracking connect events with hashmap
// Total byte count is 24 bytes
struct connect_event{
    __u32 ppid; // parent process id {4 bytes}
    __u32 ip;   // connect ip {4 bytes}
    __u64 net_ts;   // timestamp {8 byte}
    __u16 port; // connect port {2 byte}
    // compiler will fill 6 bytes of padding
};

/*************************************
******* Events Streaming Structs *****
**************************************/


//This struct used for alerting suspicious processes {mainly reverse shells}
// Total bytes count is 288 bytes
struct reverse_shell_event_alert{
    //common fields
    __u32 pid;  // process id {4 bytes}
    __u32 ppid; // parent process id {4 bytes}
    // execve fields
    char filename[256]; // execve has filename {256 bytes}
    __u64 execve_ts;    // timestamp for execve {8 bytes}
    //  connect fields
    __u64  net_ts; // connect timestamp {8 bytes}
    __u32 ip;   // connect ip address {4 bytes}
    __u16 port; // connect port {2 bytes}
    //compiler will fill 2 bytes of padding
};

/*************************************
******* Struct Validations ***********
**************************************/

// connect_event must remain 24 bytes (aligned to 8)
_Static_assert(sizeof(struct connect_event) == 24,"connect_event size mismatch!");

// Layout must remain 288 bytes (8-byte aligned).
// If fields change and size differs, fail compilation.
_Static_assert(sizeof(struct reverse_shell_event_alert) == 288,"reverse_shell_event_alert size mismatch!");

//  Stop reordering structs
_Static_assert(offsetof(struct reverse_shell_event_alert, net_ts) == 272,"net_ts offset changed!");