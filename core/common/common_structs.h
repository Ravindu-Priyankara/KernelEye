#pragma once

// This struct use for tracking connect events with hashmap
struct net_event{
    __u32 ppid; // parent process id {4 bytes}
    __u32 ip;   // connect ip {4 bytes}
    __u16 port; // connect port {2 byte}
    __u64 ts;   // timestamp {8 byte}
    // total = 18 bytes, need 6 bytes for alignment
    __u8 padding[6]; // total 24 bytes
};