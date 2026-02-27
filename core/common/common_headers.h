#pragma once

// eBPF helpers & macros
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h> // for bpf_ntohs

#include <linux/types.h>   // __u32, __u16, __u8, __u64
#include <linux/in.h>      // sockaddr_in, sockaddr_in6
#include <linux/socket.h>  // AF_INET, AF_INET6