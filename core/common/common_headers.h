#pragma once

// Core kernel structs + CO-RE (Compile Once – Run Everywhere)
#include "vmlinux.h"

// eBPF helpers & macros
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// for socket based things
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>