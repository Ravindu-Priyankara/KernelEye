#pragma once

// Core kernel structs + CO-RE (Compile Once – Run Everywhere)
#include "vmlinux.h"

// eBPF helpers & macros
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>