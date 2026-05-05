#pragma once

#include "common_syscalls.h"

#ifndef COMMON_BIT_OPS_H
#define COMMON_BIT_OPS_H

// ===================== Network Layer =====================
#define SOCKET_SEEN                 (1ULL << 0)
#define LOOPBACK_IPV4_SEEN          (1ULL << 1)
#define CONNECT_SEEN                (1ULL << 2)
#define PRIVATE_IP_SEEN             (1ULL << 3)
#define SUSPICIOUS_PORT_SEEN        (1ULL << 4)
#define EPHEMERAL_PORT_SEEN         (1ULL << 5)
#define SOCKET_MATCH_SEEN           (1ULL << 6)

// ===================== FD Manipulation Layer =====================
#define DUP_SEEN                    (1ULL << 7)
#define DUP2_SEEN                   (1ULL << 8)
#define DUP3_SEEN                   (1ULL << 9)
#define FCNTL_SEEN                  (1ULL << 10)
#define FD_REDERECTS_SEEN           (1ULL << 11)
#define FD_DUPLICATION_SEEN         (1ULL << 12)
#define FD_REWIRING_SEEN            (1ULL << 13)
#define STDIO_HIJACK_SEEN           (1ULL << 14)

// ===================== Process Execution Layer =====================
#define FORK_SEEN                   (1ULL << 15)
#define EXECVE_SEEN                 (1ULL << 16)
#define INTERPRETER_REAL_SEEN       (1ULL << 17)
#define INTERPRETER_ARGV_SEEN       (1ULL << 18)
#define SHELL_INLINE_SEEN           (1ULL << 19)

// ===================== System Interaction Layer =====================
#define OPEN_SEEN                   (1ULL << 20)
#define OPENAT_SEEN                 (1ULL << 21)
#define OPENAT2_SEEN                (1ULL << 22)
#define PTMX_SEEN                   (1ULL << 23)
#define NETWORK_INTENT_SEEN         (1ULL << 24)

#endif