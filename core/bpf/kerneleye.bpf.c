#include "../common/common_headers.h"
#include "../common/common_structs.h"
#include "../common/common_validation.h"
#include "../common/common_status.h"
#include "../common/common_debugging.h"
#include "../common/common_syscalls.h"

#include "../helpers/event_helpers.h"
#include "../helpers/common_helpers.h"
#include "../helpers/connect_helpers.h"

#include "../maps/maps.h"

// connect probe
#include "../probes/connect_tracker.bpf.h"

// execve probe
#include "../probes/execve_tracker.bpf.h"

// dup2 probe
#include "../probes/dup2_tracker.bpf.h"

// fork probe
#include "../probes/fork_tracker.bpf.h"

// socket create LSM hook
#include "../probes/socket_create_lsm.bpf.h"

// dup tracker(kprobe)
#include "../probes/dup_kprobe.bpf.h"

// dup3 tracker
#include "../probes/dup3_tracker.bpf.h"

// open syscall tracker for detect PTY create
#include "../probes/open_tracker.bpf.h"

char LICENSE[] SEC("license") = "GPL";