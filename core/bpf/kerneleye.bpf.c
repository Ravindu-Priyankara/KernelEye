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

// probes
#include "../probes/connect_tracker.bpf.h"
#include "../probes/execve_tracker.bpf.h"
#include "../probes/dup2_tracker.bpf.h"
#include "../probes/fork_tracker.bpf.h"
#include "../probes/socket_create_lsm.bpf.h"
#include "../probes/dup_kprobe.bpf.h"
#include "../probes/dup3_tracker.bpf.h"
#include "../probes/open_tracker.bpf.h"

char LICENSE[] SEC("license") = "GPL";