#pragma once

#include "../build/connect_tracker.skel.h"
#include "../build/execve_tracker.skel.h"

struct connect_tracker_bpf *load_connect_probe();
struct execve_tracker_bpf *load_execve_probe();