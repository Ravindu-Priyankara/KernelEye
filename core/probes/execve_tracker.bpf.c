#include "../common/common_headers.h"
#include "../common/common_structs.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter_handler(struct trace_event_raw_sys_enter *ctx){

}

//License
char LICENSE[] SEC("license") = "GPL"; 