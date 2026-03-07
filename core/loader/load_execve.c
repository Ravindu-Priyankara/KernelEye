#include <stdio.h>
#include "loader.h"

// Load the execve_tracker eBPF program and return its skeleton handle
struct execve_tracker_bpf *load_execve_probe(){
    // eBPF skeleton for execve tracker
    struct execve_tracker_bpf *skel;

    // open the BPF ELF program
    skel = execve_tracker_bpf__open();
    if(!skel){
        fprintf(stderr, "Failed to open execve tracker!\n");
        return NULL;
    }

    // load the BPF object into kernel
    if(execve_tracker_bpf__load(skel)){
        fprintf(stderr, "Failed to load execve tracker!\n");
        execve_tracker_bpf__destroy(skel);
        return NULL;
    }

    // attach the programs
    if(execve_tracker_bpf__attach(skel)){
        fprintf(stderr, "Failed to attach execve tracker!\n");
        execve_tracker_bpf__destroy(skel);
        return NULL;
    }

    printf("Execve tracker loaded!\n");
    
    return skel;
}