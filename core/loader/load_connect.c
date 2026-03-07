#include <stdio.h>
#include "loader.h"

// Load the connect_tracker eBPF program and return its skeleton handle
struct connect_tracker_bpf *load_connect_probe(){
    // eBPF skeleton for connect tracker
    struct connect_tracker_bpf *skel;

    // open the BPF ELF program
    skel = connect_tracker_bpf__open();
    if(!skel){
        fprintf(stderr, "Failed to open connect tracker!\n");
        return NULL;
    }

    // load the BPF object into kernel
    if(connect_tracker_bpf__load(skel)){
        fprintf(stderr, "Failed to load connect tracker!\n");
        connect_tracker_bpf__destroy(skel);
        return NULL;
    }

    // attach the programs
    if(connect_tracker_bpf__attach(skel)){
        fprintf(stderr, "Failed to attach connect tracker!\n");
        connect_tracker_bpf__destroy(skel);
        return NULL;
    }

    printf("Connect tracker loaded\n");

    return skel;
}