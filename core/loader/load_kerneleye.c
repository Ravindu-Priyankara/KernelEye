#include <stdio.h>
#include "loader.h"

// Load the kerneleye eBPF program and return its skeleton handle
struct kerneleye_bpf *load_kerneleye(){
    // eBPF skeleton for connect tracker
    struct kerneleye_bpf *skel;

    // open the BPF ELF program
    skel = kerneleye_bpf__open();
    if(!skel){
        fprintf(stderr, "Failed to open KernelEye eBPF program!\n");
        return NULL;
    }

    // load the BPF object into kernel
    if(kerneleye_bpf__load(skel)){
        fprintf(stderr, "Failed to load KernelEye program!\n");
        kerneleye_bpf__destroy(skel);
        return NULL;
    }

    // attach the programs
    if(kerneleye_bpf__attach(skel)){
        fprintf(stderr, "Failed to attach KernelEye program!\n");
        kerneleye_bpf__destroy(skel);
        return NULL;
    }

    //printf("KernelEye loaded\n");

    return skel;
}