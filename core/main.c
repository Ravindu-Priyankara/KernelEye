#include <stdio.h>
#include "../loader/loader.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include "detections/rules/exec_rules.h"
#include "events/event_handler.h"

// ruleset macro
#define KE_RULES_PATH "../detections/config/rules.conf"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;  // for fix unused warning
    stop = 1;
}

int main(int argc, char *argv[]){
    // avoid taking arguments
    (void)argv; // for fix unused warning
    if(argc != 1) return 1;

    // signal handlers
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    //eBPF skelton for kernel-eye
    struct kerneleye_bpf *kern;

    // pointer to the main input data stream.
    struct ring_buffer *rb = NULL;

    // power-up the KernelEye {open, load, attach}
    // return : pointer
    kern = load_kerneleye();
    if(!kern) return 1;

    printf("KernelEye loaded successfully!\n");

    // load exec rules once
    exec_rules_init();
    exec_rules_load_from_file(KE_RULES_PATH);
    printf("Rules loaded successfully!\n");

    // Creates a new instance of a user ring buffer.
    rb = ring_buffer__new(
        bpf_map__fd(kern->maps.alert_map),
        handle_event,
        NULL,
        NULL
    );
    if(!rb){
        fprintf(stderr, "Failed to create ring buffer!\n");
        return 1;
    }

    while(!stop){
        int err = ring_buffer__poll(rb, 100);   // timeout = 100ms

        if (err == -EINTR) {
            return 0;   // graceful shutdown
        }

        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    // destroy the probes
    kerneleye_bpf__destroy(conn);

    // clear ring buffer
    ring_buffer__free(rb);

    return 0;
}