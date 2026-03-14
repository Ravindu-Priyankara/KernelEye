#include <stdio.h>
#include "../loader/loader.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include "detections/rules/exec_rules.h"
#include "events/event_handler.h"
#include "ui/banner/banner.h"
#include "ui/display/display.h"

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

    // banner
    ke_print_banner();

    //eBPF skelton for kernel-eye
    struct kerneleye_bpf *kern;

    // pointer to the main input data stream.
    struct ring_buffer *rb = NULL;

    // power-up the KernelEye {open, load, attach}
    // return : pointer
    kern = load_kerneleye();
    if(!kern) return 1;

    printf("[+] Initializing eBPF probes...\n");

    // load exec rules once
    exec_rules_init();
    exec_rules_load_from_file(KE_RULES_PATH);
    printf("[+] Loading detection rules...\n");
    printf("[+] Loading detection rules...\n");

    system("clear");   // clean screen for monitoring UI
    ke_print_banner();
    ke_description();
    ke_display_init();

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
    kerneleye_bpf__destroy(kern);

    // clear ring buffer
    ring_buffer__free(rb);

    return 0;
}