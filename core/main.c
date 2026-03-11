#include <stdio.h>
#include "../loader/loader.h"
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include "detections/rules/exec_rules.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    stop = 1;
}

int main(int argc, char *argv[]){
    // avoid taking arguments
    if(argc != 1) return 1;

    // signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    //eBPF skelton for connect tracker
    struct connect_tracker_bpf *conn;

    //eBPF skelton for execve tracker
    struct execve_tracker_bpf *exec;

    // pointer to the main input data stream.
    struct ring_buffer *rb = NULL;

    // power-up the connect tracker {open, load, attach}
    // return : pointer
    conn = load_connect_probe();
    if(!conn) return 1;

    // power-up the execve tracker {open, load, attach}
    // return: pointer
    exec = load_execve_probe();
    if(!exec) return 1;

    printf("All probes loaded successfully!\n");

    // load exec rules once
    exec_rules_init();
    exec_rules_load_from_file("detections/config/rules.conf");
    printf("Rules loaded successfully!\n");

    // Creates a new instance of a user ring buffer.
    rb = ring_buffer__new(
        bpf_map__fd(conn->maps.alert_map),
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

        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

    // destroy the probes
    connect_tracker_bpf__destroy(conn);
    execve_tracker_bpf__destroy(exec);

    // clear ring buffer
    ring_buffer__free(rb);

    return 0;
}