#include <stdio.h>

#include "base_response.h"
#include "../common/common_sockets.h"

// Forward declaration for pre-event printers
int print_reverse_shell(struct ke_event_header *event);

// Printer table mapping event type -> printer function
typedef int (*event_printer)(struct ke_event_header *);

// This table hold function type{event->type} and address of the function
struct {
    int type;
    event_printer printer;
} alert_printers [] = {
    {KE_REVERSE_SHELL,  print_reverse_shell}    // currently we have reverse shell only
};

// This is the function that we pass the alert events. And it chooses which function to pass data
int alert_execute(struct ke_vent_header *event){
    // total table size / 1st function size (each function allocate same size)
    for(int i = 0; i < sizeof(alert_printers)/sizeof(alert_printers[0]); i++){
        if(alert_printers[i].type == event->type){
            return alert_printers[i].printer(event);
        }
    }

    // This helps to prevent a crash if an unknown type is in the table.
    fprintf(stderr, "[KernelEye ALERT]. Unknown event type %d\n", event->type);
    return 0;
}

/* ================ Event Printers ================*/

int print_reverse_shell(
    struct ke_event_header *event
)
{
    printf("[KernelEye ALERT]. Reverse shell type event detected!\n");
    printf("================ Process Info =======================");
    printf("Process id: %d\n", event->hdr.pid);
    printf("Parent Process id: %d\n", event->hdr.ppid);
    printf("Process filename: %s\n", event->data.filename);
    printf("================ Timestamp Info =====================");
    printf("Process Triggered TS: %llu\n", event->hdr.ts);
    printf("Execve TS: %llu\n", event->data.execve_ts);
    printf("Network TS: %llu\n", event->data.net_ts);
    // TODO: Add network info also
    return 0;
}

// register the alert respose
ke_response alert_response = {
    .action = KE_POLICY_ALERT,
    .execute = alert_execute
};