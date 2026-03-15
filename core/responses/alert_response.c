#include <stdio.h>

#include "base_response.h"
#include "response_header.h"

// Forward declaration for pre-event printers
int print_reverse_shell(struct ke_event_header *event);

// Printer table mapping event type -> printer function
typedef int (*event_printer)(struct ke_event_header *);

// This table hold function type{event->type} and address of the function
struct {
    __u32 type;
    event_printer printer;
} alert_printers [] = {
    {KE_EVENT_REVERSE_SHELL,  print_reverse_shell}    // currently we have reverse shell only
};

// This is the function that we pass the alert events. And it chooses which function to pass data
int alert_execute(struct ke_event_header *event){
    // total table size / 1st function size (each function allocate same size)
    for(size_t i = 0; i < sizeof(alert_printers)/sizeof(alert_printers[0]); i++){
        if(alert_printers[i].type == event->type){
            return alert_printers[i].printer(event);
        }
    }

    // This helps to prevent a crash if an unknown type is in the table.
    //fprintf(stderr, "[KernelEye ALERT]. Unknown event type %d\n", event->type);
    return 0;
}

/* ================ Event Printers ================*/

int print_reverse_shell(
    struct ke_event_header *event
)
{
    // for fix unused parameter warning
    (void)event;
    
    // in the future this function used to log alert
    
    return 0;
}

// register the alert respose
ke_response alert_response = {
    .action = KE_POLICY_ALERT,
    .execute = alert_execute
};