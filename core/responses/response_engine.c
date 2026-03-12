#include <stdio.h>
#include "base_response.h"

// access response registry has table and response count
extern int response_count;
extern ke_response *responses[];

// This function used to pass data according to action {Allow / Alert / Block}
int ke_execute_response(enum ke_policy_result action, struct ke_event_header *event) {
    for(int i = 0; i < response_count; i++) {
        if(responses[i]->action == action) {
            return responses[i]->execute(event);
        }
    }
    printf("[KernelEye] Unknown policy result %d\n", action);
    return -1;
}