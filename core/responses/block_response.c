#include <stdio.h>
#include <signal.h>
#include "base_response.h"
#include "response_header.h"

// This is the function we used for terminate process
int block_execute(
    struct ke_event_header *event
)
{
    kill(event->pid, SIGTERM);
    //printf("[KernelEye BLOCK] Malicious process killed!\n");
    //TODO: show more details {pid , ..}
    return 0;
}

// register this block response
ke_response block_response = {
    .action = KE_POLICY_BLOCK,
    .execute = block_execute
};