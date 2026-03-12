#include <stdio.h>
#include "base_response.h"

// This function for allow responses
int allow_execute(
    struct ke_event_header *event
)
{
    // do nothing.
    return 0;
}

// register this allow response
ke_response allow_response = {
    .action = KE_POLICY_ALLOW,
    .execute = allow_execute
};