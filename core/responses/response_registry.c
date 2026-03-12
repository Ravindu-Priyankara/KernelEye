#include <stdio.h>

#include "base_response.h"
#include "alert_response.c"
#include "block_response.c"
#include "allow_response.c"

// List of all response modules
ke_response *responses[] = {
    &allow_response,
    &alert_response,
    &block_response
};

// before call mark it as extern
int response_count = sizeof(responses)/sizeof(responses[0]);