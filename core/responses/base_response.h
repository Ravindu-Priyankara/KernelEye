#pragma once

#include "../common/common_structs.h"
#include "../policies/policy_engine.h"

typedef struct ke_response {
    // ALLOW / ALERT / BLOCK
    enum ke_policy_result action;
    int (*execute)(struct ke_event_header *event);
} ke_response;