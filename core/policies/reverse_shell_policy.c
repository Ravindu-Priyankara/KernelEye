#include <stdio.h>
#include "policy_engine.h"
#include "../detections/detection_results.h"

enum ke_policy_result check_reverse_shell(struct ke_detection_result *result){

    // for block
    if(result->severity == KE_SEV_CRITICAL || result->score >= BLOCK_SCORE)
        return KE_POLICY_BLOCK;

    // for alert
    if(result->severity == KE_SEV_WARNING || result->score >= ALERT_SCORE)
        return KE_POLICY_ALERT;

    return KE_POLICY_ALLOW; // others allow
}