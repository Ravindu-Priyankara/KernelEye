#include <stdio.h>
#include "policy_engine.h"
#include "../detections/detection_results.h"

/*
*   Reverse Shell Policy Evaluation
*
*   This function determines the final action based on the
*   detection result produced by the detection engine.
*
*   Decision Logic
*
*   Severity OR score can independently trigger a policy decision.
*
*   CRITICAL severity OR score >= BLOCK_SCORE
*       → Considered high confidence malicious behaviour
*       → Action: BLOCK
*
*   WARNING severity OR score >= ALERT_SCORE
*       → Suspicious behaviour but not confirmed attack
*       → Action: ALERT
*
*   Otherwise
*       → Behaviour considered safe or insufficient evidence
*       → Action: ALLOW
*
*   Notes
*   - Severity represents rule confidence
*   - Score represents behavioural accumulation
*   - Either metric can trigger enforcement
*/

enum ke_policy_result check_reverse_shell(struct ke_detection_result *result){

    // for block
    if(result->severity == KE_SEV_CRITICAL || result->score >= BLOCK_SCORE)
        return KE_POLICY_BLOCK;

    // for alert
    if(result->severity == KE_SEV_WARNING || result->score >= ALERT_SCORE)
        return KE_POLICY_ALERT;

    return KE_POLICY_ALLOW; // others allow
}