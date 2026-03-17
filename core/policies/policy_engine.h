#pragma once

/*
*   KernelEye Policy Actions
*
*   These values define what action the response engine should take
*   after a detection is evaluated by the policy engine.
*
*   KE_POLICY_ALLOW
*       No suspicious behaviour detected or score is too low.
*       The event is ignored and execution continues normally.
*
*   KE_POLICY_ALERT
*       Suspicious behaviour detected but not confirmed malicious.
*       The system should log or alert the event for investigation.
*
*   KE_POLICY_BLOCK
*       High confidence malicious behaviour detected.
*       The system should actively respond (kill process, block connection, etc).
*/

// This hold what action we take
enum ke_policy_result{
    KE_POLICY_ALLOW = 0,
    KE_POLICY_ALERT,
    KE_POLICY_BLOCK,
};

/*
*   Score Thresholds
*
*   Detection modules assign scores based on suspicious behaviour.
*   The policy engine uses these thresholds to determine actions.
*
*   ALERT_SCORE
*       Minimum score required to trigger an alert.
*
*   BLOCK_SCORE
*       Minimum score required to trigger an active block response.
*
*   These values can be tuned later to reduce false positives.
*/
#define BLOCK_SCORE 70
#define ALERT_SCORE 40