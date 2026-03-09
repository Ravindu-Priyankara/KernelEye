#pragma once

// This hold what action we take
enum ke_policy_result{
    KE_POLICY_ALLOW = 0,
    KE_POLICY_ALERT,
    KE_POLICY_BLOCK,
}

#define BLOCK_SCORE 80
#define ALERT_SCORE 60