static inline void evaluate_stage(__u32 flags, __u8 *stage)
{
    // suspicious stage
    if (
        ((flags & INTERPRETER_REAL_SEEN) ^ (flags & INTERPRETER_ARGV_SEEN)) &&
        (flags & SHELL_INLINE_SEEN)
    ){
        ADVANCE_STAGE(stage, STAGE_SUSPICIOUS);
    }

    // behavioral stage
    if (flags & NETWORK_INTENT_SEEN){
        ADVANCE_STAGE(stage, STAGE_BEHAVIORAL);
    }

    // high risk
    if (
        (flags & CONNECT_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN)) &&
        (flags & FD_REDERECTS_SEEN)
    ){
        ADVANCE_STAGE(stage, STAGE_HIGH_RISK);
    }

    // confirmed
    if (
        (flags & CONNECT_SEEN) &&
        (flags & SOCKET_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN)) &&
        (flags & STDIO_HIJACK_SEEN)
    ){
        ADVANCE_STAGE(stage, STAGE_CONFIRMED);
    }
}

// updater
static inline void update_state(struct ke_ctx_state *s, __u32 flag)
{
    s->flags |= flag;
    evaluate_stage(s->flags, &s->stage);
}