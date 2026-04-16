static inline void evaluate_stage(__u32 flags, __u16 *stage, __u64 last_time)
{
    __u64 now = get_trigger_time();
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

    if(
        (flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & FD_REDERECTS_SEEN) &&
        (flags & STDIO_HIJACK_SEEN)
    ){
        ADVANCE_STAGE(stage, STAGE_BEHAVIORAL);
    }

    // high risk section
    if (
        (flags & CONNECT_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN)) &&
        (flags & FD_REDERECTS_SEEN) &&
        (now - last_time < KE_WINDOW_NS)
    ){
        ADVANCE_STAGE(stage, STAGE_HIGH_RISK);
    }

    // PTY-based shell (stealthy interactive shell)
    if (
        (flags & (CONNECT_SEEN | SOCKET_SEEN)) && 
        (flags & PTMX_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN | FCNTL_SEEN)) &&
        (now - last_time < KE_WINDOW_NS)
    ){
        ADVANCE_STAGE(stage, STAGE_HIGH_RISK);
    }

    // confirmed
    if (
        (flags & CONNECT_SEEN) &&
        (flags & SOCKET_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN)) &&
        (flags & STDIO_HIJACK_SEEN) &&
        (now - last_time < KE_WINDOW_NS)
    ){
        ADVANCE_STAGE(stage, STAGE_CONFIRMED);
    }
}

// updater
static inline void update_state(struct ke_ctx_state *s, __u32 flag)
{
    s->flags |= flag;
    evaluate_stage(s->flags, &s->stage, s->last_time);
}