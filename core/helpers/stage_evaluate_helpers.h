/*
|*********************************|
|*********** Rules ***************|
|*********************************|
*/

// suspicious category

/*
*   Check:
*       - argv[0] and filename contain same filename{paths not concider}
*       - and also check there was an inline arguments
*   Check execve_kprobe for more details
*/
static __always_inline int rule_suspicious_executables(__u64 flags){
    return (
        ((!!(flags & INTERPRETER_REAL_SEEN)) ^ (!!(flags & INTERPRETER_ARGV_SEEN))) &&
        (flags & SHELL_INLINE_SEEN)
    );
}

// behaviour category

static inline int rule_network_behavior(__u64 flags)
{
    return (flags & NETWORK_INTENT_SEEN) ||
        ((flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & FD_REDERECTS_SEEN) &&
        (flags & STDIO_HIJACK_SEEN));
}

// high risk category

static __always_inline int rule_suspicious_network_activities
(
    __u64 flags,
    __u64 delta
)
{
    return (flags & CONNECT_SEEN) &&
        (flags & (DUP2_SEEN | DUP3_SEEN)) &&
        (flags & FD_REDERECTS_SEEN) &&
        (delta < KE_WINDOW_NS);
}

// confimed category

static __always_inline int rule_confirmed_pty_shell
(
    __u64 flags,
    __u64 delta
){
    return (flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & PTMX_SEEN) &&
        (flags & (DUP_SEEN | DUP2_SEEN | DUP3_SEEN | FCNTL_SEEN)) &&
        (flags & (FD_REDERECTS_SEEN | STDIO_HIJACK_SEEN | FD_REWIRING_SEEN)) &&
        (delta < KE_WINDOW_NS);
}

static __always_inline int rule_confirmed_textbook_reverse_shell
(
    __u64 flags,
    __u64 delta
){
    return (flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & (DUP_SEEN | DUP2_SEEN | DUP3_SEEN | FCNTL_SEEN)) &&
        (flags & SOCKET_MATCH_SEEN) &&
        (flags & (FD_REDERECTS_SEEN | STDIO_HIJACK_SEEN | FD_REWIRING_SEEN)) &&
        (delta < KE_WINDOW_NS);
}

static __always_inline int rule_confirmed_forked_reverse_shell
(
    __u64 flags,
    __u64 delta
){
    return (flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & FORK_SEEN) &&
        (flags & (DUP_SEEN | DUP2_SEEN | DUP3_SEEN | FCNTL_SEEN)) &&
        (flags & (FD_REDERECTS_SEEN | STDIO_HIJACK_SEEN | FD_REWIRING_SEEN)) &&
        (delta < KE_WINDOW_NS);
}

// mainly target socat based shells
static __always_inline int rule_confimed_pty_relay_shell
(
    __u64 flags,
    __u64 delta
){
    return (flags & SOCKET_SEEN) &&
        (flags & CONNECT_SEEN) &&
        (flags & FORK_SEEN) &&
        (flags & PTMX_SEEN) &&
       (flags & (DUP_SEEN | DUP2_SEEN | DUP3_SEEN)) &&
       (delta < KE_WINDOW_NS);
}

static __always_inline void evaluate_rules(struct ke_ctx_state *s){

    __u64 now = get_trigger_time();
    __u64 delta = now - s->last_time;

    // set flags
    if(rule_suspicious_executables(s->flags)){
        ADVANCE_STAGE(&s->stage, STAGE_SUSPICIOUS);
    }

    if(rule_network_behavior(s->flags)){
        ADVANCE_STAGE(&s->stage, STAGE_BEHAVIORAL);
    }

    if(rule_suspicious_network_activities(s->flags, delta)){
        ADVANCE_STAGE(&s->stage, STAGE_HIGH_RISK);
    }

    if(rule_confirmed_pty_shell(s->flags, delta)){
        ADVANCE_STAGE(&s->stage, STAGE_CONFIRMED);
    }

    if(rule_confirmed_textbook_reverse_shell(s->flags, delta)){
        ADVANCE_STAGE(&s->stage, STAGE_CONFIRMED);
    }

    if(rule_confirmed_forked_reverse_shell(s->flags, delta)){
        ADVANCE_STAGE(&s->stage, STAGE_CONFIRMED);
    }

    if(rule_confimed_pty_relay_shell(s->flags, delta)){
        ADVANCE_STAGE(&s->stage, STAGE_CONFIRMED);
    }
}


// updater
static inline void update_state(struct ke_ctx_state *s, __u32 flag)
{
    s->flags |= flag;

    // assign stage
    evaluate_rules(s);

}