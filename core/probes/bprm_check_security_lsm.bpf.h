
SEC("lsm/bprm_check_security")
int BPF_PROG(trace_process_execute, struct linux_binprm *bprm){


    #ifdef DEBUG_MODE
        debug_counter(1);
    #endif

    return 0;
}