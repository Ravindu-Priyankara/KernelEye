#pragma once

struct stats {
    int events;
    int reverse_shells;
    int alerts;
    int blocks;
};

void ke_display_init(void);

void ke_display_event(
    int pid,
    int type,
    int severity,
    const char *detection,
    int score
);

void ke_print_stats(struct stats *s);