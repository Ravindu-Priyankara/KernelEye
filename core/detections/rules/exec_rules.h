#pragma once

typedef struct exec_rule exec_rule;

// initialize rule system
void exec_rules_init();

// add rule 
void exec_rules_add(const char *name, int severity);

// lookup rule
exec_rule *exec_rules_find(const char *filename);

// for load rules via rules.conf
void exec_rules_load_from_file(const char *path);

// get basename 
const char *get_basename_lower(const char *path);

// rule structure
struct exec_rule {
    char name[32];
    int severity;
};

