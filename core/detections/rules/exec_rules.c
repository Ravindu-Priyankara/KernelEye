#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include "exec_rules.h"
#include <ctype.h>

// for hold our rules
typedef struct exec_rule_internal {
    char name[32];
    int severity;
    UT_hash_handle hh;
} exec_rule_internal;

static exec_rule_internal *rules = NULL;


// initialize rules 
void exec_rules_init() {
    rules = NULL;
}


// for manually add rules
void exec_rules_add(const char *name, int severity) {

    exec_rule_internal *r = malloc(sizeof(exec_rule_internal));

    if (!r)
        return;

    strncpy(r->name, name, sizeof(r->name));
    r->name[sizeof(r->name)-1] = '\0';

    r->severity = severity;

    HASH_ADD_STR(rules, name, r);
}


// for find rules
exec_rule *exec_rules_find(const char *filename) {

    exec_rule_internal *r;

    HASH_FIND_STR(rules, filename, r);

    if (!r)
        return NULL;

    return (exec_rule *)r;
}

// trim leading and trailing whitespace
char *trim(char *str) {
    if (!str) return NULL;

    // trim leading
    while(*str && (*str == ' ' || *str == '\t'))
        str++;

    // trim trailing
    char *end = str + strlen(str) - 1;
    while(end > str && (*end == ' ' || *end == '\t')) {
        *end = '\0';
        end--;
    }

    return str;
}

// for loads rules from file
void exec_rules_load_from_file(const char *path)
{
    // open the rules file
    FILE *f = fopen(path, "r");

    if (!f) {
        printf("[ERROR]. Failed to open rules file: %s\n", path);
        return;
    }

    // buffer for rules
    char line[128];

    while (fgets(line, sizeof(line), f)) {

        // remove newline
        line[strcspn(line, "\n")] = 0;

        // skip comments or empty lines
        if (line[0] == '#' || line[0] == '\0')
            continue;

        // split name and severity
        char *name = strtok(line, ":");
        char *sev  = strtok(NULL, ":");

        if (!name || !sev)
            continue;

        // trim the values
        name = trim(name);
        sev  = trim(sev);

        // convert to intiger
        int severity = atoi(sev);

        // add the rules
        exec_rules_add(name, severity);
    }

    fclose(f);
}

/*
*   This function is used for extract basename and make path lowercase
*   Assumption:
*       1. Protect Capitalized letter based bypass
*/
const char *get_basename_lower(const char *path) {
    // locate path starting character
    const char *base = strrchr(path, '/');
    if (!base) 
        base = path;
    else
        base++;  // skip '/'

    // copy to static buffer
    static char name[64];
    size_t i;
    for (i = 0; i < sizeof(name) - 1 && base[i]; i++)
        name[i] = tolower((unsigned char)base[i]);
    // prevent memory leaks
    name[i] = '\0';

    return name;
}