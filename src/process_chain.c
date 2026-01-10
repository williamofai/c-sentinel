/*
 * process_chain.c - Process ancestry tracking for C-Sentinel
 *
 * Walks /proc/<pid>/stat to build process chain.
 * Enables semantic analysis like "python3 spawned by apache2 accessed /etc/shadow"
 */

#define _GNU_SOURCE  /* For strcasestr */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include "../include/audit.h"

/* Suspicious parent->child patterns */
typedef struct {
    const char *parent_pattern;
    const char *child_pattern;
    const char *description;
} suspicious_pattern_t;

static const suspicious_pattern_t SUSPICIOUS_PATTERNS[] = {
    /* Web server spawning shells - classic web exploit */
    {"apache",   "sh",      "Web server spawned shell"},
    {"apache",   "bash",    "Web server spawned shell"},
    {"apache2",  "sh",      "Web server spawned shell"},
    {"apache2",  "bash",    "Web server spawned shell"},
    {"nginx",    "sh",      "Web server spawned shell"},
    {"nginx",    "bash",    "Web server spawned shell"},
    {"httpd",    "sh",      "Web server spawned shell"},
    {"httpd",    "bash",    "Web server spawned shell"},
    {"httpd",    "python",  "Web server spawned script"},
    {"apache",   "python",  "Web server spawned script"},
    {"nginx",    "python",  "Web server spawned script"},

    /* Cron spawning network tools - potential C2 callback */
    {"cron",     "curl",    "Cron job making HTTP request"},
    {"cron",     "wget",    "Cron job downloading file"},
    {"cron",     "nc",      "Cron job using netcat"},
    {"cron",     "ncat",    "Cron job using netcat"},

    /* Database spawning unexpected processes */
    {"postgres", "sh",      "Database spawned shell"},
    {"postgres", "bash",    "Database spawned shell"},
    {"mysql",    "sh",      "Database spawned shell"},
    {"mysqld",   "sh",      "Database spawned shell"},

    /* Mail server abuse */
    {"postfix",  "sh",      "Mail server spawned shell"},
    {"sendmail", "sh",      "Mail server spawned shell"},
    {"exim",     "sh",      "Mail server spawned shell"},

    {NULL, NULL, NULL}
};


/*
 * Read /proc/<pid>/stat to get comm and ppid
 * Format: pid (comm) state ppid ...
 */
static int read_proc_stat(pid_t pid, char *comm, size_t comm_len, pid_t *ppid) {
    char path[64];
    char buf[512];

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    if (!fgets(buf, sizeof(buf), fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    /* Extract comm from between ( and ) */
    char *l = strchr(buf, '(');
    char *r = strrchr(buf, ')');
    if (!l || !r || r <= l) return -1;

    size_t len = (size_t)(r - l - 1);
    if (len >= comm_len) len = comm_len - 1;

    memcpy(comm, l + 1, len);
    comm[len] = '\0';

    /* ppid follows state: ") S ppid ..." */
    char *after = r + 2;  /* skip ") " */
    char state;
    if (sscanf(after, "%c %d", &state, ppid) != 2) {
        return -1;
    }

    return 0;
}


/*
 * Fallback: get PPID from /proc/<pid>/status if stat parsing fails
 */
static pid_t get_ppid_fallback(pid_t pid) {
    char path[64];
    char line[256];

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    pid_t ppid = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "PPid:", 5) == 0) {
            ppid = atoi(line + 5);
            break;
        }
    }
    fclose(fp);
    return ppid;
}


/*
 * Build process chain by walking up the parent tree
 * APPENDS to existing chain (caller may have seeded with audit data)
 * Result order: child → parent (e.g., ["python3", "bash", "sshd", "systemd"])
 */
void build_process_chain(pid_t pid, process_chain_t *out) {
    if (pid <= 0) return;

    while (out->depth < MAX_PROCESS_CHAIN_DEPTH && pid > 1) {
        char comm[64];
        pid_t ppid = -1;

        if (read_proc_stat(pid, comm, sizeof(comm), &ppid) == 0) {
            /* Store in chain */
            memset(out->names[out->depth], 0, sizeof(out->names[out->depth]));
            size_t copylen = strlen(comm);
            if (copylen >= sizeof(out->names[out->depth])) {
                copylen = sizeof(out->names[out->depth]) - 1;
            }
            memcpy(out->names[out->depth], comm, copylen);
            out->depth++;
        } else {
            /* Process gone - can't continue */
            break;
        }

        /* Try fallback if ppid lookup failed or returned invalid */
        if (ppid <= 1) {
            ppid = get_ppid_fallback(pid);
        }

        /* Stop conditions */
        if (ppid <= 1 || ppid == pid) {
            break;
        }

        pid = ppid;
    }
}


/*
 * Check if a process chain matches any suspicious patterns
 * Chain is child→parent order, so we check chain[i] (child) against chain[i+1] (parent)
 */
bool is_suspicious_chain(const process_chain_t *chain, const char **description) {
    if (!chain || chain->depth < 2) {
        return false;
    }

    /* Check each adjacent pair: chain[i] is child, chain[i+1] is parent */
    for (int i = 0; i < chain->depth - 1; i++) {
        const char *child = chain->names[i];
        const char *parent = chain->names[i + 1];

        for (const suspicious_pattern_t *p = SUSPICIOUS_PATTERNS; p->parent_pattern; p++) {
            /* Case-insensitive substring match */
            if (strcasestr(parent, p->parent_pattern) &&
                strcasestr(child, p->child_pattern)) {
                if (description) {
                    *description = p->description;
                }
                return true;
            }
        }
    }

    return false;
}


/*
 * Format a process chain as a string for display
 * Output: "python3 <- bash <- sshd <- systemd"
 */
void format_process_chain(const process_chain_t *chain, char *buf, size_t bufsize) {
    if (!chain || chain->depth == 0) {
        snprintf(buf, bufsize, "(empty)");
        return;
    }

    buf[0] = '\0';
    size_t pos = 0;

    for (int i = 0; i < chain->depth && pos < bufsize - 1; i++) {
        if (i > 0) {
            int written = snprintf(buf + pos, bufsize - pos, " <- ");
            if (written > 0) pos += (size_t)written;
        }
        int written = snprintf(buf + pos, bufsize - pos, "%s", chain->names[i]);
        if (written > 0) pos += (size_t)written;
    }
}
