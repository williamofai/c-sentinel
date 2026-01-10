/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * audit_linux.c - Linux auditd implementation
 *
 * This file provides audit functionality for Linux systems using
 * the auditd subsystem. It parses /var/log/audit/audit.log via
 * the ausearch command.
 *
 * Function mapping (1:1 with audit_bsm.c):
 *   probe_audit_linux()           <-> probe_audit_bsm()
 *   parse_auth_events_linux()     <-> parse_auth_events_bsm()
 *   parse_priv_events_linux()     <-> parse_priv_events_bsm()
 *   parse_file_events_linux()     <-> parse_file_events_bsm()
 *   parse_exec_events_linux()     <-> parse_exec_events_bsm()
 *   check_security_framework_linux() <-> check_security_framework_bsm()
 */

#define _GNU_SOURCE  /* Required for popen/pclose with -std=c99 */

#include "platform.h"

#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#include "audit.h"
#include "audit_platform.h"
#include "process_chain.h"
#include "sha256.h"

/* ============================================================
 * Static Variables
 * ============================================================ */

/* Timestamp string for ausearch queries */
static char g_ausearch_ts[64] = "recent";

/* SYSCALL context for process correlation */
#define MAX_EVENT_CTX 256

typedef struct {
    unsigned long serial;       /* Audit event serial */
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[64];
    char exe[256];
} event_ctx_t;

static event_ctx_t g_event_ctx[MAX_EVENT_CTX];
static int g_event_ctx_count = 0;

/* ============================================================
 * Helper Functions
 * ============================================================ */

/*
 * Format timestamp for ausearch in locale-aware format
 */
static void format_ausearch_timestamp(time_t ts, char *buf, size_t bufsize) {
    struct tm *tm = localtime(&ts);
    if (!tm) {
        snprintf(buf, bufsize, "recent");
        return;
    }
    
    /* Use locale-aware date format */
    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%x", tm);
    
    snprintf(buf, bufsize, "%s %02d:%02d:%02d",
             datebuf, tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/*
 * Clear event context
 */
static void clear_event_ctx(void) {
    g_event_ctx_count = 0;
    memset(g_event_ctx, 0, sizeof(g_event_ctx));
}

/*
 * Find or add a hashed user to the failure list
 */
static hashed_user_t* find_or_add_user(audit_summary_t *summary, const char *username) {
    char hashed[HASH_USERNAME_LEN];
    hash_username(username, hashed, sizeof(hashed));
    
    /* Look for existing */
    for (int i = 0; i < summary->failure_user_count; i++) {
        if (strcmp(summary->failure_users[i].hash, hashed) == 0) {
            return &summary->failure_users[i];
        }
    }
    
    /* Add new if space */
    if (summary->failure_user_count < MAX_AUDIT_USERS) {
        hashed_user_t *user = &summary->failure_users[summary->failure_user_count++];
        memset(user->hash, 0, sizeof(user->hash));
        snprintf(user->hash, sizeof(user->hash), "%s", hashed);
        user->count = 0;
        return user;
    }
    
    return NULL;
}

/*
 * Parse SYSCALL records for process context
 */
static void parse_syscall_context(int window_seconds) {
    char cmd[512];
    char line[2048];
    FILE *fp;
    
    (void)window_seconds;
    
    clear_event_ctx();
    
    /* Get SYSCALL events with raw format for stable parsing */
    snprintf(cmd, sizeof(cmd),
             "ausearch -m SYSCALL -ts '%s' --format raw 2>/dev/null | tail -500",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp) && g_event_ctx_count < MAX_EVENT_CTX) {
        event_ctx_t *ctx = &g_event_ctx[g_event_ctx_count];
        
        /* Extract serial number */
        char *msg = strstr(line, "msg=audit(");
        if (!msg) continue;
        
        unsigned long serial;
        if (sscanf(msg, "msg=audit(%*[^:]):%lu)", &serial) != 1) continue;
        ctx->serial = serial;
        
        /* Extract pid */
        char *pid_str = strstr(line, " pid=");
        if (pid_str) {
            ctx->pid = atoi(pid_str + 5);
        }
        
        /* Extract ppid */
        char *ppid_str = strstr(line, " ppid=");
        if (ppid_str) {
            ctx->ppid = atoi(ppid_str + 6);
        }
        
        /* Extract uid */
        char *uid_str = strstr(line, " uid=");
        if (uid_str) {
            ctx->uid = atoi(uid_str + 5);
        }
        
        /* Extract comm (command name) */
        char *comm = strstr(line, " comm=\"");
        if (comm) {
            comm += 7;
            int i = 0;
            while (*comm && *comm != '"' && i < 63) {
                ctx->comm[i++] = *comm++;
            }
            ctx->comm[i] = '\0';
        }
        
        /* Extract exe (executable path) */
        char *exe = strstr(line, " exe=\"");
        if (exe) {
            exe += 6;
            int i = 0;
            while (*exe && *exe != '"' && i < 255) {
                ctx->exe[i++] = *exe++;
            }
            ctx->exe[i] = '\0';
        }
        
        g_event_ctx_count++;
    }
    
    pclose(fp);
}

/*
 * Find event context by serial number
 */
static event_ctx_t* find_event_ctx(unsigned long serial) {
    for (int i = 0; i < g_event_ctx_count; i++) {
        if (g_event_ctx[i].serial == serial) {
            return &g_event_ctx[i];
        }
    }
    return NULL;
}

/* ============================================================
 * Authentication Events
 * ============================================================ */

/*
 * Parse ausearch output for authentication events
 * Looks for: type=USER_AUTH ... res=failed
 */
void parse_auth_events_linux(audit_summary_t *summary, int window_seconds) {
    char cmd[512];
    char line[2048];
    FILE *fp;
    
    (void)window_seconds;
    
    /* Use raw format for stable parsing */
    snprintf(cmd, sizeof(cmd), 
             "ausearch -m USER_AUTH -ts '%s' --format raw 2>/dev/null | "
             "grep -E 'res=(success|failed)' | tail -100 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp)) {
        /* Check result */
        if (strstr(line, "res=failed")) {
            summary->auth_failures++;
            
            /* Extract username from acct="..." */
            char *acct = strstr(line, "acct=\"");
            if (acct) {
                acct += 6;
                char username[64] = {0};
                int i = 0;
                while (*acct && *acct != '"' && i < 63) {
                    username[i++] = *acct++;
                }
                username[i] = '\0';
                
                if (strlen(username) > 0) {
                    hashed_user_t *user = find_or_add_user(summary, username);
                    if (user) {
                        user->count++;
                    }
                }
            }
        } else if (strstr(line, "res=success")) {
            summary->auth_successes++;
        }
    }
    
    pclose(fp);
    
    /* Detect brute force: >5 failures in the window */
    summary->brute_force_detected = (summary->auth_failures > 5);
}

/* ============================================================
 * Privilege Escalation Events
 * ============================================================ */

/*
 * Parse sudo/su events
 */
void parse_priv_events_linux(audit_summary_t *summary, int window_seconds) {
    char cmd[512];
    char line[1024];
    FILE *fp;
    
    (void)window_seconds;
    
    /* Count sudo usage */
    snprintf(cmd, sizeof(cmd),
             "ausearch -m USER_CMD -ts '%s' --format raw 2>/dev/null | "
             "grep -c 'exe=\"/usr/bin/sudo\"' 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->sudo_count = atoi(line);
        }
        pclose(fp);
    }
    
    /* Count su usage */
    snprintf(cmd, sizeof(cmd),
             "ausearch -m USER_CMD -ts '%s' --format raw 2>/dev/null | "
             "grep -c 'exe=\"/usr/bin/su\"' 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->su_count = atoi(line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * File Events
 * ============================================================ */

/*
 * Parse sensitive file access events
 */
void parse_file_events_linux(audit_summary_t *summary, int window_seconds) {
    char cmd[512];
    char line[2048];
    FILE *fp;
    
    (void)window_seconds;
    
    /* Look for file access events using audit watch rules */
    snprintf(cmd, sizeof(cmd),
             "ausearch -m PATH -ts '%s' --format raw 2>/dev/null | "
             "grep -E 'name=\"/etc/(passwd|shadow|sudoers|ssh/)' | tail -50 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp) && summary->sensitive_file_count < MAX_AUDIT_FILES) {
        /* Extract path */
        char *name = strstr(line, "name=\"");
        if (!name) continue;
        name += 6;
        
        char path[AUDIT_PATH_LEN] = {0};
        int i = 0;
        while (*name && *name != '"' && i < AUDIT_PATH_LEN - 1) {
            path[i++] = *name++;
        }
        path[i] = '\0';
        
        if (strlen(path) == 0) continue;
        
        /* Find or create file entry */
        file_access_t *fa = NULL;
        for (int j = 0; j < summary->sensitive_file_count; j++) {
            if (strcmp(summary->sensitive_files[j].path, path) == 0) {
                fa = &summary->sensitive_files[j];
                break;
            }
        }
        
        if (!fa && summary->sensitive_file_count < MAX_AUDIT_FILES) {
            fa = &summary->sensitive_files[summary->sensitive_file_count++];
            snprintf(fa->path, sizeof(fa->path), "%s", path);
            strcpy(fa->access_type, "access");
            fa->count = 0;
        }
        
        if (fa) {
            fa->count++;
            
            /* Extract serial and correlate with SYSCALL context */
            char *msg = strstr(line, "msg=audit(");
            if (msg) {
                unsigned long serial;
                if (sscanf(msg, "msg=audit(%*[^:]):%lu)", &serial) == 1) {
                    event_ctx_t *ctx = find_event_ctx(serial);
                    if (ctx && strlen(ctx->comm) > 0) {
                        snprintf(fa->process, sizeof(fa->process), "%s", ctx->comm);
                        
                        /* Build process chain */
                        process_chain_t *chain = &fa->chain;
                        memset(chain, 0, sizeof(*chain));
                        
                        /* First hop: audited process name */
                        snprintf(chain->names[0], sizeof(chain->names[0]), "%s", ctx->comm);
                        chain->depth = 1;
                        
                        /* Continue from ppid */
                        if (ctx->ppid > 1) {
                            build_process_chain(ctx->ppid, chain);
                        }
                        
                        /* Check for suspicious process chains */
                        const char *reason = NULL;
                        if (is_suspicious_chain(chain, &reason)) {
                            fa->suspicious = true;
                            summary->suspicious_exec_count++;
                        }
                    }
                }
            }
            
            /* Mark shadow/sudoers as suspicious */
            if (strstr(path, "shadow") || strstr(path, "sudoers")) {
                fa->suspicious = true;
            }
        }
    }
    
    pclose(fp);
}

/* ============================================================
 * Execution Events
 * ============================================================ */

/*
 * Parse executions from suspicious locations
 */
void parse_exec_events_linux(audit_summary_t *summary, int window_seconds) {
    char cmd[512];
    char line[1024];
    FILE *fp;
    
    (void)window_seconds;
    
    /* Look for execve syscalls with paths in /tmp or /dev/shm */
    snprintf(cmd, sizeof(cmd),
             "ausearch -sc execve -ts '%s' -i 2>/dev/null | "
             "grep -E 'name=(/tmp/|/dev/shm/)' 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "/tmp/")) {
            summary->tmp_executions++;
        }
        if (strstr(line, "/dev/shm/")) {
            summary->devshm_executions++;
        }
    }
    
    pclose(fp);
    
    /* Count shell spawns */
    snprintf(cmd, sizeof(cmd),
             "ausearch -sc execve -ts '%s' -i 2>/dev/null | "
             "grep -cE 'name=.*/bin/(ba)?sh' 2>/dev/null",
             g_ausearch_ts);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->shell_spawns = atoi(line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * Security Framework
 * ============================================================ */

/*
 * Check SELinux/AppArmor status
 */
void check_security_framework_linux(audit_summary_t *summary) {
    FILE *fp;
    char line[256];
    char cmd[512];
    
    /* Check SELinux */
    fp = fopen("/sys/fs/selinux/enforce", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->selinux_enforcing = (atoi(line) == 1);
        }
        fclose(fp);
        
        /* Count AVC denials */
        snprintf(cmd, sizeof(cmd),
                 "ausearch -m AVC -ts '%s' 2>/dev/null | "
                 "grep -c 'denied' 2>/dev/null",
                 g_ausearch_ts);
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(line, sizeof(line), fp)) {
                summary->selinux_avc_denials = atoi(line);
            }
            pclose(fp);
        }
    }
    
    /* Check AppArmor */
    snprintf(cmd, sizeof(cmd),
             "ausearch -m APPARMOR_DENIED -ts '%s' 2>/dev/null | "
             "wc -l 2>/dev/null",
             g_ausearch_ts);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->apparmor_denials = atoi(line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * Main Probe Function
 * ============================================================ */

/*
 * Main Linux audit probe - gather all audit data
 */
audit_summary_t* probe_audit_linux(int window_seconds) {
    audit_summary_t *summary = calloc(1, sizeof(audit_summary_t));
    if (!summary) {
        return NULL;
    }
    
    summary->enabled = true;
    summary->period_seconds = window_seconds;
    summary->capture_time = time(NULL);
    
    /* Check if auditd is available */
    if (access(AUDIT_LOG_PATH, R_OK) != 0) {
        summary->enabled = false;
        return summary;
    }
    
    /* Load baseline to get last probe time */
    audit_baseline_t baseline = {0};
    bool has_baseline = load_audit_baseline(&baseline);
    
    /* Set global timestamp for ausearch queries */
    if (has_baseline && baseline.updated > 0) {
        format_ausearch_timestamp(baseline.updated, g_ausearch_ts, sizeof(g_ausearch_ts));
    } else {
        strcpy(g_ausearch_ts, "recent");
    }
    
    /* Build SYSCALL context first (for process correlation) */
    clear_event_ctx();
    parse_syscall_context(window_seconds);
    
    /* Parse various event types */
    parse_auth_events_linux(summary, window_seconds);
    parse_priv_events_linux(summary, window_seconds);
    parse_file_events_linux(summary, window_seconds);
    parse_exec_events_linux(summary, window_seconds);
    check_security_framework_linux(summary);
    
    /* Clean up event context */
    clear_event_ctx();
    
    /* Detect anomalies using baseline */
    if (has_baseline) {
        detect_anomalies(summary, &baseline);
        summary->baseline_sample_count = baseline.sample_count;
    } else {
        summary->baseline_sample_count = 0;
    }
    
    /* Calculate overall risk score */
    calculate_risk_score(summary);
    
    return summary;
}

#endif /* PLATFORM_LINUX */
