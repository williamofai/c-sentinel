/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * audit_bsm.c - OpenBSM audit implementation (macOS + BSD)
 *
 * This file provides audit functionality for macOS and BSD systems.
 * 
 * On macOS:
 *   - Primary: OpenBSM (if enabled)
 *   - Fallback: Unified Logging (log show) - works on all modern macOS
 *
 * On BSD:
 *   - OpenBSM audit framework
 *
 * Function mapping (1:1 with audit_linux.c):
 *   probe_audit_bsm()              <-> probe_audit_linux()
 *   parse_auth_events_bsm()        <-> parse_auth_events_linux()
 *   parse_priv_events_bsm()        <-> parse_priv_events_linux()
 *   parse_file_events_bsm()        <-> parse_file_events_linux()
 *   parse_exec_events_bsm()        <-> parse_exec_events_linux()
 *   check_security_framework_bsm() <-> check_security_framework_linux()
 */

#define _GNU_SOURCE  /* Required for popen/pclose with -std=c99 */

#include "platform.h"

#if defined(PLATFORM_MACOS) || defined(PLATFORM_BSD)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>

#include "audit.h"
#include "audit_platform.h"
#include "sha256.h"

/* ============================================================
 * Platform-Specific Paths
 * ============================================================ */

#define BSM_AUDIT_DIR           "/var/audit"
#define BSM_PRAUDIT_CMD         "praudit"

/* ============================================================
 * Backend Detection
 * ============================================================ */

typedef enum {
    AUDIT_BACKEND_NONE_AVAILABLE,
    AUDIT_BACKEND_BSM_AVAILABLE,
    AUDIT_BACKEND_UNIFIED_LOG      /* macOS only */
} audit_backend_type_t;

static audit_backend_type_t g_backend = AUDIT_BACKEND_NONE_AVAILABLE;
static int g_window_seconds = 300;

/* ============================================================
 * Helper Functions
 * ============================================================ */

/*
 * Find the most recent BSM audit trail file
 */
static int find_current_audit_trail(char *path, size_t pathsize) {
    DIR *dir;
    struct dirent *entry;
    char newest[NAME_MAX + 1] = {0};
    time_t newest_time = 0;
    
    dir = opendir(BSM_AUDIT_DIR);
    if (!dir) {
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        /* Check for "current" symlink first */
        if (strcmp(entry->d_name, "current") == 0) {
            snprintf(path, pathsize, "%s/current", BSM_AUDIT_DIR);
            closedir(dir);
            return 0;
        }
        
        /* Look for .not_terminated (active trail) */
        if (strstr(entry->d_name, ".not_terminated")) {
            snprintf(path, pathsize, "%s/%s", BSM_AUDIT_DIR, entry->d_name);
            closedir(dir);
            return 0;
        }
        
        /* Track newest regular audit file */
        char fullpath[PATH_MAX];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", BSM_AUDIT_DIR, entry->d_name);
        
        struct stat st;
        if (stat(fullpath, &st) == 0 && S_ISREG(st.st_mode)) {
            if (st.st_mtime > newest_time) {
                newest_time = st.st_mtime;
                snprintf(newest, sizeof(newest), "%s", entry->d_name);
            }
        }
    }
    
    closedir(dir);
    
    if (newest[0]) {
        snprintf(path, pathsize, "%s/%s", BSM_AUDIT_DIR, newest);
        return 0;
    }
    
    return -1;
}

/*
 * Detect which audit backend is available
 */
static audit_backend_type_t detect_audit_backend(void) {
    char trail[512];
    
    /* Try BSM first */
    if (find_current_audit_trail(trail, sizeof(trail)) == 0) {
        /* Verify we can actually read it */
        if (access(trail, R_OK) == 0) {
            return AUDIT_BACKEND_BSM_AVAILABLE;
        }
    }
    
#ifdef PLATFORM_MACOS
    /* Try Unified Logging on macOS */
    FILE *fp = popen("log show --last 1s --predicate 'process == \"kernel\"' 2>/dev/null | head -1", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp) != NULL && strlen(line) > 10) {
            pclose(fp);
            return AUDIT_BACKEND_UNIFIED_LOG;
        }
        pclose(fp);
    }
#endif
    
    return AUDIT_BACKEND_NONE_AVAILABLE;
}

/*
 * Find or add a hashed user to the failure list
 */
static hashed_user_t* find_or_add_user_bsm(audit_summary_t *summary, const char *username) {
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

/* ============================================================
 * BSM Backend Implementation
 * ============================================================ */

static void parse_auth_events_bsm_backend(audit_summary_t *summary) {
    char cmd[1024];
    char line[2048];
    FILE *fp;
    char trail[512];
    
    if (find_current_audit_trail(trail, sizeof(trail)) != 0) {
        return;
    }
    
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -iE '(authentication|login|su|sudo|ssh)' | "
             "tail -200",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp)) {
        bool is_failure = (strstr(line, "failure") != NULL ||
                          strstr(line, "failed") != NULL ||
                          strstr(line, "return,failure") != NULL);
        
        bool is_success = (strstr(line, "return,success") != NULL);
        
        if (is_failure) {
            summary->auth_failures++;
            
            char *subject = strstr(line, "subject,");
            if (subject) {
                subject += 8;
                char username[64] = {0};
                int i = 0;
                
                while (*subject && *subject != ',' && i < 63) {
                    username[i++] = *subject++;
                }
                username[i] = '\0';
                
                if (strlen(username) > 0 && !isdigit(username[0])) {
                    hashed_user_t *user = find_or_add_user_bsm(summary, username);
                    if (user) {
                        user->count++;
                    }
                }
            }
        } else if (is_success) {
            summary->auth_successes++;
        }
    }
    
    pclose(fp);
}

static void parse_priv_events_bsm_backend(audit_summary_t *summary) {
    char cmd[1024];
    char line[1024];
    FILE *fp;
    char trail[512];
    
    if (find_current_audit_trail(trail, sizeof(trail)) != 0) {
        return;
    }
    
    /* Count sudo events */
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -c -i 'sudo' 2>/dev/null",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->sudo_count = atoi(line);
        }
        pclose(fp);
    }
    
    /* Count su events */
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -E '(AUE_su|/usr/bin/su)' | "
             "grep -c -v sudo 2>/dev/null",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->su_count = atoi(line);
        }
        pclose(fp);
    }
}

static void parse_file_events_bsm_backend(audit_summary_t *summary) {
    char cmd[1024];
    char line[2048];
    FILE *fp;
    char trail[512];
    
    if (find_current_audit_trail(trail, sizeof(trail)) != 0) {
        return;
    }
    
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -E '/etc/(passwd|shadow|sudoers|master.passwd|ssh/)' | "
             "tail -50",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp) && 
           summary->sensitive_file_count < MAX_AUDIT_FILES) {
        
        char *path_start = NULL;
        
        const char *patterns[] = {
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/master.passwd", "/etc/ssh/", NULL
        };
        
        for (int i = 0; patterns[i]; i++) {
            path_start = strstr(line, patterns[i]);
            if (path_start) break;
        }
        
        if (!path_start) continue;
        
        char path[AUDIT_PATH_LEN] = {0};
        int j = 0;
        while (*path_start && *path_start != ',' && 
               *path_start != '\n' && j < AUDIT_PATH_LEN - 1) {
            path[j++] = *path_start++;
        }
        path[j] = '\0';
        
        if (strlen(path) == 0) continue;
        
        file_access_t *fa = NULL;
        for (int k = 0; k < summary->sensitive_file_count; k++) {
            if (strcmp(summary->sensitive_files[k].path, path) == 0) {
                fa = &summary->sensitive_files[k];
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
            
            if (strstr(path, "shadow") || strstr(path, "sudoers") ||
                strstr(path, "master.passwd")) {
                fa->suspicious = true;
            }
        }
    }
    
    pclose(fp);
}

static void parse_exec_events_bsm_backend(audit_summary_t *summary) {
    char cmd[1024];
    char line[1024];
    FILE *fp;
    char trail[512];
    
    if (find_current_audit_trail(trail, sizeof(trail)) != 0) {
        return;
    }
    
    /* Count executions from /tmp */
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -c '/tmp/' 2>/dev/null",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->tmp_executions = atoi(line);
        }
        pclose(fp);
    }
    
    /* BSD/macOS: check /var/tmp instead of /dev/shm */
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -c '/var/tmp/' 2>/dev/null",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->tmp_executions += atoi(line);
        }
        pclose(fp);
    }
    
    /* Count shell spawns */
    snprintf(cmd, sizeof(cmd),
             "%s -l '%s' 2>/dev/null | "
             "grep -cE '/(ba)?sh' 2>/dev/null",
             BSM_PRAUDIT_CMD, trail);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->shell_spawns = atoi(line);
        }
        pclose(fp);
    }
}

/* ============================================================
 * macOS Unified Logging Backend
 * ============================================================ */

#ifdef PLATFORM_MACOS

static void parse_auth_events_unified(audit_summary_t *summary) {
    char cmd[512];
    char line[2048];
    FILE *fp;
    
    /* Authentication failures */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "(eventMessage CONTAINS \"authentication failed\" OR "
             "eventMessage CONTAINS \"Authentication failed\" OR "
             "eventMessage CONTAINS \"FAILED LOGIN\" OR "
             "eventMessage CONTAINS \"error: PAM\")' "
             "--style compact 2>/dev/null | tail -100",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Timestamp") || strlen(line) < 20) continue;
            summary->auth_failures++;
            
            /* Try to extract username */
            char *user_ptr = strstr(line, "user=");
            if (!user_ptr) user_ptr = strstr(line, "User ");
            if (!user_ptr) user_ptr = strstr(line, "for ");
            
            if (user_ptr) {
                if (strstr(user_ptr, "user=")) user_ptr += 5;
                else if (strstr(user_ptr, "User ")) user_ptr += 5;
                else if (strstr(user_ptr, "for ")) user_ptr += 4;
                
                char username[64] = {0};
                int i = 0;
                while (*user_ptr && *user_ptr != ' ' && 
                       *user_ptr != ',' && *user_ptr != '\n' && i < 63) {
                    username[i++] = *user_ptr++;
                }
                username[i] = '\0';
                
                if (strlen(username) > 0 && !isdigit(username[0])) {
                    hashed_user_t *user = find_or_add_user_bsm(summary, username);
                    if (user) user->count++;
                }
            }
        }
        pclose(fp);
    }
    
    /* SSH failures specifically */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "process == \"sshd\" AND "
             "(eventMessage CONTAINS \"Failed\" OR eventMessage CONTAINS \"Invalid\")' "
             "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->auth_failures += atoi(line);
        }
        pclose(fp);
    }
    
    /* Successful auths (for baseline) */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "eventMessage CONTAINS \"Accepted\" OR "
             "eventMessage CONTAINS \"authentication succeeded\"' "
             "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->auth_successes = atoi(line);
        }
        pclose(fp);
    }
    
    summary->brute_force_detected = (summary->auth_failures > 5);
}

static void parse_priv_events_unified(audit_summary_t *summary) {
    char cmd[512];
    char line[256];
    FILE *fp;
    
    /* Sudo usage */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate 'process == \"sudo\"' "
             "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->sudo_count = atoi(line);
        }
        pclose(fp);
    }
    
    /* su usage */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "process == \"su\" OR eventMessage CONTAINS \"su:\"' "
             "--style compact 2>/dev/null | grep -v sudo | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->su_count = atoi(line);
        }
        pclose(fp);
    }
}

static void parse_file_events_unified(audit_summary_t *summary) {
    char cmd[512];
    char line[2048];
    FILE *fp;
    
    /* Look for sensitive file access in logs */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "eventMessage CONTAINS \"/etc/passwd\" OR "
             "eventMessage CONTAINS \"/etc/sudoers\" OR "
             "eventMessage CONTAINS \"/etc/master.passwd\" OR "
             "eventMessage CONTAINS \"/etc/ssh/\"' "
             "--style compact 2>/dev/null | tail -50",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp) && 
           summary->sensitive_file_count < MAX_AUDIT_FILES) {
        if (strstr(line, "Timestamp") || strlen(line) < 20) continue;
        
        const char *patterns[] = {
            "/etc/passwd", "/etc/sudoers", "/etc/master.passwd", "/etc/ssh/", NULL
        };
        
        for (int i = 0; patterns[i]; i++) {
            if (strstr(line, patterns[i])) {
                /* Find or create entry */
                file_access_t *fa = NULL;
                for (int k = 0; k < summary->sensitive_file_count; k++) {
                    if (strstr(summary->sensitive_files[k].path, patterns[i])) {
                        fa = &summary->sensitive_files[k];
                        break;
                    }
                }
                
                if (!fa && summary->sensitive_file_count < MAX_AUDIT_FILES) {
                    fa = &summary->sensitive_files[summary->sensitive_file_count++];
                    snprintf(fa->path, sizeof(fa->path), "%s", patterns[i]);
                    strcpy(fa->access_type, "access");
                    fa->count = 0;
                }
                
                if (fa) {
                    fa->count++;
                    if (strstr(patterns[i], "sudoers") || strstr(patterns[i], "master.passwd")) {
                        fa->suspicious = true;
                    }
                }
                break;
            }
        }
    }
    
    pclose(fp);
}

static void parse_exec_events_unified(audit_summary_t *summary) {
    char cmd[512];
    char line[256];
    FILE *fp;
    
    /* /tmp executions */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "eventMessage CONTAINS \"/tmp/\" AND "
             "(eventMessage CONTAINS \"exec\" OR subsystem == \"com.apple.execpolicy\")' "
             "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->tmp_executions = atoi(line);
        }
        pclose(fp);
    }
    
    /* Shell spawns - look for terminal/shell activity */
    snprintf(cmd, sizeof(cmd),
             "log show --last %dm --predicate '"
             "(process == \"bash\" OR process == \"zsh\" OR process == \"sh\") AND "
             "eventMessage CONTAINS \"exec\"' "
             "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
             g_window_seconds / 60 + 1);
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->shell_spawns = atoi(line);
        }
        pclose(fp);
    }
}

#endif /* PLATFORM_MACOS */

/* ============================================================
 * Security Framework (Platform-Specific)
 * ============================================================ */

void check_security_framework_bsm(audit_summary_t *summary) {
    FILE *fp;
    char line[256];

#ifdef PLATFORM_MACOS
    /* Check if SIP is enabled */
    fp = popen("csrutil status 2>/dev/null | grep -c enabled", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            summary->selinux_enforcing = (atoi(line) > 0);
        }
        pclose(fp);
    }
    
    /* Check Gatekeeper status */
    fp = popen("spctl --status 2>/dev/null | grep -c enabled", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            /* Use apparmor_denials field to indicate Gatekeeper */
            if (atoi(line) == 0) {
                summary->apparmor_denials = 1;  /* Gatekeeper disabled = concern */
            }
        }
        pclose(fp);
    }
    
    /* TCC (Transparency, Consent, Control) denials via Unified Log */
    if (g_backend == AUDIT_BACKEND_UNIFIED_LOG) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd),
                 "log show --last %dm --predicate '"
                 "subsystem == \"com.apple.TCC\" AND "
                 "eventMessage CONTAINS \"deny\"' "
                 "--style compact 2>/dev/null | grep -v Timestamp | wc -l",
                 g_window_seconds / 60 + 1);
        
        fp = popen(cmd, "r");
        if (fp) {
            if (fgets(line, sizeof(line), fp)) {
                summary->selinux_avc_denials = atoi(line);  /* Repurpose for TCC */
            }
            pclose(fp);
        }
    }
    
#elif defined(PLATFORM_BSD)
    /* Check securelevel */
    fp = popen("sysctl -n kern.securelevel 2>/dev/null", "r");
    if (fp) {
        if (fgets(line, sizeof(line), fp)) {
            int securelevel = atoi(line);
            summary->selinux_enforcing = (securelevel > 0);
        }
        pclose(fp);
    }
#endif
}

/* ============================================================
 * Unified Entry Points
 * ============================================================ */

void parse_auth_events_bsm(audit_summary_t *summary, int window_seconds) {
    (void)window_seconds;
    
    if (g_backend == AUDIT_BACKEND_BSM_AVAILABLE) {
        parse_auth_events_bsm_backend(summary);
    }
#ifdef PLATFORM_MACOS
    else if (g_backend == AUDIT_BACKEND_UNIFIED_LOG) {
        parse_auth_events_unified(summary);
    }
#endif
}

void parse_priv_events_bsm(audit_summary_t *summary, int window_seconds) {
    (void)window_seconds;
    
    if (g_backend == AUDIT_BACKEND_BSM_AVAILABLE) {
        parse_priv_events_bsm_backend(summary);
    }
#ifdef PLATFORM_MACOS
    else if (g_backend == AUDIT_BACKEND_UNIFIED_LOG) {
        parse_priv_events_unified(summary);
    }
#endif
}

void parse_file_events_bsm(audit_summary_t *summary, int window_seconds) {
    (void)window_seconds;
    
    if (g_backend == AUDIT_BACKEND_BSM_AVAILABLE) {
        parse_file_events_bsm_backend(summary);
    }
#ifdef PLATFORM_MACOS
    else if (g_backend == AUDIT_BACKEND_UNIFIED_LOG) {
        parse_file_events_unified(summary);
    }
#endif
}

void parse_exec_events_bsm(audit_summary_t *summary, int window_seconds) {
    (void)window_seconds;
    
    if (g_backend == AUDIT_BACKEND_BSM_AVAILABLE) {
        parse_exec_events_bsm_backend(summary);
    }
#ifdef PLATFORM_MACOS
    else if (g_backend == AUDIT_BACKEND_UNIFIED_LOG) {
        parse_exec_events_unified(summary);
    }
#endif
}

/* ============================================================
 * Main Probe Function
 * ============================================================ */

audit_summary_t* probe_audit_bsm(int window_seconds) {
    audit_summary_t *summary = calloc(1, sizeof(audit_summary_t));
    if (!summary) {
        return NULL;
    }
    
    g_window_seconds = window_seconds;
    summary->period_seconds = window_seconds;
    summary->capture_time = time(NULL);
    
    /* Detect available backend */
    g_backend = detect_audit_backend();
    
    if (g_backend == AUDIT_BACKEND_NONE_AVAILABLE) {
        summary->enabled = false;
        return summary;
    }
    
    summary->enabled = true;
    
    /* Load baseline */
    audit_baseline_t baseline = {0};
    bool has_baseline = load_audit_baseline(&baseline);
    
    /* Parse events using detected backend */
    parse_auth_events_bsm(summary, window_seconds);
    parse_priv_events_bsm(summary, window_seconds);
    parse_file_events_bsm(summary, window_seconds);
    parse_exec_events_bsm(summary, window_seconds);
    check_security_framework_bsm(summary);
    
    /* Anomaly detection */
    if (has_baseline) {
        detect_anomalies(summary, &baseline);
        summary->baseline_sample_count = baseline.sample_count;
    } else {
        summary->baseline_sample_count = 0;
    }
    
    /* Risk scoring */
    calculate_risk_score(summary);
    
    return summary;
}

#endif /* PLATFORM_MACOS || PLATFORM_BSD */

