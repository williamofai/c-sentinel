/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * policy.c - Deterministic Safety Gate Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "policy.h"

/* ============================================================
 * Built-in Rules - The "Battle Scars" List
 * ============================================================
 * These are commands that should NEVER be suggested by an AI
 * in a production or non-prod environment. Each one represents
 * a real incident or near-miss from decades of UNIX experience.
 */

/* Commands that are always blocked */
static const char *BLOCKED_COMMANDS[] = {
    "rm -rf /",
    "rm -rf /*",
    "rm -rf .",
    "rm -rf ..",
    "mkfs",
    "dd if=",
    "> /dev/sda",
    "chmod 777 /",
    "chmod -R 777",
    "chown -R",
    ":(){:|:&};:",      /* Fork bomb */
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "systemctl halt",
    "systemctl poweroff",
    NULL
};

/* Patterns that indicate danger when found anywhere in command */
static const char *BLOCKED_PATTERNS[] = {
    "| sh",
    "| bash",
    "|sh",
    "|bash",
    "curl|",
    "wget|",
    "> /etc/passwd",
    "> /etc/shadow",
    "> /etc/sudoers",
    "mv /etc",
    "rm /etc",
    "--no-preserve-root",
    "/dev/sd",
    "/dev/nvme",
    "/dev/vd",
    "mkfs.",
    NULL
};

/* Commands that get a warning but aren't blocked */
static const char *WARN_PATTERNS[] = {
    "sudo ",
    "su -",
    "chmod ",
    "chown ",
    "kill ",
    "pkill ",
    "killall ",
    "service ",
    "systemctl restart",
    "systemctl stop",
    NULL
};

/* Safe read-only commands (explicitly allowed even in strict mode) */
static const char *SAFE_COMMANDS[] = {
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "df",
    "du",
    "ps",
    "top",
    "htop",
    "free",
    "uptime",
    "who",
    "w",
    "last",
    "netstat",
    "ss",
    "ip addr",
    "ip route",
    "mount",
    "lsblk",
    "lsof",
    "stat",
    "file",
    "wc",
    "sort",
    "uniq",
    "diff",
    "awk",
    "sed",  /* Note: sed can modify, but usually used for viewing */
    NULL
};

/* Critical paths that should never be suggested for modification */
static const char *PROTECTED_PATHS[] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/boot",
    "/etc/fstab",
    "/etc/crypttab",
    "/root",
    "/var/log",
    NULL
};

/* ============================================================
 * State
 * ============================================================ */

static policy_mode_t current_mode = MODE_NORMAL;
static int audit_enabled = 0;

#define MAX_AUDIT_ENTRIES 100
static audit_entry_t audit_log[MAX_AUDIT_ENTRIES];
static int audit_count = 0;

/* Custom rules storage */
#define MAX_CUSTOM_RULES 50
typedef struct {
    rule_type_t type;
    char pattern[256];
    risk_level_t risk;
    char reason[256];
    int active;
} custom_rule_t;

static custom_rule_t custom_rules[MAX_CUSTOM_RULES];
static int custom_rule_count = 0;

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Case-insensitive substring search */
static const char* strcasestr_local(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        
        while (*h && *n && (tolower((unsigned char)*h) == tolower((unsigned char)*n))) {
            h++;
            n++;
        }
        
        if (!*n) return haystack;
    }
    
    return NULL;
}

/* Check if string starts with prefix */
static int starts_with(const char *str, const char *prefix) {
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* Trim leading whitespace, return pointer into same buffer */
static const char* trim_left(const char *str) {
    while (*str && isspace((unsigned char)*str)) str++;
    return str;
}

/* Extract first "word" (command) from a string */
static void extract_command(const char *input, char *cmd, size_t cmd_size) {
    const char *trimmed = trim_left(input);
    size_t i = 0;
    
    while (trimmed[i] && !isspace((unsigned char)trimmed[i]) && i < cmd_size - 1) {
        cmd[i] = trimmed[i];
        i++;
    }
    cmd[i] = '\0';
}

/* Log an audit entry */
static void log_audit(const char *command, policy_result_t *result) {
    if (!audit_enabled) return;
    
    int idx = audit_count % MAX_AUDIT_ENTRIES;
    audit_log[idx].timestamp = (uint64_t)time(NULL);
    audit_log[idx].command = command;  /* Note: should strdup for safety */
    audit_log[idx].result = *result;
    audit_count++;
}

/* ============================================================
 * Core Validation Logic
 * ============================================================ */

policy_result_t policy_check_command(const char *command) {
    policy_result_t result = {
        .decision = POLICY_ALLOW,
        .risk = RISK_NONE,
        .reason = "No policy violations detected",
        .matched_rule = NULL
    };
    
    if (!command || !*command) {
        result.decision = POLICY_BLOCK;
        result.reason = "Empty command";
        return result;
    }
    
    const char *trimmed = trim_left(command);
    char first_cmd[128];
    extract_command(trimmed, first_cmd, sizeof(first_cmd));
    
    /* Phase 1: Check for explicitly blocked commands */
    for (int i = 0; BLOCKED_COMMANDS[i]; i++) {
        if (strcasestr_local(trimmed, BLOCKED_COMMANDS[i])) {
            result.decision = POLICY_BLOCK;
            result.risk = RISK_CRITICAL;
            result.reason = "Command matches blocked list - potential system damage";
            result.matched_rule = BLOCKED_COMMANDS[i];
            log_audit(command, &result);
            return result;
        }
    }
    
    /* Phase 2: Check for dangerous patterns anywhere in command */
    for (int i = 0; BLOCKED_PATTERNS[i]; i++) {
        if (strcasestr_local(trimmed, BLOCKED_PATTERNS[i])) {
            result.decision = POLICY_BLOCK;
            result.risk = RISK_HIGH;
            result.reason = "Command contains dangerous pattern";
            result.matched_rule = BLOCKED_PATTERNS[i];
            log_audit(command, &result);
            return result;
        }
    }
    
    /* Phase 3: Check custom rules */
    for (int i = 0; i < custom_rule_count; i++) {
        if (!custom_rules[i].active) continue;
        
        int matched = 0;
        switch (custom_rules[i].type) {
            case RULE_BLOCK_COMMAND:
                matched = (strcmp(trimmed, custom_rules[i].pattern) == 0);
                break;
            case RULE_BLOCK_PREFIX:
                matched = starts_with(trimmed, custom_rules[i].pattern);
                break;
            case RULE_BLOCK_CONTAINS:
                matched = (strcasestr_local(trimmed, custom_rules[i].pattern) != NULL);
                break;
            case RULE_ALLOW_COMMAND:
                if (starts_with(trimmed, custom_rules[i].pattern)) {
                    result.decision = POLICY_ALLOW;
                    result.risk = RISK_NONE;
                    result.reason = custom_rules[i].reason;
                    result.matched_rule = custom_rules[i].pattern;
                    log_audit(command, &result);
                    return result;
                }
                break;
            default:
                break;
        }
        
        if (matched && custom_rules[i].type != RULE_ALLOW_COMMAND) {
            result.decision = POLICY_BLOCK;
            result.risk = custom_rules[i].risk;
            result.reason = custom_rules[i].reason;
            result.matched_rule = custom_rules[i].pattern;
            log_audit(command, &result);
            return result;
        }
    }
    
    /* Phase 4: In strict mode, only allow explicitly safe commands */
    if (current_mode == MODE_STRICT) {
        int is_safe = 0;
        for (int i = 0; SAFE_COMMANDS[i]; i++) {
            if (strcmp(first_cmd, SAFE_COMMANDS[i]) == 0) {
                is_safe = 1;
                break;
            }
        }
        
        if (!is_safe) {
            result.decision = POLICY_REVIEW;
            result.risk = RISK_MEDIUM;
            result.reason = "Command not in safe list (strict mode)";
            result.matched_rule = "STRICT_MODE";
            log_audit(command, &result);
            return result;
        }
    }
    
    /* Phase 5: Check for warning patterns */
    for (int i = 0; WARN_PATTERNS[i]; i++) {
        if (strcasestr_local(trimmed, WARN_PATTERNS[i])) {
            result.decision = (current_mode == MODE_PERMISSIVE) ? POLICY_ALLOW : POLICY_WARN;
            result.risk = RISK_MEDIUM;
            result.reason = "Command may modify system state - review carefully";
            result.matched_rule = WARN_PATTERNS[i];
            log_audit(command, &result);
            return result;
        }
    }
    
    log_audit(command, &result);
    return result;
}

policy_result_t policy_check_path(const char *path) {
    policy_result_t result = {
        .decision = POLICY_ALLOW,
        .risk = RISK_NONE,
        .reason = "Path is not protected",
        .matched_rule = NULL
    };
    
    if (!path || !*path) {
        result.decision = POLICY_BLOCK;
        result.reason = "Empty path";
        return result;
    }
    
    /* Check against protected paths */
    for (int i = 0; PROTECTED_PATHS[i]; i++) {
        if (starts_with(path, PROTECTED_PATHS[i])) {
            result.decision = POLICY_BLOCK;
            result.risk = RISK_HIGH;
            result.reason = "Path is system-critical and protected";
            result.matched_rule = PROTECTED_PATHS[i];
            return result;
        }
    }
    
    return result;
}

/* ============================================================
 * Rule Management
 * ============================================================ */

int policy_add_rule(rule_type_t type, const char *pattern,
                    risk_level_t risk, const char *reason) {
    if (custom_rule_count >= MAX_CUSTOM_RULES) {
        return -1;
    }
    
    custom_rule_t *rule = &custom_rules[custom_rule_count];
    rule->type = type;
    strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
    rule->pattern[sizeof(rule->pattern) - 1] = '\0';
    rule->risk = risk;
    strncpy(rule->reason, reason, sizeof(rule->reason) - 1);
    rule->reason[sizeof(rule->reason) - 1] = '\0';
    rule->active = 1;
    
    custom_rule_count++;
    return 0;
}

void policy_clear_custom_rules(void) {
    custom_rule_count = 0;
}

int policy_count_rules(rule_type_t type) {
    int count = 0;
    for (int i = 0; i < custom_rule_count; i++) {
        if (custom_rules[i].type == type && custom_rules[i].active) {
            count++;
        }
    }
    return count;
}

/* ============================================================
 * Audit and Configuration
 * ============================================================ */

void policy_set_audit(int enabled) {
    audit_enabled = enabled;
}

int policy_get_audit_log(audit_entry_t *entries, int max_entries) {
    int start = (audit_count > MAX_AUDIT_ENTRIES) ? 
                audit_count - MAX_AUDIT_ENTRIES : 0;
    int count = 0;
    
    for (int i = start; i < audit_count && count < max_entries; i++) {
        entries[count] = audit_log[i % MAX_AUDIT_ENTRIES];
        count++;
    }
    
    return count;
}

void policy_set_mode(policy_mode_t mode) {
    current_mode = mode;
}

policy_mode_t policy_get_mode(void) {
    return current_mode;
}

int policy_init(void) {
    current_mode = MODE_NORMAL;
    audit_enabled = 0;
    custom_rule_count = 0;
    audit_count = 0;
    return 0;
}

void policy_cleanup(void) {
    policy_clear_custom_rules();
    audit_count = 0;
}
