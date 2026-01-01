/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * policy.h - Deterministic Safety Gate for LLM Suggestions
 */

#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>

/* Policy decision types */
typedef enum {
    POLICY_ALLOW,           /* Command is safe to present */
    POLICY_WARN,            /* Present with warning */
    POLICY_BLOCK,           /* Do not present to user */
    POLICY_REVIEW           /* Requires human review */
} policy_decision_t;

/* Risk levels for categorization */
typedef enum {
    RISK_NONE = 0,
    RISK_LOW = 1,
    RISK_MEDIUM = 2,
    RISK_HIGH = 3,
    RISK_CRITICAL = 4
} risk_level_t;

/* Result of a policy check */
typedef struct {
    policy_decision_t decision;
    risk_level_t risk;
    const char *reason;         /* Human-readable explanation */
    const char *matched_rule;   /* Which rule triggered */
} policy_result_t;

/* ============================================================
 * Command Validation - Check if a suggested command is safe
 * ============================================================ */

/*
 * Validate a shell command suggested by an LLM.
 * 
 * This is the core safety gate. It checks:
 * - Blocked commands (rm -rf, mkfs, dd, etc.)
 * - Dangerous patterns (pipes to sh, curl|bash, etc.)
 * - Privilege escalation attempts
 * - Write operations vs read-only
 * 
 * Returns: policy_result_t with decision and explanation
 */
policy_result_t policy_check_command(const char *command);

/*
 * Check if a file path is safe to recommend for modification.
 * 
 * Blocks:
 * - System critical paths (/etc/passwd, /etc/shadow, etc.)
 * - Boot-related files
 * - Kernel parameters (unless explicitly allowed)
 */
policy_result_t policy_check_path(const char *path);

/* ============================================================
 * Rule Management
 * ============================================================ */

/* Rule types */
typedef enum {
    RULE_BLOCK_COMMAND,     /* Block exact command */
    RULE_BLOCK_PREFIX,      /* Block commands starting with */
    RULE_BLOCK_CONTAINS,    /* Block if command contains */
    RULE_BLOCK_PATH,        /* Block file path modifications */
    RULE_ALLOW_COMMAND,     /* Explicitly allow (overrides blocks) */
    RULE_WARN_COMMAND       /* Allow but warn */
} rule_type_t;

/* Add a custom rule at runtime */
int policy_add_rule(rule_type_t type, const char *pattern, 
                    risk_level_t risk, const char *reason);

/* Clear all custom rules (keeps built-in rules) */
void policy_clear_custom_rules(void);

/* Get count of rules by type */
int policy_count_rules(rule_type_t type);

/* ============================================================
 * Audit and Logging
 * ============================================================ */

/* Audit log entry */
typedef struct {
    uint64_t timestamp;
    const char *command;
    policy_result_t result;
} audit_entry_t;

/* Enable/disable audit logging */
void policy_set_audit(int enabled);

/* Get recent audit entries (returns count, fills buffer) */
int policy_get_audit_log(audit_entry_t *entries, int max_entries);

/* ============================================================
 * Policy Configuration
 * ============================================================ */

/* Operating modes */
typedef enum {
    MODE_STRICT,        /* Block anything not explicitly allowed */
    MODE_NORMAL,        /* Block known dangerous, allow others */
    MODE_PERMISSIVE     /* Warn but don't block (for testing) */
} policy_mode_t;

/* Set operating mode */
void policy_set_mode(policy_mode_t mode);

/* Get current mode */
policy_mode_t policy_get_mode(void);

/* Initialize policy engine with defaults */
int policy_init(void);

/* Cleanup */
void policy_cleanup(void);

#endif /* POLICY_H */
