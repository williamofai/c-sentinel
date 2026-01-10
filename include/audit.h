/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * audit.h - Audit integration types and constants
 *
 * This header defines the data structures used by the audit module
 * across all platforms (Linux auditd, macOS/BSD OpenBSM).
 */

#ifndef AUDIT_H
#define AUDIT_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* ============================================================
 * Constants
 * ============================================================ */

#define MAX_AUDIT_USERS         16
#define MAX_AUDIT_FILES         32
#define MAX_AUDIT_ANOMALIES     16
#define MAX_SUSPICIOUS_PROCS    16
#define MAX_RISK_FACTORS        16
#define MAX_PROCESS_CHAIN_DEPTH 8
#ifndef AUDIT_PATH_LEN
    #define AUDIT_PATH_LEN 256
#endif
#define HASH_USERNAME_LEN       16
#define RISK_FACTOR_REASON_LEN  128

/* ============================================================
 * Process Chain (for file access context)
 * ============================================================ */

typedef struct {
    char names[MAX_PROCESS_CHAIN_DEPTH][64];
    int  depth;
} process_chain_t;

/* ============================================================
 * Hashed User (privacy-preserving)
 * ============================================================ */

typedef struct {
    char hash[HASH_USERNAME_LEN];   /* e.g., "user_8f3d" */
    int  count;                      /* Number of events for this user */
} hashed_user_t;

/* ============================================================
 * File Access Record
 * ============================================================ */

typedef struct {
    char path[AUDIT_PATH_LEN];
    char access_type[16];            /* "read", "write", "exec" */
    int  count;
    char process[64];                /* Process that accessed the file */
    process_chain_t chain;           /* Full process ancestry */
    bool suspicious;                 /* Flagged as suspicious? */
} file_access_t;

/* ============================================================
 * Suspicious Execution Record
 * ============================================================ */

typedef struct {
    char path[AUDIT_PATH_LEN];         /* Path of executed binary */
    char parent_process[64];         /* Parent process name */
    process_chain_t chain;           /* Full process ancestry */
    bool from_tmp;                   /* Executed from /tmp? */
    bool from_devshm;                /* Executed from /dev/shm? */
    char description[128];           /* Why it's suspicious */
} suspicious_exec_t;

/* ============================================================
 * Anomaly Record
 * ============================================================ */

typedef struct {
    char type[32];                   /* e.g., "auth_failure_spike" */
    char description[128];
    char severity[12];               /* "low", "medium", "high", "critical" */
    float current_value;
    float baseline_avg;
    float deviation_pct;
    time_t timestamp;
} audit_anomaly_t;

/* ============================================================
 * Risk Factor (explains score contribution)
 * ============================================================ */

typedef struct {
    char reason[RISK_FACTOR_REASON_LEN];
    int  weight;                     /* Points added to score */
} risk_factor_t;

/* ============================================================
 * Main Audit Summary Structure
 * ============================================================ */

typedef struct {
    /* Metadata */
    bool enabled;
    int  period_seconds;
    time_t capture_time;

    /* Authentication */
    int  auth_failures;
    int  auth_successes;             /* Track but don't output */
    hashed_user_t failure_users[MAX_AUDIT_USERS];
    int  failure_user_count;
    int  failure_sources;            /* Unique source addresses */
    float auth_baseline_avg;
    float auth_deviation_pct;
    bool brute_force_detected;

    /* Privilege escalation */
    int  sudo_count;
    float sudo_baseline_avg;
    float sudo_deviation_pct;
    int  su_count;
    int  setuid_executions;
    int  capability_changes;

    /* File integrity */
    int  permission_changes;
    int  ownership_changes;
    file_access_t sensitive_files[MAX_AUDIT_FILES];
    int  sensitive_file_count;

    /* Process activity */
    suspicious_exec_t suspicious_execs[MAX_SUSPICIOUS_PROCS];
    int  suspicious_exec_count;
    int  tmp_executions;
    int  devshm_executions;
    int  shell_spawns;
    int  cron_executions;

    /* Security framework */
    bool selinux_enforcing;          /* Or SIP/securelevel on BSD */
    int  selinux_avc_denials;        /* Or Sandbox denials on macOS */
    int  apparmor_denials;           /* Or TCC denials on macOS */

    /* Anomalies */
    audit_anomaly_t anomalies[MAX_AUDIT_ANOMALIES];
    int  anomaly_count;

    /* Risk assessment */
    int  risk_score;
    char risk_level[12];             /* "low", "medium", "high", "critical" */

    /* Risk factors - explains the score */
    risk_factor_t risk_factors[MAX_RISK_FACTORS];
    int  risk_factor_count;

    /* Baseline learning status */
    int  baseline_sample_count;      /* How many samples in baseline */
} audit_summary_t;

/* ============================================================
 * Rolling Baseline (stored to disk)
 * ============================================================ */

typedef struct {
    char magic[8];                   /* "SNTLAUDT" */
    uint32_t version;
    time_t created;
    time_t updated;
    uint32_t sample_count;

    /* Exponential moving averages */
    float avg_auth_failures;
    float avg_sudo_count;
    float avg_sensitive_access;
    float avg_tmp_executions;
    float avg_shell_spawns;
} audit_baseline_t;

#endif /* AUDIT_H */
