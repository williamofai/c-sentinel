/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * audit_platform.h - Platform audit abstraction layer
 *
 * This header provides cross-platform audit support:
 *   - Linux: auditd (audit.log parsing via ausearch)
 *   - macOS: OpenBSM (audit trail via praudit)
 *   - BSD:   OpenBSM (audit trail via praudit)
 *
 * OpenBSM is shared across macOS and all BSD variants, providing
 * a single implementation for the entire BSD family.
 *
 * USAGE: Include this header instead of audit.h in your code.
 *        It includes audit.h automatically.
 */

#ifndef AUDIT_PLATFORM_H
#define AUDIT_PLATFORM_H

#include "audit.h"
#include "platform.h"

#include <stdlib.h>  /* for calloc in inline function */

/* ============================================================
 * Platform-Specific Audit Backend Identification
 * ============================================================ */

#ifdef PLATFORM_LINUX
    #define AUDIT_BACKEND_NAME      "auditd"
    #define AUDIT_BACKEND_AUDITD    1
    #define AUDIT_LOG_PATH          "/var/log/audit/audit.log"
#elif defined(PLATFORM_MACOS)
    #define AUDIT_BACKEND_NAME      "openbsm"
    #define AUDIT_BACKEND_BSM       1
    #define AUDIT_LOG_PATH          "/var/audit/current"
    #define AUDIT_CONTROL_PATH      "/etc/security/audit_control"
#elif defined(PLATFORM_BSD)
    #define AUDIT_BACKEND_NAME      "openbsm"
    #define AUDIT_BACKEND_BSM       1
    #define AUDIT_LOG_PATH          "/var/audit/current"
    #define AUDIT_CONTROL_PATH      "/etc/security/audit_control"
#else
    #define AUDIT_BACKEND_NAME      "none"
    #define AUDIT_BACKEND_NONE      1
#endif

/* ============================================================
 * Baseline file paths
 * ============================================================ */

#define AUDIT_BASELINE_PATH_SYSTEM "/var/lib/sentinel/audit_baseline.dat"
#define AUDIT_BASELINE_PATH_USER   ".sentinel/audit_baseline.dat"
#define AUDIT_BASELINE_MAGIC       "SNTLAUDT"
#define AUDIT_BASELINE_VERSION     1

/* ============================================================
 * Platform-Specific Audit Functions
 * ============================================================
 * Each platform implements these with identical signatures.
 * The implementation files are:
 *   - Linux: src/audit_linux.c
 *   - macOS/BSD: src/audit_bsm.c
 */

#ifdef AUDIT_BACKEND_AUDITD
audit_summary_t* probe_audit_linux(int period_seconds);
#endif

#ifdef AUDIT_BACKEND_BSM
audit_summary_t* probe_audit_bsm(int period_seconds);
#endif

/* ============================================================
 * Common Functions (Platform-Independent)
 * ============================================================
 * These are implemented in src/audit_common.c and shared by
 * all platform backends.
 */

/* Username hashing for privacy */
void hash_username(const char *username, char *output, size_t outsize);

/* Risk scoring */
void calculate_risk_score(audit_summary_t *summary);
void add_risk_factor(audit_summary_t *summary, const char *reason, int weight);

/* Anomaly detection */
void detect_anomalies(audit_summary_t *summary, const audit_baseline_t *baseline);
float calculate_deviation_pct(float current, float baseline_avg);
const char* deviation_significance(float deviation_pct);

/* Baseline management */
bool load_audit_baseline(audit_baseline_t *baseline);
bool save_audit_baseline(const audit_baseline_t *baseline);
void update_audit_baseline(audit_baseline_t *baseline, const audit_summary_t *current);

/* Cleanup */
void free_audit_summary(audit_summary_t *summary);

/* JSON serialization (implemented in audit_json.c) */
void audit_to_json(const audit_summary_t *summary, char *buf, size_t bufsize);

/* ============================================================
 * Unified Entry Point
 * ============================================================
 * This function automatically calls the correct platform
 * implementation based on compile-time detection.
 */

static inline audit_summary_t* probe_audit(int period_seconds) {
#ifdef AUDIT_BACKEND_AUDITD
    return probe_audit_linux(period_seconds);
#elif defined(AUDIT_BACKEND_BSM)
    return probe_audit_bsm(period_seconds);
#else
    /* No audit backend available */
    audit_summary_t *summary = calloc(1, sizeof(audit_summary_t));
    if (summary) {
        summary->enabled = false;
        summary->period_seconds = period_seconds;
        summary->capture_time = time(NULL);
    }
    return summary;
#endif
}

/* ============================================================
 * Platform Feature Detection
 * ============================================================ */

/* Check if audit is available on this system */
static inline bool audit_available(void) {
#ifdef AUDIT_BACKEND_AUDITD
    return (access(AUDIT_LOG_PATH, R_OK) == 0);
#elif defined(AUDIT_BACKEND_BSM)
    return (access(AUDIT_LOG_PATH, R_OK) == 0 || 
            access(AUDIT_CONTROL_PATH, R_OK) == 0);
#else
    return false;
#endif
}

/* Get human-readable backend name */
static inline const char* audit_backend_name(void) {
    return AUDIT_BACKEND_NAME;
}

#endif /* AUDIT_PLATFORM_H */
