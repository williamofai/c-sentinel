/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * audit_common.c - Platform-independent audit logic
 *
 * This file contains audit functionality that is shared across
 * all platforms (Linux auditd, macOS/BSD OpenBSM):
 *   - Username hashing (privacy)
 *   - Risk scoring and factor tracking
 *   - Anomaly detection
 *   - Baseline management (load/save/update)
 *   - Deviation calculations
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>

#include "audit.h"
#include "audit_platform.h"
#include "sha256.h"

/* ============================================================
 * Constants
 * ============================================================ */

/* Salt for username hashing - should be consistent across runs */
static const char *username_salt = "c-sentinel-v1";

/* Exponential moving average alpha for baseline learning */
#define EMA_ALPHA 0.2f

/* ============================================================
 * Username Hashing (Privacy)
 * ============================================================ */

/*
 * Hash a username for privacy-preserving output
 * Output format: "user_xxxx" where xxxx is first 4 chars of hash
 */
void hash_username(const char *username, char *output, size_t outsize) {
    if (!username || !output || outsize < HASH_USERNAME_LEN) {
        if (output && outsize > 0) output[0] = '\0';
        return;
    }
    
    /* Combine username with salt */
    char salted[256];
    snprintf(salted, sizeof(salted), "%s:%s", username_salt, username);
    
    /* Use SHA256 for hashing */
    char hash[65];
    sha256_string(salted, hash, sizeof(hash));
    
    /* Take first 4 chars for readability */
    snprintf(output, outsize, "user_%.4s", hash);
}

/* ============================================================
 * Risk Factor Management
 * ============================================================ */

/*
 * Add a risk factor explaining part of the risk score
 */
void add_risk_factor(audit_summary_t *summary, const char *reason, int weight) {
    if (!summary || !reason) return;
    if (summary->risk_factor_count >= MAX_RISK_FACTORS) return;
    
    risk_factor_t *factor = &summary->risk_factors[summary->risk_factor_count++];
    snprintf(factor->reason, sizeof(factor->reason), "%s", reason);
    factor->weight = weight;
}

/* ============================================================
 * Risk Scoring
 * ============================================================ */

/*
 * Calculate overall risk score from audit summary
 * This is platform-independent - same logic for all backends
 */
void calculate_risk_score(audit_summary_t *summary) {
    if (!summary) return;
    
    int score = 0;
    int factor_score;
    char reason[RISK_FACTOR_REASON_LEN];
    
    /* Reset risk factors */
    summary->risk_factor_count = 0;
    
    /* Authentication failures */
    if (summary->auth_failures > 0) {
        factor_score = summary->auth_failures * 1;
        
        /* Apply deviation multiplier */
        if (summary->auth_deviation_pct > 500.0f) {
            factor_score = (int)(factor_score * 5.0f);
            snprintf(reason, sizeof(reason), 
                    "%d auth failures (%.0f%% above baseline - critical)", 
                    summary->auth_failures, summary->auth_deviation_pct);
        } else if (summary->auth_deviation_pct > 200.0f) {
            factor_score = (int)(factor_score * 3.0f);
            snprintf(reason, sizeof(reason), 
                    "%d auth failures (%.0f%% above baseline - high)", 
                    summary->auth_failures, summary->auth_deviation_pct);
        } else if (summary->auth_deviation_pct > 100.0f) {
            factor_score = (int)(factor_score * 2.0f);
            snprintf(reason, sizeof(reason), 
                    "%d auth failures (%.0f%% above baseline)", 
                    summary->auth_failures, summary->auth_deviation_pct);
        } else {
            snprintf(reason, sizeof(reason), "%d authentication failures", 
                    summary->auth_failures);
        }
        
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Brute force detection */
    if (summary->brute_force_detected) {
        add_risk_factor(summary, "Brute force attack pattern detected", 10);
        score += 10;
    }
    
    /* Privilege escalation - sudo deviation */
    if (summary->sudo_deviation_pct > 200.0f) {
        snprintf(reason, sizeof(reason), 
                "Sudo usage %.0f%% above baseline (%d commands)", 
                summary->sudo_deviation_pct, summary->sudo_count);
        add_risk_factor(summary, reason, 5);
        score += 5;
    }
    
    /* su usage */
    if (summary->su_count > 0) {
        factor_score = summary->su_count * 2;
        snprintf(reason, sizeof(reason), "%d su command(s) executed", summary->su_count);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* File integrity - permission changes */
    if (summary->permission_changes > 0) {
        factor_score = summary->permission_changes * 3;
        snprintf(reason, sizeof(reason), "%d file permission change(s)", 
                summary->permission_changes);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* File integrity - ownership changes */
    if (summary->ownership_changes > 0) {
        factor_score = summary->ownership_changes * 3;
        snprintf(reason, sizeof(reason), "%d file ownership change(s)", 
                summary->ownership_changes);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Sensitive file access */
    if (summary->sensitive_file_count > 0) {
        int suspicious_count = 0;
        for (int i = 0; i < summary->sensitive_file_count; i++) {
            if (summary->sensitive_files[i].suspicious) {
                suspicious_count++;
            }
        }
        
        factor_score = summary->sensitive_file_count * 2;
        if (suspicious_count > 0) {
            factor_score += suspicious_count * 5;
            snprintf(reason, sizeof(reason), 
                    "%d sensitive file(s) accessed (%d suspicious)", 
                    summary->sensitive_file_count, suspicious_count);
        } else {
            snprintf(reason, sizeof(reason), "%d sensitive file(s) accessed", 
                    summary->sensitive_file_count);
        }
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Executions from /tmp */
    if (summary->tmp_executions > 0) {
        factor_score = summary->tmp_executions * 4;
        snprintf(reason, sizeof(reason), "%d execution(s) from /tmp", 
                summary->tmp_executions);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Executions from /dev/shm */
    if (summary->devshm_executions > 0) {
        factor_score = summary->devshm_executions * 6;
        snprintf(reason, sizeof(reason), "%d execution(s) from /dev/shm", 
                summary->devshm_executions);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Suspicious process executions */
    if (summary->suspicious_exec_count > 0) {
        factor_score = summary->suspicious_exec_count * 10;
        snprintf(reason, sizeof(reason), 
                "%d suspicious process execution(s)", 
                summary->suspicious_exec_count);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Security framework - SELinux denials (Linux) */
    if (summary->selinux_avc_denials > 0) {
        factor_score = summary->selinux_avc_denials * 1;
        snprintf(reason, sizeof(reason), "%d SELinux AVC denial(s)", 
                summary->selinux_avc_denials);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    /* Security framework - AppArmor denials (Linux) */
    if (summary->apparmor_denials > 0) {
        factor_score = summary->apparmor_denials * 1;
        snprintf(reason, sizeof(reason), "%d AppArmor denial(s)", 
                summary->apparmor_denials);
        add_risk_factor(summary, reason, factor_score);
        score += factor_score;
    }
    
    summary->risk_score = score;
    
    /* Determine risk level */
    if (score >= 31) {
        strcpy(summary->risk_level, "critical");
    } else if (score >= 16) {
        strcpy(summary->risk_level, "high");
    } else if (score >= 6) {
        strcpy(summary->risk_level, "medium");
    } else {
        strcpy(summary->risk_level, "low");
    }
}

/* ============================================================
 * Deviation Calculations
 * ============================================================ */

/*
 * Calculate percentage deviation from baseline
 */
float calculate_deviation_pct(float current, float baseline_avg) {
    if (baseline_avg < 0.1f) {
        /* Baseline near zero - any activity is significant */
        return current > 0 ? 100.0f : 0.0f;
    }
    return ((current - baseline_avg) / baseline_avg) * 100.0f;
}

/*
 * Determine significance of deviation
 */
const char* deviation_significance(float deviation_pct) {
    if (deviation_pct > 500.0f) return "CRITICAL";
    if (deviation_pct > 200.0f) return "HIGH";
    if (deviation_pct > 100.0f) return "MEDIUM";
    if (deviation_pct > 50.0f) return "LOW";
    return "NORMAL";
}

/* ============================================================
 * Anomaly Detection
 * ============================================================ */

/*
 * Add an anomaly to the summary
 */
static void add_anomaly(audit_summary_t *summary, const char *type, 
                       const char *description, const char *severity,
                       float current, float baseline, float deviation) {
    if (!summary) return;
    if (summary->anomaly_count >= MAX_AUDIT_ANOMALIES) return;
    
    audit_anomaly_t *a = &summary->anomalies[summary->anomaly_count++];
    snprintf(a->type, sizeof(a->type), "%s", type);
    snprintf(a->description, sizeof(a->description), "%s", description);
    snprintf(a->severity, sizeof(a->severity), "%s", severity);
    a->current_value = current;
    a->baseline_avg = baseline;
    a->deviation_pct = deviation;
    a->timestamp = time(NULL);
}

/*
 * Detect anomalies by comparing against baseline
 */
void detect_anomalies(audit_summary_t *summary, const audit_baseline_t *baseline) {
    if (!summary || !baseline) return;
    if (baseline->sample_count < 5) {
        /* Not enough baseline data yet */
        return;
    }
    
    char desc[128];
    
    /* Authentication failures */
    summary->auth_baseline_avg = baseline->avg_auth_failures;
    summary->auth_deviation_pct = calculate_deviation_pct(
        (float)summary->auth_failures, baseline->avg_auth_failures);
    
    if (summary->auth_deviation_pct > 100.0f) {
        snprintf(desc, sizeof(desc), "%d auth failures (%.0f%% above baseline)",
                summary->auth_failures, summary->auth_deviation_pct);
        add_anomaly(summary, "auth_failure_spike", desc,
                   deviation_significance(summary->auth_deviation_pct),
                   (float)summary->auth_failures, baseline->avg_auth_failures,
                   summary->auth_deviation_pct);
    }
    
    /* Sudo usage */
    summary->sudo_baseline_avg = baseline->avg_sudo_count;
    summary->sudo_deviation_pct = calculate_deviation_pct(
        (float)summary->sudo_count, baseline->avg_sudo_count);
    
    if (summary->sudo_deviation_pct > 100.0f) {
        snprintf(desc, sizeof(desc), "%d sudo commands (%.0f%% above baseline)",
                summary->sudo_count, summary->sudo_deviation_pct);
        add_anomaly(summary, "sudo_spike", desc,
                   deviation_significance(summary->sudo_deviation_pct),
                   (float)summary->sudo_count, baseline->avg_sudo_count,
                   summary->sudo_deviation_pct);
    }
    
    /* Sensitive file access */
    float sensitive_deviation = calculate_deviation_pct(
        (float)summary->sensitive_file_count, baseline->avg_sensitive_access);
    
    if (sensitive_deviation > 100.0f) {
        snprintf(desc, sizeof(desc), "%d sensitive files accessed (%.0f%% above baseline)",
                summary->sensitive_file_count, sensitive_deviation);
        add_anomaly(summary, "sensitive_access_spike", desc,
                   deviation_significance(sensitive_deviation),
                   (float)summary->sensitive_file_count, baseline->avg_sensitive_access,
                   sensitive_deviation);
    }
    
    /* /tmp executions */
    float tmp_deviation = calculate_deviation_pct(
        (float)summary->tmp_executions, baseline->avg_tmp_executions);
    
    if (summary->tmp_executions > 0 && tmp_deviation > 50.0f) {
        snprintf(desc, sizeof(desc), "%d /tmp executions (%.0f%% above baseline)",
                summary->tmp_executions, tmp_deviation);
        add_anomaly(summary, "tmp_exec_spike", desc,
                   deviation_significance(tmp_deviation),
                   (float)summary->tmp_executions, baseline->avg_tmp_executions,
                   tmp_deviation);
    }
    
    /* Shell spawns */
    float shell_deviation = calculate_deviation_pct(
        (float)summary->shell_spawns, baseline->avg_shell_spawns);
    
    if (shell_deviation > 200.0f) {
        snprintf(desc, sizeof(desc), "%d shell spawns (%.0f%% above baseline)",
                summary->shell_spawns, shell_deviation);
        add_anomaly(summary, "shell_spawn_spike", desc,
                   deviation_significance(shell_deviation),
                   (float)summary->shell_spawns, baseline->avg_shell_spawns,
                   shell_deviation);
    }
}

/* ============================================================
 * Baseline Management
 * ============================================================ */

/*
 * Load audit baseline from disk
 */
bool load_audit_baseline(audit_baseline_t *baseline) {
    if (!baseline) return false;
    
    char path[512];
    FILE *fp;
    
    /* Try system path first, then user path */
    snprintf(path, sizeof(path), "%s", AUDIT_BASELINE_PATH_SYSTEM);
    fp = fopen(path, "rb");
    
    if (!fp) {
        const char *home = getenv("HOME");
        if (home) {
            snprintf(path, sizeof(path), "%s/%s", home, AUDIT_BASELINE_PATH_USER);
            fp = fopen(path, "rb");
        }
    }
    
    if (!fp) {
        return false;
    }
    
    if (fread(baseline, sizeof(*baseline), 1, fp) != 1) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    
    /* Validate magic */
    if (memcmp(baseline->magic, AUDIT_BASELINE_MAGIC, 8) != 0) {
        return false;
    }
    
    return true;
}

/*
 * Helper to create directory recursively (mkdir -p equivalent)
 */
static void create_directory(const char *dir) {
    char tmp[256];
    char *p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    
    /* Remove trailing slash */
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }
    
    /* Create each directory in path */
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/*
 * Save audit baseline to disk
 */
bool save_audit_baseline(const audit_baseline_t *baseline) {
    if (!baseline) return false;
    
    char path[512];
    char dir[512];
    FILE *fp;
    
    /* Try system path first */
    snprintf(path, sizeof(path), "%s", AUDIT_BASELINE_PATH_SYSTEM);
    
    /* Extract directory and create if needed */
    snprintf(dir, sizeof(dir), "%s", path);
    char *last_slash = strrchr(dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        create_directory(dir);
    }
    
    fp = fopen(path, "wb");
    
    if (!fp) {
        /* Fall back to user path */
        const char *home = getenv("HOME");
        if (!home) return false;
        
        snprintf(dir, sizeof(dir), "%s/.sentinel", home);
        snprintf(path, sizeof(path), "%s/%s", home, AUDIT_BASELINE_PATH_USER);
        
        create_directory(dir);
        
        fp = fopen(path, "wb");
    }
    
    if (!fp) {
        return false;
    }
    
    if (fwrite(baseline, sizeof(*baseline), 1, fp) != 1) {
        fclose(fp);
        return false;
    }
    
    fclose(fp);
    return true;
}

/*
 * Update baseline with new sample using exponential moving average
 */
void update_audit_baseline(audit_baseline_t *baseline, const audit_summary_t *current) {
    if (!baseline || !current) return;
    
    /* Initialize if new */
    if (baseline->sample_count == 0) {
        memcpy(baseline->magic, AUDIT_BASELINE_MAGIC, 8);
        baseline->version = AUDIT_BASELINE_VERSION;
        baseline->created = time(NULL);
        baseline->avg_auth_failures = (float)current->auth_failures;
        baseline->avg_sudo_count = (float)current->sudo_count;
        baseline->avg_sensitive_access = (float)current->sensitive_file_count;
        baseline->avg_tmp_executions = (float)current->tmp_executions;
        baseline->avg_shell_spawns = (float)current->shell_spawns;
    } else {
        /* Update using EMA */
        baseline->avg_auth_failures = 
            (current->auth_failures * EMA_ALPHA) + 
            (baseline->avg_auth_failures * (1 - EMA_ALPHA));
        baseline->avg_sudo_count = 
            (current->sudo_count * EMA_ALPHA) + 
            (baseline->avg_sudo_count * (1 - EMA_ALPHA));
        baseline->avg_sensitive_access = 
            (current->sensitive_file_count * EMA_ALPHA) + 
            (baseline->avg_sensitive_access * (1 - EMA_ALPHA));
        baseline->avg_tmp_executions = 
            (current->tmp_executions * EMA_ALPHA) + 
            (baseline->avg_tmp_executions * (1 - EMA_ALPHA));
        baseline->avg_shell_spawns = 
            (current->shell_spawns * EMA_ALPHA) + 
            (baseline->avg_shell_spawns * (1 - EMA_ALPHA));
    }
    
    baseline->sample_count++;
    baseline->updated = time(NULL);
}

/* ============================================================
 * Cleanup
 * ============================================================ */

/*
 * Free audit summary
 */
void free_audit_summary(audit_summary_t *summary) {
    free(summary);
}
