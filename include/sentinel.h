/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * A lightweight system prober that captures "system fingerprints"
 * for AI-assisted analysis of non-obvious risks.
 */

#ifndef SENTINEL_H
#define SENTINEL_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Version and limits */
#define SENTINEL_VERSION "0.1.0"
#define MAX_PATH_LEN 4096
#define MAX_PROCS 1024
#define MAX_FDS_PER_PROC 256
#define MAX_CONFIG_FILES 64

/* ============================================================
 * Core Data Structures - The "System Fingerprint"
 * ============================================================
 * These structures capture system state in a way that can be
 * serialized to JSON and sent to an LLM for semantic analysis.
 */

/* Basic system identity and health */
typedef struct {
    char hostname[256];
    char kernel_version[128];
    time_t boot_time;
    time_t probe_time;
    double load_avg[3];         /* 1, 5, 15 minute */
    uint64_t total_ram;
    uint64_t free_ram;
    uint64_t uptime_seconds;
} system_info_t;

/* Process snapshot - for detecting zombies and anomalies */
typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[256];
    char state;                 /* R, S, D, Z, T, etc. */
    uint64_t rss_bytes;         /* Resident memory */
    uint64_t vsize_bytes;       /* Virtual memory */
    time_t start_time;
    uint32_t open_fd_count;
    uint32_t thread_count;
    double cpu_percent;
    /* Zombie detection fields */
    uint64_t age_seconds;       /* How long has this been running? */
    int is_potentially_stuck;   /* Heuristic flag */
} process_info_t;

/* File descriptor info - for detecting leaked handles */
typedef struct {
    int fd;
    char type[32];              /* file, socket, pipe, etc. */
    char target[MAX_PATH_LEN];  /* What it points to */
    time_t estimated_age;       /* If we can determine it */
} fd_info_t;

/* Config file metadata - for drift detection */
typedef struct {
    char path[MAX_PATH_LEN];
    uint64_t size;
    time_t mtime;
    time_t ctime;
    mode_t permissions;
    uid_t owner;
    gid_t group;
    char checksum[65];          /* SHA256 hex string */
} config_file_t;

/* The complete system fingerprint */
typedef struct {
    system_info_t system;
    process_info_t processes[MAX_PROCS];
    int process_count;
    config_file_t configs[MAX_CONFIG_FILES];
    int config_count;
    /* Metadata about the probe itself */
    double probe_duration_ms;
    int probe_errors;
} fingerprint_t;

/* ============================================================
 * Prober Functions - Gather System State
 * ============================================================ */

/* Initialize a fingerprint structure */
int fingerprint_init(fingerprint_t *fp);

/* Probe system basics: hostname, kernel, memory, load */
int probe_system_info(system_info_t *info);

/* Probe running processes from /proc */
int probe_processes(process_info_t *procs, int max_procs, int *count);

/* Probe specific config files for drift detection */
int probe_config_files(const char **paths, int path_count, 
                       config_file_t *configs, int *config_count);

/* Full fingerprint capture */
int capture_fingerprint(fingerprint_t *fp, const char **config_paths, 
                        int config_path_count);

/* ============================================================
 * Serialization - Convert to JSON for LLM
 * ============================================================ */

/* Serialize fingerprint to JSON string (caller must free) */
char* fingerprint_to_json(const fingerprint_t *fp);

/* ============================================================
 * Sanitization - Strip sensitive data before sending to LLM
 * ============================================================ */

/* Redact IPs, usernames, and other PII from a string */
int sanitize_string(char *str, int max_len);

/* Sanitize entire fingerprint in place */
int sanitize_fingerprint(fingerprint_t *fp);

/* ============================================================
 * Analysis Helpers - Deterministic Pre-checks
 * ============================================================ */

/* Check for obvious issues before involving LLM */
typedef struct {
    int zombie_process_count;
    int high_fd_process_count;      /* Processes with >100 open fds */
    int long_running_process_count; /* Running >7 days */
    int config_permission_issues;   /* World-writable, etc. */
    int config_drift_detected;      /* Checksums differ from expected */
} quick_analysis_t;

int analyze_fingerprint_quick(const fingerprint_t *fp, quick_analysis_t *result);

#endif /* SENTINEL_H */
