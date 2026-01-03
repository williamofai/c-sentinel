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
#define SENTINEL_VERSION "0.6.0"
#define MAX_PATH_LEN 4096
#define MAX_PROCS 1024
#define MAX_FDS_PER_PROC 256
#define MAX_CONFIG_FILES 64
#define MAX_LISTENERS 128
#define MAX_CONNECTIONS 256

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

/* Network listener - for detecting unexpected open ports */
typedef struct {
    char protocol[8];           /* tcp, tcp6, udp, udp6 */
    char local_addr[64];        /* IP address */
    uint16_t local_port;
    char state[16];             /* LISTEN, ESTABLISHED, etc. */
    pid_t pid;                  /* Process owning this socket */
    char process_name[256];     /* Name of owning process */
} net_listener_t;

/* Network connection - for detecting suspicious connections */
typedef struct {
    char protocol[8];
    char local_addr[64];
    uint16_t local_port;
    char remote_addr[64];
    uint16_t remote_port;
    char state[16];
    pid_t pid;
    char process_name[256];
} net_connection_t;

/* Network summary */
typedef struct {
    net_listener_t listeners[MAX_LISTENERS];
    int listener_count;
    net_connection_t connections[MAX_CONNECTIONS];
    int connection_count;
    int total_established;
    int total_listening;
    int unusual_port_count;     /* Ports not in common list */
} network_info_t;

/* The complete system fingerprint */
typedef struct {
    system_info_t system;
    process_info_t processes[MAX_PROCS];
    int process_count;
    config_file_t configs[MAX_CONFIG_FILES];
    int config_count;
    network_info_t network;
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

/* Probe network state */
int probe_network(network_info_t *net);

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
    int unusual_listeners;          /* Ports not in common services list */
    int external_connections;       /* Connections to non-local IPs */
    int total_issues;               /* Sum of all issues for exit code */
} quick_analysis_t;

/* Exit codes for CI/CD integration */
#define EXIT_OK 0
#define EXIT_WARNINGS 1
#define EXIT_CRITICAL 2
#define EXIT_ERROR 3

int analyze_fingerprint_quick(const fingerprint_t *fp, quick_analysis_t *result);

/* ============================================================
 * Baseline Learning - Detect deviations from "normal"
 * ============================================================ */

#define MAX_BASELINE_LISTENERS 64
#define MAX_BASELINE_CONFIGS 32

/* Baseline data structure - what we consider "normal" */
typedef struct {
    /* Header */
    char magic[8];              /* "SNTLBASE" */
    uint32_t version;           /* Baseline format version */
    time_t created;
    time_t last_updated;
    char hostname[256];
    int sample_count;           /* How many samples contributed */
    
    /* Normal process ranges */
    int process_count_min;
    int process_count_max;
    int process_count_avg;
    
    /* Normal memory usage */
    double memory_used_percent_avg;
    double memory_used_percent_max;
    
    /* Normal load */
    double load_avg_1_max;
    double load_avg_5_max;
    
    /* Expected listeners - ports that should be open */
    uint16_t expected_ports[MAX_BASELINE_LISTENERS];
    int expected_port_count;
    
    /* Expected config checksums */
    struct {
        char path[256];
        char checksum[65];
    } expected_configs[MAX_BASELINE_CONFIGS];
    int expected_config_count;
    
} baseline_t;

/* Deviation report */
typedef struct {
    int new_listeners;          /* Ports open that weren't before */
    int missing_listeners;      /* Ports that should be open but aren't */
    int config_changes;         /* Config files with different checksums */
    int process_count_anomaly;  /* Outside normal range */
    int memory_anomaly;         /* Higher than normal */
    int load_anomaly;           /* Higher than normal */
    
    /* Details */
    uint16_t new_ports[32];
    int new_port_count;
    uint16_t missing_ports[32];
    int missing_port_count;
    char changed_configs[8][256];
    int changed_config_count;
    
    int total_deviations;
} deviation_report_t;

/* Baseline functions */
void baseline_init(baseline_t *b);
int baseline_load(baseline_t *b);
int baseline_save(const baseline_t *b);
int baseline_learn(baseline_t *b, const fingerprint_t *fp);
int baseline_compare(const baseline_t *b, const fingerprint_t *fp, 
                     deviation_report_t *report);
void baseline_print_report(const baseline_t *b, const deviation_report_t *report);
void baseline_print_info(const baseline_t *b);

/* ============================================================
 * Configuration
 * ============================================================ */

int config_load(void);
int config_create_default(void);
void config_print(void);

/* ============================================================
 * SHA256 Checksums
 * ============================================================ */

int sha256_file(const char *path, char *out, size_t out_size);
int sha256_string(const char *str, char *out, size_t out_size);

#endif /* SENTINEL_H */
