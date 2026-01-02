/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * baseline.c - Learn "normal" and detect deviations
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>

#include "sentinel.h"

/* Default baseline location */
#define DEFAULT_BASELINE_DIR ".sentinel"
#define BASELINE_FILENAME "baseline.dat"

/* Note: baseline_t and deviation_report_t are defined in sentinel.h */

/* Get baseline directory path */
static void get_baseline_dir(char *path, size_t path_size) {
    struct stat st;
    
    /* If /var/lib/sentinel exists and is writable, use it (system service mode) */
    if (stat("/var/lib/sentinel", &st) == 0 && S_ISDIR(st.st_mode)) {
        if (access("/var/lib/sentinel", W_OK) == 0) {
            snprintf(path, path_size, "/var/lib/sentinel");
            return;
        }
    }
    
    /* Fall back to ~/.sentinel (user mode) */
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(path, path_size, "%s/%s", home, DEFAULT_BASELINE_DIR);
}

/* Get baseline file path */
static void get_baseline_path(char *path, size_t path_size) {
    char dir[256];
    get_baseline_dir(dir, sizeof(dir));
    snprintf(path, path_size, "%s/%s", dir, BASELINE_FILENAME);
}

/* Ensure baseline directory exists */
static int ensure_baseline_dir(void) {
    char dir[512];
    get_baseline_dir(dir, sizeof(dir));
    
    struct stat st;
    if (stat(dir, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    
    return mkdir(dir, 0700);
}

/* Initialize a new baseline */
void baseline_init(baseline_t *b) {
    memset(b, 0, sizeof(*b));
    memcpy(b->magic, "SNTLBASE", 8);
    b->version = 1;
    b->created = time(NULL);
    b->last_updated = b->created;
    b->process_count_min = 9999;
    b->process_count_max = 0;
}

/* Load baseline from disk */
int baseline_load(baseline_t *b) {
    char path[512];
    get_baseline_path(path, sizeof(path));
    
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;  /* No baseline exists yet */
    }
    
    size_t read = fread(b, sizeof(*b), 1, f);
    fclose(f);
    
    if (read != 1 || memcmp(b->magic, "SNTLBASE", 8) != 0) {
        return -1;  /* Invalid or corrupt baseline */
    }
    
    return 0;
}

/* Save baseline to disk */
int baseline_save(const baseline_t *b) {
    if (ensure_baseline_dir() != 0) {
        return -1;
    }
    
    char path[512];
    get_baseline_path(path, sizeof(path));
    
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    
    size_t written = fwrite(b, sizeof(*b), 1, f);
    fclose(f);
    
    return (written == 1) ? 0 : -1;
}

/* Check if a port is in the expected list */
static int port_in_list(uint16_t port, const uint16_t *list, int count) {
    for (int i = 0; i < count; i++) {
        if (list[i] == port) return 1;
    }
    return 0;
}

/* Learn from current fingerprint - update baseline */
int baseline_learn(baseline_t *b, const fingerprint_t *fp) {
    /* Update hostname - use snprintf to avoid truncation warning */
    snprintf(b->hostname, sizeof(b->hostname), "%s", fp->system.hostname);
    
    /* Update process count range */
    if (fp->process_count < b->process_count_min) {
        b->process_count_min = fp->process_count;
    }
    if (fp->process_count > b->process_count_max) {
        b->process_count_max = fp->process_count;
    }
    
    /* Running average for process count */
    b->process_count_avg = (b->process_count_avg * b->sample_count + fp->process_count) 
                           / (b->sample_count + 1);
    
    /* Memory usage */
    double mem_used = 100.0 * (1.0 - (double)fp->system.free_ram / fp->system.total_ram);
    b->memory_used_percent_avg = (b->memory_used_percent_avg * b->sample_count + mem_used)
                                 / (b->sample_count + 1);
    if (mem_used > b->memory_used_percent_max) {
        b->memory_used_percent_max = mem_used;
    }
    
    /* Load averages - track maximums */
    if (fp->system.load_avg[0] > b->load_avg_1_max) {
        b->load_avg_1_max = fp->system.load_avg[0];
    }
    if (fp->system.load_avg[1] > b->load_avg_5_max) {
        b->load_avg_5_max = fp->system.load_avg[1];
    }
    
    /* Learn expected listeners */
    for (int i = 0; i < fp->network.listener_count && b->expected_port_count < MAX_BASELINE_LISTENERS; i++) {
        uint16_t port = fp->network.listeners[i].local_port;
        if (!port_in_list(port, b->expected_ports, b->expected_port_count)) {
            b->expected_ports[b->expected_port_count++] = port;
        }
    }
    
    /* Learn config checksums */
    for (int i = 0; i < fp->config_count && b->expected_config_count < MAX_BASELINE_CONFIGS; i++) {
        const config_file_t *cfg = &fp->configs[i];
        
        /* Check if we already have this path */
        int found = -1;
        for (int j = 0; j < b->expected_config_count; j++) {
            if (strcmp(b->expected_configs[j].path, cfg->path) == 0) {
                found = j;
                break;
            }
        }
        
        if (found >= 0) {
            /* Update existing - keep the checksum (first seen is "correct") */
        } else {
            /* Add new */
            strncpy(b->expected_configs[b->expected_config_count].path, 
                    cfg->path, 255);
            strncpy(b->expected_configs[b->expected_config_count].checksum,
                    cfg->checksum, 64);
            b->expected_config_count++;
        }
    }
    
    b->sample_count++;
    b->last_updated = time(NULL);
    
    return 0;
}

/* Compare fingerprint against baseline */
int baseline_compare(const baseline_t *b, const fingerprint_t *fp, 
                     deviation_report_t *report) {
    memset(report, 0, sizeof(*report));
    
    /* Check process count */
    int margin = (b->process_count_max - b->process_count_min) / 2 + 10;
    if (fp->process_count < b->process_count_min - margin ||
        fp->process_count > b->process_count_max + margin) {
        report->process_count_anomaly = 1;
        report->total_deviations++;
    }
    
    /* Check memory */
    double mem_used = 100.0 * (1.0 - (double)fp->system.free_ram / fp->system.total_ram);
    if (mem_used > b->memory_used_percent_max + 10.0) {
        report->memory_anomaly = 1;
        report->total_deviations++;
    }
    
    /* Check load */
    if (fp->system.load_avg[0] > b->load_avg_1_max * 2.0 ||
        fp->system.load_avg[1] > b->load_avg_5_max * 2.0) {
        report->load_anomaly = 1;
        report->total_deviations++;
    }
    
    /* Check for new listeners (ports that weren't in baseline) */
    for (int i = 0; i < fp->network.listener_count; i++) {
        uint16_t port = fp->network.listeners[i].local_port;
        if (!port_in_list(port, b->expected_ports, b->expected_port_count)) {
            if (report->new_port_count < 32) {
                report->new_ports[report->new_port_count++] = port;
            }
            report->new_listeners++;
        }
    }
    if (report->new_listeners > 0) {
        report->total_deviations++;
    }
    
    /* Check for missing listeners (expected ports that aren't open) */
    for (int i = 0; i < b->expected_port_count; i++) {
        int found = 0;
        for (int j = 0; j < fp->network.listener_count; j++) {
            if (fp->network.listeners[j].local_port == b->expected_ports[i]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            if (report->missing_port_count < 32) {
                report->missing_ports[report->missing_port_count++] = b->expected_ports[i];
            }
            report->missing_listeners++;
        }
    }
    if (report->missing_listeners > 0) {
        report->total_deviations++;
    }
    
    /* Check config file checksums */
    for (int i = 0; i < b->expected_config_count; i++) {
        for (int j = 0; j < fp->config_count; j++) {
            if (strcmp(b->expected_configs[i].path, fp->configs[j].path) == 0) {
                if (strcmp(b->expected_configs[i].checksum, fp->configs[j].checksum) != 0) {
                    if (report->changed_config_count < 8) {
                        strncpy(report->changed_configs[report->changed_config_count],
                                fp->configs[j].path, 255);
                        report->changed_config_count++;
                    }
                    report->config_changes++;
                }
                break;
            }
        }
    }
    if (report->config_changes > 0) {
        report->total_deviations++;
    }
    
    return report->total_deviations;
}

/* Print deviation report */
void baseline_print_report(const baseline_t *b, const deviation_report_t *report) {
    printf("\n");
    printf("Baseline Comparison\n");
    printf("══════════════════════════════════════════════════\n");
    printf("Baseline created: %s", ctime(&b->created));
    printf("Samples learned: %d\n", b->sample_count);
    printf("Expected ports: %d\n", b->expected_port_count);
    printf("Tracked configs: %d\n", b->expected_config_count);
    printf("\n");
    
    if (report->total_deviations == 0) {
        printf("✓ System matches baseline - no deviations detected\n");
        return;
    }
    
    printf("⚠ DEVIATIONS DETECTED: %d\n", report->total_deviations);
    printf("──────────────────────────────────────────────────\n");
    
    if (report->process_count_anomaly) {
        printf("• Process count outside normal range (%d - %d)\n",
               b->process_count_min, b->process_count_max);
    }
    
    if (report->memory_anomaly) {
        printf("• Memory usage above normal maximum (%.1f%%)\n",
               b->memory_used_percent_max);
    }
    
    if (report->load_anomaly) {
        printf("• Load average above normal maximum\n");
    }
    
    if (report->new_listeners > 0) {
        printf("• NEW LISTENERS (%d):", report->new_listeners);
        for (int i = 0; i < report->new_port_count && i < 10; i++) {
            printf(" %d", report->new_ports[i]);
        }
        printf("\n");
    }
    
    if (report->missing_listeners > 0) {
        printf("• MISSING LISTENERS (%d):", report->missing_listeners);
        for (int i = 0; i < report->missing_port_count && i < 10; i++) {
            printf(" %d", report->missing_ports[i]);
        }
        printf("\n");
    }
    
    if (report->config_changes > 0) {
        printf("• CONFIG CHANGES (%d):\n", report->config_changes);
        for (int i = 0; i < report->changed_config_count; i++) {
            printf("    - %s\n", report->changed_configs[i]);
        }
    }
}

/* Print baseline info */
void baseline_print_info(const baseline_t *b) {
    printf("\n");
    printf("Current Baseline\n");
    printf("══════════════════════════════════════════════════\n");
    printf("Hostname: %s\n", b->hostname);
    printf("Created: %s", ctime(&b->created));
    printf("Last updated: %s", ctime(&b->last_updated));
    printf("Samples: %d\n", b->sample_count);
    printf("\n");
    printf("Learned Ranges:\n");
    printf("  Process count: %d - %d (avg: %d)\n", 
           b->process_count_min, b->process_count_max, b->process_count_avg);
    printf("  Memory used: avg %.1f%%, max %.1f%%\n",
           b->memory_used_percent_avg, b->memory_used_percent_max);
    printf("  Load (1m/5m max): %.2f / %.2f\n",
           b->load_avg_1_max, b->load_avg_5_max);
    printf("\n");
    printf("Expected Ports (%d):\n  ", b->expected_port_count);
    for (int i = 0; i < b->expected_port_count; i++) {
        printf("%d ", b->expected_ports[i]);
        if ((i + 1) % 10 == 0) printf("\n  ");
    }
    printf("\n\n");
    printf("Tracked Configs (%d):\n", b->expected_config_count);
    for (int i = 0; i < b->expected_config_count; i++) {
        printf("  %s\n", b->expected_configs[i].path);
    }
}
