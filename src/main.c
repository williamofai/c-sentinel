/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * main.c - CLI entry point
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "sentinel.h"

/* Default config files to probe if none specified */
static const char *default_configs[] = {
    "/etc/hosts",
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/fstab",
    "/etc/resolv.conf",
    NULL
};

static void print_usage(const char *prog) {
    fprintf(stderr, "C-Sentinel v%s - Semantic Observability for UNIX Systems\n\n", SENTINEL_VERSION);
    fprintf(stderr, "Usage: %s [OPTIONS] [config_files...]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
    fprintf(stderr, "  -q, --quick     Only show quick analysis summary\n");
    fprintf(stderr, "  -v, --verbose   Include all processes (not just notable ones)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no config files are specified, probes common system configs.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s /etc/nginx/nginx.conf /etc/mysql/my.cnf\n", prog);
}

int main(int argc, char *argv[]) {
    int quick_mode = 0;
    int opt;
    
    static struct option long_options[] = {
        {"help",    no_argument, 0, 'h'},
        {"quick",   no_argument, 0, 'q'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "hqv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'q':
                quick_mode = 1;
                break;
            case 'v':
                /* verbose mode - future enhancement */
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    /* Determine config files to probe */
    const char **configs;
    int config_count;
    
    if (optind < argc) {
        /* Use command line specified configs */
        configs = (const char **)&argv[optind];
        config_count = argc - optind;
    } else {
        /* Use defaults */
        configs = default_configs;
        config_count = 0;
        while (default_configs[config_count]) config_count++;
    }
    
    /* Capture the fingerprint */
    fingerprint_t fp;
    int result = capture_fingerprint(&fp, configs, config_count);
    
    if (result != 0) {
        fprintf(stderr, "Warning: Some probes failed (errors: %d)\n", fp.probe_errors);
    }
    
    if (quick_mode) {
        /* Quick analysis only */
        quick_analysis_t analysis;
        analyze_fingerprint_quick(&fp, &analysis);
        
        printf("C-Sentinel Quick Analysis\n");
        printf("========================\n");
        printf("Hostname: %s\n", fp.system.hostname);
        printf("Uptime: %.1f days\n", fp.system.uptime_seconds / 86400.0);
        printf("Load: %.2f %.2f %.2f\n", 
               fp.system.load_avg[0], fp.system.load_avg[1], fp.system.load_avg[2]);
        printf("Processes: %d total\n", fp.process_count);
        printf("\nPotential Issues:\n");
        printf("  Zombie processes: %d\n", analysis.zombie_process_count);
        printf("  High FD processes: %d\n", analysis.high_fd_process_count);
        printf("  Long-running (>7d): %d\n", analysis.long_running_process_count);
        printf("  Config permission issues: %d\n", analysis.config_permission_issues);
        
        return 0;
    }
    
    /* Full JSON output */
    char *json = fingerprint_to_json(&fp);
    if (!json) {
        fprintf(stderr, "Error: Failed to serialize fingerprint to JSON\n");
        return 1;
    }
    
    printf("%s", json);
    free(json);
    
    return 0;
}
