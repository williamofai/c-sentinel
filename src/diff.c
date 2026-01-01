/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * diff.c - Fingerprint Drift Detection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ============================================================
 * Simple JSON Value Extraction
 * 
 * Note: This is intentionally simple - not a full JSON parser.
 * It extracts string and numeric values by key for comparison.
 * ============================================================ */

/* Find a string value in JSON (returns pointer to start of value, not including quotes) */
static const char* json_find_string(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char *found = strstr(json, search);
    if (!found) return NULL;
    
    found += strlen(search);
    while (*found && (*found == ' ' || *found == '\t')) found++;
    
    if (*found == '"') return found + 1;
    return NULL;
}

/* Extract a string value (caller provides buffer) */
static int json_get_string(const char *json, const char *key, 
                           char *buf, size_t buf_size) {
    const char *start = json_find_string(json, key);
    if (!start) return -1;
    
    size_t i = 0;
    while (start[i] && start[i] != '"' && i < buf_size - 1) {
        buf[i] = start[i];
        i++;
    }
    buf[i] = '\0';
    return 0;
}

/* Find a numeric value in JSON */
static int json_get_number(const char *json, const char *key, double *value) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char *found = strstr(json, search);
    if (!found) return -1;
    
    found += strlen(search);
    while (*found && (*found == ' ' || *found == '\t')) found++;
    
    if (*found == '"') return -1;  /* It's a string, not a number */
    
    *value = atof(found);
    return 0;
}

/* ============================================================
 * Diff Report Generation
 * ============================================================ */

typedef struct {
    char field[64];
    char value_a[256];
    char value_b[256];
    double numeric_a;
    double numeric_b;
    double diff_percent;
    int is_numeric;
    int is_significant;  /* Worthy of highlighting */
} diff_item_t;

#define MAX_DIFFS 100
static diff_item_t diffs[MAX_DIFFS];
static int diff_count = 0;

static void add_string_diff(const char *field, const char *a, const char *b) {
    if (diff_count >= MAX_DIFFS) return;
    if (strcmp(a, b) == 0) return;  /* No difference */
    
    diff_item_t *d = &diffs[diff_count++];
    strncpy(d->field, field, sizeof(d->field) - 1);
    strncpy(d->value_a, a, sizeof(d->value_a) - 1);
    strncpy(d->value_b, b, sizeof(d->value_b) - 1);
    d->is_numeric = 0;
    d->is_significant = 1;
}

static void add_numeric_diff(const char *field, double a, double b, double threshold) {
    if (diff_count >= MAX_DIFFS) return;
    
    double diff = fabs(a - b);
    double avg = (fabs(a) + fabs(b)) / 2.0;
    double percent = (avg > 0) ? (diff / avg * 100.0) : 0.0;
    
    if (percent < threshold) return;  /* Below significance threshold */
    
    diff_item_t *d = &diffs[diff_count++];
    strncpy(d->field, field, sizeof(d->field) - 1);
    snprintf(d->value_a, sizeof(d->value_a), "%.2f", a);
    snprintf(d->value_b, sizeof(d->value_b), "%.2f", b);
    d->numeric_a = a;
    d->numeric_b = b;
    d->diff_percent = percent;
    d->is_numeric = 1;
    d->is_significant = (percent > 10.0);  /* >10% is significant */
}

static void compare_fingerprints(const char *json_a, const char *json_b) {
    diff_count = 0;
    
    char buf_a[256], buf_b[256];
    double num_a, num_b;
    
    /* Compare system info */
    if (json_get_string(json_a, "hostname", buf_a, sizeof(buf_a)) == 0 &&
        json_get_string(json_b, "hostname", buf_b, sizeof(buf_b)) == 0) {
        add_string_diff("hostname", buf_a, buf_b);
    }
    
    if (json_get_string(json_a, "kernel", buf_a, sizeof(buf_a)) == 0 &&
        json_get_string(json_b, "kernel", buf_b, sizeof(buf_b)) == 0) {
        add_string_diff("kernel", buf_a, buf_b);
    }
    
    /* Numeric comparisons */
    if (json_get_number(json_a, "uptime_days", &num_a) == 0 &&
        json_get_number(json_b, "uptime_days", &num_b) == 0) {
        add_numeric_diff("uptime_days", num_a, num_b, 1.0);
    }
    
    if (json_get_number(json_a, "memory_total_gb", &num_a) == 0 &&
        json_get_number(json_b, "memory_total_gb", &num_b) == 0) {
        add_numeric_diff("memory_total_gb", num_a, num_b, 1.0);
    }
    
    if (json_get_number(json_a, "memory_used_percent", &num_a) == 0 &&
        json_get_number(json_b, "memory_used_percent", &num_b) == 0) {
        add_numeric_diff("memory_used_percent", num_a, num_b, 5.0);
    }
    
    if (json_get_number(json_a, "total_count", &num_a) == 0 &&
        json_get_number(json_b, "total_count", &num_b) == 0) {
        add_numeric_diff("process_count", num_a, num_b, 5.0);
    }
    
    if (json_get_number(json_a, "zombie_count", &num_a) == 0 &&
        json_get_number(json_b, "zombie_count", &num_b) == 0) {
        if (num_a != num_b) {
            add_numeric_diff("zombie_count", num_a, num_b, 0.0);
        }
    }
    
    if (json_get_number(json_a, "high_fd_count", &num_a) == 0 &&
        json_get_number(json_b, "high_fd_count", &num_b) == 0) {
        if (num_a != num_b) {
            add_numeric_diff("high_fd_count", num_a, num_b, 0.0);
        }
    }
    
    /* TODO: Compare config file checksums */
    /* This would require more sophisticated JSON parsing */
}

static void print_diff_report(const char *name_a, const char *name_b) {
    printf("C-Sentinel Drift Report\n");
    printf("========================\n");
    printf("Comparing: %s vs %s\n\n", name_a, name_b);
    
    if (diff_count == 0) {
        printf("No significant differences detected.\n");
        return;
    }
    
    printf("%-25s %-20s %-20s %s\n", "FIELD", name_a, name_b, "DELTA");
    printf("%-25s %-20s %-20s %s\n", "-----", "------", "------", "-----");
    
    int significant_count = 0;
    
    for (int i = 0; i < diff_count; i++) {
        diff_item_t *d = &diffs[i];
        
        char delta[32] = "";
        if (d->is_numeric && d->diff_percent > 0) {
            snprintf(delta, sizeof(delta), "%.1f%%", d->diff_percent);
        }
        
        /* Highlight significant diffs */
        const char *prefix = d->is_significant ? "* " : "  ";
        
        printf("%s%-23s %-20s %-20s %s\n", 
               prefix, d->field, d->value_a, d->value_b, delta);
        
        if (d->is_significant) significant_count++;
    }
    
    printf("\n");
    printf("Total differences: %d\n", diff_count);
    printf("Significant (*): %d\n", significant_count);
    
    if (significant_count > 0) {
        printf("\n--- Analysis Hints ---\n");
        for (int i = 0; i < diff_count; i++) {
            diff_item_t *d = &diffs[i];
            if (!d->is_significant) continue;
            
            if (strcmp(d->field, "kernel") == 0) {
                printf("- Kernel version mismatch: May affect system call behavior\n");
            } else if (strcmp(d->field, "uptime_days") == 0) {
                printf("- Uptime difference: Recent restart may indicate instability\n");
            } else if (strcmp(d->field, "memory_used_percent") == 0) {
                printf("- Memory usage differs: Check for memory leaks or different workloads\n");
            } else if (strcmp(d->field, "zombie_count") == 0) {
                printf("- Zombie process count differs: Parent process handling issue\n");
            } else if (strcmp(d->field, "high_fd_count") == 0) {
                printf("- FD-heavy processes differ: Possible descriptor leak\n");
            }
        }
    }
}

/* ============================================================
 * File Reading
 * ============================================================ */

static char* read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", path);
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    
    size_t bytes_read = fread(content, 1, size, f);
    content[bytes_read] = '\0';
    fclose(f);
    
    return content;
}

/* ============================================================
 * Main
 * ============================================================ */

static void print_usage(const char *prog) {
    fprintf(stderr, "C-Sentinel Diff - Fingerprint Drift Detection\n\n");
    fprintf(stderr, "Usage: %s <fingerprint_a.json> <fingerprint_b.json>\n\n", prog);
    fprintf(stderr, "Compares two system fingerprints and highlights differences.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  ./sentinel > node_a.json\n");
    fprintf(stderr, "  ssh node_b ./sentinel > node_b.json\n");
    fprintf(stderr, "  %s node_a.json node_b.json\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *file_a = argv[1];
    const char *file_b = argv[2];
    
    char *json_a = read_file(file_a);
    if (!json_a) return 1;
    
    char *json_b = read_file(file_b);
    if (!json_b) {
        free(json_a);
        return 1;
    }
    
    /* Extract hostnames for display (use filenames as fallback) */
    char name_a[64], name_b[64];
    if (json_get_string(json_a, "hostname", name_a, sizeof(name_a)) != 0) {
        strncpy(name_a, file_a, sizeof(name_a) - 1);
    }
    if (json_get_string(json_b, "hostname", name_b, sizeof(name_b)) != 0) {
        strncpy(name_b, file_b, sizeof(name_b) - 1);
    }
    
    compare_fingerprints(json_a, json_b);
    print_diff_report(name_a, name_b);
    
    free(json_a);
    free(json_b);
    
    return (diff_count > 0) ? 1 : 0;  /* Exit code indicates drift */
}
