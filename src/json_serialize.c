/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * json_serialize.c - Convert fingerprints to JSON for LLM analysis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "sentinel.h"

/* Buffer growth settings */
#define INITIAL_BUF_SIZE 8192
#define BUF_GROW_FACTOR 2

/* Dynamic buffer for JSON construction */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} json_buffer_t;

static int buf_init(json_buffer_t *buf) {
    buf->data = malloc(INITIAL_BUF_SIZE);
    if (!buf->data) return -1;
    buf->data[0] = '\0';
    buf->size = 0;
    buf->capacity = INITIAL_BUF_SIZE;
    return 0;
}

static int buf_ensure(json_buffer_t *buf, size_t additional) {
    if (buf->size + additional < buf->capacity) return 0;
    
    size_t new_cap = buf->capacity;
    while (new_cap < buf->size + additional) {
        new_cap *= BUF_GROW_FACTOR;
    }
    
    char *new_data = realloc(buf->data, new_cap);
    if (!new_data) return -1;
    
    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

static int buf_append(json_buffer_t *buf, const char *str) {
    size_t len = strlen(str);
    if (buf_ensure(buf, len + 1) != 0) return -1;
    
    memcpy(buf->data + buf->size, str, len + 1);
    buf->size += len;
    return 0;
}

static int buf_appendf(json_buffer_t *buf, const char *fmt, ...) {
    char tmp[1024];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    
    if (len < 0) return -1;
    if ((size_t)len >= sizeof(tmp)) {
        /* Need larger buffer */
        char *large = malloc(len + 1);
        if (!large) return -1;
        va_start(args, fmt);
        vsnprintf(large, len + 1, fmt, args);
        va_end(args);
        int result = buf_append(buf, large);
        free(large);
        return result;
    }
    
    return buf_append(buf, tmp);
}

/* Escape a string for JSON */
static int buf_append_json_string(json_buffer_t *buf, const char *str) {
    if (buf_append(buf, "\"") != 0) return -1;
    
    for (const char *p = str; *p; p++) {
        char escaped[8];
        switch (*p) {
            case '"':  strcpy(escaped, "\\\""); break;
            case '\\': strcpy(escaped, "\\\\"); break;
            case '\b': strcpy(escaped, "\\b"); break;
            case '\f': strcpy(escaped, "\\f"); break;
            case '\n': strcpy(escaped, "\\n"); break;
            case '\r': strcpy(escaped, "\\r"); break;
            case '\t': strcpy(escaped, "\\t"); break;
            default:
                if ((unsigned char)*p < 0x20) {
                    snprintf(escaped, sizeof(escaped), "\\u%04x", (unsigned char)*p);
                } else {
                    escaped[0] = *p;
                    escaped[1] = '\0';
                }
        }
        if (buf_append(buf, escaped) != 0) return -1;
    }
    
    return buf_append(buf, "\"");
}

/* Format time as ISO 8601 */
static void format_iso_time(time_t t, char *buf, size_t buf_size) {
    struct tm *tm = gmtime(&t);
    strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", tm);
}

/* ============================================================
 * Main Serialization Function
 * ============================================================ */

char* fingerprint_to_json(const fingerprint_t *fp) {
    if (!fp) return NULL;
    
    json_buffer_t buf;
    if (buf_init(&buf) != 0) return NULL;
    
    char time_buf[32];
    
    /* Root object */
    buf_append(&buf, "{\n");
    
    /* Metadata */
    buf_append(&buf, "  \"sentinel_version\": \"" SENTINEL_VERSION "\",\n");
    format_iso_time(fp->system.probe_time, time_buf, sizeof(time_buf));
    buf_appendf(&buf, "  \"probe_time\": \"%s\",\n", time_buf);
    buf_appendf(&buf, "  \"probe_duration_ms\": %.2f,\n", fp->probe_duration_ms);
    buf_appendf(&buf, "  \"probe_errors\": %d,\n", fp->probe_errors);
    
    /* System info */
    buf_append(&buf, "  \"system\": {\n");
    buf_append(&buf, "    \"hostname\": ");
    buf_append_json_string(&buf, fp->system.hostname);
    buf_append(&buf, ",\n");
    buf_append(&buf, "    \"kernel\": ");
    buf_append_json_string(&buf, fp->system.kernel_version);
    buf_append(&buf, ",\n");
    buf_appendf(&buf, "    \"uptime_days\": %.2f,\n", 
                fp->system.uptime_seconds / 86400.0);
    buf_appendf(&buf, "    \"load_average\": [%.2f, %.2f, %.2f],\n",
                fp->system.load_avg[0], fp->system.load_avg[1], fp->system.load_avg[2]);
    buf_appendf(&buf, "    \"memory_total_gb\": %.2f,\n",
                fp->system.total_ram / (1024.0 * 1024.0 * 1024.0));
    buf_appendf(&buf, "    \"memory_free_gb\": %.2f,\n",
                fp->system.free_ram / (1024.0 * 1024.0 * 1024.0));
    buf_appendf(&buf, "    \"memory_used_percent\": %.1f\n",
                100.0 * (1.0 - (double)fp->system.free_ram / fp->system.total_ram));
    buf_append(&buf, "  },\n");
    
    /* Process summary - we don't dump all processes, just interesting ones */
    buf_append(&buf, "  \"process_summary\": {\n");
    buf_appendf(&buf, "    \"total_count\": %d,\n", fp->process_count);
    
    /* Find interesting processes */
    int zombie_count = 0;
    int high_fd_count = 0;
    int stuck_count = 0;
    
    buf_append(&buf, "    \"notable_processes\": [\n");
    int first = 1;
    
    for (int i = 0; i < fp->process_count; i++) {
        const process_info_t *p = &fp->processes[i];
        
        /* Only include "interesting" processes */
        int interesting = 0;
        const char *reason = "";
        
        if (p->state == 'Z') {
            interesting = 1;
            reason = "zombie";
            zombie_count++;
        } else if (p->open_fd_count > 100 && p->open_fd_count < 100000) {
            /* Only flag if we could actually read FDs (uint32 -1 wraps to ~4 billion) */
            interesting = 1;
            reason = "high_fd_count";
            high_fd_count++;
        } else if (p->is_potentially_stuck) {
            interesting = 1;
            reason = "potentially_stuck";
            stuck_count++;
        } else if (p->age_seconds > 30 * 24 * 3600) {
            interesting = 1;
            reason = "very_long_running";
        } else if (p->rss_bytes > 1024 * 1024 * 1024) {
            interesting = 1;
            reason = "high_memory";
        }
        
        if (interesting) {
            if (!first) buf_append(&buf, ",\n");
            first = 0;
            
            buf_append(&buf, "      {\n");
            buf_appendf(&buf, "        \"pid\": %d,\n", p->pid);
            buf_append(&buf, "        \"name\": ");
            buf_append_json_string(&buf, p->name);
            buf_append(&buf, ",\n");
            buf_appendf(&buf, "        \"state\": \"%c\",\n", p->state);
            buf_appendf(&buf, "        \"age_days\": %.2f,\n", p->age_seconds / 86400.0);
            buf_appendf(&buf, "        \"memory_mb\": %.1f,\n", p->rss_bytes / (1024.0 * 1024.0));
            buf_appendf(&buf, "        \"open_fds\": %d,\n", p->open_fd_count);
            buf_appendf(&buf, "        \"threads\": %d,\n", p->thread_count);
            buf_append(&buf, "        \"flag\": ");
            buf_append_json_string(&buf, reason);
            buf_append(&buf, "\n");
            buf_append(&buf, "      }");
        }
    }
    
    buf_append(&buf, "\n    ],\n");
    buf_appendf(&buf, "    \"zombie_count\": %d,\n", zombie_count);
    buf_appendf(&buf, "    \"high_fd_count\": %d,\n", high_fd_count);
    buf_appendf(&buf, "    \"stuck_count\": %d\n", stuck_count);
    buf_append(&buf, "  },\n");
    
    /* Config files */
    buf_append(&buf, "  \"config_files\": [\n");
    for (int i = 0; i < fp->config_count; i++) {
        const config_file_t *c = &fp->configs[i];
        
        if (i > 0) buf_append(&buf, ",\n");
        
        buf_append(&buf, "    {\n");
        buf_append(&buf, "      \"path\": ");
        buf_append_json_string(&buf, c->path);
        buf_append(&buf, ",\n");
        buf_appendf(&buf, "      \"size_bytes\": %lu,\n", (unsigned long)c->size);
        format_iso_time(c->mtime, time_buf, sizeof(time_buf));
        buf_appendf(&buf, "      \"modified\": \"%s\",\n", time_buf);
        buf_appendf(&buf, "      \"permissions\": \"%04o\",\n", c->permissions & 07777);
        buf_appendf(&buf, "      \"owner_uid\": %d,\n", c->owner);
        buf_append(&buf, "      \"checksum\": ");
        buf_append_json_string(&buf, c->checksum);
        
        /* Flag permission issues */
        if (c->permissions & S_IWOTH) {
            buf_append(&buf, ",\n      \"warning\": \"world_writable\"");
        }
        
        buf_append(&buf, "\n    }");
    }
    buf_append(&buf, "\n  ]\n");
    
    buf_append(&buf, "}\n");
    
    return buf.data;
}
