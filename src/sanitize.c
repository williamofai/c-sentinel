/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * sanitize.c - Data Sanitization Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sanitize.h"

/* ============================================================
 * State and Configuration
 * ============================================================ */

#define MAX_CUSTOM_PATTERNS 32
#define MAX_SECRET_VARS 16
#define MAX_PATTERN_LEN 256

typedef struct {
    char pattern[MAX_PATTERN_LEN];
    char replacement[MAX_PATTERN_LEN];
    int active;
} custom_pattern_t;

static custom_pattern_t custom_patterns[MAX_CUSTOM_PATTERNS];
static int custom_pattern_count = 0;

static char secret_values[MAX_SECRET_VARS][MAX_PATTERN_LEN];
static int secret_value_count = 0;

static sanitize_stats_t last_stats;

/* Common patterns that look like secrets */
static const char *SECRET_PATTERNS[] = {
    "password=",
    "passwd=",
    "secret=",
    "api_key=",
    "apikey=",
    "token=",
    "auth=",
    "credential",
    "private_key",
    NULL
};

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Check if a string segment looks like an IPv4 address */
static int looks_like_ipv4(const char *str, int len) {
    if (len < 7 || len > 15) return 0;  /* "1.1.1.1" to "255.255.255.255" */
    
    int dots = 0;
    int digits = 0;
    int segment_digits = 0;
    
    for (int i = 0; i < len; i++) {
        if (str[i] == '.') {
            if (segment_digits == 0 || segment_digits > 3) return 0;
            dots++;
            segment_digits = 0;
        } else if (isdigit((unsigned char)str[i])) {
            digits++;
            segment_digits++;
        } else {
            return 0;
        }
    }
    
    /* Valid IPv4: exactly 3 dots, reasonable digit count */
    return (dots == 3 && digits >= 4 && digits <= 12 && segment_digits > 0);
}

/* Check if a string segment looks like an IPv6 address (simplified) */
static int looks_like_ipv6(const char *str, int len) {
    if (len < 2) return 0;
    
    int colons = 0;
    int hex_chars = 0;
    
    for (int i = 0; i < len; i++) {
        char c = str[i];
        if (c == ':') {
            colons++;
        } else if (isxdigit((unsigned char)c)) {
            hex_chars++;
        } else {
            return 0;
        }
    }
    
    /* IPv6 has multiple colons and hex digits */
    return (colons >= 2 && hex_chars >= 2);
}

/* Check if string looks like a home directory path */
static int looks_like_homedir(const char *str) {
    return (strncmp(str, "/home/", 6) == 0 ||
            strncmp(str, "/Users/", 7) == 0 ||
            strncmp(str, "/root", 5) == 0);
}

/* Safe string replacement in a buffer */
static int replace_range(char *buf, size_t buf_size, size_t pos, 
                         size_t old_len, const char *replacement) {
    size_t current_len = strlen(buf);
    size_t repl_len = strlen(replacement);
    size_t new_len = current_len - old_len + repl_len;
    
    if (new_len >= buf_size) return -1;  /* Would overflow */
    
    /* Move tail of string */
    memmove(buf + pos + repl_len, 
            buf + pos + old_len,
            current_len - pos - old_len + 1);  /* +1 for null terminator */
    
    /* Insert replacement */
    memcpy(buf + pos, replacement, repl_len);
    
    return 0;
}

/* Find end of a "word" (IP, hostname, etc.) */
static size_t find_word_end(const char *str) {
    size_t i = 0;
    while (str[i] && !isspace((unsigned char)str[i]) && 
           str[i] != '"' && str[i] != '\'' && 
           str[i] != ',' && str[i] != ';' &&
           str[i] != ')' && str[i] != ']' && str[i] != '}') {
        i++;
    }
    return i;
}

/* ============================================================
 * Core Sanitization
 * ============================================================ */

int sanitize_string(char *str, size_t max_len, sanitize_flags_t flags) {
    if (!str || max_len == 0) return -1;
    
    memset(&last_stats, 0, sizeof(last_stats));
    
    size_t pos = 0;
    size_t len = strlen(str);
    
    while (pos < len) {
        /* Skip whitespace */
        if (isspace((unsigned char)str[pos])) {
            pos++;
            continue;
        }
        
        size_t word_end = find_word_end(str + pos);
        if (word_end == 0) {
            pos++;
            continue;
        }
        
        /* Check for IPv4 */
        if ((flags & SANITIZE_IPV4) && looks_like_ipv4(str + pos, word_end)) {
            if (replace_range(str, max_len, pos, word_end, REDACT_IP) == 0) {
                last_stats.ipv4_count++;
                last_stats.total_redactions++;
                len = strlen(str);
                pos += strlen(REDACT_IP);
                continue;
            }
        }
        
        /* Check for IPv6 */
        if ((flags & SANITIZE_IPV6) && looks_like_ipv6(str + pos, word_end)) {
            if (replace_range(str, max_len, pos, word_end, REDACT_IP) == 0) {
                last_stats.ipv6_count++;
                last_stats.total_redactions++;
                len = strlen(str);
                pos += strlen(REDACT_IP);
                continue;
            }
        }
        
        /* Check for home directories */
        if ((flags & SANITIZE_HOMEDIR) && looks_like_homedir(str + pos)) {
            /* Find the username portion */
            const char *start = str + pos;
            const char *user_start = NULL;
            
            if (strncmp(start, "/home/", 6) == 0) {
                user_start = start + 6;
            } else if (strncmp(start, "/Users/", 7) == 0) {
                user_start = start + 7;
            }
            
            if (user_start) {
                /* Find end of username */
                const char *user_end = user_start;
                while (*user_end && *user_end != '/' && 
                       !isspace((unsigned char)*user_end)) {
                    user_end++;
                }
                
                size_t path_len = user_end - start;
                if (replace_range(str, max_len, pos, path_len, REDACT_PATH) == 0) {
                    last_stats.homedir_count++;
                    last_stats.total_redactions++;
                    len = strlen(str);
                    pos += strlen(REDACT_PATH);
                    continue;
                }
            }
        }
        
        pos += word_end;
    }
    
    /* Check for secrets (case-insensitive substring search) */
    if (flags & SANITIZE_SECRETS) {
        for (int i = 0; SECRET_PATTERNS[i]; i++) {
            char *found = str;
            while ((found = strstr(found, SECRET_PATTERNS[i])) != NULL) {
                /* Find the value after the = sign */
                char *eq = strchr(found, '=');
                if (eq && *(eq + 1)) {
                    char *value_start = eq + 1;
                    size_t value_len = find_word_end(value_start);
                    if (value_len > 0) {
                        if (replace_range(str, max_len, value_start - str, 
                                          value_len, REDACT_SECRET) == 0) {
                            last_stats.secret_count++;
                            last_stats.total_redactions++;
                            len = strlen(str);
                        }
                    }
                }
                found++;
            }
        }
        
        /* Check custom secret values */
        for (int i = 0; i < secret_value_count; i++) {
            char *found;
            while ((found = strstr(str, secret_values[i])) != NULL) {
                size_t secret_len = strlen(secret_values[i]);
                if (replace_range(str, max_len, found - str, 
                                  secret_len, REDACT_SECRET) == 0) {
                    last_stats.secret_count++;
                    last_stats.total_redactions++;
                    len = strlen(str);
                }
            }
        }
    }
    
    /* Check custom patterns */
    for (int i = 0; i < custom_pattern_count; i++) {
        if (!custom_patterns[i].active) continue;
        
        char *found;
        while ((found = strstr(str, custom_patterns[i].pattern)) != NULL) {
            size_t pattern_len = strlen(custom_patterns[i].pattern);
            const char *repl = custom_patterns[i].replacement[0] ? 
                               custom_patterns[i].replacement : "[REDACTED]";
            
            if (replace_range(str, max_len, found - str, pattern_len, repl) == 0) {
                last_stats.custom_count++;
                last_stats.total_redactions++;
                len = strlen(str);
            }
        }
    }
    
    return last_stats.total_redactions;
}

int sanitize_string_copy(const char *input, char *output,
                         size_t out_size, sanitize_flags_t flags) {
    if (!input || !output || out_size == 0) return -1;
    
    /* Copy input to output buffer */
    strncpy(output, input, out_size - 1);
    output[out_size - 1] = '\0';
    
    return sanitize_string(output, out_size, flags);
}

int sanitize_json(char *json, size_t max_len, sanitize_flags_t flags) {
    /* For JSON, we use the same sanitization but need to be
     * careful about JSON escaping. For now, use simple approach. */
    return sanitize_string(json, max_len, flags);
}

/* ============================================================
 * Pattern Management
 * ============================================================ */

int sanitize_add_pattern(const char *pattern, const char *replacement) {
    if (custom_pattern_count >= MAX_CUSTOM_PATTERNS) return -1;
    if (!pattern || !*pattern) return -1;
    
    custom_pattern_t *p = &custom_patterns[custom_pattern_count];
    strncpy(p->pattern, pattern, MAX_PATTERN_LEN - 1);
    p->pattern[MAX_PATTERN_LEN - 1] = '\0';
    
    if (replacement) {
        strncpy(p->replacement, replacement, MAX_PATTERN_LEN - 1);
        p->replacement[MAX_PATTERN_LEN - 1] = '\0';
    } else {
        p->replacement[0] = '\0';
    }
    
    p->active = 1;
    custom_pattern_count++;
    
    return 0;
}

int sanitize_add_secret_var(const char *var_name) {
    if (secret_value_count >= MAX_SECRET_VARS) return -1;
    if (!var_name) return -1;
    
    const char *value = getenv(var_name);
    if (!value || !*value) return 0;  /* Env var not set, skip */
    
    /* Store the value (not the name) so we can redact it */
    strncpy(secret_values[secret_value_count], value, MAX_PATTERN_LEN - 1);
    secret_values[secret_value_count][MAX_PATTERN_LEN - 1] = '\0';
    secret_value_count++;
    
    return 0;
}

void sanitize_clear_patterns(void) {
    custom_pattern_count = 0;
    secret_value_count = 0;
}

/* ============================================================
 * Utility Functions
 * ============================================================ */

sanitize_flags_t sanitize_detect(const char *str, sanitize_flags_t flags) {
    sanitize_flags_t found = SANITIZE_NONE;
    
    if (!str) return found;
    
    size_t len = strlen(str);
    size_t pos = 0;
    
    while (pos < len) {
        if (isspace((unsigned char)str[pos])) {
            pos++;
            continue;
        }
        
        size_t word_end = find_word_end(str + pos);
        if (word_end == 0) {
            pos++;
            continue;
        }
        
        if ((flags & SANITIZE_IPV4) && looks_like_ipv4(str + pos, word_end)) {
            found |= SANITIZE_IPV4;
        }
        
        if ((flags & SANITIZE_IPV6) && looks_like_ipv6(str + pos, word_end)) {
            found |= SANITIZE_IPV6;
        }
        
        if ((flags & SANITIZE_HOMEDIR) && looks_like_homedir(str + pos)) {
            found |= SANITIZE_HOMEDIR;
        }
        
        pos += word_end;
    }
    
    /* Check for secret patterns */
    if (flags & SANITIZE_SECRETS) {
        for (int i = 0; SECRET_PATTERNS[i]; i++) {
            if (strstr(str, SECRET_PATTERNS[i])) {
                found |= SANITIZE_SECRETS;
                break;
            }
        }
    }
    
    return found;
}

void sanitize_get_stats(sanitize_stats_t *stats) {
    if (stats) {
        *stats = last_stats;
    }
}

int sanitize_init(void) {
    custom_pattern_count = 0;
    secret_value_count = 0;
    memset(&last_stats, 0, sizeof(last_stats));
    
    /* Add common secret env vars */
    sanitize_add_secret_var("AWS_SECRET_ACCESS_KEY");
    sanitize_add_secret_var("AWS_SESSION_TOKEN");
    sanitize_add_secret_var("GITHUB_TOKEN");
    sanitize_add_secret_var("ANTHROPIC_API_KEY");
    sanitize_add_secret_var("OPENAI_API_KEY");
    sanitize_add_secret_var("DATABASE_PASSWORD");
    sanitize_add_secret_var("DB_PASSWORD");
    
    return 0;
}

void sanitize_cleanup(void) {
    sanitize_clear_patterns();
}
