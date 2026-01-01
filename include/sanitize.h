/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * sanitize.h - Data Sanitization Before External Transmission
 */

#ifndef SANITIZE_H
#define SANITIZE_H

#include <stddef.h>

/* Redaction placeholders - visible so analysts know data was removed */
#define REDACT_IP       "[REDACTED-IP]"
#define REDACT_USER     "[REDACTED-USER]"
#define REDACT_HOST     "[REDACTED-HOST]"
#define REDACT_PATH     "[REDACTED-PATH]"
#define REDACT_SECRET   "[REDACTED-SECRET]"

/* Sanitization options (can be OR'd together) */
typedef enum {
    SANITIZE_NONE       = 0,
    SANITIZE_IPV4       = 1 << 0,   /* Redact IPv4 addresses */
    SANITIZE_IPV6       = 1 << 1,   /* Redact IPv6 addresses */
    SANITIZE_HOSTNAME   = 1 << 2,   /* Redact hostnames */
    SANITIZE_USERNAME   = 1 << 3,   /* Redact usernames from paths */
    SANITIZE_HOMEDIR    = 1 << 4,   /* Redact /home/username paths */
    SANITIZE_SECRETS    = 1 << 5,   /* Redact potential secrets */
    SANITIZE_ALL        = 0xFFFF    /* Everything */
} sanitize_flags_t;

/* Default: IP addresses and home directories */
#define SANITIZE_DEFAULT (SANITIZE_IPV4 | SANITIZE_IPV6 | SANITIZE_HOMEDIR | SANITIZE_SECRETS)

/* ============================================================
 * Core Sanitization Functions
 * ============================================================ */

/*
 * Sanitize a string in place.
 * 
 * Note: The output may be LONGER than input due to redaction
 * placeholders. Ensure buffer has adequate space.
 * 
 * @param str       String to sanitize (modified in place)
 * @param max_len   Maximum buffer size
 * @param flags     What to sanitize (SANITIZE_* flags)
 * @return          Number of redactions made, or -1 on error
 */
int sanitize_string(char *str, size_t max_len, sanitize_flags_t flags);

/*
 * Sanitize a string to a new buffer.
 * 
 * @param input     Input string
 * @param output    Output buffer
 * @param out_size  Size of output buffer
 * @param flags     What to sanitize
 * @return          Number of redactions, or -1 on error
 */
int sanitize_string_copy(const char *input, char *output, 
                         size_t out_size, sanitize_flags_t flags);

/*
 * Sanitize JSON content.
 * 
 * Handles JSON escaping properly while sanitizing values.
 * Does not modify JSON structure, only string values.
 * 
 * @param json      JSON string to sanitize (modified in place)
 * @param max_len   Maximum buffer size
 * @param flags     What to sanitize
 * @return          Number of redactions, or -1 on error
 */
int sanitize_json(char *json, size_t max_len, sanitize_flags_t flags);

/* ============================================================
 * Pattern Management
 * ============================================================ */

/*
 * Add a custom pattern to redact.
 * 
 * Useful for organization-specific patterns like:
 * - Internal domain names
 * - Project codenames
 * - Internal IP ranges
 * 
 * @param pattern       Pattern to match (simple substring, not regex)
 * @param replacement   What to replace with (or NULL for default)
 * @return              0 on success, -1 on error
 */
int sanitize_add_pattern(const char *pattern, const char *replacement);

/*
 * Add sensitive environment variable names.
 * 
 * Values of these env vars will be redacted if found in strings.
 * 
 * @param var_name  Environment variable name (e.g., "AWS_SECRET_KEY")
 * @return          0 on success, -1 on error
 */
int sanitize_add_secret_var(const char *var_name);

/*
 * Clear all custom patterns.
 */
void sanitize_clear_patterns(void);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/*
 * Check if a string contains potentially sensitive data.
 * 
 * @param str   String to check
 * @param flags What to check for
 * @return      Flags indicating what sensitive data was found
 */
sanitize_flags_t sanitize_detect(const char *str, sanitize_flags_t flags);

/*
 * Get statistics about last sanitization operation.
 */
typedef struct {
    int ipv4_count;
    int ipv6_count;
    int hostname_count;
    int username_count;
    int homedir_count;
    int secret_count;
    int custom_count;
    int total_redactions;
} sanitize_stats_t;

void sanitize_get_stats(sanitize_stats_t *stats);

/*
 * Initialize sanitizer with default patterns.
 */
int sanitize_init(void);

/*
 * Cleanup sanitizer resources.
 */
void sanitize_cleanup(void);

#endif /* SANITIZE_H */
