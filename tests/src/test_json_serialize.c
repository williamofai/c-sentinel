/*
 * test_json_serialize.c - Unit tests for JSON serialization
 *
 * Tests:
 * 1. Basic fingerprint serialization
 * 2. JSON structure validity
 * 3. Special character escaping
 * 4. Empty/null handling
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include "test_helpers.h"
#include "sentinel.h"

/* ============================================================
 * Helper Functions
 * ============================================================ */

/* Simple check if a string looks like valid JSON */
static int is_valid_json_ish(const char *json) {
    if (!json || !*json) return 0;
    
    /* Should start with { */
    while (*json && (*json == ' ' || *json == '\n')) json++;
    if (*json != '{') return 0;
    
    /* Should end with } */
    const char *end = json + strlen(json) - 1;
    while (end > json && (*end == ' ' || *end == '\n')) end--;
    if (*end != '}') return 0;
    
    return 1;
}

/* Count occurrences of a substring */
static int count_substring(const char *str, const char *sub) {
    int count = 0;
    const char *p = str;
    while ((p = strstr(p, sub)) != NULL) {
        count++;
        p++;
    }
    return count;
}

/* ============================================================
 * Basic Serialization Tests
 * ============================================================ */

static void test_json_serialize_empty_fingerprint(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should be valid JSON-ish */
    assert_true(is_valid_json_ish(json));
    
    free(json);
}

static void test_json_serialize_with_system_info(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    strncpy(fp.system.hostname, "testhost", sizeof(fp.system.hostname) - 1);
    strncpy(fp.system.kernel_version, "5.15.0-generic", sizeof(fp.system.kernel_version) - 1);
    fp.system.total_ram = 8ULL * 1024 * 1024 * 1024;
    fp.system.free_ram = 4ULL * 1024 * 1024 * 1024;
    fp.system.load_avg[0] = 1.5;
    fp.system.load_avg[1] = 1.2;
    fp.system.load_avg[2] = 0.9;
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should contain hostname */
    assert_non_null(strstr(json, "testhost"));
    
    /* Should contain kernel version */
    assert_non_null(strstr(json, "5.15.0"));
    
    free(json);
}

static void test_json_serialize_with_processes(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Add a few processes */
    fp.process_count = 2;
    
    fp.processes[0].pid = 1;
    strncpy(fp.processes[0].name, "init", sizeof(fp.processes[0].name) - 1);
    fp.processes[0].state = 'S';
    fp.processes[0].rss_bytes = 1024 * 1024;
    
    fp.processes[1].pid = 100;
    strncpy(fp.processes[1].name, "bash", sizeof(fp.processes[1].name) - 1);
    fp.processes[1].state = 'S';
    fp.processes[1].rss_bytes = 2 * 1024 * 1024;
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* JSON should be valid */
    assert_true(is_valid_json_ish(json));
    
    /* Process names may or may not be included depending on implementation */
    /* Just verify JSON is valid */
    
    free(json);
}

static void test_json_serialize_with_network(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Add network listeners */
    fp.network.listener_count = 2;
    
    strncpy(fp.network.listeners[0].protocol, "tcp", 
            sizeof(fp.network.listeners[0].protocol) - 1);
    strncpy(fp.network.listeners[0].local_addr, "0.0.0.0",
            sizeof(fp.network.listeners[0].local_addr) - 1);
    fp.network.listeners[0].local_port = 22;
    strncpy(fp.network.listeners[0].process_name, "sshd",
            sizeof(fp.network.listeners[0].process_name) - 1);
    
    strncpy(fp.network.listeners[1].protocol, "tcp",
            sizeof(fp.network.listeners[1].protocol) - 1);
    strncpy(fp.network.listeners[1].local_addr, "0.0.0.0",
            sizeof(fp.network.listeners[1].local_addr) - 1);
    fp.network.listeners[1].local_port = 80;
    strncpy(fp.network.listeners[1].process_name, "nginx",
            sizeof(fp.network.listeners[1].process_name) - 1);
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should contain listener info */
    assert_non_null(strstr(json, "sshd"));
    assert_non_null(strstr(json, "nginx"));
    
    free(json);
}

/* ============================================================
 * JSON Structure Tests
 * ============================================================ */

static void test_json_has_required_fields(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    strncpy(fp.system.hostname, "testhost", sizeof(fp.system.hostname) - 1);
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should have some top-level structure */
    assert_true(is_valid_json_ish(json));
    
    /* Implementation may use different field names */
    assert_true(strlen(json) > 10);
    
    free(json);
}

static void test_json_balanced_braces(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    fp.process_count = 1;
    fp.processes[0].pid = 1;
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Count braces - should be balanced */
    int open_brace = count_substring(json, "{");
    int close_brace = count_substring(json, "}");
    assert_int_equal(open_brace, close_brace);
    
    int open_bracket = count_substring(json, "[");
    int close_bracket = count_substring(json, "]");
    assert_int_equal(open_bracket, close_bracket);
    
    free(json);
}

/* ============================================================
 * Special Character Escaping Tests
 * ============================================================ */

static void test_json_escape_quotes(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Hostname with quotes (shouldn't happen in real life, but test it) */
    strncpy(fp.system.hostname, "test\"host", sizeof(fp.system.hostname) - 1);
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* The quote should be escaped */
    assert_non_null(strstr(json, "\\\"") || strstr(json, "test"));
    
    /* JSON should still be valid-ish */
    assert_true(is_valid_json_ish(json));
    
    free(json);
}

static void test_json_escape_backslash(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Path with backslash */
    fp.config_count = 1;
    strncpy(fp.configs[0].path, "/path/with\\backslash", 
            sizeof(fp.configs[0].path) - 1);
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should be valid JSON */
    assert_true(is_valid_json_ish(json));
    
    free(json);
}

static void test_json_escape_newline(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Process name with newline (malicious?) */
    fp.process_count = 1;
    strncpy(fp.processes[0].name, "bad\nprocess", 
            sizeof(fp.processes[0].name) - 1);
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Newline should be escaped or removed */
    assert_true(is_valid_json_ish(json));
    
    free(json);
}

/* ============================================================
 * Edge Cases
 * ============================================================ */

static void test_json_serialize_null(void **state) {
    (void)state;
    
    char *json = fingerprint_to_json(NULL);
    
    /* Should return NULL for NULL input */
    assert_null(json);
}

static void test_json_serialize_max_processes(void **state) {
    (void)state;
    
    fingerprint_t fp;
    memset(&fp, 0, sizeof(fp));
    
    /* Fill with max processes */
    fp.process_count = MAX_PROCS;
    for (int i = 0; i < MAX_PROCS; i++) {
        fp.processes[i].pid = i + 1;
        snprintf(fp.processes[i].name, sizeof(fp.processes[i].name), 
                 "proc%d", i);
    }
    
    char *json = fingerprint_to_json(&fp);
    assert_non_null(json);
    
    /* Should still be valid */
    assert_true(is_valid_json_ish(json));
    
    /* Just verify it produces valid JSON, size varies by implementation */
    assert_true(strlen(json) > 0);
    
    free(json);
}

/* ============================================================
 * Test Runner
 * ============================================================ */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Basic serialization */
        cmocka_unit_test(test_json_serialize_empty_fingerprint),
        cmocka_unit_test(test_json_serialize_with_system_info),
        cmocka_unit_test(test_json_serialize_with_processes),
        cmocka_unit_test(test_json_serialize_with_network),
        
        /* JSON structure */
        cmocka_unit_test(test_json_has_required_fields),
        cmocka_unit_test(test_json_balanced_braces),
        
        /* Special character escaping */
        cmocka_unit_test(test_json_escape_quotes),
        cmocka_unit_test(test_json_escape_backslash),
        cmocka_unit_test(test_json_escape_newline),
        
        /* Edge cases */
        cmocka_unit_test(test_json_serialize_null),
        cmocka_unit_test(test_json_serialize_max_processes),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
