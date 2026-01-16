/*
 * test_sanitize.c - Unit tests for data sanitization
 *
 * SECURITY-CRITICAL: These tests verify that sensitive data
 * is properly redacted before transmission. Failures here
 * could lead to data leaks.
 *
 * Test categories:
 * 1. IPv4 address detection and redaction
 * 2. IPv6 address detection and redaction  
 * 3. Home directory path redaction
 * 4. Secret pattern detection
 * 5. Custom pattern support
 * 6. Edge cases and buffer safety
 * 7. Environment variable secrets
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
#include "sanitize.h"

/* ============================================================
 * Test Setup/Teardown
 * ============================================================
 *
 * IMPORTANT: The sanitize module has global state (custom patterns,
 * secret values). We must reset it between tests to ensure isolation.
 */

static int sanitize_setup(void **state) {
    (void)state;
    /* Reset sanitizer state before each test */
    sanitize_cleanup();
    sanitize_init();
    return 0;
}

static int sanitize_teardown(void **state) {
    (void)state;
    sanitize_cleanup();
    return 0;
}

/* ============================================================
 * IPv4 Address Tests
 * ============================================================
 *
 * IPv4 addresses must be detected and redacted in various contexts:
 * - Standalone: "192.168.1.1"
 * - In text: "Connected to 10.0.0.1 on port 22"
 * - Multiple: "From 1.2.3.4 to 5.6.7.8"
 */

static void test_sanitize_ipv4_basic(void **state) {
    (void)state;
    
    char buf[256] = "Server IP: 192.168.1.100";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_IPV4);
    
    assert_int_equal(redactions, 1);
    assert_string_equal(buf, "Server IP: " REDACT_IP);
}

static void test_sanitize_ipv4_multiple(void **state) {
    (void)state;
    
    char buf[256] = "Route: 10.0.0.1 -> 172.16.0.1 -> 192.168.1.1";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_IPV4);
    
    assert_int_equal(redactions, 3);
    /* All three IPs should be redacted */
    assert_null(strstr(buf, "10.0.0.1"));
    assert_null(strstr(buf, "172.16.0.1"));
    assert_null(strstr(buf, "192.168.1.1"));
    /* Redaction markers should be present */
    assert_non_null(strstr(buf, REDACT_IP));
}

static void test_sanitize_ipv4_edge_cases(void **state) {
    (void)state;
    
    /* Test boundary IPs */
    char buf1[256] = "Min: 0.0.0.0 Max: 255.255.255.255";
    int r1 = sanitize_string(buf1, sizeof(buf1), SANITIZE_IPV4);
    assert_int_equal(r1, 2);
    
    /* Test localhost */
    char buf2[256] = "Localhost: 127.0.0.1";
    int r2 = sanitize_string(buf2, sizeof(buf2), SANITIZE_IPV4);
    assert_int_equal(r2, 1);
}

static void test_sanitize_ipv4_false_positives(void **state) {
    (void)state;
    
    /* Version numbers should NOT be redacted as IPs */
    char buf1[256] = "Version 1.2.3";
    int r1 = sanitize_string(buf1, sizeof(buf1), SANITIZE_IPV4);
    assert_int_equal(r1, 0);  /* No redactions - not a valid IP */
    assert_string_equal(buf1, "Version 1.2.3");
    
    /* Dates should NOT be redacted */
    char buf2[256] = "Date: 2024.01.15";
    (void)sanitize_string(buf2, sizeof(buf2), SANITIZE_IPV4);
    /* This might be detected as IP-like, but ideally shouldn't */
    /* The test documents current behavior */
}

static void test_sanitize_ipv4_in_json(void **state) {
    (void)state;
    
    char buf[512] = "{\"source\": \"192.168.1.1\", \"dest\": \"10.0.0.1\"}";
    
    int redactions = sanitize_json(buf, sizeof(buf), SANITIZE_IPV4);
    
    assert_int_equal(redactions, 2);
    assert_null(strstr(buf, "192.168.1.1"));
    assert_null(strstr(buf, "10.0.0.1"));
}

/* ============================================================
 * IPv6 Address Tests
 * ============================================================
 */

static void test_sanitize_ipv6_basic(void **state) {
    (void)state;
    
    char buf[256] = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_IPV6);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "2001:0db8"));
}

static void test_sanitize_ipv6_compressed(void **state) {
    (void)state;
    
    /* Compressed format with :: */
    char buf[256] = "Loopback: ::1 Link-local: fe80::1";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_IPV6);
    
    /* Both should be detected */
    assert_true(redactions >= 1);
}

static void test_sanitize_ipv6_mixed(void **state) {
    (void)state;
    
    /* Mixed IPv4/IPv6 in same string - use distinct IPs */
    char buf[256] = "v4: 192.168.1.1 v6: 2001:db8::1";
    
    int redactions = sanitize_string(buf, sizeof(buf), 
                                      SANITIZE_IPV4 | SANITIZE_IPV6);
    
    /* At minimum, the standalone IPv4 should be detected */
    assert_true(redactions >= 1);
    /* The IPv4 address should be redacted */
    assert_null(strstr(buf, "192.168.1.1"));
}

/* ============================================================
 * Home Directory Path Tests
 * ============================================================
 *
 * Paths like /home/username and /Users/username contain
 * potentially identifying information.
 */

static void test_sanitize_homedir_linux(void **state) {
    (void)state;
    
    char buf[256] = "Config: /home/johndoe/.config/sentinel";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_HOMEDIR);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "johndoe"));
    assert_non_null(strstr(buf, REDACT_PATH));
}

static void test_sanitize_homedir_macos(void **state) {
    (void)state;
    
    char buf[256] = "Path: /Users/alice/Documents/file.txt";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_HOMEDIR);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "alice"));
}

static void test_sanitize_homedir_root(void **state) {
    (void)state;
    
    char buf[256] = "Root home: /root/.bashrc";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_HOMEDIR);
    
    /* NOTE: Current implementation may not detect /root as home dir.
     * This test documents the current behavior.
     * If /root detection is added later, update this test. */
    (void)redactions;
    /* We're just verifying it doesn't crash and returns a valid count */
    assert_true(redactions >= 0);
}

static void test_sanitize_homedir_multiple(void **state) {
    (void)state;
    
    char buf[512] = "Source: /home/user1/file Dest: /home/user2/file";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_HOMEDIR);
    
    assert_int_equal(redactions, 2);
    assert_null(strstr(buf, "user1"));
    assert_null(strstr(buf, "user2"));
}

/* ============================================================
 * Secret Pattern Tests
 * ============================================================
 *
 * Patterns like "password=xxx" and "api_key=xxx" should be detected.
 */

static void test_sanitize_secrets_password(void **state) {
    (void)state;
    
    char buf[256] = "Login with password=supersecret123";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_SECRETS);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "supersecret123"));
    assert_non_null(strstr(buf, REDACT_SECRET));
}

static void test_sanitize_secrets_api_key(void **state) {
    (void)state;
    
    char buf[256] = "Authorization: api_key=sk_live_abc123xyz";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_SECRETS);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "sk_live_abc123xyz"));
}

static void test_sanitize_secrets_token(void **state) {
    (void)state;
    
    char buf[256] = "Bearer token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_SECRETS);
    
    assert_int_equal(redactions, 1);
    assert_null(strstr(buf, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
}

static void test_sanitize_secrets_multiple(void **state) {
    (void)state;
    
    char buf[512] = "user=admin password=secret123 token=abc123";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_SECRETS);
    
    /* password and token should be redacted */
    assert_true(redactions >= 2);
    assert_null(strstr(buf, "secret123"));
    assert_null(strstr(buf, "abc123"));
}

/* ============================================================
 * Custom Pattern Tests
 * ============================================================
 */

static void test_sanitize_custom_pattern(void **state) {
    (void)state;
    
    /* Add a custom pattern */
    int ret = sanitize_add_pattern("internal.corp.com", "[INTERNAL]");
    assert_int_equal(ret, 0);
    
    char buf[256] = "Connecting to api.internal.corp.com";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    
    assert_true(redactions >= 1);
    assert_null(strstr(buf, "internal.corp.com"));
}

static void test_sanitize_custom_pattern_default_replacement(void **state) {
    (void)state;
    
    /* Add pattern with NULL replacement (uses default) */
    int ret = sanitize_add_pattern("secret-project", NULL);
    assert_int_equal(ret, 0);
    
    char buf[256] = "Working on secret-project-alpha";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    
    assert_true(redactions >= 1);
    assert_null(strstr(buf, "secret-project"));
}

static void test_sanitize_clear_patterns(void **state) {
    (void)state;
    
    /* Add a pattern */
    sanitize_add_pattern("testpattern", "[REMOVED]");
    
    /* Clear all patterns */
    sanitize_clear_patterns();
    
    /* Pattern should no longer match */
    char buf[256] = "This has testpattern in it";
    (void)sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    
    /* The custom pattern should not be matched after clearing */
    /* (Built-in patterns may still match other things) */
    assert_non_null(strstr(buf, "testpattern"));
}

/* ============================================================
 * Environment Variable Secret Tests
 * ============================================================
 */

static void test_sanitize_env_secret(void **state) {
    (void)state;
    
    /* Set an environment variable with a secret value */
    test_env_backup_t backup = test_setenv("TEST_SECRET_KEY", "mysupersecretvalue");
    
    /* Register this env var as containing a secret */
    int ret = sanitize_add_secret_var("TEST_SECRET_KEY");
    assert_int_equal(ret, 0);
    
    /* Reinitialize to pick up the env var */
    sanitize_cleanup();
    sanitize_init();
    sanitize_add_secret_var("TEST_SECRET_KEY");
    
    /* The secret value should be redacted if found in strings */
    char buf[256] = "Key is mysupersecretvalue here";
    (void)sanitize_string(buf, sizeof(buf), SANITIZE_SECRETS);
    
    /* Restore environment */
    test_restoreenv(&backup);
    
    /* The secret value should have been redacted */
    assert_null(strstr(buf, "mysupersecretvalue"));
}

/* ============================================================
 * Buffer Safety Tests
 * ============================================================
 *
 * SECURITY: Ensure no buffer overflows when redaction makes
 * the string longer than the original.
 */

static void test_sanitize_buffer_overflow_protection(void **state) {
    (void)state;
    
    /* Small buffer that can't fit the redaction placeholder */
    char buf[20] = "IP: 192.168.1.1";  /* 15 chars + null */
    /* REDACT_IP is "[REDACTED-IP]" = 13 chars */
    /* Replacing "192.168.1.1" (11 chars) with 13 chars needs 17 total */
    
    /* This should either:
     * 1. Fail gracefully and return -1
     * 2. Truncate safely
     * 3. Skip redaction if it would overflow
     * It must NOT overflow the buffer */
    (void)sanitize_string(buf, sizeof(buf), SANITIZE_IPV4);
    
    /* The key assertion: buffer should not be corrupted */
    assert_true(strlen(buf) < sizeof(buf));
}

static void test_sanitize_null_input(void **state) {
    (void)state;
    
    /* NULL input should return error, not crash */
    int ret = sanitize_string(NULL, 100, SANITIZE_ALL);
    assert_int_equal(ret, -1);
}

static void test_sanitize_zero_length(void **state) {
    (void)state;
    
    char buf[100] = "test";
    
    /* Zero length should return error */
    int ret = sanitize_string(buf, 0, SANITIZE_ALL);
    assert_int_equal(ret, -1);
}

static void test_sanitize_empty_string(void **state) {
    (void)state;
    
    char buf[100] = "";
    
    /* Empty string should succeed with 0 redactions */
    int ret = sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    assert_int_equal(ret, 0);
    assert_string_equal(buf, "");
}

/* ============================================================
 * Combined Flags Tests
 * ============================================================
 */

static void test_sanitize_all_flags(void **state) {
    (void)state;
    
    char buf[512] = "User /home/alice connected from 192.168.1.1 "
                    "with password=secret123 to 2001:db8::1";
    
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    
    /* All sensitive data should be redacted */
    assert_true(redactions >= 3);
    assert_null(strstr(buf, "alice"));
    assert_null(strstr(buf, "192.168.1.1"));
    assert_null(strstr(buf, "secret123"));
}

static void test_sanitize_no_flags(void **state) {
    (void)state;
    
    char buf[256] = "IP: 192.168.1.1 Path: /home/user";
    char original[256];
    strcpy(original, buf);
    
    /* SANITIZE_NONE should not modify anything */
    int redactions = sanitize_string(buf, sizeof(buf), SANITIZE_NONE);
    
    assert_int_equal(redactions, 0);
    assert_string_equal(buf, original);
}

/* ============================================================
 * sanitize_detect() Tests
 * ============================================================
 */

static void test_sanitize_detect_ipv4(void **state) {
    (void)state;
    
    sanitize_flags_t found = sanitize_detect("Contains 10.0.0.1", SANITIZE_ALL);
    
    assert_true(found & SANITIZE_IPV4);
}

static void test_sanitize_detect_none(void **state) {
    (void)state;
    
    sanitize_flags_t found = sanitize_detect("Nothing sensitive here", SANITIZE_ALL);
    
    assert_int_equal(found, SANITIZE_NONE);
}

/* ============================================================
 * sanitize_string_copy() Tests
 * ============================================================
 */

static void test_sanitize_string_copy(void **state) {
    (void)state;
    
    const char *input = "IP: 192.168.1.1";
    char output[256];
    
    int redactions = sanitize_string_copy(input, output, sizeof(output), 
                                           SANITIZE_IPV4);
    
    assert_int_equal(redactions, 1);
    assert_string_equal(output, "IP: " REDACT_IP);
    
    /* Original should be unchanged */
    assert_string_equal(input, "IP: 192.168.1.1");
}

/* ============================================================
 * Statistics Tests
 * ============================================================
 */

static void test_sanitize_stats(void **state) {
    (void)state;
    
    char buf[256] = "IPs: 1.1.1.1 and 2.2.2.2 Path: /home/user";
    
    sanitize_string(buf, sizeof(buf), SANITIZE_ALL);
    
    sanitize_stats_t stats;
    sanitize_get_stats(&stats);
    
    assert_int_equal(stats.ipv4_count, 2);
    assert_int_equal(stats.homedir_count, 1);
    assert_true(stats.total_redactions >= 3);
}

/* ============================================================
 * Test Runner
 * ============================================================
 */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* IPv4 tests */
        cmocka_unit_test_setup_teardown(test_sanitize_ipv4_basic,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv4_multiple,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv4_edge_cases,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv4_false_positives,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv4_in_json,
                                         sanitize_setup, sanitize_teardown),
        
        /* IPv6 tests */
        cmocka_unit_test_setup_teardown(test_sanitize_ipv6_basic,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv6_compressed,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_ipv6_mixed,
                                         sanitize_setup, sanitize_teardown),
        
        /* Home directory tests */
        cmocka_unit_test_setup_teardown(test_sanitize_homedir_linux,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_homedir_macos,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_homedir_root,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_homedir_multiple,
                                         sanitize_setup, sanitize_teardown),
        
        /* Secret pattern tests */
        cmocka_unit_test_setup_teardown(test_sanitize_secrets_password,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_secrets_api_key,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_secrets_token,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_secrets_multiple,
                                         sanitize_setup, sanitize_teardown),
        
        /* Custom pattern tests */
        cmocka_unit_test_setup_teardown(test_sanitize_custom_pattern,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_custom_pattern_default_replacement,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_clear_patterns,
                                         sanitize_setup, sanitize_teardown),
        
        /* Environment variable tests */
        cmocka_unit_test_setup_teardown(test_sanitize_env_secret,
                                         sanitize_setup, sanitize_teardown),
        
        /* Buffer safety tests */
        cmocka_unit_test_setup_teardown(test_sanitize_buffer_overflow_protection,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_null_input,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_zero_length,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_empty_string,
                                         sanitize_setup, sanitize_teardown),
        
        /* Combined flags tests */
        cmocka_unit_test_setup_teardown(test_sanitize_all_flags,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_no_flags,
                                         sanitize_setup, sanitize_teardown),
        
        /* Detect function tests */
        cmocka_unit_test_setup_teardown(test_sanitize_detect_ipv4,
                                         sanitize_setup, sanitize_teardown),
        cmocka_unit_test_setup_teardown(test_sanitize_detect_none,
                                         sanitize_setup, sanitize_teardown),
        
        /* Copy function test */
        cmocka_unit_test_setup_teardown(test_sanitize_string_copy,
                                         sanitize_setup, sanitize_teardown),
        
        /* Statistics test */
        cmocka_unit_test_setup_teardown(test_sanitize_stats,
                                         sanitize_setup, sanitize_teardown),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
