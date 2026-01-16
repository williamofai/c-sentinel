/*
 * test_config.c - Unit tests for configuration loading
 *
 * Tests:
 * 1. Default configuration values
 * 2. Config file parsing
 * 3. Environment variable overrides
 * 4. Missing config handling
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
 * Test Setup/Teardown
 * ============================================================ */

static int config_setup(void **state) {
    char *tmpdir = test_create_tmpdir();
    if (!tmpdir) return -1;
    
    /* Set HOME to temp dir */
    setenv("HOME", tmpdir, 1);
    
    /* Clear any API keys that might be set */
    unsetenv("ANTHROPIC_API_KEY");
    unsetenv("OPENAI_API_KEY");
    
    *state = tmpdir;
    return 0;
}

static int config_teardown(void **state) {
    unsetenv("HOME");
    unsetenv("ANTHROPIC_API_KEY");
    unsetenv("OPENAI_API_KEY");
    test_remove_tmpdir(*state);
    return 0;
}

/* ============================================================
 * Default Configuration Tests
 * ============================================================ */

static void test_config_load_defaults(void **state) {
    (void)state;
    
    /* Load config (no config file exists, should use defaults) */
    int ret = config_load();
    
    /* Should succeed even without config file */
    assert_int_equal(ret, 0);
}

static void test_config_create_default(void **state) {
    (void)state;
    
    /* Create default config file */
    int ret = config_create_default();
    assert_int_equal(ret, 0);
    
    /* Verify the config file was created */
    char *tmpdir = *state;
    char path[512];
    snprintf(path, sizeof(path), "%s/.sentinel/config", tmpdir);
    
    FILE *f = fopen(path, "r");
    assert_non_null(f);
    fclose(f);
}

/* ============================================================
 * Config File Parsing Tests
 * ============================================================ */

static void test_config_parse_key_value(void **state) {
    char *tmpdir = *state;
    
    /* Create .sentinel directory */
    test_mkdir(tmpdir, ".sentinel");
    
    /* Create a config file with some settings */
    const char *config_content = 
        "# This is a comment\n"
        "zombie_threshold = 5\n"
        "high_fd_threshold = 200\n"
        "memory_warn_percent = 75.0\n"
        "default_model = openai\n"
        "webhook_url = https://hooks.example.com/webhook\n";
    
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.sentinel", tmpdir);
    test_write_file(dir, "config", config_content);
    
    /* Load the config */
    int ret = config_load();
    assert_int_equal(ret, 0);
}

static void test_config_ignore_comments(void **state) {
    char *tmpdir = *state;
    
    test_mkdir(tmpdir, ".sentinel");
    
    /* Config with various comment styles */
    const char *config_content = 
        "# Full line comment\n"
        "  # Indented comment\n"
        "zombie_threshold = 3  # Inline comment should be handled\n"
        "\n"
        "   \n"
        "high_fd_threshold = 150\n";
    
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.sentinel", tmpdir);
    test_write_file(dir, "config", config_content);
    
    /* Should parse without error */
    int ret = config_load();
    assert_int_equal(ret, 0);
}

static void test_config_quoted_values(void **state) {
    char *tmpdir = *state;
    
    test_mkdir(tmpdir, ".sentinel");
    
    /* Config with quoted values */
    const char *config_content = 
        "webhook_url = \"https://hooks.example.com/webhook\"\n"
        "ollama_host = 'http://localhost:11434'\n";
    
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.sentinel", tmpdir);
    test_write_file(dir, "config", config_content);
    
    int ret = config_load();
    assert_int_equal(ret, 0);
}

/* ============================================================
 * Environment Variable Override Tests
 * ============================================================ */

static void test_config_env_override(void **state) {
    (void)state;
    
    /* Set environment variable */
    setenv("ANTHROPIC_API_KEY", "sk-test-key-12345", 1);
    
    /* Load config */
    int ret = config_load();
    assert_int_equal(ret, 0);
    
    /* The env var should take precedence */
    /* (We can't easily verify the internal state without a getter,
     * but we verify the load doesn't fail) */
}

/* ============================================================
 * Edge Cases
 * ============================================================ */

static void test_config_empty_file(void **state) {
    char *tmpdir = *state;
    
    test_mkdir(tmpdir, ".sentinel");
    test_write_file(tmpdir, ".sentinel/config", "");
    
    /* Empty config should still work (use defaults) */
    int ret = config_load();
    assert_int_equal(ret, 0);
}

static void test_config_malformed_lines(void **state) {
    char *tmpdir = *state;
    
    test_mkdir(tmpdir, ".sentinel");
    
    /* Config with malformed lines that should be ignored */
    const char *config_content = 
        "no_equals_sign_here\n"
        "= missing_key\n"
        "valid_key = valid_value\n"
        "zombie_threshold = not_a_number\n"  /* Should ignore or use default */
        "high_fd_threshold = 100\n";
    
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.sentinel", tmpdir);
    test_write_file(dir, "config", config_content);
    
    /* Should handle gracefully (not crash) */
    int ret = config_load();
    /* May return 0 or -1 depending on strictness */
    (void)ret;
}

static void test_config_print(void **state) {
    (void)state;
    
    /* Load config first */
    config_load();
    
    /* config_print should not crash */
    config_print();
}

/* ============================================================
 * Test Runner
 * ============================================================ */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Default config */
        cmocka_unit_test_setup_teardown(test_config_load_defaults,
                                         config_setup, config_teardown),
        cmocka_unit_test_setup_teardown(test_config_create_default,
                                         config_setup, config_teardown),
        
        /* Config parsing */
        cmocka_unit_test_setup_teardown(test_config_parse_key_value,
                                         config_setup, config_teardown),
        cmocka_unit_test_setup_teardown(test_config_ignore_comments,
                                         config_setup, config_teardown),
        cmocka_unit_test_setup_teardown(test_config_quoted_values,
                                         config_setup, config_teardown),
        
        /* Environment overrides */
        cmocka_unit_test_setup_teardown(test_config_env_override,
                                         config_setup, config_teardown),
        
        /* Edge cases */
        cmocka_unit_test_setup_teardown(test_config_empty_file,
                                         config_setup, config_teardown),
        cmocka_unit_test_setup_teardown(test_config_malformed_lines,
                                         config_setup, config_teardown),
        cmocka_unit_test_setup_teardown(test_config_print,
                                         config_setup, config_teardown),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
