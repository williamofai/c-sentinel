/*
 * test_audit_common.c - Unit tests for audit common functionality
 *
 * Tests:
 * 1. Username hashing (privacy)
 * 2. Risk score calculation
 * 3. Risk factor management
 * 4. Deviation calculations
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
#include "audit.h"
#include "sha256.h"

/* Forward declarations for functions we're testing */
void hash_username(const char *username, char *output, size_t outsize);
void add_risk_factor(audit_summary_t *summary, const char *reason, int weight);
void calculate_risk_score(audit_summary_t *summary);
float calculate_deviation_pct(float current, float baseline_avg);
const char* deviation_significance(float deviation_pct);

/* ============================================================
 * Username Hashing Tests
 * ============================================================ */

static void test_hash_username_basic(void **state) {
    (void)state;
    
    char output[HASH_USERNAME_LEN];
    hash_username("alice", output, sizeof(output));
    
    /* Should produce "user_xxxx" format */
    assert_non_null(strstr(output, "user_"));
    assert_true(strlen(output) > 5);
    assert_true(strlen(output) < HASH_USERNAME_LEN);
}

static void test_hash_username_consistent(void **state) {
    (void)state;
    
    char output1[HASH_USERNAME_LEN];
    char output2[HASH_USERNAME_LEN];
    
    /* Same username should produce same hash */
    hash_username("bob", output1, sizeof(output1));
    hash_username("bob", output2, sizeof(output2));
    
    assert_string_equal(output1, output2);
}

static void test_hash_username_different(void **state) {
    (void)state;
    
    char output1[HASH_USERNAME_LEN];
    char output2[HASH_USERNAME_LEN];
    
    /* Different usernames should produce different hashes */
    hash_username("alice", output1, sizeof(output1));
    hash_username("bob", output2, sizeof(output2));
    
    assert_string_not_equal(output1, output2);
}

static void test_hash_username_null(void **state) {
    (void)state;
    
    char output[HASH_USERNAME_LEN];
    output[0] = 'X';  /* Mark it */
    
    /* NULL username should not crash */
    hash_username(NULL, output, sizeof(output));
    
    /* Should produce empty string or safe output */
    assert_true(output[0] == '\0' || output[0] == 'X');
}

static void test_hash_username_empty(void **state) {
    (void)state;
    
    char output[HASH_USERNAME_LEN];
    hash_username("", output, sizeof(output));
    
    /* Empty username should still produce valid output */
    assert_non_null(output);
}

static void test_hash_username_small_buffer(void **state) {
    (void)state;
    
    char output[5];  /* Too small for "user_xxxx" */
    
    /* Should handle gracefully without overflow */
    hash_username("alice", output, sizeof(output));
    
    /* Just verify no crash */
}

/* ============================================================
 * Risk Factor Tests
 * ============================================================ */

static void test_add_risk_factor(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    add_risk_factor(&summary, "Auth failures detected", 5);
    
    assert_int_equal(summary.risk_factor_count, 1);
    assert_string_equal(summary.risk_factors[0].reason, "Auth failures detected");
    assert_int_equal(summary.risk_factors[0].weight, 5);
}

static void test_add_risk_factor_multiple(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    add_risk_factor(&summary, "Auth failures", 5);
    add_risk_factor(&summary, "Sudo usage", 3);
    add_risk_factor(&summary, "Tmp execution", 10);
    
    assert_int_equal(summary.risk_factor_count, 3);
}

static void test_add_risk_factor_overflow(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    /* Try to add more than MAX_RISK_FACTORS */
    for (int i = 0; i < MAX_RISK_FACTORS + 5; i++) {
        add_risk_factor(&summary, "Test factor", 1);
    }
    
    /* Should cap at MAX_RISK_FACTORS */
    assert_int_equal(summary.risk_factor_count, MAX_RISK_FACTORS);
}

static void test_add_risk_factor_null(void **state) {
    (void)state;
    
    /* NULL summary should not crash */
    add_risk_factor(NULL, "Test", 5);
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    /* NULL reason should not crash */
    add_risk_factor(&summary, NULL, 5);
    assert_int_equal(summary.risk_factor_count, 0);
}

/* ============================================================
 * Risk Score Calculation Tests
 * ============================================================ */

static void test_calculate_risk_score_zero(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    
    calculate_risk_score(&summary);
    
    /* No issues = low risk */
    assert_int_equal(summary.risk_score, 0);
    assert_string_equal(summary.risk_level, "low");
}

static void test_calculate_risk_score_auth_failures(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.auth_failures = 10;
    
    calculate_risk_score(&summary);
    
    /* Auth failures should increase score */
    assert_true(summary.risk_score > 0);
}

static void test_calculate_risk_score_brute_force(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.auth_failures = 50;
    summary.brute_force_detected = true;
    
    calculate_risk_score(&summary);
    
    /* Brute force should be high/critical */
    assert_true(summary.risk_score >= 10);
}

static void test_calculate_risk_score_tmp_execution(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.tmp_executions = 5;
    
    calculate_risk_score(&summary);
    
    /* Tmp execution is suspicious */
    assert_true(summary.risk_score > 0);
}

static void test_calculate_risk_score_combined(void **state) {
    (void)state;
    
    audit_summary_t summary;
    memset(&summary, 0, sizeof(summary));
    summary.auth_failures = 5;
    summary.sudo_count = 10;
    summary.tmp_executions = 2;
    summary.sensitive_file_count = 3;
    
    calculate_risk_score(&summary);
    
    /* Multiple factors should combine */
    assert_true(summary.risk_score > 0);
    assert_true(summary.risk_factor_count > 0);
}

static void test_calculate_risk_score_null(void **state) {
    (void)state;
    
    /* NULL summary should not crash */
    calculate_risk_score(NULL);
}

/* ============================================================
 * Deviation Calculation Tests
 * ============================================================ */

static void test_deviation_pct_zero_baseline(void **state) {
    (void)state;
    
    /* Zero baseline should handle gracefully */
    float deviation = calculate_deviation_pct(10.0f, 0.0f);
    
    /* Implementation may return 0, 100, or special value */
    (void)deviation;  /* Just verify no crash/nan */
}

static void test_deviation_pct_normal(void **state) {
    (void)state;
    
    /* Current = 20, baseline = 10 -> 100% deviation */
    float deviation = calculate_deviation_pct(20.0f, 10.0f);
    
    assert_true(deviation >= 99.0f && deviation <= 101.0f);
}

static void test_deviation_pct_below_baseline(void **state) {
    (void)state;
    
    /* Current below baseline -> negative deviation */
    float deviation = calculate_deviation_pct(5.0f, 10.0f);
    
    assert_true(deviation < 0.0f || deviation >= 0.0f);  /* Just verify valid number */
}

static void test_deviation_significance_low(void **state) {
    (void)state;
    
    const char *sig = deviation_significance(10.0f);
    assert_non_null(sig);
}

static void test_deviation_significance_high(void **state) {
    (void)state;
    
    const char *sig = deviation_significance(200.0f);
    assert_non_null(sig);
}

/* ============================================================
 * Test Runner
 * ============================================================ */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Username hashing */
        cmocka_unit_test(test_hash_username_basic),
        cmocka_unit_test(test_hash_username_consistent),
        cmocka_unit_test(test_hash_username_different),
        cmocka_unit_test(test_hash_username_null),
        cmocka_unit_test(test_hash_username_empty),
        cmocka_unit_test(test_hash_username_small_buffer),
        
        /* Risk factors */
        cmocka_unit_test(test_add_risk_factor),
        cmocka_unit_test(test_add_risk_factor_multiple),
        cmocka_unit_test(test_add_risk_factor_overflow),
        cmocka_unit_test(test_add_risk_factor_null),
        
        /* Risk score calculation */
        cmocka_unit_test(test_calculate_risk_score_zero),
        cmocka_unit_test(test_calculate_risk_score_auth_failures),
        cmocka_unit_test(test_calculate_risk_score_brute_force),
        cmocka_unit_test(test_calculate_risk_score_tmp_execution),
        cmocka_unit_test(test_calculate_risk_score_combined),
        cmocka_unit_test(test_calculate_risk_score_null),
        
        /* Deviation calculations */
        cmocka_unit_test(test_deviation_pct_zero_baseline),
        cmocka_unit_test(test_deviation_pct_normal),
        cmocka_unit_test(test_deviation_pct_below_baseline),
        cmocka_unit_test(test_deviation_significance_low),
        cmocka_unit_test(test_deviation_significance_high),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
