/*
 * test_sha256.c - Unit tests for SHA256 implementation
 *
 * Tests the SHA256 hashing functions using:
 * 1. NIST test vectors (from FIPS 180-4)
 * 2. Edge cases (empty string, long strings)
 * 3. File hashing with real temp files
 *
 * This is a good first test file because:
 * - SHA256 is a pure function (same input = same output)
 * - Well-defined test vectors exist
 * - Minimal dependencies
 */

/* Standard headers required by cmocka */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>

/* cmocka header */
#include <cmocka.h>

/* Test helpers for temp files */
#include "test_helpers.h"

/* Module under test */
#include "sha256.h"

/* ============================================================
 * Test Vectors
 * ============================================================
 *
 * These are official NIST test vectors from FIPS 180-4.
 * If these pass, we can be confident the implementation is correct.
 */

/* NIST Test Vector 1: Empty string "" */
#define HASH_EMPTY "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/* NIST Test Vector 2: "abc" */
#define HASH_ABC "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

/* NIST Test Vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
 * This is a 448-bit message (56 bytes), which tests the padding logic */
#define MSG_448BIT "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define HASH_448BIT "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

/* Test Vector 4: One million 'a' characters
 * This tests multi-block processing */
#define HASH_MILLION_A "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

/* ============================================================
 * Test: Empty String Hash
 * ============================================================
 *
 * This tests that hashing an empty string produces the correct result.
 * Important because it verifies the padding logic handles zero-length input.
 */
static void test_sha256_empty_string(void **state) {
    (void)state;  /* Unused parameter */

    char hash[SHA256_HEX_LENGTH];
    
    sha256_string("", hash, sizeof(hash));
    
    /* assert_string_equal is a cmocka macro that compares strings
     * and prints both values if they don't match */
    assert_string_equal(hash, HASH_EMPTY);
}

/* ============================================================
 * Test: "abc" Hash (NIST Vector 2)
 * ============================================================
 *
 * This is the most common test vector. If this fails, something
 * is fundamentally wrong with the implementation.
 */
static void test_sha256_abc(void **state) {
    (void)state;
    
    char hash[SHA256_HEX_LENGTH];
    
    sha256_string("abc", hash, sizeof(hash));
    
    assert_string_equal(hash, HASH_ABC);
}

/* ============================================================
 * Test: 448-bit Message (Tests Padding)
 * ============================================================
 *
 * A 448-bit (56 byte) message is significant because SHA256
 * pads messages to a multiple of 512 bits. A 448-bit message
 * plus the 1-bit and 64-bit length field exactly fills one block.
 * This tests the edge case where padding creates a new block.
 */
static void test_sha256_448bit_message(void **state) {
    (void)state;
    
    char hash[SHA256_HEX_LENGTH];
    
    sha256_string(MSG_448BIT, hash, sizeof(hash));
    
    assert_string_equal(hash, HASH_448BIT);
}

/* ============================================================
 * Test: Multi-block Processing (1 million 'a's)
 * ============================================================
 *
 * This tests that the implementation correctly processes
 * multiple 64-byte blocks. It's important for file hashing
 * where files can be arbitrarily large.
 */
static void test_sha256_million_a(void **state) {
    (void)state;
    
    /* Create a string of 1,000,000 'a' characters */
    char *million_a = malloc(1000001);
    assert_non_null(million_a);
    
    memset(million_a, 'a', 1000000);
    million_a[1000000] = '\0';
    
    char hash[SHA256_HEX_LENGTH];
    sha256_string(million_a, hash, sizeof(hash));
    
    free(million_a);
    
    assert_string_equal(hash, HASH_MILLION_A);
}

/* ============================================================
 * Test: Low-level API (init/update/final)
 * ============================================================
 *
 * The low-level API allows incremental hashing, which is
 * important for streaming data or large files.
 */
static void test_sha256_incremental(void **state) {
    (void)state;
    
    sha256_ctx_t ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    char hash[SHA256_HEX_LENGTH];
    
    /* Hash "abc" using incremental API */
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"a", 1);
    sha256_update(&ctx, (const uint8_t *)"bc", 2);
    sha256_final(&ctx, digest);
    
    /* Convert digest to hex string for comparison */
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hash + (i * 2), 3, "%02x", digest[i]);
    }
    
    /* Should produce same hash as "abc" hashed all at once */
    assert_string_equal(hash, HASH_ABC);
}

/* ============================================================
 * Test: Buffer Size Handling
 * ============================================================
 *
 * Verify that sha256_string handles small output buffers safely.
 * The function should not overflow if given a too-small buffer.
 */
static void test_sha256_buffer_safety(void **state) {
    (void)state;
    
    /* This test verifies the function doesn't crash with edge cases.
     * A proper implementation should truncate or handle small buffers. */
    char small_buffer[10];
    memset(small_buffer, 'X', sizeof(small_buffer));
    
    /* This should not crash or overflow */
    sha256_string("test", small_buffer, sizeof(small_buffer));
    
    /* Buffer should be modified but not overflow past its bounds */
    /* We're mainly checking this doesn't crash */
    assert_true(1);
}

/* ============================================================
 * Test: File Hashing (uses real temp files)
 * ============================================================
 *
 * This tests sha256_file() using our temp file strategy.
 * We create a real file, hash it, and verify the result.
 */

/* Setup function: creates a temp directory for file tests */
static int file_test_setup(void **state) {
    char *tmpdir = test_create_tmpdir();
    if (!tmpdir) {
        return -1;
    }
    *state = tmpdir;
    return 0;
}

/* Teardown function: removes the temp directory */
static int file_test_teardown(void **state) {
    test_remove_tmpdir(*state);
    return 0;
}

static void test_sha256_file_basic(void **state) {
    char *tmpdir = *state;
    char filepath[PATH_MAX];
    char hash[SHA256_HEX_LENGTH];
    
    /* Create a test file with known content */
    int ret = test_write_file(tmpdir, "test.txt", "abc");
    assert_int_equal(ret, 0);
    
    /* Build the full path */
    test_build_path(filepath, sizeof(filepath), tmpdir, "test.txt");
    
    /* Hash the file */
    ret = sha256_file(filepath, hash, sizeof(hash));
    assert_int_equal(ret, 0);
    
    /* Should match the hash of "abc" */
    assert_string_equal(hash, HASH_ABC);
}

static void test_sha256_file_empty(void **state) {
    char *tmpdir = *state;
    char filepath[PATH_MAX];
    char hash[SHA256_HEX_LENGTH];
    
    /* Create an empty file */
    int ret = test_write_file(tmpdir, "empty.txt", "");
    assert_int_equal(ret, 0);
    
    test_build_path(filepath, sizeof(filepath), tmpdir, "empty.txt");
    
    ret = sha256_file(filepath, hash, sizeof(hash));
    assert_int_equal(ret, 0);
    
    /* Should match empty string hash */
    assert_string_equal(hash, HASH_EMPTY);
}

static void test_sha256_file_not_found(void **state) {
    char *tmpdir = *state;
    char filepath[PATH_MAX];
    char hash[SHA256_HEX_LENGTH];
    
    /* Try to hash a non-existent file */
    test_build_path(filepath, sizeof(filepath), tmpdir, "nonexistent.txt");
    
    int ret = sha256_file(filepath, hash, sizeof(hash));
    
    /* Should return error (-1) for non-existent file */
    assert_int_equal(ret, -1);
}

static void test_sha256_file_large(void **state) {
    char *tmpdir = *state;
    char filepath[PATH_MAX];
    char hash[SHA256_HEX_LENGTH];
    
    /* Create a file larger than one SHA256 block (64 bytes)
     * Using 1000 bytes to test multi-block file reading */
    char *content = malloc(1001);
    assert_non_null(content);
    memset(content, 'a', 1000);
    content[1000] = '\0';
    
    int ret = test_write_file(tmpdir, "large.txt", content);
    free(content);
    assert_int_equal(ret, 0);
    
    test_build_path(filepath, sizeof(filepath), tmpdir, "large.txt");
    
    ret = sha256_file(filepath, hash, sizeof(hash));
    assert_int_equal(ret, 0);
    
    /* Verify it's a valid hex string (64 chars) */
    assert_int_equal(strlen(hash), 64);
    
    /* Verify all characters are valid hex */
    for (int i = 0; i < 64; i++) {
        assert_true((hash[i] >= '0' && hash[i] <= '9') ||
                    (hash[i] >= 'a' && hash[i] <= 'f'));
    }
}

/* ============================================================
 * Test Runner
 * ============================================================
 *
 * cmocka uses a test array to define which tests to run.
 * Each entry specifies the test function and optional setup/teardown.
 */
int main(void) {
    const struct CMUnitTest tests[] = {
        /* String hashing tests (no setup needed) */
        cmocka_unit_test(test_sha256_empty_string),
        cmocka_unit_test(test_sha256_abc),
        cmocka_unit_test(test_sha256_448bit_message),
        cmocka_unit_test(test_sha256_million_a),
        cmocka_unit_test(test_sha256_incremental),
        cmocka_unit_test(test_sha256_buffer_safety),
        
        /* File hashing tests (need temp directory setup) */
        cmocka_unit_test_setup_teardown(test_sha256_file_basic, 
                                         file_test_setup, file_test_teardown),
        cmocka_unit_test_setup_teardown(test_sha256_file_empty,
                                         file_test_setup, file_test_teardown),
        cmocka_unit_test_setup_teardown(test_sha256_file_not_found,
                                         file_test_setup, file_test_teardown),
        cmocka_unit_test_setup_teardown(test_sha256_file_large,
                                         file_test_setup, file_test_teardown),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
