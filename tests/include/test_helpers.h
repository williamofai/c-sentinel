/*
 * test_helpers.h - Common utilities for C-Sentinel unit tests
 *
 * This header provides:
 * 1. cmocka includes and standard test macros
 * 2. Temporary directory management for file-based tests
 * 3. Fixture file utilities
 * 4. Common assertions for C-Sentinel types
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

/* Standard includes */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>

/* cmocka must be included after the above standard headers */
#include <cmocka.h>

/* ============================================================
 * Temporary Directory Management
 * ============================================================
 * 
 * These functions create and clean up temp directories for tests
 * that need to work with real files (following our "real temp files"
 * strategy for cross-platform compatibility).
 *
 * Usage in tests:
 *   static int setup(void **state) {
 *       *state = test_create_tmpdir();
 *       return *state ? 0 : -1;
 *   }
 *   static int teardown(void **state) {
 *       test_remove_tmpdir(*state);
 *       return 0;
 *   }
 */

/* Create a temporary directory for test files.
 * Returns malloc'd path string that must be freed via test_remove_tmpdir().
 * Returns NULL on failure. */
static inline char *test_create_tmpdir(void) {
    char template[PATH_MAX];
    
    /* Use TMPDIR if set (standard Unix practice), fallback to /tmp */
    const char *tmpbase = getenv("TMPDIR");
    if (!tmpbase || !tmpbase[0]) {
        tmpbase = "/tmp";
    }
    
    snprintf(template, sizeof(template), "%s/sentinel-test-XXXXXX", tmpbase);
    
    char *result = mkdtemp(template);
    if (!result) {
        return NULL;
    }
    
    /* Return a malloc'd copy since template is on stack */
    return strdup(result);
}

/* Recursively remove a directory and all its contents.
 * Used for cleanup in test teardown. */
static inline int test_remove_tmpdir(char *path) {
    if (!path) return -1;
    
    DIR *dir = opendir(path);
    if (!dir) {
        free(path);
        return -1;
    }
    
    struct dirent *entry;
    char filepath[PATH_MAX];
    
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || 
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (lstat(filepath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                /* Recursively remove subdirectory */
                char *subdir = strdup(filepath);
                test_remove_tmpdir(subdir);
            } else {
                unlink(filepath);
            }
        }
    }
    
    closedir(dir);
    rmdir(path);
    free(path);
    return 0;
}

/* ============================================================
 * File Utilities
 * ============================================================
 *
 * Helper functions for creating test fixture files.
 */

/* Write content to a file in the test directory.
 * Returns 0 on success, -1 on failure. */
static inline int test_write_file(const char *dir, const char *filename, 
                                   const char *content) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    
    size_t len = strlen(content);
    size_t written = fwrite(content, 1, len, f);
    fclose(f);
    
    return (written == len) ? 0 : -1;
}

/* Write binary content to a file in the test directory.
 * Returns 0 on success, -1 on failure. */
static inline int test_write_binary(const char *dir, const char *filename,
                                     const void *data, size_t size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    
    size_t written = fwrite(data, 1, size, f);
    fclose(f);
    
    return (written == size) ? 0 : -1;
}

/* Read entire file content into malloc'd buffer.
 * Caller must free the returned buffer.
 * Returns NULL on failure. */
static inline char *test_read_file(const char *dir, const char *filename) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, filename);
    
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    
    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, size, f);
    buffer[read_size] = '\0';
    fclose(f);
    
    return buffer;
}

/* Create a subdirectory within the test directory.
 * Returns 0 on success, -1 on failure. */
static inline int test_mkdir(const char *dir, const char *subdir) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir, subdir);
    return mkdir(path, 0755);
}

/* Build a full path from directory and filename.
 * Writes to the provided buffer. */
static inline void test_build_path(char *out, size_t outsize,
                                    const char *dir, const char *filename) {
    snprintf(out, outsize, "%s/%s", dir, filename);
}

/* ============================================================
 * Environment Variable Helpers
 * ============================================================
 *
 * For tests that need to manipulate environment variables.
 * These follow standard POSIX setenv/unsetenv patterns.
 */

/* Set an environment variable for the duration of a test.
 * Stores the old value so it can be restored later. */
typedef struct {
    char *name;
    char *old_value;
    int was_set;
} test_env_backup_t;

static inline test_env_backup_t test_setenv(const char *name, const char *value) {
    test_env_backup_t backup;
    backup.name = strdup(name);
    
    const char *old = getenv(name);
    backup.was_set = (old != NULL);
    backup.old_value = old ? strdup(old) : NULL;
    
    setenv(name, value, 1);
    return backup;
}

/* Restore an environment variable to its previous state. */
static inline void test_restoreenv(test_env_backup_t *backup) {
    if (!backup->name) return;
    
    if (backup->was_set) {
        setenv(backup->name, backup->old_value, 1);
        free(backup->old_value);
    } else {
        unsetenv(backup->name);
    }
    free(backup->name);
    backup->name = NULL;
}

/* ============================================================
 * Test Output Helpers
 * ============================================================
 */

/* Print a message during test execution (for debugging).
 * Only prints if SENTINEL_TEST_VERBOSE is set. */
static inline void test_printf(const char *fmt, ...) {
    if (getenv("SENTINEL_TEST_VERBOSE")) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}

/* ============================================================
 * Common Test Macros
 * ============================================================
 */

/* Convenience macro for defining a test case */
#define TEST_CASE(name) static void name(void **state)

/* Convenience macro for the test array entry */
#define TEST(name) cmocka_unit_test(name)

/* Convenience macro for test with setup/teardown */
#define TEST_WITH_FIXTURE(name, setup, teardown) \
    cmocka_unit_test_setup_teardown(name, setup, teardown)

/* Run tests and return result suitable for main() */
#define RUN_TESTS(tests) cmocka_run_group_tests(tests, NULL, NULL)

/* Run tests with group setup/teardown */
#define RUN_TESTS_WITH_FIXTURE(tests, setup, teardown) \
    cmocka_run_group_tests(tests, setup, teardown)

#endif /* TEST_HELPERS_H */
