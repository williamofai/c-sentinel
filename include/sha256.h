/*
 * C-Sentinel - Semantic Observability for UNIX Systems
 * Copyright (c) 2025 William Murray
 *
 * Licensed under the MIT License.
 * See LICENSE file for details.
 *
 * https://github.com/williamofai/c-sentinel
 *
 * sha256.h - Pure C SHA256 implementation
 *
 * This header provides SHA256 hashing for integrity verification
 * and privacy-preserving username hashing.
 *
 * NOTE: This is a stub file. The actual implementation should
 * exist in sha256.c in your main source tree (based on RFC 6234).
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

/* SHA256 produces a 256-bit (32-byte) hash */
#define SHA256_DIGEST_LENGTH 32
#define SHA256_HEX_LENGTH    65  /* 64 hex chars + null */

/*
 * SHA256 context structure
 */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} sha256_ctx_t;

/*
 * Initialize SHA256 context
 */
void sha256_init(sha256_ctx_t *ctx);

/*
 * Update context with data
 */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * Finalize and output digest
 */
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]);

/*
 * Convenience function: hash string to hex string
 *
 * @param input   Input string to hash
 * @param output  Output buffer (must be at least SHA256_HEX_LENGTH)
 * @param outsize Size of output buffer
 */
void sha256_string(const char *input, char *output, size_t outsize);

/*
 * Convenience function: hash file contents
 *
 * @param filepath  Path to file
 * @param output    Output buffer (must be at least SHA256_HEX_LENGTH)
 * @param outsize   Size of output buffer
 * @return          0 on success, -1 on error
 */
int sha256_file(const char *filepath, char *output, size_t outsize);

#endif /* SHA256_H */
