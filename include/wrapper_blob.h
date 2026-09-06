#ifndef WRAPPER_BLOB_H
#define WRAPPER_BLOB_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_primitives.h"

#define WRAPPER_BLOB_MAGIC 0x425054464c464d31ULL /* "1MFLFTPB" */
#define WRAPPER_BLOB_VERSION 2u
#define WRAPPER_METADATA_VERSION 6u
#define WRAPPER_MAX_PROTECTED_REGIONS 16u
#define WRAPPER_MAX_PROTECTED_FUNCTIONS 32u
#define WRAPPER_RESERVED_METADATA_SIZE 40u

enum wrapper_blob_algorithm {
    WRAPPER_ALGO_CHACHA20_POLY1305 = 2u,
};

enum wrapper_tamper_policy {
    WRAPPER_TAMPER_ABORT = 1u,
};

enum wrapper_blob_flags {
    WRAPPER_FLAG_PAYLOAD_PIE = 1u << 0,
    WRAPPER_FLAG_PAYLOAD_DYNAMIC = 1u << 1,
    WRAPPER_FLAG_METADATA_PRESENT = 1u << 2,
};

enum wrapper_function_flags {
    WRAPPER_FUNCTION_DEMO_TARGET = 1u << 0,
};

struct protected_metadata_header {
    uint32_t version;
    uint32_t size;
    uint32_t reserved_flags;
    uint32_t region_count;
    uint32_t function_count;
    uint32_t reserved0;
    uint8_t reserved[WRAPPER_RESERVED_METADATA_SIZE];
};

struct protected_region_metadata {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
    uint32_t reserved;
    uint8_t plaintext_hash[32];
};

struct protected_function_metadata {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t size;
    uint32_t flags;
    uint32_t reserved;
    uint8_t nonce[WRAPPER_NONCE_SIZE];
    uint8_t tag[WRAPPER_TAG_SIZE];
    uint8_t plaintext_hash[32];
    uint8_t ciphertext_hash[32];
};

struct protected_blob_header {
    uint64_t magic;
    uint32_t version;
    uint32_t header_size;
    uint32_t flags;
    uint32_t algorithm;
    uint32_t tamper_policy;
    uint32_t metadata_version;
    uint64_t original_size;
    uint64_t ciphertext_size;
    uint64_t metadata_size;
    uint64_t entry_point;
    uint8_t nonce[WRAPPER_NONCE_SIZE];
    uint8_t tag[WRAPPER_TAG_SIZE];
    uint8_t wrapped_key[32];
    uint8_t plaintext_hash[32];
    uint8_t ciphertext_hash[32];
    uint8_t package_hash[32];
};

struct wrapper_embedded_blob {
    struct protected_blob_header header;
    const unsigned char *ciphertext_bytes;
    const unsigned char *metadata_bytes;
};

#endif
