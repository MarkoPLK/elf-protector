#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_primitives.h"
#include "runtime_core.h"
#include "wrapper_blob.h"

#include "embedded_payload_nopie.h"

static int run_case(const char *name, struct wrapper_embedded_blob *blob)
{
    int rc = wrapper_verify_blob_integrity(blob);
    printf("%s: %s\n", name, rc == 0 ? "OK" : "REJECTED");
    return rc;
}

static int run_rfc8439_aead_vector(void)
{
    static const uint8_t key[WRAPPER_KEY_SIZE] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    static const uint8_t nonce[WRAPPER_NONCE_SIZE] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41,
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    };
    static const uint8_t aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    };
    static const uint8_t plaintext[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
    };
    static const uint8_t ciphertext[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
    };
    static const uint8_t expected_tag[WRAPPER_TAG_SIZE] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    };
    uint8_t buffer[sizeof(plaintext)];
    uint8_t tag[WRAPPER_TAG_SIZE];

    memcpy(buffer, plaintext, sizeof(buffer));
    if (chacha20_poly1305_encrypt(buffer,
                                  sizeof(buffer),
                                  aad,
                                  sizeof(aad),
                                  key,
                                  nonce,
                                  tag) != 0 ||
        memcmp(buffer, ciphertext, sizeof(buffer)) != 0 ||
        memcmp(tag, expected_tag, sizeof(tag)) != 0) {
        fprintf(stderr, "Vector RFC 8439 de cifrado AEAD no coincide\n");
        return -1;
    }
    if (chacha20_poly1305_decrypt(buffer,
                                  sizeof(buffer),
                                  aad,
                                  sizeof(aad),
                                  key,
                                  nonce,
                                  tag) != 0 ||
        memcmp(buffer, plaintext, sizeof(buffer)) != 0) {
        fprintf(stderr, "Vector RFC 8439 de descifrado AEAD no coincide\n");
        return -1;
    }

    printf("rfc8439-aead-vector: OK\n");
    secure_bzero(buffer, sizeof(buffer));
    secure_bzero(tag, sizeof(tag));
    return 0;
}

static int verify_jit_function_metadata(const struct wrapper_embedded_blob *blob)
{
    const struct protected_metadata_header *metadata =
        (const struct protected_metadata_header *)blob->metadata_bytes;
    const struct protected_function_metadata *functions =
        (const struct protected_function_metadata
             *)(blob->metadata_bytes + sizeof(*metadata) +
                (size_t)metadata->region_count *
                    sizeof(struct protected_region_metadata));
    uint8_t master_key[WRAPPER_KEY_SIZE];
    uint8_t session_key[WRAPPER_KEY_SIZE];
    uint8_t computed_hash[WRAPPER_HASH_SIZE];
    uint8_t *protected_image = NULL;
    int rc = -1;

    if (metadata->function_count < 4U) {
        fprintf(stderr,
                "Se esperaban al menos 4 funciones protegidas; hay %u\n",
                metadata->function_count);
        return -1;
    }

    protected_image = malloc((size_t)blob->header.original_size);
    if (protected_image == NULL) {
        fprintf(stderr, "malloc falló\n");
        goto cleanup;
    }

    memcpy(protected_image,
           blob->ciphertext_bytes,
           (size_t)blob->header.ciphertext_size);
    wrapper_get_master_key(master_key);
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        session_key[i] = (uint8_t)(blob->header.wrapped_key[i] ^ master_key[i]);
    }
    if (chacha20_poly1305_decrypt(protected_image,
                                  (size_t)blob->header.original_size,
                                  blob->metadata_bytes,
                                  (size_t)blob->header.metadata_size,
                                  session_key,
                                  blob->header.nonce,
                                  blob->header.tag) != 0) {
        fprintf(stderr, "Tag AEAD del payload no coincide\n");
        goto cleanup;
    }

    for (uint32_t i = 0; i < metadata->function_count; ++i) {
        uint8_t *function_plaintext = NULL;

        blake2b_hash(protected_image + functions[i].file_offset,
                     (size_t)functions[i].size,
                     computed_hash);
        if (memcmp(computed_hash,
                   functions[i].ciphertext_hash,
                   sizeof(computed_hash)) != 0) {
            fprintf(stderr, "Hash de función cifrada no coincide\n");
            goto cleanup;
        }

        function_plaintext = malloc((size_t)functions[i].size);
        if (function_plaintext == NULL) {
            fprintf(stderr, "malloc falló\n");
            goto cleanup;
        }
        memcpy(function_plaintext,
               protected_image + functions[i].file_offset,
               (size_t)functions[i].size);
        if (chacha20_poly1305_decrypt(function_plaintext,
                                      (size_t)functions[i].size,
                                      NULL,
                                      0U,
                                      session_key,
                                      functions[i].nonce,
                                      functions[i].tag) != 0) {
            fprintf(stderr, "Tag AEAD de función no coincide\n");
            secure_bzero(function_plaintext, (size_t)functions[i].size);
            free(function_plaintext);
            goto cleanup;
        }
        blake2b_hash(function_plaintext,
                     (size_t)functions[i].size,
                     computed_hash);
        secure_bzero(function_plaintext, (size_t)functions[i].size);
        free(function_plaintext);
        if (memcmp(computed_hash,
                   functions[i].plaintext_hash,
                   sizeof(computed_hash)) != 0) {
            fprintf(stderr, "Hash de función descifrada no coincide\n");
            goto cleanup;
        }
    }

    printf("jit-function-metadata: OK\n");
    rc = 0;

cleanup:
    if (protected_image != NULL) {
        secure_bzero(protected_image, (size_t)blob->header.original_size);
        free(protected_image);
    }
    secure_bzero(master_key, sizeof(master_key));
    secure_bzero(session_key, sizeof(session_key));
    secure_bzero(computed_hash, sizeof(computed_hash));
    return rc;
}

int main(void)
{
    struct wrapper_embedded_blob blob = protected_payload_nopie;
    unsigned char *mutable_ciphertext = NULL;
    unsigned char *mutable_metadata = NULL;
    int failures = 0;

    if (run_rfc8439_aead_vector() != 0) {
        failures++;
    }

    mutable_ciphertext = malloc((size_t)blob.header.ciphertext_size);
    if (mutable_ciphertext == NULL) {
        fprintf(stderr, "malloc falló\n");
        return EXIT_FAILURE;
    }

    memcpy(mutable_ciphertext,
           blob.ciphertext_bytes,
           (size_t)blob.header.ciphertext_size);
    mutable_metadata = malloc((size_t)blob.header.metadata_size);
    if (mutable_metadata == NULL) {
        fprintf(stderr, "malloc falló\n");
        free(mutable_ciphertext);
        return EXIT_FAILURE;
    }

    memcpy(mutable_metadata,
           blob.metadata_bytes,
           (size_t)blob.header.metadata_size);

    if (run_case("baseline", &blob) != 0) {
        failures++;
    }
    if (verify_jit_function_metadata(&blob) != 0) {
        failures++;
    }

    blob.ciphertext_bytes = mutable_ciphertext;
    mutable_ciphertext[0] ^= 0x01u;
    if (run_case("tampered-ciphertext", &blob) == 0) {
        failures++;
    }
    mutable_ciphertext[0] ^= 0x01u;

    blob.metadata_bytes = mutable_metadata;
    mutable_metadata[sizeof(struct protected_metadata_header)] ^= 0x5au;
    if (run_case("tampered-metadata", &blob) == 0) {
        failures++;
    }
    mutable_metadata[sizeof(struct protected_metadata_header)] ^= 0x5au;


    blob = protected_payload_nopie;
    blob.metadata_bytes = mutable_metadata;
    ((struct protected_metadata_header *)mutable_metadata)->region_count =
        WRAPPER_MAX_PROTECTED_REGIONS + 1U;
    if (run_case("tampered-region-count", &blob) == 0) {
        failures++;
    }
    memcpy(mutable_metadata,
           protected_payload_nopie.metadata_bytes,
           (size_t)protected_payload_nopie.header.metadata_size);

    blob = protected_payload_nopie;
    blob.metadata_bytes = mutable_metadata;
    ((struct protected_metadata_header *)mutable_metadata)->function_count =
        WRAPPER_MAX_PROTECTED_FUNCTIONS + 1U;
    if (run_case("tampered-function-count", &blob) == 0) {
        failures++;
    }
    memcpy(mutable_metadata,
           protected_payload_nopie.metadata_bytes,
           (size_t)protected_payload_nopie.header.metadata_size);

    blob = protected_payload_nopie;
    blob.header.tag[0] ^= 0x44u;
    if (run_case("tampered-payload-tag", &blob) == 0) {
        failures++;
    }

    blob = protected_payload_nopie;
    blob.header.package_hash[0] ^= 0x33u;
    if (run_case("tampered-header", &blob) == 0) {
        failures++;
    }

    free(mutable_ciphertext);
    free(mutable_metadata);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
