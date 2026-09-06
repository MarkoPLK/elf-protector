#ifndef CRYPTO_PRIMITIVES_H
#define CRYPTO_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

#define WRAPPER_KEY_SIZE 32u
#define WRAPPER_NONCE_SIZE 12u
#define WRAPPER_TAG_SIZE 16u
#define WRAPPER_HASH_SIZE 32u

void wrapper_get_master_key(uint8_t out_key[WRAPPER_KEY_SIZE]);
void secure_bzero(void *ptr, size_t len);

int fill_random_bytes(uint8_t *buffer, size_t len);

void blake2b_hash(const uint8_t *input,
                  size_t input_len,
                  uint8_t out_hash[WRAPPER_HASH_SIZE]);

int chacha20_poly1305_encrypt(uint8_t *data,
                              size_t data_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t key[WRAPPER_KEY_SIZE],
                              const uint8_t nonce[WRAPPER_NONCE_SIZE],
                              uint8_t tag[WRAPPER_TAG_SIZE]);

int chacha20_poly1305_decrypt(uint8_t *data,
                              size_t data_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t key[WRAPPER_KEY_SIZE],
                              const uint8_t nonce[WRAPPER_NONCE_SIZE],
                              const uint8_t tag[WRAPPER_TAG_SIZE]);

#endif
