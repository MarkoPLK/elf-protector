#include "crypto_primitives.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

/*
 * Envoltura fina sobre libsodium. Las primitivas criptográficas (cifrado
 * autenticado ChaCha20-Poly1305 IETF y hash BLAKE2b) las provee libsodium, una
 * implementación auditada y de tiempo constante, enlazada estáticamente para
 * preservar la autonomía del wrapper. Este módulo se limita a adaptar la API
 * interna del prototipo a las llamadas de la biblioteca.
 */

/* Comprobaciones de que los tamaños del prototipo coinciden con los de la
 * primitiva IETF de libsodium; cualquier divergencia rompe el build. */
_Static_assert(WRAPPER_KEY_SIZE == crypto_aead_chacha20poly1305_ietf_KEYBYTES,
               "tamano de clave incompatible con libsodium");
_Static_assert(WRAPPER_NONCE_SIZE == crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
               "tamano de nonce incompatible con libsodium");
_Static_assert(WRAPPER_TAG_SIZE == crypto_aead_chacha20poly1305_ietf_ABYTES,
               "tamano de tag incompatible con libsodium");
_Static_assert(WRAPPER_HASH_SIZE >= crypto_generichash_BYTES_MIN &&
                   WRAPPER_HASH_SIZE <= crypto_generichash_BYTES_MAX,
               "tamano de hash fuera del rango de BLAKE2b");

/* Clave maestra fija embebida con la que se ofusca la clave de sesión en el
 * wrapper. No es un secreto criptográfico: viaja en claro dentro del binario y
 * solo eleva el coste de recuperar la clave (véase el análisis de amenazas). */
static const uint8_t k_master_key[WRAPPER_KEY_SIZE] = {
    0x51, 0x82, 0x43, 0xa1, 0x0b, 0xcd, 0x72, 0x19, 0xde, 0x34, 0x9a,
    0xef, 0x44, 0x90, 0x17, 0x6d, 0x28, 0xc0, 0x5f, 0xb3, 0x81, 0x2e,
    0x79, 0xa6, 0x13, 0xdc, 0x67, 0x3b, 0xe8, 0x4c, 0x95, 0xfa,
};

/* sodium_init() es idempotente: devuelve 0 en la primera inicialización
 * correcta, 1 si ya estaba inicializada y -1 en error. */
static int ensure_sodium(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

void wrapper_get_master_key(uint8_t out_key[WRAPPER_KEY_SIZE])
{
    memcpy(out_key, k_master_key, WRAPPER_KEY_SIZE);
}

void secure_bzero(void *ptr, size_t len)
{
    volatile uint8_t *p = ptr;
    while (len-- > 0U) {
        *p++ = 0U;
    }
}

int fill_random_bytes(uint8_t *buffer, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    size_t offset = 0;

    if (fd < 0) {
        return -1;
    }

    while (offset < len) {
        ssize_t got = read(fd, buffer + offset, len - offset);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (got == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)got;
    }

    close(fd);
    return 0;
}

void blake2b_hash(const uint8_t *input,
                  size_t input_len,
                  uint8_t out_hash[WRAPPER_HASH_SIZE])
{
    if (ensure_sodium() != 0) {
        /* Sin biblioteca no puede calcularse el hash; se deja el buffer a cero
         * para que la verificación posterior falle de forma segura. */
        secure_bzero(out_hash, WRAPPER_HASH_SIZE);
        return;
    }
    crypto_generichash(out_hash, WRAPPER_HASH_SIZE, input, input_len, NULL, 0U);
}

int chacha20_poly1305_encrypt(uint8_t *data,
                              size_t data_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t key[WRAPPER_KEY_SIZE],
                              const uint8_t nonce[WRAPPER_NONCE_SIZE],
                              uint8_t tag[WRAPPER_TAG_SIZE])
{
    if (ensure_sodium() != 0) {
        return -1;
    }
    /* Cifrado en el sitio (c == m) con etiqueta separada. */
    if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            data, tag, NULL,
            data, (unsigned long long)data_len,
            aad, (unsigned long long)aad_len,
            NULL, nonce, key) != 0) {
        return -1;
    }
    return 0;
}

int chacha20_poly1305_decrypt(uint8_t *data,
                              size_t data_len,
                              const uint8_t *aad,
                              size_t aad_len,
                              const uint8_t key[WRAPPER_KEY_SIZE],
                              const uint8_t nonce[WRAPPER_NONCE_SIZE],
                              const uint8_t tag[WRAPPER_TAG_SIZE])
{
    if (ensure_sodium() != 0) {
        return -1;
    }
    /* libsodium verifica la etiqueta en tiempo constante y solo escribe el
     * texto en claro si es válida; devuelve -1 en caso contrario. */
    if (crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            data, NULL,
            data, (unsigned long long)data_len,
            tag, aad, (unsigned long long)aad_len,
            nonce, key) != 0) {
        return -1;
    }
    return 0;
}
