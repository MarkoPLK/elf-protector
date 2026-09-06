#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto_primitives.h"
#include "runtime_trace.h"
#include "wrapper_blob.h"

static int create_memfd(const char *name)
{
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, 0U);
#else
    (void)name;
    errno = ENOSYS;
    return -1;
#endif
}

static int write_all(int fd, const unsigned char *buffer, size_t size)
{
    size_t offset = 0;
    while (offset < size) {
        ssize_t written = write(fd, buffer + offset, size - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int constant_time_eq(const uint8_t *lhs, const uint8_t *rhs, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(lhs[i] ^ rhs[i]);
    }
    return diff == 0U;
}

static int ranges_overlap(uint64_t first_offset,
                          uint64_t first_size,
                          uint64_t second_offset,
                          uint64_t second_size)
{
    uint64_t first_end = first_offset + first_size;
    uint64_t second_end = second_offset + second_size;

    if (first_end < first_offset || second_end < second_offset) {
        return 1;
    }
    return first_offset < second_end && second_offset < first_end;
}

static int validate_blob_header(const struct wrapper_embedded_blob *blob)
{
    if (blob == NULL || blob->ciphertext_bytes == NULL) {
        fprintf(stderr, "Blob nulo o incompleto\n");
        return -1;
    }
    if (blob->header.magic != WRAPPER_BLOB_MAGIC) {
        fprintf(stderr, "Magic de blob inválido\n");
        return -1;
    }
    if (blob->header.version != WRAPPER_BLOB_VERSION) {
        fprintf(stderr,
                "Versión de blob no soportada: %u\n",
                blob->header.version);
        return -1;
    }
    if (blob->header.header_size != sizeof(struct protected_blob_header)) {
        fprintf(stderr, "Tamaño de cabecera inesperado\n");
        return -1;
    }
    if (blob->header.algorithm != WRAPPER_ALGO_CHACHA20_POLY1305) {
        fprintf(stderr, "Algoritmo del blob no soportado\n");
        return -1;
    }
    if (blob->header.tamper_policy != WRAPPER_TAMPER_ABORT) {
        fprintf(stderr, "Política anti-tampering no soportada\n");
        return -1;
    }
    if (blob->header.metadata_version != WRAPPER_METADATA_VERSION) {
        fprintf(stderr, "Versión de metadatos no soportada\n");
        return -1;
    }
    if (blob->header.original_size == 0 ||
        blob->header.ciphertext_size != blob->header.original_size) {
        fprintf(stderr, "Tamaño del payload inconsistente\n");
        return -1;
    }
    if ((blob->header.flags & WRAPPER_FLAG_METADATA_PRESENT) == 0U ||
        blob->metadata_bytes == NULL ||
        blob->header.metadata_size < sizeof(struct protected_metadata_header)) {
        fprintf(stderr, "Metadatos del blob ausentes o inconsistentes\n");
        return -1;
    }
    return 0;
}

int wrapper_verify_blob_integrity(const struct wrapper_embedded_blob *blob)
{
    const struct protected_metadata_header *metadata;
    const struct protected_function_metadata *functions;
    uint8_t computed_hash[WRAPPER_HASH_SIZE];
    uint8_t session_key[WRAPPER_KEY_SIZE] = {0};
    uint8_t master_key[WRAPPER_KEY_SIZE] = {0};
    uint8_t *package_buffer = NULL;
    uint8_t *auth_buffer = NULL;
    size_t package_size;
    int rc = -1;

    if (validate_blob_header(blob) != 0) {
        goto cleanup;
    }

    metadata = (const struct protected_metadata_header *)blob->metadata_bytes;
    if (metadata->version != WRAPPER_METADATA_VERSION ||
        metadata->size != sizeof(*metadata)) {
        fprintf(stderr, "Cabecera de metadatos inválida\n");
        goto cleanup;
    }
    if (metadata->region_count > WRAPPER_MAX_PROTECTED_REGIONS) {
        fprintf(stderr, "Demasiadas regiones protegidas en metadatos\n");
        goto cleanup;
    }
    if (metadata->function_count > WRAPPER_MAX_PROTECTED_FUNCTIONS) {
        fprintf(stderr, "Demasiadas funciones protegidas en metadatos\n");
        goto cleanup;
    }
    if (blob->header.metadata_size !=
        sizeof(*metadata) +
            (uint64_t)metadata->region_count *
                sizeof(struct protected_region_metadata) +
            (uint64_t)metadata->function_count *
                sizeof(struct protected_function_metadata)) {
        fprintf(stderr, "Tamaño de metadatos incoherente con regiones/funciones\n");
        goto cleanup;
    }
    functions = (const struct protected_function_metadata
                     *)(blob->metadata_bytes + sizeof(*metadata) +
                        (size_t)metadata->region_count *
                            sizeof(struct protected_region_metadata));
    for (uint32_t i = 0; i < metadata->function_count; ++i) {
        if (functions[i].size == 0U ||
            functions[i].file_offset + functions[i].size <
                functions[i].file_offset ||
            functions[i].file_offset + functions[i].size >
                blob->header.original_size) {
            fprintf(stderr, "Metadatos de función protegida fuera de rango\n");
            goto cleanup;
        }
        for (uint32_t j = 0; j < i; ++j) {
            if (ranges_overlap(functions[i].file_offset,
                               functions[i].size,
                               functions[j].file_offset,
                               functions[j].size)) {
                fprintf(stderr, "Metadatos de función protegida solapados\n");
                goto cleanup;
            }
        }
    }

    package_size = (size_t)blob->header.metadata_size +
                   (size_t)blob->header.ciphertext_size;
    package_buffer = malloc(package_size);
    if (package_buffer == NULL) {
        fprintf(stderr, "malloc() falló al verificar el paquete\n");
        goto cleanup;
    }
    memcpy(package_buffer, blob->metadata_bytes, (size_t)blob->header.metadata_size);
    memcpy(package_buffer + blob->header.metadata_size,
           blob->ciphertext_bytes,
           (size_t)blob->header.ciphertext_size);
    blake2b_hash(package_buffer, package_size, computed_hash);
    if (!constant_time_eq(computed_hash,
                          blob->header.package_hash,
                          sizeof(computed_hash))) {
        fprintf(stderr, "Integridad global del paquete inválida\n");
        goto cleanup;
    }

    blake2b_hash(blob->ciphertext_bytes,
                 (size_t)blob->header.ciphertext_size,
                 computed_hash);
    if (!constant_time_eq(computed_hash,
                          blob->header.ciphertext_hash,
                          sizeof(computed_hash))) {
        fprintf(stderr, "Integridad del ciphertext inválida\n");
        goto cleanup;
    }

    auth_buffer = malloc((size_t)blob->header.ciphertext_size);
    if (auth_buffer == NULL) {
        fprintf(stderr, "malloc() falló al verificar el tag AEAD\n");
        goto cleanup;
    }
    memcpy(auth_buffer,
           blob->ciphertext_bytes,
           (size_t)blob->header.ciphertext_size);
    wrapper_get_master_key(master_key);
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        session_key[i] = (uint8_t)(blob->header.wrapped_key[i] ^ master_key[i]);
    }
    if (chacha20_poly1305_decrypt(auth_buffer,
                                  (size_t)blob->header.ciphertext_size,
                                  blob->metadata_bytes,
                                  (size_t)blob->header.metadata_size,
                                  session_key,
                                  blob->header.nonce,
                                  blob->header.tag) != 0) {
        fprintf(stderr, "Autenticidad AEAD del payload inválida\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (auth_buffer != NULL) {
        secure_bzero(auth_buffer, (size_t)blob->header.ciphertext_size);
        free(auth_buffer);
    }
    if (package_buffer != NULL) {
        secure_bzero(package_buffer, package_size);
        free(package_buffer);
    }
    secure_bzero(computed_hash, sizeof(computed_hash));
    secure_bzero(session_key, sizeof(session_key));
    secure_bzero(master_key, sizeof(master_key));
    return rc;
}

int wrapper_execute_blob(const struct wrapper_embedded_blob *blob,
                         int argc,
                         char **argv)
{
    int memfd = -1;
    uint8_t *plaintext = NULL;
    uint8_t computed_hash[WRAPPER_HASH_SIZE];
    uint8_t session_key[WRAPPER_KEY_SIZE];
    uint8_t master_key[WRAPPER_KEY_SIZE];
    int rc = -1;

#ifdef WRAPPER_ANTIDEBUG_COTRACE
    /* Endurecimiento opcional: instala la co-traza del padre y aborta si ya
     * hay un depurador adjunto, antes de reconstruir la clave de sesión. */
    if (wrapper_antidebug_install_cotrace() != 0) {
        return EXIT_FAILURE;
    }
#endif

    if (wrapper_verify_blob_integrity(blob) != 0) {
        goto cleanup;
    }

    plaintext = malloc((size_t)blob->header.original_size);
    if (plaintext == NULL) {
        fprintf(stderr, "malloc() falló al reservar payload descifrado\n");
        goto cleanup;
    }
    memcpy(plaintext, blob->ciphertext_bytes, (size_t)blob->header.ciphertext_size);

    wrapper_get_master_key(master_key);
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        session_key[i] = (uint8_t)(blob->header.wrapped_key[i] ^ master_key[i]);
    }

    if (chacha20_poly1305_decrypt(plaintext,
                                  (size_t)blob->header.original_size,
                                  blob->metadata_bytes,
                                  (size_t)blob->header.metadata_size,
                                  session_key,
                                  blob->header.nonce,
                                  blob->header.tag) != 0) {
        fprintf(stderr, "Tag AEAD del payload inválido\n");
        goto cleanup;
    }

    blake2b_hash(plaintext, (size_t)blob->header.original_size, computed_hash);
    if (!constant_time_eq(computed_hash,
                          blob->header.plaintext_hash,
                          sizeof(computed_hash))) {
        fprintf(stderr, "Integridad del payload descifrado inválida\n");
        goto cleanup;
    }

    memfd = create_memfd("protected-payload");
    if (memfd < 0) {
        fprintf(stderr, "memfd_create falló: %s\n", strerror(errno));
        goto cleanup;
    }

    if (write_all(memfd, plaintext, (size_t)blob->header.original_size) != 0) {
        fprintf(stderr, "No se pudo materializar el payload: %s\n",
                strerror(errno));
        goto cleanup;
    }

    if (fchmod(memfd, S_IRUSR | S_IXUSR) != 0) {
        fprintf(stderr, "fchmod falló: %s\n", strerror(errno));
        goto cleanup;
    }

    secure_bzero(plaintext, (size_t)blob->header.original_size);
    free(plaintext);
    plaintext = NULL;

    rc = wrapper_trace_exec_memfd(memfd, argc, argv, blob, session_key);

cleanup:
    if (memfd >= 0) {
        close(memfd);
    }
    if (plaintext != NULL) {
        secure_bzero(plaintext, (size_t)blob->header.original_size);
        free(plaintext);
    }
    secure_bzero(computed_hash, sizeof(computed_hash));
    secure_bzero(session_key, sizeof(session_key));
    secure_bzero(master_key, sizeof(master_key));
    return rc;
}
