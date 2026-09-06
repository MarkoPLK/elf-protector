#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto_primitives.h"
#include "elf_inspect.h"
#include "wrapper_blob.h"

struct options {
    const char *input_path;
    const char *output_path;
    const char *symbol_name;
    bool uniform;
};

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Uso: %s --input <elf> --output <header.h> [--symbol <nombre>] "
            "[--uniform]\n",
            argv0);
}

static bool parse_args(int argc, char **argv, struct options *opts)
{
    opts->symbol_name = "protected_payload";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
            opts->input_path = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            opts->output_path = argv[++i];
        } else if (strcmp(argv[i], "--symbol") == 0 && i + 1 < argc) {
            opts->symbol_name = argv[++i];
        } else if (strcmp(argv[i], "--uniform") == 0) {
            opts->uniform = true;
        } else {
            return false;
        }
    }

    return opts->input_path != NULL && opts->output_path != NULL;
}

static unsigned char *read_file(const char *path, size_t *size_out)
{
    FILE *fp = fopen(path, "rb");
    unsigned char *buffer = NULL;
    long file_size;

    if (fp == NULL) {
        fprintf(stderr, "No se pudo abrir '%s': %s\n", path, strerror(errno));
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "fseek() falló para '%s'\n", path);
        fclose(fp);
        return NULL;
    }

    file_size = ftell(fp);
    if (file_size <= 0) {
        fprintf(stderr, "ftell() devolvió un tamaño inválido para '%s'\n", path);
        fclose(fp);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "fseek() rewind falló para '%s'\n", path);
        fclose(fp);
        return NULL;
    }

    buffer = malloc((size_t)file_size);
    if (buffer == NULL) {
        fprintf(stderr, "malloc() sin memoria para %ld bytes\n", file_size);
        fclose(fp);
        return NULL;
    }

    if (fread(buffer, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "fread() incompleto para '%s'\n", path);
        free(buffer);
        fclose(fp);
        return NULL;
    }

    fclose(fp);
    *size_out = (size_t)file_size;
    return buffer;
}

static bool write_formatted(FILE *fp, const char *format, ...)
{
    va_list args;
    int result;

    va_start(args, format);
    result = vfprintf(fp, format, args);
    va_end(args);
    return result >= 0 && ferror(fp) == 0;
}

static bool write_hex_array(FILE *fp,
                            const char *name,
                            const uint8_t *data,
                            size_t size)
{
    if (!write_formatted(fp, "static const unsigned char %s[] = {", name)) {
        return false;
    }
    for (size_t i = 0; i < size; ++i) {
        if (i % 12U == 0U) {
            if (!write_formatted(fp, "\n    ")) {
                return false;
            }
        }
        if (!write_formatted(fp, "0x%02x,", data[i])) {
            return false;
        }
    }
    return write_formatted(fp, "\n};\n\n");
}

static char *create_output_template(const char *output_path)
{
    const char *last_slash = strrchr(output_path, '/');
    const char *template_name = ".packer-XXXXXX";
    size_t directory_size = last_slash == NULL ? 2U :
                            (size_t)(last_slash - output_path + 1);
    size_t template_size = directory_size + strlen(template_name) + 1U;
    char *template_path = malloc(template_size);

    if (template_path == NULL) {
        fprintf(stderr, "malloc() falló para ruta temporal\n");
        return NULL;
    }
    if (last_slash == NULL) {
        memcpy(template_path, "./", 2U);
    } else {
        memcpy(template_path, output_path, directory_size);
    }
    memcpy(template_path + directory_size,
           template_name,
           strlen(template_name) + 1U);
    return template_path;
}

static bool write_header(const struct options *opts,
                         const struct protected_blob_header *header,
                         const uint8_t *metadata,
                         size_t metadata_size,
                         const uint8_t *ciphertext)
{
    char *template_path = create_output_template(opts->output_path);
    FILE *fp = NULL;
    int temporary_fd;
    bool written = false;

    if (template_path == NULL) {
        return false;
    }

    temporary_fd = mkstemp(template_path);
    if (temporary_fd < 0) {
        fprintf(stderr, "No se pudo crear temporal para '%s': %s\n",
                opts->output_path,
                strerror(errno));
        free(template_path);
        return false;
    }
    fp = fdopen(temporary_fd, "w");
    if (fp == NULL) {
        fprintf(stderr, "No se pudo abrir temporal para '%s': %s\n",
                opts->output_path,
                strerror(errno));
        close(temporary_fd);
        unlink(template_path);
        free(template_path);
        return false;
    }

    if (!write_formatted(fp, "/* Archivo generado automáticamente. No editar a mano. */\n") ||
        !write_formatted(fp, "#ifndef EMBEDDED_PAYLOAD_GENERATED_H\n") ||
        !write_formatted(fp, "#define EMBEDDED_PAYLOAD_GENERATED_H\n\n") ||
        !write_formatted(fp, "#include \"wrapper_blob.h\"\n\n")) {
        goto cleanup;
    }

    if (!write_hex_array(fp,
                         "generated_ciphertext",
                         ciphertext,
                         (size_t)header->ciphertext_size) ||
        !write_hex_array(fp, "generated_metadata", metadata, metadata_size)) {
        goto cleanup;
    }

    if (!write_formatted(fp,
            "static const struct wrapper_embedded_blob %s = {\n"
            "    .header = {\n"
            "        .magic = 0x%llxULL,\n"
            "        .version = %uu,\n"
            "        .header_size = %uu,\n"
            "        .flags = 0x%xu,\n"
            "        .algorithm = %uu,\n"
            "        .tamper_policy = %uu,\n"
            "        .metadata_version = %uu,\n"
            "        .original_size = %lluULL,\n"
            "        .ciphertext_size = %lluULL,\n"
            "        .metadata_size = %lluULL,\n"
            "        .entry_point = 0x%llxULL,\n"
            "        .nonce = {",
            opts->symbol_name,
            (unsigned long long)header->magic,
            header->version,
            header->header_size,
            header->flags,
            header->algorithm,
            header->tamper_policy,
            header->metadata_version,
            (unsigned long long)header->original_size,
            (unsigned long long)header->ciphertext_size,
            (unsigned long long)header->metadata_size,
            (unsigned long long)header->entry_point)) {
        goto cleanup;
    }

    for (size_t i = 0; i < sizeof(header->nonce); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->nonce[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp, "},\n        .tag = {")) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(header->tag); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->tag[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp, "},\n        .wrapped_key = {")) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(header->wrapped_key); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->wrapped_key[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp, "},\n        .plaintext_hash = {")) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(header->plaintext_hash); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->plaintext_hash[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp, "},\n        .ciphertext_hash = {")) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(header->ciphertext_hash); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->ciphertext_hash[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp, "},\n        .package_hash = {")) {
        goto cleanup;
    }
    for (size_t i = 0; i < sizeof(header->package_hash); ++i) {
        if (i > 0U) {
            if (!write_formatted(fp, " ")) {
                goto cleanup;
            }
        }
        if (!write_formatted(fp, "0x%02x,", header->package_hash[i])) {
            goto cleanup;
        }
    }
    if (!write_formatted(fp,
            "},\n"
            "    },\n"
            "    .ciphertext_bytes = generated_ciphertext,\n"
            "    .metadata_bytes = generated_metadata,\n"
            "};\n\n")) {
        goto cleanup;
    }

    if (!write_formatted(fp, "#endif\n") || fflush(fp) != 0 ||
        ferror(fp) != 0) {
        goto cleanup;
    }
    if (fclose(fp) != 0) {
        fp = NULL;
        goto cleanup;
    }
    fp = NULL;
    if (rename(template_path, opts->output_path) != 0) {
        fprintf(stderr, "No se pudo publicar '%s': %s\n",
                opts->output_path,
                strerror(errno));
        goto cleanup;
    }
    written = true;

cleanup:
    if (!written) {
        if (fp != NULL && fclose(fp) != 0) {
            fprintf(stderr, "No se pudo cerrar temporal para '%s': %s\n",
                    opts->output_path,
                    strerror(errno));
        }
        unlink(template_path);
    }
    free(template_path);
    if (!written) {
        fprintf(stderr, "No se pudo escribir '%s': %s\n",
                opts->output_path,
                strerror(errno));
    }
    return written;
}

static bool ranges_overlap(uint64_t first_offset,
                           uint64_t first_size,
                           uint64_t second_offset,
                           uint64_t second_size)
{
    uint64_t first_end = first_offset + first_size;
    uint64_t second_end = second_offset + second_size;

    if (first_end < first_offset || second_end < second_offset) {
        return true;
    }
    return first_offset < second_end && second_offset < first_end;
}

int main(int argc, char **argv)
{
    struct options opts = {0};
    struct elf_payload_info elf_info = {0};
    struct protected_blob_header header = {0};
    struct protected_metadata_header metadata_header = {0};
    struct protected_region_metadata regions[ELF_INSPECT_MAX_EXEC_REGIONS] = {0};
    struct protected_function_metadata functions[WRAPPER_MAX_PROTECTED_FUNCTIONS] = {0};
    uint32_t function_count = 0;
    uint8_t *metadata = NULL;
    size_t metadata_size = 0;
    uint8_t *plaintext = NULL;
    uint8_t *protected_plaintext = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t session_key[WRAPPER_KEY_SIZE];
    uint8_t master_key[WRAPPER_KEY_SIZE];
    uint8_t *package_buffer = NULL;
    size_t package_size = 0;
    char elf_error[160];
    bool ok = false;
    size_t size = 0;

    if (!parse_args(argc, argv, &opts)) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    plaintext = read_file(opts.input_path, &size);
    if (plaintext == NULL) {
        goto cleanup;
    }

    if (inspect_elf_payload(plaintext,
                            size,
                            opts.uniform ? 1 : 0,
                            &elf_info,
                            elf_error,
                            sizeof(elf_error)) != 0) {
        fprintf(stderr, "ELF inválido: %s\n", elf_error);
        goto cleanup;
    }

    if (!opts.uniform && elf_info.protected_function_count == 0U) {
        fprintf(stderr,
                "No se encontraron funciones seleccionables con prefijo '%s'\n",
                ELF_INSPECT_PROTECTED_SYMBOL_PREFIX);
        goto cleanup;
    }

    protected_plaintext = malloc(size);
    if (protected_plaintext == NULL) {
        fprintf(stderr, "malloc() falló para protected_plaintext\n");
        goto cleanup;
    }
    memcpy(protected_plaintext, plaintext, size);

    if (fill_random_bytes(session_key, sizeof(session_key)) != 0 ||
        fill_random_bytes(header.nonce, sizeof(header.nonce)) != 0) {
        fprintf(stderr, "No se pudieron generar bytes aleatorios: %s\n",
                strerror(errno));
        goto cleanup;
    }

    wrapper_get_master_key(master_key);
    for (size_t i = 0; i < sizeof(session_key); ++i) {
        header.wrapped_key[i] = (uint8_t)(session_key[i] ^ master_key[i]);
    }

    header.magic = WRAPPER_BLOB_MAGIC;
    header.version = WRAPPER_BLOB_VERSION;
    header.header_size = (uint32_t)sizeof(header);
    header.algorithm = WRAPPER_ALGO_CHACHA20_POLY1305;
    header.tamper_policy = WRAPPER_TAMPER_ABORT;
    header.metadata_version = WRAPPER_METADATA_VERSION;
    header.original_size = size;
    header.ciphertext_size = size;
    function_count = elf_info.protected_function_count;
    if (function_count > WRAPPER_MAX_PROTECTED_FUNCTIONS) {
        fprintf(stderr, "Demasiadas funciones protegidas\n");
        goto cleanup;
    }
    for (uint32_t i = 0; i < function_count; ++i) {
        const struct elf_function_symbol *function =
            &elf_info.protected_functions[i];

        if (!function->present || function->size == 0U ||
            function->file_offset + function->size < function->file_offset ||
            function->file_offset + function->size > size) {
            fprintf(stderr, "Función protegida fuera de rango\n");
            goto cleanup;
        }
        for (uint32_t j = 0; j < i; ++j) {
            const struct elf_function_symbol *previous =
                &elf_info.protected_functions[j];

            if (ranges_overlap(function->file_offset,
                               function->size,
                               previous->file_offset,
                               previous->size)) {
                fprintf(stderr, "Funciones protegidas solapadas\n");
                goto cleanup;
            }
        }
    }

    metadata_size = sizeof(metadata_header) +
                    (size_t)elf_info.exec_region_count * sizeof(regions[0]) +
                    (size_t)function_count * sizeof(functions[0]);
    metadata = calloc(1U, metadata_size);
    if (metadata == NULL) {
        fprintf(stderr, "calloc() falló para metadatos\n");
        goto cleanup;
    }

    header.metadata_size = metadata_size;
    header.entry_point = elf_info.entry_point;
    if (elf_info.is_pie) {
        header.flags |= WRAPPER_FLAG_PAYLOAD_PIE;
    }
    if (elf_info.is_dynamic) {
        header.flags |= WRAPPER_FLAG_PAYLOAD_DYNAMIC;
    }
    header.flags |= WRAPPER_FLAG_METADATA_PRESENT;

    metadata_header.version = WRAPPER_METADATA_VERSION;
    metadata_header.size = (uint32_t)sizeof(metadata_header);
    metadata_header.reserved_flags = 0u;
    metadata_header.region_count = elf_info.exec_region_count;
    metadata_header.function_count = function_count;

    for (uint32_t i = 0; i < elf_info.exec_region_count; ++i) {
        const struct elf_exec_region *src = &elf_info.exec_regions[i];
        struct protected_region_metadata *dst = &regions[i];

        dst->file_offset = src->file_offset;
        dst->virtual_address = src->virtual_address;
        dst->file_size = src->file_size;
        dst->memory_size = src->memory_size;
        dst->flags = src->flags;
    }

    for (uint32_t i = 0; i < function_count; ++i) {
        const struct elf_function_symbol *src = &elf_info.protected_functions[i];
        struct protected_function_metadata *dst = &functions[i];

        if (fill_random_bytes(dst->nonce, sizeof(dst->nonce)) != 0) {
            fprintf(stderr,
                    "No se pudo generar nonce de función: %s\n",
                    strerror(errno));
            goto cleanup;
        }

        dst->file_offset = src->file_offset;
        dst->virtual_address = src->virtual_address;
        dst->size = src->size;
        dst->flags = WRAPPER_FUNCTION_DEMO_TARGET;
        blake2b_hash(plaintext + dst->file_offset,
                     (size_t)dst->size,
                     dst->plaintext_hash);
        if (chacha20_poly1305_encrypt(protected_plaintext + dst->file_offset,
                                       (size_t)dst->size,
                                       NULL,
                                       0U,
                                       session_key,
                                       dst->nonce,
                                       dst->tag) != 0) {
            fprintf(stderr, "No se pudo cifrar función protegida\n");
            goto cleanup;
        }
        blake2b_hash(protected_plaintext + dst->file_offset,
                     (size_t)dst->size,
                     dst->ciphertext_hash);
    }

    for (uint32_t i = 0; i < elf_info.exec_region_count; ++i) {
        const struct elf_exec_region *src = &elf_info.exec_regions[i];
        struct protected_region_metadata *dst = &regions[i];

        blake2b_hash(protected_plaintext + src->file_offset,
                     (size_t)src->file_size,
                     dst->plaintext_hash);
    }

    memcpy(metadata, &metadata_header, sizeof(metadata_header));
    memcpy(metadata + sizeof(metadata_header),
           regions,
           (size_t)elf_info.exec_region_count * sizeof(regions[0]));
    memcpy(metadata + sizeof(metadata_header) +
               (size_t)elf_info.exec_region_count * sizeof(regions[0]),
           functions,
           (size_t)function_count * sizeof(functions[0]));

    ciphertext = malloc(size);
    if (ciphertext == NULL) {
        fprintf(stderr, "malloc() falló para ciphertext\n");
        goto cleanup;
    }
    memcpy(ciphertext, protected_plaintext, size);

    blake2b_hash(protected_plaintext, size, header.plaintext_hash);
    if (chacha20_poly1305_encrypt(ciphertext,
                                  size,
                                  metadata,
                                  metadata_size,
                                  session_key,
                                  header.nonce,
                                  header.tag) != 0) {
        fprintf(stderr, "No se pudo cifrar payload con AEAD\n");
        goto cleanup;
    }
    blake2b_hash(ciphertext, size, header.ciphertext_hash);

    package_size = metadata_size + size;
    package_buffer = malloc(package_size);
    if (package_buffer == NULL) {
        fprintf(stderr, "malloc() falló para package_buffer\n");
        goto cleanup;
    }
    memcpy(package_buffer, metadata, metadata_size);
    memcpy(package_buffer + metadata_size, ciphertext, size);
    blake2b_hash(package_buffer, package_size, header.package_hash);

    ok = write_header(&opts, &header, metadata, metadata_size, ciphertext);

cleanup:
    if (package_buffer != NULL) {
        secure_bzero(package_buffer, package_size);
        free(package_buffer);
    }
    if (plaintext != NULL) {
        secure_bzero(plaintext, size);
        free(plaintext);
    }
    if (ciphertext != NULL) {
        secure_bzero(ciphertext, size);
        free(ciphertext);
    }
    if (protected_plaintext != NULL) {
        secure_bzero(protected_plaintext, size);
        free(protected_plaintext);
    }
    if (metadata != NULL) {
        secure_bzero(metadata, metadata_size);
        free(metadata);
    }
    secure_bzero(session_key, sizeof(session_key));
    secure_bzero(master_key, sizeof(master_key));
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
