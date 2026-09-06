#ifndef ELF_INSPECT_H
#define ELF_INSPECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ELF_INSPECT_MAX_EXEC_REGIONS 16u
#define ELF_INSPECT_MAX_PROTECTED_FUNCTIONS 32u
#define ELF_INSPECT_PROTECTED_SYMBOL_PREFIX "protected_"

struct elf_exec_region {
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t file_size;
    uint64_t memory_size;
    uint32_t flags;
};

struct elf_function_symbol {
    bool present;
    uint64_t file_offset;
    uint64_t virtual_address;
    uint64_t size;
};

struct elf_payload_info {
    bool is_pie;
    bool is_dynamic;
    uint64_t entry_point;
    size_t file_size;
    uint32_t exec_region_count;
    struct elf_exec_region exec_regions[ELF_INSPECT_MAX_EXEC_REGIONS];
    uint32_t protected_function_count;
    struct elf_function_symbol
        protected_functions[ELF_INSPECT_MAX_PROTECTED_FUNCTIONS];
};

/* La selección de STT_FUNC consulta tanto SHT_SYMTAB como SHT_DYNSYM: un ELF
 * sin .symtab es válido si .dynsym conserva funciones utilizables. uniform != 0
 * protege todas las funciones de aplicación del payload (variante de control
 * para contrastar la selección por función); uniform == 0 mantiene el criterio
 * selectivo por prefijo ELF_INSPECT_PROTECTED_SYMBOL_PREFIX. */
int inspect_elf_payload(const uint8_t *data,
                        size_t size,
                        int uniform,
                        struct elf_payload_info *info,
                        char *error_buffer,
                        size_t error_buffer_size);

#endif
