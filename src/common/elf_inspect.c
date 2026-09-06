#include "elf_inspect.h"

#include <elf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void set_error(char *buffer,
                      size_t buffer_size,
                      const char *fmt,
                      ...)
{
    va_list args;

    if (buffer == NULL || buffer_size == 0U) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(buffer, buffer_size, fmt, args);
    va_end(args);
}

static int range_fits_file(uint64_t offset, uint64_t bytes, size_t file_size)
{
    return offset <= file_size && bytes <= file_size &&
           offset + bytes >= offset && offset + bytes <= file_size;
}

static int symbol_name_has_prefix(const char *strings,
                                  size_t strings_size,
                                  uint32_t name_offset,
                                  const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    size_t available;

    if (name_offset >= strings_size) {
        return 0;
    }

    available = strings_size - name_offset;
    return available > prefix_len &&
           memcmp(strings + name_offset, prefix, prefix_len) == 0;
}

/* Arranques del C-runtime que se ejecutan antes de que el tracer se enganche;
 * insertar un int3 en ellos abortaría el proceso. En modo uniforme se excluyen
 * de la protección para que la variante uniforme cubra solo las funciones de la
 * aplicación. */
static int symbol_excluded_from_uniform(const char *name)
{
    static const char *const excluded[] = {
        "_start",
        "_dl_relocate_static_pie",
        "_dl_relocate_static_pie_ifunc",
        "_init",
        "_fini",
        "__libc_csu_init",
        "__libc_csu_fini",
    };
    size_t name_len;

    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); ++i) {
        if (strcmp(name, excluded[i]) == 0) {
            return 1;
        }
    }

    /* Los resolvers ifunc se ejecutan durante la relocalización del arranque,
     * antes de que el tracer se enganche; un int3 en ellos sería fatal. */
    name_len = strlen(name);
    if (name_len >= 6U && strcmp(name + name_len - 6U, "_ifunc") == 0) {
        return 1;
    }
    return 0;
}

static int virtual_to_file_offset(const struct elf_payload_info *info,
                                  uint64_t virtual_address,
                                  uint64_t bytes,
                                  uint64_t *file_offset_out)
{
    for (uint32_t i = 0; i < info->exec_region_count; ++i) {
        const struct elf_exec_region *region = &info->exec_regions[i];
        uint64_t virtual_end = region->virtual_address + region->file_size;
        uint64_t requested_end = virtual_address + bytes;
        uint64_t delta;

        if (virtual_end < region->virtual_address ||
            requested_end < virtual_address) {
            continue;
        }
        if (virtual_address < region->virtual_address ||
            requested_end > virtual_end) {
            continue;
        }

        delta = virtual_address - region->virtual_address;
        *file_offset_out = region->file_offset + delta;
        return 0;
    }

    return -1;
}

static int protected_symbol_already_recorded(
    const struct elf_payload_info *info,
    uint64_t virtual_address,
    uint64_t size)
{
    for (uint32_t i = 0; i < info->protected_function_count; ++i) {
        const struct elf_function_symbol *function =
            &info->protected_functions[i];

        if (function->virtual_address == virtual_address &&
            function->size == size) {
            return 1;
        }
    }
    return 0;
}

static void sort_protected_symbols(struct elf_payload_info *info)
{
    for (uint32_t i = 1; i < info->protected_function_count; ++i) {
        struct elf_function_symbol current = info->protected_functions[i];
        uint32_t j = i;

        while (j > 0U &&
               (info->protected_functions[j - 1U].virtual_address >
                    current.virtual_address ||
                (info->protected_functions[j - 1U].virtual_address ==
                     current.virtual_address &&
                 info->protected_functions[j - 1U].file_offset >
                     current.file_offset))) {
            info->protected_functions[j] = info->protected_functions[j - 1U];
            --j;
        }
        info->protected_functions[j] = current;
    }
}

static int find_protected_symbols(const uint8_t *data,
                                  size_t size,
                                  const Elf64_Ehdr *ehdr,
                                  int uniform,
                                  struct elf_payload_info *info,
                                  char *error_buffer,
                                  size_t error_buffer_size)
{
    const Elf64_Shdr *shdrs;
    size_t shdr_bytes;

    if (ehdr->e_shnum == 0U) {
        return 0;
    }
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        set_error(error_buffer, error_buffer_size, "tabla de secciones inválida");
        return -1;
    }

    shdr_bytes = (size_t)ehdr->e_shnum * sizeof(Elf64_Shdr);
    if (!range_fits_file(ehdr->e_shoff, shdr_bytes, size)) {
        set_error(error_buffer, error_buffer_size, "section headers fuera de rango");
        return -1;
    }

    shdrs = (const Elf64_Shdr *)(data + ehdr->e_shoff);
    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        const Elf64_Shdr *symtab = &shdrs[i];
        const Elf64_Shdr *strtab;
        const Elf64_Sym *symbols;
        const char *strings;
        size_t symbol_count;

        /* Una tabla dinámica puede ser la única tabla conservada después de
         * strip; ambas fuentes aportan STT_FUNC al mismo contrato de selección. */
        if (symtab->sh_type != SHT_SYMTAB && symtab->sh_type != SHT_DYNSYM) {
            continue;
        }
        if (symtab->sh_entsize != sizeof(Elf64_Sym) ||
            symtab->sh_link >= ehdr->e_shnum) {
            set_error(error_buffer, error_buffer_size, "tabla de símbolos inválida");
            return -1;
        }
        if (!range_fits_file(symtab->sh_offset, symtab->sh_size, size)) {
            set_error(error_buffer, error_buffer_size, "símbolos fuera de rango");
            return -1;
        }

        strtab = &shdrs[symtab->sh_link];
        if (strtab->sh_type != SHT_STRTAB ||
            !range_fits_file(strtab->sh_offset, strtab->sh_size, size)) {
            set_error(error_buffer, error_buffer_size, "strings de símbolos fuera de rango");
            return -1;
        }

        symbols = (const Elf64_Sym *)(data + symtab->sh_offset);
        strings = (const char *)(data + strtab->sh_offset);
        symbol_count = (size_t)(symtab->sh_size / sizeof(Elf64_Sym));

        for (size_t j = 0; j < symbol_count; ++j) {
            const Elf64_Sym *symbol = &symbols[j];
            uint64_t file_offset = 0;

            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC ||
                symbol->st_name >= strtab->sh_size) {
                continue;
            }

            if (uniform) {
                /* Modo uniforme: protege toda función definida del payload,
                 * omitiendo en silencio importadas, sin tamaño o fuera de
                 * región, y los arranques del C-runtime de la denylist. */
                if (symbol_excluded_from_uniform(strings + symbol->st_name)) {
                    continue;
                }
                if (symbol->st_shndx == SHN_UNDEF ||
                    symbol->st_size == 0U ||
                    virtual_to_file_offset(info,
                                           symbol->st_value,
                                           symbol->st_size,
                                           &file_offset) != 0) {
                    continue;
                }
            } else {
                if (!symbol_name_has_prefix(strings,
                                            (size_t)strtab->sh_size,
                                            symbol->st_name,
                                            ELF_INSPECT_PROTECTED_SYMBOL_PREFIX)) {
                    continue;
                }
                if (symbol->st_size == 0U ||
                    virtual_to_file_offset(info,
                                           symbol->st_value,
                                           symbol->st_size,
                                           &file_offset) != 0) {
                    set_error(error_buffer,
                              error_buffer_size,
                              "símbolo protegido fuera de región ejecutable");
                    return -1;
                }
            }

            if (protected_symbol_already_recorded(info,
                                                  symbol->st_value,
                                                  symbol->st_size)) {
                continue;
            }
            if (info->protected_function_count >=
                ELF_INSPECT_MAX_PROTECTED_FUNCTIONS) {
                set_error(error_buffer,
                          error_buffer_size,
                          "demasiadas funciones a proteger (máx %u)",
                          (unsigned)ELF_INSPECT_MAX_PROTECTED_FUNCTIONS);
                return -1;
            }

            info->protected_functions[info->protected_function_count].present =
                true;
            info->protected_functions[info->protected_function_count]
                .file_offset = file_offset;
            info->protected_functions[info->protected_function_count]
                .virtual_address = symbol->st_value;
            info->protected_functions[info->protected_function_count].size =
                symbol->st_size;
            info->protected_function_count++;
        }
    }

    sort_protected_symbols(info);
    return 0;
}

int inspect_elf_payload(const uint8_t *data,
                        size_t size,
                        int uniform,
                        struct elf_payload_info *info,
                        char *error_buffer,
                        size_t error_buffer_size)
{
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdrs;
    size_t phdr_bytes;
    int has_interp = 0;
    int has_dynamic = 0;

    if (data == NULL || info == NULL) {
        set_error(error_buffer, error_buffer_size, "argumentos inválidos");
        return -1;
    }

    if (size < sizeof(Elf64_Ehdr)) {
        set_error(error_buffer, error_buffer_size, "fichero demasiado pequeño");
        return -1;
    }

    ehdr = (const Elf64_Ehdr *)data;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        set_error(error_buffer, error_buffer_size, "el input no es ELF");
        return -1;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        set_error(error_buffer, error_buffer_size, "solo se soporta ELF64");
        return -1;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        set_error(error_buffer, error_buffer_size, "solo se soporta little-endian");
        return -1;
    }
    if (ehdr->e_machine != EM_X86_64) {
        set_error(error_buffer, error_buffer_size, "solo se soporta x86-64");
        return -1;
    }
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        set_error(error_buffer,
                  error_buffer_size,
                  "solo se soportan ejecutables ET_EXEC/ET_DYN");
        return -1;
    }
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        set_error(error_buffer, error_buffer_size, "tabla de programas inválida");
        return -1;
    }

    phdr_bytes = (size_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
    if ((size_t)ehdr->e_phoff > size || phdr_bytes > size ||
        (size_t)ehdr->e_phoff + phdr_bytes > size) {
        set_error(error_buffer, error_buffer_size, "program headers fuera de rango");
        return -1;
    }

    memset(info, 0, sizeof(*info));

    phdrs = (const Elf64_Phdr *)(data + ehdr->e_phoff);
    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_INTERP) {
            has_interp = 1;
        } else if (phdrs[i].p_type == PT_DYNAMIC) {
            has_dynamic = 1;
        } else if (phdrs[i].p_type == PT_LOAD &&
                   (phdrs[i].p_flags & PF_X) != 0U) {
            uint64_t end_offset = phdrs[i].p_offset + phdrs[i].p_filesz;
            struct elf_exec_region *region;

            if (phdrs[i].p_filesz == 0U) {
                continue;
            }
            if (end_offset < phdrs[i].p_offset || end_offset > size) {
                set_error(error_buffer,
                          error_buffer_size,
                          "segmento ejecutable fuera de rango");
                return -1;
            }
            if (info->exec_region_count >= ELF_INSPECT_MAX_EXEC_REGIONS) {
                set_error(error_buffer,
                          error_buffer_size,
                          "demasiadas regiones ejecutables");
                return -1;
            }

            region = &info->exec_regions[info->exec_region_count++];
            region->file_offset = phdrs[i].p_offset;
            region->virtual_address = phdrs[i].p_vaddr;
            region->file_size = phdrs[i].p_filesz;
            region->memory_size = phdrs[i].p_memsz;
            region->flags = phdrs[i].p_flags;
        }
    }

    if (info->exec_region_count == 0U) {
        set_error(error_buffer,
                  error_buffer_size,
                  "no hay segmentos PT_LOAD ejecutables");
        return -1;
    }

    info->is_pie = (ehdr->e_type == ET_DYN);
    info->is_dynamic = has_interp || has_dynamic;
    info->entry_point = ehdr->e_entry;
    info->file_size = size;
    if (find_protected_symbols(data,
                               size,
                               ehdr,
                               uniform,
                               info,
                               error_buffer,
                               error_buffer_size) != 0) {
        return -1;
    }
    return 0;
}
