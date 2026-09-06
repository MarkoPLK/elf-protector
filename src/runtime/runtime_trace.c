#define _GNU_SOURCE

#include "runtime_trace.h"

#include "bench_harness.h"
#include "crypto_primitives.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define INT3_OPCODE 0xccUL
#define TRACE_MAX_TIDS 64U
#define TRACE_MAX_FUNCTION_FRAMES 128U
#define TRACE_MAX_RETURN_BREAKPOINTS 64U

extern char **environ;

struct runtime_mapping {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    char perms[5];
    char path[512];
};

struct resolved_region {
    uint64_t start;
    uint64_t end;
    int resolved;
};

struct resolved_layout {
    struct resolved_region regions[WRAPPER_MAX_PROTECTED_REGIONS];
    uint32_t region_count;
    uint64_t entry_runtime_address;
    uint64_t function_runtime_addresses[WRAPPER_MAX_PROTECTED_FUNCTIONS];
    uint32_t function_count;
};

struct software_breakpoint {
    uint64_t address;
    uint64_t word_address;
    unsigned int byte_offset;
    unsigned long original_word;
    int enabled;
    int stepping_over;
    pid_t stepping_tid;
    pid_t stepping_tids[TRACE_MAX_TIDS];
    size_t stepping_count;
    int reenable_after_step;
    unsigned int hit_count;
};

struct return_breakpoint_state {
    struct software_breakpoint breakpoint;
    uint64_t address;
    uint32_t frame_count;
};

struct function_call_frame {
    pid_t tid;
    uint64_t return_address;
};

struct function_trace_state {
    struct software_breakpoint entry_breakpoint;
    struct function_call_frame frames[TRACE_MAX_FUNCTION_FRAMES];
    size_t frame_count;
    uint64_t runtime_address;
    uint8_t *original_ciphertext;
    size_t original_ciphertext_size;
    int decrypted;
#ifdef WRAPPER_TEST_HOOKS
    uint8_t last_restored_hash[WRAPPER_HASH_SIZE];
    uint64_t restore_count;
    int last_restored_hash_valid;
#endif
#ifdef WRAPPER_EXPOSURE_INSTRUMENTATION
    uint64_t exposure_open_ns;
#endif
};

struct traced_tid {
    pid_t tid;
    int options_configured;
    int stopped;
    int suspended_for_step;
    int has_deferred_status;
    int deferred_status;
};

struct trace_state {
    struct software_breakpoint entry_breakpoint;
    struct function_trace_state functions[WRAPPER_MAX_PROTECTED_FUNCTIONS];
    struct return_breakpoint_state return_breakpoints[TRACE_MAX_RETURN_BREAKPOINTS];
    uint32_t function_count;
    int test_tamper_decrypted;
    int test_tamper_decrypted_done;
    pid_t leader_tid;
    struct traced_tid tids[TRACE_MAX_TIDS];
    size_t tid_count;
    int world_stopped_for_step;
    pid_t step_owner_tid;
    int protected_world_held;
    pid_t protected_owner_tid;
    int release_protected_world_after_step;
};

#ifdef WRAPPER_EXPOSURE_INSTRUMENTATION
/*
 * Instrumentación opcional de la ventana de exposición (evaluación §5.5).
 * Activada solo si la variable de entorno WRAPPER_EXPOSURE_LOG define una ruta
 * de fichero. No altera el camino normal de ejecución cuando está inactiva:
 * registra, en cada activación, cuántas funciones protegidas están descifradas
 * de forma simultánea y la duración del intervalo descifrado -> restauración
 * del ciphertext original.
 */
static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0ULL;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint32_t count_decrypted(const struct trace_state *state)
{
    uint32_t decrypted_now = 0U;

    for (uint32_t i = 0U; i < state->function_count; ++i) {
        if (state->functions[i].decrypted) {
            ++decrypted_now;
        }
    }
    return decrypted_now;
}

static FILE *exposure_log_stream(void)
{
    static int initialized = 0;
    static FILE *stream = NULL;

    if (!initialized) {
        const char *path = getenv("WRAPPER_EXPOSURE_LOG");

        if (path != NULL && path[0] != '\0') {
            stream = fopen(path, "w");
            if (stream != NULL) {
                fprintf(stream,
                        "event\tfunc_index\tclear_now\ttotal_funcs\twindow_ns\n");
            }
        }
        initialized = 1;
    }
    return stream;
}
#endif /* WRAPPER_EXPOSURE_INSTRUMENTATION */

static int trace_debug_enabled(void)
{
    static int initialized = 0;
    static int enabled = 0;

    if (!initialized) {
        const char *value = getenv("WRAPPER_TRACE_DEBUG");

        enabled = value != NULL && strcmp(value, "1") == 0;
        initialized = 1;
    }
    return enabled;
}

#define TRACE_DEBUG(...)                        \
    do {                                        \
        if (trace_debug_enabled()) {            \
            fprintf(stderr, __VA_ARGS__);       \
        }                                       \
    } while (0)

static int get_registers(pid_t child, struct user_regs_struct *regs);

/* --- Tracee process/bootstrap helpers ---------------------------------- */

static char **build_child_argv(int argc, char **argv)
{
    char **child_argv = calloc((size_t)argc + 1U, sizeof(char *));
    if (child_argv == NULL) {
        return NULL;
    }

    child_argv[0] = (char *)"embedded-payload";
    for (int i = 1; i < argc; ++i) {
        child_argv[i] = argv[i];
    }
    return child_argv;
}

static const struct protected_metadata_header *blob_metadata_header(
    const struct wrapper_embedded_blob *blob)
{
    return (const struct protected_metadata_header *)blob->metadata_bytes;
}

static const struct protected_region_metadata *blob_metadata_regions(
    const struct wrapper_embedded_blob *blob)
{
    return (const struct protected_region_metadata *)(blob->metadata_bytes +
                                                     sizeof(struct protected_metadata_header));
}

static const struct protected_function_metadata *blob_metadata_functions(
    const struct wrapper_embedded_blob *blob)
{
    const struct protected_metadata_header *metadata =
        blob_metadata_header(blob);

    return (const struct protected_function_metadata
                *)(blob->metadata_bytes + sizeof(*metadata) +
                   (size_t)metadata->region_count *
                       sizeof(struct protected_region_metadata));
}

static int is_memfd_payload_mapping(const struct runtime_mapping *mapping)
{
    return strstr(mapping->path, "memfd:protected-payload") != NULL;
}

static int parse_maps_line(const char *line, struct runtime_mapping *mapping)
{
    char dev[32];
    unsigned long inode = 0;
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long offset = 0;
    int fields;

    memset(mapping, 0, sizeof(*mapping));
    fields = sscanf(line,
                    "%lx-%lx %4s %lx %31s %lu %511[^\n]",
                    &start,
                    &end,
                    mapping->perms,
                    &offset,
                    dev,
                    &inode,
                    mapping->path);
    if (fields < 6) {
        return -1;
    }

    mapping->start = (uint64_t)start;
    mapping->end = (uint64_t)end;
    mapping->offset = (uint64_t)offset;
    if (fields < 7) {
        mapping->path[0] = '\0';
    }
    return 0;
}

static int mapping_covers_region(const struct runtime_mapping *mapping,
                                 const struct protected_region_metadata *region)
{
    uint64_t mapping_size;
    uint64_t mapping_file_end;
    uint64_t region_file_end;

    if (mapping->end < mapping->start) {
        return 0;
    }
    mapping_size = mapping->end - mapping->start;
    mapping_file_end = mapping->offset + mapping_size;
    region_file_end = region->file_offset + region->file_size;

    return mapping_file_end >= mapping->offset &&
           region_file_end >= region->file_offset &&
           region->file_offset >= mapping->offset &&
           region_file_end <= mapping_file_end;
}

static int region_contains_virtual_address(
    const struct protected_region_metadata *region,
    uint64_t virtual_address)
{
    uint64_t virtual_end = region->virtual_address + region->memory_size;

    return virtual_end >= region->virtual_address &&
           virtual_address >= region->virtual_address &&
           virtual_address < virtual_end;
}

static int region_virtual_to_file_offset(
    const struct protected_region_metadata *region,
    uint64_t virtual_address,
    uint64_t *file_offset_out)
{
    uint64_t delta;

    if (!region_contains_virtual_address(region, virtual_address)) {
        return -1;
    }

    delta = virtual_address - region->virtual_address;
    if (delta >= region->file_size) {
        return -1;
    }
    if (region->file_offset + delta < region->file_offset) {
        return -1;
    }

    *file_offset_out = region->file_offset + delta;
    return 0;
}

static int mapping_covers_file_range(const struct runtime_mapping *mapping,
                                     uint64_t file_offset,
                                     uint64_t file_size)
{
    uint64_t mapping_size;
    uint64_t mapping_file_end;
    uint64_t file_end = file_offset + file_size;

    if (mapping->end < mapping->start || file_end < file_offset) {
        return 0;
    }

    mapping_size = mapping->end - mapping->start;
    mapping_file_end = mapping->offset + mapping_size;
    return mapping_file_end >= mapping->offset &&
           file_offset >= mapping->offset &&
           file_end <= mapping_file_end;
}

static int resolve_regions_from_maps(pid_t child,
                                     const struct wrapper_embedded_blob *blob,
                                     struct resolved_layout *layout)
{
    const struct protected_metadata_header *metadata = blob_metadata_header(blob);
    const struct protected_region_metadata *regions = blob_metadata_regions(blob);
    const struct protected_function_metadata *functions =
        blob_metadata_functions(blob);
    char maps_path[64];
    FILE *fp = NULL;
    char line[1024];
    uint32_t resolved_count = 0;
    int entry_resolved = 0;
    int rc = -1;

    memset(layout, 0, sizeof(*layout));
    layout->region_count = metadata->region_count;
    layout->function_count = metadata->function_count;

    snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", (long)child);
    fp = fopen(maps_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "No se pudo abrir %s: %s\n", maps_path, strerror(errno));
        goto cleanup;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        struct runtime_mapping mapping;

        if (parse_maps_line(line, &mapping) != 0) {
            continue;
        }
        if (mapping.perms[2] != 'x' || !is_memfd_payload_mapping(&mapping)) {
            continue;
        }

        for (uint32_t i = 0; i < metadata->region_count; ++i) {
            if (layout->regions[i].resolved) {
                continue;
            }
            if (!mapping_covers_region(&mapping, &regions[i])) {
                continue;
            }

            layout->regions[i].start = mapping.start +
                                        (regions[i].file_offset - mapping.offset);
            layout->regions[i].end = layout->regions[i].start + regions[i].file_size;
            layout->regions[i].resolved = 1;
            resolved_count++;
        }

        if (!entry_resolved) {
            for (uint32_t i = 0; i < metadata->region_count; ++i) {
                uint64_t entry_file_offset = 0;

                if (region_virtual_to_file_offset(&regions[i],
                                                  blob->header.entry_point,
                                                  &entry_file_offset) != 0) {
                    continue;
                }
                if (!mapping_covers_file_range(&mapping, entry_file_offset, 1U)) {
                    continue;
                }

                layout->entry_runtime_address =
                    mapping.start + (entry_file_offset - mapping.offset);
                entry_resolved = 1;
                break;
            }
        }

        for (uint32_t i = 0; i < metadata->function_count; ++i) {
            uint64_t function_file_offset = 0;

            if (layout->function_runtime_addresses[i] != 0U) {
                continue;
            }
            for (uint32_t j = 0; j < metadata->region_count; ++j) {
                if (region_virtual_to_file_offset(&regions[j],
                                                  functions[i].virtual_address,
                                                  &function_file_offset) != 0) {
                    continue;
                }
                if (!mapping_covers_file_range(&mapping,
                                               function_file_offset,
                                               1U)) {
                    continue;
                }

                layout->function_runtime_addresses[i] =
                    mapping.start + (function_file_offset - mapping.offset);
                break;
            }
        }
    }

    if (resolved_count != metadata->region_count) {
        fprintf(stderr,
                "No se pudieron resolver todas las regiones ejecutables "
                "(%u/%u)\n",
                resolved_count,
                metadata->region_count);
        goto cleanup;
    }
    if (!entry_resolved) {
        fprintf(stderr, "No se pudo resolver el entry point del payload\n");
        goto cleanup;
    }
    for (uint32_t i = 0; i < metadata->function_count; ++i) {
        if (layout->function_runtime_addresses[i] == 0U) {
            fprintf(stderr, "No se pudo resolver una función protegida\n");
            goto cleanup;
        }
    }

    rc = 0;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    return rc;
}

/* --- Remote execution control and memory access helpers ----------------- */

static long trace_options(void)
{
    return PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;
}

static int seize_tracer(pid_t child)
{
    long options = trace_options();

    if (ptrace(PTRACE_SEIZE, child, NULL, (void *)options) != 0) {
        fprintf(stderr,
                "PTRACE_SEIZE falló para TID %ld: %s\n",
                (long)child,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int configure_tracer(pid_t child)
{
    long options = trace_options();

    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)options) != 0) {
        fprintf(stderr,
                "PTRACE_SETOPTIONS falló para TID %ld: %s\n",
                (long)child,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int continue_child(pid_t child, int signal_to_deliver)
{
    if (ptrace(PTRACE_CONT,
               child,
               NULL,
               (void *)(uintptr_t)signal_to_deliver) != 0) {
        fprintf(stderr,
                "PTRACE_CONT falló para TID %ld: %s\n",
                (long)child,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int single_step_child(pid_t child)
{
    if (ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) != 0) {
        fprintf(stderr,
                "PTRACE_SINGLESTEP falló para TID %ld: %s\n",
                (long)child,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int single_step_child_with_signal(pid_t child, int signal_to_deliver)
{
    if (ptrace(PTRACE_SINGLESTEP,
               child,
               NULL,
               (void *)(uintptr_t)signal_to_deliver) != 0) {
        fprintf(stderr,
                "PTRACE_SINGLESTEP falló para TID %ld con señal %d: %s\n",
                (long)child,
                signal_to_deliver,
                strerror(errno));
        return -1;
    }
    return 0;
}

static struct traced_tid *find_traced_tid(struct trace_state *state, pid_t tid)
{
    for (size_t i = 0; i < state->tid_count; ++i) {
        if (state->tids[i].tid == tid) {
            return &state->tids[i];
        }
    }
    return NULL;
}

static int register_traced_tid(struct trace_state *state,
                               pid_t tid,
                               int options_configured,
                               int stopped)
{
    struct traced_tid *existing;

    if (tid <= 0) {
        fprintf(stderr, "TID trazado inválido: %ld\n", (long)tid);
        return -1;
    }

    existing = find_traced_tid(state, tid);
    if (existing != NULL) {
        if (options_configured) {
            existing->options_configured = 1;
        }
        if (stopped) {
            existing->stopped = 1;
        }
        return 0;
    }

    if (state->tid_count >= TRACE_MAX_TIDS) {
        fprintf(stderr,
                "Demasiados TIDs trazados para esta demo (%zu/%u)\n",
                state->tid_count,
                TRACE_MAX_TIDS);
        return -1;
    }

    state->tids[state->tid_count].tid = tid;
    state->tids[state->tid_count].options_configured = options_configured;
    state->tids[state->tid_count].stopped = stopped;
    state->tids[state->tid_count].suspended_for_step = 0;
    state->tids[state->tid_count].has_deferred_status = 0;
    state->tids[state->tid_count].deferred_status = 0;
    state->tid_count++;
    return 0;
}

static void unregister_traced_tid(struct trace_state *state, pid_t tid)
{
    for (size_t i = 0; i < state->tid_count; ++i) {
        if (state->tids[i].tid != tid) {
            continue;
        }

        state->tids[i] = state->tids[state->tid_count - 1U];
        state->tid_count--;
        return;
    }
}

static int configure_traced_tid_if_needed(struct trace_state *state, pid_t tid)
{
    struct traced_tid *entry = find_traced_tid(state, tid);

    if (entry == NULL) {
        if (register_traced_tid(state, tid, 0, 1) != 0) {
            return -1;
        }
        entry = find_traced_tid(state, tid);
    }

    if (entry == NULL) {
        fprintf(stderr, "No se pudo registrar el TID trazado %ld\n", (long)tid);
        return -1;
    }
    if (entry->options_configured) {
        return 0;
    }

    if (configure_tracer(tid) != 0) {
        return -1;
    }
    entry->options_configured = 1;
    return 0;
}

static int mark_tid_stopped(struct trace_state *state, pid_t tid)
{
    struct traced_tid *entry = find_traced_tid(state, tid);

    if (entry == NULL) {
        if (register_traced_tid(state, tid, 0, 1) != 0) {
            return -1;
        }
        return 0;
    }
    entry->stopped = 1;
    return 0;
}

static void mark_tid_running(struct trace_state *state, pid_t tid)
{
    struct traced_tid *entry = find_traced_tid(state, tid);

    if (entry != NULL) {
        entry->stopped = 0;
        entry->suspended_for_step = 0;
    }
}

static int trace_continue_child(struct trace_state *state,
                                pid_t child,
                                int signal_to_deliver)
{
    if (continue_child(child, signal_to_deliver) != 0) {
        return -1;
    }
    mark_tid_running(state, child);
    return 0;
}

static int trace_single_step_child(struct trace_state *state, pid_t child)
{
    if (single_step_child(child) != 0) {
        return -1;
    }
    mark_tid_running(state, child);
    return 0;
}

static int trace_single_step_child_with_signal(struct trace_state *state,
                                               pid_t child,
                                               int signal_to_deliver)
{
    if (single_step_child_with_signal(child, signal_to_deliver) != 0) {
        return -1;
    }
    mark_tid_running(state, child);
    return 0;
}

static int is_interrupt_stop_status(int status)
{
    unsigned int event = (unsigned int)status >> 16;

    return WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
           event == PTRACE_EVENT_STOP;
}

static int synthetic_sigtrap_status(void)
{
    return (SIGTRAP << 8) | 0x7f;
}

static int breakpoint_matches_trap_address(
    const struct software_breakpoint *breakpoint,
    uint64_t trap_address)
{
    return (breakpoint->enabled || breakpoint->stepping_over) &&
           breakpoint->address == trap_address;
}

static int breakpoint_enabled_matches_trap_address(
    const struct software_breakpoint *breakpoint,
    uint64_t trap_address)
{
    return breakpoint->enabled && breakpoint->address == trap_address;
}

static int tid_stopped_at_known_breakpoint(struct trace_state *state,
                                           pid_t tid,
                                           uint64_t *trap_address_out)
{
    struct user_regs_struct regs;
    uint64_t trap_address;

    if (get_registers(tid, &regs) != 0) {
        return 0;
    }

    trap_address = (uint64_t)regs.rip - 1U;
    if (breakpoint_matches_trap_address(&state->entry_breakpoint,
                                        trap_address)) {
        *trap_address_out = trap_address;
        return 1;
    }
    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (breakpoint_matches_trap_address(
                &state->functions[i].entry_breakpoint,
                trap_address)) {
            *trap_address_out = trap_address;
            return 1;
        }
    }
    for (size_t i = 0; i < TRACE_MAX_RETURN_BREAKPOINTS; ++i) {
        if (breakpoint_matches_trap_address(
                &state->return_breakpoints[i].breakpoint,
                trap_address)) {
            *trap_address_out = trap_address;
            return 1;
        }
    }

    return 0;
}

static int tid_stopped_at_enabled_breakpoint(struct trace_state *state,
                                             pid_t tid,
                                             uint64_t *trap_address_out)
{
    struct user_regs_struct regs;
    uint64_t trap_address;

    if (get_registers(tid, &regs) != 0) {
        return 0;
    }

    trap_address = (uint64_t)regs.rip - 1U;
    if (breakpoint_enabled_matches_trap_address(&state->entry_breakpoint,
                                                trap_address)) {
        *trap_address_out = trap_address;
        return 1;
    }
    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (breakpoint_enabled_matches_trap_address(
                &state->functions[i].entry_breakpoint,
                trap_address)) {
            *trap_address_out = trap_address;
            return 1;
        }
    }
    for (size_t i = 0; i < TRACE_MAX_RETURN_BREAKPOINTS; ++i) {
        if (breakpoint_enabled_matches_trap_address(
                &state->return_breakpoints[i].breakpoint,
                trap_address)) {
            *trap_address_out = trap_address;
            return 1;
        }
    }

    return 0;
}

static int defer_stopped_status(struct trace_state *state,
                                pid_t tid,
                                int status)
{
    struct traced_tid *entry = find_traced_tid(state, tid);

    if (entry == NULL) {
        if (register_traced_tid(state, tid, 0, 1) != 0) {
            return -1;
        }
        entry = find_traced_tid(state, tid);
    }
    if (entry == NULL) {
        fprintf(stderr,
                "No se pudo diferir la parada del TID %ld\n",
                (long)tid);
        return -1;
    }
    if (entry->has_deferred_status) {
        fprintf(stderr,
                "El TID %ld ya tenía una parada diferida\n",
                (long)tid);
        return -1;
    }

    entry->stopped = 1;
    entry->suspended_for_step = 0;
    entry->deferred_status = status;
    entry->has_deferred_status = 1;
    return 0;
}

static int take_deferred_status(struct trace_state *state,
                                pid_t *tid_out,
                                int *status_out)
{
    for (size_t i = 0; i < state->tid_count; ++i) {
        struct traced_tid *entry = &state->tids[i];

        if (!entry->has_deferred_status) {
            continue;
        }
        *tid_out = entry->tid;
        *status_out = entry->deferred_status;
        entry->deferred_status = 0;
        entry->has_deferred_status = 0;
        entry->stopped = 1;
        return 1;
    }
    return 0;
}

static int other_tids_are_stopped(const struct trace_state *state,
                                  pid_t owner_tid)
{
    for (size_t i = 0; i < state->tid_count; ++i) {
        const struct traced_tid *entry = &state->tids[i];

        if (entry->tid == owner_tid) {
            continue;
        }
        if (!entry->stopped && !entry->has_deferred_status) {
            return 0;
        }
    }
    return 1;
}

static int request_interrupt_for_running_tids(struct trace_state *state,
                                              pid_t owner_tid)
{
    size_t i = 0;

    while (i < state->tid_count) {
        struct traced_tid *entry = &state->tids[i];

        if (entry->tid == owner_tid || entry->stopped ||
            entry->has_deferred_status) {
            ++i;
            continue;
        }

        TRACE_DEBUG("trace: interrupt TID %ld for owner %ld\n",
                    (long)entry->tid,
                    (long)owner_tid);
        if (ptrace(PTRACE_INTERRUPT, entry->tid, NULL, NULL) != 0) {
            if (errno == ESRCH) {
                unregister_traced_tid(state, entry->tid);
                continue;
            }
            fprintf(stderr,
                    "PTRACE_INTERRUPT falló para TID %ld: %s\n",
                    (long)entry->tid,
                    strerror(errno));
            return -1;
        }
        entry->suspended_for_step = 1;
        ++i;
    }

    return 0;
}

static int wait_for_step_stop_settle(struct trace_state *state,
                                     pid_t owner_tid)
{
    while (!other_tids_are_stopped(state, owner_tid)) {
        int status = 0;
        pid_t waited = waitpid(-1, &status, __WALL);

        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr,
                    "waitpid() durante pausa multi-TID falló: %s\n",
                    strerror(errno));
            return -1;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (waited == state->leader_tid) {
                fprintf(stderr,
                        "El líder del payload terminó durante pausa multi-TID\n");
                return -1;
            }
            unregister_traced_tid(state, waited);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            continue;
        }
        TRACE_DEBUG("trace: settle stop TID %ld signal %d event %u\n",
                    (long)waited,
                    WSTOPSIG(status),
                    (unsigned int)status >> 16);
        if (trace_debug_enabled() && WSTOPSIG(status) != SIGTRAP &&
            WSTOPSIG(status) != SIGSTOP) {
            struct user_regs_struct regs;

            if (get_registers(waited, &regs) == 0) {
                TRACE_DEBUG("trace: signal stop regs TID %ld rip=0x%llx rsp=0x%llx\n",
                            (long)waited,
                            (unsigned long long)regs.rip,
                            (unsigned long long)regs.rsp);
            }
        }
        if (mark_tid_stopped(state, waited) != 0) {
            return -1;
        }

        if (is_interrupt_stop_status(status)) {
            struct traced_tid *entry = find_traced_tid(state, waited);
            uint64_t trap_address = 0;

            if (tid_stopped_at_known_breakpoint(state,
                                                waited,
                                                &trap_address)) {
                TRACE_DEBUG("trace: TID %ld interrupt-stop actually at breakpoint 0x%llx\n",
                            (long)waited,
                            (unsigned long long)trap_address);
                if (defer_stopped_status(state,
                                          waited,
                                          synthetic_sigtrap_status()) != 0) {
                    return -1;
                }
                continue;
            }
            if (trace_debug_enabled()) {
                struct user_regs_struct regs;

                if (get_registers(waited, &regs) == 0) {
                    TRACE_DEBUG("trace: interrupt-stop TID %ld rip=0x%llx trap_candidate=0x%llx\n",
                                (long)waited,
                                (unsigned long long)regs.rip,
                                (unsigned long long)((uint64_t)regs.rip - 1U));
                }
            }

            if (entry != NULL) {
                entry->suspended_for_step = 1;
            }
            continue;
        }

        if (defer_stopped_status(state, waited, status) != 0) {
            return -1;
        }
    }

    return 0;
}

static int stop_other_tids_for_step(struct trace_state *state, pid_t owner_tid)
{
    struct traced_tid *owner = find_traced_tid(state, owner_tid);

    if (state->world_stopped_for_step) {
        return state->step_owner_tid == owner_tid ? 0 : -1;
    }
    TRACE_DEBUG("trace: stop world for TID %ld\n", (long)owner_tid);
    if (owner == NULL) {
        if (register_traced_tid(state, owner_tid, 0, 1) != 0) {
            return -1;
        }
    } else {
        owner->stopped = 1;
    }

    if (request_interrupt_for_running_tids(state, owner_tid) != 0) {
        return -1;
    }
    if (wait_for_step_stop_settle(state, owner_tid) != 0) {
        return -1;
    }

    state->world_stopped_for_step = 1;
    state->step_owner_tid = owner_tid;
    TRACE_DEBUG("trace: world stopped for TID %ld\n", (long)owner_tid);
    return 0;
}

static int resume_tids_after_step(struct trace_state *state, pid_t owner_tid)
{
    if (!state->world_stopped_for_step) {
        return 0;
    }
    if (state->step_owner_tid != owner_tid) {
        fprintf(stderr,
                "Propietario de pausa multi-TID inesperado: %ld != %ld\n",
                (long)state->step_owner_tid,
                (long)owner_tid);
        return -1;
    }

    if (state->protected_world_held &&
        state->protected_owner_tid == owner_tid &&
        !state->release_protected_world_after_step) {
        state->world_stopped_for_step = 0;
        state->step_owner_tid = 0;
        return 0;
    }

    for (size_t i = 0; i < state->tid_count; ++i) {
        struct traced_tid *entry = &state->tids[i];

        if (entry->tid == owner_tid || !entry->suspended_for_step) {
            continue;
        }
        if (entry->has_deferred_status) {
            TRACE_DEBUG("trace: keep deferred TID %ld stopped\n",
                        (long)entry->tid);
            entry->suspended_for_step = 0;
            continue;
        }
        TRACE_DEBUG("trace: resume TID %ld after step owner %ld\n",
                    (long)entry->tid,
                    (long)owner_tid);
        if (entry->stopped &&
            trace_continue_child(state, entry->tid, 0) != 0) {
            return -1;
        }
        entry->suspended_for_step = 0;
    }

    state->world_stopped_for_step = 0;
    state->step_owner_tid = 0;
    if (state->release_protected_world_after_step &&
        state->protected_owner_tid == owner_tid) {
        state->protected_world_held = 0;
        state->protected_owner_tid = 0;
        state->release_protected_world_after_step = 0;
    }
    return 0;
}

static int ptrace_read_word(pid_t child,
                            uint64_t address,
                            unsigned long *word_out)
{
    long word;

    errno = 0;
    word = ptrace(PTRACE_PEEKTEXT, child, (void *)(uintptr_t)address, NULL);
    if (word == -1 && errno != 0) {
        fprintf(stderr,
                "PTRACE_PEEKTEXT falló para TID %ld en 0x%llx: %s\n",
                (long)child,
                (unsigned long long)address,
                strerror(errno));
        return -1;
    }

    *word_out = (unsigned long)word;
    return 0;
}

static int ptrace_read_data_word(pid_t child,
                                 uint64_t address,
                                 unsigned long *word_out)
{
    long word;

    errno = 0;
    word = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)address, NULL);
    if (word == -1 && errno != 0) {
        fprintf(stderr,
                "PTRACE_PEEKDATA falló para TID %ld en 0x%llx: %s\n",
                (long)child,
                (unsigned long long)address,
                strerror(errno));
        return -1;
    }

    *word_out = (unsigned long)word;
    return 0;
}

static int ptrace_write_word(pid_t child, uint64_t address, unsigned long word)
{
    if (ptrace(PTRACE_POKETEXT,
               child,
               (void *)(uintptr_t)address,
               (void *)word) != 0) {
        fprintf(stderr,
                "PTRACE_POKETEXT falló para TID %ld en 0x%llx: %s\n",
                (long)child,
                (unsigned long long)address,
                strerror(errno));
        return -1;
    }
    return 0;
}

static int tracee_read_bytes(pid_t child,
                             uint64_t address,
                             uint8_t *buffer,
                             size_t size)
{
    size_t offset = 0;

    while (offset < size) {
        uint64_t current_address = address + offset;
        uint64_t word_address =
            current_address & ~(uint64_t)(sizeof(long) - 1U);
        unsigned int byte_offset =
            (unsigned int)(current_address - word_address);
        size_t chunk = sizeof(long) - byte_offset;
        unsigned long word;

        if (chunk > size - offset) {
            chunk = size - offset;
        }
        if (ptrace_read_word(child, word_address, &word) != 0) {
            return -1;
        }

        memcpy(buffer + offset, ((uint8_t *)&word) + byte_offset, chunk);
        offset += chunk;
    }

    return 0;
}

static int tracee_write_bytes(pid_t child,
                              uint64_t address,
                              const uint8_t *buffer,
                              size_t size)
{
    size_t offset = 0;

    while (offset < size) {
        uint64_t current_address = address + offset;
        uint64_t word_address =
            current_address & ~(uint64_t)(sizeof(long) - 1U);
        unsigned int byte_offset =
            (unsigned int)(current_address - word_address);
        size_t chunk = sizeof(long) - byte_offset;
        unsigned long word;

        if (chunk > size - offset) {
            chunk = size - offset;
        }
        if (ptrace_read_word(child, word_address, &word) != 0) {
            return -1;
        }

        memcpy(((uint8_t *)&word) + byte_offset, buffer + offset, chunk);
        if (ptrace_write_word(child, word_address, word) != 0) {
            return -1;
        }

        offset += chunk;
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

/* --- Software breakpoint helpers --------------------------------------- */

static int enable_breakpoint(pid_t child,
                             struct software_breakpoint *breakpoint,
                             uint64_t address)
{
    unsigned long patched_word;
    unsigned int bit_shift;
    unsigned int previous_hit_count = breakpoint->hit_count;

    memset(breakpoint, 0, sizeof(*breakpoint));
    breakpoint->hit_count = previous_hit_count;
    breakpoint->address = address;
    breakpoint->word_address = address & ~(uint64_t)(sizeof(long) - 1U);
    breakpoint->byte_offset =
        (unsigned int)(address - breakpoint->word_address);
    bit_shift = breakpoint->byte_offset * 8U;

    if (ptrace_read_word(child,
                         breakpoint->word_address,
                         &breakpoint->original_word) != 0) {
        return -1;
    }

    patched_word = (breakpoint->original_word & ~(0xffUL << bit_shift)) |
                   (INT3_OPCODE << bit_shift);
    if (ptrace_write_word(child, breakpoint->word_address, patched_word) != 0) {
        return -1;
    }

    breakpoint->enabled = 1;
    return 0;
}

static int disable_breakpoint(pid_t child,
                              struct software_breakpoint *breakpoint)
{
    if (!breakpoint->enabled && !breakpoint->stepping_over) {
        return 0;
    }
    if (ptrace_write_word(child,
                          breakpoint->word_address,
                          breakpoint->original_word) != 0) {
        return -1;
    }
    breakpoint->enabled = 0;
    return 0;
}

static int get_registers(pid_t child, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, child, NULL, regs) != 0) {
        fprintf(stderr, "PTRACE_GETREGS falló: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int set_registers(pid_t child, const struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_SETREGS, child, NULL, (void *)regs) != 0) {
        fprintf(stderr, "PTRACE_SETREGS falló: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int breakpoint_has_stepping_tid(
    const struct software_breakpoint *breakpoint,
    pid_t tid)
{
    for (size_t i = 0; i < breakpoint->stepping_count; ++i) {
        if (breakpoint->stepping_tids[i] == tid) {
            return 1;
        }
    }
    return 0;
}

static int begin_breakpoint_step_over(struct software_breakpoint *breakpoint,
                                      pid_t tid,
                                      int reenable_after_step)
{
    if (breakpoint_has_stepping_tid(breakpoint, tid)) {
        return 0;
    }
    if (breakpoint->stepping_count >= TRACE_MAX_TIDS) {
        fprintf(stderr,
                "Demasiados TIDs en single-step sobre el mismo breakpoint\n");
        return -1;
    }

    if (breakpoint->stepping_count == 0U) {
        breakpoint->reenable_after_step = reenable_after_step;
    } else if (reenable_after_step) {
        breakpoint->reenable_after_step = 1;
    }
    breakpoint->stepping_tids[breakpoint->stepping_count] = tid;
    breakpoint->stepping_count++;
    breakpoint->stepping_over = 1;
    breakpoint->stepping_tid = tid;
    return 0;
}

static int finish_breakpoint_step_over(struct software_breakpoint *breakpoint,
                                       pid_t tid,
                                       int *reenable_after_step_out,
                                       uint64_t *breakpoint_address_out)
{
    size_t index = TRACE_MAX_TIDS;

    for (size_t i = 0; i < breakpoint->stepping_count; ++i) {
        if (breakpoint->stepping_tids[i] == tid) {
            index = i;
            break;
        }
    }
    if (index == TRACE_MAX_TIDS) {
        return 0;
    }

    for (size_t i = index + 1U; i < breakpoint->stepping_count; ++i) {
        breakpoint->stepping_tids[i - 1U] = breakpoint->stepping_tids[i];
    }
    breakpoint->stepping_count--;
    if (breakpoint->stepping_count > 0U) {
        breakpoint->stepping_tid =
            breakpoint->stepping_tids[breakpoint->stepping_count - 1U];
        *reenable_after_step_out = 0;
        *breakpoint_address_out = breakpoint->address;
        return 1;
    }

    *reenable_after_step_out = breakpoint->reenable_after_step;
    *breakpoint_address_out = breakpoint->address;
    breakpoint->stepping_over = 0;
    breakpoint->stepping_tid = 0;
    breakpoint->reenable_after_step = 0;
    return 1;
}

/* --- JIT protected-function helpers ------------------------------------ */

static int validate_function_size(
    const struct protected_function_metadata *function,
    size_t *function_size_out)
{
    if (function->size == 0U ||
        (uint64_t)(size_t)function->size != function->size) {
        fprintf(stderr, "Tamaño de función protegida inválido\n");
        return -1;
    }
    *function_size_out = (size_t)function->size;
    return 0;
}

static int verify_remote_function_hash(
    pid_t child,
    const struct protected_function_metadata *function,
    uint64_t runtime_address,
    const uint8_t expected_hash[WRAPPER_HASH_SIZE],
    const char *failure_message)
{
    uint8_t computed_hash[WRAPPER_HASH_SIZE];
    uint8_t *buffer = NULL;
    size_t function_size;
    int rc = -1;

    if (validate_function_size(function, &function_size) != 0) {
        return -1;
    }

    buffer = malloc(function_size);
    if (buffer == NULL) {
        fprintf(stderr, "malloc() falló para función protegida\n");
        return -1;
    }

    if (tracee_read_bytes(child, runtime_address, buffer, function_size) != 0) {
        goto cleanup;
    }

    {
        BENCH_BEGIN(t_hash);
        blake2b_hash(buffer, function_size, computed_hash);
        BENCH_END(t_hash, "hash", function_size);
    }
    if (!constant_time_eq(computed_hash,
                          expected_hash,
                          sizeof(computed_hash))) {
        fprintf(stderr, "%s\n", failure_message);
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (buffer != NULL) {
        secure_bzero(buffer, function_size);
        free(buffer);
    }
    secure_bzero(computed_hash, sizeof(computed_hash));
    return rc;
}

static int decrypt_remote_function_bytes(
    pid_t child,
    const struct protected_function_metadata *function,
    uint64_t runtime_address,
    const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    uint8_t *buffer = NULL;
    size_t function_size;
    int rc = -1;

    if (validate_function_size(function, &function_size) != 0) {
        return -1;
    }

    buffer = malloc(function_size);
    if (buffer == NULL) {
        fprintf(stderr, "malloc() falló para función protegida\n");
        return -1;
    }

    if (tracee_read_bytes(child, runtime_address, buffer, function_size) != 0) {
        goto cleanup;
    }

    {
        int aead_rc;
        BENCH_BEGIN(t_dec);
        aead_rc = chacha20_poly1305_decrypt(buffer,
                                            function_size,
                                            NULL,
                                            0U,
                                            jit_key,
                                            function->nonce,
                                            function->tag);
        BENCH_END(t_dec, "aead_decrypt", function_size);
        if (aead_rc != 0) {
            fprintf(stderr, "Tag AEAD de función protegida inválido\n");
            goto cleanup;
        }
    }

    if (tracee_write_bytes(child, runtime_address, buffer, function_size) != 0) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (buffer != NULL) {
        secure_bzero(buffer, function_size);
        free(buffer);
    }
    return rc;
}

static int cache_original_function_ciphertext(
    pid_t child,
    const struct protected_function_metadata *function,
    struct function_trace_state *function_state)
{
    size_t function_size;

    if (validate_function_size(function, &function_size) != 0) {
        return -1;
    }
    if (function_state->original_ciphertext != NULL) {
        if (function_state->original_ciphertext_size != function_size) {
            fprintf(stderr,
                    "Tamaño de cache de función protegida incoherente\n");
            return -1;
        }
        return 0;
    }

    function_state->original_ciphertext = malloc(function_size);
    if (function_state->original_ciphertext == NULL) {
        fprintf(stderr, "malloc() falló para cache de función protegida\n");
        return -1;
    }
    if (tracee_read_bytes(child,
                          function_state->runtime_address,
                          function_state->original_ciphertext,
                          function_size) != 0) {
        secure_bzero(function_state->original_ciphertext, function_size);
        free(function_state->original_ciphertext);
        function_state->original_ciphertext = NULL;
        return -1;
    }

    function_state->original_ciphertext_size = function_size;
    return 0;
}

static int restore_original_function_ciphertext(
    pid_t child,
    const struct protected_function_metadata *function,
    const struct function_trace_state *function_state)
{
    size_t function_size;

    if (validate_function_size(function, &function_size) != 0) {
        return -1;
    }
    if (function_state->original_ciphertext == NULL ||
        function_state->original_ciphertext_size != function_size) {
        fprintf(stderr, "Cache de función protegida ausente o inválida\n");
        return -1;
    }

    return tracee_write_bytes(child,
                              function_state->runtime_address,
                              function_state->original_ciphertext,
                              function_size);
}

static void release_function_ciphertext_cache(struct trace_state *state)
{
    for (uint32_t i = 0U; i < state->function_count; ++i) {
        struct function_trace_state *function_state = &state->functions[i];

        if (function_state->original_ciphertext != NULL) {
            secure_bzero(function_state->original_ciphertext,
                         function_state->original_ciphertext_size);
            free(function_state->original_ciphertext);
        }
        function_state->original_ciphertext = NULL;
        function_state->original_ciphertext_size = 0U;
    }
}

#ifdef WRAPPER_TEST_HOOKS
static int capture_restored_ciphertext_hash_for_test(
    pid_t child,
    const struct protected_function_metadata *function,
    struct function_trace_state *function_state)
{
    uint8_t *buffer = NULL;
    size_t function_size;
    int rc = -1;

    if (validate_function_size(function, &function_size) != 0) {
        return -1;
    }
    buffer = malloc(function_size);
    if (buffer == NULL) {
        fprintf(stderr, "malloc() falló para auditoría de restauración\n");
        return -1;
    }
    if (tracee_read_bytes(child,
                          function_state->runtime_address,
                          buffer,
                          function_size) != 0) {
        goto cleanup;
    }

    blake2b_hash(buffer,
                 function_size,
                 function_state->last_restored_hash);
    function_state->restore_count++;
    function_state->last_restored_hash_valid = 1;
    rc = 0;

cleanup:
    secure_bzero(buffer, function_size);
    free(buffer);
    return rc;
}

static void write_hash_hex(FILE *stream,
                           const uint8_t hash[WRAPPER_HASH_SIZE])
{
    for (size_t i = 0U; i < WRAPPER_HASH_SIZE; ++i) {
        fprintf(stream, "%02x", hash[i]);
    }
}

static int write_ciphertext_restore_audit_for_test(
    const struct trace_state *state,
    const struct protected_function_metadata *functions)
{
    const char *path = getenv("WRAPPER_TEST_CIPHERTEXT_AUDIT");
    FILE *stream;
    size_t observed_functions = 0U;
    int rc = 0;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    stream = fopen(path, "w");
    if (stream == NULL) {
        fprintf(stderr,
                "No se pudo abrir la auditoría de restauración %s: %s\n",
                path,
                strerror(errno));
        return -1;
    }

    fprintf(stream,
            "function_index,restore_count,observed_hash,expected_hash,match\n");
    for (uint32_t i = 0U; i < state->function_count; ++i) {
        const struct function_trace_state *function_state =
            &state->functions[i];
        int matches;

        if (!function_state->last_restored_hash_valid) {
            continue;
        }
        matches = constant_time_eq(function_state->last_restored_hash,
                                   functions[i].ciphertext_hash,
                                   WRAPPER_HASH_SIZE);
        fprintf(stream,
                "%u,%llu,",
                i,
                (unsigned long long)function_state->restore_count);
        write_hash_hex(stream, function_state->last_restored_hash);
        fputc(',', stream);
        write_hash_hex(stream, functions[i].ciphertext_hash);
        fprintf(stream, ",%d\n", matches);
        observed_functions++;
        if (!matches) {
            rc = -1;
        }
    }
    if (observed_functions == 0U) {
        fprintf(stderr,
                "La auditoría no observó restauraciones de ciphertext\n");
        rc = -1;
    }
    if (fclose(stream) != 0) {
        fprintf(stderr,
                "No se pudo cerrar la auditoría de restauración %s: %s\n",
                path,
                strerror(errno));
        rc = -1;
    }
    return rc;
}
#endif

static int decrypt_remote_function(
    pid_t child,
    const struct protected_function_metadata *function,
    struct function_trace_state *function_state,
    const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    if (verify_remote_function_hash(child,
                                    function,
                                    function_state->runtime_address,
                                    function->ciphertext_hash,
                                    "Hash de función cifrada inválido") != 0) {
        return -1;
    }
    if (cache_original_function_ciphertext(child,
                                           function,
                                           function_state) != 0) {
        return -1;
    }
    if (decrypt_remote_function_bytes(child,
                                      function,
                                      function_state->runtime_address,
                                      jit_key) != 0) {
        return -1;
    }
    if (verify_remote_function_hash(child,
                                    function,
                                    function_state->runtime_address,
                                    function->plaintext_hash,
                                    "Hash de función descifrada inválido") != 0) {
        return -1;
    }
    return 0;
}

static int restore_remote_function(
    pid_t child,
    const struct protected_function_metadata *function,
    const struct function_trace_state *function_state)
{
    if (verify_remote_function_hash(child,
                                    function,
                                    function_state->runtime_address,
                                    function->plaintext_hash,
                                    "Hash de función descifrada inválido") != 0) {
        return -1;
    }
    if (restore_original_function_ciphertext(child,
                                             function,
                                             function_state) != 0) {
        return -1;
    }
    if (verify_remote_function_hash(child,
                                    function,
                                    function_state->runtime_address,
                                    function->ciphertext_hash,
                                    "Hash de función restaurada inválido") != 0) {
        return -1;
    }
    return 0;
}

static int tamper_decrypted_function_for_test(pid_t child,
                                              uint64_t runtime_address)
{
    uint8_t byte;

    if (tracee_read_bytes(child, runtime_address, &byte, sizeof(byte)) != 0) {
        return -1;
    }
    byte ^= 0x01U;
    if (tracee_write_bytes(child, runtime_address, &byte, sizeof(byte)) != 0) {
        return -1;
    }

    fprintf(stderr,
            "WRAPPER_TEST_TAMPER_DECRYPTED: byte de función descifrada "
            "modificado\n");
    return 0;
}

static struct return_breakpoint_state *find_return_breakpoint(
    struct trace_state *state,
    uint64_t return_address)
{
    for (size_t i = 0; i < TRACE_MAX_RETURN_BREAKPOINTS; ++i) {
        struct return_breakpoint_state *candidate =
            &state->return_breakpoints[i];

        if ((candidate->frame_count > 0U ||
             candidate->breakpoint.enabled ||
             candidate->breakpoint.stepping_over) &&
            candidate->address == return_address) {
            return candidate;
        }
    }
    return NULL;
}

static struct return_breakpoint_state *reserve_return_breakpoint(
    struct trace_state *state,
    uint64_t return_address)
{
    struct return_breakpoint_state *available = NULL;

    for (size_t i = 0; i < TRACE_MAX_RETURN_BREAKPOINTS; ++i) {
        struct return_breakpoint_state *candidate =
            &state->return_breakpoints[i];

        if (candidate->frame_count == 0U &&
            !candidate->breakpoint.enabled &&
            !candidate->breakpoint.stepping_over) {
            available = candidate;
            break;
        }
    }

    if (available != NULL) {
        memset(available, 0, sizeof(*available));
        available->address = return_address;
    }
    return available;
}

static int register_function_frame(pid_t child,
                                   struct trace_state *state,
                                   struct function_trace_state *function_state,
                                   uint64_t return_address)
{
    struct return_breakpoint_state *return_state;

    if (function_state->frame_count >= TRACE_MAX_FUNCTION_FRAMES) {
        fprintf(stderr,
                "Demasiadas activaciones concurrentes de función protegida "
                "(%zu/%u)\n",
                function_state->frame_count,
                TRACE_MAX_FUNCTION_FRAMES);
        return -1;
    }

    return_state = find_return_breakpoint(state, return_address);
    if (return_state == NULL) {
        return_state = reserve_return_breakpoint(state, return_address);
    }
    if (return_state == NULL) {
        fprintf(stderr,
                "Demasiadas direcciones de retorno activas en función "
                "protegida\n");
        return -1;
    }

    if (return_state->frame_count == 0U &&
        !return_state->breakpoint.enabled &&
        !return_state->breakpoint.stepping_over &&
        enable_breakpoint(child,
                          &return_state->breakpoint,
                          return_address) != 0) {
        return -1;
    }

    return_state->frame_count++;
    function_state->frames[function_state->frame_count].tid = child;
    function_state->frames[function_state->frame_count].return_address =
        return_address;
    function_state->frame_count++;
    TRACE_DEBUG("trace: register frame TID %ld function 0x%llx return 0x%llx frames=%zu return_frames=%u\n",
                (long)child,
                (unsigned long long)function_state->runtime_address,
                (unsigned long long)return_address,
                function_state->frame_count,
                return_state->frame_count);
    return 0;
}

static int function_frame_exists(
    const struct function_trace_state *function_state,
    pid_t child,
    uint64_t return_address)
{
    for (size_t i = function_state->frame_count; i > 0U; --i) {
        const size_t candidate_index = i - 1U;

        if (function_state->frames[candidate_index].tid == child &&
            function_state->frames[candidate_index].return_address ==
                return_address) {
            return 1;
        }
    }
    return 0;
}

static int unregister_function_frame(struct function_trace_state *function_state,
                                     pid_t child,
                                     uint64_t return_address)
{
    size_t frame_index = TRACE_MAX_FUNCTION_FRAMES;

    for (size_t i = function_state->frame_count; i > 0U; --i) {
        const size_t candidate_index = i - 1U;

        if (function_state->frames[candidate_index].tid == child &&
            function_state->frames[candidate_index].return_address ==
                return_address) {
            frame_index = candidate_index;
            break;
        }
    }

    if (frame_index == TRACE_MAX_FUNCTION_FRAMES) {
        fprintf(stderr,
                "Retorno protegido sin activación asociada al TID %ld\n",
                (long)child);
        return -1;
    }

    for (size_t i = frame_index + 1U; i < function_state->frame_count; ++i) {
        function_state->frames[i - 1U] = function_state->frames[i];
    }
    function_state->frame_count--;
    TRACE_DEBUG("trace: unregister frame TID %ld function 0x%llx return 0x%llx frames=%zu\n",
                (long)child,
                (unsigned long long)function_state->runtime_address,
                (unsigned long long)return_address,
                function_state->frame_count);
    return 0;
}

static int trace_has_active_return_breakpoints(const struct trace_state *state)
{
    for (size_t i = 0; i < TRACE_MAX_RETURN_BREAKPOINTS; ++i) {
        const struct return_breakpoint_state *candidate =
            &state->return_breakpoints[i];

        if (candidate->frame_count > 0U ||
            candidate->breakpoint.enabled ||
            candidate->breakpoint.stepping_over) {
            return 1;
        }
    }
    return 0;
}

static size_t trace_active_function_frame_count(const struct trace_state *state)
{
    size_t active_count = 0;

    for (uint32_t i = 0; i < state->function_count; ++i) {
        active_count += state->functions[i].frame_count;
    }
    return active_count;
}

/* --- Trace stop/event handlers ----------------------------------------- */

static int handle_entry_breakpoint(pid_t child,
                                   struct trace_state *state,
                                   struct software_breakpoint *breakpoint)
{
    struct user_regs_struct regs;
    uint64_t trap_address;

    if (!breakpoint->enabled) {
        return 0;
    }

    if (get_registers(child, &regs) != 0) {
        return -1;
    }

    trap_address = (uint64_t)regs.rip - 1U;
    if (trap_address != breakpoint->address) {
        return 0;
    }

    regs.rip = breakpoint->address;
    if (set_registers(child, &regs) != 0) {
        return -1;
    }
    if (stop_other_tids_for_step(state, child) != 0) {
        return -1;
    }
    if (disable_breakpoint(child, breakpoint) != 0) {
        return -1;
    }

    if (begin_breakpoint_step_over(breakpoint, child, 0) != 0) {
        return -1;
    }
    breakpoint->hit_count++;
    return trace_single_step_child(state, child) == 0 ? 1 : -1;
}

static int handle_function_entry_breakpoint(
    pid_t child,
    struct trace_state *state,
    struct function_trace_state *function_state,
    const struct protected_function_metadata *function,
    const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    struct software_breakpoint *function_breakpoint =
        &function_state->entry_breakpoint;
    struct user_regs_struct regs;
    unsigned long return_address = 0;
    uint64_t trap_address;

    if (!function_breakpoint->enabled && !function_breakpoint->stepping_over) {
        return 0;
    }

    if (get_registers(child, &regs) != 0) {
        return -1;
    }

    trap_address = (uint64_t)regs.rip - 1U;
    if (trap_address != function_breakpoint->address) {
        return 0;
    }

    if (ptrace_read_data_word(child, (uint64_t)regs.rsp, &return_address) != 0) {
        return -1;
    }
    if (return_address == 0UL) {
        fprintf(stderr, "Dirección de retorno nula en función protegida\n");
        return -1;
    }

    if (stop_other_tids_for_step(state, child) != 0) {
        return -1;
    }
    if (state->protected_world_held &&
        state->protected_owner_tid != child) {
        fprintf(stderr,
                "Entrada protegida de TID %ld mientras el TID %ld posee "
                "la sección protegida\n",
                (long)child,
                (long)state->protected_owner_tid);
        return -1;
    }
    if (!state->protected_world_held) {
        state->protected_world_held = 1;
        state->protected_owner_tid = child;
        state->release_protected_world_after_step = 0;
    }
    if (disable_breakpoint(child, function_breakpoint) != 0) {
        return -1;
    }
    if (!function_state->decrypted) {
        if (decrypt_remote_function(child,
                                    function,
                                    function_state,
                                    jit_key) != 0) {
            return -1;
        }
        function_state->decrypted = 1;
#ifdef WRAPPER_EXPOSURE_INSTRUMENTATION
        {
            FILE *exposure_log = exposure_log_stream();

            if (exposure_log != NULL) {
                function_state->exposure_open_ns = monotonic_ns();
                fprintf(exposure_log,
                        "OPEN\t%d\t%u\t%u\t0\n",
                        (int)(function_state - state->functions),
                        count_decrypted(state),
                        state->function_count);
                fflush(exposure_log);
            }
        }
#endif
    }

    if (register_function_frame(child,
                                state,
                                function_state,
                                (uint64_t)return_address) != 0) {
        return -1;
    }

    regs.rip = function_breakpoint->address;
    if (set_registers(child, &regs) != 0) {
        return -1;
    }

    if (begin_breakpoint_step_over(function_breakpoint, child, 1) != 0) {
        return -1;
    }
    function_breakpoint->hit_count++;
    return trace_single_step_child(state, child) == 0 ? 1 : -1;
}

static int restore_function_if_idle(
    pid_t child,
    struct trace_state *state,
    struct function_trace_state *function_state,
    const struct protected_function_metadata *function)
{
    struct software_breakpoint *function_breakpoint =
        &function_state->entry_breakpoint;

    if (function_state->frame_count != 0U) {
        return 0;
    }
    if (function_breakpoint->stepping_over) {
        fprintf(stderr,
                "No se puede restaurar el ciphertext original con una "
                "entrada en single-step\n");
        return -1;
    }
    if (disable_breakpoint(child, function_breakpoint) != 0) {
        return -1;
    }
    if (state->test_tamper_decrypted &&
        !state->test_tamper_decrypted_done) {
        if (tamper_decrypted_function_for_test(
                child,
                function_state->runtime_address) != 0) {
            return -1;
        }
        state->test_tamper_decrypted_done = 1;
    }
    if (restore_remote_function(child,
                                function,
                                function_state) != 0) {
        return -1;
    }
#ifdef WRAPPER_TEST_HOOKS
    if (capture_restored_ciphertext_hash_for_test(child,
                                                  function,
                                                  function_state) != 0) {
        return -1;
    }
#endif
    function_state->decrypted = 0;
#ifdef WRAPPER_EXPOSURE_INSTRUMENTATION
    {
        FILE *exposure_log = exposure_log_stream();

        if (exposure_log != NULL) {
            uint64_t now_ns = monotonic_ns();
            uint64_t window_ns =
                (function_state->exposure_open_ns != 0ULL &&
                 now_ns >= function_state->exposure_open_ns)
                    ? now_ns - function_state->exposure_open_ns
                    : 0ULL;

            fprintf(exposure_log,
                    "CLOSE\t%d\t%u\t%u\t%llu\n",
                    (int)(function_state - state->functions),
                    count_decrypted(state),
                    state->function_count,
                    (unsigned long long)window_ns);
            fflush(exposure_log);
        }
    }
#endif
    if (enable_breakpoint(child,
                          function_breakpoint,
                          function_state->runtime_address) != 0) {
        return -1;
    }
    return 0;
}

static void terminate_tracee(pid_t child)
{
    int status = 0;
    unsigned int idle_attempts = 0;

    (void)kill(child, SIGKILL);
    (void)ptrace(PTRACE_KILL, child, NULL, NULL);
    while (idle_attempts < 100U) {
        pid_t waited = waitpid(-1, &status, __WALL | WNOHANG);

        if (waited >= 0) {
            if (waited == 0) {
                idle_attempts++;
                usleep(10000U);
            } else {
                idle_attempts = 0;
            }
            continue;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
}

static int test_tamper_decrypted_enabled(void)
{
    const char *value = getenv("WRAPPER_TEST_TAMPER_DECRYPTED");

    return value != NULL && strcmp(value, "1") == 0;
}

static void initialize_trace_state(struct trace_state *state,
                                   uint32_t function_count,
                                   pid_t leader_tid)
{
    memset(state, 0, sizeof(*state));
    state->function_count = function_count;
    state->leader_tid = leader_tid;
    state->test_tamper_decrypted = test_tamper_decrypted_enabled();
}

static int install_initial_breakpoints(pid_t child,
                                       const struct resolved_layout *layout,
                                       struct trace_state *state)
{
    if (enable_breakpoint(child,
                          &state->entry_breakpoint,
                          layout->entry_runtime_address) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < layout->function_count; ++i) {
        state->functions[i].runtime_address =
            layout->function_runtime_addresses[i];
        if (enable_breakpoint(child,
                              &state->functions[i].entry_breakpoint,
                              state->functions[i].runtime_address) != 0) {
            return -1;
        }
    }

    return 0;
}

static int handle_exec_stop(pid_t child,
                            const struct wrapper_embedded_blob *blob,
                            struct resolved_layout *layout,
                            struct trace_state *state)
{
    if (resolve_regions_from_maps(child, blob, layout) != 0) {
        return -1;
    }
    if (install_initial_breakpoints(child, layout, state) != 0) {
        return -1;
    }

    return 0;
}

static int handle_clone_stop(pid_t stopped_tid, struct trace_state *state)
{
    unsigned long event_message = 0;
    pid_t new_tid;

    if (ptrace(PTRACE_GETEVENTMSG,
               stopped_tid,
               NULL,
               &event_message) != 0) {
        fprintf(stderr,
                "PTRACE_GETEVENTMSG(CLONE) falló para TID %ld: %s\n",
                (long)stopped_tid,
                strerror(errno));
        return -1;
    }

    new_tid = (pid_t)event_message;
    if (register_traced_tid(state, new_tid, 0, 0) != 0) {
        return -1;
    }

    /*
     * El kernel deja el nuevo hilo en una parada ptrace inicial. Este bucle
     * lo recogerá con waitpid(..., __WALL), configurará sus opciones y lo
     * continuará sin entregar SIGSTOP.
     */
    return trace_continue_child(state, stopped_tid, 0) == 0 ? 1 : -1;
}

static int validate_trace_exit(const struct trace_state *state, int exec_seen)
{
    if (!exec_seen) {
        fprintf(stderr, "El payload terminó antes de completar exec\n");
        return -1;
    }
    if (state->entry_breakpoint.hit_count == 0U) {
        fprintf(stderr, "El breakpoint de entrada no llegó a activarse\n");
        return -1;
    }

    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (state->functions[i].decrypted) {
            fprintf(stderr,
                    "El payload terminó con una función protegida "
                    "descifrada\n");
            return -1;
        }
        if (state->functions[i].frame_count != 0U) {
            fprintf(stderr,
                    "El payload terminó con activaciones protegidas activas\n");
            return -1;
        }
        /*
         * Una funcion protegida que nunca se invoca en esta ejecucion
         * permanece cifrada (hit_count == 0): es el comportamiento JIT
         * correcto, no un error. Los chequeos anteriores (decrypted y
         * frame_count) descartan estados inconsistentes, y los invariantes
         * globales de mas abajo garantizan que el payload se intercepto
         * (breakpoint de entrada y al menos un retorno activados). Exigir
         * cobertura total por funcion solo vale cuando el banco protegido se
         * ejerce entero; no vale para variantes que protegen funciones de
         * ejecucion condicional (p. ej. hilos).
         */
    }
    if (trace_has_active_return_breakpoints(state)) {
        fprintf(stderr, "El payload terminó con retornos protegidos activos\n");
        return -1;
    }
    if (state->function_count > 0U) {
        unsigned int return_hit_count = 0;

        for (size_t j = 0; j < TRACE_MAX_RETURN_BREAKPOINTS; ++j) {
            return_hit_count +=
                state->return_breakpoints[j].breakpoint.hit_count;
        }
        if (return_hit_count == 0U) {
            fprintf(stderr, "Ningún breakpoint de retorno llegó a activarse\n");
            return -1;
        }
    }

    return 0;
}

static int continue_after_step_over(pid_t child,
                                    struct trace_state *state,
                                    struct software_breakpoint *breakpoint)
{
    int reenable_after_step = 0;
    uint64_t breakpoint_address = 0;
    int finished;

    finished = finish_breakpoint_step_over(breakpoint,
                                           child,
                                           &reenable_after_step,
                                           &breakpoint_address);
    if (finished == 0) {
        return 0;
    }
    if (reenable_after_step &&
        enable_breakpoint(child, breakpoint, breakpoint_address) != 0) {
        return -1;
    }
    if (resume_tids_after_step(state, child) != 0) {
        return -1;
    }
    return trace_continue_child(state, child, 0) == 0 ? 1 : -1;
}

static int discard_stale_step_over(pid_t child,
                                   struct software_breakpoint *breakpoint)
{
    int reenable_after_step = 0;
    uint64_t breakpoint_address = 0;
    int was_enabled = breakpoint->enabled;
    int finished;

    finished = finish_breakpoint_step_over(breakpoint,
                                           child,
                                           &reenable_after_step,
                                           &breakpoint_address);
    if (finished == 0) {
        return 0;
    }
    if (reenable_after_step && !was_enabled && !breakpoint->enabled &&
        enable_breakpoint(child, breakpoint, breakpoint_address) != 0) {
        return -1;
    }
    return 0;
}

static int discard_stale_step_overs_for_tid(pid_t child,
                                            struct trace_state *state)
{
    if (discard_stale_step_over(child, &state->entry_breakpoint) != 0) {
        return -1;
    }
    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (discard_stale_step_over(
                child,
                &state->functions[i].entry_breakpoint) != 0) {
            return -1;
        }
    }
    for (size_t j = 0; j < TRACE_MAX_RETURN_BREAKPOINTS; ++j) {
        if (discard_stale_step_over(
                child,
                &state->return_breakpoints[j].breakpoint) != 0) {
            return -1;
        }
    }
    return 0;
}

static int handle_step_over_trap(pid_t child, struct trace_state *state)
{
    int rc;
    uint64_t trap_address = 0;

    if (tid_stopped_at_enabled_breakpoint(state, child, &trap_address)) {
        TRACE_DEBUG("trace: TID %ld reached breakpoint 0x%llx while stale step-over was pending\n",
                    (long)child,
                    (unsigned long long)trap_address);
        return discard_stale_step_overs_for_tid(child, state);
    }

    rc = continue_after_step_over(child, state, &state->entry_breakpoint);
    if (rc != 0) {
        return rc;
    }

    for (uint32_t i = 0; i < state->function_count; ++i) {
        rc = continue_after_step_over(
            child,
            state,
            &state->functions[i].entry_breakpoint);
        if (rc != 0) {
            return rc;
        }
    }

    for (size_t j = 0; j < TRACE_MAX_RETURN_BREAKPOINTS; ++j) {
        rc = continue_after_step_over(
            child,
            state,
            &state->return_breakpoints[j].breakpoint);
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

static int handle_function_return_traps(
    pid_t child,
    struct trace_state *state,
    const struct protected_function_metadata *functions)
{
    struct user_regs_struct regs;
    struct return_breakpoint_state *return_state;
    struct software_breakpoint *return_breakpoint;
    uint64_t trap_address;
    uint32_t matched_function = state->function_count;

    if (get_registers(child, &regs) != 0) {
        return -1;
    }

    trap_address = (uint64_t)regs.rip - 1U;
    return_state = find_return_breakpoint(state, trap_address);
    if (return_state == NULL ||
        (!return_state->breakpoint.enabled &&
         !return_state->breakpoint.stepping_over)) {
        return 0;
    }

    return_breakpoint = &return_state->breakpoint;
    TRACE_DEBUG("trace: return trap TID %ld address 0x%llx return_frames=%u\n",
                (long)child,
                (unsigned long long)trap_address,
                return_state->frame_count);
    if (stop_other_tids_for_step(state, child) != 0) {
        return -1;
    }
    regs.rip = return_breakpoint->address;
    if (set_registers(child, &regs) != 0) {
        return -1;
    }
    if (disable_breakpoint(child, return_breakpoint) != 0) {
        return -1;
    }

    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (function_frame_exists(&state->functions[i],
                                  child,
                                  trap_address)) {
            matched_function = i;
            break;
        }
    }

    if (matched_function != state->function_count) {
        struct function_trace_state *function_state =
            &state->functions[matched_function];

        if (!function_state->decrypted) {
            fprintf(stderr,
                    "Retorno de función protegida sin descifrado activo\n");
            return -1;
        }
        if (unregister_function_frame(function_state,
                                      child,
                                      trap_address) != 0) {
            return -1;
        }
        if (return_state->frame_count == 0U) {
            fprintf(stderr,
                    "Retorno protegido sin contador global activo\n");
            return -1;
        }
        return_state->frame_count--;
        return_breakpoint->hit_count++;

        if (restore_function_if_idle(child,
                                     state,
                                     function_state,
                                     &functions[matched_function]) != 0) {
            return -1;
        }
        if (trace_active_function_frame_count(state) == 0U) {
            state->release_protected_world_after_step = 1;
        }
    } else {
        TRACE_DEBUG("trace: return trap TID %ld address 0x%llx without matching function frame\n",
                    (long)child,
                    (unsigned long long)trap_address);
    }

    if (begin_breakpoint_step_over(return_breakpoint,
                                   child,
                                   return_state->frame_count > 0U) != 0) {
        return -1;
    }
    return trace_single_step_child(state, child) == 0 ? 1 : -1;
}

static int handle_function_entry_traps(
    pid_t child,
    struct trace_state *state,
    const struct protected_function_metadata *functions,
    const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    int rc;

    for (uint32_t i = 0; i < state->function_count; ++i) {
        rc = handle_function_entry_breakpoint(child,
                                              state,
                                              &state->functions[i],
                                              &functions[i],
                                              jit_key);
        if (rc != 0) {
            return rc;
        }
    }

    return 0;
}

static int handle_breakpoint_trap(
    pid_t child,
    struct trace_state *state,
    const struct protected_function_metadata *functions,
    const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    int rc;

    rc = handle_step_over_trap(child, state);
    if (rc != 0) {
        return rc;
    }

    rc = handle_function_return_traps(child, state, functions);
    if (rc != 0) {
        return rc;
    }

    rc = handle_function_entry_traps(child, state, functions, jit_key);
    if (rc != 0) {
        return rc;
    }

    rc = handle_entry_breakpoint(child, state, &state->entry_breakpoint);
    if (rc != 0) {
        return rc;
    }

    return 0;
}

static int breakpoint_is_stepping_tid(const struct software_breakpoint *breakpoint,
                                      pid_t tid)
{
    return breakpoint_has_stepping_tid(breakpoint, tid);
}

static int tid_has_step_over(const struct trace_state *state, pid_t tid)
{
    if (breakpoint_is_stepping_tid(&state->entry_breakpoint, tid)) {
        return 1;
    }

    for (uint32_t i = 0; i < state->function_count; ++i) {
        if (breakpoint_is_stepping_tid(
                &state->functions[i].entry_breakpoint,
                tid)) {
            return 1;
        }
    }
    for (size_t j = 0; j < TRACE_MAX_RETURN_BREAKPOINTS; ++j) {
        if (breakpoint_is_stepping_tid(
                &state->return_breakpoints[j].breakpoint,
                tid)) {
            return 1;
        }
    }

    return 0;
}

static int trace_loop(pid_t child,
                      const struct wrapper_embedded_blob *blob,
                      const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    const struct protected_metadata_header *metadata = blob_metadata_header(blob);
    const struct protected_function_metadata *functions =
        blob_metadata_functions(blob);
    struct resolved_layout layout;
    struct trace_state state;
    int exec_seen = 0;
    int rc = -1;

    memset(&layout, 0, sizeof(layout));
    initialize_trace_state(&state, metadata->function_count, child);
    if (register_traced_tid(&state, child, 1, 1) != 0) {
        goto cleanup;
    }

    if (trace_continue_child(&state, child, 0) != 0) {
        goto cleanup;
    }

    for (;;) {
        int status = 0;
        int stop_signal;
        unsigned int event;
        pid_t stopped_tid;

        if (state.world_stopped_for_step || state.protected_world_held ||
            !take_deferred_status(&state, &stopped_tid, &status)) {
            stopped_tid = waitpid(-1, &status, __WALL);
            if (stopped_tid < 0) {
                if (errno == EINTR) {
                    continue;
                }
                fprintf(stderr, "waitpid() falló: %s\n", strerror(errno));
                goto cleanup;
            }
        }

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            unregister_traced_tid(&state, stopped_tid);
            if (stopped_tid == state.leader_tid || state.tid_count == 0U) {
                if (validate_trace_exit(&state, exec_seen) != 0) {
                    goto cleanup;
                }
#ifdef WRAPPER_TEST_HOOKS
                if (write_ciphertext_restore_audit_for_test(&state,
                                                            functions) != 0) {
                    goto cleanup;
                }
#endif
                rc = exit_code;
                goto cleanup;
            }
            continue;
        }

        if (WIFSIGNALED(status)) {
            int term_signal = WTERMSIG(status);
            unregister_traced_tid(&state, stopped_tid);
            fprintf(stderr,
                    "El TID %ld del payload terminó por señal %d\n",
                    (long)stopped_tid,
                    term_signal);
            rc = 128 + term_signal;
            goto cleanup;
        }

        if (!WIFSTOPPED(status)) {
            continue;
        }
        if (mark_tid_stopped(&state, stopped_tid) != 0) {
            terminate_tracee(child);
            goto cleanup;
        }

        stop_signal = WSTOPSIG(status);
        event = (unsigned int)status >> 16;

        if (find_traced_tid(&state, stopped_tid) == NULL &&
            register_traced_tid(&state, stopped_tid, 0, 1) != 0) {
            terminate_tracee(child);
            goto cleanup;
        }

        if (stop_signal == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            if (handle_exec_stop(stopped_tid, blob, &layout, &state) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            exec_seen = 1;
            if (trace_continue_child(&state, stopped_tid, 0) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            continue;
        }

        if (stop_signal == SIGTRAP && event == PTRACE_EVENT_CLONE) {
            if (handle_clone_stop(stopped_tid, &state) < 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            continue;
        }

        if (stop_signal == SIGTRAP && event != 0U) {
            if (trace_continue_child(&state, stopped_tid, 0) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            continue;
        }

        if (stop_signal == SIGSTOP) {
            if (configure_traced_tid_if_needed(&state, stopped_tid) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            if (trace_continue_child(&state, stopped_tid, 0) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            continue;
        }

        if (configure_traced_tid_if_needed(&state, stopped_tid) != 0) {
            terminate_tracee(child);
            goto cleanup;
        }

        if (stop_signal == SIGTRAP) {
            int trap_rc = handle_breakpoint_trap(stopped_tid,
                                                 &state,
                                                 functions,
                                                 jit_key);
            if (trap_rc < 0) {
                terminate_tracee(child);
                goto cleanup;
            }
            if (trap_rc == 0) {
                if (trace_continue_child(&state, stopped_tid, SIGTRAP) != 0) {
                    terminate_tracee(child);
                    goto cleanup;
                }
            }
            continue;
        } else {
            if (tid_has_step_over(&state, stopped_tid)) {
                if (trace_single_step_child_with_signal(&state,
                                                        stopped_tid,
                                                        stop_signal) != 0) {
                    terminate_tracee(child);
                    goto cleanup;
                }
                continue;
            }
            if (trace_continue_child(&state, stopped_tid, stop_signal) != 0) {
                terminate_tracee(child);
                goto cleanup;
            }
        }
    }

cleanup:
    release_function_ciphertext_cache(&state);
    return rc;
}

#ifdef WRAPPER_ANTIDEBUG_COTRACE
#include <sys/prctl.h>

/* --- Endurecimiento opcional: co-traza anti-depuración del padre ---------- */
/*
 * El motor runtime (proceso padre) traza al payload, pero su propio slot de
 * tracer queda libre: un depurador externo podría adjuntarse al padre y volcar
 * la clave de sesión tras su reconstrucción. Esta capa forka un guardián
 * ligero y sin clave que ocupa el slot de tracer del padre mediante
 * PTRACE_SEIZE. Con ello (1) el enganche tardío (gdb -p <padre>) falla al estar
 * el slot ocupado, y (2) si el proceso ya nace bajo un depurador
 * (gdb ./wrapper), el SEIZE del guardián falla y el padre aborta (fail-close)
 * antes de reconstruir la clave. Es protección de coste, no de imposibilidad:
 * bajo el modelo MATE el código del guardián viaja en claro en el motor y es
 * susceptible de parcheo estático.
 */

static int cotrace_read_full(int fd, void *buffer, size_t len)
{
    uint8_t *cursor = buffer;
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = read(fd, cursor + offset, len - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        offset += (size_t)n;
    }
    return 0;
}

static int cotrace_write_full(int fd, const void *buffer, size_t len)
{
    const uint8_t *cursor = buffer;
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = write(fd, cursor + offset, len - offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)n;
    }
    return 0;
}

/*
 * Bucle transparente del guardián: mantiene ocupado el slot de tracer del padre
 * y reinyecta cualquier señal que el padre reciba, sin alterar su
 * comportamiento observable. Termina cuando el padre finaliza. El padre rara
 * vez recibe señales (permanece en waitpid sobre el payload), por lo que el
 * bucle bloquea casi siempre en waitpid sin coste apreciable.
 */
static void cotrace_guardian_loop(pid_t parent)
{
    for (;;) {
        int status = 0;
        pid_t waited = waitpid(parent, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }
        int signal_number = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;
        if (event == (unsigned int)PTRACE_EVENT_STOP) {
            /* group-stop bajo PTRACE_SEIZE: no se reinyecta señal; se escucha
             * hasta que el grupo se reanuda. */
            ptrace(PTRACE_LISTEN, parent, NULL, NULL);
            continue;
        }
        if (event != 0U) {
            /* Cualquier otro evento ptrace: continuar sin reinyectar. */
            signal_number = 0;
        }
        ptrace(PTRACE_CONT, parent, NULL, (void *)(long)signal_number);
    }
}

int wrapper_antidebug_install_cotrace(void)
{
    int ready_pipe[2];
    int result_pipe[2];
    pid_t guardian;
    uint8_t token;

    if (pipe(ready_pipe) != 0) {
        return 0; /* fail-open ante fallo de recursos, no de depuración */
    }
    if (pipe(result_pipe) != 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return 0;
    }

    guardian = fork();
    if (guardian < 0) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        close(result_pipe[0]);
        close(result_pipe[1]);
        return 0; /* fail-open: no se pudo forkar el guardián */
    }

    if (guardian == 0) {
        /* --- Proceso guardián: sin clave, superficie mínima --- */
        pid_t parent = getppid();
        close(ready_pipe[1]);
        close(result_pipe[0]);
        /* Espera a que el padre autorice la traza (PR_SET_PTRACER). */
        if (cotrace_read_full(ready_pipe[0], &token, 1) != 0) {
            _exit(0);
        }
        close(ready_pipe[0]);
        token = (ptrace(PTRACE_SEIZE, parent, NULL, (void *)0L) == 0) ? 1U : 0U;
        (void)cotrace_write_full(result_pipe[1], &token, 1);
        close(result_pipe[1]);
        if (token == 0U) {
            _exit(0); /* no se pudo ocupar el slot: tracer externo presente */
        }
        cotrace_guardian_loop(parent);
        _exit(0);
    }

    /* --- Proceso padre (motor) --- */
    close(ready_pipe[0]);
    close(result_pipe[1]);
    /* Autoriza a este guardián concreto a trazar al padre bajo Yama LSM. */
    (void)prctl(PR_SET_PTRACER, (unsigned long)guardian, 0UL, 0UL, 0UL);
    token = 1U;
    if (cotrace_write_full(ready_pipe[1], &token, 1) != 0) {
        close(ready_pipe[1]);
        close(result_pipe[0]);
        return 0; /* fail-open ante fallo de coordinación */
    }
    close(ready_pipe[1]);
    if (cotrace_read_full(result_pipe[0], &token, 1) != 0) {
        close(result_pipe[0]);
        return 0; /* fail-open: el guardián no reportó */
    }
    close(result_pipe[0]);
    if (token == 0U) {
        fprintf(stderr,
                "Depurador detectado sobre el motor runtime: ejecución "
                "abortada\n");
        return -1; /* fail-close antes de reconstruir la clave */
    }
    return 0;
}
#endif /* WRAPPER_ANTIDEBUG_COTRACE */

int wrapper_trace_exec_memfd(int payload_fd,
                             int argc,
                             char **argv,
                             const struct wrapper_embedded_blob *blob,
                             const uint8_t jit_key[WRAPPER_KEY_SIZE])
{
    char **child_argv = NULL;
    pid_t child;
    int status = 0;
    int rc = -1;

    child_argv = build_child_argv(argc, argv);
    if (child_argv == NULL) {
        fprintf(stderr, "calloc() falló\n");
        return -1;
    }

    child = fork();
    if (child < 0) {
        fprintf(stderr, "fork() falló: %s\n", strerror(errno));
        goto cleanup;
    }

    if (child == 0) {
        raise(SIGSTOP);
        fexecve(payload_fd, child_argv, environ);
        fprintf(stderr, "fexecve falló: %s\n", strerror(errno));
        _exit(127);
    }

    for (;;) {
        if (waitpid(child, &status, WUNTRACED) >= 0) {
            break;
        }
        if (errno != EINTR) {
            fprintf(stderr, "waitpid() inicial falló: %s\n", strerror(errno));
            goto cleanup;
        }
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        fprintf(stderr, "El tracee no alcanzó el SIGSTOP inicial\n");
        goto cleanup;
    }

    if (seize_tracer(child) != 0) {
        terminate_tracee(child);
        goto cleanup;
    }

    rc = trace_loop(child, blob, jit_key);

cleanup:
    free(child_argv);
    return rc;
}
