#ifndef BENCH_HARNESS_H
#define BENCH_HARNESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef WRAPPER_BENCH

#include <time.h>

#ifndef BENCH_MAX_SAMPLES
#define BENCH_MAX_SAMPLES 100000
#endif

void bench_init(void);
void bench_record(const char *op, size_t size_bytes, uint64_t latency_ns);
void bench_dump_csv(void);

static inline uint64_t bench_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#define BENCH_BEGIN(varname) uint64_t varname = bench_now_ns()
#define BENCH_END(varname, op_name, size_bytes) \
    bench_record((op_name), (size_t)(size_bytes), bench_now_ns() - (varname))

#else  /* WRAPPER_BENCH not defined */

#define BENCH_BEGIN(varname) ((void)0)
#define BENCH_END(varname, op_name, size_bytes) ((void)0)

static inline void bench_init(void) {}
static inline void bench_dump_csv(void) {}

#endif /* WRAPPER_BENCH */

#endif /* BENCH_HARNESS_H */
