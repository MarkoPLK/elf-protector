#ifdef WRAPPER_BENCH

#include "bench_harness.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    const char *op;
    size_t size_bytes;
    uint64_t latency_ns;
} bench_sample_t;

static bench_sample_t g_samples[BENCH_MAX_SAMPLES];
static size_t g_sample_count = 0U;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;
static int g_atexit_registered = 0;

static void bench_atexit_cb(void)
{
    bench_dump_csv();
}

void bench_init(void)
{
    pthread_mutex_lock(&g_mutex);
    if (!g_atexit_registered) {
        atexit(bench_atexit_cb);
        g_atexit_registered = 1;
    }
    g_initialized = 1;
    g_sample_count = 0U;
    pthread_mutex_unlock(&g_mutex);
}

void bench_record(const char *op, size_t size_bytes, uint64_t latency_ns)
{
    pthread_mutex_lock(&g_mutex);
    if (!g_initialized) {
        if (!g_atexit_registered) {
            atexit(bench_atexit_cb);
            g_atexit_registered = 1;
        }
        g_initialized = 1;
    }
    if (g_sample_count < BENCH_MAX_SAMPLES) {
        g_samples[g_sample_count].op = op;
        g_samples[g_sample_count].size_bytes = size_bytes;
        g_samples[g_sample_count].latency_ns = latency_ns;
        g_sample_count++;
    }
    pthread_mutex_unlock(&g_mutex);
}

void bench_dump_csv(void)
{
    char path[128];
    const char *out_dir = getenv("WRAPPER_BENCH_OUT");
    if (out_dir == NULL || out_dir[0] == '\0') {
        out_dir = "/tmp";
    }
    snprintf(path, sizeof(path), "%s/bench_runtime_%d.csv", out_dir, (int)getpid());

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        fprintf(stderr, "bench_dump_csv: no se pudo abrir %s\n", path);
        return;
    }

    pthread_mutex_lock(&g_mutex);
    fprintf(f, "op,size_bytes,latency_ns\n");
    for (size_t i = 0; i < g_sample_count; ++i) {
        fprintf(f, "%s,%zu,%lu\n",
                g_samples[i].op,
                g_samples[i].size_bytes,
                (unsigned long)g_samples[i].latency_ns);
    }
    size_t n = g_sample_count;
    pthread_mutex_unlock(&g_mutex);

    fclose(f);
    fprintf(stderr, "bench_dump_csv: %zu muestras escritas en %s\n", n, path);
}

#else

/* WRAPPER_BENCH not defined: this translation unit produces no code. */
typedef int bench_harness_disabled_dummy_t;

#endif /* WRAPPER_BENCH */
