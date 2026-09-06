#include <pthread.h>
#ifdef THREAD_DEPENDENCY_TEST
#include <sched.h>
#include <stdatomic.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <string.h>
#ifdef H1_REGRESSION
#include <stdlib.h>
#endif

__attribute__((noinline, used)) int protected_demo_function(int value);
__attribute__((noinline, used)) int protected_second_function(int value);
__attribute__((noinline, used)) int protected_recursive_function(int value);
__attribute__((noinline, used)) int protected_signal_function(int value);
#ifdef NESTED_EXPOSURE_TEST
static __attribute__((noinline, used)) int protected_nested_leaf(int value);
static __attribute__((noinline, used)) int protected_nested_parent(int value);
#endif
#ifdef THREAD_DEPENDENCY_TEST
static __attribute__((noinline, used)) int
protected_thread_dependency_waiter(int value);
#endif

int (*volatile protected_demo_function_ptr)(int) = protected_demo_function;
int (*volatile protected_second_function_ptr)(int) = protected_second_function;
int (*volatile protected_recursive_function_ptr)(int) =
    protected_recursive_function;
int (*volatile protected_signal_function_ptr)(int) = protected_signal_function;

static volatile sig_atomic_t signal_hits = 0;

struct worker_result {
    int id;
    int ok;
    int total;
};

struct stress_context {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int ready;
    int release;
    int thread_count;
};

struct stress_worker_arg {
    struct stress_context *context;
    struct worker_result *result;
};

static void handle_sigusr1(int signal_number)
{
    (void)signal_number;
    signal_hits++;
}

__attribute__((noinline, used)) int protected_demo_function(int value)
{
    volatile int adjusted = value * 7;
    volatile int scratch = 0;

    for (int i = 0; i < 16; ++i) {
        scratch += (value + i) & 3;
    }
    (void)scratch;
    return adjusted + 11;
}

__attribute__((noinline, used)) int protected_second_function(int value)
{
    volatile int adjusted = value + 5;
    volatile int mixed = adjusted * adjusted;
    volatile int scratch = 0;

    for (int i = 0; i < 16; ++i) {
        scratch ^= adjusted + i;
    }
    (void)scratch;
    return mixed - value;
}

__attribute__((noinline, used)) int protected_recursive_function(int value)
{
    volatile int current = value;

    if (current <= 0) {
        return 1;
    }
    return current + protected_recursive_function_ptr(current - 1);
}

__attribute__((noinline, used)) int protected_signal_function(int value)
{
    sig_atomic_t before_signal = signal_hits;
    volatile int scratch = value;

    if (raise(SIGUSR1) != 0) {
        return -1;
    }
    for (int i = 0; i < 16; ++i) {
        scratch += i & 1;
    }
    (void)scratch;
    return signal_hits > before_signal ? value + 31 : value - 31;
}

#ifdef NESTED_EXPOSURE_TEST
static __attribute__((noinline, used)) int protected_nested_leaf(int value)
{
    volatile int adjusted = value * 3;

    return adjusted + 1;
}

static __attribute__((noinline, used)) int protected_nested_parent(int value)
{
    volatile int leaf_value = protected_nested_leaf(value);

    return leaf_value + 7;
}
#endif

#ifdef THREAD_DEPENDENCY_TEST
static atomic_int dependency_waiter_entered;
static atomic_int dependency_ready;

static void *dependency_producer(void *arg)
{
    (void)arg;
    while (atomic_load_explicit(&dependency_waiter_entered,
                                memory_order_acquire) == 0) {
        sched_yield();
    }
    atomic_store_explicit(&dependency_ready, 1, memory_order_release);
    return NULL;
}

static __attribute__((noinline, used)) int
protected_thread_dependency_waiter(int value)
{
    atomic_store_explicit(&dependency_waiter_entered, 1, memory_order_release);
    fprintf(stderr, "THREAD-DEPENDENCY-WAITER-ENTERED\n");
    fflush(stderr);
    while (atomic_load_explicit(&dependency_ready, memory_order_acquire) == 0) {
        sched_yield();
    }
    return value + 1;
}

static int run_thread_dependency_case(void)
{
    pthread_t producer;
    int observed;

    atomic_store_explicit(&dependency_waiter_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&dependency_ready, 0, memory_order_relaxed);
    if (pthread_create(&producer, NULL, dependency_producer, NULL) != 0) {
        return 0;
    }
    observed = protected_thread_dependency_waiter(41);
    if (pthread_join(producer, NULL) != 0) {
        return 0;
    }
    return observed == 42;
}
#endif

static int expected_demo_function(int value)
{
    return value * 7 + 11;
}

static int expected_second_function(int value)
{
    int adjusted = value + 5;

    return adjusted * adjusted - value;
}

static int expected_recursive_function(int value)
{
    int total = 1;

    for (int current = 1; current <= value; ++current) {
        total += current;
    }
    return total;
}

static int expected_signal_function(int value)
{
    return value + 31;
}

static int expected_protected_sequence(int seed)
{
    return expected_demo_function(seed) +
           expected_second_function(seed + 2) +
           expected_recursive_function(3);
}

static int run_protected_sequence(int seed)
{
    int demo_value;
    int second_value;
    int recursive_value;

    demo_value = protected_demo_function_ptr(seed);
    second_value = protected_second_function_ptr(seed + 2);
    recursive_value = protected_recursive_function_ptr(3);

    return demo_value + second_value + recursive_value;
}

static void *thread_worker(void *arg)
{
    struct worker_result *result = (struct worker_result *)arg;

    result->ok = 1;
    result->total = 0;
    for (int iteration = 0; iteration < 1; ++iteration) {
        int seed = result->id * 10 + iteration + 1;
        int observed = run_protected_sequence(seed);
        int expected = expected_protected_sequence(seed);

        result->total += observed;
        if (observed != expected) {
            result->ok = 0;
        }
    }

    return NULL;
}

static int run_threaded_protected_calls(void)
{
    enum { THREAD_COUNT = 2 };
    struct worker_result results[THREAD_COUNT];
    int ok = 1;

    for (int i = 0; i < THREAD_COUNT; ++i) {
        pthread_t thread;

        results[i].id = i;
        results[i].ok = 0;
        results[i].total = 0;
        if (pthread_create(&thread, NULL, thread_worker, &results[i]) !=
            0) {
            ok = 0;
            break;
        }
        if (pthread_join(thread, NULL) != 0) {
            ok = 0;
        }
        if (!results[i].ok) {
            ok = 0;
        }
    }

    return ok;
}

static int wait_for_stress_release(struct stress_context *context)
{
    if (pthread_mutex_lock(&context->mutex) != 0) {
        return 0;
    }

    context->ready++;
    if (context->ready == context->thread_count) {
        pthread_cond_broadcast(&context->cond);
    }
    while (!context->release) {
        if (pthread_cond_wait(&context->cond, &context->mutex) != 0) {
            pthread_mutex_unlock(&context->mutex);
            return 0;
        }
    }

    pthread_mutex_unlock(&context->mutex);
    return 1;
}

static void *thread_stress_worker(void *arg)
{
    enum { STRESS_ITERATIONS = 1 };
    struct stress_worker_arg *worker_arg = (struct stress_worker_arg *)arg;
    struct worker_result *result = worker_arg->result;

    result->ok = 1;
    result->total = 0;
    if (!wait_for_stress_release(worker_arg->context)) {
        result->ok = 0;
        return NULL;
    }

    for (int iteration = 0; iteration < STRESS_ITERATIONS; ++iteration) {
        int seed = result->id * 100 + iteration + 1;
        int observed = protected_demo_function_ptr(seed);
        int expected = expected_demo_function(seed);

        result->total += observed;
        if (observed != expected) {
            result->ok = 0;
        }
    }

    return NULL;
}

static int release_stress_workers(struct stress_context *context)
{
    int ok = 1;

    if (pthread_mutex_lock(&context->mutex) != 0) {
        return 0;
    }
    context->release = 1;
    if (pthread_cond_broadcast(&context->cond) != 0) {
        ok = 0;
    }
    if (pthread_mutex_unlock(&context->mutex) != 0) {
        ok = 0;
    }

    return ok;
}

static int wait_until_stress_workers_ready(struct stress_context *context)
{
    int ok = 1;

    if (pthread_mutex_lock(&context->mutex) != 0) {
        return 0;
    }
    while (context->ready < context->thread_count) {
        if (pthread_cond_wait(&context->cond, &context->mutex) != 0) {
            ok = 0;
            break;
        }
    }
    if (pthread_mutex_unlock(&context->mutex) != 0) {
        ok = 0;
    }

    return ok;
}

static int run_threaded_stress_protected_calls(void)
{
    enum { THREAD_COUNT = 4 };
    struct stress_context context;
    struct stress_worker_arg args[THREAD_COUNT];
    struct worker_result results[THREAD_COUNT];
    pthread_t threads[THREAD_COUNT];
    int created = 0;
    int ok = 1;

    memset(&context, 0, sizeof(context));
    context.thread_count = THREAD_COUNT;
    if (pthread_mutex_init(&context.mutex, NULL) != 0 ||
        pthread_cond_init(&context.cond, NULL) != 0) {
        return 0;
    }

    for (int i = 0; i < THREAD_COUNT; ++i) {
        results[i].id = i;
        results[i].ok = 0;
        results[i].total = 0;
        args[i].context = &context;
        args[i].result = &results[i];
        if (pthread_create(&threads[i], NULL, thread_stress_worker, &args[i]) !=
            0) {
            ok = 0;
            break;
        }
        created++;
    }

    if (ok && !wait_until_stress_workers_ready(&context)) {
        ok = 0;
    }
    if (!release_stress_workers(&context)) {
        ok = 0;
    }

    for (int i = 0; i < created; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            ok = 0;
        }
    }
    for (int i = 0; i < created; ++i) {
        if (!results[i].ok) {
            ok = 0;
        }
    }

    pthread_cond_destroy(&context.cond);
    pthread_mutex_destroy(&context.mutex);
    return ok;
}

static int run_signal_protected_call(int seed)
{
    int observed = protected_signal_function_ptr(seed);

    return observed == expected_signal_function(seed);
}

int main(int argc, char **argv)
{
    int protected_value;
    int second_value;
    int recursive_value;
    int signal_ok;
    int threaded_ok = 1;
    int threaded_stress_ok = 1;
    int run_threads = argc > 1 && strcmp(argv[1], "threaded-demo") == 0;
    int run_thread_stress = argc > 1 && strcmp(argv[1], "threaded-stress") == 0;

    if (signal(SIGUSR1, handle_sigusr1) == SIG_ERR) {
        fprintf(stderr, "No se pudo instalar el manejador de SIGUSR1\n");
        return 1;
    }

#ifdef NESTED_EXPOSURE_TEST
    if (argc >= 2 && strcmp(argv[1], "exposure-identity") == 0) {
        int observed = protected_demo_function_ptr(2);

        if (observed != 25) {
            return 1;
        }
#if defined(__PIE__) || defined(__pie__)
        printf("exposure payload binary=pie\n");
#else
        printf("exposure payload binary=nopie\n");
#endif
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "ordinary-protected") == 0) {
        int observed = protected_demo_function_ptr(2);

        printf("ordinary protected result=%d\n", observed);
        return observed == 25 ? 0 : 1;
    }
    if (argc >= 2 && strcmp(argv[1], "nested-protected") == 0) {
        int observed = protected_nested_parent(5);

        printf("nested protected result=%d\n", observed);
        return observed == 23 ? 0 : 1;
    }
#endif

#ifdef THREAD_DEPENDENCY_TEST
    if (argc >= 2 && strcmp(argv[1], "thread-dependency") == 0) {
        int ok = run_thread_dependency_case();

        printf("thread dependency protected call: %s\n", ok ? "OK" : "FAIL");
        return ok ? 0 : 1;
    }
#endif

#ifdef H1_REGRESSION
    /*
     * Modo de regresión (evaluación §5.3): ejecuta un número controlado de
     * activaciones de una función protegida para aislar el coste por activación
     * del coste fijo de arranque. Fuera del payload de producción por defecto.
     */
    if (argc >= 3 && strcmp(argv[1], "activations") == 0) {
        long activation_count = strtol(argv[2], NULL, 10);
        volatile int accumulator = 0;

        for (long i = 0; i < activation_count; ++i) {
            accumulator += protected_demo_function_ptr((int)i);
        }
        printf("activations=%ld acc=%d\n", activation_count, accumulator);
        return 0;
    }
    /*
     * Modo de ciclo (evaluación §5.5, evidencia de minimización): recorre en
     * rotación tres funciones protegidas distintas para que, en cualquier
     * instante, a lo sumo una permanezca descifrada. Sirve de carga de larga
     * vida al observar la memoria del payload desde un proceso privilegiado.
     * Fuera del payload de producción por defecto.
     */
    if (argc >= 3 && strcmp(argv[1], "activations-cycle") == 0) {
        long activation_count = strtol(argv[2], NULL, 10);
        volatile int accumulator = 0;

        for (long i = 0; i < activation_count; ++i) {
            switch (i % 3) {
            case 0:
                accumulator += protected_demo_function_ptr((int)(i & 0x7f));
                break;
            case 1:
                accumulator += protected_second_function_ptr((int)(i & 0x7f));
                break;
            default:
                accumulator += protected_recursive_function_ptr((int)(i % 7));
                break;
            }
        }
        printf("activations-cycle=%ld acc=%d\n", activation_count, accumulator);
        return 0;
    }
#endif

    protected_value = protected_demo_function_ptr(argc);
    second_value = protected_second_function_ptr(argc + 2);
    recursive_value = protected_recursive_function_ptr(3);
    signal_ok = run_signal_protected_call(argc + 4);

    if (run_threads) {
        threaded_ok = run_threaded_protected_calls();
    }
    if (run_thread_stress) {
        threaded_stress_ok = run_threaded_stress_protected_calls();
    }

    printf("Hola desde el payload ELF embebido.\n");
    printf("argc = %d\n", argc);
    printf("protected_demo_function(argc) = %d\n", protected_value);
    printf("protected_second_function(argc + 2) = %d\n", second_value);
    printf("protected_recursive_function(3) = %d\n", recursive_value);
    printf("signal protected call: %s\n", signal_ok ? "OK" : "FAIL");
    printf("threaded protected calls: %s\n",
           threaded_ok ? (run_threads ? "OK" : "SKIPPED") : "FAIL");
    printf("threaded stress protected calls: %s\n",
           threaded_stress_ok ? (run_thread_stress ? "OK" : "SKIPPED") : "FAIL");

    for (int i = 0; i < argc; ++i) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    return signal_ok && threaded_ok && threaded_stress_ok ? 0 : 1;
}
