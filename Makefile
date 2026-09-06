CC := cc
# libsodium enlazado estáticamente (vendorizado en third_party/): el AEAD
# ChaCha20-Poly1305 IETF y el hash BLAKE2b los provee la biblioteca auditada,
# no una implementación propia. El .a se sitúa tras las fuentes en el enlace.
SODIUM_DIR := third_party/libsodium
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude -I$(SODIUM_DIR)/include
LDFLAGS := $(SODIUM_DIR)/lib/libsodium.a
PTHREAD_FLAGS := -pthread

# Instrumentación opcional de la ventana de exposición (evaluación §5.5). Fuera
# del binario de producción por defecto; compilar con `make EXPOSURE=1 ...` para
# incluir el gancho activable en tiempo de ejecución con WRAPPER_EXPOSURE_LOG.
EXPOSURE ?= 0
ifeq ($(EXPOSURE),1)
CFLAGS += -DWRAPPER_EXPOSURE_INSTRUMENTATION
endif

# Variantes de caracterización, siempre fuera de la build de producción.
NESTED_EXPOSURE_TEST ?= 0
ifeq ($(NESTED_EXPOSURE_TEST),1)
CFLAGS += -DNESTED_EXPOSURE_TEST
endif

THREAD_DEPENDENCY_TEST ?= 0
ifeq ($(THREAD_DEPENDENCY_TEST),1)
CFLAGS += -DTHREAD_DEPENDENCY_TEST
endif

# Capa de endurecimiento anti-depuración por co-traza del proceso padre (§4.3):
# un guardián ligero ocupa el slot de tracer del motor para cerrar el enganche
# tardío al padre y detectar el lanzamiento bajo depurador. Fuera del binario de
# producción por defecto; compilar con `make ANTIDEBUG=1 ...` para incluirla. No
# forma parte de las medidas del Capítulo 5.
ANTIDEBUG ?= 0
ifeq ($(ANTIDEBUG),1)
CFLAGS += -DWRAPPER_ANTIDEBUG_COTRACE
endif

BUILD_DIR := build
GEN_DIR := $(BUILD_DIR)/generated
BIN_DIR := $(BUILD_DIR)/bin

COMMON_SRC := src/common/crypto_primitives.c src/common/elf_inspect.c
RUNTIME_COMMON_SRC := src/common/crypto_primitives.c src/common/bench_harness.c src/runtime/runtime_core.c src/runtime/runtime_trace.c

PACKER := $(BIN_DIR)/packer
PAYLOAD_NO_PIE := $(BIN_DIR)/hello_payload_nopie
PAYLOAD_PIE := $(BIN_DIR)/hello_payload_pie
EMBEDDED_NO_PIE := $(GEN_DIR)/embedded_payload_nopie.h
EMBEDDED_PIE := $(GEN_DIR)/embedded_payload_pie.h
WRAPPER_NO_PIE := $(BIN_DIR)/wrapper_nopie_demo
WRAPPER_PIE := $(BIN_DIR)/wrapper_pie_demo
EMBEDDED_NO_PIE_UNIFORM := $(GEN_DIR)/embedded_payload_nopie_uniform.h
EMBEDDED_PIE_UNIFORM := $(GEN_DIR)/embedded_payload_pie_uniform.h
WRAPPER_NO_PIE_UNIFORM := $(BIN_DIR)/wrapper_nopie_uniform
WRAPPER_PIE_UNIFORM := $(BIN_DIR)/wrapper_pie_uniform
TAMPER_TEST := $(BIN_DIR)/tamper_checks
JIT_RESTORE_TEST_BUILD_DIR := build/test-jit-ciphertext-restore
THREAD_DEPENDENCY_BUILD_DIR := build/test-thread-dependency-limit

.PHONY: all clean run-demo run-demo-pie inspect test-packer-negative test-tamper test-jit-tamper test-jit-ciphertext-restore test-threads test-threads-stress test-signals test-thread-dependency-limit uniform run-demo-uniform run-demo-pie-uniform test-uniform h1-regression test-antidebug

all: $(WRAPPER_NO_PIE) $(WRAPPER_PIE) $(TAMPER_TEST)

$(BIN_DIR) $(GEN_DIR):
	mkdir -p $@

$(PACKER): src/offline/packer.c $(COMMON_SRC) include/wrapper_blob.h include/crypto_primitives.h include/elf_inspect.h | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test-packer-negative: $(PACKER) $(PAYLOAD_NO_PIE)
	PACKER=$(abspath $(PACKER)) CC=$(CC) CFLAGS='$(CFLAGS)' bash tests/packer_negative.sh

$(PAYLOAD_NO_PIE): samples/hello_payload.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -fno-pie -no-pie $< -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

$(PAYLOAD_PIE): samples/hello_payload.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -fPIE -pie $< -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

$(EMBEDDED_NO_PIE): $(PACKER) $(PAYLOAD_NO_PIE) | $(GEN_DIR)
	$(PACKER) --input $(PAYLOAD_NO_PIE) --output $@ --symbol protected_payload_nopie

$(EMBEDDED_PIE): $(PACKER) $(PAYLOAD_PIE) | $(GEN_DIR)
	$(PACKER) --input $(PAYLOAD_PIE) --output $@ --symbol protected_payload_pie

$(WRAPPER_NO_PIE): src/runtime/wrapper_main.c src/runtime/runtime_core.c src/runtime/runtime_core.h src/runtime/runtime_trace.c src/runtime/runtime_trace.h src/common/crypto_primitives.c include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_NO_PIE) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -DEMBEDDED_PAYLOAD_HEADER=\"embedded_payload_nopie.h\" -DPROTECTED_PAYLOAD_SYMBOL=protected_payload_nopie src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

$(WRAPPER_PIE): src/runtime/wrapper_main.c src/runtime/runtime_core.c src/runtime/runtime_core.h src/runtime/runtime_trace.c src/runtime/runtime_trace.h src/common/crypto_primitives.c include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_PIE) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -DEMBEDDED_PAYLOAD_HEADER=\"embedded_payload_pie.h\" -DPROTECTED_PAYLOAD_SYMBOL=protected_payload_pie src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

# --- Variante uniforme (control para contrastar H3: protege todas las
# --- funciones de aplicación del payload, no solo el banco protected_*) ---
$(EMBEDDED_NO_PIE_UNIFORM): $(PACKER) $(PAYLOAD_NO_PIE) | $(GEN_DIR)
	$(PACKER) --input $(PAYLOAD_NO_PIE) --output $@ --symbol protected_payload_nopie_uniform --uniform

$(EMBEDDED_PIE_UNIFORM): $(PACKER) $(PAYLOAD_PIE) | $(GEN_DIR)
	$(PACKER) --input $(PAYLOAD_PIE) --output $@ --symbol protected_payload_pie_uniform --uniform

$(WRAPPER_NO_PIE_UNIFORM): src/runtime/wrapper_main.c src/runtime/runtime_core.c src/runtime/runtime_core.h src/runtime/runtime_trace.c src/runtime/runtime_trace.h src/common/crypto_primitives.c include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_NO_PIE_UNIFORM) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -DEMBEDDED_PAYLOAD_HEADER=\"embedded_payload_nopie_uniform.h\" -DPROTECTED_PAYLOAD_SYMBOL=protected_payload_nopie_uniform src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

$(WRAPPER_PIE_UNIFORM): src/runtime/wrapper_main.c src/runtime/runtime_core.c src/runtime/runtime_core.h src/runtime/runtime_trace.c src/runtime/runtime_trace.h src/common/crypto_primitives.c include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_PIE_UNIFORM) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -DEMBEDDED_PAYLOAD_HEADER=\"embedded_payload_pie_uniform.h\" -DPROTECTED_PAYLOAD_SYMBOL=protected_payload_pie_uniform src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

uniform: $(WRAPPER_NO_PIE_UNIFORM) $(WRAPPER_PIE_UNIFORM)

# --- Variante de regresión H1 (control para aislar el coste por activación del
#     coste fijo de arranque, §5.3). Payload compilado con -DH1_REGRESSION, que
#     habilita el modo `activations N`; fuera de la build de producción.
PAYLOAD_NO_PIE_H1 := $(BIN_DIR)/hello_payload_h1
EMBEDDED_NO_PIE_H1 := $(GEN_DIR)/embedded_payload_h1.h
WRAPPER_NO_PIE_H1 := $(BIN_DIR)/wrapper_nopie_h1

$(PAYLOAD_NO_PIE_H1): samples/hello_payload.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -DH1_REGRESSION -fno-pie -no-pie $< -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

$(EMBEDDED_NO_PIE_H1): $(PACKER) $(PAYLOAD_NO_PIE_H1) | $(GEN_DIR)
	$(PACKER) --input $(PAYLOAD_NO_PIE_H1) --output $@ --symbol protected_payload_nopie_h1

$(WRAPPER_NO_PIE_H1): src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_NO_PIE_H1) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -DEMBEDDED_PAYLOAD_HEADER=\"embedded_payload_h1.h\" -DPROTECTED_PAYLOAD_SYMBOL=protected_payload_nopie_h1 src/runtime/wrapper_main.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

h1-regression: $(WRAPPER_NO_PIE_H1)

run-demo-uniform: $(WRAPPER_NO_PIE_UNIFORM)
	$(WRAPPER_NO_PIE_UNIFORM) demo-no-pie

run-demo-pie-uniform: $(WRAPPER_PIE_UNIFORM)
	$(WRAPPER_PIE_UNIFORM) demo-pie

# Validación funcional de la variante uniforme: los 4 modos sobre ambos
# wrappers deben terminar con código 0, las líneas OK esperadas y los valores
# deterministas del banco (argc=2 -> 25/77/7).
test-uniform: $(WRAPPER_NO_PIE_UNIFORM) $(WRAPPER_PIE_UNIFORM)
	@set -e; \
	for wrapper in $(WRAPPER_NO_PIE_UNIFORM) $(WRAPPER_PIE_UNIFORM); do \
		for mode in demo-no-pie signal-demo; do \
			tmp="$$(mktemp)"; \
			if ! "$$wrapper" "$$mode" >"$$tmp" 2>&1; then \
				cat "$$tmp"; rm -f "$$tmp"; \
				echo "test-uniform: FALLO (exit != 0) en $$wrapper $$mode"; \
				exit 1; \
			fi; \
			grep -q "protected_demo_function(argc) = 25" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-uniform: valor demo != 25 en $$wrapper $$mode"; exit 1; }; \
			grep -q "protected_second_function(argc + 2) = 77" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-uniform: valor second != 77 en $$wrapper $$mode"; exit 1; }; \
			grep -q "protected_recursive_function(3) = 7" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-uniform: valor recursive != 7 en $$wrapper $$mode"; exit 1; }; \
			grep -q "signal protected call: OK" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-uniform: signal FAIL en $$wrapper $$mode"; exit 1; }; \
			rm -f "$$tmp"; \
			echo "test-uniform: OK $$wrapper $$mode"; \
		done; \
	done; \
	echo "test-uniform: OK (todos los modos, ambos wrappers)"

$(TAMPER_TEST): tests/tamper_checks.c src/runtime/runtime_core.c src/runtime/runtime_core.h src/runtime/runtime_trace.c src/runtime/runtime_trace.h src/common/crypto_primitives.c include/wrapper_blob.h include/crypto_primitives.h $(EMBEDDED_NO_PIE) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(PTHREAD_FLAGS) -I$(GEN_DIR) -Isrc/runtime tests/tamper_checks.c $(RUNTIME_COMMON_SRC) -o $@ $(LDFLAGS) $(PTHREAD_FLAGS)

run-demo: $(WRAPPER_NO_PIE)
	$(WRAPPER_NO_PIE) demo-no-pie

run-demo-pie: $(WRAPPER_PIE)
	$(WRAPPER_PIE) demo-pie

inspect: $(WRAPPER_NO_PIE) $(WRAPPER_PIE)
	readelf -h $(WRAPPER_NO_PIE)
	readelf -h $(WRAPPER_PIE)

test-tamper: $(TAMPER_TEST)
	$(TAMPER_TEST)

test-jit-tamper: $(WRAPPER_NO_PIE)
	@set -e; \
	tmp="$$(mktemp)"; \
	if WRAPPER_TEST_TAMPER_DECRYPTED=1 $(WRAPPER_NO_PIE) demo-no-pie >"$$tmp" 2>&1; then \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		echo "test-jit-tamper: el wrapper aceptó tampering JIT"; \
		exit 1; \
	fi; \
	if ! grep -q "Hash de función descifrada inválido" "$$tmp"; then \
		cat "$$tmp"; \
		rm -f "$$tmp"; \
		echo "test-jit-tamper: no apareció el error de hash esperado"; \
		exit 1; \
	fi; \
	cat "$$tmp"; \
	rm -f "$$tmp"; \
	echo "test-jit-tamper: OK"

# Regresión criptográfica del ciclo JIT. Ejecuta 64 activaciones de la misma
# función en una build instrumentada y exige que el retorno no invoque AEAD
# encrypt: el ciphertext autenticado debe restaurarse desde su copia original.
test-jit-ciphertext-restore:
	$(MAKE) BUILD_DIR=$(JIT_RESTORE_TEST_BUILD_DIR) CFLAGS="$(CFLAGS) -DWRAPPER_BENCH=1 -DWRAPPER_TEST_HOOKS=1" h1-regression
	@set -e; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	if ! WRAPPER_BENCH_OUT="$$tmpdir" WRAPPER_TEST_CIPHERTEXT_AUDIT="$$tmpdir/ciphertext_restore_audit.csv" $(JIT_RESTORE_TEST_BUILD_DIR)/bin/wrapper_nopie_h1 activations 64 >"$$tmpdir/output" 2>&1; then \
		cat "$$tmpdir/output"; \
		echo "test-jit-ciphertext-restore: el wrapper instrumentado falló"; \
		exit 1; \
	fi; \
	grep -q "activations=64 acc=14816" "$$tmpdir/output" || { cat "$$tmpdir/output"; echo "test-jit-ciphertext-restore: resultado funcional inesperado"; exit 1; }; \
	[ -f "$$tmpdir/ciphertext_restore_audit.csv" ] || { cat "$$tmpdir/output"; echo "test-jit-ciphertext-restore: evidencia final de restauración ausente"; exit 1; }; \
	awk -F, 'NR == 1 { next } $$1 == 0 && $$2 == 64 && length($$3) == 64 && $$3 == $$4 && $$5 == 1 { ok = 1 } END { exit !ok }' "$$tmpdir/ciphertext_restore_audit.csv" || { cat "$$tmpdir/ciphertext_restore_audit.csv"; echo "test-jit-ciphertext-restore: hash final restaurado no coincide con metadatos"; exit 1; }; \
	set -- "$$tmpdir"/bench_runtime_*.csv; \
	[ "$$#" -eq 1 ] && [ -f "$$1" ] || { cat "$$tmpdir/output"; echo "test-jit-ciphertext-restore: CSV runtime ausente o ambiguo"; exit 1; }; \
	decrypt_count="$$(grep -c '^aead_decrypt,' "$$1")"; \
	[ "$$decrypt_count" -eq 64 ] || { cat "$$1"; echo "test-jit-ciphertext-restore: se esperaban 64 descifrados; hay $$decrypt_count"; exit 1; }; \
	if grep -q '^aead_encrypt,' "$$1"; then \
		cat "$$1"; \
		echo "test-jit-ciphertext-restore: el retorno JIT todavía cifra con el nonce original en vez de restaurar"; \
		exit 1; \
	fi; \
	echo "test-jit-ciphertext-restore: OK"

test-threads: $(WRAPPER_NO_PIE) $(WRAPPER_PIE)
	@set -e; \
	for wrapper in $(WRAPPER_NO_PIE) $(WRAPPER_PIE); do \
		tmp="$$(mktemp)"; \
		"$$wrapper" threaded-demo >"$$tmp" 2>&1; \
		cat "$$tmp"; \
		if ! grep -q "threaded protected calls: OK" "$$tmp"; then \
			rm -f "$$tmp"; \
			echo "test-threads: no apareció la línea OK en $$wrapper"; \
			exit 1; \
		fi; \
		rm -f "$$tmp"; \
	done; \
	echo "test-threads: OK"

test-threads-stress: $(WRAPPER_NO_PIE) $(WRAPPER_PIE)
	@set -e; \
	for wrapper in $(WRAPPER_NO_PIE) $(WRAPPER_PIE); do \
		tmp="$$(mktemp)"; \
		"$$wrapper" threaded-stress >"$$tmp" 2>&1; \
		cat "$$tmp"; \
		if ! grep -q "threaded stress protected calls: OK" "$$tmp"; then \
			rm -f "$$tmp"; \
			echo "test-threads-stress: no apareció la línea OK en $$wrapper"; \
			exit 1; \
		fi; \
		rm -f "$$tmp"; \
	done; \
	echo "test-threads-stress: OK"

test-signals: $(WRAPPER_NO_PIE) $(WRAPPER_PIE)
	@set -e; \
	for wrapper in $(WRAPPER_NO_PIE) $(WRAPPER_PIE); do \
		tmp="$$(mktemp)"; \
		"$$wrapper" signal-demo >"$$tmp" 2>&1; \
		cat "$$tmp"; \
		if ! grep -q "signal protected call: OK" "$$tmp"; then \
			rm -f "$$tmp"; \
			echo "test-signals: no apareció la línea OK en $$wrapper"; \
			exit 1; \
		fi; \
		rm -f "$$tmp"; \
	done; \
	echo "test-signals: OK"

# Caracteriza, sin corregirla, la dependencia cruzada incompatible con la
# política stop-the-world. El baseline y el control deben acabar; el caso límite
# exige rc=124, entrada efectiva en el waiter y señal emitida por timeout.
test-thread-dependency-limit:
	$(MAKE) -B BUILD_DIR=$(THREAD_DEPENDENCY_BUILD_DIR) THREAD_DEPENDENCY_TEST=1 all
	@set -e; \
	tmpdir="$$(mktemp -d /tmp/tfm-thread-dependency-XXXXXXXX)"; \
	trap 'rm -rf "$$tmpdir"' EXIT INT TERM; \
	echo "thread-dependency-baseline"; \
	if ! timeout --kill-after=1s 3 $(THREAD_DEPENDENCY_BUILD_DIR)/bin/hello_payload_nopie thread-dependency >"$$tmpdir/baseline.out" 2>&1; then \
		cat "$$tmpdir/baseline.out"; \
		echo "test-thread-dependency-limit: el baseline no terminó correctamente"; \
		exit 1; \
	fi; \
	grep -q "thread dependency protected call: OK" "$$tmpdir/baseline.out" || { cat "$$tmpdir/baseline.out"; echo "test-thread-dependency-limit: resultado baseline inesperado"; exit 1; }; \
	echo "thread-dependency-wrapper-control"; \
	if ! timeout --kill-after=1s 3 $(THREAD_DEPENDENCY_BUILD_DIR)/bin/wrapper_nopie_demo demo-no-pie >"$$tmpdir/control.out" 2>&1; then \
		cat "$$tmpdir/control.out"; \
		echo "test-thread-dependency-limit: el control protegido ordinario no terminó correctamente"; \
		exit 1; \
	fi; \
	echo "thread-dependency-protected"; \
	set +e; \
	LC_ALL=C timeout --verbose --kill-after=1s 3 $(THREAD_DEPENDENCY_BUILD_DIR)/bin/wrapper_nopie_demo thread-dependency >"$$tmpdir/protected.out" 2>&1; \
	rc=$$?; \
	set -e; \
	if [ "$$rc" -ne 124 ]; then \
		cat "$$tmpdir/protected.out"; \
		echo "test-thread-dependency-limit: rc=$$rc; se esperaba exclusivamente timeout (124)"; \
		exit 1; \
	fi; \
	grep -q "THREAD-DEPENDENCY-WAITER-ENTERED" "$$tmpdir/protected.out" || { cat "$$tmpdir/protected.out"; echo "test-thread-dependency-limit: el waiter protegido no alcanzó la espera"; exit 1; }; \
	grep -q "sending signal TERM" "$$tmpdir/protected.out" || { cat "$$tmpdir/protected.out"; echo "test-thread-dependency-limit: rc=124 sin evidencia de señal de timeout"; exit 1; }; \
	echo "KNOWN-LIMITATION: protected cross-thread dependency"

# Validación de la capa anti-depuración por co-traza (requiere ANTIDEBUG=1 y gdb).
# Comprueba que: (1) la ejecución normal sigue produciendo los valores del banco;
# (2) al lanzar el wrapper bajo gdb, el motor detecta el tracer y aborta ANTES de
# descifrar (no aparece el valor 25). El enganche tardío `gdb -p <motor>` se
# verifica manualmente: falla con «already traced by process <guardián>».
test-antidebug: $(WRAPPER_NO_PIE)
ifeq ($(ANTIDEBUG),1)
	@set -e; \
	command -v gdb >/dev/null 2>&1 || { echo "test-antidebug: SKIP (gdb no disponible)"; exit 0; }; \
	tmp="$$(mktemp)"; \
	$(WRAPPER_NO_PIE) demo-no-pie >"$$tmp" 2>&1; \
	grep -q "protected_demo_function(argc) = 25" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-antidebug: la ejecución normal no produjo el valor esperado"; exit 1; }; \
	rm -f "$$tmp"; \
	echo "test-antidebug: ejecución normal OK"; \
	tmp="$$(mktemp)"; \
	gdb -q -batch -ex run -ex quit --args $(WRAPPER_NO_PIE) demo-no-pie >"$$tmp" 2>&1 || true; \
	grep -q "Depurador detectado" "$$tmp" || { cat "$$tmp"; rm -f "$$tmp"; echo "test-antidebug: el motor NO detectó gdb al lanzarse bajo depurador"; exit 1; }; \
	if grep -q "protected_demo_function(argc) = 25" "$$tmp"; then cat "$$tmp"; rm -f "$$tmp"; echo "test-antidebug: el motor descifró bajo gdb (fail-close no aplicado)"; exit 1; fi; \
	rm -f "$$tmp"; \
	echo "test-antidebug: fail-close bajo gdb OK"; \
	echo "test-antidebug: OK"
else
	@echo "test-antidebug requiere ANTIDEBUG=1 (uso: make ANTIDEBUG=1 test-antidebug)"; exit 1
endif

clean:
	rm -rf $(BUILD_DIR)
