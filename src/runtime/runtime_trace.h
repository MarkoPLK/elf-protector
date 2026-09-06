#ifndef RUNTIME_TRACE_H
#define RUNTIME_TRACE_H

#include <stdint.h>

#include "crypto_primitives.h"
#include "wrapper_blob.h"

int wrapper_trace_exec_memfd(int payload_fd,
                             int argc,
                             char **argv,
                             const struct wrapper_embedded_blob *blob,
                             const uint8_t jit_key[WRAPPER_KEY_SIZE]);

#ifdef WRAPPER_ANTIDEBUG_COTRACE
/* Capa de endurecimiento opcional (anti-depuración por co-traza del proceso
 * padre). Compilada solo con -DWRAPPER_ANTIDEBUG_COTRACE (make ANTIDEBUG=1);
 * fuera del binario de producción medido en el Capítulo 5. Devuelve 0 si la
 * co-traza queda instalada (o si la instalación falla por recursos y se
 * continúa sin la capa) y -1 si detecta un tracer externo ya presente sobre el
 * motor, en cuyo caso el llamante debe abortar antes de reconstruir la clave. */
int wrapper_antidebug_install_cotrace(void);
#endif

#endif
