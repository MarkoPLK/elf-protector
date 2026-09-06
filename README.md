# Protector de binarios ELF

Prototipo de investigación de un sistema de protección de binarios ELF64 para
Linux x86-64 mediante reempaquetado (*repacking*): transforma un ejecutable en
un *wrapper* autónomo que embebe el *payload* cifrado y un motor *runtime* que
descifra cada función protegida bajo demanda (*just-in-time*), verifica su
integridad y la vuelve a proteger tras su ejecución. Combina cifrado autenticado
por función (AEAD ChaCha20-Poly1305), *self-tracing* con `ptrace` e `int3`, y
verificación criptográfica de integridad.

Es el prototipo que acompaña al Trabajo Fin de Máster *«Técnicas de Protección
Binaria para Ejecutables Linux»* (Máster Universitario en Ciberseguridad y
Ciberinteligencia, ETSINF – Universitat Politècnica de València), de Marko
Pylypyuk. Se publica como material de referencia: es un prototipo académico, no
un producto de seguridad maduro.

## Requisitos

- Linux x86-64.
- Compilador C con soporte C11 (`gcc` o `clang`) y `make`.
- libsodium: se distribuye vendorizado en `third_party/libsodium/` (biblioteca
  estática ya incluida). Para regenerarlo, `third_party/libsodium/build_libsodium.sh`
  (descarga y compila la versión pineada 1.0.22).

Compilación y demostración:

```sh
make          # construye el packer, los payloads de prueba y los wrappers
make run-demo # ejecuta el wrapper cifrado del payload no-PIE
```

## Estado actual

Actualmente está implementada la **Fase 1**, una **Fase 2 inicial** y varios bloques de la **Fase 3**:

1. compilación de payloads ELF de prueba,
2. inspección ELF64 offline,
3. empaquetado del payload **cifrado** con AEAD ChaCha20-Poly1305,
4. generación de un wrapper nuevo con el blob protegido embebido,
5. validación anti-tampering del paquete protegido,
6. descifrado en memoria + verificación de hashes + `memfd_create` + `fexecve`,
7. metadatos versionados de regiones ejecutables (`PT_LOAD` con `PF_X`) para preparar el JIT por función/región,
8. topología tracer/tracee inicial con `ptrace`, `PTRACE_TRACEME`, `PTRACE_EVENT_EXEC` y resolución de regiones desde `/proc/<pid>/maps`,
9. primer breakpoint `int3` en el `entry_point`, con restauración del byte original, corrección de `RIP` y `PTRACE_SINGLESTEP`,
10. flujo controlado de breakpoints de función y retorno sobre `protected_demo_function`: símbolo localizado en `.symtab` o `.dynsym`, dirección de retorno leída desde `RSP` y validación de hit antes de aceptar la salida,
11. cifrado JIT de múltiples funciones demo: el packer localiza símbolos `STT_FUNC` con prefijo `protected_`, cifra cada cuerpo con nonce propio dentro de la imagen del payload, y el tracer lo descifra al entrar y restaura el ciphertext original al alcanzar el retorno externo,
12. soporte básico de recursión en un único hilo: una función protegida permanece descifrada durante llamadas recursivas internas y recupera su ciphertext original al volver al caller externo,
13. anti-tampering en memoria para funciones JIT descifradas: el tracer valida el hash cifrado antes de descifrar, el hash en claro al entrar y el hash en claro justo antes de restaurar el ciphertext original,
14. soporte multi-TID controlado para la demo `pthread`: el tracer usa `PTRACE_O_TRACECLONE`, espera TIDs con `waitpid(..., __WALL)`, mantiene activaciones por TID y usa una tabla global de breakpoints de retorno para evitar duplicados en direcciones compartidas,
15. manejo básico de señales durante código protegido: las señales no internas se reinyectan al tracee y la demo valida `SIGUSR1` mientras una función `protected_` está descifrada,
16. prueba de entrada simultánea multi-hilo sobre una misma función protegida: el tracer pausa otros TIDs durante los `step-over` de breakpoints software y serializa de forma conservadora la sección protegida para evitar que un hilo atraviese un `int3` temporalmente desarmado.

## Qué protege ya esta versión

- evita embeber el ELF original en claro dentro del wrapper,
- valida que el input sea ELF64 x86-64 ejecutable,
- detecta si el payload es PIE/no-PIE y dinámico,
- genera metadatos versionados con las regiones ejecutables del ELF original,
- genera metadatos de funciones protegidas cuando encuentra símbolos de demo con prefijo `protected_`,
- mantiene cada función protegida cifrada en la imagen cargada salvo durante su ejecución,
- mantiene una función recursiva descifrada hasta su retorno externo para evitar restaurar el ciphertext en retornos internos,
- sigue TIDs secundarios creados por `pthread` en una demo controlada,
- permite llamadas protegidas desde TIDs sucesivos sin mutex de payload alrededor de las funciones protegidas,
- soporta una demo con varios TIDs liberados simultáneamente contra la misma función `protected_`, resuelta mediante serialización en el tracer,
- reinyecta señales no internas del tracer y valida una señal de usuario durante ejecución protegida,
- detecta modificaciones de funciones protegidas mientras están descifradas en memoria y aborta el tracee,
- verifica integridad de metadatos + ciphertext como paquete,
- autentica el ciphertext con tag AEAD ChaCha20-Poly1305 antes de aceptarlo,
- verifica integridad del payload descifrado antes de ejecutarlo.

## Qué no está todavía implementado

- cifrado JIT por regiones completas,
- ejecución paralela real dentro de la misma función protegida sin serialización del tracer,
- señales complejas, `fork`/`vfork` y cambios de imagen con múltiples hilos vivos,
- heurísticas de funciones para binarios strippeados.

## Estructura

- `include/`: tipos, parser ELF y primitivas criptográficas
- `src/common/`: cripto y utilidades compartidas
- `src/offline/`: herramienta de build-time
- `src/runtime/`: runtime del wrapper
- `samples/`: payloads de prueba

## Comandos

```sh
make
make run-demo
make run-demo-pie
make test-packer-negative
make test-tamper
make test-jit-tamper
make test-threads
make test-threads-stress
make test-signals
```

## Artefactos generados

La generación del wrapper se realiza en dos etapas: el packer no emite el ELF
final directamente. La cadena es la siguiente:

```text
ELF de entrada -> packer -> embedded_payload_*.h -> compilación/enlace del runtime -> wrapper ELF
```

El packer valida un ELF64 x86-64 ejecutable y selecciona las funciones
`protected_` por defecto, o las funciones de aplicación en modo `--uniform`.
La selección acepta símbolos `STT_FUNC` procedentes de `.symtab` o `.dynsym`;
por tanto, la ausencia de `.symtab` no invalida por sí sola el payload. En modo
por prefijo, la ausencia de funciones seleccionables se rechaza antes de crear
la cabecera. La cabecera se escribe primero en un temporal del directorio de
destino y solo sustituye la ruta final mediante `rename` tras completar la
escritura correctamente.

- `build/bin/packer`: herramienta offline
- `build/bin/hello_payload_nopie`: payload no-PIE de prueba
- `build/bin/hello_payload_pie`: payload PIE de prueba
- `build/bin/wrapper_nopie_demo`: wrapper cifrado para el payload no-PIE
- `build/bin/wrapper_pie_demo`: wrapper cifrado para el payload PIE

## Trabajo futuro

Sobre la base multi-función y multi-TID con serialización conservadora:

1. evaluar una alternativa sin serialización completa del tracer, por ejemplo hardware breakpoints o colas por breakpoint,
2. evaluar cifrado JIT por regiones como comparación de granularidad,
3. heurísticas para localizar funciones sin símbolo de demo.

## Licencia

Publicado bajo licencia MIT. Véase el fichero [`LICENSE`](LICENSE).

libsodium (`third_party/libsodium/`) se distribuye bajo su propia licencia ISC.
