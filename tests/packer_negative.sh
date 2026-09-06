#!/usr/bin/env bash
set -euo pipefail

: "${PACKER:?PACKER debe apuntar al binario packer}"
: "${CC:=cc}"
: "${CFLAGS:=-std=c11 -Wall -Wextra -Wpedantic -O2}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM
chmod 755 "$tmpdir"

fail() {
    echo "test-packer-negative: FALLO: $*" >&2
    exit 1
}

expect_failure() {
    local description=$1
    shift

    if "$@" >"$tmpdir/output" 2>&1; then
        cat "$tmpdir/output" >&2
        fail "$description aceptó una entrada que debía rechazar"
    fi
}

assert_absent() {
    local path=$1

    [ ! -e "$path" ] || fail "se publicó inesperadamente $path"
}

run_without_write_privilege() {
    if [ "$(id -u)" -eq 0 ]; then
        command -v runuser >/dev/null 2>&1 || \
            fail "runuser es necesario para probar permisos como root"
        runuser -u nobody -- "$@"
    else
        "$@"
    fi
}

cat >"$tmpdir/dynsym_payload.c" <<'EOF'
int protected_exported(int value)
{
    return value + 1;
}

int main(void)
{
    return protected_exported(41) == 42 ? 0 : 1;
}
EOF
"$CC" $CFLAGS -rdynamic "$tmpdir/dynsym_payload.c" -o "$tmpdir/dynsym_payload"
strip --strip-all "$tmpdir/dynsym_payload"
readelf -S --wide "$tmpdir/dynsym_payload" | grep -q '[.]dynsym' || \
    fail "el fixture no conserva .dynsym"
if readelf -S --wide "$tmpdir/dynsym_payload" | grep -q '[.]symtab'; then
    fail "el fixture conserva .symtab"
fi
"$PACKER" --input "$tmpdir/dynsym_payload" --output "$tmpdir/dynsym.h"
[ -s "$tmpdir/dynsym.h" ] || fail ".dynsym no produjo una cabecera"

cp "$tmpdir/dynsym_payload" "$tmpdir/elf32"
printf '\001' | dd of="$tmpdir/elf32" bs=1 seek=4 conv=notrunc status=none
expect_failure "ELF con clase distinta de ELF64" \
    "$PACKER" --input "$tmpdir/elf32" --output "$tmpdir/elf32.h"
assert_absent "$tmpdir/elf32.h"

cat >"$tmpdir/no_prefix.c" <<'EOF'
int plain_function(int value)
{
    return value + 1;
}

int main(void)
{
    return plain_function(41) == 42 ? 0 : 1;
}
EOF
"$CC" $CFLAGS "$tmpdir/no_prefix.c" -o "$tmpdir/no_prefix"
expect_failure "ELF sin funciones seleccionables por prefijo" \
    "$PACKER" --input "$tmpdir/no_prefix" --output "$tmpdir/no-prefix.h"
grep -q "No se encontraron funciones seleccionables" "$tmpdir/output" || {
    cat "$tmpdir/output" >&2
    fail "no apareció el diagnóstico de selección vacía"
}
assert_absent "$tmpdir/no-prefix.h"

mkdir "$tmpdir/no-write"
chmod a-w "$tmpdir/no-write"
expect_failure "directorio de salida sin permiso de escritura" \
    run_without_write_privilege "$PACKER" --input "$tmpdir/dynsym_payload" \
    --output "$tmpdir/no-write/output.h"
assert_absent "$tmpdir/no-write/output.h"
chmod u+w "$tmpdir/no-write"

printf 'contenido previo que debe conservarse\n' >"$tmpdir/existing.h"
cp "$tmpdir/existing.h" "$tmpdir/existing.expected"
expect_failure "generación fallida sobre salida preexistente" \
    "$PACKER" --input "$tmpdir/no_prefix" --output "$tmpdir/existing.h"
cmp -s "$tmpdir/existing.expected" "$tmpdir/existing.h" || \
    fail "la salida existente cambió tras un fallo"

echo "test-packer-negative: OK"
