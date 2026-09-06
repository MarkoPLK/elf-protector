#!/usr/bin/env bash
# Compila libsodium de forma estática y coloca libsodium.a + cabeceras bajo
# este directorio (third_party/libsodium/), de modo que el Makefile del
# prototipo pueda enlazar la biblioteca criptográfica sin depender de una
# .so instalada en la máquina de destino.
#
# Versión pinneada para reproducibilidad. El binario resultante (libsodium.a)
# se vendoriza junto a este script; ejecutar este script solo hace falta para
# regenerarlo o actualizar la versión.
set -euo pipefail

VERSION="1.0.22"
SHA256="adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349"
URL="https://download.libsodium.org/libsodium/releases/libsodium-${VERSION}.tar.gz"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "[libsodium] descargando ${VERSION}"
curl -sSL -o "${WORK}/src.tar.gz" "$URL"
echo "${SHA256}  ${WORK}/src.tar.gz" | sha256sum -c -

tar -xzf "${WORK}/src.tar.gz" -C "$WORK"
cd "${WORK}/libsodium-${VERSION}"

echo "[libsodium] configure (estático)"
./configure --enable-static --disable-shared \
    --prefix="${WORK}/_install" --disable-dependency-tracking >/dev/null
echo "[libsodium] make"
make -j"$(nproc)" >/dev/null
make install >/dev/null

mkdir -p "${HERE}/lib" "${HERE}/include"
cp "${WORK}/_install/lib/libsodium.a" "${HERE}/lib/"
cp -r "${WORK}/_install/include/." "${HERE}/include/"
cp "${WORK}/libsodium-${VERSION}/LICENSE" "${HERE}/LICENSE"
echo "[libsodium] listo: ${HERE}/lib/libsodium.a ($(stat -c%s "${HERE}/lib/libsodium.a") bytes)"
