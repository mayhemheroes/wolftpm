#!/usr/bin/env bash
#
# wolftpm/mayhem/build.sh — build wolfTPM's libFuzzer harnesses as sanitized targets
# (+ standalone reproducers). wolfTPM depends on wolfSSL, so we clone+build+install wolfSSL
# first (matching the OSS-Fuzz recipe), then build wolfTPM against it, then the harnesses.
#
# Fuzzed surface — TWO harnesses:
#   fuzz_asn_cert — wolfTPM's ASN.1 decoders (TPM2_ASN_DecodeX509Cert /
#                   TPM2_ASN_DecodeRsaPubKey in src/tpm2_asn.c). These parse untrusted bytes
#                   (an EK certificate / RSA pubkey read from a TPM NV index) into wolfTPM
#                   structs — a classic parser attack surface. First input byte selects the
#                   decoder. (This is the OSS-Fuzz canonical harness, from AdaLogics/ada-fuzzers.)
#   fwtpm_fuzz    — wolfTPM's firmware-TPM command processor (FWTPM_ProcessCommand in
#                   src/fwtpm/). Feeds raw TPM 2.0 COMMAND PACKETS (tag+size+CC+payload) into
#                   the fwTPM server's parse/dispatch path. Ships upstream in tests/fuzz/ with
#                   a TPM-command dictionary (tpm2.dict) and a seed generator (gen_corpus.py).
#
# We compile the wolfTPM library (and the fwTPM sources) WITH $SANITIZER_FLAGS so the fuzzed
# code — not just the harness — is instrumented. wolfSSL is a sanitized static dependency.
#
# Build contract comes from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/
# STANDALONE_FUZZ_MAIN/$OUT. Outputs: one libFuzzer binary + one -standalone per harness in /mayhem.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: DWARF ≤ 3 required (clang-19 defaults to DWARF 5; Mayhem triage needs < 4).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# Coverage instrumentation for the fuzzed code (libFuzzer needs -fsanitize=fuzzer-no-link on the
# library TUs; the engine flag adds the runtime when linking the target).
SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

SRC="${SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT="${OUT:-/mayhem}"
WORK="${WORK:-$SRC/mayhem-build}"
mkdir -p "$WORK" "$OUT"

HARNESS_DIR="$SRC/mayhem/harnesses"

# ── 1) Build wolfSSL (static, sanitized) with wolfTPM + keygen support, install to a prefix ────────
# fwTPM needs WOLFSSL_KEY_GEN; the ASN decoders need the public mp / RSA-no-padding flags.
PREFIX="$WORK/wolfssl-install"
WOLFSSL_SRC="$WORK/wolfssl"
mkdir -p "$PREFIX"
if [ ! -d "$WOLFSSL_SRC/.git" ] && [ ! -f "$WOLFSSL_SRC/configure.ac" ]; then
  git clone --depth 1 https://github.com/wolfssl/wolfssl "$WOLFSSL_SRC"
fi

cd "$WOLFSSL_SRC"
./autogen.sh
# Build wolfSSL itself with the sanitizers so the dependency is instrumented too.
./configure \
    --prefix="$PREFIX" \
    --enable-static --disable-shared \
    --enable-wolftpm \
    --enable-pkcallbacks \
    --enable-keygen \
    --enable-certgen \
    --enable-certreq \
    --enable-certext \
    CC="$CC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP" \
    LDFLAGS="$SANITIZER_FLAGS"
make -j"$MAYHEM_JOBS"
make install
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# ── 2) Build wolfTPM (static, sanitized) with fuzz + fwTPM enabled ─────────────────────────────────
# --enable-fuzz wires the fuzz config; --enable-fwtpm builds the firmware-TPM command processor that
# fwtpm_fuzz drives (and defines WOLFTPM_FWTPM in options.h so the harness compiles its real body).
cd "$SRC"
./autogen.sh
./configure \
    --prefix="$WORK/wolftpm-install" \
    --enable-static --disable-shared \
    --disable-examples \
    --enable-fwtpm \
    --enable-fuzz \
    CC="$CC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -I$PREFIX/include" \
    LDFLAGS="$SANITIZER_FLAGS -L$PREFIX/lib"
make -j"$MAYHEM_JOBS"

LIBWOLFTPM="$SRC/src/.libs/libwolftpm.a"
LIBWOLFSSL="$PREFIX/lib/libwolfssl.a"
[ -f "$LIBWOLFTPM" ] || { echo "ERROR: $LIBWOLFTPM not built" >&2; exit 1; }

# Common include + link flags. wolfTPM headers live under $SRC (namespace 'wolftpm/...') and the
# generated options.h lands in $SRC; wolfSSL headers come from the install prefix.
INC="-I$SRC -I$PREFIX/include"

# Standalone driver object (no libFuzzer runtime, reads one input file).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESS_DIR/standalone_main.c" -o "$WORK/standalone_main.o"

# ── 3a) fuzz_asn_cert — the ASN.1 decoders live IN libwolftpm.a, so link the harness directly. ─────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/fuzz_asn_cert.c" $LIB_FUZZING_ENGINE "$LIBWOLFTPM" "$LIBWOLFSSL" -lm \
    -o "$OUT/fuzz_asn_cert"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/fuzz_asn_cert.c" "$WORK/standalone_main.o" "$LIBWOLFTPM" "$LIBWOLFSSL" -lm \
    -o "$OUT/fuzz_asn_cert-standalone"
echo "built fuzz_asn_cert (+ standalone)"

# ── 3b) fwtpm_fuzz — the fwTPM command processor is NOT in libwolftpm.a; it is compiled separately
#        with -DWOLFTPM_FWTPM (see src/fwtpm/include.am). `make` above (with --enable-fwtpm
#        --enable-fuzz) already produced a fully-linked, sanitized libFuzzer binary at
#        tests/fuzz/fwtpm_fuzz — reuse it rather than re-linking (linking against libwolftpm.a would
#        miss WOLFTPM_FWTPM and silently fall back to the stub body). For the standalone reproducer
#        we recompile the SAME source list with -DWOLFTPM_FWTPM against our standalone main.
FWTPM_BIN="$SRC/tests/fuzz/fwtpm_fuzz"
[ -x "$FWTPM_BIN" ] || { echo "ERROR: upstream make did not build $FWTPM_BIN (is --enable-fwtpm active?)" >&2; exit 1; }
cp "$FWTPM_BIN" "$OUT/fwtpm_fuzz"

FWTPM_SRCS=(
  "$HARNESS_DIR/fwtpm_fuzz.c"
  "$SRC/src/fwtpm/fwtpm.c"
  "$SRC/src/fwtpm/fwtpm_command.c"
  "$SRC/src/fwtpm/fwtpm_crypto.c"
  "$SRC/src/fwtpm/fwtpm_nv.c"
  "$SRC/src/tpm2_util.c"
  "$SRC/src/tpm2_packet.c"
  "$SRC/src/tpm2_crypto.c"
  "$SRC/src/tpm2_param_enc.c"
)
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -DWOLFTPM_FWTPM $INC \
    "${FWTPM_SRCS[@]}" "$WORK/standalone_main.o" "$LIBWOLFSSL" -lm \
    -o "$OUT/fwtpm_fuzz-standalone"
echo "built fwtpm_fuzz (+ standalone)"

echo "build.sh complete:"
ls -la "$OUT/fuzz_asn_cert" "$OUT/fuzz_asn_cert-standalone" \
       "$OUT/fwtpm_fuzz" "$OUT/fwtpm_fuzz-standalone" 2>&1 || true
