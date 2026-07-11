#!/usr/bin/env bash
#
# wolftpm/mayhem/test.sh — functional oracle over wolfTPM's FUZZED ASN.1 parse path, emitted as CTRF.
#
# Oracle source: a GOLDEN test (mayhem/test_asn_oracle.c) over TPM2_ASN_DecodeX509Cert /
# TPM2_ASN_DecodeRsaPubKey — the exact decoders fuzz_asn_cert drives. wolfTPM's upstream
# tests/unit_tests.c need a real or simulated TPM (socket swtpm), so they can't run headless in the
# build sandbox; this oracle runs anywhere because it only parses bytes. It asserts known-answer
# decode results (modulus length, keyBits) AND that malformed/length-confused inputs are rejected
# (the past-bug regressions the in-tree comments call out) — so a no-op/exit(0) patch to the
# decoders fails. It is NOT a no-op stub.
#
# build.sh has already built the sanitized wolfTPM + wolfSSL static libs; we only compile+run the
# oracle here. exit 0 iff no case failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
WORK="${WORK:-$SRC/mayhem-build}"
: "${CC:=clang}"
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"

PREFIX="$WORK/wolfssl-install"
LIBWOLFTPM="$SRC/src/.libs/libwolftpm.a"
LIBWOLFSSL="$PREFIX/lib/libwolfssl.a"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -f "$LIBWOLFTPM" ] || [ ! -f "$LIBWOLFSSL" ]; then
  echo "missing static libs ($LIBWOLFTPM / $LIBWOLFSSL) — run mayhem/build.sh first" >&2
  emit_ctrf "wolftpm-asn-oracle" 0 1 0; exit 2
fi

BIN="$WORK/test_asn_oracle"
echo "=== compiling ASN oracle ==="
$CC $SANITIZER_FLAGS -I"$SRC" -I"$PREFIX/include" \
    "$SRC/mayhem/test_asn_oracle.c" "$LIBWOLFTPM" "$LIBWOLFSSL" -lm \
    -o "$BIN" || { echo "oracle failed to compile" >&2; emit_ctrf "wolftpm-asn-oracle" 0 1 0; exit 2; }

echo "=== running ASN oracle ==="
out="$("$BIN" 2>&1)"; rc=$?
echo "$out"

PASSED=$(printf '%s\n' "$out" | grep -c '^PASS ')
FAILED=$(printf '%s\n' "$out" | grep -c '^FAIL ')
: "${PASSED:=0}" "${FAILED:=0}"

# Trust the oracle's exit code too: a crash (sanitizer abort) yields rc!=0 with no FAIL line.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  FAILED=1
fi

emit_ctrf "wolftpm-asn-oracle" "$PASSED" "$FAILED" 0
