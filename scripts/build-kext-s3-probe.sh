#!/bin/bash
# Build the S3 boundary probe (tests/kext/s3-probe/kext_s3_probe.c) into
# build/kext-s3-probe/kext-s3-probe, run the clang static analyzer over it and run its self-test.
# Never installs, loads or touches a kext; the self-test makes no IOKit calls. See docs/kext-s3-probe.md.
#
# Warnings are errors. There is deliberately no warning suppression: KextManagerCopyLoadedKextInfo is
# not deprecated in the SDK this was written against, and if a newer SDK deprecates it the build must
# fail so that the identity check is revisited, not silenced.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
SRC="$ROOT/tests/kext/s3-probe/kext_s3_probe.c"
OUT="$ROOT/build/kext-s3-probe"
BIN="$OUT/kext-s3-probe"

fail() {
  echo "build-kext-s3-probe: $*" >&2
  exit 1
}

[[ "$(uname -s)" == "Darwin" ]] || fail "requires macOS (Darwin)"
command -v clang >/dev/null 2>&1 || fail "missing required tool: clang"
[[ -f "$SRC" ]] || fail "missing source: $SRC"
[[ ! -L "$ROOT/build" && ! -L "$OUT" ]] || fail "refusing to build through a symlink under $ROOT/build"

mkdir -p "$OUT"

CFLAGS=(-std=c11 -Wall -Wextra -Werror)
FRAMEWORKS=(-framework IOKit -framework CoreFoundation)

echo "== build =="
clang "${CFLAGS[@]}" -O2 "$SRC" "${FRAMEWORKS[@]}" -o "$BIN"
echo "built: $BIN"

echo "== static analyzer =="
clang --analyze "${CFLAGS[@]}" -Xclang -analyzer-werror -Xclang -analyzer-output=text "$SRC" -o /dev/null
echo "analyzer: clean"

echo "== self-test =="
if ! "$BIN" self-test >"$OUT/self-test.jsonl"; then
  grep -F '"pass":false' "$OUT/self-test.jsonl" >&2 || true
  fail "self-test failed (log: $OUT/self-test.jsonl)"
fi
if grep -q -F '"pass":false' "$OUT/self-test.jsonl"; then
  fail "self-test reported a failing case (log: $OUT/self-test.jsonl)"
fi
grep -F '"event":"summary"' "$OUT/self-test.jsonl"
echo "self-test log: $OUT/self-test.jsonl"
echo "kext-s3-probe build OK: $BIN"
