#!/bin/bash
# Builds the real usbgadget kext translation units against the user-space IOKit shim in tests/kext/shim
# and runs the lifecycle/fault-injection harness under ASan+UBSan, then under TSan.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/vendor/macos_usb_gadget_poc/usbgadget/usbgadget"
SHIM="$ROOT/tests/kext/shim"
HARNESS="$ROOT/tests/kext/harness.cpp"
OUT="$ROOT/build/kext-harness"

fail() {
  echo "$1" >&2
  exit 1
}

command -v clang++ >/dev/null 2>&1 || fail "missing required tool: clang++"

for file in "$SHIM/kext_shim.cpp" "$HARNESS" "$SOURCE/usbgadget.cpp" "$SOURCE/usbgadget_userclient.cpp"; do
  [[ -f "$file" ]] || fail "missing source: $file"
done

mkdir -p "$OUT"

# -fno-sanitize=function: IOKit dispatch tables cast static methods to IOExternalMethodAction by design.
COMMON=(
  -std=c++11 -g -O1 -fno-omit-frame-pointer -fno-sanitize=function
  -I "$SHIM" -I "$SOURCE"
  "$SHIM/kext_shim.cpp" "$HARNESS" "$SOURCE/usbgadget.cpp" "$SOURCE/usbgadget_userclient.cpp"
  -lpthread
)

echo "building ASan+UBSan harness"
clang++ -fsanitize=address,undefined "${COMMON[@]}" -o "$OUT/harness"
echo "running ASan+UBSan harness"
ASAN_OPTIONS="abort_on_error=0:halt_on_error=1" \
  UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
  "$OUT/harness" || fail "ASan+UBSan harness failed"

echo "building TSan harness"
clang++ -fsanitize=thread "${COMMON[@]}" -o "$OUT/harness-tsan"
echo "running TSan harness"
TSAN_OPTIONS="halt_on_error=1" "$OUT/harness-tsan" || fail "TSan harness failed"

echo "kext harness passed (asan+ubsan, tsan)"
