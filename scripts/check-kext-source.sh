#!/bin/bash
# Syntax-only and static-analyzer gate for the vendored kext translation units; produces no build products.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/vendor/macos_usb_gadget_poc/usbgadget/usbgadget"

fail() {
  echo "$1" >&2
  exit 1
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "kext source check requires macOS (Darwin)"
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  fail "kext source check requires an arm64 host"
fi
for tool in xcrun clang; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done

SDK="$(xcrun --sdk macosx --show-sdk-path)"
HEADERS="$SDK/System/Library/Frameworks/Kernel.framework/Headers"

if [[ ! -f "$HEADERS/IOKit/IOService.h" ]]; then
  fail "missing kernel headers: $HEADERS/IOKit/IOService.h"
fi

COMMON=(
  -x c++ -std=c++11 -mkernel
  -target arm64e-apple-macos12.0
  -isysroot "$SDK"
  "-I$HEADERS"
  "-I$SOURCE"
  -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT
)
WARNINGS=(-Wall -Wextra -Werror -Wconversion -Wshorten-64-to-32 -Wnull-dereference -Wno-unused-parameter)

for file in usbgadget.cpp usbgadget_userclient.cpp; do
  echo "checking $file"
  if ! clang -fsyntax-only "${COMMON[@]}" "${WARNINGS[@]}" "$SOURCE/$file"; then
    fail "kext source check failed"
  fi

  echo "checking $file"
  if ! clang --analyze -Xclang -analyzer-werror "${COMMON[@]}" "${WARNINGS[@]}" -Xanalyzer -analyzer-output=text "$SOURCE/$file"; then
    fail "kext source check failed"
  fi
done

echo "kext source checks passed (2 translation units)"
