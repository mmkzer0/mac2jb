#!/bin/bash
# Build usbgadget.kext from the vendored Xcode project into build/kext and validate it; never installs.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/vendor/macos_usb_gadget_poc/usbgadget"
OUT="$ROOT/build/kext"

ADHOC_SIGN=0
case "$#" in
  0) ;;
  1)
    if [[ "$1" == "--adhoc-sign" ]]; then
      ADHOC_SIGN=1
    else
      echo "usage: scripts/build-kext.sh [--adhoc-sign]" >&2
      exit 2
    fi
    ;;
  *)
    echo "usage: scripts/build-kext.sh [--adhoc-sign]" >&2
    exit 2
    ;;
esac

fail() {
  echo "$1" >&2
  exit 1
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "kext build requires macOS (Darwin)"
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  fail "kext build requires an arm64 host"
fi

for tool in xcodebuild plutil ditto find shasum file stat sort grep codesign; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[[ -x /usr/libexec/PlistBuddy ]] || fail "missing required tool: /usr/libexec/PlistBuddy"

[[ -d "$SOURCE/usbgadget.xcodeproj" ]] || fail "missing kext project: $SOURCE/usbgadget.xcodeproj"
[[ -f "$SOURCE/usbgadget/Info.plist" ]] || fail "missing kext Info.plist: $SOURCE/usbgadget/Info.plist"

if [[ "$OUT" != "$ROOT/build/kext" ]]; then
  fail "refusing unexpected output directory: $OUT"
fi
if [[ -L "$ROOT/build" ]]; then
  fail "refusing to build through symlink: $ROOT/build"
fi
if [[ -L "$OUT" ]]; then
  fail "refusing to build through symlink: $OUT"
fi

rm -rf -- "$OUT"
mkdir -p "$OUT"

ditto "$SOURCE" "$OUT/src"

if ! grep -F -q -- 'MACOSX_DEPLOYMENT_TARGET = 12.0;' "$OUT/src/usbgadget.xcodeproj/project.pbxproj"; then
  fail "kext project still targets an unsupported macOS version; see vendor/README.md"
fi

if ! xcodebuild \
  -project "$OUT/src/usbgadget.xcodeproj" \
  -configuration Release \
  -sdk macosx \
  ARCHS=arm64e \
  ONLY_ACTIVE_ARCH=YES \
  CODE_SIGNING_ALLOWED=NO \
  SYMROOT="$OUT/sym" \
  OBJROOT="$OUT/obj" \
  build >"$OUT/build.log" 2>&1; then
  cat "$OUT/build.log" >&2
  fail "kext build failed"
fi
echo "kext build succeeded"

BUILT="$OUT/sym/Release/usbgadget.kext"
if [[ ! -d "$BUILT" || -L "$BUILT" ]]; then
  fail "kext artifact missing or not a plain directory: $BUILT"
fi

ditto "$BUILT" "$OUT/usbgadget.kext"
KEXT="$OUT/usbgadget.kext"
BIN="$KEXT/Contents/MacOS/usbgadget"
PLIST="$KEXT/Contents/Info.plist"

# 1. bundle layout: exactly two regular files, no symlinks
if [[ -n "$(find "$KEXT" -type l -print)" ]]; then
  fail "kext bundle contains symlinks"
fi
if [[ -n "$(find "$KEXT" ! -type f ! -type d -print)" ]]; then
  fail "kext bundle contains entries that are neither regular files nor directories"
fi
if [[ -e "$KEXT/Contents/Resources" ]]; then
  fail "kext bundle contains Contents/Resources; the Xcode Resources phase was not cleaned up (duplicate Info.plist)"
fi
FILES=""
while IFS= read -r path; do
  FILES="$FILES${path#"$KEXT"/}"$'\n'
done < <(find "$KEXT" -type f -print | LC_ALL=C sort)
EXPECTED_FILES=$'Contents/Info.plist\nContents/MacOS/usbgadget\n'
if [[ "$FILES" != "$EXPECTED_FILES" ]]; then
  echo "kext bundle file list is not exactly Contents/Info.plist and Contents/MacOS/usbgadget; found:" >&2
  printf '%s' "$FILES" >&2
  exit 1
fi

# 2. executable format
BIN_DESC="$(file "$BIN")"
if [[ "$BIN_DESC" != *'Mach-O 64-bit kext bundle arm64e'* ]]; then
  fail "kext executable is not a Mach-O 64-bit kext bundle arm64e: $BIN_DESC"
fi

# 3. plist syntax
if ! plutil -lint "$PLIST" >/dev/null; then
  fail "kext Info.plist failed plutil -lint"
fi

# 4. plist identity keys
check_plist_value() {
  local key="$1" want="$2" got
  if ! got="$(/usr/libexec/PlistBuddy -c "Print :$key" "$PLIST" 2>/dev/null)"; then
    fail "kext Info.plist is missing $key"
  fi
  if [[ "$got" != "$want" ]]; then
    fail "kext Info.plist $key is '$got', expected '$want'"
  fi
}
check_plist_value CFBundleIdentifier gay.bowser.usbgadget
check_plist_value CFBundlePackageType KEXT
check_plist_value CFBundleExecutable usbgadget

# 5. signing state
if [[ "$ADHOC_SIGN" == "1" ]]; then
  codesign --force --sign - --timestamp=none "$KEXT"
  codesign --verify --strict "$KEXT"
  echo "kext signing: ad-hoc"
else
  SIGN_STATUS=0
  SIGN_INFO="$(codesign -dv "$KEXT" 2>&1)" || SIGN_STATUS=$?
  if [[ "$SIGN_STATUS" != "0" ]]; then
    echo "kext signing: unsigned"
  else
    while IFS= read -r line; do
      case "$line" in
        Identifier=* | Signature=* | Authority=* | TeamIdentifier=*) echo "kext signing: $line" ;;
      esac
    done <<<"$SIGN_INFO"
  fi
fi

# 6. sizes and digests
file_sha256() {
  local out
  out="$(shasum -a 256 "$1")"
  echo "${out%% *}"
}
echo "kext executable size: $(stat -f %z "$BIN")"
echo "kext executable sha256: $(file_sha256 "$BIN")"
echo "kext Info.plist size: $(stat -f %z "$PLIST")"
echo "kext Info.plist sha256: $(file_sha256 "$PLIST")"

echo "kext artifact: $KEXT"
echo "kext sha256: $(file_sha256 "$BIN")"
