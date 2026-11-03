#!/bin/bash
# Build usbgadget.kext from the git-tracked vendored Xcode project into build/kext, validate it and
# write build/kext/provenance.json next to it; never installs.
#
# The artifact is a function of the commit and the toolchain only:
#   - xcodebuild runs under `env -i` with an explicit allowlist (PATH, LANG, an isolated HOME and
#     TMPDIR below build/kext, and DEVELOPER_DIR only when the operator exported it, which the record
#     keeps), so OTHER_CFLAGS, SDKROOT, user-wide Xcode defaults and DerivedData cannot leak in;
#   - only git-tracked files of the kext source directory are compiled;
#   - debug information is off, so no build-directory path ends up in the Mach-O stabs and the
#     executable hash does not depend on the checkout path.
# A dirty tree still builds for iteration; the record says dirty:true and `kext-provenance.py verify`
# (and the S2 preflight) reject it.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
SOURCE_REL="vendor/macos_usb_gadget_poc/usbgadget"
SOURCE="$ROOT/$SOURCE_REL"
OUT="$ROOT/build/kext"
PROVENANCE="$ROOT/scripts/kext-provenance.py"
PYTHON=/usr/bin/python3

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

for tool in xcodebuild xcrun plutil ditto find shasum file stat sort grep codesign git env; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required tool: $tool"
done
[[ -x /usr/libexec/PlistBuddy ]] || fail "missing required tool: /usr/libexec/PlistBuddy"
[[ -x "$PYTHON" ]] || fail "missing required tool: $PYTHON"

[[ -d "$SOURCE/usbgadget.xcodeproj" ]] || fail "missing kext project: $SOURCE/usbgadget.xcodeproj"
[[ -f "$SOURCE/usbgadget/Info.plist" ]] || fail "missing kext Info.plist: $SOURCE/usbgadget/Info.plist"
[[ -f "$PROVENANCE" ]] || fail "missing provenance tool: $PROVENANCE"

# The provenance record names a commit, so the build needs the repository this script lives in.
if ! GIT_TOP="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" || [[ ! "$GIT_TOP" -ef "$ROOT" ]]; then
  fail "kext build requires a git checkout rooted at $ROOT (the provenance record names the commit)"
fi

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
mkdir -p "$OUT/src" "$OUT/home" "$OUT/tmp"

# Copy exactly the git-tracked files of the kext source; ignored files (.DS_Store, xcuserdata) and
# untracked scratch files never reach the compiler.
git -C "$SOURCE" ls-files -z -- . >"$OUT/source-files.list" || fail "git ls-files failed for $SOURCE_REL"
SOURCE_COUNT=0
while IFS= read -r -d '' rel; do
  [[ -f "$SOURCE/$rel" && ! -L "$SOURCE/$rel" ]] || fail "tracked kext source is not a regular file: $SOURCE_REL/$rel"
  mkdir -p "$OUT/src/$(dirname "$rel")"
  ditto "$SOURCE/$rel" "$OUT/src/$rel"
  SOURCE_COUNT=$((SOURCE_COUNT + 1))
done <"$OUT/source-files.list"
[[ "$SOURCE_COUNT" -gt 0 ]] || fail "no tracked files under $SOURCE_REL"
[[ -d "$OUT/src/usbgadget.xcodeproj" ]] || fail "tracked kext sources do not contain usbgadget.xcodeproj"

if ! grep -F -q -- 'MACOSX_DEPLOYMENT_TARGET = 12.0;' "$OUT/src/usbgadget.xcodeproj/project.pbxproj"; then
  fail "kext project still targets an unsupported macOS version; see vendor/README.md"
fi

# Sanitized environment shared by xcodebuild, xcrun and the provenance tool.
CLEAN_ENV=("PATH=$PATH" "HOME=$OUT/home" "TMPDIR=$OUT/tmp" "LANG=C")
if [[ -n "${DEVELOPER_DIR:-}" ]]; then
  CLEAN_ENV+=("DEVELOPER_DIR=$DEVELOPER_DIR")
  echo "kext build uses operator-selected DEVELOPER_DIR=$DEVELOPER_DIR (recorded)"
fi

# Non-path arguments are recorded; the three path arguments below are not.
BUILD_ARGS=(
  -configuration Release
  -sdk macosx
  ARCHS=arm64e
  ONLY_ACTIVE_ARCH=YES
  CODE_SIGNING_ALLOWED=NO
  GCC_GENERATE_DEBUGGING_SYMBOLS=NO
)
PATH_ARGS=(
  -project "$OUT/src/usbgadget.xcodeproj"
  SYMROOT="$OUT/sym"
  OBJROOT="$OUT/obj"
)

if ! env -i "${CLEAN_ENV[@]}" /usr/bin/xcodebuild "${PATH_ARGS[@]}" "${BUILD_ARGS[@]}" \
  -showBuildSettings >"$OUT/build-settings.txt" 2>"$OUT/build-settings.err"; then
  cat "$OUT/build-settings.err" >&2
  fail "xcodebuild -showBuildSettings failed"
fi

if ! env -i "${CLEAN_ENV[@]}" /usr/bin/xcodebuild "${PATH_ARGS[@]}" "${BUILD_ARGS[@]}" \
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

# 7. provenance: bind artifact, compiled source copy, toolchain and this script
RECORD_ARGS=()
for arg in "${BUILD_ARGS[@]}"; do
  RECORD_ARGS+=("--build-arg=$arg")
done
env -i "${CLEAN_ENV[@]}" "$PYTHON" "$PROVENANCE" record \
  --artifact "$KEXT" \
  --source "$SOURCE" \
  --built-source "$OUT/src" \
  --build-script "$ROOT/scripts/build-kext.sh" \
  --build-settings "$OUT/build-settings.txt" \
  "${RECORD_ARGS[@]}" \
  --output "$OUT/provenance.json" || fail "kext provenance record failed"
env -i "${CLEAN_ENV[@]}" "$PYTHON" "$PROVENANCE" verify --allow-dirty \
  --record "$OUT/provenance.json" --artifact "$KEXT" --source "$SOURCE" \
  --build-script "$ROOT/scripts/build-kext.sh" || fail "kext provenance self-check failed"
echo "kext provenance: $OUT/provenance.json"

echo "kext artifact: $KEXT"
echo "kext sha256: $(file_sha256 "$BIN")"
