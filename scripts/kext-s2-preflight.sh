#!/bin/bash
# Read-only preflight for the S2 policy gate. Builds the kext twice to test
# reproducibility, runs the S1 source/harness gates, checks the matching KDK,
# prints bundle/linkage diagnostics, records the public SIP state, and prints
# the documented rollback commands. It never changes SIP, never installs, and
# never loads a kext. A private LocalPolicy snapshot is captured only when
# --private-policy-out is supplied explicitly.
#
# Usage: scripts/kext-s2-preflight.sh [--private-policy-out <private-path>]
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/kext-s2-preflight"
REPORT="$OUT/preflight.md"
ARTIFACT="$ROOT/build/kext/usbgadget.kext"
EXECUTABLE="$ARTIFACT/Contents/MacOS/usbgadget"
PRIVATE_POLICY_OUT=""

usage() {
  echo "usage: $0 [--private-policy-out <private-path>]"
  echo "  The private path must be outside the repository; its contents are never printed."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --private-policy-out)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      PRIVATE_POLICY_OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$(id -u)" -eq 0 ]]; then
  echo "run this preflight as the build user, not root" >&2
  exit 2
fi

mkdir -p "$OUT"
: > "$REPORT"

failures=0
record() { printf '%s\n' "$*" >> "$REPORT"; }
pass() { record "- PASS: $*"; }
fail() { failures=$((failures + 1)); record "- FAIL: $*"; }
info() { record "- INFO: $*"; }
section() { printf '\n## %s\n\n' "$*" >> "$REPORT"; }

host_version="$(sw_vers -productVersion 2>/dev/null || true)"
host_build="$(sw_vers -buildVersion 2>/dev/null || true)"
host_arch="$(uname -m 2>/dev/null || true)"
xcode_version="$(xcodebuild -version 2>/dev/null | head -n 1 | tr -d '\r' || true)"
sdk_version="$(xcrun --sdk macosx --show-sdk-version 2>/dev/null || true)"
sdk_path="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"

record "# S2 preflight report"
record ""
record "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
record "Host: macOS ${host_version:-unknown} (${host_build:-unknown}), ${host_arch:-unknown}"
record "Xcode: ${xcode_version:-unknown}; macOS SDK: ${sdk_version:-unknown}"
record "SDK path: ${sdk_path:-unknown}"

section "Host and toolchain"
if [[ "$host_arch" == "arm64" ]]; then
  pass "arm64 host"
else
  fail "unexpected host architecture: ${host_arch:-unknown}"
fi
if [[ -n "$xcode_version" && -n "$sdk_version" ]]; then
  pass "Xcode and macOS SDK available"
else
  fail "Xcode or the macOS SDK is unavailable"
fi

section "KDK"
kdk_root="/Library/Developer/KDKs"
expected_kdk="$kdk_root/KDK_${host_version}_${host_build}.kdk"
installed_kdks=""
if [[ -d "$kdk_root" ]]; then
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    if [[ -n "$installed_kdks" ]]; then
      installed_kdks+=", "
    fi
    installed_kdks+="$(basename "$path")"
  done < <(find "$kdk_root" -maxdepth 1 -mindepth 1 -type d -name 'KDK_*.kdk' -print 2>/dev/null | sort)
fi
if [[ -d "$expected_kdk" ]]; then
  pass "matching KDK present: $(basename "$expected_kdk")"
else
  fail "matching KDK missing: $(basename "$expected_kdk") (install it from developer.apple.com; do not use --allow-missing-kdk)"
fi
if [[ -n "$installed_kdks" ]]; then
  info "installed KDKs: $installed_kdks"
else
  info "no KDKs installed"
fi

section "S1 source and harness gates"
if bash "$ROOT/scripts/check-kext-source.sh" >"$OUT/source-check.log" 2>&1; then
  pass "strict source check and analyzer"
else
  fail "strict source check failed (log: $OUT/source-check.log)"
fi
if bash "$ROOT/scripts/test-kext-harness.sh" >"$OUT/harness.log" 2>&1; then
  pass "mock harness (ASan+UBSan and TSan)"
else
  fail "mock harness failed (log: $OUT/harness.log)"
fi

section "Reproducible build"
if ! bash "$ROOT/scripts/build-kext.sh" >"$OUT/build-1.log" 2>&1; then
  fail "first build failed (log: $OUT/build-1.log)"
else
  if [[ ! -f "$EXECUTABLE" ]]; then
    fail "build did not produce $EXECUTABLE"
  else
    hash1="$(shasum -a 256 "$EXECUTABLE" | awk '{print $1}')"
    if ! bash "$ROOT/scripts/build-kext.sh" >"$OUT/build-2.log" 2>&1; then
      fail "second build failed (log: $OUT/build-2.log)"
    else
      hash2="$(shasum -a 256 "$EXECUTABLE" | awk '{print $1}')"
      if [[ "$hash1" == "$hash2" ]]; then
        pass "two clean builds produced the same executable hash"
      else
        fail "two clean builds produced different hashes: $hash1 vs $hash2"
      fi
      info "executable: $(stat -f '%z' "$EXECUTABLE") bytes, SHA-256 $hash2"
    fi
  fi
fi

section "Bundle and load diagnostics"
if [[ -d "$ARTIFACT" ]]; then
  file_count="$(find "$ARTIFACT" -type f | wc -l | tr -d ' ')"
  link_count="$(find "$ARTIFACT" -type l | wc -l | tr -d ' ')"
  if [[ "$file_count" -eq 2 && "$link_count" -eq 0 ]]; then
    pass "bundle file list is exactly two files and contains no symlinks"
  else
    fail "bundle file list is $file_count files and $link_count symlinks"
  fi
  if plutil -lint "$ARTIFACT/Contents/Info.plist" >"$OUT/plutil.log" 2>&1; then
    pass "Info.plist lint"
  else
    fail "Info.plist lint failed (log: $OUT/plutil.log)"
  fi
  arch_info="$(file -b "$EXECUTABLE" 2>/dev/null || true)"
  if [[ "$arch_info" == *arm64e* ]]; then
    pass "executable architecture: arm64e"
  else
    fail "unexpected executable architecture: ${arch_info:-unknown}"
  fi
  codesign_info="$(codesign -dv "$ARTIFACT" 2>&1 || true)"
  if [[ "$codesign_info" == *"not signed at all"* ]]; then
    info "bundle is unsigned as built; S2 approval/signature policy remains"
  elif [[ "$codesign_info" == *"Authority="* ]]; then
    info "bundle is signed; inspect the authority before approval"
  else
    info "bundle signing state could not be classified"
  fi

  if kmutil print-diagnostics -p "$ARTIFACT" -z >"$OUT/kmutil-diagnostics.txt" 2>&1; then
    :
  fi
  if grep -q "Dependencies: OK" "$OUT/kmutil-diagnostics.txt"; then
    pass "kext dependency resolution"
  else
    fail "kext dependency resolution failed (log: $OUT/kmutil-diagnostics.txt)"
  fi
  if grep -q "Filesystem error" "$OUT/kmutil-diagnostics.txt"; then
    info "user-owned build path; the installer applies root:wheel ownership"
  fi
  if grep -q "Authenticating extension failed" "$OUT/kmutil-diagnostics.txt"; then
    info "pre-install authentication is expected to fail for the unsigned build"
  fi
else
  fail "bundle missing after build"
fi

section "Current load and policy state"
if kmutil showloaded --list-only >"$OUT/loaded.txt" 2>&1; then
  if grep -q "usbgadget" "$OUT/loaded.txt"; then
    fail "usbgadget is already loaded; unload it before approving a new build"
  else
    pass "usbgadget is not currently loaded"
  fi
else
  fail "kmutil showloaded failed (log: $OUT/loaded.txt)"
fi
if [[ -e /Library/Extensions/usbgadget.kext ]]; then
  fail "/Library/Extensions/usbgadget.kext already exists; clean up the previous install first"
else
  pass "target install path is absent"
fi
if csrutil status >"$OUT/csrutil.txt" 2>&1; then
  kext_signing="$(grep -E 'Kext Signing:' "$OUT/csrutil.txt" | head -n 1 || true)"
  info "public SIP state: ${kext_signing:-Kext Signing line not found}"
  info "this preflight did not change SIP"
else
  fail "csrutil status failed (log: $OUT/csrutil.txt)"
fi

section "Private policy snapshot"
if [[ -n "$PRIVATE_POLICY_OUT" ]]; then
  if [[ "$PRIVATE_POLICY_OUT" != /* ]]; then
    fail "private LocalPolicy path must be absolute and outside the repository"
  elif [[ "$PRIVATE_POLICY_OUT" == "$ROOT"/* ]]; then
    fail "refusing to write the private LocalPolicy snapshot inside the repository"
  elif ! command -v bputil >/dev/null 2>&1; then
    fail "bputil not found"
  elif ! sudo -n true >/dev/null 2>&1; then
    fail "sudo requires a password; run manually: sudo bputil -d -j > <private-path>"
  else
    umask 077
    if sudo -n bputil -d -j >"$PRIVATE_POLICY_OUT" 2>"$OUT/bputil.err"; then
      chmod 600 "$PRIVATE_POLICY_OUT"
      pass "private LocalPolicy snapshot captured (contents not printed)"
    else
      fail "bputil failed (log: $OUT/bputil.err)"
    fi
  fi
else
  info "private LocalPolicy not captured; rerun with --private-policy-out <private-path> after explicit approval"
  info "the snapshot contains ECID/kuid/vuid and must stay outside the repository"
fi

section "Rollback readiness (not executed)"
info "unload: sudo kmutil unload -p /Library/Extensions/usbgadget.kext; restart; verify it is absent from kmutil showloaded"
info "remove: delete /Library/Extensions/usbgadget.kext; sudo kmutil install --update-all; restart; verify the aux/unloaded collections"
info "SIP: recoveryOS csrutil enable --without debug; restore research guests if previously enabled"
if grep -q "kmutil unload -p" "$ROOT/docs/kext-hardening-plan.md" &&
   grep -q "kmutil install --update-all" "$ROOT/docs/kext-hardening-plan.md"; then
  pass "rollback commands are documented in docs/kext-hardening-plan.md"
else
  fail "rollback commands are missing from docs/kext-hardening-plan.md"
fi
info "no install, unload, SIP change, or kext load was performed by this preflight"

section "Result"
if [[ "$failures" -eq 0 ]]; then
  record "PASS: no preflight blockers"
else
  record "BLOCKED: $failures preflight blocker(s); see FAIL lines"
fi
record ""
cat "$REPORT"
if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
