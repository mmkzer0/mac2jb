#!/bin/bash
# Regression tests for the kext build provenance contract. Builds from throw-away copies of the
# working tree (scripts/kext-provenance.py export-checkout) in a temporary directory; the repository
# is never modified. Needs Xcode; no sudo, no kmutil, no network. Exits non-zero on any failure.
#
# Covered: executable hash independent of the checkout path and the ambient environment; verify
# rejects a tampered artifact, a post-build source edit (uncommitted and committed) and a dirty tree;
# ignored files do not change the source digest; `record` refuses a source that differs from the
# compiled copy; the KDK check rejects empty or mismatching KDK directories; verify-bundle accepts a
# bundle written by `bundle` and rejects a flipped executable byte, an extra file, a wrong SHA256SUMS
# line, reordered or duplicated PROVENANCE keys and a wrong lc_uuid; `bundle` refuses a dirty
# checkout and its output is byte-identical to the repository's drivers/ files; the preflight rejects
# private-policy paths that resolve into the repository.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
TOOL="$ROOT/scripts/kext-provenance.py"
PYTHON=/usr/bin/python3
SRC_REL="vendor/macos_usb_gadget_poc/usbgadget"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kext-provenance-test.XXXXXX")"
[[ -n "$WORK" && -d "$WORK" ]] || { echo "cannot create a temporary directory" >&2; exit 1; }
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

failures=0
note_ok() { echo "ok: $1"; }
note_fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

# run <name> <command...>: run quietly, remember the status and the output.
status=0
run() {
  local name="$1"
  shift
  status=0
  "$@" >"$WORK/last.out" 2>&1 || status=$?
  LAST_NAME="$name"
}
expect_status() { # expect_status <want> <name> <command...>
  local want="$1" name="$2"
  shift 2
  run "$name" "$@"
  if [[ "$status" -eq "$want" ]]; then
    note_ok "$name"
  else
    note_fail "$name (exit $status, wanted $want)"
    head -n 20 "$WORK/last.out"
  fi
}
expect_pass() { expect_status 0 "$@"; }
expect_nonzero() { # expect_nonzero <name> <command...>
  local name="$1"
  shift
  run "$name" "$@"
  if [[ "$status" -ne 0 ]]; then
    note_ok "$name"
  else
    note_fail "$name (unexpectedly succeeded)"
    head -n 20 "$WORK/last.out"
  fi
}
last_has() { grep -q -- "$1" "$WORK/last.out"; }
expect_code() { # a problem code must (or must not) appear in the last output
  local want="$1" code="$2" have=no
  if last_has "problem: $code:"; then
    have=yes
  fi
  if [[ "$have" == "$want" ]]; then
    note_ok "$LAST_NAME: problem code $code present=$have"
  else
    note_fail "$LAST_NAME: problem code $code present=$have, wanted $want"
  fi
}

gitq() {
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git \
    -c user.name=kext-test -c user.email=kext-test@localhost \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"
}
build_in() { (cd "$1" && bash scripts/build-kext.sh); }
verify_in() { (cd "$1" && "$PYTHON" scripts/kext-provenance.py verify "${@:2}"); }
bundle_in() { (cd "$1" && "$PYTHON" scripts/kext-provenance.py bundle --dest-dir "$2" "${@:3}"); }
verify_bundle_in() { (cd "$1" && "$PYTHON" scripts/kext-provenance.py verify-bundle "${@:2}"); }
exec_hash() {
  local out
  out="$(shasum -a 256 "$1/build/kext/usbgadget.kext/Contents/MacOS/usbgadget")"
  echo "${out%% *}"
}
verify_field() { # verify_field <checkout> <field>: value from the verify summary line
  verify_in "$1" 2>&1 | grep '^provenance:' | tr ' ' '\n' | grep "^$2=" | cut -d= -f2 || true
}
build_hostile() {
  (
    export OTHER_CFLAGS=-O0 OTHER_CPLUSPLUSFLAGS=-O0 OTHER_LDFLAGS=-Wl,-v GCC_OPTIMIZATION_LEVEL=0
    export MACOSX_DEPLOYMENT_TARGET=13.0 DEBUG_INFORMATION_FORMAT=dwarf GCC_GENERATE_DEBUGGING_SYMBOLS=YES
    build_in "$1"
  )
}
append_byte() { printf 'x' >>"$1"; }
append_line() { printf '\n// provenance test edit\n' >>"$1"; }

echo "== path and environment independence"
A="$WORK/a one/mac2jb checkout"
B="$WORK/b/other-name"
expect_pass "export checkout A (path with a space)" "$PYTHON" "$TOOL" export-checkout --dest "$A"
expect_pass "export checkout B" "$PYTHON" "$TOOL" export-checkout --dest "$B"
expect_pass "build A" build_in "$A"
expect_pass "build B" build_in "$B"
hash_a="$(exec_hash "$A")"
hash_b="$(exec_hash "$B")"
if [[ "$hash_a" == "$hash_b" ]]; then
  note_ok "same commit content, different checkout paths: identical executable sha256 ($hash_a)"
else
  note_fail "executable hash depends on the checkout path: $hash_a vs $hash_b"
fi
expect_pass "verify clean A" verify_in "$A"
expect_pass "verify clean B" verify_in "$B"
digest_a="$(verify_field "$A" source_sha256)"
digest_b="$(verify_field "$B" source_sha256)"
if [[ -n "$digest_a" && "$digest_a" == "$digest_b" ]]; then
  note_ok "source digest is identical across checkouts"
else
  note_fail "source digest differs across checkouts: '$digest_a' vs '$digest_b'"
fi

expect_pass "build A with hostile environment" build_hostile "$A"
if [[ "$(exec_hash "$A")" == "$hash_a" ]]; then
  note_ok "OTHER_CFLAGS/OPTIMIZATION/SDKROOT in the environment do not change the executable"
else
  note_fail "ambient environment changed the executable hash"
fi

echo "== bundled driver"
BUNDLE="$WORK/bundle"
expect_pass "bundle writes a driver from a clean checkout" bundle_in "$A" "$BUNDLE"
expect_pass "verify-bundle accepts the written bundle" verify_bundle_in "$A" --bundle-dir "$BUNDLE"
bundle_line="$(verify_bundle_in "$A" --bundle-dir "$BUNDLE" 2>&1 | grep '^bundle:' || true)"
bundle_uuid="${bundle_line#*lc_uuid=}"
bundle_uuid="${bundle_uuid%% *}"
if [[ "$bundle_line" == "bundle: executable_sha256=$hash_a lc_uuid=$bundle_uuid source_tree_sha256=$digest_a" ]] &&
   [[ "$bundle_uuid" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]]; then
  note_ok "verify-bundle summary names the executable, its LC_UUID and the source digest"
else
  note_fail "unexpected verify-bundle summary: $bundle_line"
fi

expect_pass "bundle into a temporary directory from the repository build" \
  "$PYTHON" "$TOOL" bundle --dest-dir "$WORK/repo-drivers"
for relative in usbgadget.kext/Contents/Info.plist usbgadget.kext/Contents/MacOS/usbgadget \
                SHA256SUMS PROVENANCE; do
  if cmp -s "$WORK/repo-drivers/$relative" "$ROOT/drivers/$relative"; then
    note_ok "bundle output is byte-identical to drivers/$relative"
  else
    note_fail "bundle output differs from drivers/$relative"
  fi
done

cp -R "$BUNDLE" "$WORK/bundle-flip"
append_byte "$WORK/bundle-flip/usbgadget.kext/Contents/MacOS/usbgadget"
expect_nonzero "verify-bundle rejects a flipped executable byte" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-flip"
expect_code yes bundle-bytes

cp -R "$BUNDLE" "$WORK/bundle-extra"
printf 'x' >"$WORK/bundle-extra/usbgadget.kext/Contents/extra"
expect_nonzero "verify-bundle rejects an extra file" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-extra"
expect_code yes bundle-files

cp -R "$BUNDLE" "$WORK/bundle-sums"
{ printf '0000000000000000000000000000000000000000000000000000000000000000  Contents/Info.plist\n'
  awk 'NR==2' "$WORK/bundle-sums/SHA256SUMS"; } >"$WORK/bundle-sums/SHA256SUMS.new"
mv "$WORK/bundle-sums/SHA256SUMS.new" "$WORK/bundle-sums/SHA256SUMS"
expect_nonzero "verify-bundle rejects a wrong SHA256SUMS line" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-sums"
expect_code yes sums

cp -R "$BUNDLE" "$WORK/bundle-order"
awk 'NR==2{line=$0;next} NR==3{print;print line;next} {print}' \
  "$WORK/bundle-order/PROVENANCE" >"$WORK/bundle-order/PROVENANCE.new"
mv "$WORK/bundle-order/PROVENANCE.new" "$WORK/bundle-order/PROVENANCE"
expect_nonzero "verify-bundle rejects reordered PROVENANCE keys" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-order"
expect_code yes provenance

cp -R "$BUNDLE" "$WORK/bundle-dup"
awk '{print} NR==2{print}' "$WORK/bundle-dup/PROVENANCE" >"$WORK/bundle-dup/PROVENANCE.new"
mv "$WORK/bundle-dup/PROVENANCE.new" "$WORK/bundle-dup/PROVENANCE"
expect_nonzero "verify-bundle rejects a duplicated PROVENANCE key" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-dup"
expect_code yes provenance

cp -R "$BUNDLE" "$WORK/bundle-uuid"
awk -F= '$1=="lc_uuid"{print "lc_uuid=00000000-0000-0000-0000-000000000000"; next} {print}' \
  "$WORK/bundle-uuid/PROVENANCE" >"$WORK/bundle-uuid/PROVENANCE.new"
mv "$WORK/bundle-uuid/PROVENANCE.new" "$WORK/bundle-uuid/PROVENANCE"
expect_nonzero "verify-bundle rejects a wrong lc_uuid" \
  verify_bundle_in "$A" --bundle-dir "$WORK/bundle-uuid"
expect_code yes provenance
if last_has "lc_uuid"; then
  note_ok "wrong lc_uuid rejection names lc_uuid"
else
  note_fail "wrong lc_uuid rejection does not name lc_uuid"
fi

echo "== ignored files"
mkdir -p "$A/$SRC_REL/usbgadget.xcodeproj/xcuserdata/tester.xcuserdatad"
printf 'noise' >"$A/$SRC_REL/.DS_Store"
printf 'noise' >"$A/$SRC_REL/usbgadget.xcodeproj/xcuserdata/tester.xcuserdatad/x.xcuserstate"
expect_pass "verify after ignored-file noise" verify_in "$A"
expect_pass "rebuild A with ignored noise present" build_in "$A"
if [[ "$(exec_hash "$A")" == "$hash_a" && "$(verify_field "$A" source_sha256)" == "$digest_a" ]]; then
  note_ok "ignored files change neither the digest nor the executable"
else
  note_fail "ignored files changed the digest or the executable"
fi

echo "== tampering and post-build edits"
append_byte "$A/build/kext/usbgadget.kext/Contents/MacOS/usbgadget"
expect_nonzero "verify rejects a modified artifact" verify_in "$A"
expect_code yes artifact-hash
expect_pass "rebuild A" build_in "$A"
expect_pass "verify rebuilt A" verify_in "$A"

append_line "$A/$SRC_REL/usbgadget/usbgadget.cpp"
expect_nonzero "verify rejects an uncommitted post-build source edit" verify_in "$A"
expect_code yes source-digest
expect_code yes dirty
run "record refuses a source that differs from the compiled copy" \
  "$PYTHON" "$A/scripts/kext-provenance.py" record \
  --artifact "$A/build/kext/usbgadget.kext" --source "$A/$SRC_REL" \
  --built-source "$A/build/kext/src" --build-script "$A/scripts/build-kext.sh" \
  --build-settings "$A/build/kext/build-settings.txt" --output "$WORK/must-not-exist.json"
if [[ "$status" -ne 0 && ! -e "$WORK/must-not-exist.json" ]]; then
  note_ok "record refuses a source that differs from the compiled copy"
else
  note_fail "record accepted a post-build source edit (exit $status)"
fi
gitq -C "$A" commit -q -a --no-verify -m "Edit after build"
expect_nonzero "verify rejects a committed post-build source edit (clean tree)" verify_in "$A"
expect_code yes source-digest
expect_code no dirty

echo "== dirty tree"
printf 'scratch' >"$B/$SRC_REL/scratch.txt"
expect_nonzero "verify rejects untracked build input" verify_in "$B"
expect_code yes dirty
expect_code no source-digest
expect_pass "dirty tree still builds for iteration" build_in "$B"
if [[ "$(exec_hash "$B")" == "$hash_a" ]]; then
  note_ok "an untracked file is not compiled"
else
  note_fail "an untracked file changed the executable"
fi
expect_nonzero "verify rejects a record made from a dirty tree" verify_in "$B"
expect_code yes record-dirty
expect_nonzero "bundle refuses a dirty checkout" bundle_in "$B" "$WORK/bundle-dirty"
expect_code yes dirty
if [[ ! -e "$WORK/bundle-dirty/usbgadget.kext" ]]; then
  note_ok "bundle writes nothing when verification fails"
else
  note_fail "bundle wrote a driver despite failed verification"
fi
expect_pass "verify --allow-dirty accepts the iteration build" verify_in "$B" --allow-dirty

echo "== KDK content check"
host_version="$(sw_vers -productVersion)"
KDKS="$WORK/kdks"
make_kdk() { # make_kdk <name> <plist build> <kernel kind: arm|x86|none>
  local dir="$KDKS/$1"
  mkdir -p "$dir/System/Library/CoreServices" "$dir/System/Library/Kernels" "$dir/System/Library/Extensions"
  cat >"$dir/System/Library/CoreServices/SystemVersion.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>$host_version</string>
<key>ProductBuildVersion</key><string>$2</string>
</dict></plist>
EOF
  case "$3" in
    arm)
      printf '\317\372\355\376\014\000\000\001' >"$dir/System/Library/Kernels/kernel"
      printf '\317\372\355\376\014\000\000\001' >"$dir/System/Library/Kernels/kernel.release.t8103"
      ;;
    x86)
      printf '\317\372\355\376\007\000\000\001' >"$dir/System/Library/Kernels/kernel"
      printf '\317\372\355\376\007\000\000\001' >"$dir/System/Library/Kernels/kernel.release.t8103"
      ;;
  esac
}
kdk_check() { "$PYTHON" "$TOOL" kdk-check --kdk-root "$KDKS" --product-version "$host_version" --product-build "$1"; }
expect_output() { # the last command's output must contain a pattern (guards against vacuous rejections)
  if last_has "$1"; then
    note_ok "$LAST_NAME: rejected for the intended reason ($1)"
  else
    note_fail "$LAST_NAME: rejection reason does not mention '$1'"
    head -n 10 "$WORK/last.out"
  fi
}
mkdir -p "$KDKS/KDK_${host_version}_TESTA1.kdk"
expect_nonzero "KDK check rejects an empty KDK directory" kdk_check TESTA1
expect_output "SystemVersion.plist"
expect_nonzero "KDK check rejects a missing KDK" kdk_check TESTMISSING
expect_output "KDK directory is missing"
make_kdk "KDK_${host_version}_TESTB1.kdk" TESTB1 arm
expect_pass "KDK check accepts a complete KDK" kdk_check TESTB1
make_kdk "KDK_${host_version}_TESTC1.kdk" OTHERBUILD arm
expect_nonzero "KDK check rejects a KDK whose SystemVersion build differs from its name" kdk_check TESTC1
expect_output "ProductBuildVersion"
make_kdk "KDK_${host_version}_TESTD1.kdk" TESTD1 none
expect_nonzero "KDK check rejects a KDK without kernels" kdk_check TESTD1
expect_output "Kernels/kernel"
make_kdk "KDK_${host_version}_TESTE1.kdk" TESTE1 x86
expect_nonzero "KDK check rejects a KDK without an arm64 release kernel" kdk_check TESTE1
expect_output "arm64"
host_build="$(sw_vers -buildVersion)"
if [[ -d "/Library/Developer/KDKs/KDK_${host_version}_${host_build}.kdk" ]]; then
  expect_pass "KDK check accepts the installed host KDK" \
    "$PYTHON" "$TOOL" kdk-check --product-version "$host_version" --product-build "$host_build"
else
  echo "skip: no installed KDK for $host_version ($host_build)"
fi

echo "== private policy path guard"
repo_name="$(basename "$ROOT")"
repo_parent="$(dirname "$ROOT")"
ln -s "$ROOT" "$WORK/repo-link"
ln -s "$ROOT/priv-link-target.json" "$WORK/priv-link.json"
preflight() { bash "$ROOT/scripts/kext-s2-preflight.sh" --validate-only --private-policy-out "$1"; }
expect_status 0 "outside path is accepted" preflight "$WORK/private.json"
expect_status 2 "path inside the repository is rejected" preflight "$ROOT/priv.json"
expect_status 2 "path in a repository subdirectory is rejected" preflight "$ROOT/docs/priv.json"
expect_status 2 "dot-dot path into the repository is rejected" preflight "/tmp/../$repo_parent/$repo_name/priv.json"
expect_status 2 "dot-dot inside the repository path is rejected" preflight "$ROOT/../$repo_name/priv.json"
expect_status 2 "double-slash path into the repository is rejected" preflight "$repo_parent//$repo_name/priv.json"
expect_status 2 "symlinked directory into the repository is rejected" preflight "$WORK/repo-link/priv.json"
expect_status 2 "symlinked file is rejected" preflight "$WORK/priv-link.json"
expect_status 2 "case-variant path into the repository is rejected" \
  preflight "$repo_parent/$(printf '%s' "$repo_name" | tr '[:lower:]' '[:upper:]')/priv.json"
expect_status 2 "relative path is rejected" preflight "priv.json"
expect_status 2 "missing parent directory is rejected" preflight "$WORK/no-such-dir/priv.json"

if [[ "$failures" -ne 0 ]]; then
  echo "kext provenance tests: $failures failure(s)"
  exit 1
fi
echo "kext provenance tests passed"
