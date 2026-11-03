#!/bin/bash
# mac2jb USB driver installer, shared by the GUI and the CLI.
#
# Installs only the pinned, self-built usbgadget.kext described by
# drivers/PROVENANCE and drivers/SHA256SUMS. It never changes SIP or the startup
# security policy and never deletes a driver: a replaced one is moved out of
# /Library/Extensions into the mac2jb driver state folder.
#
#   install-driver.sh            install (idempotent) and request loading; needs root
#   install-driver.sh --verify   check the bundled copy only
#   install-driver.sh --status   report installed and loaded identity; no root, no writes
#
# --status prints "MAC2JB_DRIVER_STATUS=<state>" on line 1 and one sentence on
# line 2. Exit codes: 0 verified, 10 restart-required, 11 not-installed,
# 12 not-loaded, 13 mismatch-installed, 14 mismatch-loaded, 15 bundle-invalid,
# 16 unknown. Only 0 with state "verified" permits USB input.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUNDLED="$ROOT/drivers/usbgadget.kext"
SUMS="$ROOT/drivers/SHA256SUMS"
PROVENANCE="$ROOT/drivers/PROVENANCE"
EXTENSIONS=/Library/Extensions
STATE_DIR='/Library/Application Support/mac2jb/driver'
LOCK_FILE=/var/run/mac2jb-driver-install.lock
OWNER=root:wheel
TARGET="$EXTENSIONS/usbgadget.kext"
MARKER="$EXTENSIONS/.mac2jb-usbgadget-restart-required"
BUNDLE_LISTING=$'./Contents\n./Contents/Info.plist\n./Contents/MacOS\n./Contents/MacOS/usbgadget'
STAGE=''
LOCKED=0

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

provenance_value() { # provenance_value <key>: value of a key that occurs exactly once
  awk -F= -v key="$1" '$1 == key { value = substr($0, length(key) + 2); count++ }
    END { if (count != 1) exit 1; print value }' "$PROVENANCE"
}

load_pins() { # sets BUNDLE_ID, PIN_UUID, PIN_EXECUTABLE, PIN_PLIST; PIN_ERROR on failure
  local format
  PIN_ERROR='The bundled driver manifest (drivers/PROVENANCE, drivers/SHA256SUMS) is missing.'
  [[ -f "$PROVENANCE" && ! -L "$PROVENANCE" && -f "$SUMS" && ! -L "$SUMS" ]] || return 1
  PIN_ERROR='drivers/PROVENANCE is malformed or has an unsupported format.'
  format="$(provenance_value format)" && [[ "$format" == mac2jb-bundled-kext-v1 ]] || return 1
  BUNDLE_ID="$(provenance_value bundle_identifier)" &&
    [[ "$BUNDLE_ID" == gay.bowser.usbgadget ]] || return 1
  PIN_UUID="$(provenance_value lc_uuid)" &&
    [[ "$PIN_UUID" =~ ^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$ ]] || return 1
  PIN_EXECUTABLE="$(provenance_value executable_sha256)" &&
    [[ "$PIN_EXECUTABLE" =~ ^[0-9a-f]{64}$ ]] || return 1
  PIN_PLIST="$(provenance_value info_plist_sha256)" && [[ "$PIN_PLIST" =~ ^[0-9a-f]{64}$ ]] || return 1
  PIN_ERROR='drivers/SHA256SUMS does not match drivers/PROVENANCE.'
  [[ "$(cat "$SUMS")" == "$PIN_PLIST  Contents/Info.plist"$'\n'"$PIN_EXECUTABLE  Contents/MacOS/usbgadget" ]]
}

digest() {
  shasum -a 256 "$1" | awk '{print $1}'
}

bundle_matches() { # bundle_matches <dir>: exactly the pinned files and digests, no links
  local dir="$1" listing
  [[ -d "$dir" && ! -L "$dir" ]] || return 1
  listing="$(cd "$dir" && find . -mindepth 1 -print | LC_ALL=C sort)" || return 1
  [[ "$listing" == "$BUNDLE_LISTING" ]] || return 1
  [[ -d "$dir/Contents" && ! -L "$dir/Contents" && -d "$dir/Contents/MacOS" && ! -L "$dir/Contents/MacOS" ]] || return 1
  [[ -f "$dir/Contents/Info.plist" && ! -L "$dir/Contents/Info.plist" ]] || return 1
  [[ -f "$dir/Contents/MacOS/usbgadget" && ! -L "$dir/Contents/MacOS/usbgadget" ]] || return 1
  [[ "$(digest "$dir/Contents/Info.plist")" == "$PIN_PLIST" ]] || return 1
  [[ "$(digest "$dir/Contents/MacOS/usbgadget")" == "$PIN_EXECUTABLE" ]]
}

metadata_ok() { # metadata_ok <dir>: the ownership and modes kmutil expects; call after bundle_matches
  local entry mode
  while IFS= read -r entry; do
    [[ "$(stat -f '%Su:%Sg' "$entry")" == "$OWNER" ]] || return 1
    mode="$(stat -f '%Lp' "$entry")"
    if [[ -d "$entry" || "$entry" == "$1/Contents/MacOS/usbgadget" ]]; then
      [[ "$mode" == 755 ]] || return 1
    else
      [[ "$mode" == 644 ]] || return 1
    fi
  done < <(find "$1" -print)
}

foreign_copies() { # other kext bundles in EXTENSIONS that declare our bundle identifier
  local kext id
  for kext in "$EXTENSIONS"/*.kext "$EXTENSIONS"/.*.kext; do
    [[ -e "$kext" || -L "$kext" ]] || continue
    [[ "$kext" != "$TARGET" ]] || continue
    id="$(plutil -extract CFBundleIdentifier raw -o - "$kext/Contents/Info.plist" 2>/dev/null)" || id=''
    if [[ "$id" == "$BUNDLE_ID" ]]; then
      printf '%s\n' "$kext"
    fi
  done
}

loaded_uuids() { # UUID of every loaded kext with our bundle identifier, one per line
  local listing
  listing="$(kmutil showloaded --list-only 2>/dev/null)" || return 1
  awk -v id="$BUNDLE_ID" '$6 == id { print $8 }' <<< "$listing"
}

restart_pending() { # the installer changed the driver or requested a load during this boot
  local boot
  [[ -e "$MARKER" || -L "$MARKER" ]] || return 1
  boot="$(sysctl -n kern.boottime | awk '{print $4}' | tr -d ',')"
  [[ "$boot" =~ ^[0-9]+$ ]] || return 0
  (( $(stat -f %m "$MARKER") >= boot ))
}

safe_dir() { # safe_dir <dir>: a real folder owned by OWNER's user that nobody else can write
  [[ -d "$1" && ! -L "$1" && "$(stat -f '%Su' "$1")" == "${OWNER%%:*}" ]] || return 1
  (( (8#$(stat -f '%Lp' "$1") & 8#022) == 0 ))
}

report() { # report <state> <exit code> <sentence> [detail...]
  local state="$1" code="$2"
  shift 2
  printf 'MAC2JB_DRIVER_STATUS=%s\n' "$state"
  printf '%s\n' "$@"
  exit "$code"
}

status() {
  local foreign uuids
  if ! load_pins || ! bundle_matches "$BUNDLED"; then
    report bundle-invalid 15 'The bundled mac2jb driver failed verification; reinstall mac2jb.'
  fi
  foreign="$(foreign_copies)"
  if [[ -n "$foreign" ]]; then
    report mismatch-installed 13 "Another kext declares $BUNDLE_ID; remove it before using mac2jb." "$foreign"
  fi
  if [[ -L "$TARGET" || ( -e "$TARGET" && ! -d "$TARGET" ) ]]; then
    report mismatch-installed 13 "$TARGET is not a plain kext folder; inspect it, then reinstall the mac2jb driver."
  fi
  if [[ -d "$TARGET" ]] && ! { bundle_matches "$TARGET" && metadata_ok "$TARGET"; }; then
    report mismatch-installed 13 'The installed driver is not the pinned mac2jb build; reinstall it.'
  fi
  if restart_pending; then
    report restart-required 10 'The mac2jb driver was installed or a load was requested during this boot; restart this Mac.'
  fi
  if ! uuids="$(loaded_uuids)"; then
    report unknown 16 'The loaded kernel extensions could not be listed (kmutil showloaded failed).'
  fi
  if [[ -n "$uuids" && "$uuids" != "$PIN_UUID" ]]; then
    report mismatch-loaded 14 "A different $BUNDLE_ID is loaded; reinstall the pinned driver and restart." \
      "loaded UUID(s): $(tr '\n' ' ' <<< "$uuids")" "pinned UUID: $PIN_UUID"
  fi
  if [[ ! -d "$TARGET" ]]; then
    report not-installed 11 "The mac2jb driver is not installed in $EXTENSIONS."
  fi
  if [[ -z "$uuids" ]]; then
    report not-loaded 12 'The pinned driver is installed but not loaded; approve it in System Settings > Privacy & Security, then restart.'
  fi
  report verified 0 "The pinned mac2jb driver is installed and loaded (UUID $PIN_UUID)."
}

verify_bundled() {
  load_pins || die "$PIN_ERROR"
  bundle_matches "$BUNDLED" || die 'The bundled driver does not match drivers/PROVENANCE; reinstall mac2jb.'
  echo "Bundled driver verified: executable $PIN_EXECUTABLE, UUID $PIN_UUID."
}

cleanup() {
  # Staging lives outside /Library/Extensions and is never deleted recursively:
  # an empty folder is removed, anything left over goes to the Trash (macOS 15+)
  # or stays where it is and is reported.
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then
    rmdir "$STAGE" 2>/dev/null || trash "$STAGE" 2>/dev/null ||
      echo "An incomplete staging folder was left outside $EXTENSIONS: $STAGE" >&2
  fi
  # Release only a lock this process still owns.
  if (( LOCKED )) && [[ "$(head -n 1 "$LOCK_FILE" 2>/dev/null)" == "$$" ]]; then
    rm -f -- "$LOCK_FILE"
  fi
}

acquire_lock() { # one installer at a time; shlock reclaims a lock whose process is gone
  if ! shlock -f "$LOCK_FILE" -p "$$"; then
    echo 'Another mac2jb driver installation is running; wait for it to finish, then try again.' >&2
    exit 75
  fi
  LOCKED=1
}

prepare_state_dir() { # root-only folder chain for staging and replaced drivers
  local dir
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  for dir in "$EXTENSIONS" "$(dirname "$(dirname "$STATE_DIR")")" "$(dirname "$STATE_DIR")" "$STATE_DIR"; do
    safe_dir "$dir" || die "Refusing to continue: $dir is not a folder that only ${OWNER%%:*} can write."
  done
}

install_bundle() { # stage, verify, set ownership, then swap into place by rename
  local replaced
  prepare_state_dir
  STAGE="$(mktemp -d "$STATE_DIR/staging.XXXXXX")"
  ditto --noextattr --noacl "$BUNDLED" "$STAGE/usbgadget.kext"
  bundle_matches "$STAGE/usbgadget.kext" ||
    die 'The staged copy does not match the pinned build; nothing was installed.'
  chown -R "$OWNER" "$STAGE/usbgadget.kext"
  find "$STAGE/usbgadget.kext" -type d -exec chmod 755 {} +
  find "$STAGE/usbgadget.kext" -type f -exec chmod 644 {} +
  chmod 755 "$STAGE/usbgadget.kext/Contents/MacOS/usbgadget"
  { bundle_matches "$STAGE/usbgadget.kext" && metadata_ok "$STAGE/usbgadget.kext"; } ||
    die 'The staged copy failed verification after setting ownership; nothing was installed.'
  if [[ -d "$TARGET" ]]; then
    replaced="$(mktemp -d "$STATE_DIR/replaced-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
    mv "$TARGET" "$replaced/usbgadget.kext"
    if ! mv "$STAGE/usbgadget.kext" "$TARGET"; then
      mv "$replaced/usbgadget.kext" "$TARGET" ||
        die "CRITICAL: the previous driver could not be restored; it is at $replaced/usbgadget.kext"
      rmdir "$replaced" 2>/dev/null || true
      die 'Could not move the new driver into place; the previous driver was restored.'
    fi
    echo "The previous driver was moved out of $EXTENSIONS to: $replaced/usbgadget.kext"
  else
    mv "$STAGE/usbgadget.kext" "$TARGET"
  fi
  { bundle_matches "$TARGET" && metadata_ok "$TARGET"; } ||
    die "CRITICAL: $TARGET does not match the pinned build after installation; run the installer again."
}

relocate_legacy() { # move leftovers of older mac2jb installers out of /Library/Extensions
  local item moved=''
  for item in "$EXTENSIONS"/.mac2jb-usbgadget-backup-* "$EXTENSIONS"/.mac2jb-driver.*; do
    [[ -e "$item" || -L "$item" ]] || continue
    if [[ -z "$moved" ]]; then
      prepare_state_dir
      moved="$(mktemp -d "$STATE_DIR/legacy-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")"
    fi
    mv "$item" "$moved/"
    echo "Moved a leftover of an older mac2jb installer out of $EXTENSIONS: $moved/${item##*/}"
  done
}

install() {
  local foreign changed=0 load_status
  verify_bundled
  [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die 'Apple Silicon macOS is required.'
  if [[ "$EUID" != 0 ]]; then
    exec sudo /bin/bash "$0"
  fi
  umask 022
  trap cleanup EXIT
  acquire_lock
  # Custom SIP configurations cannot be judged from the status summary. Record it
  # for diagnostics; filesystem permissions and kmutil enforce the actual policy.
  echo 'Current SIP configuration (diagnostic only):'
  csrutil status 2>&1 || true
  foreign="$(foreign_copies)"
  if [[ -n "$foreign" ]]; then
    printf 'Refusing to install: another kext declares %s:\n%s\nRemove it, then run the installer again.\n' \
      "$BUNDLE_ID" "$foreign" >&2
    exit 13
  fi
  if [[ -L "$TARGET" || ( -e "$TARGET" && ! -d "$TARGET" ) || -L "$MARKER" ]]; then
    echo "Refusing to install: $TARGET or its restart marker is not a plain file or folder; inspect it manually." >&2
    exit 13
  fi
  if [[ -d "$TARGET" ]] && bundle_matches "$TARGET" && metadata_ok "$TARGET"; then
    echo "The pinned driver is already installed at $TARGET."
  else
    install_bundle
    changed=1
  fi
  relocate_legacy
  if (( changed == 0 )) && [[ "$(loaded_uuids 2>/dev/null || true)" == "$PIN_UUID" ]]; then
    echo "The pinned driver is installed and loaded (UUID $PIN_UUID). Nothing to do."
    exit 0
  fi
  touch "$MARKER"
  chmod 644 "$MARKER"
  sync
  echo "Pinned driver installed at $TARGET (UUID $PIN_UUID). Restart after macOS approval, then check: scripts/install-driver.sh --status"
  if kmutil load -p "$TARGET"; then
    echo 'Driver load request accepted. Complete any approval/restart prompts and refresh the loaded-driver check.'
  else
    load_status=$?
    echo 'macOS did not accept the driver load request. Review the kmutil error above, kernel-extension policy, and approval/restart requirements. SIP status text alone does not determine compatibility.' >&2
    exit "$load_status"
  fi
}

case "${1:-}" in
  --verify) verify_bundled ;;
  --status) status ;;
  '') install ;;
  *) die 'Usage: install-driver.sh [--verify | --status]' ;;
esac
