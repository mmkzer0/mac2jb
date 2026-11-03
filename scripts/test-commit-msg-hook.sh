#!/bin/bash
# Tests .githooks/commit-msg on message files and through real `git commit` runs.
# COMMIT_MSG_HOOK overrides the hook under test.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_HOOK="${COMMIT_MSG_HOOK:-$ROOT/.githooks/commit-msg}"
[[ -f "$SOURCE_HOOK" ]] || { echo "missing hook: $SOURCE_HOOK" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/mac2jb-commit-msg.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Isolate from user and system git configuration.
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@example.invalid

mkdir -p "$TMP/hooks"
cp "$SOURCE_HOOK" "$TMP/hooks/commit-msg"
chmod +x "$TMP/hooks/commit-msg"
HOOK="$TMP/hooks/commit-msg"

REPO="$TMP/repo"
git init -q "$REPO"
git -C "$REPO" config core.hooksPath "$TMP/hooks"

FAILED=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }

# run_hook FILE: run the hook from inside the repository, as git does.
run_hook() { (cd "$REPO" && "$HOOK" "$1" 2>"$TMP/stderr"); }

# expect_unchanged NAME FILE: the hook accepts FILE and leaves it byte for byte.
expect_unchanged() {
  local name="$1" file="$2"
  cp "$file" "$file.orig"
  if run_hook "$file" && cmp -s "$file" "$file.orig"; then pass "$name"; else fail "$name"; fi
}

# expect_rejected NAME FILE
expect_rejected() {
  local name="$1" file="$2"
  if run_hook "$file"; then fail "$name (accepted)"; else pass "$name"; fi
}

# expect_output NAME FILE EXPECTED: the hook accepts FILE and rewrites it to EXPECTED.
expect_output() {
  local name="$1" file="$2" expected="$3"
  if run_hook "$file" && cmp -s "$file" "$expected"; then pass "$name"; else fail "$name"; fi
}

LONGPATH='vendor/macos_usb_gadget_poc/usbgadget/usbgadget.xcodeproj/project.pbxproj'
LONGLINE='This line is intentionally far longer than seventy-two columns and must never be wrapped or checked.'

template() { # template CC
  printf '%s Please enter the commit message for your changes. Lines starting\n' "$1"
  printf '%s with the comment character will be ignored.\n' "$1"
  printf '%s\n%s Changes to be committed:\n%s\tnew file:   %s\n%s\n' "$1" "$1" "$1" "$LONGPATH" "$1"
}

scissors_section() { # scissors_section CC
  printf '%s ------------------------ >8 ------------------------\n' "$1"
  printf '%s Do not modify or remove the line above.\n' "$1"
  printf 'diff --git a/x b/x\n+%s   \n+\tindented\t\n+no newline at end of file' "$LONGLINE"
}

# --- Comment lines -------------------------------------------------------
{ printf 'Add the project file\n\nBody line.\n\n'; template '#'; } >"$TMP/m"
expect_unchanged "template comments with a long staged path are accepted and preserved" "$TMP/m"

{ printf 'Add the project file\n'; template '#'; } >"$TMP/m"
expect_unchanged "subject directly followed by the template is accepted" "$TMP/m"

{ printf '\n'; template '#'; } >"$TMP/m"
expect_unchanged "comment-only message is left for git to reject" "$TMP/m"

{
  printf 'Add the project file\n\nThis paragraph is deliberately written across two physical lines that are\n'
  printf 'far longer than seventy-two columns once joined, so the hook reflows it.\n\n'
  template '#'
} >"$TMP/m"
{
  printf 'Add the project file\n\nThis paragraph is deliberately written across two physical lines that\n'
  printf 'are far longer than seventy-two columns once joined, so the hook reflows\nit.\n\n'
  template '#'
} >"$TMP/expected"
expect_output "body above template comments is reflowed and comments are preserved" "$TMP/m" "$TMP/expected"

{ printf 'Add the project file\n\nBody line.\n\n'; template ';'; } >"$TMP/m"
git -C "$REPO" config core.commentChar ';'
expect_unchanged "custom core.commentChar ';' template comments are preserved" "$TMP/m"
{ printf 'Add the project file\n\nBody line.\n\n;\tnew file:   %s\n' "$LONGPATH"; scissors_section ';'; } >"$TMP/m"
expect_unchanged "custom core.commentChar ';' scissors section is untouched" "$TMP/m"
git -C "$REPO" config --unset core.commentChar
git -C "$REPO" config core.commentChar auto
{ printf 'Add the project file\n\nBody line.\n\n'; template '#'; } >"$TMP/m"
expect_unchanged "core.commentChar auto uses '#'" "$TMP/m"
git -C "$REPO" config --unset core.commentChar

# --- Scissors section ----------------------------------------------------
{ printf 'Add the project file\n\nBody line.\n\n'; template '#'; scissors_section '#'; } >"$TMP/m"
expect_unchanged "scissors section is not validated or reformatted" "$TMP/m"

{
  printf 'Add the project file\n\nThis paragraph is deliberately written across two physical lines that are\n'
  printf 'far longer than seventy-two columns once joined, so the hook reflows it.\n\n'
  template '#'; scissors_section '#'
} >"$TMP/m"
{
  printf 'Add the project file\n\nThis paragraph is deliberately written across two physical lines that\n'
  printf 'are far longer than seventy-two columns once joined, so the hook reflows\nit.\n\n'
  template '#'; scissors_section '#'
} >"$TMP/expected"
expect_output "scissors section survives byte for byte while the message above is reflowed" "$TMP/m" "$TMP/expected"

{ printf 'Add the project file\n'; scissors_section '#'; printf '\r\n\xff\xfe\n'; } >"$TMP/m"
expect_unchanged "non-UTF-8 and CRLF bytes after the scissors line are preserved" "$TMP/m"

{ scissors_section '#'; } >"$TMP/m"
expect_unchanged "scissors-only message is left for git to reject" "$TMP/m"

# --- Subject prefixes ----------------------------------------------------
LONGSUBJECT='this subject is much longer than seventy-two characters, lowercase and ends with a period.'
for prefix in 'fixup! ' 'squash! ' 'amend! ' 'Merge ' 'Revert '; do
  { printf '%s%s\n\n%s\n- %s\n\n' "$prefix" "$LONGSUBJECT" "$LONGLINE" "$LONGLINE"; template '#'; } >"$TMP/m"
  expect_unchanged "long '${prefix% }' subject is accepted and the body is not reflowed" "$TMP/m"
done
{ printf 'Merge branch '"'"'x'"'"'\n\n* x: Add the rocket \xf0\x9f\x9a\x80 feature\n'; } >"$TMP/m"
expect_unchanged "emoji in a generated Merge message is accepted" "$TMP/m"
{ printf 'fixup! Add the project file\n\nSigned-off-by: A <a@example.invalid>\n'; } >"$TMP/m"
expect_rejected "trailer in a fixup! message is rejected" "$TMP/m"

# --- Normal messages -----------------------------------------------------
printf 'A%.0s' $(seq 1 72) >"$TMP/m"; printf '\n' >>"$TMP/m"
expect_unchanged "72-character subject is accepted" "$TMP/m"
printf 'A%.0s' $(seq 1 73) >"$TMP/m"; printf '\n' >>"$TMP/m"
expect_rejected "73-character subject is rejected" "$TMP/m"
printf 'Add the project file.\n' >"$TMP/m"
expect_rejected "trailing period is rejected" "$TMP/m"
printf 'add the project file\n' >"$TMP/m"
expect_rejected "lowercase subject is rejected" "$TMP/m"
printf 'Add the project file\nbody directly below\n' >"$TMP/m"
expect_rejected "missing blank line after the subject is rejected" "$TMP/m"
printf 'Add the project file\n\nBody.\n\nSigned-off-by: A <a@example.invalid>\n' >"$TMP/m"
expect_rejected "Signed-off-by trailer is rejected" "$TMP/m"
printf 'Add the project file\n\nBody.\n\nCo-Authored-By: A <a@example.invalid>\n' >"$TMP/m"
expect_rejected "Co-Authored-By trailer is rejected" "$TMP/m"
printf 'Add the project file \xf0\x9f\x9a\x80\n' >"$TMP/m"
expect_rejected "emoji in the subject is rejected" "$TMP/m"
{
  printf 'Reflow the prose body\n\nThis paragraph is deliberately written across two physical lines that are\n'
  printf 'far longer than seventy-two columns once joined, so the hook reflows it.\n\n'
  printf -- '- first bullet holds enough words to need a continuation line when it is wrapped at the limit\n'
  printf '  and continues here\n- short bullet\n'
} >"$TMP/m"
{
  printf 'Reflow the prose body\n\nThis paragraph is deliberately written across two physical lines that\n'
  printf 'are far longer than seventy-two columns once joined, so the hook reflows\nit.\n\n'
  printf -- '- first bullet holds enough words to need a continuation line when it is\n'
  printf '  wrapped at the limit and continues here\n- short bullet\n'
} >"$TMP/expected"
expect_output "prose is reflowed to 72 columns with '- ' bullets and 2-space continuations" "$TMP/m" "$TMP/expected"
FENCE='```'
{ printf 'Keep URLs and code\n\nSee https://example.invalid/%s for details\n\n    %s\n\n%s\nshort   fenced   line\n%s\n' \
    "$(printf 'x%.0s' $(seq 1 80))" "$LONGLINE" "$FENCE" "$FENCE"; } >"$TMP/m"
expect_unchanged "URL, indented and fenced lines are exempt from wrapping" "$TMP/m"

# --- End to end through git commit --------------------------------------
cat >"$TMP/editor.sh" <<'EOF'
#!/bin/bash
# Replaces the template's blank first line with $EDITOR_SUBJECT.
{ printf '%s\n' "$EDITOR_SUBJECT"; tail -n +2 "$1"; } >"$1.new"
mv "$1.new" "$1"
EOF
chmod +x "$TMP/editor.sh"

E2E="$TMP/e2e"
git init -q "$E2E"
git -C "$E2E" config core.hooksPath "$TMP/hooks"
mkdir -p "$E2E/$(dirname "$LONGPATH")"
printf 'one\n' >"$E2E/$LONGPATH"
git -C "$E2E" add .

e2e_commit() { # e2e_commit SUBJECT [git commit options...]
  local subject="$1"; shift
  (cd "$E2E" && EDITOR_SUBJECT="$subject" GIT_EDITOR="$TMP/editor.sh" git commit "$@" >"$TMP/commit.out" 2>&1)
}

if e2e_commit 'Add the long path file'; then
  if [[ "$(git -C "$E2E" log -1 --format=%B)" == "Add the long path file" ]]; then
    pass "git commit with an editor template listing a long staged path succeeds"
  else
    fail "git commit message was not the typed subject"
  fi
else
  fail "git commit with an editor template listing a long staged path"; cat "$TMP/commit.out"
fi

printf 'two\n' >"$E2E/$LONGPATH"
printf 'x%.0s' $(seq 1 100) >>"$E2E/$LONGPATH"; printf '\n' >>"$E2E/$LONGPATH"
git -C "$E2E" add .
if e2e_commit 'Change the long path file' -v; then
  if [[ "$(git -C "$E2E" log -1 --format=%B)" == "Change the long path file" ]]; then
    pass "git commit -v with a long diff after the scissors line succeeds"
  else
    fail "git commit -v stored more than the typed subject"
  fi
else
  fail "git commit -v with a long diff after the scissors line"; cat "$TMP/commit.out"
fi

printf 'three\n' >"$E2E/$LONGPATH"
git -C "$E2E" add .
git -C "$E2E" config core.commentChar ';'
if e2e_commit 'Change the file again'; then
  if [[ "$(git -C "$E2E" log -1 --format=%B)" == "Change the file again" ]]; then
    pass "git commit with core.commentChar ';' succeeds"
  else
    fail "git commit with core.commentChar ';' stored extra lines"
  fi
else
  fail "git commit with core.commentChar ';'"; cat "$TMP/commit.out"
fi
git -C "$E2E" config --unset core.commentChar

printf 'four\n' >"$E2E/$LONGPATH"
git -C "$E2E" add .
if e2e_commit "$(printf 'A%.0s' $(seq 1 73))"; then
  fail "git commit with a 73-character subject was accepted"
else
  pass "git commit with a 73-character subject is rejected"
fi
git -C "$E2E" reset -q --hard

# Conflicted merge: git lists the conflicted paths in "# Conflicts:" comments.
git -C "$E2E" checkout -q -b side
printf 'side\n' >"$E2E/$LONGPATH"
git -C "$E2E" commit -q -a --no-verify -m 'Side change'
git -C "$E2E" checkout -q -
printf 'main\n' >"$E2E/$LONGPATH"
git -C "$E2E" commit -q -a --no-verify -m 'Main change'
if (cd "$E2E" && git merge side >/dev/null 2>&1); then
  fail "expected a conflicting merge"
else
  printf 'resolved\n' >"$E2E/$LONGPATH"
  git -C "$E2E" add .
  if (cd "$E2E" && GIT_EDITOR=true git commit >"$TMP/commit.out" 2>&1) \
      && [[ "$(git -C "$E2E" log -1 --format=%s)" == "Merge branch 'side'"* ]]; then
    pass "conflicted merge commit with a long path in the Conflicts comments succeeds"
  else
    fail "conflicted merge commit"; cat "$TMP/commit.out"
  fi
fi

if (( FAILED )); then
  echo "commit-msg hook tests failed" >&2
  exit 1
fi
echo "commit-msg hook tests passed"
