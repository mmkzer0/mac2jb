# Commit style

The repository uses one plain-text standard, enforced by `.githooks/commit-msg`.

- Subject: imperative sentence, uppercase first word, at most 72 characters,
  no trailing period, no emoji.
- One blank line between the subject and the body.
- Body prose and bullets wrap at 72 columns. Bullets use `- ` and continuations
  are indented by two spaces. Indented lines, fenced code and lines containing a
  URL are left alone.
- No `Co-Authored-By`, `Signed-off-by`, `Reviewed-by`, `Acked-by` or
  `Change-Id` trailers.
- `fixup!`, `squash!`, `amend!`, `Merge ` and `Revert ` subjects are accepted
  unchanged for interactive rebase and merge commits.
- Lines starting with the comment character (`core.commentChar`, default `#`)
  are left alone, and everything from the `git commit -v` scissors line to the
  end of the file is neither validated nor rewritten.

Enable the hook once per clone:

```sh
bash scripts/install-git-hooks.sh
```

`git commit --no-verify` bypasses the hook for generated commits; do not use it
for normal work.
