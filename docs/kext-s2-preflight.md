# S2 preflight (no SIP change)

Status: executed on 2026-11-02. Blocked before the policy gate by the missing
matching KDK. No SIP change, install, unload or kext load was performed.

This is the pre-load check for the S2 policy gate. It does not replace the
mock-IOKit harness or the S3 hardware gate.

## Command

```sh
scripts/kext-s2-preflight.sh
# Optional, after explicit approval; keep the output outside the repository:
scripts/kext-s2-preflight.sh --private-policy-out "$HOME/private/bputil.json"
```

The script:

- checks the host build, Xcode/SDK, and that a KDK matching the host build
  exists (exactly `KDK_<version>_<build>.kdk`);
- runs the strict source check and the 22-test harness under ASan+UBSan and TSan;
- builds the kext twice from a clean build tree and compares the executable
  hashes;
- checks the two-file bundle, `Info.plist`, arm64e, signing state and
  `kmutil print-diagnostics -z` dependency resolution;
- records the public `csrutil status` line and verifies `usbgadget` is not
  loaded and `/Library/Extensions/usbgadget.kext` is absent;
- optionally captures `sudo bputil -d -j` to a private path outside the
  repository, without printing it;
- prints the rollback commands and verifies they are documented.

`kextutil -tn` is not usable on this host: `kextutil` is a kmutil front end and
rejects `-n`. Use `kmutil print-diagnostics`.

## Result (2026-11-02)

| Check | Result |
|---|---|
| Host | macOS 27.0 (26A428), arm64 |
| Xcode / SDK | Xcode 27.2 / macOS SDK 27.2 |
| Matching KDK | **missing**: installed `KDK_26.0_25A5279m.kdk`; expected `KDK_27.0_26A428.kdk` |
| S1 source gate | pass |
| S1 harness | pass (22 tests, ASan+UBSan and TSan) |
| Reproducible build | pass: two clean builds, 114360 bytes, SHA-256 `644fda29022f7152ab11c029b4bf342160180af364ce8748ad965a0bd0626fd0` |
| Bundle | pass: two files, no symlinks, `Info.plist` lint, arm64e, unsigned as built |
| Load diagnostics | dependencies OK; user-owned and unsigned diagnostics are expected pre-install |
| Current state | `usbgadget` not loaded; target install path absent; `Kext Signing: enabled` |
| Private LocalPolicy | not captured; requires explicit `--private-policy-out` and approval |
| Rollback | documented in `kext-hardening-plan.md`; not executed |
| SIP / install / load | untouched |

The report is written to `build/kext-s2-preflight/preflight.md`; the build and
harness logs are next to it. These are local artifacts, not release inputs.

## Blockers and next steps

1. Install the matching KDK from developer.apple.com. Do not use
   `--allow-missing-kdk`.
2. Rerun the preflight; the KDK check must pass and the summary must say
   `PASS: no preflight blockers`.
3. Capture the full LocalPolicy privately only after explicit approval; never
   commit it (it contains ECID, kuid, vuid and policy hashes).
4. Then run the one recoveryOS S2 policy session from
   `kext-hardening-plan.md` §7. The preflight itself never changes SIP.

## Early S3 non-root probe

The IOKit registry-property boundary cannot be fully tested before the kext is
loaded. As the first S3 boundary check, from an unprivileged account:

1. Write a valid `PublishConfiguration` and `Poke` through the same
   `IORegistryEntrySetCFProperties` path `mac2jb` uses; record whether it is
   accepted.
2. Attempt an unknown property key; record the rejection.
3. Confirm the loaded service remains functional and no panic or stall occurs.

The result is S3 evidence, not a pre-load requirement. See the I7 decision in
`kext-audit.md`.

## Rollback (not executed by the preflight)

The exact unload and removal sequence, including the AuxKC rebuild and the
post-restart checks, is in `kext-hardening-plan.md` §8. A preflight run only
verifies that `kmutil unload -p` and `kmutil install --update-all` are present
in that document and that the target path is currently absent.
