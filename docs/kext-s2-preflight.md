# S2 preflight (no SIP change)

Status: the tightened preflight (path-independent build, provenance
verification, KDK content check, resolved private path) passes on the clean
commit `56668dc`. The S2 policy gate was applied on 2026-11-03 and accepted
with one recorded risk: `sip2:true` (CTRR lock disabled), which
`csrutil --without kext` sets unconditionally (`kext-hardening-plan.md` §2,
§7.1). No install, unload or kext load has been performed. Rerun the preflight
before a load attempt.

**Pre-S2 private policy snapshot (2026-11-02):** one UUID node with 42 fields,
mode `0600`, stored outside the repository. It confirms `security_mode:
permissive`, `smb1: true` (Permissive Security), `smb2: false`, `sip0: 0x1014`,
and `auxp/auxi/auxr` absent. Identifiers and hashes are not reproduced. The live
`csrutil status` matched the public SIP bits at that time. The selected target
was to keep Permissive (`smb1:true`) and add `smb2:true`. The originally expected
SIP mask (`0x1005`, `sip2:false`) is not reachable with `csrutil`; the corrected
target is `0x101D` with `sip2:true`. Reduced is not pursued.

**Post-S2 private policy snapshot (2026-11-03):** one UUID node with 42 fields,
mode `0600`, stored outside the repository. It confirms `security_mode:
permissive`, `smb1:true`, `smb2:true`, `sip0: 0x101D`, `sip1:false`,
`sip2:true`, `sip3:false`, and `auxp/auxi/auxr` absent. `spctl kext-consent
list` reports no configuration (exit 0). This matches the corrected target;
`sip2:true` (CTRR lock disabled) is the accepted risk in
`kext-hardening-plan.md` §7.1, valid until the S3 rollback.
Identifiers and hashes are not reproduced.

This is the pre-load check for the S2 policy gate. It does not replace the
mock-IOKit harness or the S3 hardware gate.

## Command

```sh
scripts/kext-s2-preflight.sh
# Optional, after explicit approval; keep the output outside the repository:
scripts/kext-s2-preflight.sh --private-policy-out "$HOME/private/bputil.json"
# Check only the arguments (including the private path) and exit:
scripts/kext-s2-preflight.sh --validate-only --private-policy-out "$HOME/private/bputil.json"
```

The script:

- validates `--private-policy-out` first, before any work: the path must be
  absolute and name a file; its parent directory is resolved with `cd -P` and
  compared by inode (`-ef`) with the repository root and every ancestor
  directory, so `..`, `//`, symlinked directories, symlinked files and
  case variants that resolve into the repository are rejected (exit 2);
- checks the host build and Xcode/SDK;
- validates the KDK for the host build, by content rather than by name
  (`kext-provenance.py kdk-check`): `KDK_<version>_<build>.kdk` must exist,
  its `System/Library/CoreServices/SystemVersion.plist` `ProductVersion` and
  `ProductBuildVersion` must equal `sw_vers`, `System/Library/Kernels/kernel`
  must be a Mach-O file, at least one arm64 `kernel.release.*` Mach-O kernel
  and `System/Library/Extensions` must exist;
- runs the strict source check and the mock harness under ASan+UBSan and
  TSan;
- builds the kext in the tree, then runs
  `kext-provenance.py verify` against `build/kext/provenance.json`
  (see `kext-provenance.md`): it **fails on a dirty tree** (uncommitted or
  untracked changes under the kext source directory or `build-kext.sh`) and on
  any mismatch of artifact, source digest or build script, and it prints the
  commit, dirty flag, source digest, executable hash and the recorded
  Xcode/SDK;
- runs `kext-provenance.py verify-bundle`: the bundled `drivers/usbgadget.kext`
  must be byte-identical to this build, and `drivers/SHA256SUMS` and
  `drivers/PROVENANCE` (digests, LC_UUID, source digest, Xcode/SDK build) must
  match it, so the driver the installer ships is the one just verified;
- exports the build inputs of the working tree into a fresh git repository at
  another path (`build/kext-s2-preflight/path-check/independent copy/mac2jb
  checkout`, which contains a space), builds there, and requires the same
  executable SHA-256 and the same source digest as the in-tree build;
- checks the two-file bundle, `Info.plist`, arm64e and signing state, and runs
  `kmutil print-diagnostics -p <bundle> -z` as a bundle-linkage diagnostic: it
  reports that the declared kext dependencies resolve on this system. It is
  not KDK evidence: the result is identical with no `--kdk`, with an empty
  directory named like a KDK and with a KDK of another release, so it is not
  passed a KDK and is not used to judge one;
- records the public `csrutil status` line (information only) and verifies
  `usbgadget` is not loaded and `/Library/Extensions/usbgadget.kext` is absent;
- optionally captures `sudo bputil -d -j` to a private path outside the
  repository, without printing it;
- prints the rollback commands and verifies they are documented.

`kextutil -tn` is not usable on this host: `kextutil` is a kmutil front end and
rejects `-n`. Use `kmutil print-diagnostics`.

## Result

Run of 2026-11-03 on the clean commit `56668dc` (exit 0, no blockers). The S2
acceptance rerun on `2f1b6db` (after the policy gate, kext source unchanged)
also exits 0 with no blockers and the same source digest and executable hash.
The S3 entry run on `102ed45`, the first commit whose `drivers/` holds the
hardened build, exits 0 with no blockers; its bundled-driver check passes
(byte-identical bundle, `PROVENANCE` matches, LC_UUID
`CF8E2A1A-9710-3430-998D-21A0E845D8B2`).

| Check | Result |
|---|---|
| Host | macOS 27.0 (26A428), arm64 |
| Xcode / SDK | Xcode 27.2 (27B52) / macOS SDK 27.2 (26B118) |
| KDK content | pass: `KDK_27.0_26A428.kdk`, SystemVersion 27.0 / 26A428, 14 arm64 release kernels |
| S1 source gate / harness | pass |
| Path-independent build | pass: the in-tree build and the build from a copy at another path (with a space) have the same executable SHA-256 `de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c5` (109296 bytes) and the same source digest |
| Provenance verify | pass: `dirty=false`, source digest `8987e0c90680e7a1f57e646c0cd8a9a339bced3cf737fec4a37f45e5d09a3e11`, build script and artifact match |
| Bundle | pass: two files, no symlinks, `Info.plist` lint, arm64e, unsigned as built |
| Bundle linkage | pass (`kmutil print-diagnostics`; user-owned and unsigned diagnostics are expected pre-install) |
| Current state | `usbgadget` not loaded; target install path absent; the `csrutil status` line printed `Kext Signing: disabled` (information only) |
| Private LocalPolicy | captured earlier, mode `0600`, outside the repo (see above) |
| Rollback | documented in `kext-hardening-plan.md`; not executed |
| SIP / install / load | the preflight itself changed none; S2 was applied later (see Status) |

A passing preflight therefore requires committing the kext source and
`build-kext.sh` first; the executable hash is a function of the source digest
and the toolchain, not of the commit or the checkout path.

The report is written to `build/kext-s2-preflight/preflight.md`; the build,
verify and harness logs are next to it. These are local artifacts, not release
inputs.

## Next steps

1. S2 is accepted (2026-11-03) with the `sip2` risk acceptance; the S2 negative
   control is `NOT_EXECUTED` and must not be reproduced by a load attempt. S3
   starts only after its entry gate (`kext-hardening-plan.md` §8).
2. Keep the preflight green: rerun it before S3 and after any source,
   toolchain or policy change before a load attempt. To refresh the private
   snapshot, use `--private-policy-out` only with explicit approval; never
   commit it.

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
