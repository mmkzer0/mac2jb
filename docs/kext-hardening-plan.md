# mac2jb kext hardening plan (S0–S3)

Status: draft, pre-S0
Owner: Lennart
Target: `usbgadget.kext` + `libusbd` in this fork, then one hardware validation on the
primary M4 Pro.

## 1. Scope and non-goals

In scope:

- Reproducible source build of `usbgadget.kext` from `vendor/macos_usb_gadget_poc`.
- Provenance comparison against the shipped `drivers/usbgadget.kext`.
- Lifetime, ownership, thread and error-path fixes in the kext.
- A user-space mock-IOKit harness with fault injection for the lifecycle logic.
- One documented policy change in recoveryOS (Reduced Security + third-party kexts,
  plus the minimal SIP exceptions), then hardware validation.

Out of scope for this plan:

- `mac2nx2` as a separate product/repository.
- Full `csrutil disable` / Permissive flow other than what is already present.
- Developer ID signing, notarization, distribution.
- Two-machine kernel debugging (KDK), KASAN kernels.
- Rewriting the exploit engine.

## 2. Evidence base

Verified on this machine and from Apple primary sources:

- Host: macOS 27.0 (26A428), Xcode 27.2 (27B52), SDK `MacOSX27.2.sdk`.
- `drivers/usbgadget.kext` is a two-file prebuilt
  (`Contents/Info.plist`, `Contents/MacOS/usbgadget`), arm64e, 114008 bytes,
  **not signed at all** (`codesign -dv`: "code object is not signed at all").
- No build script exists in the repository; CI does not build the kext.
- `drivers/SHA256SUMS` and `scripts/audit-release.py` pin the shipped binary hash
  (`a32119c7…` for `Contents/MacOS/usbgadget`).
- The vendored Xcode project builds with the SDK alone; no KDK is needed to build.
  A probe build succeeded in 2.4 s after two overrides:
  `ARCHS=arm64e ONLY_ACTIVE_ARCH=YES MACOSX_DEPLOYMENT_TARGET=12.0`.
  The project's own `MACOSX_DEPLOYMENT_TARGET = 10.11` is rejected by Xcode 27.
- Configuration evidence: a Debug (`-O0`) build of the vendored project under
  Xcode 27.2 produces `__TEXT_EXEC,__text` = 6824 bytes and 428 disassembly
  lines, and its defined-symbol surface matches the shipped binary except four
  header-emitted symbols. The shipped binary (`__text` = 6764 bytes, 424 lines)
  therefore matches a Debug build, not the Release build (`__text` = 5220 bytes,
  328 lines). This explains the size difference without assuming a source
  divergence.
- `MacOSX27.2.sdk/System/Library/Frameworks/Kernel.framework/Headers/IOKit/…`
  provides the kernel headers, so no KDK is needed to **build** the kext.
- A KDK **is** required to rebuild kernel collections on macOS 13 and later:
  `kmutil install` states that a KDK matching the system build is needed to
  rebuild kernel collections, and `kmutil load -p` takes the same path. The
  installed `KDK_26.0_25A5279m.kdk` does not match macOS 27.0 (26A428).
  Install the matching KDK from developer.apple.com/download before S2; do not
  fall back to `--allow-missing-kdk`.

Policy facts (Apple Platform Security):

- Third-party kexts require **Reduced Security** and an explicit opt-in
  (`smb2` in the LocalPolicy), then a per-kext user approval (UAKL), an AuxKC
  rebuild and a reboot.
- `kmd` validates only UAKL entries for AuxKC inclusion. With SIP enabled the
  signature of each kext is verified before inclusion; with SIP disabled it is not.
- `bputil -k/--enable-kexts` enables trust in a locally SEP-signed AuxKC and
  downgrades to Reduced Security if needed.

Current LocalPolicy on the target Mac (relevant fields only; the full dump is
private and must not be published — it contains ECID, kuid, vuid and hashes):

| Field | Value | Meaning |
|---|---|---|
| `smb0` | true | Reduced-or-lower next stage allowed |
| `smb1` | true | Permissive Security active |
| `smb2` | false | **third-party kexts not enabled — the missing gate** |
| `sip0` | 0x1014 | TASK_FOR_PID (0x4), APPLE_INTERNAL (0x10), RESEARCH_GUESTS (0x1000) |
| `sip1..3` | false | SSV check, CTRR, boot-arg filtering enforced |
| `auxp/auxi/auxr` | false | the three AuxKC fields are absent in the current LocalPolicy (see note) |

The three fields are distinct: `auxp` hashes the user-authorized kext list (UAKL)
policy, `auxi` hashes the AuxKC Image4 manifest, `auxr` hashes the AuxKC receipt.
Their absence in the current policy does not prove that an AuxKC was never built;
each field is verified separately in S3 after approval.

`csrutil` bit mapping (verified by disassembly of `csrutil` from macOS 27,
`-[CSRSecurityConfig …]` setters, masks passed to `_setSIPflag:enabled:`):

| CLI name | Setter | SIP mask |
|---|---|---|
| `kext` | `setKextSigningRequired:` | `0x1` `CSR_ALLOW_UNTRUSTED_KEXTS` |
| `fs` | `setFilesystemAccessRestricted:` | `0x2` |
| `debug` | `setDebuggingRestricted:` | `0x4` `CSR_ALLOW_TASK_FOR_PID` only |
| `dtrace` | `setDTraceRestricted:` | `0x20` |
| `nvram` | `setNVRAMAccessRestricted:` | `0x40` |
| (no CLI alias) | `setKernelDebuggingRestricted:` | `0x8` |
| (no CLI alias) | `setResearchGuestAllowed:` | `0x1000` |

Consequences:

- `--without kext` sets `0x1`, i.e. the *unsigned kext* flag. It is not
  `CSR_ALLOW_UNAPPROVED_KEXTS` (0x200).
- `--without debug` sets only `0x4`, which matches the current `sip0`. The
  kernel separately synthesizes `CSR_ALLOW_KERNEL_DEBUGGER` (0x8) in `csr_check()`
  when `0x1` or `0x10` is set (`bsd/kern/kern_csr.c`), so enabling the kext bit
  also implicitly allows kernel debugging. This is documented Apple behavior.
- `CSR_ALLOW_APPLE_INTERNAL` (0x10) is **masked out at boot** on non-IUOU/IUOS
  hardware (`kern_csr.c`). A stored bit therefore does not make it active, and
  no local project can depend on it. Losing it in a rewrite is harmless.
- `csrutil enable --without …` rebuilds the whole mask; unlisted exceptions
  (including research guests) are cleared and must be re-applied explicitly.
- Both repeated flags (`--without debug --without kext`) and comma lists
  (`--without debug,kext`) are accepted; unknown tokens fail with
  `invalid option %s.`

Target state after S2 (expected):

- `smb2: true`
- `sip0 = 0x5` (`kext` + `debug`), or `0x1005` after re-enabling research guests
- `auxp/auxi/auxr` created on the first kext approval
- `Kext Signing: disabled`, `Debugging Restrictions: disabled`, everything else enabled

## 3. Invariants

Kext (must hold on every path):

- I1 No null/uninitialized dereference: `m_pokeLock`,
  `m_configLock`, `m_thread`, `iter`, `pCommandDict`, `pDict`.
- I2 `m_provider` outlives every user-client call: retain in `start`, release in
  `stop`/`clientClose`; `initWithTask` rejects clients that must not exist.
- I3 `m_configuration` is replaced and released under `m_pokeLock` only, and is
  never used after release.
- I4 Thread lifecycle: start only after successful `kernel_thread_start`;
  `stop` waits for `m_threadDone` before `thread_deallocate`; `free` is safe
  after a partially failed `init`.
- I5 Every external entry point validates selector and argument shapes; unknown
  selector returns `kIOReturnUnsupported`.
- I6 No path continues after an allocation or lock failure; failures are
  reported, not swallowed.
- I7 The user client is restricted to the owning/privileged client (design
  decision to record; today `initWithTask` ignores the client identity).
- I8 `setProperties` validates dictionary shape and rejects unexpected keys.
- I9 Exactly-once teardown: every caller order of `clientClose`, `stop` and
  `free` releases each owned object exactly once; no double release, no use
  after free.
- I10 No teardown deadlock: never wait for `m_threadDone` while holding a lock
  the worker needs to make progress; teardown order is client, provider, thread,
  lock.
- I11 Publication atomicity: the `PublishConfiguration` registry write and the
  private `m_configuration` commit are serialized by `m_configLock`; the worker
  only swaps/reads under `m_pokeLock`, and the lock order is publication then
  poke.

Host:

- H1 The installed kext is the one built from reviewed source, with a recorded
  hash and provenance record.
- H2 Install → approve → AuxKC rebuild → reboot is documented and repeatable.
- H3 Rollback removes the kext from the AuxKC and restores the previous
  LocalPolicy/SIP state.

## 4. Branch topology

- `main` — mirror of `origin/main`; never commit.
- `dev` — integration branch, rebased on `origin/main`.
- `harden/kext-build` — S0.
- `harden/kext-lifetime` — S1.
- `harden/kext-policy-gate` — S2 (documentation + scripts only).

Downstream patches to vendored code follow the existing convention:
`vendor/README.md` records the change, `upstream.lock` keeps the upstream pin.

## 5. S0 — build and provenance (no SIP change)

Deliverables:

- `scripts/build-kext.sh`:
  - copies `vendor/macos_usb_gadget_poc/usbgadget` to `build/kext/src`,
  - runs `xcodebuild` Release with `ARCHS=arm64e ONLY_ACTIVE_ARCH=YES`
    `CODE_SIGNING_ALLOWED=NO` (the project itself supplies the deployment
    target; no override on the command line),
  - writes the kext to `build/kext/usbgadget.kext` and the log to
    `build/kext/build.log`,
  - validates the bundle: exactly two files
    (`Contents/Info.plist`, `Contents/MacOS/usbgadget`), no symlinks, no
    `Contents/Resources` directory, arm64e Mach-O, `plutil -lint`, bundle
    identifier/type/executable, signing state,
  - optional ad-hoc signing (`--adhoc-sign`) behind an explicit flag,
  - prints the artifact hash.
- Project patch: set `MACOSX_DEPLOYMENT_TARGET = 12.0` in the pbxproj so the
  build does not silently depend on command-line overrides, and remove the
  `Info.plist` Copy Bundle Resources entry. The latter is required, not
  cosmetic: without it the build emits a third file,
  `Contents/Resources/Info.plist`, which the shipped bundle does not contain.
  The downstream change is recorded in `vendor/README.md`.
- `scripts/kext-provenance.py`:
  - `record` writes `build/kext/provenance.json` (source tree hash over all
    files under `vendor/macos_usb_gadget_poc/usbgadget`, toolchain and host,
    artifact hashes, signing state),
  - `report` prints a deterministic Markdown comparison against
    `drivers/usbgadget.kext` (size, signing, Mach-O arch, undefined and defined
    symbols, sections, meaningful strings of at least 8 bytes).
- The report also explains the configuration difference: the shipped binary
  matches a Debug (`-O0`) build of the same source under the current toolchain,
  while the S0 artifact is a Release build (§2, `docs/kext-provenance.md`).
- `docs/kext-provenance.md`: captured output of `report`, with the explicit
  statement that byte-identical reproduction is **not** claimed
  (shipped: Xcode 2660 / SDK 26.5; ours: Xcode 27.2 / SDK 27.2).
- Do **not** touch `drivers/usbgadget.kext`, `drivers/SHA256SUMS` or
  `scripts/audit-release.py` in S0.

Acceptance:

- `bash scripts/build-kext.sh` succeeds from a clean checkout.
- Artifact is arm64e and unsigned (or ad-hoc signed), and its file list is
  exactly `Contents/Info.plist` and `Contents/MacOS/usbgadget`.
- `python3 scripts/kext-provenance.py record …` writes valid JSON;
  `… report …` produces `docs/kext-provenance.md` without absolute paths.
- `scripts/audit-release.py` still passes with the untouched shipped binary.
- `docs/kext-provenance.md` explains every difference to the shipped binary.

## 6. S1 — audit fixes and harness (no SIP change)

Findings to fix (all in `vendor/macos_usb_gadget_poc/usbgadget/usbgadget/`):

| ID | Location | Problem |
|---|---|---|
| F1 | `usbgadget.cpp` `setProperties` | On `OSCollectionIterator::withCollection()` failure the code jumps to `exit` and calls `iter->release()` with `iter == NULL` → kernel null deref under memory pressure |
| F2 | `usbgadget_userclient.cpp` | `m_provider` is never retained/released and there is no `clientClose`/`stop` pair; a client outliving the driver is a use-after-free window |
| F3 | `usbgadget.cpp` `init`/`free` | `IOLockAlloc()` result unchecked (`IOLockLock(NULL)`); `free()` calls `thread_deallocate` without waiting for `m_threadDone`; `m_thread` is uninitialized if `kernel_thread_start` failed |
| F4 | `usbgadget.cpp` `doUpdate`/`free` | `OSDictionary::withCapacity(1)` unchecked; `m_configuration` release is commented out in `free()` (leak); `setProperties` leaks the `poke_string` `OSSymbol` |
| F5 | `usbgadget_userclient.cpp` `initWithTask` | No privilege/identity check and the client `type` is ignored; every local process can open the user client (today only selector 0 = re-apply) |
| F6 | `usbgadget.cpp` `start`/`stop` | `registerService()` runs before the provider check; provider is not retained across `doUpdate` |

Fix direction: fail closed, validate once at the boundary, single owner per
object, explicit teardown order (client → provider → thread → lock), no silent
continuation after allocation failure.

Harness:

- `tests/kext/` (new): user-space shim for `OSObject`, `OSDictionary`,
  `OSString`, `OSNumber`, `OSArray`, `IOLock`, `IOService`, `kernel_thread_start`,
  `thread_deallocate`, `IOSleepWithLeeway`, `OSDynamicCast`.
- Compile the real `usbgadget.cpp` and `usbgadget_userclient.cpp` against the
  shim; run deterministic lifecycle scenarios:
  init/start/stop/free, user-client open/close vs unload, `setProperties`
  before/after start, repeated poke, allocation failures at each allocation
  site, thread-start failure, double stop/free, every ordering of
  `clientClose`/`stop`/`free` with exactly-once release assertions, and a
  no-deadlock interleaving where teardown waits for the worker while a poke
  holds the lock.
- Fault injection is part of the shim, not of the kernel.
- ASan/UBSan on the harness; TSan on the harness for lock/thread interleavings.
- User space: ASan/UBSan builds of `sender.c`, `keyboard.c`, `commands.c` and the
  existing `scripts/test-usb-controller-ownership.c` harness.

Static checks:

- `clang --analyze` with the SDK kernel headers on both translation units.
- Warnings as errors for the kext TU:
  `-Wall -Wextra -Werror -Wconversion -Wshorten-64-to-32 -Wnull-dereference`.
- `codesign -d`, `otool -hL` and plausibility checks on the artifact.

Not achievable (state explicitly, do not promise):

- ASan/TSan instrumentation inside the real kernel.
- Memory-safety proof for the kext; only reviewed invariants plus harness
  coverage of the modeled paths.
- KASAN (requires a development kernel from the KDK; out of scope).

Acceptance:

- All harness scenarios pass with fault injection.
- No analyzer finding of class A (null deref, UAF, uninit use) remains.
- Each F1–F6 either fixed with a test or explicitly accepted with rationale.
- `docs/kext-audit.md` records findings, fixes, residual risk.

## 7. S2 — policy gate (one recoveryOS session)

Preflight (no policy change): run `scripts/kext-s2-preflight.sh` and keep the
report in `build/kext-s2-preflight/`. The script checks the host/toolchain, the
matching KDK, the S1 strict/harness gates, two clean builds for reproducibility,
bundle and dependency diagnostics, the public SIP state, and rollback
readiness. It never changes SIP, installs, unloads or loads. The current result
is recorded in `kext-s2-preflight.md`: the preflight passes with the matching
KDK; the private LocalPolicy snapshot is captured and matches the documented
Permissive baseline. The policy gate itself remains pending; `smb2:true` is
still missing, and the Reduced-versus-Permissive target needs an explicit
decision.

Preconditions: S1 accepted and the preflight report says `PASS: no preflight
blockers`; a KDK matching macOS 27.0 (build 26A428) installed; full
`bputil -d -j` output stored privately (not in the repository, not in a
public issue).

Steps, in this order:

1. Enter recoveryOS/1TR.
2. Enable third-party kexts: Startup Security Utility → Reduced Security +
   "Allow user management of kernel extensions from identified developers"
   (or `bputil -k`, which also downgrades to Reduced Security). Goal: `smb2: true`.
3. Set the minimal SIP mask: `csrutil enable --without debug,kext`
   (alternative spelling: `--without debug --without kext`).
   Expected `sip0 = 0x5`.
4. Re-enable research guests if they are needed: `csrutil allow-research-guests enable`
   (expected `sip0 = 0x1005`).
5. Restart.

Verification after boot:

- `csrutil status` → `Kext Signing: disabled`, `Debugging Restrictions: disabled`,
  all other protections enabled, `Authenticated Root: enabled`.
- `csrutil allow-research-guests status`.
- `sudo bputil -d -j` → `smb2: true`, `sip0` as expected, `auxp/auxi/auxr` still
  absent until the kext is approved.
- `spctl kext-consent list` before and after approval.

Open empirical question (the only one that can invalidate the plan):

- Whether `kmd` treats the partial SIP kext bit (`0x1`) as "SIP off" for
  signature verification during AuxKC generation. Apple's wording is "If SIP is
  turned off"; the flag name and the `csrutil` mapping say `--without kext`.
  Failure signature to capture: the exact `kmutil load -p` error. Fallback
  options, in order: ad-hoc sign the built kext; sign with the available Apple
  Development identity (likely insufficient for `kmd`); temporarily Permissive.
- Note: `Kext Signing: disabled` plus `0x1` also synthesizes kernel-debugger
  permission via `csr_check()`. Accept and record; do not add 0x8 explicitly.

Acceptance:

- `smb2: true`, expected `sip0`, research guests state recorded.
- Negative control captured: what `kmutil load -p` reports for the shipped
  unsigned kext before the policy change (expected: policy/signature failure).

## 8. S3 — hardware validation

Order:

1. Install the S0/S1-built kext into `/Library/Extensions` with the hardened
   installer (SIP untouched by the script).
2. Approve it in System Settings → Privacy & Security; wait for the AuxKC rebuild;
   reboot.
3. `kmutil showloaded --list-only | grep usbgadget` and `kmutil showloaded --show-kernel`.
4. Early S3 non-root boundary probe: from an unprivileged account, write a
   valid `PublishConfiguration` and `Poke` through the host's
   `IORegistryEntrySetCFProperties` path, record whether it is accepted, attempt
   an unknown key and record the rejection. This runs only after the kext is
   loaded and is not a pre-load gate.
5. Boundary tests: repeated load/unload cycles, poke storm from a second
   process, `setProperties` during teardown, unplug during active transfers.
6. Functional test: mac2jb typing flow against the Switch with the kurumuz host,
   up to 4/4 verification.
7. Capture `log show` for the kext subsystem and any panic report.

Rollback (unload is not removal):

`kmutil unload -p` stops the kext lifecycle, but the extension stays in the
AuxKC that was built at approval time until the collection is rebuilt and the
Mac restarts. Rollback therefore needs two separate proofs:

1. Unload: `sudo kmutil unload -p /Library/Extensions/usbgadget.kext`, restart,
   then `kmutil showloaded --list-only | grep usbgadget` must be empty.
2. Removal: delete `/Library/Extensions/usbgadget.kext`, rebuild the AuxKC with
   `sudo kmutil install --update-all`, restart, then verify both:
   - `kmutil showloaded --show all --collection aux --list-only | grep usbgadget`
     is empty (neither loaded nor present in the AuxKC),
   - `kmutil showloaded --show unloaded --list-only | grep usbgadget` is empty.
3. SIP: in recoveryOS `csrutil enable --without debug`, then
   `csrutil allow-research-guests enable` if it was previously on.
4. LocalPolicy: restore `smb2` only if the kext capability must be withdrawn.

Acceptance:

- Kext loads from the reviewed build, the typing flow works, no panic.
- The early non-root probe results are recorded: accepted host path,
  rejected unknown key.
- Every rollback step executed at least once and documented.

## 9. Risks and open questions

- `kmd` behavior with partial SIP (see S2) — empirical.
- UAKL approval for an unsigned kext may be refused; `spctl kext-consent add`
  needs a team id from a signed kext.
- SDK 27.2 build running on 27.0 (26A428): version skew; document, do not assume.
- Apple marks kexts as deprecated and to be removed for future Apple silicon
  Macs; this plan targets the current OS only.
- The vphone setup may depend on `Research Guests` (claim to verify against the
  vphone docs before S2; the plan re-enables it regardless and verifies).
- The Apple Development identity (`VL6526N68N`) is not a Developer ID; do not
  build the plan on it.

## 10. Privacy

Do not commit or publish:

- full `bputil -d -j` output (ECID, kuid, vuid, policy hashes),
- `runs/` directories and SmileBASIC session logs,
- kext approval receipts and User-Authorized Kext List contents beyond counts.

## 11. References

- Apple Platform Security: "Securely extending the kernel in macOS",
  "Startup Disk security policy control", "Contents of a LocalPolicy file".
- Apple Developer: "Installing a custom kernel extension".
- XNU `bsd/sys/csr.h`, `bsd/kern/kern_csr.c` (Apple OSS).
- `csrutil` RE notes: feature table at `__DATA` `0x100024a88` (6 entries,
  name/status name/setter thunk), `-[CSRSecurityConfig …]` setters pass the
  masks listed in §2.
