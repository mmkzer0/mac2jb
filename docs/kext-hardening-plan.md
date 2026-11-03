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
- One documented policy change in recoveryOS (keep the existing Permissive
  Security, enable third-party kexts, and set the minimal SIP exceptions), then
  hardware validation. The stricter Reduced variant remains documented as the
  general alternative.

Out of scope for this plan:

- `mac2nx2` as a separate product/repository.
- Full `csrutil disable` / Permissive flow other than what is already present.
- Developer ID signing, notarization, distribution.
- Two-machine kernel debugging (KDK), KASAN kernels.
- Rewriting the exploit engine.

## 2. Evidence base

Verified on this machine and from Apple primary sources:

- Host: macOS 27.0 (26A428), Xcode 27.2 (27B52), SDK `MacOSX27.2.sdk`.
- Until 2026-11-03, `drivers/usbgadget.kext` was the upstream two-file prebuilt
  (`Contents/Info.plist`, `Contents/MacOS/usbgadget`), arm64e, 114008 bytes,
  **not signed at all** (`codesign -dv`: "code object is not signed at all").
  Since then it is the pinned hardened build (§8).
- No build script existed in the repository; CI does not build the kext.
- `drivers/SHA256SUMS` and `scripts/audit-release.py` pinned the upstream binary
  hash (`a32119c7…` for `Contents/MacOS/usbgadget`).
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

- Third-party kexts require **Reduced Security or lower** and an explicit opt-in
  (`smb2` in the LocalPolicy), then a per-kext user approval (UAKL), an AuxKC
  rebuild and a reboot. The selected target keeps the already-present Permissive
  mode; the stricter Reduced variant would also satisfy the requirement.
- `kmd` validates only UAKL entries for AuxKC inclusion. With SIP enabled the
  signature of each kext is verified before inclusion; with SIP disabled it is not.
- `bputil -k/--enable-kexts` enables trust in a locally SEP-signed AuxKC and
  downgrades to Reduced Security if needed.

Pre-S2 LocalPolicy baseline (2026-11-02; relevant fields only; the full dump
is private and must not be published — it contains ECID, kuid, vuid and
hashes):

| Field | Value | Meaning |
|---|---|---|
| `smb0` | true | Reduced-or-lower next stage allowed |
| `smb1` | true | Permissive Security active |
| `smb2` | false | third-party kexts not enabled in the pre-S2 baseline |
| `sip0` | 0x1014 | TASK_FOR_PID (0x4), APPLE_INTERNAL (0x10), RESEARCH_GUESTS (0x1000) |
| `sip1..3` | false | SSV check, CTRR, boot-arg filtering enforced |
| `auxp/auxi/auxr` | false | the three AuxKC fields are absent in the baseline (see note) |

The three fields are distinct: `auxp` hashes the user-authorized kext list (UAKL)
policy, `auxi` hashes the AuxKC Image4 manifest, `auxr` hashes the AuxKC receipt.
Their absence in the baseline does not prove that an AuxKC was never built;
each field is verified separately in S3 after approval.

Post-S2 LocalPolicy (2026-11-03; same 42-field schema, full dump private):

| Field | Value | Meaning |
|---|---|---|
| `security_mode` | permissive | Permissive Security |
| `smb0` | true | Reduced-or-lower next stage allowed |
| `smb1` | true | Permissive Security active |
| `smb2` | true | third-party kexts enabled |
| `sip0` | 0x101D | 0x1000 research + 0x10 Apple Internal + 0x8 kernel debugger + 0x4 task_for_pid + 0x1 untrusted kexts |
| `sip1` | false | SSV root-hash verification enforced |
| `sip2` | true | CTRR lock disabled by iBoot; set by `--without kext`, accepted risk (§7.1) |
| `sip3` | false | boot-arg allow list enforced |
| `auxp/auxi/auxr` | absent | no UAKL/AuxKC approval yet |

All three extra bits come from `csrutil --without kext` itself (mapping below):
`0x1` and `0x8` are stored, and `sip2` is set. `0x10` is `csrutil`'s default and
was already in the baseline. `csrutil status` reports CTRR as `Kernel Integrity
Protections` (observed `disabled` with `sip2:true` after S2), `sip3` as
`Boot-arg Restrictions` and `sip1` as `Authenticated Root Requirement`; the
private `bputil` dump stays the authoritative record of the raw fields.

`csrutil` bit mapping (disassembly of `/usr/bin/csrutil`, macOS 27.0 `26A428`,
SHA-256 `9757bba7656bd3111d5177314eb02faecede9f4ab4c2be08fbd913c9de4b3d7b`;
`-[CSRSecurityConfig …]` setters). The configuration is `{u64 sip0; bool sip1;
bool sip2; bool sip3}` at `self+8`, passed to `bootpolicy_get/update_sip_flags`:

| CLI name | Setter | Effect when the restriction is lifted |
|---|---|---|
| `kext` | `setKextSigningRequired:` | `0x1` `CSR_ALLOW_UNTRUSTED_KEXTS`, then `setKernelDebuggingRestricted:NO` |
| `fs` | `setFilesystemAccessRestricted:` | `0x2` |
| `debug` | `setDebuggingRestricted:` | `0x4` `CSR_ALLOW_TASK_FOR_PID` only |
| `dtrace` | `setDTraceRestricted:` | `0x20`, then `setCTRREnforcementRequired:NO` |
| `nvram` | `setNVRAMAccessRestricted:` | `0x40` |
| (no CLI alias) | `setKernelDebuggingRestricted:` | `0x8`, then `setCTRREnforcementRequired:NO` |
| (no CLI alias) | `setCTRREnforcementRequired:` | `sip2` (`self+0x11`) |
| (`authenticated-root`, alias not traced) | `setARVSealingRequired:` | `sip1` (`self+0x10`) and `0x800` |
| (no CLI alias) | `setBootArgFilteringEnabled:` | `sip3` (`self+0x12`) |
| (no CLI alias) | `setResearchGuestAllowed:` | `0x1000` |

Consequences:

- `--without kext` always produces `0x1 | 0x8` and `sip2:true`. No `csrutil`
  invocation yields the unsigned-kext bit with CTRR locked, and `bputil` cannot
  re-enable CTRR: it only has `-c` to disable it, and `-n`/`-g` recreate the
  policy without any `sip0`. CTRR stays locked only for a kext with
  a kext-enabled Developer ID signature (no `0x1`), which §1 excludes.
- `0x1` is the *unsigned kext* flag, not `CSR_ALLOW_UNAPPROVED_KEXTS` (0x200).
- `--without debug` sets only `0x4`. The kernel additionally synthesizes
  `CSR_ALLOW_KERNEL_DEBUGGER` (0x8) in `csr_check()` when `0x1` or `0x10` is set
  (`bsd/kern/kern_csr.c`), but with `--without kext` the bit is stored anyway.
- `-[CSRSecurityConfig init]` starts with `sip0 = 0x10`
  (`CSR_ALLOW_APPLE_INTERNAL`). The kernel masks this bit at boot on non-IUOU/IUOS
  hardware (`kern_csr.c`), so it is stored but never active.
- `csrutil enable --without …` rebuilds the whole mask; unlisted exceptions
  (including research guests) are cleared and must be re-applied explicitly.
- Both repeated flags (`--without debug --without kext`) and comma lists
  (`--without debug,kext`) are accepted; unknown tokens fail with
  `invalid option %s.`
- The same chain is present in the recoveryOS copy that 1TR runs: the paired
  `arm64eBaseSystem.dmg` (build `26A428`) ships a thin arm64e `csrutil`, SHA-256
  `b53cb649a1320e1aa0c9ef0aef960e4daf465dd91de58d84cbcac070a6185557`. Its
  `setKextSigningRequired:` → `setKernelDebuggingRestricted:` →
  `setCTRREnforcementRequired:` chain, its `sip2` offset (`self+0x11`) and its
  `init` default (`0x10`) match the universal macOS binary.
- Scope: this covers `csrutil` and `bputil`. Apple documents the Startup
  Security Utility kext checkbox as setting `smb2`; it was not disassembled. A
  program that writes the LocalPolicy through `libbootpolicy` directly is not a
  supported path and is not considered.

Target state after S2 (selected Permissive variant, corrected 2026-11-03):

- `security_mode: permissive`, `smb1: true` (unchanged)
- `smb2: true`
- `sip0 = 0x101D` with research guests retained, otherwise `0x1D`
- `sip1: false`, `sip2: true` (accepted risk, §7.1), `sip3: false`
- `auxp/auxi/auxr` created on the first kext approval
- `Kext Signing: disabled`, `Debugging Restrictions: disabled`, everything else enabled

The original target (`sip0 = 0x1005`, `sip2: false`) was not reachable with
`csrutil`; the actual 2026-11-03 result in §7.1 matches the corrected target.

The stricter Reduced variant would use `smb1: false` and the same SIP target.

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
- `bash scripts/build-kext.sh` writes `build/kext/provenance.json`;
  `python3 scripts/kext-provenance.py verify` passes on a clean tree and
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
Permissive baseline. The policy gate was applied on 2026-11-03 and S2 is
accepted with one recorded risk: `sip2:true` (CTRR lock disabled), which
`csrutil --without kext` sets unconditionally; see §7.1. On 2026-11-02 the target
was selected as **keep Permissive + enable kexts**; Reduced is not pursued.

Preconditions: S1 accepted and the preflight report says `PASS: no preflight
blockers`; a KDK matching macOS 27.0 (build 26A428) installed; full
`bputil -d -j` output stored privately (not in the repository, not in a
public issue).

Steps, in this order:

1. Enter recoveryOS/1TR.
2. Keep the selected Permissive mode and enable third-party kexts: Startup
   Security Utility → Permissive Security + "Allow user management of kernel
   extensions from identified developers". Goal: `security_mode: permissive`,
   `smb1: true`, `smb2: true`. If the checkbox is unavailable under Permissive,
   run `bputil -k` to enable kexts, then verify the resulting mode; if it
   changes to Reduced, re-select Permissive and re-check `smb2`. The general
   alternative remains Reduced Security + the same checkbox. Do not pass
   `bputil -a` (boot-arg allow list) or `-s` (SSV); those are separate
   downgrades and are outside S2. `bputil -c` is not needed either: step 3
   disables CTRR anyway (§2).
3. Set the minimal SIP mask: `csrutil enable --without debug,kext`
   (alternative spelling: `--without debug --without kext`).
   Expected `sip0 = 0x1D`, `sip2: true`.
4. Re-enable research guests if they are needed:
   `csrutil allow-research-guests enable` (expected `sip0 = 0x101D`). The
   current policy has research guests enabled; keep them unless they are no
   longer required.
5. Restart.

Verification after boot:

- `csrutil status` → `Kext Signing: disabled`, `Debugging Restrictions: disabled`,
  `Kernel Integrity Protections: disabled` (`sip2`, accepted), all other
  protections enabled, `Authenticated Root Requirement: enabled`.
- `csrutil allow-research-guests status`.
- `sudo bputil -d -j` → `security_mode: permissive`, `smb1: true`, `smb2: true`,
  `sip0` as expected, `sip1: false`, `sip2: true`, `sip3: false`,
  `auxp/auxi/auxr` still absent until the kext is approved.
- `spctl kext-consent list` before and after approval.

Open empirical question (the only one that can invalidate the plan):

- Whether `kmd` treats the partial SIP kext bit (`0x1`) as "SIP off" for
  signature verification during AuxKC generation. Apple's wording is "If SIP is
  turned off"; the flag name and the `csrutil` mapping say `--without kext`.
  Failure signature to capture: the exact `kmutil load -p` error. Fallback
  options, in order: ad-hoc sign the built kext; sign with the available Apple
  Development identity (likely insufficient for `kmd`); temporarily Permissive.
- Note: `--without kext` stores `0x8` (kernel debugger) and sets `sip2`; both
  are part of the accepted S2 state.

Acceptance:

- `security_mode: permissive`, `smb1: true`, `smb2: true`, `sip0` as expected,
  `sip1: false`, `sip2: true` (accepted risk), `sip3: false`, research guests
  state recorded.
- Negative control: what `kmutil load -p` reports for the shipped unsigned kext
  before the policy change (expected: policy/signature failure).

### S2 result (2026-11-03)

The policy gate was applied before the 2026-11-03 post-S2 snapshot. The pre-S2
snapshot (`bputil-pre-s2-2026-11-02.json`) and post-S2 snapshots
(`bputil-after-s2.json`, `bputil-2026-11-03.json`) are private, mode `0600`;
the two post-S2 snapshots are byte-identical.

| Check | Actual |
|---|---|
| `security_mode` | `permissive` |
| `smb1` / `smb2` | `true` / `true` |
| `sip0` | `0x101D` |
| `sip1` / `sip2` / `sip3` | `false` / **`true`** / `false` |
| `auxp` / `auxi` / `auxr` | absent |
| `spctl kext-consent list` | no configuration, exit 0 |
| loaded / installed | no `usbgadget`; empty AuxKC; install path absent |

`smb2` is set. Every deviation from the original target comes from
`csrutil --without kext` (§2): it stores `0x1` and `0x8` and sets `sip2`. `0x10`
is the `csrutil` default and is masked at boot. `sip2=true` means iBoot no
longer locks CTRR, so kernel text stays writable for any code that already has a
kernel write primitive. It does not let user space write kernel memory. With
`csrutil`/`bputil` it cannot be avoided for an unsigned kext; a kext with a
kext-enabled Developer ID signature would not need `0x1` and keeps CTRR.

S2 is **accepted** on 2026-11-03 with this risk acceptance:

- Risk: `sip2:true` (CTRR lock disabled) together with stored `0x8` (kernel
  debugger) on the primary M4 Pro.
- Reason: required by the unsigned research kext; a kext-enabled Developer ID is
  out of scope (§1).
- Limit: valid until S3 rollback. Rollback step 3 must leave `sip2` absent; a
  fresh `bputil -d -j` after the reboot proves it.

Negative control: `NOT_EXECUTED`. No `kmutil load -p` artifact was recorded
before the gate. It must not be reproduced now, because `smb2:true` plus the
kext SIP bit could attempt the load.

Acceptance record: S2 accepted on 2026-11-03 against the corrected target
(§2). Evidence: post-S2 private dumps (byte-identical), `csrutil` setter chain
in both the macOS and the recoveryOS binary, preflight pass on the acceptance
commit (`kext-s2-preflight.md`). S3 has not started.

## 8. S3 — hardware validation

Only the pinned, self-built hardened kext may be installed or used. Since
2026-11-03 `drivers/usbgadget.kext` is byte-identical to the Release build of
the reviewed source, and `drivers/PROVENANCE` pins its digests and LC_UUID
(`CF8E2A1A-9710-3430-998D-21A0E845D8B2`). Every entry point checks the pins:

| Point | Check |
|---|---|
| Repository | `kext-provenance.py verify-bundle` (part of the preflight): the bundle equals a fresh build of the committed source; `PROVENANCE` matches the build record and the Mach-O LC_UUID |
| Release zip | `audit-release.py`: pinned digests, `PROVENANCE`, LC_UUID parsed from the zipped executable |
| Install | `scripts/install-driver.sh`: installs only a copy that matches the pins; refuses another kext that declares `gay.bowser.usbgadget`; idempotent; one installer at a time; never deletes (a replaced driver moves to `/Library/Application Support/mac2jb/driver/replaced-*`) |
| Run time | `install-driver.sh --status`: installed bytes and the loaded UUID must equal the pins; `mac2jb.command` and the GUI start USB input only on `verified` |
| S3 probe | `kext-s3-probe` refuses every open or write unless the loaded UUID equals the pin |

Boot behavior: the personality matches `IOUSBDeviceController`, so after the
approval reboot the kext starts automatically, one instance per controller
(three `AppleT8132USBXDCI` on this Mac), before login. `init`/`start` only
allocate two locks, start the worker thread, retain the provider and register
the service; nothing is written to the controller until a host publishes a
configuration. A defect on that path would panic at every boot, so the boot
failure recovery below must be known before step 1.

Entry gate (all must hold before step 1; record each in the S3 log):

- `bash scripts/kext-s2-preflight.sh` passes on the commit that is installed,
  including the bundled-driver check.
- `bash scripts/install-driver.sh --verify` passes and `--status` reports
  `not-installed`; `node --test scripts/test-driver-package.cjs` and
  `bash scripts/build-kext-s3-probe.sh` pass.
- A verified backup of the Data volume exists, and the restore was checked.
- 1TR access works (used for S2 on 2026-11-03), and the pre-S2 private
  LocalPolicy snapshot is available for the rollback comparison.
- The host runs no untrusted kernel-facing workload during the window; the
  window ends with the rollback below, not with the functional test.

Abort: a kernel panic, a failed AuxKC rebuild or approval, a status other than
`verified` after the approval reboot, a probe exit 5, 6 or 7, or IOKit behavior
outside the harness contract (stuck teardown, leaked user clients, refused
registry writes from the host path) stops S3. Capture logs and the panic
report, then run the rollback immediately.

Order:

1. Install: `./mac2jb.command --install-driver` (or the GUI). Keep the output;
   it names the UUID and where a replaced driver was moved, if any.
2. Approve it in System Settings → Privacy & Security; wait for the AuxKC
   rebuild; reboot.
3. Identity: `./mac2jb.command --driver-status` must print
   `MAC2JB_DRIVER_STATUS=verified` (exit 0); `kext-s3-probe identity` exits 0
   and `inventory` lists three services with no user clients.
4. Early non-root boundary probe: `kext-s3-probe reject` from the login user;
   every invalid input must be refused. The valid `PublishConfiguration` and
   `Poke` path is exercised by the unprivileged host in step 6.
5. Boundary tests, as in `kext-s3-probe.md` (login user, mac2jb host stopped):
   1000 `open-close` cycles return to the user-client baseline (F17 on
   hardware); `poke` 1000 × 8 threads without a hang; a cross-process poke
   storm; a poke storm during user-client churn. Then, as root, repeated
   `kmutil unload -b gay.bowser.usbgadget` and `kmutil load -b
   gay.bowser.usbgadget` with `inventory` in between, once while a poke storm
   runs (`setProperties` during service teardown); record whether reloading
   from the AuxKC works without a reboot. Finally, unplug during an active
   transfer.
6. Functional test: mac2jb typing flow against the Switch with the kurumuz host,
   up to 4/4 verification.
7. Capture `log show` for the kext subsystem and any panic report
   (`/Library/Logs/DiagnosticReports/*.panic`).

Boot failure (panic on every boot):

1. Safe mode skips the AuxKC. Apple documents this for Apple silicon: start
   into the startup options (hold the power button), hold Shift and choose
   Continue in Safe Mode; BootPicker sets an `nvram` variable so iBoot does not
   load the AuxKC on that boot
   ([Boot modes](https://support.apple.com/guide/security/boot-modes-sec10869885b/web)).
2. In safe mode, move the kext out of the extensions folder (never delete it):
   `sudo mv /Library/Extensions/usbgadget.kext "/Library/Application
   Support/mac2jb/driver/removed-$(date -u +%Y%m%dT%H%M%SZ)"`, run
   `sudo kmutil install --update-all`, and restart normally. This step has not
   been exercised.
3. If safe mode is not reachable: in 1TR, Startup Security Utility, clear
   "Allow user management of kernel extensions" (`smb2`); iBoot then loads no
   AuxKC. Remove the kext as in step 2 before enabling it again, and compare a
   fresh `bputil -d -j` with the S2 snapshot afterwards.

Rollback (unload is not removal):

`kmutil unload -p` stops the kext lifecycle, but the extension stays in the
AuxKC that was built at approval time until the collection is rebuilt and the
Mac restarts. Rollback therefore needs two separate proofs:

1. Unload: `sudo kmutil unload -p /Library/Extensions/usbgadget.kext`, restart,
   then `kmutil showloaded --list-only | grep usbgadget` must be empty.
2. Removal: move `/Library/Extensions/usbgadget.kext` out of the extensions
   folder as in boot failure step 2 (never delete it), rebuild the AuxKC with
   `sudo kmutil install --update-all`, restart, then verify all three:
   - `kmutil showloaded --show all --collection aux --list-only | grep usbgadget`
     is empty (neither loaded nor present in the AuxKC),
   - `kmutil showloaded --show unloaded --list-only | grep usbgadget` is empty,
   - `scripts/install-driver.sh --status` reports `not-installed`.
3. SIP: in recoveryOS `csrutil enable --without debug`, then
   `csrutil allow-research-guests enable` if it was previously on. After the
   reboot `sudo bputil -d -j` must show `sip2` absent (CTRR locked again) and
   `sip0` without `0x1`/`0x8`. Do not stop rollback before this check.
4. LocalPolicy: restore `smb2` only if the kext capability must be withdrawn.

Acceptance:

- `--status` is `verified` after the approval reboot, and the probe identity
  matches the pin.
- Kext loads from the pinned build, the typing flow works, no panic.
- The early non-root probe results are recorded: accepted host path,
  rejected invalid inputs; the boundary-test probe evidence is kept
  (`kext-s3-probe.md`, outside git).
- Every rollback step executed at least once and documented.

### S3 log (2026-11-03, in progress)

Evidence: private, `~/private/mac2jb-s3/` (one folder per phase, mode 0700).

| Step | Result |
|---|---|
| Entry gate | preflight passes on `102ed45` (bundled driver byte-identical); `--verify` passes, `--status` `not-installed`; Time Machine backup exists on an external disk (operator) |
| 1 Install | pinned build installed via the admin dialog (GUI path), root:wheel, both digests OK; `kmutil load -p` exits 27 "not approved to load", as expected before approval |
| 2 Approval | UAKL updated; the AuxKC rebuild also took Apple's pending `com.apple.nke.rvi` (Xcode Remote Virtual Interface); reboot without panic |
| 3 Identity | `--status` `verified`; one loaded `gay.bowser.usbgadget`, UUID `CF8E2A1A-9710-3430-998D-21A0E845D8B2`; `rvi` is in the AuxKC but not loaded; three services on `AppleT8132USBXDCI@0/1/2`, no user clients; an iPhone connected normally |
| 4 Reject | 6 invalid inputs × 3 services refused, each with `kIOReturnBadArgument` |
| 5 open-close | 1000 cycles × 3 services, all opens and closes succeed; user clients peak at 6 and return to 0 within 12 ms (F17 fixed on hardware) |
| 5 poke | 8000 calls × 3 services; two processes × 320,000 calls on one service; 320,000 calls during 5000 open/close cycles; no hang, no error, slowest call 148 ms under contention |
| Logs | no panic report; no kernel error since the reboot. `kernelmanagerd` logs "invalid codeful kernel extension in the restricted lookup table" for every AuxKC kext (also Apple's); the kext's debug log writes one line per user-client call (about 25,000 lines in these runs) |

Still open: unload/reload cycles as root (one with a poke storm, `setProperties`
during service teardown), unplug during a transfer, the functional test, log
capture, and the rollback.

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
- CTRR is disabled from S2 until rollback (`sip2:true`, §7.1). A kernel
  exploit in that window can patch kernel text. Keep the window short and do
  not run untrusted kernel-facing code on the host during it.

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
