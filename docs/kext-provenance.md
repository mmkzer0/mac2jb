# Kext build provenance (S0, S1, S1.1)

Status: build and hardening evidence; the build contract below is enforced by
`scripts/build-kext.sh`, `scripts/kext-provenance.py` and
`scripts/test-kext-provenance.sh`.
Capture: 2026-11-03, host macOS 27.0 (26A428), Xcode 27.2 (27B52), SDK
`MacOSX27.2.sdk` (26B118).

Since 2026-11-03 `drivers/usbgadget.kext` is our Release build itself:
`kext-provenance.py verify-bundle` checks that it is byte-identical to a fresh
build of the committed source and that `drivers/PROVENANCE` matches the build
record and the executable's LC_UUID (`CF8E2A1A-9710-3430-998D-21A0E845D8B2`).

The comparison below documents the binary it replaced: the upstream v0.3.1
prebuilt (`a32119c7…`, LC_UUID `124391F6-0CFF-32E0-8884-6F6360DF5D1C`), built
by the upstream maintainer with Xcode 2660 / SDK 26.5 in a Debug configuration
(evidence below). In the sections below, "shipped" means that upstream binary.
Byte-identical reproduction of the upstream binary is **not** claimed; every
observed difference is explained or bounded. Reproduction of *our own* build is
claimed and tested, within the limits listed at the end.

## Build contract

`bash scripts/build-kext.sh` produces `build/kext/usbgadget.kext` and
`build/kext/provenance.json`. The executable's SHA-256 is a function of the
git-tracked kext source and the toolchain only:

- **Source:** only the files `git ls-files` lists under
  `vendor/macos_usb_gadget_poc/usbgadget` are copied to `build/kext/src` and
  compiled. Ignored files (`.DS_Store`, `xcuserdata`, `*.xcuserstate`) and
  untracked scratch files never reach the compiler and never change the source
  digest.
- **Environment:** `xcodebuild`, `xcrun` and the provenance tool run under
  `env -i` with an allowlist: `PATH`, `LANG=C`, a `HOME` and `TMPDIR` inside
  `build/kext` (so user-wide Xcode defaults and `~/Library/Developer/Xcode`
  caches cannot influence the build), and `DEVELOPER_DIR` only when the operator
  exported it (the record keeps it). `OTHER_CFLAGS`, `GCC_OPTIMIZATION_LEVEL`,
  `SDKROOT` and similar variables in the calling shell are ignored.
- **Path independence:** the build runs with
  `GCC_GENERATE_DEBUGGING_SYMBOLS=NO`. With debug information the Mach-O symbol
  table carried `SO`/`OSO` stabs naming `build/kext/obj/...` (so the hash
  changed with the checkout path and embedded the builder's home directory) and
  the LC_UUID, which is derived from the content, changed with it. Without debug
  information no dSYM is produced and the executable is identical from any
  checkout path. The cost is that no dSYM exists for the built kext; the
  executable keeps its defined and undefined symbols, only the debug stabs
  are gone.
- **Dirty trees:** a dirty build still succeeds for iteration. The record says
  `dirty: true`; dirty means a tracked modification or an untracked,
  non-ignored file under the kext source directory or `scripts/build-kext.sh`.
  `verify` and the S2 preflight reject it.

`provenance.json` (`format: mac2jb-kext-provenance-v2`) records:

| Field | Content |
|---|---|
| `git` | `commit`, `branch`, `dirty`, `dirty_paths` of the build inputs |
| `source` | per-file SHA-256 of the tracked files, and `tree_sha256` over sorted `<path>\0<sha256>\n` lines |
| `build` | the non-path `xcodebuild` arguments, the build script path and its SHA-256 |
| `toolchain` | `xcodebuild -version` (Xcode version and build), `xcrun` SDK path/version/build, clang, the `DEVELOPER_DIR` override (or `null`), and the `xcodebuild -showBuildSettings` values actually used (`SDK_NAME`, `SDK_VERSION`, `SDK_PRODUCT_BUILD_VERSION`, `XCODE_PRODUCT_BUILD_VERSION`, `MACOSX_DEPLOYMENT_TARGET`, `SDKROOT`, ...) |
| `kdk` | the `KDK_<version>_<build>.kdk` matching the host: name, `SystemVersion.plist` version/build and SHA-256, arm64 release kernels, `valid`/`problems` |
| `host` | `sw_vers` product, version and build |
| `artifact` | per-file SHA-256 of the bundle, executable hash/size/arch, `Info.plist` hash, signing state |

`record` is invoked only by `build-kext.sh`, right after the build. It compares
the digest of the working-tree source with the digest of `build/kext/src` (what
was compiled) and refuses to write a record when they differ, so a source edit
between the compile and the record cannot produce one.

## Reproduce and verify

```sh
bash scripts/build-kext.sh
python3 scripts/kext-provenance.py verify          # exits non-zero on any problem
bash scripts/test-kext-provenance.sh               # regression tests (about 15 s)
python3 scripts/kext-provenance.py report \
  --artifact build/kext/usbgadget.kext \
  --shipped drivers/usbgadget.kext \
  --source vendor/macos_usb_gadget_poc/usbgadget
```

`verify` prints `provenance: commit=... dirty=... source_sha256=...
executable_sha256=...` and one `problem: <code>: <detail>` line per failure:

| Code | Meaning |
|---|---|
| `record` | record missing, unreadable or of another format |
| `dirty` | the build inputs have uncommitted changes now |
| `record-dirty` | the artifact was built from a dirty tree |
| `source-digest` | the tracked source no longer equals the recorded digest (edit after the build, committed or not) |
| `build-script` | `build-kext.sh` differs from the script that built the artifact |
| `artifact-hash`, `artifact-files` | the executable or any bundle file changed, or files were added or removed |

`--allow-dirty` downgrades `dirty` and `record-dirty` to notes (the iteration
build runs this as a self-check). `kext-provenance.py kdk-check` validates a
KDK directory by content (see `kext-s2-preflight.md`). `export-checkout --dest
<dir>` copies the build inputs of the working tree into a fresh one-commit git
repository at another path; the preflight and the tests use it for the
path-independence check.

### Limits

- The record pins *which* Xcode, SDK and KDK were used; it does not require a
  particular one. A different Xcode builds a different binary and verifies
  against its own record; compare `toolchain` before treating two records as
  equivalent.
- The KDK is not an input of the build. It is recorded because the AuxKC
  rebuild at install time needs the matching one.
- `verify` proves the artifact still equals what was recorded and that the
  source and script still equal what was compiled. It does not rebuild; the
  preflight rebuilds from a copy at another path.
- `build-kext.sh` requires a git checkout rooted at the repository (the record
  names a commit); a source zip without `.git` cannot build the kext.

## Current build

Captured by the 2026-11-03 build from the working tree of branch `dev`. The
record of that build states: commit `0e7addbc495dc2d98e18b8b4b63c6a6a47de28cb`
with `dirty: true` (uncommitted edits to `usbgadget_userclient.cpp` and
`scripts/build-kext.sh`), source `tree_sha256`
`8987e0c90680e7a1f57e646c0cd8a9a339bced3cf737fec4a37f45e5d09a3e11`, executable
`109296` bytes, SHA-256
`de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c5`,
`Info.plist` SHA-256
`a4ca368ce107273aaf008a8dd68d1de898eb9889c5efc6e56ea76601912ce0bd`, Xcode 27.2
(27B52), SDK 27.2 (26B118). The same executable hash came out of the in-tree
build, of exported copies at differently named paths (one containing a space)
and of a build with hostile `OTHER_CFLAGS`/`GCC_OPTIMIZATION_LEVEL`/
`MACOSX_DEPLOYMENT_TARGET` in the environment. The record proves this digest and
this executable correspond; because it is dirty it does not name a commit that
contains this source. Rebuild from a clean commit and run `verify` to obtain a
record that does. The hash in earlier revisions of this document
(`644fda29...`) predates the path-independent build and the later source edits
and is obsolete.

## Comparison with the shipped kext

Debug reference (used to explain the shipped binary's code size; not under
provenance control):

```sh
D="$(mktemp -d)"
cp -R vendor/macos_usb_gadget_poc/usbgadget/. "$D/"
cd "$D"
xcodebuild -project usbgadget.xcodeproj -configuration Debug -sdk macosx \
  ARCHS=arm64e ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO \
  SYMROOT="$D/sym" OBJROOT="$D/obj" build
```

Output of `report` for the build above (the built kext is a Release build
without debug information; the shipped one is Debug):

```text
## Artifacts

- Built: `build/kext/usbgadget.kext`
  - Total size: 111552 bytes
  - Executable: `Contents/MacOS/usbgadget` (109296 bytes)
    - SHA256: `de79702967e272694568d6545f4e131bfcf0b21509c1cc3aab8c4c4c572674c5`
  - Info.plist: `Contents/Info.plist` (2256 bytes)
    - SHA256: `a4ca368ce107273aaf008a8dd68d1de898eb9889c5efc6e56ea76601912ce0bd`
- Shipped: `drivers/usbgadget.kext`
  - Total size: 116261 bytes
  - Executable: `Contents/MacOS/usbgadget` (114008 bytes)
    - SHA256: `a32119c7908098c49c2540a17aad4d172378de969885ad4f4a752bdb8ef91308`
  - Info.plist: `Contents/Info.plist` (2253 bytes)
    - SHA256: `c38786b3eb1b51055505bca54c88df77b797e1785c146ec1d54ee3273a934faf`

## Signing

- Built: `unsigned`
- Shipped: `unsigned`

## Mach-O

- Built: build/kext/usbgadget.kext/Contents/MacOS/usbgadget: Mach-O 64-bit kext bundle arm64e (arch: `arm64e`)
- Shipped: drivers/usbgadget.kext/Contents/MacOS/usbgadget: Mach-O 64-bit kext bundle arm64e (arch: `arm64e`)

## Undefined symbols

- Counts: built has 354 undefined symbols, shipped has 351 undefined symbols.
- Added in built (6):
  - `_IOLockSleep`
  - `_IOLockWakeup`
  - `__ZN15IORegistryEntry13setPropertiesEP8OSObject`
  - `__ZN8OSString9metaClassE`
  - `__ZN8OSSymbol9metaClassE`
  - `__ZN9IOService9metaClassE`
- Removed in built (3):
  - `__ZN12IOUserClient11clientCloseEv`
  - `__ZN12IOUserClient4freeEv`
  - `__ZN31gay_bowser_usbgadget_userclient13setPropertiesEP8OSObject`

## Sections

- Counts: built has 10 sections, shipped has 10 sections.
- Added sections (0):
  - none
- Removed sections (0):
  - none
- Changed sections (7):
  - `__DATA,__data`: built 200 bytes, shipped 196 bytes (+4 bytes)
  - `__DATA_CONST,__auth_got`: built 216 bytes, shipped 200 bytes (+16 bytes)
  - `__DATA_CONST,__const`: built 5288 bytes, shipped 5296 bytes (-8 bytes)
  - `__DATA_CONST,__got`: built 80 bytes, shipped 56 bytes (+24 bytes)
  - `__TEXT,__cstring`: built 1100 bytes, shipped 835 bytes (+265 bytes)
  - `__TEXT_EXEC,__auth_stubs`: built 432 bytes, shipped 400 bytes (+32 bytes)
  - `__TEXT_EXEC,__text`: built 6956 bytes, shipped 6764 bytes (+192 bytes)

## Defined symbols

- Counts: built has 80 defined symbols, shipped has 74 defined symbols.
- Added in built (10):
  - `_OSKextGetCurrentIdentifier`
  - `_OSKextGetCurrentLoadTag`
  - `_OSKextGetCurrentVersionString`
  - `__Z16thread_bootstrapPvi`
  - `__ZN20gay_bowser_usbgadget10stopThreadEv`
  - `__ZN31gay_bowser_usbgadget_userclient11clientCloseEv`
  - `__ZN31gay_bowser_usbgadget_userclient12copyProviderEv`
  - `__ZN31gay_bowser_usbgadget_userclient15releaseProviderEv`
  - `__ZN31gay_bowser_usbgadget_userclient4freeEv`
  - `__kext_apple_cc`
- Removed in built (4):
  - `__Z16thread_bootstrapPv`
  - `__ZN11OSMetaClassdlEPvm`
  - `__ZN20gay_bowser_usbgadget20setConfigurationDictEP12OSDictionary`
  - `___cxx_global_var_init`

## Strings (-n 8)

- Unique strings (-a -n 8, minimum length 8): built has 21, shipped has 18.
- Added in built (4):
  - `usbgadget: Controller setProperties failed in 'gay_bowser_usbgadget:doUpdate()' (0x%x).`
  - `usbgadget: Executing 'gay_bowser_usbgadget_userclient::clientClose()'.`
  - `usbgadget: Failed to allocate config lock in 'gay_bowser_usbgadget:init()'.`
  - `usbgadget: Failed to allocate lock in 'gay_bowser_usbgadget:init()'.`
- Removed in built (1):
  - `usbgadget: setProperties(%s) not handled`

These artifacts were built with different Xcode/SDK versions; byte-identical reproduction is not claimed.
```

### S1.1 analysis

- The six new imports are all kernel exports: `_IOLockSleep`, `_IOLockWakeup`,
  `IORegistryEntry::setProperties`, `OSString::metaClass`,
  `OSSymbol::metaClass` and `IOService::metaClass`. The three removed imports
  were the dead user-client `setProperties` symbol and the base
  `IOUserClient::clientClose`/`free` stubs; the hardened code implements both
  explicitly. With `clientClose` calling `terminate()`, all 354 imports of the
  current build resolve against the arm64 KDK 27.0 (`26A428`) release kernels.
- `__TEXT_EXEC,__text` is 6956 bytes against the shipped 6764 (+192) and the S0
  Release build's 5220. The hardening adds about 1.7 KiB; the explicit
  publication lock and its allocation-failure log are part of that delta. The
  shipped binary remains a Debug build (see below), so size alone is not
  behavioral equivalence.
- Defined symbols add the new `stopThread`, `copyProvider`, `releaseProvider`,
  `clientClose`, `free` and the two-argument `thread_bootstrap`; the removed
  `gay_bowser_usbgadget::setConfigurationDict` is the helper replaced by the
  validate/copy/publish sequence. The removed `OSMetaClass::operator delete` and
  `___cxx_global_var_init` are Debug-codegen artifacts present in the shipped
  binary.
- Strings gain four new log lines (controller `setProperties` failure,
  `clientClose`, config-lock allocation failure, lock-allocation failure) and
  lose the old unknown-key log; no protocol string changed.
- `Info.plist` is unchanged from S0: toolchain fields plus
  `LSMinimumSystemVersion` 12.0 (the original 10.11 target is rejected by
  Xcode 27).

## S0 baseline (history)

The pre-hardening Release build (`ef1dcf6e…`, executable 113552 bytes,
`__TEXT_EXEC,__text` 5220 bytes) had 351/351 identical undefined symbols and
18/18 identical strings of at least 8 bytes against the shipped binary. That
build and the first S1.1 build carried debug stabs and were not
path-independent; their sizes (113552 and 114360 bytes) include them.

The shipped binary matches a **Debug** (`-O0`) build of the same source under
the current toolchain: `__TEXT_EXEC,__text` 6824 bytes (0.9 percent above the
shipped 6764), identical undefined symbols, identical meaningful strings, and
only four header-emitted defined symbols of difference. Its `Info.plist`
records Xcode 2660 / SDK 26.5. The shipped artifact's exact build configuration
was never recorded by the upstream project; the Debug inference is the
best-supported explanation for the code-size delta.

## Consequence

The source-to-artifact chain is reproducible on this host from any checkout
path, is bound to the git-tracked source and the recorded toolchain by
`provenance.json`, and every difference to the shipped binary is either a
deliberate hardening change or a toolchain/configuration artifact. Behavioral
equivalence still rests on the S1 mock-IOKit harness and the S3 hardware test,
not on this comparison.
