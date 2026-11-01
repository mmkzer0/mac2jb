# Kext build provenance (S0, S1)

Status: build and hardening evidence.
Capture: 2026-11-01, branch `harden/kext-build`, host macOS 27.0 (26A428),
Xcode 27.2 (27B52), SDK `MacOSX27.2.sdk`.

The shipped `drivers/usbgadget.kext` was built by the upstream maintainer with
Xcode 2660 / SDK 26.5 in a Debug configuration (evidence below). Our artifacts
are Release builds from the vendored source with the current toolchain.
Byte-identical reproduction is **not** claimed; every observed difference is
explained or bounded.

## Reproduce

```sh
bash scripts/build-kext.sh
python3 scripts/kext-provenance.py record \
  --artifact build/kext/usbgadget.kext \
  --source vendor/macos_usb_gadget_poc/usbgadget \
  --output build/kext/provenance.json
python3 scripts/kext-provenance.py report \
  --artifact build/kext/usbgadget.kext \
  --shipped drivers/usbgadget.kext \
  --source vendor/macos_usb_gadget_poc/usbgadget
```

Debug reference (used to explain the shipped binary's code size):

```sh
D="$(mktemp -d)"
cp -R vendor/macos_usb_gadget_poc/usbgadget/. "$D/"
cd "$D"
xcodebuild -project usbgadget.xcodeproj -configuration Debug -sdk macosx \
  ARCHS=arm64e ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO \
  SYMROOT="$D/sym" OBJROOT="$D/obj" build
```

## S1 hardened build

```text
## Artifacts

- Built: `build/kext/usbgadget.kext`
  - Total size: 116656 bytes
  - Executable: `Contents/MacOS/usbgadget` (114400 bytes)
    - SHA256: `41f650949afcecf9bd730212d55a2ee3254c7c748962d5ebb2d81e86ed8546cf`
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

- Counts: built has 353 undefined symbols, shipped has 351 undefined symbols.
- Added in built (5):
  - `_IOLockSleep`
  - `_IOLockWakeup`
  - `__ZN15IORegistryEntry13setPropertiesEP8OSObject`
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
- Changed sections (6):
  - `__DATA,__data`: built 200 bytes, shipped 196 bytes (+4 bytes)
  - `__DATA_CONST,__auth_got`: built 216 bytes, shipped 200 bytes (+16 bytes)
  - `__DATA_CONST,__got`: built 72 bytes, shipped 56 bytes (+16 bytes)
  - `__TEXT,__cstring`: built 977 bytes, shipped 835 bytes (+142 bytes)
  - `__TEXT_EXEC,__auth_stubs`: built 432 bytes, shipped 400 bytes (+32 bytes)
  - `__TEXT_EXEC,__text`: built 6452 bytes, shipped 6764 bytes (-312 bytes)

## Defined symbols

- Counts: built has 81 defined symbols, shipped has 74 defined symbols.
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
- Removed in built (3):
  - `__Z16thread_bootstrapPv`
  - `__ZN11OSMetaClassdlEPvm`
  - `___cxx_global_var_init`

## Strings (-n 8)

- Unique strings (-a -n 8, minimum length 8): built has 20, shipped has 18.
- Added in built (2):
  - `usbgadget: Executing 'gay_bowser_usbgadget_userclient::clientClose()'.`
  - `usbgadget: Failed to allocate lock in 'gay_bowser_usbgadget:init()'.`
- Removed in built (0):
  - none

These artifacts were built with different Xcode/SDK versions; byte-identical reproduction is not claimed.
```

### S1 analysis

- The five new imports are all kernel exports: `_IOLockSleep`, `_IOLockWakeup`,
  `IORegistryEntry::setProperties`, `OSSymbol::metaClass` and
  `IOService::metaClass` are present in the KDK 26.0 kernel symbol table. The
  three removed imports were the dead user-client `setProperties` symbol and the
  base `IOUserClient::clientClose`/`free` stubs; the hardened code implements
  both explicitly.
- `__TEXT_EXEC,__text` is 6452 bytes against the shipped 6764 (-312) and the S0
  Release build's 5220. The hardening adds roughly 1.2 KiB; the shipped binary
  remains a Debug build (see below), which is why it is still slightly larger.
- Defined symbols add the new `stopThread`, `copyProvider`, `releaseProvider`,
  `clientClose`, `free` and the two-argument `thread_bootstrap`; the removed
  `OSMetaClass::operator delete` and `___cxx_global_var_init` are Debug-codegen
  artifacts present in the shipped binary.
- Strings gain exactly two new log lines (`clientClose`, lock-allocation
  failure); no protocol string changed.
- `Info.plist` is unchanged from S0: toolchain fields plus
  `LSMinimumSystemVersion` 12.0 (the original 10.11 target is rejected by
  Xcode 27).

## S0 baseline (history)

The pre-hardening Release build (`ef1dcf6e…`, executable 113552 bytes,
`__TEXT_EXEC,__text` 5220 bytes) had 351/351 identical undefined symbols and
18/18 identical strings of at least 8 bytes against the shipped binary.

The shipped binary matches a **Debug** (`-O0`) build of the same source under
the current toolchain: `__TEXT_EXEC,__text` 6824 bytes (0.9 percent above the
shipped 6764), identical undefined symbols, identical meaningful strings, and
only four header-emitted defined symbols of difference. Its `Info.plist`
records Xcode 2660 / SDK 26.5. The shipped artifact's exact build configuration
was never recorded by the upstream project; the Debug inference is the
best-supported explanation for the code-size delta.

## Consequence

The source-to-artifact chain is reproducible on this host, and every
difference to the shipped binary is either a deliberate hardening change or a
toolchain/configuration artifact. Behavioral equivalence still rests on the S1
mock-IOKit harness and the S3 hardware test, not on this comparison.
