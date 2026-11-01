# Kext build provenance (S0)

Status: S0 evidence record.
Capture: 2026-11-01, branch `harden/kext-build`, host macOS 27.0 (26A428),
Xcode 27.2 (27B52), SDK `MacOSX27.2.sdk`.

This record compares the S0 Release build of `usbgadget.kext` against the
shipped `drivers/usbgadget.kext`. Byte-identical reproduction is **not**
claimed; the goal is to explain every observed difference and to fix the
source-to-artifact chain for the hardening work.

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

The Debug reference used in the analysis below:

```sh
D="$(mktemp -d)"
cp -R vendor/macos_usb_gadget_poc/usbgadget/. "$D/"
cd "$D"
xcodebuild -project usbgadget.xcodeproj -configuration Debug -sdk macosx \
  ARCHS=arm64e ONLY_ACTIVE_ARCH=YES CODE_SIGNING_ALLOWED=NO \
  SYMROOT="$D/sym" OBJROOT="$D/obj" build
```

## Report

```text
## Artifacts

- Built: `build/kext/usbgadget.kext`
  - Total size: 115808 bytes
  - Executable: `Contents/MacOS/usbgadget` (113552 bytes)
    - SHA256: `ef1dcf6edd9a2af5be43686b865e93b6e57447d5185ff31df275d1af624f0a7f`
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

- Counts: built has 351 undefined symbols, shipped has 351 undefined symbols.
- Added in built (0):
  - none
- Removed in built (0):
  - none

## Sections

- Counts: built has 10 sections, shipped has 10 sections.
- Added sections (0):
  - none
- Removed sections (0):
  - none
- Changed sections (2):
  - `__DATA,__data`: built 200 bytes, shipped 196 bytes (+4 bytes)
  - `__TEXT_EXEC,__text`: built 5220 bytes, shipped 6764 bytes (-1544 bytes)

## Defined symbols

- Counts: built has 76 defined symbols, shipped has 74 defined symbols.
- Added in built (4):
  - `_OSKextGetCurrentIdentifier`
  - `_OSKextGetCurrentLoadTag`
  - `_OSKextGetCurrentVersionString`
  - `__kext_apple_cc`
- Removed in built (2):
  - `__ZN11OSMetaClassdlEPvm`
  - `___cxx_global_var_init`

## Strings (-n 8)

- Unique strings (-a -n 8, minimum length 8): built has 18, shipped has 18.
- Added in built (0):
  - none
- Removed in built (0):
  - none

These artifacts were built with different Xcode/SDK versions; byte-identical reproduction is not claimed.
```

## Analysis

The shipped binary and the S0 Release build agree on everything that identifies
the source-level contract:

- 351/351 undefined imports, identical sets.
- 18/18 strings of at least 8 bytes, identical sets.
- 10/10 Mach-O sections; the section set is identical.
- arm64e Mach-O kext bundle; both unsigned.

The remaining differences are configuration and toolchain, not source:

- `__TEXT_EXEC,__text` is 5220 bytes in the Release build and 6764 bytes in the
  shipped binary. A **Debug** (`-O0`) build of the same vendored project with
  Xcode 27.2 yields 6824 bytes (0.9 percent above the shipped size) and 428
  disassembly lines versus 424 for the shipped binary. Its defined-symbol
  surface matches the shipped binary except four symbols emitted by the newer
  headers (`__kext_apple_cc`, `_OSKextGetCurrent*`). The shipped binary is
  therefore consistent with a Debug build produced by Xcode 2660 / SDK 26.5, as
  recorded in its `Info.plist`.
- The Release build additionally drops `___cxx_global_var_init` and
  `OSMetaClass::operator delete`, which the Debug build retains; the four
  `_OSKextGetCurrent*` / `__kext_apple_cc` symbols are SDK-emitted and appear in
  both of our builds.
- `__DATA,__data` differs by four bytes (200 versus 196).
- `Info.plist` differs only in toolchain fields (`BuildMachineOSBuild`,
  `DTPlatform*`, `DTSDK*`, `DTXcode*`) and `LSMinimumSystemVersion`
  (`11` -> `12.0`, required because Xcode 27 rejects the original 10.11 target
  and 12.0 is the supported floor).

Consequence: the shipped binary cannot be reproduced byte-for-byte from this
tree with the current toolchain, and its exact build configuration was never
recorded. The S0 artifact is a Release build; behavioral equivalence must be
shown by the S1 harness and the S3 hardware test, not by this comparison.
