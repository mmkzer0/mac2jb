# Vendored upstream components

The pinned source revisions and project URLs are listed in `../upstream.lock`.
The MIT licenses and APSL 2.0 license texts are retained alongside the relevant
source files. Root `LICENSE` does not override third-party terms.

- libusbd: based on the upstream revision in `upstream.lock`, with dated
  downstream changes in `Makefile` and `src/plat/macos/impl.c`, plus a
  2026-10-26 IOKit service-handle ownership fix in
  `src/plat/macos/alt_IOUSBDeviceControllerLib.c`. The wrapper retains its own
  service reference and balances its release; the original author credits and
  licenses remain. The pin records the upstream origin, not an unmodified tree.
- macos_usb_gadget_poc: intentionally trimmed upstream source. Contains
  `usbgadget/` (MIT-licensed kernel extension source and Xcode project), plus
  provenance README and APSL text. The unused `usb_device/` proof of concept,
  upstream convenience shell scripts, prebuilt `usbgadget.kext/`, and machine-local
  Xcode user settings are excluded. This is not a byte-for-byte upstream tree.
  2026-11-01 downstream change: MACOSX_DEPLOYMENT_TARGET was raised from 10.11
  to 12.0 (Xcode 27 rejects older targets) and the Info.plist Copy Bundle
  Resources entry was removed so the bundle keeps exactly Contents/Info.plist;
  upstream.lock still records the upstream origin revision. 2026-11-01
  downstream hardening: usbgadget.kext lifetime/ownership/thread teardown paths
  (provider retain, worker join, user-client provider release) were fixed.
- ns2jb: the `BermTheSequel/ns2jb2` fork, based on pepsipu's
  original project, replaces the previous runtime. Its complete snapshot and
  tests are pinned in `upstream.lock`. All runtime, exploit, and test files are
  unchanged. `SHA256SUMS` is regenerated over the actual snapshot because the
  fork's supplied manifest is retained separately. Its original
  manifest is retained in `packaging/ns2jb-8461942-SHA256SUMS.upstream`.
  `assets/bootstrap.bas` is copied byte for byte from the fork, including its
  five-argument START interface. `scripts/prepare-bootstrap.cjs` copies and
  checks that exact asset; no compatibility transformation is applied. The
  wrappers and senders use the five-argument command. Previously saved
  nine-argument NS2 programs must be replaced before testing this build.
  Any redistributor must establish their
  own rights to ship it; a Git URL or public availability alone is not a license.

Do not run `scripts/freeze-upstream.sh` in a normal user installation. It is a
maintainer-only source refresh requiring a new provenance, license and security
review before publication.
