# Kext audit and hardening (S1)

Status: implementation record; hardware loading remains S3.
Scope: `vendor/macos_usb_gadget_poc/usbgadget/usbgadget/` (service and user
client), the S1 mock harness, and the static gate.

Method: invariants I1–I10 from `kext-hardening-plan.md`, forward and backward
path tracing, fault injection, strict compilation and static analysis. No
kernel sanitizers exist for third-party arm64e kexts; the harness models the
IOKit boundary in user space and cannot replace the S3 hardware gate.

## Findings

| ID | Location | Severity | Problem | Status |
|---|---|---|---|---|
| F1 | `usbgadget.cpp` `setProperties` | High | On `OSCollectionIterator::withCollection` failure the code released a null iterator (kernel null deref under memory pressure) | fixed |
| F2 | `usbgadget.cpp` `setConfigurationDict`/`setProperties` | High | A failed configuration copy was swallowed; the call still returned success and never applied the new configuration | fixed: `bool`, `kIOReturnNoMemory`, no `setProperty` |
| F3 | `usbgadget_userclient.cpp` | High | Provider was never retained/released and there was no `clientClose`; a client outliving the service was a use-after-free window | fixed: retain under a lock, `copyProvider`/`releaseProvider`, `clientClose`, `free` |
| F4 | `usbgadget_userclient.cpp` `externalMethod` | Medium | `m_provider` was read without `m_providerLock` while `clientClose` wrote it under the lock (TSan race) | fixed: removed the redundant pre-check; `methodPoke` re-checks under the lock |
| F5 | `usbgadget.cpp` `init`/`free`/`stop` | High | Unchecked `IOLockAlloc`; `thread_deallocate` without waiting; uninitialized `m_thread`; `stop` could hang forever after a failed `kernel_thread_start` | fixed: member init, lock check, `stopThread` with lock-protected wait and exactly-once handoff |
| F6 | `usbgadget.cpp` `free` | Medium | A `start()` without a later `stop()` leaked the provider retain | fixed: `free` releases a non-null provider |
| F7 | `usbgadget.cpp` `kernel_thread_start` | Medium | Function-pointer cast to `thread_continue_t` had an incompatible signature | fixed: `thread_bootstrap(void *, wait_result_t)` without a cast |
| F8 | `usbgadget.cpp` dictionary helpers / `setProperties` | Medium | Created `OSString`/`OSNumber` objects were not released; `Poke`/`PublishConfiguration` symbols leaked on some exits | fixed |
| F9 | `usbgadget.cpp` `doUpdate` | Medium | Unchecked `OSDictionary::withCapacity` | fixed |
| F10 | `usbgadget_userclient.h` | Low | Declared but undefined `setProperties` override produced a dead undefined symbol | fixed: declaration removed |
| F11 | `usbgadget.cpp` `start`/`stop` | Medium | `registerService` ran before provider validation; provider was not retained | fixed: validate, retain, then register; release in `stop`/`free` |
| F12 | `usbgadget.cpp` `setProperties` | Low | A non-dictionary `PublishConfiguration` value was silently ignored | fixed: returns `kIOReturnBadArgument` |

## Teardown protocol after the fix

- Service start: validate provider, retain, assign under `m_pokeLock`, then
  `super::start`, then `registerService`. Failure releases and nulls.
- Worker: started once in `init`; loops under `m_pokeLock`; drops it only while
  sleeping; observes `m_exitThreads` under the lock; on exit sets
  `m_threadDone` and wakes all waiters.
- `stopThread` (used by `stop` and `free`): sets exit and `m_needsUpdate` under
  the lock, waits on `m_threadDone` via `IOLockSleep` (lock released while
  asleep), takes `m_thread` under the lock and nulls it, then deallocates the
  local copy. Idempotent; a concurrent second caller neither waits nor
  deallocates.
- `free`: `stopThread`, release provider if non-null, release configuration,
  free the lock once, null both.
- User client: members initialized before any early return; provider retained
  in `start` under `m_providerLock`; `stop` and `clientClose` both call the
  idempotent `releaseProvider`; `methodPoke` takes a retained copy under the
  lock and rejects with `kIOReturnNotReady` after close; `free` releases the
  provider and the lock exactly once.

## Verification

- `scripts/check-kext-source.sh`: strict syntax pass (`-Wall -Wextra -Werror
  -Wconversion -Wshorten-64-to-32 -Wnull-dereference`) and `clang --analyze`
  pass for both translation units.
- `scripts/build-kext.sh`: Release build, arm64e, exactly
  `Contents/Info.plist` and `Contents/MacOS/usbgadget`, unsigned.
  Current executable SHA-256 `41f650949afcecf9bd730212d55a2ee3254c7c748962d5ebb2d81e86ed8546cf`.
- `nm -u`: no undefined symbol from this kext's own classes. The new kernel
  imports (`IOLockSleep`, `IOLockWakeup`, `IORegistryEntry::setProperties`,
  `OSSymbol::metaClass`, `IOService::metaClass`) exist in the KDK 26.0 kernel
  symbol table.
- Mock harness: `scripts/test-kext-harness.sh` builds and runs 12 tests under
  ASan+UBSan and again under TSan; all pass (5.1 s). Coverage: shim lock
  semantics; `setProperties` validation and an allocation-failure sweep; thread
  start failure; lifecycle permutations (start/stop/free, start/free, double
  stop, free without start/init, super failures); exactly-once teardown with
  100 stop/stopThread/poke races; user-client init/start/stop/clientClose/free
  orderings, poke-vs-close (200 iterations), not-ready dispatch; deadlock
  scenario with the worker holding `m_pokeLock`.
  Limits: the shim models IOKit; it cannot model the real
  `IOUSBDeviceController`, and the tests use `#define private public` to reach
  internals.

## Research dispositions

The SQLite testing review and the formal/semi-formal verification research are
dispositioned in `docs/kext-verification-options.md`. Adopted in S1: the
allocation-failure sweep shape, lifecycle permutations with a live-object
baseline, and the watchdog. Adopted next: a general shim-operation failure
sweep, an operation trace with “no call after stop/free”, a tagged live-object
registry, and a TLA+ teardown model checked with TLC. Rejected: TCL/TH3/
dbsqlfuzz artifacts, VFS shims, Frama-C/TrustInSoft/seL4, and KASAN for
third-party kexts.

## Residual risks

- `doUpdate` calls the provider's `setProperties` while holding `m_pokeLock`
  (pre-existing). No reentrancy is known, but the harness cannot model the real
  `IOUSBDeviceController`. The S3 load/unload and transfer tests must watch for
  hangs.
- No authorization check was added to the user client. The host runs
  unprivileged and the configuration path is gated by IOKit registry property
  policy; a non-root probe belongs to S3. Selector 0 is an idempotent re-apply.
- `clientClose` returns success without calling `super::clientClose` (the base
  returns `kIOReturnUnsupported`; `clientDied` calls `clientClose`).
- The worker continuation returns normally (no `thread_terminate`); this is the
  pre-existing kernel-thread pattern.
- Kernel ABI, PAC signing, AuxKC policy and hardware timing are outside static
  verification; S3 is the gate.
- The shipped binary corresponds to a Debug build of an older toolchain; our
  Release artifact differs in codegen (see `kext-provenance.md`).
