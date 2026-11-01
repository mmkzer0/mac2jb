# Kext audit and hardening (S1, S1.1)

Status: implementation record for S1 and the S1.1 follow-up; hardware loading
remains S3.
Scope: `vendor/macos_usb_gadget_poc/usbgadget/usbgadget/` (service and user
client), the S1/S1.1 mock harness, and the static gate.

Method: invariants I1–I10 from `kext-hardening-plan.md`, forward and backward
path tracing, fault injection, strict compilation and static analysis. No
kernel sanitizers exist for third-party arm64e kexts; the harness models the
IOKit boundary in user space and cannot replace the S3 hardware gate.

## Findings

| ID | Location | Severity | Problem | Status |
|---|---|---|---|---|
| F1 | `usbgadget.cpp` `setProperties` | High | On `OSCollectionIterator::withCollection` failure the code released a null iterator (kernel null deref under memory pressure) | fixed |
| F2 | `usbgadget.cpp` `setProperties` | High | A failed configuration copy was swallowed; the call still returned success and never applied the new configuration | fixed: validate, copy, publish, then commit; failure returns an error and leaves state unchanged |
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
| F13 | `usbgadget.cpp` `init` | Medium | A failed `kernel_thread_start` was logged but init returned success, so a workerless service registered and Poke reported success | fixed: init frees the lock, returns false, and `free` remains safe after the partial init |
| F14 | `usbgadget.cpp` `doUpdate` | Medium | The provider callback ran under `m_pokeLock`; a synchronous reentrant callback would self-deadlock, and a slow callback serialized pokes | fixed: retain configuration/provider snapshots, consume the pending update, drop the lock for the callback, and keep a callback poke pending; test 7b |
| F15 | `usbgadget.cpp` `setProperties` | Medium | Unknown keys were ignored, `Poke` accepted any value type, and a failed `setProperty` was reported as success after the configuration had already changed | fixed: validate the entire dictionary, require the host's `OSString` Poke value, publish before committing, and leave state unchanged on failure; test 1 |

## Teardown protocol after the fix

- Service start: validate provider, retain, assign under `m_pokeLock`, then
  `super::start`, then `registerService`. Failure releases and nulls.
- Worker: started once in `init`; when an update is pending it snapshots the
  configuration and controller under `m_pokeLock`, retains both, clears the
  pending flag, drops the lock, and calls the provider. A poke during that call
  sets the flag again and is processed on the next pass; a callback poke is
  therefore not lost. The worker sleeps only outside the lock; on exit it sets
  `m_threadDone` and wakes all waiters.
- `stopThread` (used by `stop` and `free`): sets exit and `m_needsUpdate` under
  the lock, waits on `m_threadDone` via `IOLockSleep` (lock released while
  asleep), takes `m_thread` under the lock and nulls it, then deallocates the
  local copy. Idempotent; a concurrent second caller neither waits nor
  deallocates.
- `setProperties`: validates every key and value before changing state;
  `Poke` must be the host's `OSString`, unknown keys and non-dictionary
  configurations return `kIOReturnBadArgument`. The private config copy is made,
  the registry property is published, and only then is `m_configuration` swapped
  under `m_pokeLock`; a copy or publication failure leaves both unchanged.
- `free`: `stopThread`, release provider if non-null, release configuration,
  free the lock once, null both.
- User client: members initialized before any early return; provider retained
  in `start` under `m_providerLock`; `stop` and `clientClose` both call the
  idempotent `releaseProvider`; `methodPoke` takes a retained copy under the
  lock and rejects with `kIOReturnNotReady` after close; `free` releases the
  provider and the lock exactly once.

## Boundary decision (I7)

The user client remains available to local tasks. It exposes only selector 0
(`Poke`), which re-applies the stored configuration and carries no caller data.
Configuration writes use `IORegistryEntrySetCFProperties`, the boundary the
unprivileged host already uses; no entitlement check was added because it would
break that host. S2 must capture a non-root probe proving the registry-write
policy and record the residual local-process Poke capability.

## Verification

- `scripts/check-kext-source.sh`: strict syntax pass (`-Wall -Wextra -Werror
  -Wconversion -Wshorten-64-to-32 -Wnull-dereference`) and `clang --analyze`
  pass for both translation units.
- `scripts/build-kext.sh`: Release build, arm64e, exactly
  `Contents/Info.plist` and `Contents/MacOS/usbgadget`, unsigned.
  Current executable SHA-256 `e8e82a5794b50a9ab4ec8bfd2944848189e4c93ba2a8e53c946ccff7e8a11d8e`.
- `nm -u`: no undefined symbol from this kext's own classes. The new kernel
  imports (`IOLockSleep`, `IOLockWakeup`, `IORegistryEntry::setProperties`,
  `OSString::metaClass`, `OSSymbol::metaClass`, `IOService::metaClass`) exist in
  the KDK 26.0 kernel symbol table.
- Mock harness: `scripts/test-kext-harness.sh` builds and runs 21 tests under
  ASan+UBSan and again under TSan; all pass (5.75 s). Coverage: shim lock
  semantics; `setProperties` validation (unknown keys, Poke type, publish
  failure/no state change) and an allocation-failure sweep; fail-closed thread
  start failure; lifecycle permutations (start/stop/free, start/free, double
  stop, free without start/init, super failures); exactly-once teardown with
  100 stop/stopThread/poke races; user-client init/start/stop/clientClose/free
  orderings, poke-vs-close (200 iterations), not-ready dispatch; stop waits for
  an in-flight controller call while a poke completes; synchronous controller
  reentrancy without deadlock or a lost update; general one-shot and sticky
  fault sweeps over every tracked allocation, `IOLockAlloc`,
  `kernel_thread_start` and provider `setProperties` for both teardown
  variants; a 256-entry operation trace dumped on failure; worker-after-
  teardown, lock-balance and freed-lock checks; seeded sleep/lock jitter.
  Limits: the shim models IOKit; it cannot model the real
  `IOUSBDeviceController`, and the tests use `#define private public` to reach
  internals.

## Research dispositions

The SQLite testing review and the formal/semi-formal verification research are
dispositioned in `docs/kext-verification-options.md`. Adopted in S1: the
allocation-failure sweep shape, lifecycle permutations with a live-object
baseline, the watchdog, the general shim-operation failure sweep, the operation
trace with “no call after stop/free” and lock-balance checks, and seeded
scheduling jitter. Adopted next: a tagged live-object registry, sweep sites for
iterator creation and the second `getNextObject`, and a TLA+ teardown model
checked with TLC. Rejected: TCL/TH3/dbsqlfuzz artifacts, VFS shims,
Frama-C/TrustInSoft/seL4, and KASAN for third-party kexts.

## Residual risks

- The real `IOUSBDeviceController` reentrancy contract remains unknown; the
  mock negative test covers a synchronous `triggerUpdate` callback. The S3
  load/unload and transfer tests must watch for provider-induced stalls or
  hangs.
- `start()` called twice overwrites `m_provider` and `m_controller_provider`
  after `retain()`, leaking one retain. The kernel start path calls it once;
  this is outside the tested contract and has no start-twice test.
- The sweeps' minimum-site thresholds (10 allocations with 12 observed, 2 lock
  allocations, 1 thread start, 1 provider call) and the 0-or-1 controller
  update assume the current allocation pattern; source changes require
  retuning.
- The seeded jitter reproduces the RNG stream, not the OS schedule; a failing
  trial may not replay byte-for-byte.
- The I7 decision keeps the user client open to local tasks (selector 0 is an
  idempotent re-apply). The configuration path relies on IOKit's registry-property
  write policy; a non-root probe belongs to S2 and the residual local-process
  Poke capability remains.
- `clientClose` returns success without calling `super::clientClose` (the base
  returns `kIOReturnUnsupported`; `clientDied` calls `clientClose`).
- The worker continuation returns normally (no `thread_terminate`); this is the
  pre-existing kernel-thread pattern.
- Kernel ABI, PAC signing, AuxKC policy and hardware timing are outside static
  verification; S3 is the gate.
- The shipped binary corresponds to a Debug build of an older toolchain; our
  Release artifact differs in codegen (see `kext-provenance.md`).
