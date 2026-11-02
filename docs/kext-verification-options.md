# Kext verification options (S1/S1.1 decision record)

Status: decision record after the S1/S1.1 audit and two research passes.
Sources:

- SQLite testing review: read-only inspection of `github.com/sqlite/sqlite` at
  `3044c8b3b2be8f2fff54bb8357aa5377c01570c6` (2026-11-01). TH3 and dbsqlfuzz
  were not inspected: proprietary and unpublished respectively.
- Formal/semi-formal verification research: tool documentation and papers,
  reviewed below.

## Adopted in S1

- **Allocation-failure sweep (SQLite `malloc_common.tcl` / `do_malloc_test`
  shape).** The harness iterates the Nth allocation until a trial injects no
  failure, asserts the expected `kIOReturnNoMemory`, unchanged configuration and
  no leaks. Implemented in harness test `2_set_properties_oom`.
- **General shim-operation failure sweep.** Iterate the Nth tracked allocation,
  `IOLockAlloc`, `kernel_thread_start` and provider `setProperties` in one-shot
  and sticky modes, for both teardown variants; stop at the first N that injects
  nothing and require a minimum number of reached sites. Implemented in harness
  tests `8a`–`8h`; iterator creation and the second `getNextObject` remain
  uncovered.
- **Operation trace with teardown and lock assertions.** A 256-entry ring dumps
  the last 32 shim calls on failure; a worker call after `stop()`/`free()`
  returns, a running worker, unbalanced lock/unlock, and a use-after-free lock
  are violations. `IOSleepWithLeeway` and lock operations use a seeded jitter.
- **S1.1 boundary and reentrancy checks.** A failed worker start fails `init`;
  unknown property keys and non-`OSString` Poke values are rejected; a failed
  registry publication leaves both the property and the private copy unchanged.
  The provider callback runs outside `m_pokeLock` with retained snapshots, and a
  synchronous reentrant callback must not deadlock or lose the pending poke.
- **Lifecycle permutations with a live-object baseline.** Every ordering of
  start/stop/stopThread/free and the user-client orderings must return the
  object/lock/thread counters to baseline. This is the SQLite post-run
  `integrity_check` idea reduced to our object graph.
- **Exactly-once teardown and deadlock watchdogs.** 100 racing stop/stopThread/
  poke iterations and a worker-holds-the-lock scenario, each under a hard
  timeout; ASan+UBSan and TSan variants.
- **Strict compile and analyzer gate.** `-Wall -Wextra -Werror -Wconversion
  -Wshorten-64-to-32 -Wnull-dereference` plus `clang --analyze` on both TUs.
- **No `assert()` as a runtime guard.** The SDK `kern/assert.h` compiles to
  `(void)0` unless `MACH_ASSERT` or `APPLE_KEXT_ASSERTIONS` is set; the kext
  uses explicit checks and fail-closed returns instead.

## Adopted next (not implemented in S1)

- **Sweep extension for iterator operations.** Add `OSCollectionIterator`
  creation and the second `getNextObject` to the general sweep; the S1 sweep
  covers allocation, `IOLockAlloc`, thread start and provider `setProperties`.
- **Tagged live-object registry.** Attach `__FILE__:__LINE__` to every tracked
  `OSObject`/`IOLock` so a baseline diff names the leaking site, not just the
  count. SQLite `src/mem2.c` guards/titles are the model.
- **Two-tier self-check in the shim.** A no-allocation `quick` check (provider
  refs, thread state, config types, exactly-once flags) after every trial and a
  full check at scenario end. Keep it in the harness; do not add test hooks to
  the shipped kext.
- **Coverage report, then scoped mutation testing.** `llvm-cov` over the
  harness first (report, not gate); later mutate the ~200 teardown/
  `setProperties` lines and require the harness to kill each mutant. SQLite
  TH3's mutation test is the reference; start with the teardown paths.
- **S2 diagnostics.** `kmutil`/`kextutil` bundle and linkage diagnostics before
  loading, the matching KDK check, and reproducible-build verification, driven
  by `scripts/kext-s2-preflight.sh`. The non-root IOKit registry-property probe
  belongs to early S3, after the kext is loaded, and is not a pre-load gate.

## Formal experiment (bounded, not S1)

- **TLA+ teardown model, written from the code and checked with TLC.** Model
  service states (init/start/stop/free), worker states (running/exiting/done),
  user-client states (open/closing/closed), the provider reference count, and
  the lock. Invariants: no double release, no poke after close, no deadlock,
  eventual `m_threadDone`. The research sketch is **not usable**: its
  `SafeClientAccess` invariant is violated by design, the provider-refcount
  model does not match the code (the service releases in `stop`, not `free`),
  and the suggested TLC command has no config or invariant list. Method yes,
  artifact no. Cost: one to two days including TLC setup.
- **CBMC on the shim.** Conditional. The proposed example is not runnable as
  written (`__CPROVER_ASYNC_1`, `--race-check`, `nondet_osdict()` unverified),
  and CBMC's C++ `std::mutex`/`condition_variable` modelling needs a prototype.
  Prototype only after the TLA+ model; do not treat it as a gate.

## Rejected

- **TCL harness, TH3, dbsqlfuzz.** The TCL harness needs Tcl and `testfixture`;
  TH3 and dbsqlfuzz are proprietary/unpublished. Only the driver shapes
  transfer (adopted above).
- **VFS/storage shims** (`test_multiplex.c`, `test_onefile.c`, `test_quota.c`,
  `test_async.c`, `test_fs.c`, `test_journal.c`). They model a paged file with
  locks and journals; the kext has no file/pager path. The pattern (wrap the
  substrate) is already our shim.
- **Frama-C, TrustInSoft, seL4 refinement.** C-only, commercial, or
  person-years; the C++ IOKit object model and Mach runtime are outside scope.
- **KASAN/ASan in the real kext.** Third-party arm64e kexts have no supported
  kernel sanitizer path. The research claim that KASAN is internal-only was
  labeled fact without a citation; we treat it as unverified and rely on the
  user-space harness plus S3. A KDK development kernel is a possible S3
  diagnostic but needs a matching KDK and boot policy.
- **KLEE now.** Mock-only and high effort; the harness already has symbolic-free
  fault sweeps. Revisit only if a specific parser/hostile-input surface appears.
- **SPIN/Promela in addition to TLA+.** Same class of result; one model is
  enough.
- **Runtime test-control surface in the shipped kext.** SQLite's
  `sqlite3_test_control` is a production API; exposing fault hooks through
  `IOExternalMethod` would add attack surface. Test hooks stay compile-time and
  harness-only.
- **Virtual-clock timing assumptions.** SQLite's test controls expose timing;
  our harness uses bounded real-time waits with watchdogs. Deterministic virtual
  time is not feasible without restructuring the kernel timing calls.

## Corrections to the research (review findings)

- SQLite paths were corrected by the researcher: `SQLITE_MEMDEBUG` lives in
  `src/mem2.c`, `ossfuzz.c` in `test/`, `vfslog` in `ext/misc/vfslog.c` (no
  `test/vfslog.test`), and the binary log is `src/test_osinst.c`. The counts
  (39 `SQLITE_TESTCTRL_*`, 1306 test files) are observed.
- The formal report's TLA+ and CBMC artifacts are sketches, not runnable tests;
  its "Infer P0, 2-4 hours" estimate ignores the C++ compile database problem;
  its KASAN claim lacked a citation; the KDK development-kernel estimate is
  optimistic given no matching KDK is installed. The methodological ranking
  (TLA+ first, CBMC conditional, Frama-C/seL4 rejected) survives review.

## Verification status

- Harness: 22 tests, pass under ASan+UBSan and TSan (~7.1 s); 30 ASan+UBSan
  and 10 TSan full-suite stress loops passed.
- Strict source gate: pass.
- Final artifact: 114360 bytes, SHA-256
  `644fda29022f7152ab11c029b4bf342160180af364ce8748ad965a0bd0626fd0`.
- S2 preflight: pass with `KDK_27.0_26A428.kdk`; private LocalPolicy captured
  privately (Permissive baseline, `smb2:false`); no SIP change, install or load.
- Not yet: iterator-creation and second-`getNextObject` sweep sites, tagged
  registry, two-tier self-check, coverage, mutation, TLA+ model. The early-S3
  non-root registry probe runs after the kext is loaded, not before.
