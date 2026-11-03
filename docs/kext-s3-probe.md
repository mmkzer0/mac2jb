# S3 boundary probe (`kext-s3-probe`)

`kext-s3-probe` is a small C11 command-line tool that turns the S3 boundary checks of
[`kext-hardening-plan.md`](kext-hardening-plan.md) §8 into reproducible, machine-readable
evidence. It talks to the loaded `usbgadget.kext` through IOKit and CoreFoundation only.

What it is not:

- It does not install, load or unload a kext, needs no root and refuses to run its IOKit
  commands as root (the evidence must come from an unprivileged caller).
- It never sends a valid `PublishConfiguration`. The only dictionary it writes that the kext
  accepts is `{"Poke":"Poke"}`; every other dictionary it writes is deliberately invalid.
  Step 4 of §8 also asks for a *valid* `PublishConfiguration` through the host path; that is
  done with the real mac2jb host (libusbd), not with this tool, and is recorded separately.
- It does not call the user client's `Poke` selector (`IOConnectCallMethod`). It opens and
  closes connections only.

## Build

```sh
bash scripts/build-kext-s3-probe.sh
```

Builds `build/kext-s3-probe/kext-s3-probe` with `clang -std=c11 -Wall -Wextra -Werror` (no warning
is suppressed), runs `clang --analyze -Xclang -analyzer-werror` over the source, then runs
`kext-s3-probe self-test` and keeps its log in `build/kext-s3-probe/self-test.jsonl`. The only
dependencies are the macOS SDK's IOKit and CoreFoundation frameworks.

Source: `tests/kext/s3-probe/kext_s3_probe.c`.

## Output and exit codes

stdout carries JSON lines only: one object per event, always starting with a `start` event
(`uid`, `euid`, `pid`, `unix_time`, `os_version`, `os_build`) and ending with exactly one
`summary` object (`command`, `status`, `ok`, `exit`, and `services` when a command enumerated
services). Diagnostics go to stderr. Return codes are printed as `0x%08x` with a name, for example
`{"code":"0xe00002c2","name":"kIOReturnBadArgument","count":6}`.

| exit | meaning |
|---|---|
| 0 | the command's check passed |
| 1 | usage error, unreadable or malformed `PROVENANCE`, loaded-kext query failed, IOKit enumeration error, running as root, or a loaded UUID that cannot be read |
| 2 | `gay.bowser.usbgadget` is not loaded |
| 3 | the loaded UUID differs from the pin, or several are loaded |
| 4 | no `gay_bowser_usbgadget` service (or none with the given `--entry-id`) |
| 5 | `open-close`: user clients leaked, did not settle, or an open/close failed |
| 6 | `poke`: a call hung, or any call returned something other than success |
| 7 | `reject`: an invalid input was accepted |

Bounds (anything else is a usage error, exit 1): `--iterations` 1..100000, `--threads` 1..64,
`--settle-ms` 0..60000 (default 2000), `--call-timeout-ms` 1..600000 (default 5000). Numbers are
plain decimal digits. `--entry-id` is a nonzero decimal or `0x`-hex registry entry ID. Unknown
flags, repeated flags, positional arguments and flags that a command does not take are rejected.

## Pinned identity

`open-close`, `poke` and `reject` first run the identity check below and refuse with exit 2 or 3
(exit 1 if the check itself cannot be done) before they enumerate services, open a connection or
write a property. The pin is the `lc_uuid` of `drivers/PROVENANCE`:

- `--provenance PATH` (default `drivers/PROVENANCE`, relative to the working directory), or
- `--uuid UUID` (8-4-4-4-12 hex, either case; mutually exclusive with `--provenance`).

The `PROVENANCE` parser is strict and fails closed: exactly the nine contract keys in contract
order, LF line endings, each key once, uppercase `lc_uuid`, 64 lowercase hex digits for the
SHA-256 values, 40 for `source_commit`, bundle identifier `gay.bowser.usbgadget`, format
`mac2jb-bundled-kext-v1`. Anything else is exit 1 and nothing is touched.

The loaded UUID comes from `KextManagerCopyLoadedKextInfo` (`OSBundleUUID`, 16 bytes; the
in-process equivalent of `kmutil showloaded --list-only`, no root).

## Subcommands

### `identity [--provenance PATH | --uuid UUID]`

Compares the loaded `gay.bowser.usbgadget` UUID with the pin. Emits one `identity` event
(`pin_source`, `pinned_uuid`, `loaded_count`, `loaded_uuids`, `result`, `exit`).
Exit 0 match, 2 not loaded, 3 mismatch or several loaded, 1 error.

Proves: the kernel is running the binary built from the reviewed source, not the old upstream
v0.3.1 build (LC_UUID `124391F6-0CFF-32E0-8884-6F6360DF5D1C`) and not another build. Everything
else in this document is only meaningful if this holds.

### `inventory`

Lists every `gay_bowser_usbgadget` service (no open, no write; no identity gate). One `service`
event each: `entry_id`, `class`, `name`, `location`, `provider` (`class`, `name`, `location` in the
IOService plane), `busy_state`/`busy`, `userclient_children` (children of class
`gay_bowser_usbgadget_userclient`), `children` (all children) and `configuration_published`
(whether the registry entry has a `PublishConfiguration` property).
Exit 0 if at least one service, 4 if none.

Proves: the personality matched, one gadget per `IOUSBDeviceController` provider (three
`AppleT8132USBXDCI@0..2` on the M4 Pro), none stuck busy, and the baseline user-client count.

### `open-close --iterations N [--entry-id ID] [--settle-ms MS] [identity flags]`

For every selected service (all gadget services, or the one with `--entry-id`): reads the
baseline user-client count, runs N times `IOServiceOpen(service, mach_task_self(), 0)` +
`IOServiceClose`, samples the count after every open and every close, then polls (10 ms steps)
until the count equals the baseline or `--settle-ms` expires. Event `open-close`:
`baseline`, `max`, `final`, `settled`, `settle_ms_elapsed`, `open_histogram`, `close_histogram`,
`sample_errors`, `ok`. Exit 0 if clean, 5 if the count did not return to baseline, or any open or
close returned non-success, or a count could not be read.

Expected for a non-root caller (from `usbgadget_userclient.cpp`, to be confirmed on hardware):
`initWithTask` only rejects a null task and calls `IOUserClient::initWithTask`; it ignores the
caller's identity and the connection type (decision I7: the client stays available to local
tasks, its only selector is a no-argument `Poke`). So every open returns success and every close
returns success. A refused open would be a change in the kext, not a pass: it exits 5 so the
change is noticed.

Proves F17 (close/terminate): `clientClose` calls `terminate()`, so each closed client is stopped
and detached; `final == baseline` after N cycles shows no attached client is left per cycle.
`max` shows how many clients were attached at once (expected `baseline + 1`; more means
termination lagged the next open). Also exercises I2 (provider lifetime) and I9 (exactly-once
teardown) from the user-client side: a provider release that is missed or doubled shows up as a
stuck count, a hang or a panic. Another process that holds a connection during the run changes
the baseline; run it with the mac2jb host stopped.

### `poke --iterations N --threads K [--entry-id ID] [--call-timeout-ms T] [identity flags]`

K threads, each N times `IORegistryEntrySetCFProperties(service, {"Poke":"Poke"})` on every
selected service in turn, released together by a start flag. The main thread is a watchdog: a call
that has been running longer than T ms (default 5000) emits a `hang` event and stops further
calls. If a blocked call is still blocked another T ms later (threads cannot be cancelled out of
the kernel) the tool emits the `poke` and `summary` events and exits 6 without joining.
Event `poke`: `calls`, `calls_expected`, `hung_calls`, `max_call_us`, `wall_ms`,
`configuration_published`, `histogram`, `ok`. Exit 0 if no call hung and every call returned
success, 6 otherwise.

Expected for a non-root caller: success for every call (`setProperties` accepts `Poke` as an
`OSString`; with no published configuration it is a no-op). Run it before a mac2jb session has
published a configuration (`configuration_published` is `false`); with a published configuration
`Poke` makes the worker re-apply it to the controller.

Proves I3/I4 (`m_configuration` swapped only under `m_pokeLock`; thread lifecycle) as far as a
black box can: K concurrent `setProperties` callers contend on `m_pokeLock`, wake the worker
thread repeatedly, and none blocks or crashes. Run a second instance in another shell
for a cross-process storm, and run it together with `open-close` on the same `--entry-id` to put
`setProperties` against `clientClose`/`terminate` (I9/I10 teardown ordering).

### `reject [--entry-id ID] [identity flags]`

Sends six invalid inputs to every selected service and requires every one to be refused
(non-success). The kext validates the whole dictionary before changing any state and returns
`kIOReturnBadArgument` for each:

| case | input |
|---|---|
| `unknown-key` | `{"S3ProbeUnknownKey":"x"}` |
| `poke-with-number` | `{"Poke":1}` |
| `publish-configuration-with-string` | `{"PublishConfiguration":"not-a-dictionary"}` |
| `non-dictionary-array` | `["Poke"]` |
| `non-dictionary-string` | `"Poke"` |
| `valid-poke-plus-unknown-key` | `{"Poke":"Poke","S3ProbeUnknownKey":"x"}` |

One `reject` event per case (`kr`, `name`, `expected_kr`, `refused`, `expected_match`), one
`reject-result` per service (`refused`, `accepted`, `expected_code_matches`). Exit 0 if all are
refused, 7 if any is accepted. A refusal with a code other than `kIOReturnBadArgument` still
passes the exit check (`refused` is true) but `expected_match` is false: look at it, because it
means something other than the kext's own validation refused the write.

Proves I8 (`setProperties` validates shape and rejects unexpected keys) and, through the last
case, that validation is all-or-nothing: a valid `Poke` next to an unknown key does not run. The
empty dictionary and a `PublishConfiguration` dictionary are deliberately not sent: the kext
accepts both.

### `self-test`

No IOKit calls. Checks the `PROVENANCE` parser (the contract example, plus a negative case each
for empty file, NUL, CR, missing final LF, wrong format or bundle value, duplicate key, unknown
key, out-of-order key, missing first or last key, line without `=`, blank line, lowercase,
short, undashed and non-hex UUIDs, bad SHA-256 or commit length or case, bad build token), UUID
parsing and formatting, bounded decimal and entry-ID parsing (sign, space, hex, exponent,
overflow, zero, bounds), argument validation (bounds on N, K and ms, missing required flags,
duplicates, unknown and misplaced flags, `--provenance` with `--uuid`), the identity decision
(not loaded, match, mismatch, one-bit difference, several loaded, unreadable UUID), histogram
overflow handling and the JSON emitter. Exit 0 if all pass, 1 otherwise; one `test` event per
case.

## S3 sequence (normal user, after the reboot that loaded the kext)

Run from the repository root as the unprivileged login user, with the mac2jb GUI/host stopped.
Replace `$EV` with a fresh evidence directory (below). `$P` is the probe binary.

```sh
set -o pipefail                                           # keep the probe's exit code through tee
bash scripts/build-kext-s3-probe.sh                       # build + analyzer + self-test
P=build/kext-s3-probe/kext-s3-probe
scripts/install-driver.sh --status                        # MAC2JB_DRIVER_STATUS=verified, exit 0
$P identity            | tee $EV/01-identity.jsonl        # exit 0 (match)
$P inventory           | tee $EV/02-inventory.jsonl       # exit 0; 3 services expected on t8132
$P reject              | tee $EV/03-reject.jsonl          # exit 0; early non-root probe (§8 step 4)
$P open-close --iterations 1000 --settle-ms 5000 | tee $EV/04-open-close.jsonl   # exit 0
$P poke --iterations 1000 --threads 8             | tee $EV/05-poke.jsonl         # exit 0
$P inventory           | tee $EV/06-inventory-after.jsonl # userclient_children back to baseline
```

Then the boundary tests of §8 step 5 that this tool can drive (`ID` = an `entry_id` from the
inventory):

1. Cross-process poke storm: start `$P poke --iterations 20000 --threads 16 --entry-id ID` in
   two shells at once; both must exit 0.
2. `setProperties` during teardown: start `$P poke --iterations 20000 --threads 16 --entry-id ID`
   and, while it runs, `$P open-close --iterations 5000 --entry-id ID --settle-ms 10000` in
   another shell; both must exit 0.
3. Repeat `identity` after the storms: it must still exit 0 (no reload, same UUID).

Stop and start the rollback of §8 if any command exits 5, 6 or 7, if `identity` stops exiting
0, if a `hang` event appears, or if the machine panics. Exits 2/3/4 before any write mean the
precondition (driver loaded and pinned) did not hold: fix that, do not retry with another pin.

## Evidence to keep

Keep these per S3 run, outside git (see the privacy rules in the plan, §10: no `runs/` commits):

- every `*.jsonl` above and the stderr of each run;
- `shasum -a 256 build/kext-s3-probe/kext-s3-probe`, `git rev-parse HEAD`,
  `shasum -a 256 drivers/PROVENANCE`, and the `start` event's `os_version`/`os_build`;
- `kmutil showloaded --list-only | grep usbgadget` and
  `ioreg -r -c gay_bowser_usbgadget -l` before and after;
- `log show --last 30m --predicate 'sender == "usbgadget" OR eventMessage CONTAINS "usbgadget"'`
  and, if any, the panic report from `/Library/Logs/DiagnosticReports`.

Suggested layout: `EV=build/kext-s3-probe/evidence/$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$EV"`.

## Limits

- Black box: the probe observes return codes, the IOService-plane child count and hangs. It
  cannot see a leaked retain, a stale pointer or a lock-order violation that does not show up as a
  stuck count, a hang or a panic; those stay covered by the harness (`tests/kext`) and review.
- The user-client count is shared state: any other process opening the gadget during a run changes
  the baseline and can turn a clean run into exit 5.
- A hang cannot be cancelled: after exit 6 with `stuck_threads > 0` the blocked kernel call may
  still be stuck; treat it as an S3 abort condition and capture logs before rebooting.
