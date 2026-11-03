'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn, spawnSync} = require('node:child_process');

const repo = path.resolve(__dirname, '..');
const PROVENANCE_KEYS = ['format', 'bundle_identifier', 'executable_sha256', 'info_plist_sha256', 'lc_uuid',
  'source_tree_sha256', 'source_commit', 'xcode_build', 'sdk_build'];
const UPSTREAM_UUID = '124391F6-0CFF-32E0-8884-6F6360DF5D1C'; // pre-hardening v0.3.1 binary

function parseProvenance(text) {
  const lines = text.split('\n');
  assert.equal(lines.pop(), '', 'PROVENANCE ends with a newline');
  assert.deepEqual(lines.map(line => line.slice(0, line.indexOf('='))), PROVENANCE_KEYS);
  return Object.fromEntries(lines.map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]));
}
const pins = parseProvenance(fs.readFileSync(path.join(repo, 'drivers/PROVENANCE'), 'utf8'));

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function machoUuid(buffer) { // LC_UUID of a thin 64-bit Mach-O
  assert.equal(buffer.readUInt32LE(0), 0xfeedfacf, 'thin 64-bit Mach-O');
  let offset = 32;
  for (let index = 0, count = buffer.readUInt32LE(16); index < count; index++) {
    if (buffer.readUInt32LE(offset) === 0x1b) {
      const hex = buffer.subarray(offset + 8, offset + 24).toString('hex').toUpperCase();
      return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
    }
    offset += buffer.readUInt32LE(offset + 4);
  }
  return null;
}

function loadedRow(uuid) { // one `kmutil showloaded --list-only` row for our bundle identifier
  return `  210    0 0xfffffe000a7c4000 0x1b000    0x1b000    gay.bowser.usbgadget (1.01) ${uuid} <8 7 6 5 3 1>\n`;
}

function tree(dir) { // sorted relative entries below dir
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, {recursive: true}).map(String).sort();
}

function stub(bin, name, lines) {
  fs.writeFileSync(path.join(bin, name), ['#!/bin/bash', 'set -eu', ...lines, ''].join('\n'), {mode: 0o755});
}

// A disposable copy of the installer whose system folders, owner, lock and tools
// point into a temporary directory. Production keeps its fixed PATH and paths.
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mac2jb-driver-'));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  assert.match(root, /^[A-Za-z0-9_/.-]+$/);
  const f = {
    root,
    bin: path.join(root, 'bin'),
    extensions: path.join(root, 'Extensions'),
    support: path.join(root, 'Application Support'),
    runDir: path.join(root, 'run'),
    trash: path.join(root, 'Trash'),
    calls: path.join(root, 'calls.log'),
  };
  f.state = path.join(f.support, 'mac2jb', 'driver');
  f.target = path.join(f.extensions, 'usbgadget.kext');
  f.marker = path.join(f.extensions, '.mac2jb-usbgadget-restart-required');
  f.lock = path.join(f.runDir, 'mac2jb-driver-install.lock');
  f.bundled = path.join(root, 'drivers', 'usbgadget.kext');
  for (const dir of [path.join(root, 'scripts'), f.bin, f.extensions, f.support, f.runDir]) {
    fs.mkdirSync(dir, {recursive: true});
  }
  fs.cpSync(path.join(repo, 'drivers'), path.join(root, 'drivers'), {recursive: true});
  const owner = spawnSync('/usr/bin/stat', ['-f', '%Su:%Sg', root], {encoding: 'utf8'}).stdout.trim();
  let script = fs.readFileSync(path.join(repo, 'scripts/install-driver.sh'), 'utf8');
  const rewrite = (from, to) => {
    assert.ok(script.includes(from), 'installer changed; update the fixture rewrite for: ' + from);
    script = script.replace(from, to);
  };
  rewrite('PATH=/usr/bin:/bin:/usr/sbin:/sbin', `PATH=${f.bin}:/usr/bin:/bin:/usr/sbin:/sbin`);
  rewrite('if [[ "$EUID" != 0 ]]; then', 'if false; then');
  rewrite("STATE_DIR='/Library/Application Support/mac2jb/driver'", `STATE_DIR='${f.state}'`);
  rewrite('LOCK_FILE=/var/run/mac2jb-driver-install.lock', `LOCK_FILE=${f.lock}`);
  rewrite('OWNER=root:wheel', `OWNER=${owner}`);
  script = script.replaceAll('/Library/Extensions', f.extensions);
  assert.doesNotMatch(script.replaceAll(f.state, '').replaceAll(f.extensions, ''), /\/Library\/|\/var\/run/);
  f.script = path.join(root, 'scripts', 'install-driver.sh');
  fs.writeFileSync(f.script, script, {mode: 0o755});
  stub(f.bin, 'uname', ['case "$1" in -s) echo Darwin;; -m) echo arm64;; *) exit 1;; esac']);
  stub(f.bin, 'csrutil', ['printf "%s\\n" "${MAC2JB_TEST_SIP:-System Integrity Protection status: unknown (Custom Configuration).}"',
    'exit "${MAC2JB_TEST_CSR_EXIT:-0}"']);
  stub(f.bin, 'chown', ['printf "chown %s\\n" "$*" >> "$MAC2JB_TEST_CALLS"']);
  stub(f.bin, 'sync', ['exit 0']);
  stub(f.bin, 'sudo', ['echo "Unexpected privilege request in test" >&2', 'exit 99']);
  stub(f.bin, 'sysctl', ['[[ "$*" == "-n kern.boottime" ]] || exit 1',
    'echo "{ sec = ${MAC2JB_TEST_BOOT:-1000}, usec = 0 } Thu Jan  1 00:16:40 1970"']);
  stub(f.bin, 'kmutil', [
    'printf "kmutil %s\\n" "$*" >> "$MAC2JB_TEST_CALLS"',
    'case "$1" in',
    '  showloaded) printf "%s" "${MAC2JB_TEST_SHOWLOADED:-}"; exit "${MAC2JB_TEST_SHOWLOADED_EXIT:-0}";;',
    '  load) if [[ "${MAC2JB_TEST_LOAD_EXIT:-0}" != 0 ]]; then echo "fixture: macOS refused unsigned driver" >&2; fi',
    '        exit "${MAC2JB_TEST_LOAD_EXIT:-0}";;',
    '  *) exit 64;;',
    'esac']);
  stub(f.bin, 'trash', ['mkdir -p "$MAC2JB_TEST_TRASH"', 'printf "trash %s\\n" "$*" >> "$MAC2JB_TEST_CALLS"',
    'for item in "$@"; do /bin/mv "$item" "$MAC2JB_TEST_TRASH/"; done']);
  f.run = (args = [], env = {}) => spawnSync('/bin/bash', [f.script, ...args], {encoding: 'utf8',
    env: {...process.env, MAC2JB_TEST_CALLS: f.calls, MAC2JB_TEST_TRASH: f.trash, ...env}});
  f.loadCalls = () => (fs.existsSync(f.calls) ? fs.readFileSync(f.calls, 'utf8') : '')
    .split('\n').filter(line => line.startsWith('kmutil load'));
  f.status = env => {
    const result = f.run(['--status'], env);
    return {code: result.status, state: result.stdout.split('\n')[0], stdout: result.stdout, stderr: result.stderr};
  };
  return f;
}

function assertPinnedInstall(f) {
  assert.deepEqual(tree(f.target), ['Contents', 'Contents/Info.plist', 'Contents/MacOS', 'Contents/MacOS/usbgadget']);
  for (const file of ['Contents/Info.plist', 'Contents/MacOS/usbgadget']) {
    assert.deepEqual(fs.readFileSync(path.join(f.target, file)), fs.readFileSync(path.join(f.bundled, file)));
  }
  const mode = rel => (fs.statSync(path.join(f.target, rel)).mode & 0o777).toString(8);
  assert.deepEqual(['', 'Contents', 'Contents/MacOS', 'Contents/Info.plist', 'Contents/MacOS/usbgadget'].map(mode),
    ['755', '755', '755', '644', '755']);
}

function oldMarker(f) {
  fs.utimesSync(f.marker, 500, 500); // before the fixture boot time (1000): no restart pending
}

test('bundled pins agree with the shipped bytes', () => {
  const bundle = path.join(repo, 'drivers/usbgadget.kext');
  assert.deepEqual(tree(bundle), ['Contents', 'Contents/Info.plist', 'Contents/MacOS', 'Contents/MacOS/usbgadget']);
  assert.equal(pins.format, 'mac2jb-bundled-kext-v1');
  assert.equal(pins.bundle_identifier, 'gay.bowser.usbgadget');
  assert.equal(sha256(path.join(bundle, 'Contents/MacOS/usbgadget')), pins.executable_sha256);
  assert.equal(sha256(path.join(bundle, 'Contents/Info.plist')), pins.info_plist_sha256);
  assert.equal(machoUuid(fs.readFileSync(path.join(bundle, 'Contents/MacOS/usbgadget'))), pins.lc_uuid);
  assert.notEqual(pins.lc_uuid, UPSTREAM_UUID);
  assert.equal(fs.readFileSync(path.join(repo, 'drivers/SHA256SUMS'), 'utf8'),
    `${pins.info_plist_sha256}  Contents/Info.plist\n${pins.executable_sha256}  Contents/MacOS/usbgadget\n`);
  const id = spawnSync('/usr/bin/plutil', ['-extract', 'CFBundleIdentifier', 'raw', '-o', '-',
    path.join(bundle, 'Contents/Info.plist')], {encoding: 'utf8'});
  assert.equal(id.stdout.trim(), pins.bundle_identifier);
});

test('--verify accepts the pinned copy and rejects every deviation', t => {
  const cases = [
    ['tampered executable', f => fs.appendFileSync(path.join(f.bundled, 'Contents/MacOS/usbgadget'), 'x')],
    ['extra file', f => fs.writeFileSync(path.join(f.bundled, 'Contents/extra'), 'signing metadata')],
    ['extra empty folder', f => fs.mkdirSync(path.join(f.bundled, 'Contents/Resources'))],
    ['symlinked Info.plist', f => {
      const plist = path.join(f.bundled, 'Contents/Info.plist');
      fs.renameSync(plist, path.join(f.root, 'Info.plist'));
      fs.symlinkSync(path.join(f.root, 'Info.plist'), plist);
    }],
    ['PROVENANCE digest drift', f => {
      const file = path.join(f.root, 'drivers/PROVENANCE');
      fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/executable_sha256=./, 'executable_sha256=0'));
    }],
    ['duplicated PROVENANCE key', f => fs.appendFileSync(path.join(f.root, 'drivers/PROVENANCE'), `lc_uuid=${UPSTREAM_UUID}\n`)],
    ['malformed lc_uuid', f => {
      const file = path.join(f.root, 'drivers/PROVENANCE');
      fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace(/lc_uuid=.*/, 'lc_uuid=not-a-uuid'));
    }],
    ['unsupported format', f => {
      const file = path.join(f.root, 'drivers/PROVENANCE');
      fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('mac2jb-bundled-kext-v1', 'mac2jb-bundled-kext-v0'));
    }],
    ['SHA256SUMS lists another binary', f => fs.writeFileSync(path.join(f.root, 'drivers/SHA256SUMS'),
      `${pins.info_plist_sha256}  Contents/Info.plist\n${'a'.repeat(64)}  Contents/MacOS/usbgadget\n`)],
  ];
  const clean = fixture(t);
  const ok = clean.run(['--verify']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, new RegExp(pins.lc_uuid));
  for (const [name, mutate] of cases) {
    const f = fixture(t);
    mutate(f);
    const result = f.run(['--verify']);
    assert.notEqual(result.status, 0, name);
    const status = f.status({MAC2JB_TEST_SHOWLOADED: loadedRow(pins.lc_uuid)});
    assert.deepEqual([status.code, status.state], [15, 'MAC2JB_DRIVER_STATUS=bundle-invalid'], name);
  }
});

test('fresh install places exactly the pinned build and requests one load', t => {
  const f = fixture(t);
  const result = f.run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assertPinnedInstall(f);
  assert.deepEqual(f.loadCalls(), ['kmutil load -p ' + f.target]);
  assert.deepEqual(tree(f.extensions), ['.mac2jb-usbgadget-restart-required', 'usbgadget.kext',
    'usbgadget.kext/Contents', 'usbgadget.kext/Contents/Info.plist', 'usbgadget.kext/Contents/MacOS',
    'usbgadget.kext/Contents/MacOS/usbgadget']);
  assert.deepEqual(tree(f.state), [], 'staging removed, nothing replaced');
  assert.equal((fs.statSync(f.state).mode & 0o777).toString(8), '700');
  assert.equal(fs.existsSync(f.lock), false, 'lock released');
  assert.match(fs.readFileSync(f.calls, 'utf8'), /^chown -R \S+ .*\/staging\.[^/]+\/usbgadget\.kext$/m);
  assert.match(result.stdout, /diagnostic only/);
  assert.equal(f.status().state, 'MAC2JB_DRIVER_STATUS=restart-required');
});

test('a second run is idempotent: no reinstall, no backup, no new load when the pin is loaded', t => {
  const f = fixture(t);
  assert.equal(f.run().status, 0);
  oldMarker(f);
  const inode = fs.statSync(f.target).ino;
  const loaded = {MAC2JB_TEST_SHOWLOADED: loadedRow(pins.lc_uuid)};
  const again = f.run([], loaded);
  assert.equal(again.status, 0, again.stdout + again.stderr);
  assert.match(again.stdout, /already installed/);
  assert.match(again.stdout, /Nothing to do/);
  assert.equal(fs.statSync(f.target).ino, inode);
  assert.equal(fs.statSync(f.marker).mtimeMs, 500000, 'restart marker untouched');
  assert.deepEqual(f.loadCalls(), ['kmutil load -p ' + f.target]);
  assert.deepEqual(tree(f.state), []);
  const status = f.status(loaded);
  assert.deepEqual([status.code, status.state], [0, 'MAC2JB_DRIVER_STATUS=verified']);
});

test('a second run while unloaded keeps the files and only repeats the load request', t => {
  const f = fixture(t);
  assert.equal(f.run().status, 0);
  oldMarker(f);
  const inode = fs.statSync(f.target).ino;
  const again = f.run();
  assert.equal(again.status, 0, again.stdout + again.stderr);
  assert.equal(fs.statSync(f.target).ino, inode);
  assert.deepEqual(tree(f.state), []);
  assert.deepEqual(f.loadCalls(), ['kmutil load -p ' + f.target, 'kmutil load -p ' + f.target]);
  assert.ok(fs.statSync(f.marker).mtimeMs > 500000, 'restart marker refreshed');
});

test('a different installed driver is moved out of Extensions, never deleted', t => {
  const f = fixture(t);
  fs.cpSync(f.bundled, f.target, {recursive: true});
  fs.writeFileSync(path.join(f.target, 'Contents/MacOS/usbgadget'), 'upstream v0.3.1 binary');
  fs.mkdirSync(path.join(f.extensions, '.mac2jb-usbgadget-backup-1234/Contents'), {recursive: true});
  fs.mkdirSync(path.join(f.extensions, '.mac2jb-driver.AbCdEf'));
  const result = f.run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assertPinnedInstall(f);
  assert.deepEqual(fs.readdirSync(f.extensions).sort(), ['.mac2jb-usbgadget-restart-required', 'usbgadget.kext']);
  const replaced = fs.readdirSync(f.state).filter(name => name.startsWith('replaced-'));
  assert.equal(replaced.length, 1);
  assert.equal(fs.readFileSync(path.join(f.state, replaced[0], 'usbgadget.kext/Contents/MacOS/usbgadget'), 'utf8'),
    'upstream v0.3.1 binary');
  assert.ok(result.stdout.includes(path.join(f.state, replaced[0], 'usbgadget.kext')));
  const legacy = fs.readdirSync(f.state).filter(name => name.startsWith('legacy-'));
  assert.equal(legacy.length, 1);
  assert.deepEqual(fs.readdirSync(path.join(f.state, legacy[0])).sort(),
    ['.mac2jb-driver.AbCdEf', '.mac2jb-usbgadget-backup-1234']);
});

test('identical bytes with wrong permissions are reinstalled with the expected modes', t => {
  const f = fixture(t);
  assert.equal(f.run().status, 0);
  fs.chmodSync(path.join(f.target, 'Contents/Info.plist'), 0o666);
  const result = f.run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assertPinnedInstall(f);
  assert.equal(fs.readdirSync(f.state).filter(name => name.startsWith('replaced-')).length, 1);
});

test('the installer refuses foreign copies and non-folder targets without changing anything', t => {
  const foreign = fixture(t);
  const other = path.join(foreign.extensions, 'usbgadget 2.kext/Contents');
  fs.mkdirSync(other, {recursive: true});
  fs.copyFileSync(path.join(foreign.bundled, 'Contents/Info.plist'), path.join(other, 'Info.plist'));
  const before = tree(foreign.extensions);
  let result = foreign.run();
  assert.equal(result.status, 13);
  assert.match(result.stderr, /another kext declares gay\.bowser\.usbgadget/);
  assert.deepEqual(tree(foreign.extensions), before);
  assert.deepEqual(foreign.loadCalls(), []);
  assert.equal(fs.existsSync(foreign.state), false);
  assert.equal(foreign.status().state, 'MAC2JB_DRIVER_STATUS=mismatch-installed');

  const linked = fixture(t);
  fs.symlinkSync(linked.bundled, linked.target);
  result = linked.run();
  assert.equal(result.status, 13);
  assert.equal(fs.lstatSync(linked.target).isSymbolicLink(), true);
  assert.deepEqual(linked.loadCalls(), []);
});

test('a live lock blocks a second installer; a stale lock is reclaimed and released', t => {
  const busy = fixture(t);
  fs.writeFileSync(busy.lock, `${process.pid}\n`);
  let result = busy.run();
  assert.equal(result.status, 75);
  assert.match(result.stderr, /Another mac2jb driver installation is running/);
  assert.equal(fs.readFileSync(busy.lock, 'utf8'), `${process.pid}\n`, 'foreign lock untouched');
  assert.equal(fs.existsSync(busy.target), false);
  assert.deepEqual(busy.loadCalls(), []);

  const stale = fixture(t);
  const gone = spawnSync('/bin/sh', ['-c', 'echo $$']).stdout.toString().trim();
  fs.writeFileSync(stale.lock, `${gone}\n`);
  // shlock reclaims a dead owner's lock only if the lock is at least one second
  // older than its own temporary file (ctime guard against concurrent removal).
  spawnSync('/bin/sleep', ['1.1']);
  result = stale.run();
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assertPinnedInstall(stale);
  assert.equal(fs.existsSync(stale.lock), false);
});

test('concurrent installers never interleave: one installs, the other waits out or is refused', async t => {
  const f = fixture(t);
  // A slow load keeps the first installer inside its locked section.
  const slow = path.join(f.bin, 'kmutil');
  fs.writeFileSync(slow, fs.readFileSync(slow, 'utf8').replace('  load) ', '  load) sleep 1; '));
  const runAsync = () => new Promise(resolve => {
    const child = spawn('/bin/bash', [f.script], {env: {...process.env, MAC2JB_TEST_CALLS: f.calls, MAC2JB_TEST_TRASH: f.trash}});
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    child.on('close', code => resolve({code, output}));
  });
  const results = await Promise.all([runAsync(), runAsync()]);
  const codes = results.map(result => result.code).sort();
  assert.deepEqual(codes, [0, 75], results.map(result => result.output).join('\n---\n'));
  assertPinnedInstall(f);
  assert.deepEqual(f.loadCalls(), ['kmutil load -p ' + f.target]);
  assert.deepEqual(tree(f.state), []);
});

test('a failed swap restores the previous driver and keeps staging out of Extensions', t => {
  const f = fixture(t);
  fs.cpSync(f.bundled, f.target, {recursive: true});
  fs.writeFileSync(path.join(f.target, 'Contents/MacOS/usbgadget'), 'previous driver');
  stub(f.bin, 'mv', [
    'if [[ "${!#}" == "$MAC2JB_TEST_FAIL_MV_TO" && "$1" == */staging.* ]]; then echo "fixture: rename refused" >&2; exit 1; fi',
    'exec /bin/mv "$@"']);
  const result = f.run([], {MAC2JB_TEST_FAIL_MV_TO: f.target});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /previous driver was restored/);
  assert.equal(fs.readFileSync(path.join(f.target, 'Contents/MacOS/usbgadget'), 'utf8'), 'previous driver');
  assert.deepEqual(fs.readdirSync(f.extensions), ['usbgadget.kext']);
  assert.deepEqual(f.loadCalls(), []);
  const trashed = fs.readdirSync(f.trash);
  assert.equal(trashed.length, 1, 'the non-empty staging folder went to the Trash, not rm -rf');
  assert.match(trashed[0], /^staging\./);
  assert.deepEqual(tree(path.join(f.trash, trashed[0])).slice(0, 1), ['usbgadget.kext']);
});

test('the loader outcome decides success, not the SIP summary', t => {
  for (const fixtureCase of [
    {sip: 'System Integrity Protection status: disabled.', code: 0},
    {sip: 'System Integrity Protection status: unknown (Custom Configuration).\nKext Signing: disabled', code: 0},
    {sip: 'System Integrity Protection status: enabled.', code: 71},
    {sip: 'csrutil: status unavailable', csrCode: 1, code: 0},
  ]) {
    const f = fixture(t);
    const result = f.run([], {MAC2JB_TEST_SIP: fixtureCase.sip, MAC2JB_TEST_CSR_EXIT: String(fixtureCase.csrCode || 0),
      MAC2JB_TEST_LOAD_EXIT: String(fixtureCase.code)});
    assert.equal(result.status, fixtureCase.code, result.stdout + result.stderr);
    assert.ok(result.stdout.includes(fixtureCase.sip));
    assert.deepEqual(f.loadCalls(), ['kmutil load -p ' + f.target]);
    assert.ok(fs.existsSync(f.marker));
    if (fixtureCase.code) {
      assert.match(result.stderr, /fixture: macOS refused unsigned driver/);
      assert.match(result.stderr, /SIP status text alone does not determine compatibility/);
      assert.doesNotMatch(result.stdout, /load request accepted/);
    }
  }
});

test('--status reports each state with its exit code and never writes', t => {
  const installed = () => {
    const f = fixture(t);
    assert.equal(f.run().status, 0);
    oldMarker(f);
    fs.writeFileSync(f.calls, '');
    return f;
  };
  const expect = (f, env, code, state) => {
    const before = [tree(f.extensions), tree(f.state), fs.existsSync(f.lock)];
    const status = f.status(env);
    assert.deepEqual([status.code, status.state], [code, 'MAC2JB_DRIVER_STATUS=' + state], status.stdout + status.stderr);
    assert.ok(status.stdout.split('\n')[1].length > 0, 'line 2 explains the state');
    assert.deepEqual([tree(f.extensions), tree(f.state), fs.existsSync(f.lock)], before);
    assert.deepEqual(f.loadCalls(), []);
    return status;
  };
  const pinned = {MAC2JB_TEST_SHOWLOADED: loadedRow(pins.lc_uuid)};

  expect(fixture(t), {}, 11, 'not-installed');
  let f = installed();
  expect(f, pinned, 0, 'verified');
  expect(f, {}, 12, 'not-loaded');
  let status = expect(f, {MAC2JB_TEST_SHOWLOADED: loadedRow(UPSTREAM_UUID)}, 14, 'mismatch-loaded');
  assert.match(status.stdout, new RegExp(UPSTREAM_UUID));
  expect(f, {MAC2JB_TEST_SHOWLOADED: loadedRow(pins.lc_uuid) + loadedRow(pins.lc_uuid)}, 14, 'mismatch-loaded');
  expect(f, {MAC2JB_TEST_SHOWLOADED_EXIT: '1'}, 16, 'unknown');
  fs.utimesSync(f.marker, 2000, 2000);
  expect(f, pinned, 10, 'restart-required');

  f = installed();
  fs.appendFileSync(path.join(f.target, 'Contents/MacOS/usbgadget'), 'x');
  expect(f, pinned, 13, 'mismatch-installed');
  f = installed();
  fs.chmodSync(path.join(f.target, 'Contents/MacOS/usbgadget'), 0o777);
  expect(f, pinned, 13, 'mismatch-installed');
  f = fixture(t);
  expect(f, {MAC2JB_TEST_SHOWLOADED: loadedRow(UPSTREAM_UUID)}, 14, 'mismatch-loaded');
});

test('mac2jb.command gates USB sessions on the verified status and exposes it', t => {
  const f = fixture(t);
  fs.copyFileSync(path.join(repo, 'mac2jb.command'), path.join(f.root, 'mac2jb.command'));
  for (const tool of ['osascript', 'node']) stub(f.bin, tool, [`printf "${tool} %s\\n" "$*" >> "$MAC2JB_TEST_CALLS"`, 'exit 1']);
  const launch = (args, input, env = {}) => spawnSync('/bin/bash', [path.join(f.root, 'mac2jb.command'), ...args], {
    encoding: 'utf8', input, env: {...process.env, PATH: `${f.bin}:${process.env.PATH}`,
      MAC2JB_TEST_CALLS: f.calls, MAC2JB_TEST_TRASH: f.trash, ...env}});

  let result = launch(['--driver-status'], '');
  assert.equal(result.status, 11);
  assert.equal(result.stdout.split('\n')[0], 'MAC2JB_DRIVER_STATUS=not-installed');

  result = launch([], '2\n');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /not installed/);
  assert.match(result.stdout, /No USB input or ns2jb host was started/);
  assert.doesNotMatch(result.stdout, /MAC2JB_DRIVER_STATUS/);

  assert.equal(f.run().status, 0);
  oldMarker(f);
  result = launch([], '2\n', {MAC2JB_TEST_SHOWLOADED: loadedRow(UPSTREAM_UUID)});
  assert.equal(result.status, 1);
  assert.match(result.stdout, /different gay\.bowser\.usbgadget is loaded/);
  assert.match(result.stdout, /No USB input or ns2jb host was started/);

  result = launch([], '2\n', {MAC2JB_TEST_SHOWLOADED: loadedRow(pins.lc_uuid)});
  assert.equal(result.status, 1);
  assert.match(result.stdout, /Missing required file: scripts\/host\.sh/, 'the gate passed; the next check stops this fixture');
  assert.doesNotMatch(result.stdout, /No USB input/);
  assert.doesNotMatch(fs.readFileSync(f.calls, 'utf8'), /^(osascript|node) /m);
});
