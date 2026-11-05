// Offline fault injection for the vendored FS supervisor.
// The real acquire.cjs runs unmodified in a private mirror; only its child and
// leaf dependencies are fixtures. No USB, kext, console, or network.
const test = require('node:test');
const assert = require('node:assert');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

const SOURCE = path.join(__dirname, '..', 'vendor/ns2jb/engine/switch2/acquire.cjs');
const SESSION = 'offline-session';
// Captured before any test enables fake timers; the spawn and its file I/O run
// on the real clock even while the supervisor's polling clock is mocked.
const realSetTimeout = setTimeout;
const CHILD = `
const fs = require('node:fs');
const path = require('node:path');
const mode = process.env.NS2_STUB_MODE;
const root = process.env.NS2_STUB_ROOT;
const file = path.join(root, 'attempt.json');
fs.appendFileSync(path.join(root, 'spawns.txt'), process.pid + '\\n');
const report = {session: process.env.NS2_STUB_SESSION, started: new Date().toISOString()};
const emit = value => {
  fs.writeFileSync(file, JSON.stringify(value));
  console.log(JSON.stringify({stage: 'connected', file}));
};
if (mode === 'connected-error') {
  emit({...report, completed: false, cleanedUp: false, error: 'Native batch did not terminate; resources retained'});
  process.exit(1);
}
if (mode === 'clean-negative') {
  emit({...report, completed: true, cleanedUp: true, placementUncertain: false});
  process.exit(0);
}
if (mode === 'ready-uncertain') {
  emit({...report, memoryControl: {ready: true, socketPath: path.join(root, 'sock')}, placementUncertain: true});
  setInterval(() => {}, 1000);
} else if (mode === 'ready') {
  emit({...report, memoryControl: {ready: true, socketPath: path.join(root, 'sock')}, retained: {threads: [], handles: []}});
  setInterval(() => {}, 1000);
} else if (mode === 'progress') {
  emit({...report, memoryControl: {ready: false}, progress: {stage: 'signal-start'}});
  process.exit(0);
} else if (mode === 'stalled') {
  emit({...report, memoryControl: {ready: false}, progress: {profile: 'positive', stage: 'signal-start',
    at: new Date().toISOString()}});
  setInterval(() => {}, 1000);
} else if (mode === 'stalled-join') {
  emit({...report, memoryControl: {ready: false}, progress: {profile: 'positive', stage: 'join-start',
    at: new Date().toISOString()}});
  setInterval(() => {}, 1000);
} else if (mode === 'stalled-replies') {
  emit({...report, memoryControl: {ready: false}, progress: {profile: 'positive', stage: 'replies-start',
    at: new Date().toISOString()}});
  setInterval(() => {}, 1000);
} else if (mode === 'repeated-stage') {
  const value = () => ({...report, memoryControl: {ready: false},
    progress: {profile: 'positive', stage: 'join-start', at: new Date().toISOString()}});
  fs.writeFileSync(file, JSON.stringify(value()));
  console.log(JSON.stringify({stage: 'connected', file}));
  setTimeout(() => fs.writeFileSync(file, JSON.stringify(value())), 250);
  setTimeout(() => process.exit(0), 1200);
} else if (mode === 'late-ready') {
  emit({...report, memoryControl: {ready: false},
    progress: {profile: 'positive', stage: 'preparing', at: new Date().toISOString()}});
  setInterval(() => {}, 1000);
} else {
  process.exit(0);
}
`;

async function mirror() {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'ns2jb-acquire-'));
  const engine = path.join(root, 'engine');
  for (const dir of ['switch2/memory', 'switch2/tools', 'switch2/ro', 'shared'])
    await fsp.mkdir(path.join(engine, dir), {recursive: true});
  await fsp.copyFile(SOURCE, path.join(engine, 'switch2/acquire.cjs'));
  await fsp.writeFile(path.join(engine, 'switch2/memory/probe-reserved-gap.cjs'), CHILD);
  await fsp.writeFile(path.join(engine, 'shared/rpc.cjs'),
    'module.exports = {a: {session: ' + JSON.stringify(SESSION) + '}};\n');
  await fsp.writeFile(path.join(engine, 'switch2/memory/verify-proof.cjs'),
    'module.exports = {verifyProof: async () => ({verified: true})};\n');
  await fsp.writeFile(path.join(engine, 'switch2/tools/endpoint.cjs'),
    'module.exports = {request: async () => ({retired: true})};\n');
  await fsp.writeFile(path.join(engine, 'switch2/ro/runtime.cjs'),
    'const fs = require("node:fs/promises");\n' +
    'module.exports = {save: (file, value) => fs.writeFile(file, JSON.stringify(value)),\n' +
    ' read: async file => JSON.parse(await fs.readFile(file, "utf8"))};\n');
  return root;
}

async function spawnCount(root) {
  const text = await fsp.readFile(path.join(root, 'spawns.txt'), 'utf8').catch(() => '');
  return text.trim() ? text.trim().split('\n').length : 0;
}

async function start(mode) {
  const root = await mirror();
  process.env.NS2_STUB_ROOT = root;
  process.env.NS2_STUB_SESSION = SESSION;
  process.env.NS2_STUB_MODE = mode;
  const supervisor = require(path.join(root, 'engine/switch2/acquire.cjs'));
  return {root, run: supervisor.start, deadlineMs: supervisor.DEADLINE_MS};
}

async function waitForFile(file) {
  for (let i = 0; i < 500; i++) {
    if (await fsp.stat(file).then(() => true, () => false)) return;
    await new Promise(resolve => realSetTimeout(resolve, 10));
  }
  throw Error('timed out waiting for ' + file);
}

async function settle(ms = 100) {
  await new Promise(resolve => realSetTimeout(resolve, ms));
}

test('native-batch failure: one attempt, no retry, no scratch cleanup', async () => {
  const {root, run} = await start('connected-error');
  await assert.rejects(run, /FS acquisition did not complete|lost lifecycle|unsafe/);
  assert.equal(await spawnCount(root), 1);
});

test('child exits before provenance: one attempt, terminal', async () => {
  const {root, run} = await start('silent');
  await assert.rejects(run, /FS acquisition did not complete/);
  assert.equal(await spawnCount(root), 1);
});

test('false clean: completed and cleaned up but not ready is terminal', async () => {
  const {root, run} = await start('clean-negative');
  await assert.rejects(run, /FS acquisition did not complete/);
  assert.equal(await spawnCount(root), 1);
});

test('ready report with placement uncertainty is rejected', async () => {
  const {root, run} = await start('ready-uncertain');
  await assert.rejects(run, /unsafe/);
  assert.equal(await spawnCount(root), 1);
});

test('ready report publishes ownership and returns', async () => {
  const {root, run} = await start('ready');
  const result = await run();
  assert.equal(result.session, SESSION);
  assert.match(result.socketPath, /sock$/);
  const current = JSON.parse(await fsp.readFile(path.join(root, 'engine/switch2/current-acquisition.json'), 'utf8'));
  assert.equal(current.session, SESSION);
  assert.equal(current.report, path.join(root, 'attempt.json'));
  await result.abandon();
});

test('a failed attempt reports its last wave stage', async () => {
  const {root, run} = await start('progress');
  await assert.rejects(run, /last stage: signal-start/);
  assert.equal(await spawnCount(root), 1);
});

test('a stalled wave fails closed with WAVE_STALLED', async () => {
  const {root, run} = await start('stalled');
  await assert.rejects(() => run({stallMs: 50}), /WAVE_STALLED.*signal-start/);
  assert.equal(await spawnCount(root), 1);
  const files = await fsp.readdir(path.join(root, 'engine/switch2/memory'));
  assert.ok(!files.some(name => name.endsWith('worker-failure.json')));
  const current = JSON.parse(await fsp.readFile(path.join(root, 'engine/switch2/current-acquisition.json'), 'utf8'));
  assert.equal(current.socketPath, undefined);
  assert.equal(current.proof, undefined);
});

test('a stalled join fails closed with WAVE_STALLED', async () => {
  const {root, run} = await start('stalled-join');
  await assert.rejects(() => run({stallMs: 50}), /WAVE_STALLED.*join-start/);
  assert.equal(await spawnCount(root), 1);
});

test('repeated stage names across waves reset the stall window', async () => {
  const {root, run} = await start('repeated-stage');
  await assert.rejects(() => run({stallMs: 700}), error => {
    assert.match(error.message, /did not complete/);
    assert.doesNotMatch(error.message, /WAVE_STALLED/);
    return true;
  });
  assert.equal(await spawnCount(root), 1);
});

test('a stalled reply read fails closed with WAVE_STALLED', async () => {
  const {root, run} = await start('stalled-replies');
  await assert.rejects(() => run({stallMs: 50}), /WAVE_STALLED.*replies-start/);
  assert.equal(await spawnCount(root), 1);
});

function readyReport(root) {
  return {session: SESSION, memoryControl: {ready: true, socketPath: path.join(root, 'sock')},
    retained: {threads: [], handles: []}};
}

test('a ready report just before the deadline publishes', async t => {
  t.mock.timers.enable({apis: ['Date', 'setTimeout'], now: 0});
  const {root, run, deadlineMs} = await start('late-ready');
  const pending = run();
  await waitForFile(path.join(root, 'attempt.json'));
  await settle();
  t.mock.timers.tick(500);
  await settle();
  await fsp.writeFile(path.join(root, 'attempt.json'), JSON.stringify(readyReport(root)));
  t.mock.timers.tick(deadlineMs - 501);
  const result = await pending;
  assert.equal(result.session, SESSION);
  assert.match(result.socketPath, /sock$/);
  await result.abandon();
});
test('a ready report at the deadline is not published', async t => {
  t.mock.timers.enable({apis: ['Date', 'setTimeout'], now: 0});
  const {root, run, deadlineMs} = await start('late-ready');
  const pending = run();
  await waitForFile(path.join(root, 'attempt.json'));
  await settle();
  t.mock.timers.tick(500);
  await settle();
  await fsp.writeFile(path.join(root, 'attempt.json'), JSON.stringify(readyReport(root)));
  t.mock.timers.tick(deadlineMs - 500);
  await assert.rejects(pending, /lost lifecycle authority/);
  const current = JSON.parse(await fsp.readFile(path.join(root, 'engine/switch2/current-acquisition.json'), 'utf8'));
  assert.equal(current.socketPath, undefined);
  assert.equal(current.proof, undefined);
});

test('a reply arriving after the wave timeout is not published', async () => {
  const {root, run} = await start('stalled');
  await assert.rejects(() => run({stallMs: 50}), /WAVE_STALLED/);
  // The console may answer after the supervisor gave up; that reply must not
  // grant ownership or produce a second attempt.
  await fsp.writeFile(path.join(root, 'attempt.json'), JSON.stringify({
    session: SESSION, memoryControl: {ready: true, socketPath: path.join(root, 'late.sock')},
    retained: {threads: [], handles: []}}));
  await new Promise(resolve => setTimeout(resolve, 250));
  assert.equal(await spawnCount(root), 1);
  const current = JSON.parse(await fsp.readFile(path.join(root, 'engine/switch2/current-acquisition.json'), 'utf8'));
  assert.equal(current.socketPath, undefined);
  assert.equal(current.proof, undefined);
  const files = await fsp.readdir(path.join(root, 'engine/switch2/memory'));
  assert.ok(!files.some(name => name.endsWith('worker-failure.json')));
});
