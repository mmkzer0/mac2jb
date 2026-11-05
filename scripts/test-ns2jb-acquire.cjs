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
  const {start: run} = require(path.join(root, 'engine/switch2/acquire.cjs'));
  return {root, run};
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
