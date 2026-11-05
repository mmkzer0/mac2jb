// Capture isolation: 13 result tables must survive a reserved reply read, and
// the result tables must be persisted before any reply is processed.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {captureWorkers} = require(path.join(__dirname, '..',
  'vendor/ns2jb/engine/switch2/memory/capture-workers.cjs'));

const RESERVED = 0x9000;

function session() {
  const reads = [];
  return {
    reads,
    async readOwned(address, bytes) {
      reads.push(address);
      return Buffer.alloc(bytes, 0x11);
    },
    rpc: {
      async query(address) {
        return {address: BigInt(address), size: 4096n, type: 5, permissions: 3,
          attributes: 0, ipcReferences: address === RESERVED ? 1 : 0, deviceReferences: 0};
      }
    }
  };
}

function workers() {
  return Array.from({length: 13}, (_, index) => ({
    label: 'w' + index,
    thread: 100 + index,
    base: 0x100000 + index * 0x40000,
    resultOffsets: [0, 8, 16],
    logicalResultIndices: [0, 1, 2],
    calls: [{kind: 'ipc', name: index === 0 ? 'Commit' : 'Negotiate',
      args: [index === 0 ? RESERVED : 0x1000 + index]}]
  }));
}

test('all result tables survive an IPC-reserved reply', async () => {
  const s = session();
  const snapshots = [];
  const capture = await captureWorkers(s, workers(), async value => {
    snapshots.push(JSON.parse(JSON.stringify(value)));
  });
  assert.equal(capture.results.length, 13);
  assert.ok(capture.results.every(result => result.status === 'read'));
  assert.equal(capture.replies[0].status, 'ipc-reserved');
  assert.equal(capture.replies[0].region.ipcReferences, 1);
  assert.equal(capture.replies[0].hex, undefined);
  assert.ok(!s.reads.includes(RESERVED), 'the reserved page must not be read');
  assert.equal(capture.partial, false);
  assert.equal(capture.workers.length, 13);
  assert.ok(capture.workers.every(worker => worker.calls[0].returned !== null));
});

test('result tables are persisted before any reply is processed', async () => {
  const snapshots = [];
  await captureWorkers(session(), workers(), async value => {
    snapshots.push(JSON.parse(JSON.stringify(value)));
  });
  assert.ok(snapshots.length >= 2);
  assert.equal(snapshots[0].results.length, 13);
  assert.ok(snapshots[0].results.every(result => result.status === 'read'));
  assert.equal(snapshots[0].replies.length, 0);
  assert.equal(snapshots[0].partial, true);
});
