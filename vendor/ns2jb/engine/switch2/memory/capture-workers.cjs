// Preserve client-side progress without sending another filesystem request.
// Result tables are read first and persisted before any reply read. Each reply
// descriptor is isolated: an IPC-reserved page is recorded, never read, and a
// failing read cannot discard earlier results.
const big = value => value === undefined || value === null ? value : String(value);

async function captureRange(s, range, precheck) {
  const entry = {address: range.address, bytes: range.bytes, status: 'unread'};
  let operation = 'query';
  try {
    if (precheck) {
      const region = await s.rpc.query(range.address);
      entry.region = {
        address: big(region.address), size: big(region.size), type: region.type,
        permissions: region.permissions, attributes: region.attributes,
        ipcReferences: region.ipcReferences, deviceReferences: region.deviceReferences
      };
      if (region.ipcReferences > 0) {
        entry.status = 'ipc-reserved';
        return entry;
      }
    }
    operation = 'read';
    const bytes = await s.readOwned(range.address, range.bytes);
    entry.status = 'read';
    entry.hex = bytes.toString('hex');
  } catch (error) {
    entry.status = 'error';
    entry.error = {operation, name: error.name, code: error.code, message: error.message};
  }
  return entry;
}

async function captureWorkers(s, workers, writePartial) {
  const reads = workers.map(worker => ({address: worker.base + worker.resultOffsets[0],
    bytes: worker.resultOffsets.length * 8}));
  const replies = workers.flatMap(worker => worker.calls.filter(call => call.kind === 'ipc')
    .map(call => ({worker: worker.label, name: call.name, address: call.args[0], bytes: 256})));
  const snapshot = {schema: 1, at: new Date().toISOString(), results: [], replies: [], partial: true};
  for (const range of reads) snapshot.results.push(await captureRange(s, range, false));
  if (writePartial) await writePartial(snapshot);
  for (let index = 0; index < replies.length; index++) {
    snapshot.replies.push(await captureRange(s, replies[index], true));
    if (writePartial && (index + 1) % 4 === 0) await writePartial(snapshot);
  }
  snapshot.partial = false;

  const sentinel = 0xfedcba9876543210n;
  return {
    ...snapshot,
    workers: workers.map((worker, index) => {
      const result = snapshot.results[index];
      const table = result && result.status === 'read' ? Buffer.from(result.hex, 'hex') : null;
      return {
        label: worker.label,
        thread: worker.thread,
        result,
        calls: worker.calls.map((call, callIndex) => {
          const value = table ? table.readBigUInt64LE(worker.logicalResultIndices[callIndex] * 8) : null;
          return {
            name: call.name || call.kind || 'call',
            returned: value === null ? null : value !== sentinel,
            value: value === null ? null : '0x' + value.toString(16)
          };
        })
      };
    })
  };
}

module.exports = {captureRange, captureWorkers};
