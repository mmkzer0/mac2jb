// Phase-evidence truth table. Pure function, no console, no repository writes.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {summarize, summarizeCopyStep, classifyAliasObservation, summarizeRangeLeak} = require(path.join(__dirname, '..',
  'vendor/ns2jb/engine/switch2/memory/phase-evidence.cjs'));

const row = overrides => ({
  restored: true, triggerAborted: false, allPending: true,
  receiveOrderMarginUs: 1000, preReleaseUsed: 0x28f0,
  changedPaths: [], canaryType: 1, canaryResult: 0, ...overrides
});
const hit = () => row({changedPaths: ['canary'], canaryType: 0});
const miss = () => row({});

test('a later hit resolves an earlier unaborted miss', () => {
  const phase = summarize('positive', [miss(), row({triggerAborted: true}), hit()], true);
  assert.equal(phase.markerObserved, true);
  assert.equal(phase.unsafe, false);
  assert.equal(phase.unaborted, 2);
  assert.equal(phase.complete, true);
});

test('a phase without a hit but with unaborted waves is unsafe', () => {
  const rows = Array.from({length: 19}, miss).concat(Array.from({length: 11}, () => row({triggerAborted: true})));
  const phase = summarize('positive', rows, true);
  assert.equal(phase.markerObserved, false);
  assert.equal(phase.unsafe, true);
  assert.equal(phase.unaborted, 19);
});

test('an all-aborted phase is not unsafe', () => {
  const phase = summarize('positive', [row({triggerAborted: true}), row({triggerAborted: true})], true);
  assert.equal(phase.unsafe, false);
  assert.equal(phase.markerObserved, false);
});

test('a hit without a qualified window does not resolve the phase', () => {
  const phase = summarize('positive', [miss(), row({changedPaths: ['canary'], canaryType: 0, allPending: false})], true);
  assert.equal(phase.markerObserved, false);
  assert.equal(phase.unsafe, true);
});

test('an aborted canary deviation is not an unsafe overwrite', () => {
  const phase = summarize('positive', [row({triggerAborted: true, changedPaths: ['canary'], canaryResult: 0x2eea02, canaryType: null})], true);
  assert.equal(phase.unsafe, false);
  assert.equal(phase.markerObserved, false);
});

test('non-positive phases never report unsafe', () => {
  const phase = summarize('extent-present', [miss()], true);
  assert.equal(phase.unsafe, false);
});

test('summarizeCopyStep aggregates accepted windows, guards, and margins', () => {
  const rows = [
    row({triggerAborted: true, nativeGuard: {completed: 1, earlyHole: 0, minimumSpacing: 0}, receiveOrderMarginUs: -120}),
    row({changedPaths: ['canary'], receiveOrderMarginUs: 450, preReleaseUsed: 0x28f0}),
    row({receiveOrderMarginUs: 500, preReleaseUsed: 0x27a0}),
    row({receiveOrderMarginUs: 600, preReleaseUsed: 0x2810}),
    row({receiveOrderMarginUs: 380, preReleaseUsed: 0x2a00})
  ];
  const summary = summarizeCopyStep('combined-leak-0-17', rows, 2, 0x2810, {qualified: true, confirmedBatch: 1});
  assert.equal(summary.qualified, true);
  assert.equal(summary.confirmedBatch, 1);
  assert.equal(summary.attempts, 5);
  assert.equal(summary.accepted, 2);
  assert.equal(summary.aborted, 1);
  assert.equal(summary.unabortedRejected, 2);
  assert.equal(summary.lowPreReleaseRejected, 1);
  assert.equal(summary.unverifiedMemoryEffect, true);
  assert.equal(summary.canaryMisses, 1);
  assert.deepEqual(summary.guards, {completed: 1, earlyHole: 0, minimumSpacing: 0});
  assert.equal(summary.bestMarginUs, 600);
  assert.equal(summary.minAcceptedMarginUs, 380);
  assert.equal(summary.minAcceptedPreReleaseUsed, 0x2810);
  assert.equal(summary.maxAcceptedPreReleaseUsed, 0x2a00);

  // Cross-batch split (1 accepted in batch 0 + 1 accepted in batch 1, none reaching required=2 in a single batch)
  const failedSummary = summarizeCopyStep('combined-leak-0-17', rows, 2, 0x2810, {qualified: false, confirmedBatch: null});
  assert.equal(failedSummary.accepted, 2);
  assert.equal(failedSummary.qualified, false);
  assert.equal(failedSummary.confirmedBatch, null);
});

test('summarizeCopyStep qualifies timing-only waves even when no metadata write landed', () => {
  // Regression test for the blind acceptance predicate: two waves with clean
  // timing and unchanged path canaries satisfy copyField qualification without
  // any cache-entry state verification, requiring classifyAliasObservation on
  // the subsequent read to distinguish a redirect from an ordinary backing read.
  const simulatedCacheEntry = Buffer.from('0000000000000000004000000000000001000100', 'hex');
  const beforeCopy = Buffer.from(simulatedCacheEntry);
  const step = summarizeCopyStep('combined-leak-0-17', [miss(), miss()], 2, 0x2810);
  assert.equal(step.qualified, true);
  assert.deepEqual(simulatedCacheEntry, beforeCopy);

  const primeBytes = Buffer.from('5052494d455f424c4f434b5f30303030', 'hex');
  const aliasControlBytes = Buffer.from('4e4f524d414c5f313430303030305f21', 'hex');
  const obs = classifyAliasObservation({
    aliased: {result: 0, bytes: Buffer.from(aliasControlBytes)},
    primeBytes,
    aliasControlBytes
  });
  assert.equal(obs.classification, 'ordinary-backing-read');
  assert.equal(obs.selectedAlias, false);
  assert.equal(obs.normalContent, true);
  assert.equal(obs.firstDiffFromPrime, 0);
  assert.equal(obs.firstDiffFromNormal, -1);
});

test('classifyAliasObservation distinguishes redirect, poison, partial prefix, and ipc error', () => {
  const primeBytes = Buffer.from('112233445566778899aabbccddeeff00', 'hex');
  const aliasControlBytes = Buffer.from('ffeeddccbbaa99887766554433221100', 'hex');

  const hitObs = classifyAliasObservation({
    aliased: {result: 0, bytes: Buffer.from(primeBytes)},
    primeBytes,
    aliasControlBytes
  });
  assert.equal(hitObs.classification, 'selected-alias');
  assert.equal(hitObs.selectedAlias, true);
  assert.equal(hitObs.normalContent, false);
  assert.equal(hitObs.primeMatchingBytes, 16);

  const poisonObs = classifyAliasObservation({
    aliased: {result: 0, bytes: Buffer.alloc(16, 0xa5)},
    primeBytes,
    aliasControlBytes
  });
  assert.equal(poisonObs.classification, 'untouched-receive-buffer');
  assert.equal(poisonObs.untouchedPoison, true);
  assert.equal(poisonObs.poisonBytes, 16);

  const partialBytes = Buffer.concat([primeBytes.subarray(0, 8), aliasControlBytes.subarray(8, 16)]);
  const partialObs = classifyAliasObservation({
    aliased: {result: 0, bytes: partialBytes},
    primeBytes,
    aliasControlBytes
  });
  assert.equal(partialObs.classification, 'partial-prime-prefix');
  assert.equal(partialObs.firstDiffFromPrime, 8);

  // Exclusivity check: all-zero buffer when primeBytes starts with 0x00 must classify as zero-filled, not partial-prime-prefix
  const zeroPrime = Buffer.from('002233445566778899aabbccddeeff00', 'hex');
  const zeroObs = classifyAliasObservation({
    aliased: {result: 0, bytes: Buffer.alloc(16, 0)},
    primeBytes: zeroPrime,
    aliasControlBytes
  });
  assert.equal(zeroObs.classification, 'zero-filled');
  assert.equal(zeroObs.zeroFilled, true);
  assert.equal(zeroObs.normalContent, false);

  // Exclusivity check: if aliasControlBytes itself is all-zeros, ordinary-backing-read takes precedence over zeroFilled
  const zeroBackingObs = classifyAliasObservation({
    aliased: {result: 0, bytes: Buffer.alloc(16, 0)},
    primeBytes,
    aliasControlBytes: Buffer.alloc(16, 0)
  });
  assert.equal(zeroBackingObs.classification, 'ordinary-backing-read');
  assert.equal(zeroBackingObs.normalContent, true);
  assert.equal(zeroBackingObs.zeroFilled, false);

  const errObs = classifyAliasObservation({
    aliased: {result: 0x202, bytes: null},
    primeBytes,
    aliasControlBytes
  });
  assert.equal(errObs.classification, 'ipc-error');
  assert.equal(errObs.selectedAlias, false);
});

test('summarizeRangeLeak forms a mutually exclusive block partition and separates raw pointers from qualified links', () => {
  const blockSize = 0x4000;
  const control = Buffer.alloc(blockSize * 4, 0x11);
  for (let i = 0; i < 4; i++) control.writeUInt32LE(0x1000 + i, i * blockSize);

  // Build 8 blocks:
  // 0: matches control[0] at same offset
  // 1: matches control[3] at different offset
  // 2: ascii-heavy block
  // 3: exact duplicate of block 2
  // 4: zero-filled block
  // 5: poison-filled block (0xa5)
  // 6: pointer-bearing block (head has 16k-aligned pointer, interior has 8-byte aligned pointer)
  // 7: other binary block
  const b0 = Buffer.from(control.subarray(0, blockSize));
  const b1 = Buffer.from(control.subarray(3 * blockSize, 4 * blockSize));
  const b2 = Buffer.alloc(blockSize, 0x41); // 'A'
  const b3 = Buffer.from(b2);
  const b4 = Buffer.alloc(blockSize, 0x00);
  const b5 = Buffer.alloc(blockSize, 0xa5);
  const b6 = Buffer.alloc(blockSize, 0x80);
  b6.writeBigUInt64LE(0x123454000n, 0); // 16k-aligned block head pointer
  b6.writeBigUInt64LE(0x123456788n, 0x100); // 8-byte aligned interior pointer
  const b7 = Buffer.alloc(blockSize, 0xfe);

  const widened = Buffer.concat([b0, b1, b2, b3, b4, b5, b6, b7]);
  const forensics = summarizeRangeLeak(widened, control, [{target: 0x123454000, encodable: true}]);
  assert.equal(forensics.totalBlocks, 8);
  const sum = Object.values(forensics.partition).reduce((a, b) => a + b, 0);
  assert.equal(sum, forensics.totalBlocks);
  assert.deepEqual(forensics.partition, {
    matchesControlSameOffset: 1,
    matchesControlOtherOffset: 1,
    exactDuplicateBlocks: 1,
    zeroFilled: 1,
    poisonFilled: 1,
    pointerBearing: 1,
    asciiHeavy: 1,
    otherBinary: 1
  });
  assert.equal(forensics.overReadBlockHeadsInRange, 1);
  assert.equal(forensics.overReadBlockHeads16kAligned, 1);
  assert.equal(forensics.overReadRawPointersTotal, 2);
  assert.equal(forensics.overReadRawPointers16kAligned, 1);
  assert.equal(forensics.qualifiedLinkCandidates, 1);
  assert.equal(forensics.encodableLinkCandidates, 1);
});
