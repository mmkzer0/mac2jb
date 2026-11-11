const fs = require('node:fs');
// Phase-evidence truth table. Pure function, no console, no repository writes.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {
  summarize,
  summarizeCopyStep,
  classifyAliasObservation,
  summarizeRangeLeak,
  classifyRunOutcome,
  shouldRetryPositiveWave
} = require(path.join(__dirname, '..', 'vendor/ns2jb/engine/switch2/memory/phase-evidence.cjs'));
const {findNativeLinks} = require(path.join(__dirname, '..', 'vendor/ns2jb/engine/switch2/memory/native-links.cjs'));
const {qualifyOverlap, qualifyExtentOverlap} = require(path.join(__dirname, '..', 'vendor/ns2jb/engine/switch2/memory/wave-overlap.cjs'));

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
  assert.deepEqual(forensics.independentCounts, {
    asciiHeavyBlocks: 2,
    pointerBearingBlocks: 1,
    uniqueOutHashes: 7
  });
  assert.equal(forensics.overReadBlockHeads16kAligned, 1);
  assert.equal(forensics.overReadRawPointersTotal, 2);
  assert.equal(forensics.overReadRawPointers16kAligned, 1);
  assert.equal(forensics.qualifiedLinkCandidates, 1);
  assert.equal(forensics.encodableLinkCandidates, 1);
});

test('summarizeRangeLeak and nativeLinks match conserved T0a2CC hardware over-read dump when NS2JB_GOLDEN_DIR is set', async t => {
  const dir = process.env.NS2JB_GOLDEN_DIR;
  if (!dir) {
    t.skip('Set NS2JB_GOLDEN_DIR to run hardware golden dump assertions');
    return;
  }
  const prefix = 'reserved-gap-1793893081989';
  const outPath = path.join(dir, `${prefix}-range-output.bin`);
  const ctrlPath = path.join(dir, `${prefix}-range-control.bin`);
  const beforeReleasePath = path.join(dir, `${prefix}-before-release-0.bin`);
  const primedPath = path.join(dir, `${prefix}-fragment-primed.bin`);
  const free0Path = path.join(dir, `${prefix}-fragment-free-0.bin`);
  const free1Path = path.join(dir, `${prefix}-fragment-free-1.bin`);
  for (const requiredFile of [outPath, ctrlPath, beforeReleasePath, primedPath, free0Path, free1Path]) {
    assert.ok(fs.existsSync(requiredFile), `Missing required golden dump file: ${requiredFile}`);
  }

  const expectedSha256 = 'c8b01df80674952242c102eb41a906a9a6a10c8cd5459030c4e9ace8c03d6d3b';
  const snapshots = [
    {name: 'before-release-0', outputFile: beforeReleasePath, outputSha256: expectedSha256},
    {name: 'initial', outputFile: outPath, outputSha256: expectedSha256},
    {name: 'fragment-primed', outputFile: primedPath, outputSha256: expectedSha256},
    {name: 'fragment-free-0', outputFile: free0Path, outputSha256: expectedSha256},
    {name: 'fragment-free-1', outputFile: free1Path, outputSha256: expectedSha256}
  ];
  const candidates = await findNativeLinks(snapshots, true);
  assert.deepEqual(candidates, []);

  const widened = fs.readFileSync(outPath);
  const control = fs.readFileSync(ctrlPath);
  const forensics = summarizeRangeLeak(widened, control, candidates);
  assert.equal(forensics.totalBlocks, 128);
  const sum = Object.values(forensics.partition).reduce((a, b) => a + b, 0);
  assert.equal(sum, 128);
  assert.deepEqual(forensics.partition, {
    matchesControlSameOffset: 1,
    matchesControlOtherOffset: 0,
    exactDuplicateBlocks: 3,
    zeroFilled: 0,
    poisonFilled: 0,
    pointerBearing: 1,
    asciiHeavy: 81,
    otherBinary: 42
  });
  assert.deepEqual(forensics.independentCounts, {
    asciiHeavyBlocks: 82,
    pointerBearingBlocks: 1,
    uniqueOutHashes: 125
  });
  assert.equal(forensics.overReadBlockHeadsInRange, 0);
  assert.equal(forensics.overReadBlockHeads16kAligned, 0);
  assert.equal(forensics.overReadRawPointersTotal, 2);
  assert.equal(forensics.overReadRawPointers16kAligned, 0);
  assert.equal(forensics.qualifiedLinkCandidates, 0);
  assert.equal(forensics.encodableLinkCandidates, 0);
});

test('classifyRunOutcome separates worker stalls, heap drift, alias misses, and post-alias link exhaustion', () => {
  const t0a2cc = classifyRunOutcome({
    markerSelected: true,
    markerReproduced: true,
    cacheAlias: {selectedAlias: true, attempts: [{attempt: 0}]},
    cacheRange: {completed: true},
    linkCandidates: [],
    error: 'Error: The bounded native leak contains no qualified, encodable link candidate'
  });
  assert.equal(t0a2cc.terminalCause, 'no-native-links');
  assert.equal(t0a2cc.furthestStage, 'native-links');
  assert.equal(t0a2cc.evidenceStatus, 'verified');
  assert.equal(t0a2cc.category, 'no-native-links');
  assert.equal(t0a2cc.substage, 'native-links');
  const bbunsz = classifyRunOutcome({
    markerSelected: true,
    markerReproduced: true,
    cacheAlias: {selectedAlias: false, attempts: []},
    error: 'Error: General-heap allocation changed while the cache was retained; stop overwrites and recover'
  });
  assert.equal(bbunsz.category, 'general-heap-drift');
  assert.equal(bbunsz.substage, 'alias-copy');

  const stallEvents = [
    {operation: 'workerStarted', label: 'reserved-gap-1-12'},
    {operation: 'timing', stage: 'join:positive', passed: false}
  ];
  const stallRepro = classifyRunOutcome({
    markerSelected: true,
    markerReproduced: false,
    error: 'Error: Native batch did not terminate; resources retained'
  }, stallEvents);
  assert.equal(stallRepro.terminalCause, 'native-worker-stall');
  assert.equal(stallRepro.furthestStage, 'canary-reproduce');
  assert.equal(stallRepro.firstUnjoinedWorkerIndex, 0);
  assert.equal(stallRepro.firstUnjoinedWorkerRole, 'commit');
  assert.equal(stallRepro.joinedBeforeStall, 0);
  const aliasMiss = classifyRunOutcome({
    markerSelected: true,
    markerReproduced: true,
    metadataAttempts: 4,
    cacheAlias: {selectedAlias: false, attempts: [{}, {}, {}, {}]},
    error: 'Error: Clean alias did not qualify within its attempt limit'
  });
  assert.equal(aliasMiss.category, 'alias-not-selected');
  assert.equal(aliasMiss.substage, 'alias-read');

  const canaryExhausted = classifyRunOutcome({
    completed: true,
    markerSelected: false,
    markerReproduced: false,
    cleanedUp: true
  });
  assert.equal(canaryExhausted.category, 'canary-not-qualified');
  assert.equal(canaryExhausted.substage, 'canary-select');

  // Orthogonal dimensions: a worker stall during address-plan must report terminalCause=native-worker-stall and furthestStage=address-plan
  const stallInAddressPlan = classifyRunOutcome({
    markerSelected: true,
    markerReproduced: true,
    cacheAlias: {selectedAlias: true, attempts: [{attempt: 0}]},
    cacheRange: {completed: true},
    linkCandidates: [{target: 0x123454000, encodable: true}],
    cacheAddress: {completed: false},
    error: 'Error: Native batch did not terminate; resources retained'
  }, stallEvents);
  assert.equal(stallInAddressPlan.furthestStage, 'address-plan');
  assert.equal(stallInAddressPlan.terminalCause, 'native-worker-stall');
  assert.equal(stallInAddressPlan.evidenceStatus, 'verified');

  // Console response timed out during init
  const initTimeout = classifyRunOutcome({
    cases: [],
    error: 'Error: Console response timed out: Prepare reserved-gap scratch'
  });
  assert.equal(initTimeout.furthestStage, 'init');
  assert.equal(initTimeout.terminalCause, 'transport-disconnected');

  // Two real observed canary-phase failures (2026-11-11): one with shifted binary-path
  // landings, one with no landing at all. Both must classify, and landing counters must
  // separate the two shapes.
  const positiveRow = (overrides = {}) => ({
    profile: 'positive', triggerAborted: false, canaryType: 1, changedPaths: [],
    rows: [{role: 'canary', result: 0}],
    ...overrides
  });
  const shifted = classifyRunOutcome({
    cases: [
      positiveRow({changedPaths: ['canary'], canaryType: null,
        rows: [{role: 'canary', result: 0x2eea02}]}),
      positiveRow(),
      positiveRow({triggerAborted: true})
    ],
    markerSelected: false,
    markerReproduced: false,
    error: 'Error: Positive phase contains an uncertain overwrite; retain resources for recovery'
  });
  assert.equal(shifted.terminalCause, 'positive-phase-uncertain');
  assert.equal(shifted.evidenceStatus, 'verified');
  assert.equal(shifted.furthestStage, 'canary-select');
  assert.equal(shifted.canaryMarkerHits, 0);
  assert.equal(shifted.canaryBinaryLandings, 1);
  assert.equal(shifted.canaryUnabortedWaves, 2);

  const noLanding = classifyRunOutcome({
    cases: [positiveRow(), positiveRow(), positiveRow()],
    markerSelected: false,
    markerReproduced: false,
    error: 'Error: Positive phase contains an uncertain overwrite; retain resources for recovery'
  });
  assert.equal(noLanding.terminalCause, 'canary-not-qualified');
  assert.equal(noLanding.canaryBinaryLandings, 0);
  assert.equal(noLanding.canaryMarkerHits, 0);
  assert.equal(noLanding.canaryUnabortedWaves, 3);

  // Second-phase variant observed on 2026-11-11 (switch2-YkJ1Bj): marker selected
  // in phase 0, then 30 clean reproduction waves, then the repeated-phase failure.
  // The verdict belongs to the failing phase, so an earlier marker hit must not be
  // read as a later deviation.
  const repeated = classifyRunOutcome({
    cases: [positiveRow({changedPaths: ['canary'], canaryType: 0, rows: [{role: 'canary', result: 0}]}),
      ...Array.from({length: 30}, () => positiveRow())],
    retryPhases: [
      {profile: 'positive', waves: 1, complete: true, markerObserved: true, unsafe: false},
      {profile: 'positive', waves: 30, complete: true, markerObserved: false, unsafe: true}
    ],
    markerSelected: true,
    markerReproduced: false,
    error: 'Error: Repeated positive phase contains an uncertain overwrite; retain resources for recovery'
  });
  assert.equal(repeated.terminalCause, 'canary-not-qualified');
  assert.equal(repeated.furthestStage, 'canary-reproduce');
  assert.equal(repeated.canaryMarkerHits, 1);
  assert.equal(repeated.canaryUnabortedWaves, 31);

  // Same shape, but the failing phase itself contains the deviation.
  const repeatedDeviation = classifyRunOutcome({
    cases: [positiveRow({changedPaths: ['canary'], canaryType: 0, rows: [{role: 'canary', result: 0}]}),
      ...Array.from({length: 29}, () => positiveRow()),
      positiveRow({changedPaths: ['canary'], canaryType: null, rows: [{role: 'canary', result: 0x2eea02}]})],
    retryPhases: [
      {profile: 'positive', waves: 1, complete: true, markerObserved: true, unsafe: false},
      {profile: 'positive', waves: 30, complete: true, markerObserved: false, unsafe: true}
    ],
    markerSelected: true,
    markerReproduced: false,
    error: 'Error: Repeated positive phase contains an uncertain overwrite; retain resources for recovery'
  });
  assert.equal(repeatedDeviation.terminalCause, 'positive-phase-uncertain');
});

test('qualifyOverlap accepts a fully overlapped wave and rejects each lifetime violation', () => {
  const held = ['canary', 'filler0', 'filler1', 'guard0', 'guard1'];
  const through = ['commit', 'tail0', 'tail1', 'tail2', 'tail3'];
  const build = ({start, end} = {}) => [
    ...held.map(role => ({role, startUs: 100, endUs: 900})),
    ...through.map(role => ({role, startUs: 100, endUs: 900})),
    {role: 'trigger', startUs: (start ?? 200), endUs: (end ?? 800)},
    {role: 'hole', startUs: 100, endUs: 900},
    {role: 'preRelease', startUs: 100, endUs: 900},
    {role: 'release', startUs: 100, endUs: 900},
    {role: 'pin', startUs: 100, endUs: 900}
  ];
  assert.deepEqual(qualifyOverlap(build()), {qualified: true, mode: 'trigger-entry'});

  // One held role starting after the trigger violates startedBeforeTrigger.
  const lateHeld = build();
  lateHeld[0] = {...lateHeld[0], startUs: 300};
  assert.equal(qualifyOverlap(lateHeld).qualified, false);

  // One held role ending exactly at the trigger start violates heldLongEnough (strict <).
  const shortHeld = build();
  shortHeld[1] = {...shortHeld[1], endUs: 200};
  assert.equal(qualifyOverlap(shortHeld).qualified, false);

  // A through role ending at the trigger end violates throughTriggerEnd.
  const shortThrough = build();
  shortThrough[7] = {...shortThrough[7], endUs: 800};
  assert.equal(qualifyOverlap(shortThrough).qualified, false);

  // Missing roles are never a qualified overlap.
  assert.deepEqual(qualifyOverlap([{role: 'trigger', startUs: 0, endUs: 1}]),
    {qualified: false, mode: 'trigger-entry'});

  // Divergence pinning, now executable against the predicate the probe calls:
  // `qualifyExtentOverlap` (used for `isExtent && hasTmp`) requires held roles to
  // outlive trigger.endUs, while upstream's `qualifyOverlap` only requires
  // `trigger.startUs < endUs`. Wiring the loose predicate into the extent branch
  // now changes a function the probe imports, so this pair fails loudly.
  const extentRows = build();
  extentRows[2] = {...extentRows[2], endUs: 500}; // held role ends before trigger.endUs (800)
  assert.equal(qualifyOverlap(extentRows).qualified, true);
  assert.equal(qualifyExtentOverlap(extentRows), false);
  assert.equal(qualifyExtentOverlap(build()), true);
  assert.equal(qualifyExtentOverlap([{role: 'trigger', startUs: 0, endUs: 1}]), false);
});

test('shouldRetryPositiveWave retries only an unchanged owned canary', () => {
  // Unchanged owned canary: the only admissible retry.
  assert.equal(shouldRetryPositiveWave({
    canaryResult: 0, canaryType: 1, changedPaths: []
  }), true);

  // Marker hit ends the phase (accept).
  assert.equal(shouldRetryPositiveWave({
    canaryResult: 0, canaryType: 0, changedPaths: ['canary']
  }), false);

  // Shifted binary-path landing observed on 2026-11-11 ends the phase at once.
  assert.equal(shouldRetryPositiveWave({
    canaryResult: 0x2eea02, canaryType: null, changedPaths: ['canary']
  }), false);

  // A canary read error and a filler/guard deviation are verdicts, not retries.
  assert.equal(shouldRetryPositiveWave({canaryResult: 0x202, canaryType: null, changedPaths: ['canary']}), false);
  assert.equal(shouldRetryPositiveWave({canaryResult: 0, canaryType: 1, changedPaths: ['filler0']}), false);
  assert.equal(shouldRetryPositiveWave({canaryResult: 0, canaryType: 1, changedPaths: ['canary', 'filler1']}), false);
});
