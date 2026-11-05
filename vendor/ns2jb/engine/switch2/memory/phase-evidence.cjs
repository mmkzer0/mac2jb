const crypto = require('node:crypto');
// Phase-level evidence for the reserved-gap probe.
// A positive phase is unsafe only when it ended without a qualified marker and
// at least one wave actually overwrote memory without aborting. A later hit in
// the same phase resolves the phase; earlier misses remain recorded in the
// summary as provenance, never as a verdict on their own.
const hasWindow = row => row.restored && !row.triggerAborted && row.allPending &&
  row.receiveOrderMarginUs >= 300 && row.preReleaseUsed >= 0x2600;

const canaryChanged = row => row.changedPaths.includes('canary') && row.allPending &&
  row.receiveOrderMarginUs >= 300;

const markerObserved = row => canaryChanged(row) && row.canaryType === 0 &&
  row.changedPaths.every(name => name === 'canary') && hasWindow(row);

function summarize(profile, rows, complete) {
  return {
    profile,
    complete: complete === true,
    waves: rows.length,
    unaborted: rows.filter(row => !row.triggerAborted).length,
    canaryChanged: rows.some(canaryChanged),
    markerObserved: rows.some(markerObserved),
    unsafe: profile === 'positive' && !rows.some(markerObserved) &&
      rows.some(row => !row.triggerAborted)
  };
}

function summarizeCopyStep(name, rows, requiredCopies, minimumCacheHeld = 0x2810, options = {}) {
  const isAccepted = row =>
    hasWindow(row) && row.preReleaseUsed >= minimumCacheHeld && row.changedPaths.length === 0;
  const acceptedRows = rows.filter(isAccepted);
  const unabortedRejected = rows.filter(row => !row.triggerAborted && !isAccepted(row)).length;
  const lowPreReleaseRejected = rows.filter(row =>
    !row.triggerAborted && hasWindow(row) && row.preReleaseUsed < minimumCacheHeld && row.changedPaths.length === 0
  ).length;
  const margins = rows.map(row => row.receiveOrderMarginUs).filter(Number.isFinite);
  const preRelease = acceptedRows.map(row => row.preReleaseUsed).filter(Number.isFinite);
  const guards = {completed: 0, earlyHole: 0, minimumSpacing: 0};
  for (const row of rows) if (row.triggerAborted)
    for (const key of Object.keys(guards)) if (row.nativeGuard?.[key]) guards[key]++;
  const qualified = typeof options.qualified === 'boolean'
    ? options.qualified
    : acceptedRows.length >= requiredCopies;
  return {
    name,
    required: requiredCopies,
    attempts: rows.length,
    accepted: acceptedRows.length,
    qualified,
    confirmedBatch: options.confirmedBatch ?? (qualified ? 0 : null),
    aborted: rows.filter(row => row.triggerAborted).length,
    unabortedRejected,
    lowPreReleaseRejected,
    unverifiedMemoryEffect: unabortedRejected > 0,
    canaryMisses: rows.filter(row => row.changedPaths.length > 0).length,
    guards,
    bestMarginUs: margins.length ? Math.max(...margins) : null,
    minAcceptedMarginUs: acceptedRows.length ? Math.min(...acceptedRows.map(r => r.receiveOrderMarginUs)) : null,
    minAcceptedPreReleaseUsed: preRelease.length ? Math.min(...preRelease) : null,
    maxAcceptedPreReleaseUsed: preRelease.length ? Math.max(...preRelease) : null
  };
}

function classifyAliasObservation({aliased, primeBytes, aliasControlBytes, outputPoison = 0xa5}) {
  const result = aliased?.result ?? null;
  const bytes = aliased?.bytes ?? null;
  if (result || !bytes) {
    return {
      classification: 'ipc-error',
      selectedAlias: false,
      normalContent: false,
      untouchedPoison: false,
      zeroFilled: false,
      poisonBytes: null,
      primeMatchingBytes: null,
      normalMatchingBytes: null,
      firstDiffFromPrime: null,
      firstDiffFromNormal: null
    };
  }
  const selectedAlias = bytes.equals(primeBytes);
  const normalContent = !selectedAlias && bytes.equals(aliasControlBytes);
  let poisonBytes = 0, zeroBytes = 0, primeMatchingBytes = 0, normalMatchingBytes = 0;
  let firstDiffFromPrime = -1, firstDiffFromNormal = -1;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === outputPoison) poisonBytes++;
    if (bytes[i] === 0) zeroBytes++;
    if (i < primeBytes.length && bytes[i] === primeBytes[i]) primeMatchingBytes++;
    else if (firstDiffFromPrime === -1) firstDiffFromPrime = i;
    if (i < aliasControlBytes.length && bytes[i] === aliasControlBytes[i]) normalMatchingBytes++;
    else if (firstDiffFromNormal === -1) firstDiffFromNormal = i;
  }
  const untouchedPoison = !selectedAlias && !normalContent && poisonBytes === bytes.length;
  const zeroFilled = !selectedAlias && !normalContent && !untouchedPoison && zeroBytes === bytes.length;
  const partialPrimePrefix = !selectedAlias && !normalContent && !untouchedPoison && !zeroFilled &&
    firstDiffFromPrime >= 4;
  const classification = selectedAlias ? 'selected-alias'
    : normalContent ? 'ordinary-backing-read'
    : untouchedPoison ? 'untouched-receive-buffer'
    : zeroFilled ? 'zero-filled'
    : partialPrimePrefix ? 'partial-prime-prefix'
    : 'unexpected-content';
  return {
    classification,
    selectedAlias,
    normalContent,
    untouchedPoison,
    zeroFilled,
    poisonBytes,
    primeMatchingBytes,
    normalMatchingBytes,
    firstDiffFromPrime,
    firstDiffFromNormal
  };
}

function summarizeRangeLeak(widenedBytes, controlBytes, linkCandidates = [], outputPoison = 0xa5) {
  const blockSize = 0x4000;
  const totalBlocks = Math.floor(widenedBytes.length / blockSize);
  const ctrlBlocks = new Map();
  const ctrlCount = Math.floor((controlBytes?.length ?? 0) / blockSize);
  for (let idx = 0; idx < ctrlCount; idx++) {
    const off = idx * blockSize;
    const h = crypto.createHash('sha256').update(controlBytes.subarray(off, off + blockSize)).digest('hex');
    if (!ctrlBlocks.has(h)) ctrlBlocks.set(h, []);
    ctrlBlocks.get(h).push(idx);
  }
  const seenOutHashes = new Set();
  const partition = {
    matchesControlSameOffset: 0,
    matchesControlOtherOffset: 0,
    exactDuplicateBlocks: 0,
    zeroFilled: 0,
    poisonFilled: 0,
    pointerBearing: 0,
    asciiHeavy: 0,
    otherBinary: 0
  };
  const independentCounts = {
    asciiHeavyBlocks: 0,
    pointerBearingBlocks: 0,
    uniqueOutHashes: 0
  };
  let overReadBlockHeadsInRange = 0;
  let overReadBlockHeads16kAligned = 0;
  let overReadRawPointersTotal = 0;
  let overReadRawPointers16kAligned = 0;

  for (let idx = 0; idx < totalBlocks; idx++) {
    const off = idx * blockSize;
    const slice = widenedBytes.subarray(off, off + blockSize);
    const h = crypto.createHash('sha256').update(slice).digest('hex');
    const isDuplicate = seenOutHashes.has(h);
    seenOutHashes.add(h);

    let zeros = 0, poisons = 0, ascii = 0, blockPtrs = 0;
    for (let i = 0; i < slice.length; i++) {
      const b = slice[i];
      if (b === 0) zeros++;
      if (b === outputPoison) poisons++;
      if ((b >= 0x20 && b <= 0x7e) || b === 0x0a || b === 0x0d || b === 0x09) ascii++;
    }
    for (let i = 0; i + 8 <= slice.length; i += 8) {
      const hi = slice.readUInt32LE(i + 4);
      if (hi < 1 || hi >= 0x80) continue;
      const lo = slice.readUInt32LE(i);
      if ((lo & 0xffffff) === 0) continue;
      if (idx >= 1 && i === 0) {
        overReadBlockHeadsInRange++;
        if ((lo & 0x3fff) === 0) overReadBlockHeads16kAligned++;
      }
      if ((lo & 7) === 0) {
        blockPtrs++;
        if (idx >= 1) {
          overReadRawPointersTotal++;
          if ((lo & 0x3fff) === 0) overReadRawPointers16kAligned++;
        }
      }
    }
    if (ascii > blockSize / 2) independentCounts.asciiHeavyBlocks++;
    if (blockPtrs > 0) independentCounts.pointerBearingBlocks++;

    // Priority-ordered mutually exclusive partition:
    const ctrlMatch = ctrlBlocks.get(h);
    if (ctrlMatch && ctrlMatch.includes(idx)) partition.matchesControlSameOffset++;
    else if (ctrlMatch) partition.matchesControlOtherOffset++;
    else if (isDuplicate) partition.exactDuplicateBlocks++;
    else if (zeros === blockSize) partition.zeroFilled++;
    else if (poisons === blockSize) partition.poisonFilled++;
    else if (blockPtrs > 0) partition.pointerBearing++;
    else if (ascii > blockSize / 2) partition.asciiHeavy++;
    else partition.otherBinary++;
  }
  independentCounts.uniqueOutHashes = seenOutHashes.size;
  return {
    blockSize,
    totalBlocks,
    partition,
    independentCounts,
    overReadBlockHeadsInRange,
    overReadBlockHeads16kAligned,
    overReadRawPointersTotal,
    overReadRawPointers16kAligned,
    qualifiedLinkCandidates: linkCandidates.length,
    encodableLinkCandidates: linkCandidates.filter(item => item.encodable).length
  };
}

module.exports = {
  hasWindow,
  canaryChanged,
  markerObserved,
  summarize,
  summarizeCopyStep,
  classifyAliasObservation,
  summarizeRangeLeak
};
