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

module.exports = {hasWindow, canaryChanged, markerObserved, summarize, summarizeCopyStep, classifyAliasObservation};
