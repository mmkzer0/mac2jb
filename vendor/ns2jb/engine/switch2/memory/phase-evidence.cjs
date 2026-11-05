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

module.exports = {hasWindow, canaryChanged, markerObserved, summarize};
