// Phase-evidence truth table. Pure function, no console, no repository writes.
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const {summarize} = require(path.join(__dirname, '..',
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
