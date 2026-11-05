const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { a } = require('../shared/rpc.cjs');
const { request } = require('./tools/endpoint.cjs');
const { verifyProof } = require('./memory/verify-proof.cjs');
const { save, read } = require('./ro/runtime.cjs');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// A wave that stops advancing while it is inside a blocking await is stalled.
// The host detects this from the report with its own monotonic clock and never
// issues an RPC while the console's request path may still be occupied.
// `signal-start`, `join-start` and `replies-start` arm the window: each marker
// is written immediately before a blocking native await, and the next marker
// proves that the await returned. The post-join reply read is included because
// a hang there has no other progress marker. Remaining inter-wave work keeps
// the previous marker and is bounded by the global acquisition deadline.
const STALL_MS = 60 * 1000;
const DEADLINE_MS = 25 * 60 * 1000;
const ARMED_STAGES = new Set(['signal-start', 'join-start', 'replies-start']);

// The acquisition owns native allocations until retire() completes.
async function start(options = {}) {
  const stallMs = Number.isFinite(options.stallMs) ? options.stallMs : STALL_MS;
  // Fail closed: one attempt only. A retry after an unsafe attempt starts a new
  // session or runs cleanup-scratch on a wedged FS session, which can block the
  // main thread for minutes.
  const MAX_ATTEMPTS = 1;
  let lastError;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
    const logFile = path.join(__dirname, 'acquisition.log');

    if (attempt === 0) {
      try {
        await fs.promises.unlink(logFile);
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    }

    const log = fs.createWriteStream(logFile, { flags: attempt === 0 ? 'wx' : 'a', mode: 0o600 });
    await new Promise((resolve, reject) => { log.once('open', resolve); log.once('error', reject); });
    const child = spawn(process.execPath, [path.join(__dirname, 'memory/probe-reserved-gap.cjs')],
      { cwd: __dirname, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
    let reportFile, exited, spawnError;
    child.once('error', error => { spawnError = error; });
    const done = new Promise(resolve => child.once('close', (code, signal) => {
      exited = { code, signal }; log.end(); resolve(exited);
    }));
    const lines = readline.createInterface({ input: child.stdout });
    lines.on('line', line => {
      let row;
      try { row = JSON.parse(line); } catch { return; }
      if (row.stage === 'connected') reportFile = row.file;
    });
    const abandon = async () => {
      if (!exited) child.kill('SIGKILL');
      await done;
    };
    try {
      const deadline = Date.now() + DEADLINE_MS;
      let report, recorded = false, armedKey = null, armedSince = 0;
// AFTER in acquire.cjs
      for (; ;) {
        if (reportFile) {
          try {
            report = await read(reportFile);
            if (!recorded) {
              // Keep the scratch owner discoverable even if acquisition later fails.
              await save(path.join(__dirname, 'current-acquisition.json'), { session: a.session, report: reportFile });
              recorded = true;
            }
          } catch {
            // Transient read/parse collision while report is being saved on Windows.
            // Safe to ignore and retry on the next 500ms tick.
          }
        }
        if (report?.memoryControl?.ready) break;
        if (exited || spawnError || Date.now() >= deadline) {
          const latest = reportFile ? await read(reportFile).catch(() => null) : null;
          const progress = latest?.progress?.stage ? ' (last stage: ' + latest.progress.stage + ')' : '';
          const cause = latest?.error ? ': ' + String(latest.error).split('\n')[0].slice(0, 240) : '';
          throw Error('FS acquisition did not complete' + cause + progress + '. Inspect ' + logFile +
            '; restart the console before another launch.');
        }
        if (report?.progress?.stage) {
          const key = report.progress.profile + ':' + report.progress.stage + ':' + report.progress.at;
          if (key !== armedKey) {
            armedKey = key;
            armedSince = performance.now();
          }
          if (ARMED_STAGES.has(report.progress.stage) && performance.now() - armedSince > stallMs)
            throw Error('FS acquisition stalled (WAVE_STALLED) at ' + report.progress.profile + ':' +
              report.progress.stage + '; no progress for ' + Math.round((performance.now() - armedSince) / 1000) +
              ' s. The worker state is unknown; do not release or reuse this session. Inspect ' +
              logFile + '; restart the console before another launch.');
        }
        await delay(500);
      }
      const publishable = async () => {
        const latest = await read(reportFile);
        if (latest.session !== a.session || latest.memoryControl?.ready !== true ||
            latest.error || latest.cleanupError || latest.cacheRestoreError ||
            latest.placementUncertain || latest.stopped || exited || spawnError ||
            Date.now() >= deadline)
          throw Error('FS acquisition lost lifecycle authority before publication');
        return latest;
      };
      if (report.session !== a.session || report.error || report.cleanupError ||
          report.cacheRestoreError || report.placementUncertain || report.stopped)
        throw Error('FS acquisition is unsafe, closed, or belongs to another session');
      const proof = await verifyProof(reportFile, a.session);
      // Saved proof is not a liveness check: revalidate authority at each publication.
      await publishable();
      const supervisorReport = path.join(__dirname, 'acquisition-supervisor.json');
      await save(supervisorReport, { stage: 'memory-ready', attempts: [{ report: reportFile }] });
      const published = await publishable();
      const current = {
        session: a.session, report: reportFile, supervisorReport,
        socketPath: published.memoryControl.socketPath, proof, finished: new Date().toISOString()
      };
      await save(path.join(__dirname, 'current-acquisition.json'), current);
      await publishable();
      return {
        ...current, abandon,
        async retire() {
          const latest = await read(reportFile);
          const retained = latest.retainedMemory;
          if (!latest.memoryControl?.ready || latest.placementUncertain || retained?.pending ||
            latest.memoryControl.pending || latest.retained.threads.length ||
            retained?.promoted && (!retained.ready || !retained.canonical || !retained.zeroCountVerified))
            throw Error('The retained endpoint cannot be retired from its current state');
          const state = latest.nativeRo;
          if (state?.worker && !state.worker.joined) throw Error('A native worker is still pending');
          const result = await request(current.socketPath, { command: 'retire' });
          if (!result.retired && !result.retiring) throw Error('The retained endpoint did not retire');
          const deadline = Date.now() + 60000;
          while (!exited && Date.now() < deadline) await delay(100);
          if (!exited) throw Error('FS cleanup timed out; inspect ' + reportFile);
          const final = await read(reportFile);
          if (exited.code !== 0 || !final.cleanedUp || final.cleanupError)
            throw Error('FS resources did not clean up completely; inspect ' + reportFile);
          return { cleanedUp: true, report: reportFile };
        },
      };
    } catch (error) {
      await abandon();
      lastError = error;
    }
  }
  throw lastError;
}

module.exports = { start, DEADLINE_MS };
