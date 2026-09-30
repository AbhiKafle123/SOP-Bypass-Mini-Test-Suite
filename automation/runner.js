#!/usr/bin/env node
/**
 * SOP Lab runner.
 *
 * Boots the multi-origin lab, drives every available engine through the probe
 * registry, and — the part that matters — independently verifies every BYPASS
 * claim before allowing it into the report.
 *
 * The verification rule: a probe runs inside the page and cannot be trusted to
 * grade itself, because a probe that has been handed the secret can "succeed"
 * without crossing anything. So the runner holds the authoritative canary (read
 * from the lab's boot line, never exposed to attacker-origin pages) and demands
 * that any BYPASS produce that exact string as evidence. A claim that cannot is
 * downgraded to INCONCLUSIVE and flagged. This is the difference between a suite
 * that measures the Same-Origin Policy and one that merely asserts things about
 * it.
 *
 * Usage
 *   node automation/runner.js                       # chromium, local lab
 *   node automation/runner.js --all                 # every engine found
 *   node automation/runner.js --engine firefox
 *   node automation/runner.js --report              # also write HTML
 *   node automation/runner.js --probe SANDBOX-01    # substring filter
 *   node automation/runner.js --lane origin-oracle
 *   node automation/runner.js --headed
 */
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { discover, LAUNCH, assertNoSopWeakeningFlags } = require('./engines');

const ROOT = path.resolve(__dirname, '..');
const OUT_DIR = path.join(ROOT, 'results');

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function parseArgs(argv) {
  const a = {
    engines: [], report: false, headed: false,
    probeFilter: null, laneFilter: null, keepOpen: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--all') a.engines = ['chromium', 'firefox', 'webkit'];
    else if (t === '--engine') a.engines.push(argv[++i]);
    else if (t === '--report') a.report = true;
    else if (t === '--headed') a.headed = true;
    else if (t === '--probe') a.probeFilter = argv[++i];
    else if (t === '--lane') a.laneFilter = argv[++i];
    else if (t === '--keep-open') a.keepOpen = true;
    else if (t === '--help' || t === '-h') { usage(); process.exit(0); }
    else { console.error('unknown argument: ' + t); usage(); process.exit(2); }
  }
  if (!a.engines.length) a.engines = ['chromium'];
  return a;
}

function usage() {
  console.log(`
SOP Lab runner

  --all               run every engine found on this machine
  --engine <name>     chromium | firefox | webkit (repeatable)
  --probe <substr>    only probes whose id contains <substr>
  --lane <name>       only probes in one lane
  --report            also write an HTML report
  --headed            show the browser window
  --keep-open         leave the lab server running after the run
`);
}

// ---------------------------------------------------------------------------
// Lab lifecycle
// ---------------------------------------------------------------------------
function startLab() {
  return new Promise((resolve, reject) => {
    const certDir = path.join(ROOT, 'lab', 'certs');
    if (!fs.existsSync(path.join(certDir, 'leaf.crt'))) {
      return reject(new Error('missing lab certs — run: bash lab/make-certs.sh'));
    }
    const proc = spawn(process.execPath, [path.join(ROOT, 'lab', 'origin-server.js')], {
      cwd: ROOT, env: Object.assign({}, process.env, { SOP_LAB_QUIET: '1' }),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let buf = '';
    const onData = (chunk) => {
      buf += chunk;
      const line = buf.split('\n').find((l) => l.startsWith('SOP_LAB_READY '));
      if (line) {
        proc.stdout.off('data', onData);
        try {
          resolve({ proc, info: JSON.parse(line.slice('SOP_LAB_READY '.length)) });
        } catch (e) { reject(e); }
      }
    };
    proc.stdout.on('data', onData);
    proc.stderr.on('data', (d) => process.stderr.write('[lab-err] ' + d));
    proc.on('exit', (c) => {
      if (!buf.includes('SOP_LAB_READY')) {
        reject(new Error('lab server exited early (code ' + c + '): ' + buf.slice(0, 400)));
      }
    });
    setTimeout(() => reject(new Error('lab server did not become ready in 20s')), 20000);
  });
}

// ---------------------------------------------------------------------------
// Verification — the integrity gate
// ---------------------------------------------------------------------------
/**
 * Re-grade a probe's self-reported verdict against ground truth.
 *
 * A BYPASS survives only if the evidence contains the exact per-run canary.
 * Anything else is recorded as unverified: the probe may be right, but this run
 * did not prove it, and an unproven bypass claim is worse than no claim.
 */
function verify(result, canary) {
  const out = Object.assign({}, result);
  out.claimedVerdict = result.verdict;
  out.canaryVerified = Boolean(result.evidence && String(result.evidence).includes(canary));

  if (result.verdict === 'BYPASS' && !out.canaryVerified) {
    out.verdict = 'INCONCLUSIVE';
    out.integrityNote = 'probe claimed BYPASS but produced no verifiable canary; '
      + 'downgraded by the runner';
  } else if (result.verdict !== 'BYPASS' && out.canaryVerified) {
    // The inverse mistake: canary present but the probe graded itself as safe.
    out.verdict = 'BYPASS';
    out.integrityNote = 'probe graded itself ' + result.verdict
      + ' but the canary is present in its evidence; upgraded by the runner';
  }

  const expected = (result.expect || {})[out.engine] || null;
  out.expected = expected;
  out.divergesFromExpectation = Boolean(expected && expected !== out.verdict);
  return out;
}

// ---------------------------------------------------------------------------
// Probe execution
// ---------------------------------------------------------------------------
async function runEngine(engine, engineInfo, lab, args) {
  const pw = require('playwright-core');
  const launchOpts = LAUNCH[engine]({
    executablePath: engineInfo.executablePath,
    headless: !args.headed,
  });
  assertNoSopWeakeningFlags(launchOpts.args);

  const browser = await pw[engine].launch(launchOpts);
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });

  const meta = {
    engine,
    executablePath: engineInfo.executablePath,
    binaryVersion: engineInfo.binaryVersion,
    playwrightBuild: engineInfo.playwrightBuild,
    protocolVersion: browser.version(),
    playwrightCore: require('playwright-core/package.json').version,
    launchArgs: launchOpts.args || [],
  };

  // Read the probe manifest once, from any origin.
  const bootPage = await ctx.newPage();
  await bootPage.goto(lab.origins.VICTIM + '/probes/harness.html',
    { waitUntil: 'load', timeout: 20000 });
  meta.userAgent = await bootPage.evaluate(() => navigator.userAgent);
  const manifest = await bootPage.evaluate(() => window.SOPProbes.manifest());
  await bootPage.close();

  let selected = manifest;
  if (args.probeFilter) {
    selected = selected.filter((p) => p.id.toLowerCase().includes(args.probeFilter.toLowerCase()));
  }
  if (args.laneFilter) {
    selected = selected.filter((p) => p.lane === args.laneFilter);
  }
  if (!selected.length) throw new Error('no probes matched the filter');

  console.log(`\n${engine} — ${meta.binaryVersion || meta.protocolVersion}`);
  console.log('  ' + meta.userAgent);
  console.log('  running ' + selected.length + ' probe(s)\n');

  const results = [];
  for (const p of selected) {
    const origin = lab.origins[p.runOn] || lab.origins.ATTACKER;
    // Some probes need response headers on the top-level harness document itself
    // (Origin-Agent-Cluster is negotiated per document, not per frame).
    const harnessUrl = origin + '/probes/harness.html'
      + (p.harnessQuery ? '?' + p.harnessQuery : '');
    const page = await ctx.newPage();
    const consoleErrors = [];
    page.on('console', (m) => {
      if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200));
    });
    page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + String(e.message).slice(0, 200)));

    let raw;
    try {
      await page.goto(harnessUrl, { waitUntil: 'load', timeout: 20000 });
      await page.waitForFunction(() => window.__SOP_HARNESS_READY__ === true,
        null, { timeout: 10000 });
      raw = await page.evaluate((id) => window.SOPProbes.run(id), p.id);
    } catch (e) {
      raw = {
        id: p.id, lane: p.lane, title: p.title, why: p.why, runOn: p.runOn,
        references: p.references, expect: p.expect,
        verdict: 'ERROR',
        detail: 'harness failure: ' + String(e && e.message ? e.message : e).slice(0, 300),
        evidence: null,
      };
    }
    await page.close();

    const withEngine = Object.assign({}, raw, {
      engine, servedFrom: origin, harnessUrl, consoleErrors,
    });
    const graded = verify(withEngine, lab.canary);
    results.push(graded);

    const mark = {
      BYPASS: 'BYPASS      ', BLOCKED: 'blocked     ',
      INCONCLUSIVE: 'inconclusive', UNSUPPORTED: 'unsupported ',
      ERROR: 'ERROR       ',
    }[graded.verdict] || graded.verdict;
    const flag = graded.divergesFromExpectation ? '  <-- diverges from expectation' : '';
    console.log('  ' + mark + ' ' + graded.id + flag);
    if (graded.integrityNote) console.log('               ! ' + graded.integrityNote);
  }

  // Server-side view of what actually arrived at the sink.
  let hits = null;
  try {
    const p2 = await ctx.newPage();
    await p2.goto(lab.origins.VICTIM + '/lab/hits', { timeout: 10000 });
    hits = JSON.parse(await p2.evaluate(() => document.body.innerText));
    await p2.close();
  } catch (_) { /* non-fatal */ }

  await browser.close();
  return { meta, results, serverHits: hits };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
function summarise(runs) {
  const counts = {};
  const bypasses = [];
  const divergences = [];
  for (const r of runs) {
    for (const x of r.results) {
      counts[x.verdict] = (counts[x.verdict] || 0) + 1;
      if (x.verdict === 'BYPASS') bypasses.push(x);
      if (x.divergesFromExpectation) divergences.push(x);
    }
  }
  return { counts, bypasses, divergences };
}

/**
 * Strip the literal canary out of anything written to disk.
 *
 * The canary is the suite's proof of a boundary crossing, so committing it would
 * hand a future reader a value they could hardcode to fake a BYPASS — which
 * defeats the one property that makes these verdicts worth anything. Verification
 * has already happened in memory by this point, and its outcome survives in the
 * canaryVerified boolean, so the raw value has no further job. Replaced with a
 * marker rather than deleted, so the evidence still reads as evidence.
 */
function redactCanary(payload, canary) {
  const json = JSON.stringify(payload);
  const rx = new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
  return JSON.parse(json.replace(rx, '<CANARY:verified-in-run>'));
}

function writeJson(payload) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(OUT_DIR, 'run-' + stamp + '.json');
  fs.writeFileSync(file, JSON.stringify(payload, null, 2));
  const latest = path.join(OUT_DIR, 'latest.json');
  fs.writeFileSync(latest, JSON.stringify(payload, null, 2));
  return file;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function writeHtml(payload) {
  const rows = [];
  for (const run of payload.runs) {
    for (const x of run.results) {
      rows.push(`<tr class="v-${esc(x.verdict)}">
  <td><code>${esc(x.id)}</code></td>
  <td>${esc(x.lane)}</td>
  <td><span class="badge b-${esc(x.verdict)}">${esc(x.verdict)}</span>
      ${x.divergesFromExpectation ? '<span class="dv">diverges</span>' : ''}</td>
  <td>${esc(x.expected || '-')}</td>
  <td>${esc(x.engine)}</td>
  <td>${esc(x.runOn)}</td>
  <td>${x.canaryVerified ? '<b class="yes">verified</b>' : '<span class="no">-</span>'}</td>
  <td class="detail">${esc(x.title)}<br><span class="d">${esc(x.detail)}</span>
      ${x.integrityNote ? '<br><span class="warn">! ' + esc(x.integrityNote) + '</span>' : ''}</td>
</tr>`);
    }
  }
  const engines = payload.runs.map((r) => `<li><b>${esc(r.meta.engine)}</b> —
    ${esc(r.meta.binaryVersion || r.meta.protocolVersion)}<br>
    <code>${esc(r.meta.userAgent)}</code></li>`).join('');

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOP Lab results</title>
<style>
 :root{color-scheme:light dark;--bg:#0f1115;--fg:#d7dae0;--mut:#8b93a1;--line:#242832}
 body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
      font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
 h1{font-size:17px;margin:0 0 2px}
 .sub{color:var(--mut);font-size:12px;margin-bottom:18px}
 table{border-collapse:collapse;width:100%;margin-top:10px}
 th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);
       vertical-align:top;font-size:12px}
 th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:10.5px;
    letter-spacing:.06em}
 .badge{padding:1px 7px;border-radius:3px;font-size:11px;font-weight:600}
 .b-BYPASS{background:#7f1d1d;color:#fecaca}
 .b-BLOCKED{background:#14532d;color:#bbf7d0}
 .b-INCONCLUSIVE{background:#78350f;color:#fde68a}
 .b-UNSUPPORTED{background:#1f2937;color:#9ca3af}
 .b-ERROR{background:#4c1d95;color:#ddd6fe}
 .dv{margin-left:6px;color:#fbbf24;font-size:10.5px}
 .d{color:var(--mut)}
 .warn{color:#fbbf24}
 .yes{color:#86efac}.no{color:#4b5563}
 .detail{max-width:46ch}
 ul{margin:6px 0 0;padding-left:18px;color:var(--mut)}
 .cards{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}
 .card{border:1px solid var(--line);border-radius:6px;padding:9px 14px;min-width:96px}
 .card b{display:block;font-size:19px}
 code{color:#93c5fd}
</style></head><body>
<h1>SOP Lab results</h1>
<div class="sub">run ${esc(payload.runId)} &middot; ${esc(payload.generatedAt)} &middot;
 canary <code>${esc(payload.canaryFingerprint)}</code></div>
<div class="cards">
${Object.entries(payload.summary.counts).map(([k, v]) =>
  `<div class="card"><b>${v}</b>${esc(k.toLowerCase())}</div>`).join('')}
</div>
<h3>Engines</h3><ul>${engines}</ul>
<table><thead><tr><th>Probe</th><th>Lane</th><th>Verdict</th><th>Expected</th>
<th>Engine</th><th>Ran on</th><th>Canary</th><th>Title / detail</th></tr></thead>
<tbody>${rows.join('\n')}</tbody></table>
</body></html>`;
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, 'report.html');
  fs.writeFileSync(file, html);
  return file;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const args = parseArgs(process.argv);
  const found = discover();

  const runnable = args.engines.filter((e) => found[e] && found[e].available);
  const missing = args.engines.filter((e) => !found[e] || !found[e].available);
  if (!runnable.length) {
    console.error('no requested engine is available on this machine.');
    console.error('found: ' + JSON.stringify(
      Object.fromEntries(Object.entries(found).map(([k, v]) => [k, v.available])), null, 2));
    process.exit(3);
  }
  if (missing.length) {
    console.log('skipping unavailable engine(s): ' + missing.join(', '));
  }

  const { proc, info } = await startLab();
  console.log('lab up — origins:');
  for (const [k, v] of Object.entries(info.origins)) console.log('  ' + k.padEnd(11) + v);

  const runs = [];
  try {
    for (const engine of runnable) {
      runs.push(await runEngine(engine, found[engine], info, args));
    }
  } finally {
    if (!args.keepOpen) proc.kill('SIGTERM');
  }

  const summary = summarise(runs);
  const payload = {
    schema: 'sop-lab/run/1',
    generatedAt: new Date().toISOString(),
    runId: info.runId,
    // Fingerprint only — the full canary stays out of committed artefacts.
    canaryFingerprint: info.canary.slice(0, 22) + '…',
    origins: info.origins,
    enginesRequested: args.engines,
    enginesRun: runnable,
    enginesUnavailable: missing.map((e) => ({
      engine: e, reason: 'no binary found on this machine',
    })),
    summary: {
      counts: summary.counts,
      verifiedBypasses: summary.bypasses.map((b) => ({
        id: b.id, engine: b.engine, lane: b.lane, detail: b.detail,
      })),
      divergences: summary.divergences.map((d) => ({
        id: d.id, engine: d.engine, expected: d.expected, got: d.verdict,
      })),
    },
    runs,
  };

  // Redact before anything touches disk, and before the HTML report is built
  // from the same object.
  const onDisk = redactCanary(payload, info.canary);
  const jsonFile = writeJson(onDisk);
  console.log('\n' + '='.repeat(72));
  console.log('summary: ' + Object.entries(summary.counts)
    .map(([k, v]) => v + ' ' + k.toLowerCase()).join(', '));
  if (summary.bypasses.length) {
    console.log('\nverified bypasses (canary crossed an origin boundary):');
    for (const b of summary.bypasses) {
      console.log('  - ' + b.id + ' [' + b.engine + '] ' + b.title);
    }
  } else {
    console.log('\nno verified bypasses in this run.');
  }
  if (summary.divergences.length) {
    console.log('\ndiverges from documented expectation:');
    for (const d of summary.divergences) {
      console.log('  - ' + d.id + ' [' + d.engine + '] expected '
        + d.expected + ', got ' + d.verdict);
    }
  }
  console.log('\njson: ' + path.relative(ROOT, jsonFile));
  if (args.report) console.log('html: ' + path.relative(ROOT, writeHtml(onDisk)));
  console.log('');
}

if (require.main === module) {
  main().catch((e) => { console.error('\nrunner failed: ' + (e && e.stack || e)); process.exit(1); });
}
module.exports = { verify, summarise, redactCanary };
