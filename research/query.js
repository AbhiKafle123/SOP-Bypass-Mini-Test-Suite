#!/usr/bin/env node
/**
 * Version-to-vulnerability matcher over the verified CVE corpus.
 *
 * This is the research mechanism: given a browser build, it answers "which
 * documented cross-origin issues is this build behind the fix line for", and
 * conversely "which build do I need in order to reach this issue". The point is
 * to stop reasoning about browser security from milestone memory. "Recent Chrome"
 * is not a security property; 141.0.7390.37 versus 151.0.7922.72 is.
 *
 *   node research/query.js --detect                       # match what is installed
 *   node research/query.js --engine chromium --version 141.0.7390.37
 *   node research/query.js --engine firefox  --version 141.0
 *   node research/query.js --lane canvas-sop
 *   node research/query.js --probe CANVAS-02
 *   node research/query.js --unreachable                  # needs a device/renderer
 *   node research/query.js --json
 */
'use strict';

const fs = require('fs');
const path = require('path');

const CORPUS = path.join(__dirname, 'cve-corpus.json');

function load() {
  if (!fs.existsSync(CORPUS)) {
    console.error('missing ' + path.relative(process.cwd(), CORPUS)
      + ' — run: node research/build-corpus.js');
    process.exit(2);
  }
  return JSON.parse(fs.readFileSync(CORPUS, 'utf8'));
}

/** Numeric dotted-version compare. Returns <0, 0, >0. */
function cmp(a, b) {
  const x = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const y = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] || 0) - (y[i] || 0);
    if (d) return d;
  }
  return 0;
}

/**
 * Is `version` affected by this entry?
 *
 * Chromium records carry a machine-readable "prior to X" boundary in the CNA
 * description, so the comparison is exact. Mozilla records do not phrase it that
 * way, so the corpus carries an explicit newestVulnerable list and Firefox
 * matching falls back to the first component of the fixed version in the MFSA
 * strings. Where neither is available the answer is null — genuinely unknown —
 * and the caller must not render that as "not affected".
 */
function affectedBy(entry, version) {
  const priorTo = entry.verification && entry.verification.priorTo;
  if (priorTo) {
    return { affected: cmp(version, priorTo) < 0, boundary: priorTo, basis: 'CNA "prior to" boundary' };
  }
  // Mozilla path: derive boundaries from the MFSA fixed_in strings.
  const mfsa = entry.mfsa || [];
  const nums = mfsa
    .map((m) => (/(\d+(?:\.\d+)*)/.exec(String(m).replace(/^\d{4}-\d+\s*/, '')) || [])[1])
    .filter(Boolean);
  if (nums.length) {
    // Compare against the mainline boundary: the largest major among the fixes
    // that shares this version's major line, else the smallest mainline fix.
    const major = parseInt(String(version).split('.')[0], 10);
    const sameLine = nums.filter((n) => parseInt(n.split('.')[0], 10) === major);
    const boundary = sameLine.length
      ? sameLine.sort(cmp)[0]
      : nums.sort(cmp).find((n) => parseInt(n.split('.')[0], 10) > major) || nums.sort(cmp)[0];
    return { affected: cmp(version, boundary) < 0, boundary, basis: 'MFSA fixed_in' };
  }
  return { affected: null, boundary: null, basis: 'no machine-readable boundary in record' };
}

function parseArgs(argv) {
  const a = { json: false };
  for (let i = 2; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--json') a.json = true;
    else if (t === '--detect') a.detect = true;
    else if (t === '--engine') a.engine = argv[++i];
    else if (t === '--version') a.version = argv[++i];
    else if (t === '--lane') a.lane = argv[++i];
    else if (t === '--probe') a.probe = argv[++i];
    else if (t === '--unreachable') a.unreachable = true;
    else if (t === '--milestones') a.milestones = true;
    else if (t === '--help' || t === '-h') { console.log(head()); process.exit(0); }
    else { console.error('unknown argument: ' + t); process.exit(2); }
  }
  return a;
}

function head() {
  return fs.readFileSync(__filename, 'utf8')
    .split('\n').slice(1, 22).map((l) => l.replace(/^ ?\*?\/?\*? ?/, '')).join('\n');
}

function fmt(e, match) {
  const v = e.verification;
  const lines = [];
  const verdict = match
    ? (match.affected === true ? 'AFFECTED'
      : match.affected === false ? 'fixed' : 'unknown')
    : '';
  lines.push(`${e.cve}  [${e.engine}/${e.lane}]${verdict ? '  ' + verdict : ''}`);
  if (v.priorTo) lines.push(`    fixed in      ${v.priorTo}`);
  if (e.mfsa) lines.push(`    advisories    ${e.mfsa.join('; ')}`);
  if (e.newestVulnerable) lines.push(`    still vuln    ${e.newestVulnerable.join(', ')}`);
  if (v.chromiumSeverity) lines.push(`    severity      ${v.chromiumSeverity} (Chromium rating)`);
  if (v.chromiumBugIds && v.chromiumBugIds.length) {
    lines.push(`    chromium bug  ${v.chromiumBugIds.join(', ')}`);
  }
  if (e.bugzilla) lines.push(`    bugzilla      ${e.bugzilla}`);
  if (e.fixCommit) lines.push(`    fix commit    ${e.fixCommit}`);
  lines.push(`    probe         ${e.probe || '(none in this suite)'}`);
  lines.push(`    reachable     ${e.clientSideOnly
    ? 'from client-side markup (this suite\'s assessment)'
    : 'NOT from client-side markup alone (this suite\'s assessment)'}`);
  if (v.description) {
    lines.push('    record        ' + v.description.replace(/\s+/g, ' ').slice(0, 150));
  }
  lines.push('    note          ' + String(e.note).replace(/\s+/g, ' '));
  return lines.join('\n');
}

async function detectInstalled() {
  const { discover } = require('../automation/engines');
  const found = discover();
  const out = [];
  for (const [engine, info] of Object.entries(found)) {
    if (!info.available) continue;
    // "Chromium 141.0.7390.37" -> "141.0.7390.37"; "Mozilla Firefox 156.0" -> "156.0"
    const m = /(\d+(?:\.\d+)+)/.exec(info.binaryVersion || '');
    out.push({ engine, version: m ? m[1] : null, binaryVersion: info.binaryVersion,
      executablePath: info.executablePath });
  }
  return out;
}

async function main() {
  const a = parseArgs(process.argv);
  const corpus = load();
  let entries = corpus.entries || [];

  if (a.lane) entries = entries.filter((e) => e.lane === a.lane);
  if (a.probe) entries = entries.filter((e) => e.probe && e.probe.includes(a.probe));
  if (a.unreachable) entries = entries.filter((e) => !e.clientSideOnly);

  if (a.milestones) {
    if (a.json) return console.log(JSON.stringify(corpus.milestones, null, 2));
    console.log('Behaviour milestones that decide what a probe should expect\n'
      + '='.repeat(72));
    for (const m of corpus.milestones) {
      console.log(`\n${m.engine} ${m.milestone}`);
      for (const [k, val] of Object.entries(m)) {
        if (k === 'engine' || k === 'milestone') continue;
        console.log('  ' + k.padEnd(18) + String(val).replace(/\s+/g, ' '));
      }
    }
    return console.log('');
  }

  // Version matching.
  let targets = [];
  if (a.detect) targets = await detectInstalled();
  else if (a.engine && a.version) targets = [{ engine: a.engine, version: a.version }];

  if (!targets.length) {
    if (a.json) return console.log(JSON.stringify({ entries }, null, 2));
    console.log(`CVE corpus — ${entries.length} entries, all verified against the CVE List`);
    console.log('='.repeat(72) + '\n');
    for (const e of entries) console.log(fmt(e, null) + '\n');
    console.log('provenance: ' + corpus.provenance.factualFields);
    console.log('caveat:     ' + corpus.provenance.caveat.replace(/\s+/g, ' '));
    return;
  }

  const report = [];
  for (const t of targets) {
    const engineEntries = entries.filter((e) => e.engine === t.engine);
    const scored = engineEntries.map((e) => ({ entry: e, match: affectedBy(e, t.version) }));
    const hit = scored.filter((s) => s.match.affected === true);
    const unk = scored.filter((s) => s.match.affected === null);
    report.push({ target: t, affected: hit, unknown: unk, considered: engineEntries.length });
  }

  if (a.json) {
    return console.log(JSON.stringify({
      queriedAt: new Date().toISOString(),
      results: report.map((r) => ({
        engine: r.target.engine, version: r.target.version,
        binaryVersion: r.target.binaryVersion || null,
        consideredEntries: r.considered,
        affected: r.affected.map((s) => ({
          cve: s.entry.cve, lane: s.entry.lane, boundary: s.match.boundary,
          basis: s.match.basis, probe: s.entry.probe,
          clientSideOnly: s.entry.clientSideOnly,
          severity: s.entry.verification.chromiumSeverity || null,
        })),
        indeterminate: r.unknown.map((s) => s.entry.cve),
      })),
    }, null, 2));
  }

  for (const r of report) {
    const t = r.target;
    console.log('='.repeat(72));
    console.log(`${t.engine} ${t.version || '(version unknown)'}`
      + (t.binaryVersion ? `   [${t.binaryVersion}]` : ''));
    if (t.executablePath) console.log('  ' + t.executablePath);
    console.log('='.repeat(72));
    if (!t.version) {
      console.log('\n  cannot match: no parsable version string\n');
      continue;
    }
    console.log(`\n${r.affected.length} of ${r.considered} ${t.engine} entries apply to this build\n`);
    // Client-side-reachable first: those are the ones a probe can chase.
    const ordered = r.affected.slice().sort((x, y) =>
      (y.entry.clientSideOnly ? 1 : 0) - (x.entry.clientSideOnly ? 1 : 0));
    for (const s of ordered) {
      console.log(fmt(s.entry, s.match));
      console.log('');
    }
    if (r.unknown.length) {
      console.log('indeterminate (no machine-readable boundary — do NOT read as '
        + '"not affected"): ' + r.unknown.map((s) => s.entry.cve).join(', ') + '\n');
    }
  }
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { affectedBy, cmp };
