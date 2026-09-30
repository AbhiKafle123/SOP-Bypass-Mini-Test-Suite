#!/usr/bin/env node
/**
 * Verify CVE records against the official CVE List V5, which is the CNA's own
 * published data rather than a secondary aggregator.
 *
 * This exists because the first version of this repository shipped CVE IDs with
 * no provenance, and at least some of them do not survive checking. A security
 * test suite that cites a CVE it has not verified is worse than one that cites
 * none: the reader cannot tell which half is real, so the whole thing has to be
 * discarded. Every ID this project publishes goes through here first, and the
 * result is committed alongside the claim.
 *
 * NVD, MITRE's web UI and the Chrome release blog are all egress-blocked in the
 * container this was developed in; the GitHub mirror of the CVE List is not, and
 * it is the better source anyway.
 *
 *   node research/verify-cves.js                    # verify the shipped corpus
 *   node research/verify-cves.js CVE-2025-4664 ...   # verify specific IDs
 *   node research/verify-cves.js --json
 */
'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');

const RAW = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/';

/** cves/2025/4xxx/CVE-2025-4664.json — last three digits become "xxx". */
function cvePath(id) {
  const m = /^CVE-(\d{4})-(\d{4,})$/.exec(id.trim().toUpperCase());
  if (!m) return null;
  const [, year, num] = m;
  const bucket = num.length <= 3 ? '0xxx' : num.slice(0, num.length - 3) + 'xxx';
  return `${year}/${bucket}/CVE-${year}-${num}.json`;
}

function get(url, redirects) {
  redirects = redirects == null ? 4 : redirects;
  return new Promise((resolve) => {
    const req = https.get(url, { headers: { 'User-Agent': 'sop-lab-cve-verify' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        return resolve(get(new URL(res.headers.location, url).toString(), redirects - 1));
      }
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', (e) => resolve({ status: 0, body: '', error: String(e.message) }));
    req.setTimeout(25000, () => { req.destroy(); resolve({ status: 0, body: '', error: 'timeout' }); });
  });
}

/** Pull the "prior to X" boundary out of Chrome's very regular phrasing. */
function extractBoundary(text) {
  const m = /prior to (\d+(?:\.\d+)*)/i.exec(text || '');
  return m ? m[1] : null;
}

function extractSeverity(text) {
  const m = /Chromium security severity:\s*([A-Za-z]+)/i.exec(text || '');
  return m ? m[1] : null;
}

async function verify(id) {
  const rel = cvePath(id);
  if (!rel) return { id, status: 'MALFORMED_ID' };
  const r = await get(RAW + rel);
  if (r.status === 404) {
    return { id, status: 'NOT_FOUND',
      note: 'no such record in the CVE List — treat the ID as unsubstantiated' };
  }
  if (r.status !== 200) {
    return { id, status: 'FETCH_FAILED', httpStatus: r.status, error: r.error || null };
  }
  let j;
  try { j = JSON.parse(r.body); } catch (e) { return { id, status: 'BAD_JSON' }; }

  const meta = j.cveMetadata || {};
  const c = (j.containers && j.containers.cna) || {};
  const desc = ((c.descriptions || []).find((d) => d.lang && d.lang.startsWith('en'))
    || (c.descriptions || [])[0] || {}).value || '';
  const products = [];
  for (const a of c.affected || []) {
    for (const v of a.versions || []) {
      products.push([a.vendor, a.product, v.version, v.lessThan, v.status]
        .filter(Boolean).join(' '));
    }
    if (!(a.versions || []).length) products.push([a.vendor, a.product].filter(Boolean).join(' '));
  }
  const refs = (c.references || []).map((x) => x.url).filter(Boolean);
  const bugIds = refs
    .map((u) => (/issues\.chromium\.org\/issues\/(\d+)/.exec(u) || [])[1])
    .filter(Boolean);

  return {
    id,
    status: meta.state === 'REJECTED' ? 'REJECTED' : 'FOUND',
    cveState: meta.state || null,
    assigner: meta.assignerShortName || null,
    datePublished: meta.datePublished || null,
    title: c.title || null,
    description: desc,
    priorTo: extractBoundary(desc),
    chromiumSeverity: extractSeverity(desc),
    affected: products.slice(0, 8),
    chromiumBugIds: bugIds,
    references: refs.slice(0, 6),
  };
}

/** Is `version` strictly below the record's "prior to" boundary? */
function isAffected(version, priorTo) {
  if (!version || !priorTo) return null;
  const a = String(version).split('.').map(Number);
  const b = String(priorTo).split('.').map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0, y = b[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false; // equal to the fixed version means fixed
}

async function main() {
  const argv = process.argv.slice(2);
  const asJson = argv.includes('--json');
  let ids = argv.filter((a) => /^CVE-/i.test(a));

  if (!ids.length) {
    const corpusFile = path.join(__dirname, 'cve-corpus.json');
    if (fs.existsSync(corpusFile)) {
      const corpus = JSON.parse(fs.readFileSync(corpusFile, 'utf8'));
      ids = (corpus.entries || []).map((e) => e.cve).filter((x) => /^CVE-/i.test(x));
    }
  }
  if (!ids.length) {
    console.error('nothing to verify: pass CVE IDs, or create research/cve-corpus.json');
    process.exit(2);
  }
  ids = Array.from(new Set(ids.map((s) => s.toUpperCase())));

  const out = [];
  for (const id of ids) {
    const r = await verify(id);
    out.push(r);
    if (!asJson) {
      if (r.status === 'FOUND') {
        console.log(`${r.id}  priorTo=${r.priorTo || '?'}  sev=${r.chromiumSeverity || '-'}`
          + `  bug=${r.chromiumBugIds.join(',') || '-'}`);
        console.log('    ' + (r.description || '').replace(/\s+/g, ' ').slice(0, 165));
      } else {
        console.log(`${r.id}  ${r.status}${r.note ? '  — ' + r.note : ''}`);
      }
    }
  }
  if (asJson) {
    console.log(JSON.stringify({ verifiedAt: new Date().toISOString(), results: out }, null, 2));
  } else {
    const found = out.filter((x) => x.status === 'FOUND').length;
    const missing = out.filter((x) => x.status === 'NOT_FOUND').map((x) => x.id);
    console.log(`\n${found}/${out.length} verified in the CVE List`);
    if (missing.length) {
      console.log('NOT FOUND (do not cite these without another primary source): '
        + missing.join(', '));
    }
  }
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { verify, cvePath, isAffected, extractBoundary };
