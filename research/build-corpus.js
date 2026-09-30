#!/usr/bin/env node
/**
 * Build research/cve-corpus.json from the official CVE List V5.
 *
 * The curated part of each entry — which lane it belongs to, which probe (if
 * any) exercises it, whether it is reachable from pure client-side markup — lives
 * in SEED below and is explicitly labelled as this project's own judgement. Every
 * factual field (description, "prior to" boundary, Chromium severity, bug ID,
 * affected product list) is fetched and never hand-typed, so the corpus cannot
 * drift away from the CNA record.
 *
 * Anything the CVE List does not confirm is written out with status NOT_FOUND
 * rather than quietly dropped, because "we looked and it is not there" is itself
 * a finding worth keeping.
 *
 *   node research/build-corpus.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { verify } = require('./verify-cves');

/**
 * Curated seed. `note` and `clientSideOnly` are this project's assessment, not a
 * quotation from the record — the CVE text almost never states reproduction
 * requirements, so treating an inference as a citation would be dishonest.
 */
const SEED = [
  // --- Chrome / Chromium: cross-origin data and site isolation --------------
  { cve: 'CVE-2025-4664', engine: 'chromium', lane: 'header-policy',
    probe: 'HDR-03-link-header-referrer-leak', clientSideOnly: false,
    note: 'Link header on a cross-origin SUBRESOURCE response downgrades the '
        + 'embedding document\'s referrer policy to unsafe-url, leaking the full '
        + 'referrer including query string. Needs server header control on the '
        + 'subresource origin — an HTML <link rel=preload referrerpolicy> tag is '
        + 'NOT this bug and will appear to pass on patched builds.' },
  { cve: 'CVE-2025-6556', engine: 'chromium', lane: 'header-policy',
    probe: null, clientSideOnly: false,
    note: 'CSP bypass in the same Loader component. Only the second record in the '
        + 'entire CVE List using the exact phrase "Insufficient policy enforcement '
        + 'in Loader".' },
  { cve: 'CVE-2026-17779', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: true,
    note: 'Best site-isolation research target in this corpus: the only Site '
        + 'Isolation record here that does NOT require a pre-compromised renderer, '
        + 'so it is reachable from a crafted page alone.' },
  { cve: 'CVE-2026-17664', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: false,
    note: 'Requires an already-compromised renderer, so it is out of reach of a '
        + 'pure JS probe.' },
  { cve: 'CVE-2026-93379', engine: 'chromium', lane: 'header-policy',
    probe: null, clientSideOnly: true,
    note: 'Opaque Response Blocking (ORB) authorisation error — ORB is the '
        + 'successor to CORB and is precisely the machinery that stops a '
        + 'cross-origin fetch body reaching a renderer.' },
  { cve: 'CVE-2026-15130', engine: 'chromium', lane: 'opener-navigation',
    probe: null, clientSideOnly: true,
    note: 'Site isolation bypass via the Navigation component. Note this is the '
        + 'browser navigation stack, NOT the JS Navigation API.' },
  { cve: 'CVE-2026-79051', engine: 'chromium', lane: 'header-policy',
    probe: null, clientSideOnly: true,
    note: 'Phrased as "bypass web origin policy" — Chrome\'s 2026 taxonomy for '
        + 'what earlier records called insufficient policy enforcement.' },
  { cve: 'CVE-2026-87508', engine: 'chromium', lane: 'header-policy',
    probe: null, clientSideOnly: true,
    note: 'Second "bypass web origin policy" record in the Loader component.' },
  { cve: 'CVE-2026-11174', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: false, note: 'Requires a compromised renderer.' },
  { cve: 'CVE-2026-9903', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: false,
    note: 'Crafted MHTML; requires a compromised renderer.' },
  { cve: 'CVE-2024-1671', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: true, note: 'CSP bypass via Site Isolation.' },
  { cve: 'CVE-2024-3840', engine: 'chromium', lane: 'site-isolation',
    probe: null, clientSideOnly: true,
    note: 'Insufficient policy enforcement in Site Isolation — navigation '
        + 'restrictions.' },
  { cve: 'CVE-2022-4908', engine: 'chromium', lane: 'sandbox-confinement',
    probe: 'SANDBOX-02-cross-origin-sandbox-holds', clientSideOnly: true,
    note: 'iFrame Sandbox component, cross-origin data leak. The V2 README '
        + 'described this as a "Navigation API entries()" issue, which the record '
        + 'does not support — it is an iframe sandbox bug.' },

  // --- Chrome / Chromium: address bar and UI spoofing ----------------------
  { cve: 'CVE-2025-14373', engine: 'chromium', lane: 'url-spoofing',
    probe: null, clientSideOnly: true,
    note: 'Toolbar domain spoofing, Chrome on Android only. Not reproducible in '
        + 'headless automation: needs a real Android device with visible browser '
        + 'chrome.' },
  { cve: 'CVE-2025-12435', engine: 'chromium', lane: 'url-spoofing',
    probe: null, clientSideOnly: true,
    note: 'Omnibox UI spoofing, Chrome on Android. The V2 README described this as '
        + 'affecting Chromium generally; the record scopes it to Android.' },

  // --- Firefox / Gecko -----------------------------------------------------
  { cve: 'CVE-2025-9180', engine: 'firefox', lane: 'canvas-sop',
    probe: 'CANVAS-02-offscreen-transfer-taint-propagation', clientSideOnly: true,
    mfsa: ['2025-64 (Firefox 142)', '2025-65 (ESR 115.27)', '2025-66 (ESR 128.14)',
           '2025-67 (ESR 140.2)', '2025-70/-71/-72 (Thunderbird)'],
    bugzilla: '1979782',
    fixCommit: '44541e940dd8ab537118a39f77b1f4e9d23ce59e',
    newestVulnerable: ['Firefox 141.x', 'ESR 115.26', 'ESR 128.13', 'ESR 140.1'],
    note: 'Same-origin policy bypass in Graphics: Canvas2D; Mozilla impact "high", '
        + 'reported by Tom Van Goethem. Mechanism read from the fix commit, not '
        + 'from a writeup: OffscreenCanvasDisplayHelper carried no write-only '
        + 'member at all, so tainting a canvas inside a Worker after '
        + 'transferControlToOffscreen() left the main-thread toDataURL()/toBlob() '
        + 'readback ungated. The leak is raw cross-origin pixel data — a full read '
        + 'primitive, not a timing oracle. The same patch also fixed a TOCTOU via '
        + 'recheckCanRead after async encode. No public POC exists and Mozilla '
        + 'shipped no in-tree test, so probe CANVAS-02 was written from the diff. '
        + 'This is why Firefox 141.x is the chosen vulnerable Firefox build here — '
        + 'it pairs with Chromium 141, the build this suite executes against.' },
  { cve: 'CVE-2023-4045', engine: 'firefox', lane: 'canvas-sop',
    probe: 'CANVAS-02-offscreen-transfer-taint-propagation', clientSideOnly: true,
    mfsa: ['2023-29 (Firefox 116)'], bugzilla: '1833876',
    note: 'First of three shipped fixes for the same Offscreen Canvas cross-origin '
        + 'class: "Offscreen Canvas could have bypassed cross-origin '
        + 'restrictions", impact high, reported by Max Vlasov. Useful as a '
        + 'version-boundary regression anchor.' },
  { cve: 'CVE-2024-5693', engine: 'firefox', lane: 'canvas-sop',
    probe: 'CANVAS-02-offscreen-transfer-taint-propagation', clientSideOnly: true,
    mfsa: ['2024-25 (Firefox 127)'], bugzilla: '1891319',
    note: 'Second of the three: "Cross-Origin Image leak via Offscreen Canvas", '
        + 'impact moderate. Three separate fixes for one class across Firefox 116, '
        + '127 and 142 is the strongest argument in this corpus that canvas taint '
        + 'is structurally fragile: the flag rides on an object, so every new '
        + 'canvas surface is a fresh chance to forget to propagate it.' },
  { cve: 'CVE-2025-23109', engine: 'firefox', lane: 'url-spoofing',
    probe: null, clientSideOnly: true,
    note: 'Long hostname address-bar spoof, Firefox for iOS. Needs a real iOS '
        + 'device; the record confirms the ID the V2 README used.' },

  // --- Other engines -------------------------------------------------------
  { cve: 'CVE-2026-20643', engine: 'webkit', lane: 'opener-navigation',
    probe: null, clientSideOnly: true,
    note: 'Apple record: a cross-origin issue in the Navigation API. Unlike the '
        + 'Chromium "Navigation" component records, this one genuinely concerns '
        + 'the web-platform Navigation API.' },
  { cve: 'CVE-2025-58485', engine: 'other', lane: 'script-execution',
    probe: null, clientSideOnly: true,
    note: 'Samsung Internet, not Opera — the V2 README attributed this to Opera. '
        + 'Improper input validation allowing script injection.' },
  { cve: 'CVE-2019-12278', engine: 'other', lane: 'url-spoofing',
    probe: null, clientSideOnly: true,
    note: 'Opera on Android, RTL Unicode address-bar spoof. Needs visible browser '
        + 'chrome.' },

  // --- Historical anchors (the V1.0 suite's subject matter) ---------------
  { cve: 'CVE-2014-6041', engine: 'other', lane: 'origin-inheritance',
    probe: null, clientSideOnly: true,
    note: 'Android WebView SOP bypass via a NUL byte in an attribute. The bug the '
        + 'original V1.0 suite was built around.' },
  { cve: 'CVE-2014-3160', engine: 'chromium', lane: 'header-policy',
    probe: null, clientSideOnly: true,
    note: 'Blink ResourceFetcher::canRequest did not properly restrict subresource '
        + 'loads — an ancestor of the modern Loader policy records.' },
];

async function main() {
  const entries = [];
  for (const seed of SEED) {
    process.stderr.write('fetching ' + seed.cve + ' ... ');
    const v = await verify(seed.cve);
    process.stderr.write(v.status + '\n');
    entries.push({
      cve: seed.cve,
      // Curated by this project:
      engine: seed.engine,
      lane: seed.lane,
      probe: seed.probe,
      clientSideOnly: seed.clientSideOnly,
      note: seed.note,
      mfsa: seed.mfsa || null,
      bugzilla: seed.bugzilla || null,
      fixCommit: seed.fixCommit || null,
      newestVulnerable: seed.newestVulnerable || null,
      assessmentSource: 'sop-lab curation (inference, not quoted from the record)',
      // Fetched from the CVE List — never hand-edited:
      verification: {
        status: v.status,
        cveState: v.cveState || null,
        assigner: v.assigner || null,
        datePublished: v.datePublished || null,
        description: v.description || null,
        priorTo: v.priorTo || null,
        chromiumSeverity: v.chromiumSeverity || null,
        affected: v.affected || [],
        chromiumBugIds: v.chromiumBugIds || [],
        references: v.references || [],
        source: 'https://github.com/CVEProject/cvelistV5 (CVE List V5, CNA record)',
      },
    });
  }

  const corpus = {
    schema: 'sop-lab/cve-corpus/1',
    builtAt: new Date().toISOString(),
    provenance: {
      factualFields: 'CVE List V5 via raw.githubusercontent.com/CVEProject/cvelistV5',
      curatedFields: ['engine', 'lane', 'probe', 'clientSideOnly', 'note'],
      caveat: 'CVE descriptions state which versions are affected. They almost '
            + 'never state whether a bug is reachable from client-side markup '
            + 'alone, so every clientSideOnly value is this project\'s inference '
            + 'and should be treated as a hypothesis to test, not a citation.',
    },
    // The verified records themselves.
    entries: entries,
    // Milestone behaviour changes that are not CVEs but decide what a probe
    // should expect. Sources are named per item.
    milestones: [
      { engine: 'chromium', milestone: 115,
        change: 'document.domain setter stops relaxing the origin by default; the '
              + 'setter does not throw, it simply has no effect',
        optOut: 'Origin-Agent-Cluster: ?0 on the main document AND every '
              + 'participating frame',
        enterprisePolicy: 'OriginAgentClusterDefaultEnabled',
        chromestatus: '5428079583297536',
        probe: 'RELAX-01 / RELAX-02 / RELAX-03',
        caveat: 'In-tree Chromium documentation still says M106 in places. M106 '
              + 'was the announced plan; M115 was the milestone that shipped. '
              + 'Sources citing 106 are describing the plan.' },
      { engine: 'firefox', milestone: 138,
        change: 'Origin-Agent-Cluster request header supported (Chrome shipped it '
              + 'in 90). Gecko keeps the document.domain setter live and NOT '
              + 'pref-gated: dom/webidl/Document.webidl declares '
              + '"[SetterThrows] attribute DOMString domain" with no [Pref]. '
              + 'Gecko\'s own warning string, "Ignoring document.domain mutation '
              + 'in an origin-keyed agent cluster", shows the mutation is ignored '
              + 'CONDITIONALLY, not generally.',
        probe: 'RELAX-01 / RELAX-02 / RELAX-03',
        consequence: 'document.domain origin relaxation is a live Firefox-only '
                   + 'primitive and dead-by-default in Chromium. That asymmetry is '
                   + 'itself a test case, and it means RELAX-01 should read BYPASS '
                   + 'on Firefox and BLOCKED on Chromium.',
        caveat: 'Prefs dom.origin_agent_cluster.enabled and '
              + '.default exist, so the default flip is built but, on available '
              + 'evidence, not shipped. Their shipped values could not be read '
              + '(StaticPrefList.yaml exceeds GitHub code-search limits) — check '
              + 'about:config on a real Firefox before relying on this. '
              + 'Origin-Agent-Cluster only engages in secure contexts, so an HTTP '
              + 'test origin cannot exercise it; this is why the lab serves HTTPS.' },
      { engine: 'chromium', milestone: 137,
        change: 'blob: URL access partitioned by Storage Key = (top-level site, '
              + 'frame origin, has-cross-site-ancestor); top-level navigations '
              + 'remain keyed on frame origin only. noopener enforced on '
              + 'renderer-initiated cross-site top-level blob navigations.',
        chromestatus: '5130361898795008',
        chromiumBug: '40057646',
        specPr: 'w3c/FileAPI#201 (partition blob URL revocation by Storage Key, '
              + 'merged 2024-12-04)',
        probe: 'INHERIT-02 / INHERIT-03',
        caveat: 'Enterprise escape hatch PartitionedBlobUrlUsage was offered '
              + 'through Chrome 146.' },
    ],
  };

  const out = path.join(__dirname, 'cve-corpus.json');
  fs.writeFileSync(out, JSON.stringify(corpus, null, 2));
  const ok = entries.filter((e) => e.verification.status === 'FOUND').length;
  console.log(`wrote ${path.relative(path.join(__dirname, '..'), out)} — `
    + `${ok}/${entries.length} entries verified against the CVE List`);
  const bad = entries.filter((e) => e.verification.status !== 'FOUND');
  if (bad.length) {
    console.log('UNVERIFIED: ' + bad.map((b) => b.cve + '=' + b.verification.status).join(', '));
  }
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
