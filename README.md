SOP Bypass Mini Test Suite V3.0
================================

Browser security research suite for Same-Origin Policy bypasses, cross-origin data
leaks and URL spoofing.

V3.0 changes what the project *is*. V1.0 and V2.0 were collections of HTML pages
that demonstrated and asserted behaviour. V3.0 adds a real multi-origin testbed, a
Playwright runner, and an integrity rule that makes the verdicts checkable:

- **Six genuinely distinct origins** on loopback, differing by host, by port and by
  scheme, served over HTTPS under a locally generated CA.
- **A per-run canary.** Regenerated on every server boot, and never served to
  attacker-origin pages. A probe that reports it has moved data across an origin
  boundary during this run — it cannot have guessed it, hardcoded it, or replayed
  it from a fixture.
- **Out-of-page verification.** A probe runs inside the page and is not trusted to
  grade itself. The runner holds the authoritative canary and downgrades any
  `BYPASS` whose evidence does not contain it.
- **Negative controls throughout.** 17 of 30 probes exist to confirm the boundary
  *holds*. A suite that can only report bypasses is not measuring anything.

Current run of record: **30 probes, Chromium 141.0.7390.37, 9 verified bypasses,
17 blocked, 4 inconclusive, 0 unresolved divergences.** See **[FINDINGS.md](FINDINGS.md)**.

## Quick start

```bash
npm install                      # playwright-core only; no browser download
bash lab/make-certs.sh           # local CA + SAN cert for the lab origins
sudo bash lab/hosts-setup.sh     # map the lab hostnames to 127.0.0.1

node automation/browser-versions.js      # what this machine can actually drive
node automation/runner.js --all --report # run everything available
node research/query.js --detect          # which corpus CVEs apply to these builds
```

Filter a run: `--engine chromium`, `--lane canvas-sop`, `--probe RELAX-02`,
`--headed`.

## The two version questions, answered

| Question | Answer | Reproduce |
|---|---|---|
| A Chrome version where cross-origin issues apply | **Chromium 141.0.7390.37** — behind the fix line for **10 of 16** Chromium records in the corpus, including CVE-2026-17779 (Site Isolation, fixed 151.0.7922.72) | `node research/query.js --detect` |
| A Firefox version with a comparable issue | **Firefox 141.x** — newest build still vulnerable to **CVE-2025-9180**, an SOP bypass in Graphics: Canvas2D (fixed in 142 / ESR 115.27 / 128.14 / 140.2) | `node research/query.js --engine firefox --version 141.0` |

Both engines land on 141, in unrelated components. Full evidence and caveats in
[FINDINGS.md](FINDINGS.md) §1–2.

## Architecture

```
lab/
  make-certs.sh       local CA + leaf cert covering every lab hostname
  hosts-setup.sh      /etc/hosts entries for the lab topology
  origin-server.js    six-origin vhost server; tunable response headers
  png.js              encodes the canary into image pixels (canvas probes)
probes/
  registry.js         all 29 probes; one source of truth for runner and dashboard
  harness.html        page the runner drives
automation/
  engines.js          on-disk browser discovery; refuses SOP-weakening flags
  browser-versions.js three independent version sources per engine
  runner.js           executes probes, verifies evidence, writes JSON + HTML
research/
  verify-cves.js      checks IDs against the official CVE List V5
  build-corpus.js     builds the verified corpus; curated fields labelled as such
  cve-corpus.json     24 entries, 24/24 verified
  query.js            version-to-vulnerability matcher
  dossier-*.md        full research dossiers, source URL per claim
.claude/agents/       four agents for extending the suite
results/              run artefacts; latest.json + report.html
tests/, legacy/       V2.0 and V1.0 HTML demonstration pages (unchanged)
```

### Lab origins

| Role | Origin | Differs from VICTIM by |
|---|---|---|
| VICTIM | `https://victim.sop-lab.test:8443` | — (holds the canary) |
| DOCUMENTED | `https://documented.sop-lab.test:8443` | the origin content *declares* |
| ATTACKER | `https://attacker.sop-lab.test:8443` | host |
| SIBLING | `https://sub.victim.sop-lab.test:8443` | host label only |
| ALTPORT | `https://victim.sop-lab.test:9443` | port only |
| INSECURE | `http://victim.sop-lab.test:8080` | scheme only |
| INSECURE_SIBLING | `http://sub.victim.sop-lab.test:8080` | scheme **and** host label |

HTTPS is not decoration: several primitives are secure-context gated, and
`Origin-Agent-Cluster` only engages in a secure context. `http://localhost` would
be a secure context but cannot provide sibling subdomains.

## Probe lanes

| Lane | Probes | Measures |
|---|---|---|
| `origin-oracle` | 2 | documented origin vs actually-loaded origin, and who may read the canary |
| `header-policy` | 3 | CORS enforcement, opaque responses, CVE-2025-4664 |
| `script-execution` | 2 | cross-origin script execution (XSSI), error muting |
| `sandbox-confinement` | 2 | `allow-scripts allow-same-origin` escape, and its cross-origin control |
| `origin-inheritance` | 4 | `srcdoc`, `blob:`, `javascript:` origin inheritance; blob partitioning |
| `origin-relaxation` | 4 | `document.domain` by default, under opt-out, unilaterally, and over plain http |
| `opener-navigation` | 3 | cross-origin `Window` property surface, frame counting, `window.name` |
| `messaging` | 2 | `postMessage` wildcard targeting, origin attribution |
| `side-channel` | 3 | status oracle, resource timing, redirect observability |
| `canvas-sop` | 3 | canvas taint, CVE-2025-9180 offscreen propagation, CORS control |
| `storage-isolation` | 2 | storage keyed on the full origin tuple |

Verdicts: `BYPASS` (canary crossed, verified) · `BLOCKED` (boundary held) ·
`INCONCLUSIVE` (ran, does not distinguish) · `UNSUPPORTED` · `ERROR`.

## Research mechanism

Every CVE this project cites is checked against the **official CVE List V5** — the
CNA's own published records — before it is allowed into the corpus:

```bash
node research/verify-cves.js CVE-2025-9180        # verify specific IDs
node research/build-corpus.js                     # rebuild; refuses unverified
node research/query.js --engine chromium --version 141.0.7390.37
node research/query.js --milestones               # behaviour changes that aren't CVEs
node research/query.js --unreachable              # needs a device or compromised renderer
```

The corpus separates **fetched** fields (description, boundary, severity, bug ID)
from **curated** ones (lane, probe mapping, whether a bug is reachable from
client-side markup). Curated fields are labelled as this project's inference,
because CVE text essentially never states reproduction requirements and presenting a
guess as a citation is how a suite loses its credibility.

## Agents

| Agent | Use |
|---|---|
`sop-probe-author` | turn a CVE, advisory or patch diff into an executable probe |
`sop-cve-researcher` | establish exact version boundaries from primary sources |
`sop-differential-triage` | run across engines; triage divergences into engine finding / harness bug / wrong expectation |
`sop-bypass-ladder` | drive one mechanism up a staged, independently-checkable ladder |

## Engine availability

`playwright-core` is used deliberately: it never downloads browsers, so the suite
runs against a **named, pinned binary** you can point at a deliberately old build —
which is the whole point when the question is which version a bug is present in.

```bash
SOP_CHROMIUM=/path/to/chrome node automation/runner.js --engine chromium
SOP_FIREFOX=/path/to/firefox  node automation/runner.js --engine firefox
```

Playwright's own Firefox is a patched Juggler build and **cannot be pinned to an
arbitrary upstream version**; for version-boundary work use a real release from
`archive.mozilla.org/pub/firefox/releases/<VERSION>/linux-x86_64/en-US/`, or
`mozregression`.

Firefox and WebKit were **not executed** in the environment that produced the
current results — no binaries were obtainable there. The runner records this in
`enginesUnavailable` rather than omitting it. Non-Chromium expectations in this
suite are documentation, not observation.

## Corrections to V2.0

Every CVE ID in the V2.0 README resolves to a real record. Several *attributions* do
not survive checking — CVE-2022-4908 is an iFrame Sandbox bug rather than a
Navigation API one, CVE-2025-58485 is Samsung Internet rather than Opera,
CVE-2025-12435 is Android-scoped, and CVE-2025-4664 was **removed** from CISA KEV in
June 2025. Details in [FINDINGS.md](FINDINGS.md) §6.

The suite's V2.0 tests under `tests/` and V1.0 tests under `legacy/` are retained
unchanged as demonstration pages. They assert; the V3.0 probes measure.

## On the blog post this was modelled after

The Hacktron post cited in the brief describes **V8 memory corruption, not an SOP
bypass** — Chrome 149.0.7827.201 / V8 14.9.207.35, no CVE, reconstructed from public
V8 fix commits. Its bug class does not transfer here at all; its *harness design*
does, and is adopted in `sop-bypass-ladder`. See [FINDINGS.md](FINDINGS.md) §7,
including the caveat that the post itself was egress-blocked and could not be read
first-hand.

## Credits

- **V3.0:** measured testbed, probe registry, verified CVE corpus
- **V2.0:** Abhi Kafle (abhikafle.com.np)
- **V1.0:** Rafay Baloch (original SOP Bypass Mini Test Suite)
- **Researchers cited:** Tom Van Goethem (CVE-2025-9180), Max Vlasov
  (CVE-2023-4045), Khalil Zhani (CVE-2025-23109), Andrew Osmond (CVE-2025-9180
  fix), Google Project Zero

## Disclaimer

For **authorized security research and responsible disclosure only**. The lab runs
entirely on loopback against origins it creates itself. Do not point the probes at
systems you do not own or have explicit written permission to test.

MIT licensed.
