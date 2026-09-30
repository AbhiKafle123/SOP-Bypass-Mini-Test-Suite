# Findings — SOP Lab V3.0

Measured results, the evidence behind them, and an explicit account of what is
*not* established. Every version number here was verified against a primary source;
every `BYPASS` was verified by the runner against a per-run secret.

Run of record: `results/latest.json` — 30 probes, Chromium 141.0.7390.37,
**9 verified bypasses / 17 blocked / 4 inconclusive / 0 unresolved divergences**.

---

## 0. What was actually executed, and what was not

This matters more than any individual result, so it goes first.

| Engine | Executed | Build |
|---|---|---|
| Chromium | **yes** | 141.0.7390.37 (Playwright build `chromium-1194`) |
| Firefox | **no** | no binary obtainable in this container |
| WebKit | **no** | no binary obtainable in this container |

Firefox and WebKit could not be run here. `cdn.playwright.dev`,
`playwright.azureedge.net` and every `*.mozilla.org` host are blocked by the
container's egress proxy, and Ubuntu's `firefox` package is a transitional stub that
defers to snap. Every Firefox expectation in this suite is therefore **documented,
not observed**. The runner records this in `enginesUnavailable` rather than omitting
it, because an untested engine reported as passing is the single easiest way for a
security suite to mislead.

To run the missing engines on a machine with open egress:

```bash
npx playwright install --with-deps firefox webkit
node automation/runner.js --all --report
```

To test the *vulnerable* Firefox specifically (see §2), Playwright's own Firefox
will not do — it is a patched Juggler build and cannot be pinned to an arbitrary
upstream version. Use a real release:

```bash
# archive.mozilla.org is blocked in this container; run this where it is not
curl -O https://archive.mozilla.org/pub/firefox/releases/141.0/linux-x86_64/en-US/firefox-141.0.tar.xz
tar xf firefox-141.0.tar.xz
SOP_FIREFOX=$PWD/firefox/firefox node automation/runner.js --engine firefox --lane canvas-sop
```

---

## 1. Chrome: a version where cross-origin issues apply

**Answer: Chromium 141.0.7390.37** — the build this suite actually executed
against. It is behind the fix boundary for **10 of the 16 Chromium records** in the
verified corpus.

Reproduce: `node research/query.js --detect`

Client-side reachable, so a probe can chase them:

| CVE | Component | Fixed in | Sev | Chromium bug |
|---|---|---|---|---|
| **CVE-2026-17779** | Site Isolation | 151.0.7922.72 | Medium | 513478933 |
| CVE-2026-93379 | ORB | 153.0.8010.52 | High | 560039872 |
| CVE-2026-15130 | Navigation | 150.0.7871.115 | High | 526541544 |
| CVE-2026-79051 | Loader | 152.0.7977.65 | Medium | 513841856 |
| CVE-2026-87508 | Loader | 153.0.8010.36 | Medium | 513346220 |
| CVE-2025-12435 | Omnibox (Android) | 142.0.7444.59 | Medium | 446463993 |
| CVE-2025-14373 | Toolbar (Android) | 143.0.7499.110 | Medium | 461532432 |

Not reachable without a pre-compromised renderer: CVE-2026-17664
(151.0.7922.72), CVE-2026-11174 (149.0.7827.53), CVE-2026-9903 (148.0.7778.216).

**CVE-2026-17779 is the best research target in this set** — it is the only Site
Isolation record here that does *not* require a compromised renderer, so a crafted
page alone can reach it.

Two caveats stated plainly:

- The two Android records (CVE-2025-12435, CVE-2025-14373) are **address-bar and
  toolbar spoofs scoped to Chrome on Android**. A headless Linux Chromium has no
  browser chrome to spoof, so they are unreachable here regardless of version. The
  V2 README described CVE-2025-12435 as affecting "Chromium-based" browsers
  generally; the CVE record scopes it to Android.
- Chromium 141 is **not** affected by CVE-2025-4664 (fixed in 136.0.7103.113).
  Probe `HDR-03` confirms this empirically — it returns `BLOCKED`, which is the
  correct result for a patched build and a useful demonstration that the probe can
  distinguish the two states.

---

## 2. Firefox: a comparable issue, and its exact boundary

**Answer: CVE-2025-9180 — same-origin-policy bypass in Graphics: Canvas2D. The
newest still-vulnerable build is Firefox 141.x.**

That pairs neatly with the Chromium answer: **both engines at version 141**, both
behind a cross-origin fix line, in unrelated components.

| Field | Value |
|---|---|
| Mozilla impact | high |
| Advisories | MFSA 2025-64 (Firefox **142**), 2025-65 (ESR **115.27**), 2025-66 (ESR **128.14**), 2025-67 (ESR **140.2**) |
| Still vulnerable | **Firefox 141.x**, ESR 115.26, ESR 128.13, ESR 140.1 |
| Bugzilla | 1979782 |
| Reporter | Tom Van Goethem |
| Fix commit | `44541e940dd8ab537118a39f77b1f4e9d23ce59e` |

**Mechanism, read from the fix commit rather than from a writeup** — necessary
because no public POC exists and Mozilla shipped the fix with no in-tree test:

`OffscreenCanvasDisplayHelper` carried **no write-only member at all**. The patch
adds `mIsWriteOnly`. Consequently, after `transferControlToOffscreen()`, tainting a
canvas inside a Worker left the main-thread `toDataURL()` / `toBlob()` readback
**ungated**. What leaks is raw pixel data of the cross-origin image — a full read
primitive, not a timing oracle. The same patch closed a TOCTOU hole by re-checking
readability after async encode (`recheckCanRead`).

Probe `CANVAS-02` implements this mechanism from the diff. Triggering it needs
`drawImage()` of a cross-origin resource without permissive CORS; there is **no
indication a specific graphics backend is required** — every file the patch touches
is platform-independent DOM/canvas plumbing, with no GPU, WebRender or driver code
changed. (That last point is inference from the diff, labelled as such.)

This is not an isolated slip. Firefox has shipped **three** fixes for the same
Offscreen-Canvas cross-origin class:

| CVE | Title | Fixed in | Bug |
|---|---|---|---|
| CVE-2023-4045 | Offscreen Canvas could have bypassed cross-origin restrictions | Firefox 116 | 1833876 |
| CVE-2024-5693 | Cross-Origin Image leak via Offscreen Canvas | Firefox 127 | 1891319 |
| CVE-2025-9180 | Same-origin policy bypass in Graphics: Canvas2D | Firefox 142 | 1979782 |

Three fixes for one class across 116, 127 and 142 is the strongest evidence in this
corpus that **canvas taint is structurally fragile**: the origin-clean flag rides on
an object rather than sitting on a boundary between realms, so every new canvas
surface is a fresh opportunity to forget to propagate it.

---

## 3. The nine verified bypasses

Each of the nine was verified by the runner: the probe's `evidence` contained the
exact per-run canary, a value regenerated on every server boot and never given to
attacker-origin pages. Shape-matched in-page, exact-matched out-of-page.

**Classification matters more than the count.** A `BYPASS` here is not automatically
an engine vulnerability, and presenting them as interchangeable would be dishonest.

### 3a. Engine behaviour that is genuinely a live SOP relaxation

**`RELAX-02` — `document.domain` relaxation under `Origin-Agent-Cluster: ?0`.**
The most substantive finding in the run.

```
self.domain=sop-lab.test  selfRelaxed=true
originAgentCluster=false (opt-out honoured)
frameRelaxedTo=sop-lab.test
crossRead=RESOLVED          <-- canary crossed
```

Read as a four-probe matrix — no single probe supports the conclusion:

| Probe | Scheme | `originAgentCluster` | Header sent | Setter | Cross-read |
|---|---|---|---|---|---|
| `RELAX-01` | https | `true` | none | **silent no-op** | BLOCKED |
| `RELAX-02` | https | `false` | `?0` on both | changes value | **RESOLVED** |
| `RELAX-03` | https | `false` | `?0`, only one side relaxes | changes value | BLOCKED |
| `RELAX-04` | **http** | **`false`** | **none** | **changes value** | **RESOLVED** |

Two conclusions, and the second is the sharper one.

**First: the Chrome 115 change is a default-flip, not a removal.** Origin relaxation
is fully alive in Chromium 141 for any site that emits `Origin-Agent-Cluster: ?0`.
`RELAX-03` bounds the severity — relaxation is **not** attacker-unilateral, so this
is a cooperative legacy feature and not a bypass against arbitrary subdomains.
Without `RELAX-03`, `RELAX-02` would read far more alarming than it is.

**Second: the default-flip only ever applied to secure contexts.** `Origin-Agent-
Cluster` is honoured only in a secure context, so on plain `http://` the header is
irrelevant — `RELAX-04` sends **no header at all**, reads
`originAgentCluster=false`, changes `document.domain` from
`sub.victim.sop-lab.test` to `sop-lab.test`, and completes the cross-subdomain read.
No opt-in, no server cooperation, nothing to configure.

So the widely repeated summary "Chrome disabled `document.domain` in 115" is true of
**https only**. Any `http://` origin retains cross-subdomain origin relaxation
unconditionally in Chromium 141. For an internal tool, a legacy intranet app or
anything else still served over plain HTTP, the mitigation people believe they got
in Chrome 115 is simply not present.

One implementation detail that cost real debugging time: `Origin-Agent-Cluster` is
negotiated **per document**, so the header must be on the top-level page as well as
the framed one — hence the `harnessQuery` mechanism. A probe that sets it only on
the frame reports a false `BLOCKED`.

A second-order observation worth recording, because it bit the hosted dashboard:
**relaxation is irreversible and it nulls the port component of the origin.** A
document that relaxes stops being same-origin with its own later-created `blob:`
frames, since those inherit the unrelaxed tuple. The hosted probe set had to move
its `document.domain` test into a throwaway frame for exactly this reason — which is
the same footgun the feature is notorious for, observed from the inside.

### 3b. By-design holes in the origin model — exploitable, and not engine bugs

| Probe | What crosses | Why it works |
|---|---|---|
| `SCRIPT-01` | canary in a script body, executed in the attacker origin | SOP never restricted script *execution* by origin, only reading source text. The XSSI/JSONP class. |
| `SANDBOX-01` | parent DOM contents; the frame also **deleted its own `sandbox` attribute** (`reachedParent=true sandboxCleared=true`) | `allow-scripts` + `allow-same-origin` on same-origin content keeps the embedder's origin. The HTML spec warns about this explicitly. |
| `INHERIT-01` | parent DOM contents, read from a `srcdoc` frame | A `srcdoc` frame has no URL and inherits the embedder's origin. |
| `INHERIT-02` | parent DOM contents, read from a `blob:` document | A `blob:` URL document executes in the origin that minted it. |
| `MSG-01` | victim-origin secret delivered to a foreign listener | `postMessage` with `targetOrigin: '*'` and no receiver-side origin check. |

`SANDBOX-01` deserves emphasis: any site serving attacker-influenced content
(uploads, previews, user templates) from its own origin under those two sandbox
tokens has handed that content **full origin authority**, including the ability to
remove its own confinement. No engine treats this as a bug, which is exactly why it
keeps shipping.

### 3c. Deployment misconfiguration

`ORACLE-02` — a wildcard `Access-Control-Allow-Origin` let an unauthorised origin
read canary material. The most common real-world SOP giveaway, and a server
mistake rather than an engine one.

### 3d. Authorised access, recorded for completeness

`CANVAS-03` — a CORS-approved cross-origin image is legitimately pixel-readable.
Recorded as `BYPASS` because the canary genuinely crosses the boundary, but the
grant is explicit and correct. Its real job is to be the **positive control** for
the canvas lane: it proves the pixel-readback path works, which is what makes
`CANVAS-01`'s `BLOCKED` meaningful rather than a broken decoder.

---

## 4. Negative controls that held

A suite that only reports bypasses is not measuring anything. 17 probes confirmed
the boundary holding, and several are load-bearing:

| Probe | Result |
|---|---|
| `HDR-01` | no-CORS cross-origin JSON read rejected — the suite's baseline sanity check |
| `HDR-02` | `no-cors` response is opaque; request dispatched, body unreadable |
| `HDR-03` | **CVE-2025-4664 referrer leak did not reproduce** — correct for a build past 136.0.7103.113 |
| `SANDBOX-02` | same two sandbox tokens on genuinely cross-origin content stays confined — proves `SANDBOX-01` is about origin inheritance, not sandbox parsing |
| `INHERIT-03` | **blob URL store is partitioned** — possessing a foreign origin's blob URL is insufficient; `fetch` rejected, frame read empty. Confirms the Chrome 137 Storage-Key work |
| `INHERIT-04` | `javascript:` URI did not execute in a cross-origin frame |
| `SCRIPT-02` | cross-origin script error correctly muted to `"Script error."` |
| `OPENER-01` | cross-origin `Window` exposed **only** `length` and `closed`; `origin`, `name`, `history.length`, `location.href`, `document.*` all blocked — nothing outside the spec allowlist |
| `STORE-01` | `localStorage` keyed on the full origin tuple — port is part of the key |
| `STORE-02` | `http` and `https` views of one host remain distinct origins |
| `CANVAS-01` | non-CORS cross-origin `drawImage` taints the canvas; both `getImageData` and `toDataURL` threw `SecurityError` |
| `CANVAS-02` | see below |

`CANVAS-02` on Chromium is a `BLOCKED` that must be read via its `gates=` list, not
its verdict:

```
transfer-bitmap:refused(DataCloneError) | copy-bitmap:refused(DataCloneError)
| worker-fetch:accepted → workerFetchErr:InvalidStateError
```

Chromium 141 refuses to hand a non-origin-clean `ImageBitmap` to a worker at all,
by transfer *or* by copy, and an opaque `no-cors` response will not decode into an
`ImageBitmap`. So Chromium is defended at **three gates sitting in front of** the
CVE-2025-9180 taint-propagation mechanism. This says nothing about whether taint
propagation itself is correct — that question is only answerable on Gecko.

---

## 5. Side channels: state inferable, no bytes crossing

Reported as `INCONCLUSIVE` deliberately. None leaks the canary, all leak state, and
none can be closed without breaking the web. Calling them bypasses would be
inflation; omitting them would be incomplete.

- `SIDE-01` — cross-origin HTTP status oracle: `200 → load`, `404 → error`. Enough
  to enumerate object IDs or probe authorisation state without reading a byte.
- `SIDE-02` — Resource Timing entry exists for a cross-origin fetch with
  `duration=256ms`; fine-grained timings correctly coarsened (`responseStart=0`).
  Existence and duration leak regardless.
- `SIDE-03` — redirect destination hidden (`opaqueFinalUrl=""`), occurrence
  observable.
- `OPENER-02` — cross-origin `frames.length` readable. Subframe count usually
  differs between logged-in and logged-out renderings, making this a login-state
  oracle that needs no bug at all.

---

## 6. Corrections to the V2 suite's claims

Every CVE ID in the V2 README **does** resolve to a real record — my initial
suspicion of fabrication was wrong and is worth stating plainly. Several
*attributions*, however, do not survive checking:

| V2 claim | Record says |
|---|---|
| CVE-2022-4908 = "Navigation API `entries()` Cross-Origin Leak" | **iFrame Sandbox** component, cross-origin data leak, prior to 107.0.5304.62. Nothing to do with the Navigation API. |
| CVE-2025-58485 = Opera / Samsung Android intent UXSS | **Samsung Internet** only, prior to 29.0.0.48. Not Opera. |
| CVE-2025-12435 = "Chromium-based" omnibox spoofing | Scoped to **Chrome on Android**. |
| CVE-2025-4664 "CISA KEV" | Added to KEV 2025-05-15, then **removed by CISA in early June 2025** for insufficient evidence of exploitation. It is **not currently in KEV**, though press coverage still says otherwise. |
| CVE-2025-4664 severity | Chrome rates it **High**; NVD scores it **4.3 Medium**. Both are true of different scales. |

One further trap, for anyone extending this: searching Mozilla advisories for
"same-origin policy bypass" silently misses all of 2023–2024, because Mozilla only
standardised that title format in mid-2025. Sweep `cross-origin` separately.
Mozilla never uses the word "UXSS" in advisory titles at all.

---

## 7. On the blog post this project was modelled after

The brief cited Hacktron's post on an AI-written Chrome exploit. Read it before
drawing conclusions from this suite, because **it is not a Same-Origin Policy
post**.

The actual title is *"Watching GPT-5.6 Sol Ultra Write a Chrome Exploit: Exploit
Development as We Know It Is Dead"* (the URL slug still says `gpt-55` / `is-over`
from an earlier draft, which is why the cited title looks close but reads wrong).
Author s1r1us, mid-July 2026.

The work was **V8 memory corruption**, not an SOP or UXSS bug: target Chrome
149.0.7827.201 / V8 14.9.207.35, **no CVE**, started from public V8 security-fix
*commits* with exploitability reconstructed from the patches. The chain ran Maglev
type confusion → addrof/fakeobj → 4GB cage R/W → DataView metadata corruption →
`String::VisitFlat` address leak → `NativeModule` UAF in the Wasm background
compiler → Code Pointer Table pivot → `posix_spawnp`. Success oracle: pop calc.

So the **bug class transfers to this project not at all.** What transfers is the
harness design, and that part is genuinely good — it is adopted in
`.claude/agents/sop-bypass-ladder.md`:

- a staged ladder where each rung is independently verifiable (reachability →
  boundary contact → observable difference → read primitive → generalisation),
- a fast local execution oracle (their sandboxed `d8`; here, a probe run in seconds),
- fan-out to subagents for investigation while one agent holds the strategy,
- strategy held in the ladder and in written reports rather than in a context
  window — theirs survived 33 compactions losing >92% of context each time.

Reported scale: 74 subagents, 2.1B tokens, 14,062 requests, ≈$1,597.

**Sourcing caveat:** `hacktron.ai` is egress-blocked in this container, as were all
mirrors and coverage domains including `web.archive.org`. The above is corroborated
across several search-index summaries of that coverage but **was not read
first-hand**. Treat §7 as second-hand and verify before quoting it.

---

## 8. What this suite does not establish

- **No engine defect was found in Chromium 141.** Every bypass is either a
  by-design hole in the origin model, a deployment misconfiguration, an authorised
  read, or — for `RELAX-02` — a documented, mutually-negotiated legacy feature. A
  genuine SOP bypass in current Chromium is a high-value security bug and is not
  going to fall out of a JavaScript test page. Any suite claiming otherwise from
  this kind of evidence is overselling.
- **The 10 CVEs Chromium 141 is behind on were not reproduced**, only matched by
  version. No probe exercises any of them yet; CVE-2026-17779 is the best entry
  point. Version-affected is a hypothesis, not a demonstration, and the two must
  never be conflated.
- **No Firefox or WebKit result is observed.** Every non-Chromium `expect` value is
  documentation.
- **`clientSideOnly` in the corpus is this project's inference**, not a citation.
  CVE text essentially never states reproduction requirements.
- **Mobile and browser-chrome issues are out of reach** of headless automation:
  address-bar spoofing, toolbar spoofing, fullscreen chrome spoofing and
  Android-intent handling all need a real device with visible UI.
- **One open question could overturn §3a's cross-engine framing.** The shipped
  defaults of Firefox's `dom.origin_agent_cluster.enabled` and
  `dom.origin_agent_cluster.default` prefs could not be read
  (`StaticPrefList.yaml` exceeds GitHub code-search's index limit). Check
  `about:config` on a real Firefox before relying on the claim that relaxation is
  unconditionally live there.
