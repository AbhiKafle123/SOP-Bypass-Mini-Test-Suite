# Firefox / Gecko SOP-Bypass, UXSS, Cross-Origin-Leak and Address-Bar-Spoof Dossier

Compiled 2026-09-30. Accuracy-first: every factual claim carries a source URL. Anything I could not
confirm against a primary or near-primary source is explicitly marked **UNVERIFIED**.

---

## 0. Sourcing methodology and egress constraints (read this first)

`www.mozilla.org` and `bugzilla.mozilla.org` — the two sources named as primary in the task brief —
are **both blocked by this container's egress proxy**, as are `nvd.nist.gov`, `cve.org`,
`osv.dev`, `bugzilla.redhat.com`, `security-tracker.debian.org`, `developer.mozilla.org`,
`searchfox.org`, `phabricator.services.mozilla.com`, `archive.mozilla.org`, `ftp.mozilla.org`,
`support.mozilla.org`, `developer.chrome.com`, `chromium.googlesource.com` and `web.archive.org`.

I therefore used these substitutes, in descending order of authority:

| Source | Why it is authoritative | Reachable |
|---|---|---|
| `raw.githubusercontent.com/mozilla/foundation-security-advisories` | **Mozilla's own advisory repository.** The `announce/YYYY/mfsaYYYY-NN.yml` files are the machine-readable originals from which the `www.mozilla.org/security/advisories/` HTML pages are generated. This is a primary source, not a mirror. | yes |
| `raw.githubusercontent.com` + GitHub code search over `mozilla-firefox/firefox` | Mozilla's official Gecko git repository. Gives patch diffs and current source. | yes |
| `ubuntu.com/security/CVE-...` | Reproduces the Mozilla-as-CNA CVE description verbatim. | yes |
| `raw.githubusercontent.com/mdn/content`, `mdn/browser-compat-data` | MDN's source of truth (MDN itself blocked). | yes |
| `raw.githubusercontent.com/mozilla/mozdownload` | Mozilla-owned tool whose tests encode the archive.mozilla.org path layout. | yes |

Repo roots for citation:
- https://github.com/mozilla/foundation-security-advisories
- https://github.com/mozilla-firefox/firefox
- https://github.com/mozilla/mozdownload

**Consequence to be aware of:** every MFSA ID, CVE title, impact rating, reporter, bug number and
`fixed_in` string below was read out of Mozilla's own YAML. Where I state a `fixed_in` version I
fetched that specific YAML file; where I only know an MFSA *contains* a CVE (from repository code
search) but did not fetch its `fixed_in`, I say so.

---

## 1. PRIORITY: CVE-2025-9180 — Same-origin policy bypass in Graphics: Canvas2D

### 1.1 Identity and ratings

| Field | Value | Source |
|---|---|---|
| CVE | **CVE-2025-9180** | below |
| Mozilla title | `Same-origin policy bypass in the Graphics: Canvas2D component` | https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-64.yml |
| Mozilla impact rating | **high** | same |
| Reporter | **Tom Van Goethem** | same |
| Bugzilla | **1979782** | same |
| Announced | **2025-08-19** | same |
| CVSS | 8.1 / HIGH (CVSS 3.x) — *assigned by NVD, not by Mozilla*; Ubuntu records its own priority as **Medium** | https://ubuntu.com/security/CVE-2025-9180 |

The user's recollection ("Firefox 142 and corresponding ESR 115.x / 128.x / 140.x") is **correct in
full**. Every number verified independently below.

### 1.2 Advisory IDs and EXACT fixed versions — all verified

Seven MFSAs carry this CVE, all announced **2025-08-19**. I fetched each YAML and read its
`fixed_in` field:

| MFSA | Advisory title | `fixed_in` (exact string) | Source |
|---|---|---|---|
| **MFSA 2025-64** | Security Vulnerabilities fixed in Firefox 142 | **Firefox 142** | [mfsa2025-64.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-64.yml) |
| **MFSA 2025-65** | Security Vulnerabilities fixed in Firefox ESR 115.27 | **Firefox ESR 115.27** | [mfsa2025-65.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-65.yml) |
| **MFSA 2025-66** | Security Vulnerabilities fixed in Firefox ESR 128.14 | **Firefox ESR 128.14** | [mfsa2025-66.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-66.yml) |
| **MFSA 2025-67** | Security Vulnerabilities fixed in Firefox ESR 140.2 | **Firefox ESR 140.2** | [mfsa2025-67.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-67.yml) |
| **MFSA 2025-70** | Security Vulnerabilities fixed in Thunderbird 142 | **Thunderbird 142** | [mfsa2025-70.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-70.yml) |
| **MFSA 2025-71** | Security Vulnerabilities fixed in Thunderbird 128.14 | **Thunderbird 128.14** | [mfsa2025-71.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-71.yml) |
| **MFSA 2025-72** | Security Vulnerabilities fixed in Thunderbird 140.2 | **Thunderbird 140.2** | [mfsa2025-72.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-72.yml) |

Mozilla's own CVE description, verbatim (Mozilla is the CNA):

> "Same-origin policy bypass in the Graphics: Canvas2D component. This vulnerability was fixed in
> Firefox 142, Firefox ESR 115.27, Firefox ESR 128.14, Firefox ESR 140.2, Thunderbird 142,
> Thunderbird 128.14, and Thunderbird 140.2."
> — https://ubuntu.com/security/CVE-2025-9180

**Therefore the newest still-vulnerable builds are: Firefox 141.x, Firefox ESR 115.26, Firefox ESR
128.13, Firefox ESR 140.1, Thunderbird 141.x / 128.13 / 140.1.** (Derived by decrementing the fixed
version; the existence of those exact archive directories is **UNVERIFIED** because
`archive.mozilla.org` is blocked — see §6.)

Note: ESR 115 was *still receiving security updates* in Aug 2025 (115.27), and as of Aug 2026 it
reached **115.39** (§2.4). ESR 115 is the realistic "old but still-supported-looking" line.

### 1.3 The patch — and therefore the precise mechanism

Mozilla's Gecko repo is reachable, so the fix itself is readable. Bug 1979782 landed as:

- **Fix commit: `44541e940dd8ab537118a39f77b1f4e9d23ce59e`** — "Bug 1979782.
  r=gfx-reviewers,bradwerth,ahale", author **Andrew Osmond**, 2025-08-09, Phabricator **D260529**
  https://github.com/mozilla-firefox/firefox/commit/44541e940dd8ab537118a39f77b1f4e9d23ce59e
- An earlier landing `1ea94eb72fb0f8549ea20146387faa5060fb91ce` was **backed out** by
  `a163c2225f56d72fc1536b1e0011bafbce6e2248` ("for causing build bustages at RefPtr.h") and then
  relanded. (Same repo; found via GitHub commit search for `1979782`.)

Files touched (7), from https://github.com/mozilla-firefox/firefox/commit/44541e940dd8ab537118a39f77b1f4e9d23ce59e.diff :

| File | Δ |
|---|---|
| `dom/canvas/CanvasRenderingContextHelper.cpp` | −55 |
| `dom/canvas/CanvasRenderingContextHelper.h` | −4 |
| `dom/canvas/OffscreenCanvas.cpp` | +4 |
| `dom/canvas/OffscreenCanvasDisplayHelper.cpp` | +32 |
| `dom/canvas/OffscreenCanvasDisplayHelper.h` | +15 |
| `dom/html/HTMLCanvasElement.cpp` | +59 |
| `dom/html/HTMLCanvasElement.h` | +2 |

**No test file (mochitest / reftest / crashtest / .html) was added or modified in the fix** — noted
because it means there is no Mozilla-authored reproducer in-tree to lift.

Key hunks, verbatim from the diff:

```c++
+void OffscreenCanvasDisplayHelper::SetWriteOnly(nsIPrincipal* aExpandedReader) {
+  MutexAutoLock lock(mMutex);
+  NS_ReleaseOnMainThread("OffscreenCanvasDisplayHelper::mExpandedReader",
+                         mExpandedReader.forget());
+  mExpandedReader = aExpandedReader;
+  mIsWriteOnly = true;
+}
```

```c++
+bool OffscreenCanvasDisplayHelper::CallerCanRead(
+    nsIPrincipal& aPrincipal) const {
+  MutexAutoLock lock(mMutex);
+  if (!mIsWriteOnly) {
+    return true;
+  }
+  if (mExpandedReader && aPrincipal.Subsumes(mExpandedReader)) {
+    return true;
+  }
+  return nsContentUtils::PrincipalHasPermission(aPrincipal,
+                                                nsGkAtoms::all_urlsPermission);
+}
```

```c++
+  bool mIsWriteOnly MOZ_GUARDED_BY(mMutex) = false;
+  RefPtr<nsIPrincipal> mExpandedReader MOZ_GUARDED_BY(mMutex);
```

```c++
+  bool recheckCanRead = mOffscreenDisplay && mOffscreenDisplay->HasWorkerRef();
+
+  if (!CallerCanRead(aSubjectPrincipal)) {
+    aRv.Throw(NS_ERROR_DOM_SECURITY_ERR);
+    return;
+  }
+
+  nsString dataURL;
+  nsresult rv = ToDataURLImpl(aCx, aSubjectPrincipal, aType, aParams, dataURL);
+  if (recheckCanRead && !CallerCanRead(aSubjectPrincipal)) {
+    aRv.Throw(NS_ERROR_DOM_SECURITY_ERR);
+    return;
+  }
```

### 1.4 What exactly crosses the origin boundary

Gecko enforces canvas origin-taint with a per-canvas **"write-only"** flag. Confirmed taint plumbing
in current source (GitHub code search over `mozilla-firefox/firefox`, `path:dom/canvas`):

- `dom/canvas/CanvasUtils.cpp` — the draw-time security check sets the flag:
  `if (forceWriteOnly) { aCanvasElement->SetWriteOnly(); return; }`
- `dom/canvas/CanvasRenderingContext2D.cpp` — propagates it:
  `void CanvasRenderingContext2D::SetWriteOnly() { mWriteOnly = true; if (mCanvasElement) { mCanvasElement->SetWriteOnly(); ...`
- `dom/canvas/OffscreenCanvas.h` / `.cpp` — `OffscreenCanvas::SetWriteOnly(RefPtr<nsIPrincipal>&&)`
- `dom/canvas/ImageBitmapRenderingContext.cpp` — parallel path for `ImageBitmap`:
  `if (mCanvasElement) { mCanvasElement->SetWriteOnly(); } else if (mOffscreenCanvas) { mOffscreenCanvas->SetWriteOnly(); }`

**The bug:** when a `<canvas>` has had its rendering handed to a worker via
`transferControlToOffscreen()`, the main-thread placeholder element reads back through
`OffscreenCanvasDisplayHelper`. Before the fix, `OffscreenCanvas::SetWriteOnly()` did **not**
propagate the taint into that display helper — the helper had no `mIsWriteOnly` member at all (the
patch *adds* it). So tainting the OffscreenCanvas on the worker side left the main-thread readback
path ungated, and `HTMLCanvasElement::ToDataURL()` / `ToBlob()` returned the pixels.

**What leaks: raw pixel data of the cross-origin image**, exfiltrated as a `data:` URL string or a
`Blob`. This is a full read primitive, not a timing/side-channel oracle — the attacker recovers the
actual rendered bytes. That makes it usable to read, e.g., a victim's cross-origin avatar, a
rendered cross-origin document/PDF page, or any image whose content is authenticated by cookies.

The patch also closes a **second, TOCTOU-flavoured hole**: `ToBlob()`/`ToDataURL()` encode
asynchronously, so the fix re-checks permission *after* encoding completes
(`recheckCanRead = mOffscreenDisplay && mOffscreenDisplay->HasWorkerRef()`) — i.e. a canvas that
became tainted *during* the async encode previously still yielded data. Two distinct primitives under
one CVE.

The removal of the public `ToBlob` overload from `CanvasRenderingContextHelper` (−55 lines) and the
move of the `EncodeCallback` class into `HTMLCanvasElement.cpp` are the refactor needed so the final
permission verification happens in one place before the blob is handed back.

### 1.5 Reproducibility — what a POC actually needs

**Pure client-side HTML/JS: yes, with one server-side prerequisite.** Required ingredients, inferred
from the patch (labelled as inference, since bug 1979782 is not publicly readable):

1. A **cross-origin image served WITHOUT permissive CORS** — i.e. no `Access-Control-Allow-Origin`
   allowing the attacker, and loaded *without* `crossOrigin="anonymous"`. This is what makes
   `CanvasUtils.cpp` set the write-only flag. So you need a second origin, but you do **not** need
   to control its headers — you need it to *lack* CORS headers, which is the default.
2. A `<canvas>` on which you call **`transferControlToOffscreen()`** — this is what creates the
   `OffscreenCanvasDisplayHelper` and the `HasWorkerRef()` condition the patch keys on.
3. A **Web Worker** that receives the `OffscreenCanvas` and performs the tainting
   `drawImage()` of the cross-origin resource.
4. Main thread then calls **`canvas.toDataURL()`** or **`canvas.toBlob()`** on the placeholder
   element and reads the pixels.

**Does it need a specific graphics backend / GPU / driver?** **No indication that it does.** Every
file the fix touches is platform-independent DOM/canvas plumbing under `dom/canvas` and
`dom/html` — there is no change to any GPU backend, WebRender, D3D/GL/Metal path, or driver-specific
code. The gate that was missing is a principal check, not a rendering behaviour. (Reviewers were
`gfx-reviewers`, which is simply the module owner for `dom/canvas`.) **Inference from the patch
contents — not stated by Mozilla.**

**Does it need a real mobile device?** No — it is a Gecko engine bug, so desktop Firefox reproduces
it. It also affects Thunderbird (same Gecko), which is why MFSA 2025-70/71/72 exist.

### 1.6 Is there a working public POC?

**No public POC or write-up found.** Specifically:

- Bug **1979782** is not publicly readable. `bugzilla.mozilla.org` is egress-blocked here, but a
  targeted web search for the bug number returned **only Mozilla advisory pages and CVE aggregators
  — never a Bugzilla page title**. For contrast, the same style of search *did* surface Bugzilla
  titles for other bugs (e.g. `1986185 - (CVE-2025-10528) Sandbox escape using canvas2d dropbuffer
  without proper size validation`, `1951533 - (CVE-2025-3859) ...`). The absence of a retrievable
  title for 1979782 is consistent with the bug still being **security-restricted**, though I
  cannot prove that without reaching Bugzilla. **Status: UNVERIFIED but strongly suggested.**
- No PoC repository, exploit-DB entry, or researcher write-up surfaced for CVE-2025-9180. Tom Van
  Goethem works on cross-origin leaks (XS-Leaks), but I found **no published article** tied to this CVE.
- Mozilla's own fix shipped **without an in-tree test**, so there is no reproducer to lift from the
  patch either.

**Practical conclusion for the test suite: you will have to write the POC yourself**, from the
four-ingredient recipe in §1.5, and validate it differentially against Firefox 141 vs 142.

---

## 2. Other Gecko same-origin-policy bypasses, 2023–2026

From **56** matches for the literal phrase `Same-origin policy bypass` in Mozilla's advisory repo
(GitHub code search, `repo:mozilla/foundation-security-advisories`), deduplicated to distinct CVEs.

**Naming-convention caveat that matters for searching:** Mozilla only adopted the standardised
`Same-origin policy bypass in the <Component> component` title format around **mid-2025**. Before
that, the same bug class was titled descriptively ("Cross-Origin Image leak via Offscreen Canvas",
"Offscreen Canvas could have bypassed cross-origin restrictions"). **Searching only for
"same-origin policy bypass" silently misses all of 2023–2024.** I ran separate `cross-origin`
sweeps over `announce/2023` and `announce/2024` to cover that gap.

### 2.1 The Offscreen-Canvas taint trilogy — directly relevant to CVE-2025-9180

Gecko has now shipped **three** fixes for "OffscreenCanvas fails to track cross-origin taint". For a
regression test suite this is the single most valuable cluster: same subsystem, same leak, three
different version boundaries.

| CVE | Mozilla title | Impact | Reporter | Bug | Fixed in | Announced |
|---|---|---|---|---|---|---|
| **CVE-2023-4045** | `Offscreen Canvas could have bypassed cross-origin restrictions` | **high** | Max Vlasov | **1833876** | **Firefox 116** (MFSA 2023-29) | 2023-08-01 |
| **CVE-2024-5693** | `Cross-Origin Image leak via Offscreen Canvas` | **moderate** | Kirtikumar Anandrao Ramchandani | **1891319** | **Firefox 127** (MFSA 2024-25) | 2024-06-11 |
| **CVE-2025-9180** | `Same-origin policy bypass in the Graphics: Canvas2D component` | **high** | Tom Van Goethem | **1979782** | **Firefox 142** + ESR 115.27 / 128.14 / 140.2 (MFSA 2025-64/65/66/67) | 2025-08-19 |

Sources: [mfsa2023-29.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2023/mfsa2023-29.yml) ·
[mfsa2024-25.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2024/mfsa2024-25.yml) ·
mfsa2025-64..67 (§1.2)

Mozilla's descriptions for the first two are near-identical, confirming they are the same bug class:

> CVE-2023-4045: "Offscreen Canvas did not properly track cross-origin tainting, which could have
> been used to access image data from another site in violation of same-origin policy."
> CVE-2024-5693: "Offscreen Canvas did not properly track cross-origin tainting, which could be
> used to access image data from another site in violation of same-origin policy."

Both are reproducible from **pure client-side HTML/JS** plus a cross-origin image lacking CORS
headers — same prerequisites as §1.5.

Additional MFSAs containing these CVEs (confirmed by code search; their individual `fixed_in`
strings **not fetched — UNVERIFIED**): CVE-2023-4045 also in MFSA 2023-30, 2023-31, 2023-32,
2023-33; CVE-2024-5693 also in MFSA 2024-26, 2024-28.

### 2.2 2025 SOP bypasses (standardised titles)

| CVE | Component | Impact | Reporter | Bug | Fixed in (verified) | Other MFSAs (fixed_in unverified) |
|---|---|---|---|---|---|---|
| **CVE-2025-10529** | Layout | moderate | Daniel Holbert | **1970490** | **Firefox 143** — MFSA 2025-73, announced 2025-09-16 | 2025-75, 2025-77, 2025-78 |
| **CVE-2025-13017** | DOM: Notifications | moderate | Mochammad Nosa Shandy Prastyo | **1980904** | **Firefox 145** — MFSA 2025-87, announced 2025-11-11 | 2025-88, 2025-90, 2025-91 |
| **CVE-2025-13019** | DOM: Workers | moderate | Oskar L | **1988412** | **Firefox 145** — MFSA 2025-87 | 2025-88, 2025-90, 2025-91 |
| **CVE-2025-14331** | Request Handling | moderate | Igor Morgenstern | **2000218** | **Firefox 146** — MFSA 2025-92, announced 2025-12-09 | 2025-93, 2025-94, 2025-95, 2025-96 |

Sources: [mfsa2025-73.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-73.yml) ·
[mfsa2025-87.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-87.yml) ·
[mfsa2025-92.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-92.yml)

Mozilla published **no `description` field** for any of these four — only the title. So the precise
mechanism of each is **UNVERIFIED** from advisories alone; the bug numbers are the route in.

### 2.3 2026 SOP bypasses

| CVE | Component | Impact | Reporter | Bug | Fixed in (verified) | Other MFSAs (unverified fixed_in) |
|---|---|---|---|---|---|---|
| **CVE-2026-2790** | Networking: JAR | low | Surya Dev Singh | **2008426** | **Firefox 148** — MFSA 2026-13, 2026-02-24 | 2026-15, 2026-16, 2026-17 |
| **CVE-2026-3846** | CSS Parsing and Computation | **high** | Jun Yang | **2018400** | **Firefox 148.0.2** — MFSA 2026-19, 2026-03-10 | — |
| **CVE-2026-8948** | DOM: Networking | **high** | satyamasd | **2038803** | **Firefox 151** — MFSA 2026-46, 2026-05-19 | 2026-50 |
| **CVE-2026-8950** | Networking: HTTP | moderate | Jakub Szymsza | **1965430** | **Firefox 151** — MFSA 2026-46 | 2026-48, 2026-50, 2026-51 |
| **CVE-2026-12304** | Networking: Cookies | moderate | Yaqoub Aldurayhim | **2034944** | **Firefox 152** — MFSA 2026-57, 2026-06-16 | 2026-58, 2026-60, 2026-61 |
| **CVE-2026-16349** | DOM: Navigation | **high** | Tran Quac | **2034682** | **Firefox 153** — MFSA 2026-68, 2026-07-21 | 2026-69, 2026-70, 2026-71, 2026-72 |
| **CVE-2026-16381** | Networking: DNS | moderate | Rintaro Kawasugi | **2041001** | **Firefox 153** — MFSA 2026-68 | 2026-70, 2026-71, 2026-72 |
| **CVE-2026-74956** | DOM: Service Workers | moderate | pakhunov.anton.n | **2032406** | **Firefox 154** — MFSA 2026-74, 2026-08-18 | 2026-77, 2026-78, 2026-80 |
| **CVE-2026-74963** | Networking: Cookies | moderate | 5up3rh3i | **2050482** | **Firefox 154** — MFSA 2026-74 | 2026-76, 2026-77, 2026-78, 2026-79, 2026-80 |
| **CVE-2026-74967** | Audio/Video: Playback | moderate | The Mozilla Fuzzing Team | **2055697** | **Firefox 154** (MFSA 2026-74); **Firefox ESR 140.14** (MFSA 2026-76) | 2026-79 |
| **CVE-2026-74974** | Graphics: ImageLib | moderate | The Mozilla Fuzzing Team | **2061794** | **Firefox 154** (MFSA 2026-74); **Firefox ESR 115.39** (MFSA 2026-75) | — |
| **CVE-2026-100803** | WebExtensions | moderate | Yaqoub Aldurayhim | **2057988** | **Firefox 157** — MFSA 2026-97, 2026-09-29 | 2026-98, 2026-99, 2026-100 |
| **CVE-2026-100809** | DevTools | moderate | Finn Westendorf | **2063658** | **Firefox 157** — MFSA 2026-97 | 2026-100 |

Sources: [mfsa2026-13](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-13.yml) ·
[mfsa2026-19](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-19.yml) ·
[mfsa2026-46](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-46.yml) ·
[mfsa2026-57](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-57.yml) ·
[mfsa2026-68](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-68.yml) ·
[mfsa2026-74](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-74.yml) ·
[mfsa2026-75](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-75.yml) ·
[mfsa2026-76](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-76.yml) ·
[mfsa2026-97](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-97.yml)

Note `CVE-2026-74974` (Graphics: ImageLib) is the closest 2026 relative of the Canvas2D/ImageLib
pixel-leak family and is worth adding to the suite alongside CVE-2025-9180.

MFSA 2026-69 additionally carries a *separate* CVE whose description reads "We are aware that
exploit code for this is public however we are not aware of any attacks in the wild abusing this
flaw." That note attaches to the CVE **preceding** CVE-2026-16349 in the file — I did not fetch
mfsa2026-69 itself, so **which CVE that note belongs to is UNVERIFIED**.

### 2.4 ESR lines in force (needed to judge "unpatched ESR you can still install")

Verified from the August 2026 advisory batch — Mozilla was maintaining **three** ESR lines
simultaneously:

| Advisory | `fixed_in` | Source |
|---|---|---|
| MFSA 2026-75 | **Firefox ESR 115.39** | [mfsa2026-75.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-75.yml) |
| MFSA 2026-76 | **Firefox ESR 140.14** | [mfsa2026-76.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-76.yml) |
| MFSA 2026-77 | **Firefox ESR 153.1** | [mfsa2026-77.yml](https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2026/mfsa2026-77.yml) |

So the ESR 115 line — the one still shipped for legacy Windows/macOS — ran from 115.27 (Aug 2025,
the CVE-2025-9180 fix) to 115.39 (Aug 2026). **ESR 115.26 and earlier are the realistic
"installable and vulnerable to CVE-2025-9180" targets.**

### 2.5 Cross-origin *leak* CVEs 2023–2024 (pre-standardised titles)

| CVE | Mozilla title | Impact | Reporter | MFSAs | Mechanism note |
|---|---|---|---|---|---|
| **CVE-2023-5722** | `Cross-Origin size and header leakage` | moderate | annevk | MFSA 2023-45 | `fixed_in` **UNVERIFIED** |
| **CVE-2024-4769** | `Cross-origin responses could be distinguished between script and non-script content-types` | moderate | — | MFSA 2024-21/22/23 | Worker `importScripts` error messages distinguished `application/javascript` from non-script responses — a classic XS-Leak oracle. **Needs server-side control of Content-Type to demo cleanly.** |
| **CVE-2024-9393** | `Cross-origin access to PDF contents through multipart responses` | **high** | — | MFSA 2024-46/47/48/49/50 | **Requires a server emitting `multipart/x-mixed-replace`** — not pure client-side. |
| **CVE-2023-23601** | `URL being dragged from cross-origin iframe into same tab triggers navigation` | moderate | — | MFSA 2023-01/02/03 | **Requires a real drag gesture** — not scriptable. |
| **CVE-2023-28164** | `URL being dragged from a removed cross-origin iframe into the same tab triggered navigation` | moderate | — | MFSA 2023-09/10/11 | Same: real drag gesture. |

Two entries I found but could **not** pin a CVE ID to (the code-search fragment showed only the
description, and I did not fetch the file):

- MFSA 2024-29/30/31/32: "A race condition could lead to a cross-origin container obtaining
  permissions of the top-level origin." Reporter **Andreas Farre**, bug **1890748**. The CVE ID
  immediately *precedes* CVE-2024-6602 in the file — **exact ID UNVERIFIED, do not cite.**
- MFSA 2023-05: cross-origin drag-and-drop image **size** leak, reporter Dohyun Lee (@l33d0hyun),
  bugs **1813376** and **1437126**; behaviour shipped in Firefox 109 then disabled.
  **CVE ID UNVERIFIED.**

All CVE titles/impacts/reporters/bugs in this subsection come from GitHub code search over
https://github.com/mozilla/foundation-security-advisories (`path:announce/2023` and
`path:announce/2024`, query `cross-origin`).

### 2.6 A note on "UXSS"

**Mozilla does not use the term "UXSS" in any advisory title I found.** Searching for it will return
nothing. The Gecko equivalents are titled `Same-origin policy bypass in ...`, and
privilege-escalation-into-chrome bugs are titled `Privilege escalation in ...` (e.g.
**CVE-2026-100820** `Privilege escalation in the Address Bar component`, moderate, Tran Quac, bug
**2071069**, MFSA 2026-97 → Firefox 157). Adjust your search vocabulary accordingly.

---

## 3. Address-bar / URL-spoofing CVEs 2023–2026

### 3.1 CVE-2025-23109 — **CONFIRMED, your ID is correct**

You were unsure about this ID. It is **right**, and it is exactly what you described.

| Field | Value |
|---|---|
| CVE | **CVE-2025-23109** |
| Mozilla title | `Address bar spoofing on iOS using long hostnames` |
| Description | "Long hostnames in URLs could be leveraged to obscure the actual host of the website or spoof the website address" |
| Impact | **moderate** |
| Reporter | **Khalil Zhani** |
| Bugzilla | **1419275** |
| Advisory | **MFSA 2025-06** — "Security Vulnerabilities fixed in Firefox for iOS 134" |
| `fixed_in` | **Firefox for iOS 134** |
| Announced | **2025-01-10** |

Source: https://raw.githubusercontent.com/mozilla/foundation-security-advisories/master/announce/2025/mfsa2025-06.yml

One correction to watch for: web search results conflate CVE-2025-23109 with **CVE-2025-3859**
(`Firefox Focus elide URL allows address bar spoofing`, moderate, James Lee, **Focus for iOS 138**,
MFSA 2025-33, Bugzilla 1951533). These are **different CVEs in different products**
(Firefox for iOS vs Focus for iOS). Don't merge them.

The same advisory (MFSA 2025-06, Firefox for iOS 134) also contains:

- **CVE-2025-23108** — `Firefox Mobile iOS Full Address Bar Spoof Using Open in New Tab and
  Javascript URI`, **moderate**, reporter **Renwa**, bug **1933172**. Description: "Opening
  Javascript links in a new tab via long-press in the Firefox iOS client could result in a
  malicious script spoofing the URL".

### 3.2 Firefox for iOS / Focus for iOS spoofs

`fixed_in` values here are taken from the `fixed_in`/`title` lines inside each YAML as returned by
code search or direct fetch, as noted.

| CVE | Title | Impact | Advisory → fixed_in | Verified by |
|---|---|---|---|---|
| **CVE-2024-26283** | `Address bar spoofing using Firefox custom open URL scheme` | moderate | MFSA 2024-08 → **Firefox for iOS 123** | code search |
| **CVE-2024-38313** | `Location URL bar could be visually spoofed with a fake toolbar` | **high** | MFSA 2024-27 → **Firefox for iOS 127** | code search |
| **CVE-2024-53975** | `SSL security padlock icon could be visually spoofed to look secure on an HTTP page` | moderate | MFSA 2024-66 → **Firefox for iOS 133** | code search |
| **CVE-2025-23108** | see §3.1 | moderate | MFSA 2025-06 → **Firefox for iOS 134** | direct fetch |
| **CVE-2025-23109** | see §3.1 | moderate | MFSA 2025-06 → **Firefox for iOS 134** | direct fetch |
| **CVE-2025-27426** | `Firefox Mobile iOS Full Address Bar Spoof Using Server-Side Redirect to internal error page` | **high** | MFSA 2025-13 → **Firefox for iOS 136** | code search |
| **CVE-2025-5020** | `Links using non-HTTP schemes opened from other apps such as Safari could have allowed spoofing of website addresses` | low | MFSA 2025-39 → **Firefox for iOS 139** | code search |
| **CVE-2025-14744** | `Filename spoofing via Unicode Right-to-Left Override in Firefox for iOS` | low | MFSA 2025-97 → **Firefox for iOS 144.0** (2025-12-15), bug **1984683**, reporter Azril | direct fetch |
| **CVE-2026-2032** | `Interrupted page loads in new tabs could allow website spoofing under trusted domains in Firefox iOS` | **high** | MFSA 2026-09 → **Firefox for iOS 147.2.1** | code search |
| **CVE-2026-2634** | `Spoofed web content presented under trusted domains using scripted navigation on Firefox iOS` | **high** | MFSA 2026-12 → **Firefox for iOS 147.4** (2026-02-20), bug **1975529**, reporter Renwa | direct fetch |
| **CVE-2026-13356** | `Interrupted navigation could allow address bar origin spoofing in Firefox for iOS` | moderate | MFSA 2026-65 → **Firefox for iOS 152.3**, reporter Azza Tegar Naufal Ataullah | code search |
| **CVE-2026-81267** | `Stalled popup navigation could allow address bar origin spoofing in Firefox for iOS` | moderate | MFSA 2026-81 → **Firefox for iOS 155.0**, reporter Azza Tegar Naufal Ataullah | code search |
| **CVE-2024-5022** | `URLs with file scheme could have been used to spoof addresses in the location bar` | **high** | MFSA 2024-24 → **Focus for iOS 126** | code search |
| **CVE-2024-8399** | `iOS Firefox Focus javascript URI address bar spoofing` | **high** | MFSA 2024-42 → **Focus for iOS 130**, reporter James Lee | code search |
| **CVE-2025-3859** | `Firefox Focus elide URL allows address bar spoofing` | moderate | MFSA 2025-33 → **Focus for iOS 138**, reporter James Lee | code search |

CVE-2026-2634's description is a good statement of the recurring iOS pattern: "Malicious code could
trigger a mismatch between the address bar display and actual page content prior to server response
arrival in Firefox iOS. This flaw enables attackers to display their content under falsified domain
names."

**Reproducibility of the whole iOS class — important:** Firefox for iOS and Focus for iOS are built
on **WKWebView**, not Gecko (Apple's App Store rules). These are therefore **browser-UI/chrome bugs,
not SOP engine bugs**, and they are **not reproducible from pure client-side HTML/JS on desktop
Gecko**. They need a real iOS device or simulator running the specific app version, and several need
a genuine user gesture (long-press, context menu, open-in-new-tab, interrupted navigation). Keep
them in a separate, manually-driven section of the suite.

Also noted but **UNVERIFIED**: **CVE-2025-10290**, Bugzilla title `Focus iOS Address Bar Spoof Using
Context Menu and Open Link of a URL that fails to load`, bug **1975566**. I have the Bugzilla title
from a search-result title only; **I did not confirm its MFSA ID or fixed version.**

### 3.3 Desktop / Android spoofs

| CVE | Title | Impact | Reporter | Bug | Fixed in | Source |
|---|---|---|---|---|---|---|
| **CVE-2025-9183** | `Spoofing issue in the Address Bar component` | low | **Renwa** | **1976102** | **Firefox 142** (MFSA 2025-64); also **Firefox ESR 140.2** (MFSA 2025-67) | direct fetch |
| **CVE-2025-9186** | `Spoofing issue in the Address Bar component of Firefox Focus for Android` | low | Kevin Brosnan | **1445758** | **Firefox 142** (MFSA 2025-64) | direct fetch |
| **CVE-2025-10530** | `Spoofing issue in the WebAuthn component in Firefox for Android` | moderate | Hafiizh & Kang Ali | **1974025** | **Firefox 143** (MFSA 2025-73) | direct fetch |
| **CVE-2025-10534** | `Spoofing issue in the Site Permissions component` | low | Emma Zühlcke | **1665334** | **Firefox 143** (MFSA 2025-73) | direct fetch |
| **CVE-2025-13015** | `Spoofing issue in Firefox` | low | — | — | **Firefox 145** (MFSA 2025-87) | direct fetch |
| **CVE-2025-14327** | `Spoofing issue in the Downloads Panel component` | moderate | — | — | **Firefox 146** (MFSA 2025-92) | direct fetch |
| **CVE-2026-2800** | `Spoofing issue in the WebAuthn component in Firefox for Android` | moderate | — | — | **Firefox 148** (MFSA 2026-13) | direct fetch |
| **CVE-2026-8960 / -8961 / -8963 / -8964** | Spoofing in WebExtensions / Form Autofill / Web Speech / Popup Blocker | — | — | — | **Firefox 151** (MFSA 2026-46) | direct fetch |
| **CVE-2026-12323** | `Spoofing issue in the DOM: Core & HTML component` | low | Jody Ritonga | — | **Firefox 152** (MFSA 2026-57) | direct fetch |
| **CVE-2026-16403** | `Spoofing issue in the Address Bar component` | low | — | — | **Firefox 153** (MFSA 2026-68) | direct fetch |
| **CVE-2026-16404** | `Spoofing issue in Firefox for Android` | low | — | — | **Firefox 153** (MFSA 2026-68) | direct fetch |
| **CVE-2026-74975** | `Spoofing issue in the Downloads component in Firefox for Android` | low | — | — | **Firefox 154** (MFSA 2026-74) | direct fetch |
| **CVE-2026-100822** | `Spoofing issue in the Networking: HTTP component` | — | — | — | **Firefox 157** (MFSA 2026-97) | direct fetch |
| **CVE-2026-100823** | `Spoofing issue in the Downloads component in Firefox for Android` | — | — | — | **Firefox 157** (MFSA 2026-97) | direct fetch |
| **CVE-2025-0246** | `Address bar spoofing using an invalid protocol scheme on Firefox for Android` | moderate | — | — | MFSA 2025-01 (advisory titled "…fixed in Firefox 134") | code search — **fixed_in not fetched** |
| **CVE-2025-8039** | `Search terms persisted in URL bar` | low | — | — | MFSA 2025-56 — **fixed_in UNVERIFIED** | code search |

One more entry I found without a confirmable CVE ID: **MFSA 2025-81** contains a moderate-severity
Android issue — "When the address bar was hidden due to scrolling on Android, a malicious page could
create a fake address bar to fool the user in response to a `visibilitychange` event", reporters
**Hafiizh & kang ali**, bug **1980808**. The CVE ID precedes CVE-2025-11713 in that file;
**exact ID UNVERIFIED — do not cite.**

**Reproducibility:** the Android-specific ones (fake address bar on scroll, Focus for Android) need a
real Android device or emulator. `CVE-2025-9183` (desktop address bar, Renwa) is the best candidate
for a desktop harness, but Mozilla published no description, so the mechanism is **UNVERIFIED**.

---

## 4. `document.domain` in Gecko — does Firefox still honour origin relaxation at 140+?

### Short answer

**Yes. As of current Gecko `main` — and with no contrary evidence through Firefox 157 (latest
advisory 2026-09-29) — Firefox still honours `document.domain` origin relaxation by default.**
Firefox has built the machinery to turn it off (origin-keyed agent clusters), ships the opt-in
header, and Mozilla is formally *in favour* of flipping the default — **but I found no primary
source showing the flip has shipped.**

### Evidence that the setter is still live

1. **It is still a writable WebIDL attribute with no pref gate.** From
   https://raw.githubusercontent.com/mozilla-firefox/firefox/main/dom/webidl/Document.webidl :
   ```
   [SetterThrows]                           attribute DOMString domain;
   ```
   Not `readonly`, and **no `[Pref=...]`** — so it is unconditionally exposed. Compare
   `dom/webidl/Window.webidl`, where the related feature *is* gated:
   ```
   // https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters
   partial interface Window {
     [Pref="dom.origin_agent_cluster.enabled"] readonly attribute boolean originAgentCluster;
   };
   ```
2. **The C++ setter still exists.** `dom/base/Document.h` declares
   `void SetDomain(const nsAString& aDomain, mozilla::ErrorResult& rv);` alongside `GetDomain`.
   (GitHub code search, `repo:mozilla-firefox/firefox SetDomain path:dom/base`.)

### Evidence that Gecko ignores it *only* inside origin-keyed agent clusters

Gecko has a dedicated console warning, and its wording is decisive:

- `dom/base/nsDocumentWarningList.inc` registers `DOCUMENT_WARNING(DocumentSetDomainIgnored)`
- `dom/locales/en-US/chrome/dom/dom.properties` defines it:
  ```
  # LOCALIZATION NOTE: do not translate "document.domain"
  DocumentSetDomainIgnoredWarning=Ignoring document.domain mutation in an origin-keyed agent cluster.
  ```

The mutation is ignored **"in an origin-keyed agent cluster"** — i.e. conditionally, not generally.
If Firefox had flipped the default, that condition would be the normal case and the string would not
be phrased as an exception.

### The Origin-Agent-Cluster machinery Firefox does ship

- **Firefox shipped `Origin-Agent-Cluster` header support in Firefox 138.** From MDN's
  browser-compat-data: `version_added` — Chrome **90**, **Firefox 138**, Safari *preview*; Edge and
  the Android variants `mirror`. Status: `standard_track: true`, `experimental: false`, `deprecated:
  false`.
  https://raw.githubusercontent.com/mdn/browser-compat-data/main/http/headers/Origin-Agent-Cluster.json
- Honouring the header disables the relaxation. MDN: when origin-keyed clustering is honoured the
  window "is not able to do the following things, which all depend on same-site, cross-origin
  communication: Use `Document.domain`."
  https://raw.githubusercontent.com/mdn/content/main/files/en-us/web/http/reference/headers/origin-agent-cluster/index.md
- **Two prefs exist**, which is the tell that Mozilla built for a future default flip:
  - `dom.origin_agent_cluster.enabled` — gates `window.originAgentCluster` and header parsing
    (`dom/webidl/Window.webidl`; `netwerk/ipc/DocumentLoadListener.cpp`:
    `httpChannel && isSecureContext && StaticPrefs::dom_origin_agent_cluster_enabled()`)
  - `dom.origin_agent_cluster.default` — the *default keying* switch:
    - `docshell/base/BrowsingContextGroup.cpp`:
      `SetUseOriginAgentClusterFromNetwork(aPrincipal, StaticPrefs::dom_origin_agent_cluster_default());`
    - `netwerk/ipc/DocumentLoadListener.cpp`:
      `bool hasOriginAgentCluster = StaticPrefs::dom_origin_agent_cluster_default() && isSecureContext;`
  (All via GitHub code search over `repo:mozilla-firefox/firefox`, query `origin_agent_cluster`.)
- **Note the `isSecureContext` conjunction**: origin-keyed clustering is only applied in secure
  contexts. On plain `http://` test origins the OAC path cannot engage at all — relevant if your
  harness serves over HTTP.

**UNVERIFIED: the shipped default *values* of `dom.origin_agent_cluster.enabled` and
`dom.origin_agent_cluster.default`.** These live in
`modules/libpref/init/StaticPrefList.yaml`, which is too large for GitHub's code-search index
(>384 KB) and too large to fetch intact. **Check it yourself in `about:config`** in the build under
test — this is the single highest-value one-line confirmation you can make locally, and it decides
whether §4's conclusion holds for your exact build.

### Mozilla's stated position

- **mozilla/standards-positions issue #601 — "Changing the Origin-Agent-Cluster default, aka
  deprecating document.domain": position **positive**, venue WHATWG, issue **closed**; opened
  2021-12-09 by `otherdaniel`.** https://github.com/mozilla/standards-positions/issues/601
  The proposal is to make `Origin-Agent-Cluster: ?1` the default, so the `document.domain` setter
  becomes a no-op, with `Origin-Agent-Cluster: ?0` as the explicit opt-out.
- Relevant Bugzilla tickets (titles from search-result titles; **pages not fetchable**, so treat the
  titles as indicative only): **1817844** "Deprecate document.domain"; **1665474** "Implement the
  Origin-Agent-Cluster header".
- MDN marks the property `deprecated` and warns: "Attempting to set `document.domain` is dangerous.
  It opens up full access to a page's DOM from *all* subdomains, which is likely not what is
  intended," and "It undermines the security protections provided by the same origin policy."
  It also notes the origin comparison **drops the port component**.
  https://raw.githubusercontent.com/mdn/content/main/files/en-us/web/api/document/domain/index.md

### Cross-engine comparison

- Chrome and Edge have both announced and shipped disabling the `document.domain` setter by default.
  I could **not** verify the exact Chrome milestone: `developer.chrome.com` and
  `chromium.googlesource.com` are both egress-blocked here. **The specific Chrome version number is
  UNVERIFIED and I am deliberately not quoting one.** Titles confirming the change exists:
  "Chrome disables modifying document.domain" (developer.chrome.com blog), "Microsoft Edge will
  disable modifying 'document.domain'" (Microsoft Learn), and Blink's
  "Intent to Ship: Origin Isolation By Default / Deprecate document.domain".
- **Practical upshot for your suite:** `document.domain` origin relaxation is a **live Firefox-only
  SOP-relaxation primitive** in the current release, and a dead one in Chromium. That asymmetry is
  itself the test case. Cover: same-site cross-origin (`a.example.com` ↔ `b.example.com`) DOM access
  after both set `document.domain = "example.com"`; the port-dropping quirk; and behaviour with
  `Origin-Agent-Cluster: ?1` present (expect the `DocumentSetDomainIgnoredWarning` console message
  in Firefox ≥138 over HTTPS).

---

## 5. `blob:` URL origin inheritance and `sandbox="allow-scripts allow-same-origin"`

This is the weakest-evidenced section of the dossier. I am flagging that plainly rather than
padding it.

### What I verified

**A Firefox-only blob-URL partitioning pref exists: `privacy.partition.bloburl_per_partition_key`.**
Found in two Gecko test files (GitHub code search over `repo:mozilla-firefox/firefox`):

- `browser/components/originattributes/test/browser/browser_blobURLIsolation.js` — sets it to
  `false` (together with `dom.security.https_first: false`) for its own isolation assertions
- `toolkit/components/antitracking/test/browser/browser_partitionkey_bloburl.js` — sets it to `true`

There is **no Chromium equivalent to this pref**. Gecko partitions blob-URL visibility by partition
key as part of its anti-tracking / dynamic-state-partitioning architecture, which Chromium
implements differently (via storage partitioning keyed on top-level site). A blob URL minted in a
third-party context in Firefox may therefore not be retrievable where a Chromium tester would expect
it to be. **This is a concrete, citable Firefox-specific divergence and the best lead in this
section.** Concrete test: create a blob URL inside a third-party iframe, attempt to fetch it from a
differently-partitioned context, with the pref at each of its two values.

### Relevant Bugzilla tickets

`bugzilla.mozilla.org` is egress-blocked, so I have **only the bug titles**, recovered from search
result titles. Titles are reliable; the contents are not verified.

| Bug | Title (verbatim from search result) |
|---|---|
| **1270451** | A Blob URL object's origin property should not be "null" |
| **1570889** | blob URLs and CSP sandbox'ed pages should inherit Cross-Origin-Opener-Policy |
| **1054646** | Can't use createObjectURL inside sandboxed iframes |
| **1559128** | Sandboxed iframes with allow-same-origin allow Javascript execution through javascript-links |
| **1411641** | CSP 'sandbox' directive prevents content scripts from matching, due to unique origin, breaking also browser features [Screenshots] |
| **341604** | (framesandbox) Implement HTML5 sandbox attribute for IFRAMEs |

Bug **1559128** is the most interesting: its title asserts that in Firefox, sandboxed iframes **with
`allow-same-origin`** permit JS execution via `javascript:` links. A secondary summary I read further
claimed Firefox executes such links in a new browsing context while Chrome and Safari refuse to open
them at all — **but I could not confirm that from any primary source, and I am marking the whole
Firefox-vs-Chromium claim UNVERIFIED.** Do not put it in the suite as a documented divergence; put
it in as a hypothesis with a differential test.

### Spec-level baseline (verified)

- Sandboxed content **without** `allow-same-origin` gets an opaque origin; its `Origin` header
  serialises as `null` and storage APIs are unavailable. **With** `allow-same-origin` the resource
  keeps its real origin. (MDN CSP `sandbox` directive documentation.)
- A blob URL created by a document inherits that document's principal — so inside a sandboxed
  (null-principal) frame the blob inherits the *opaque* origin, not the parent's.
- A Blob that sets a CSP including `sandbox` does **not** inherit the creator's CSP.

### Honest gap

**I could not establish a crisp, primary-sourced Firefox-vs-Chromium divergence on `blob:` origin
inheritance or on `sandbox="allow-scripts allow-same-origin"` beyond the partitioning pref above.**
The `bugzilla.mozilla.org` blockade is the binding constraint: the six bugs listed are exactly where
the answer is, and I could only read their titles. **Recommendation: this section needs first-hand
differential testing, not more literature search.** Your own test suite is the better instrument
here — the behaviours are cheap to probe directly and expensive to research second-hand.

---

## 6. Obtaining an old, deliberately vulnerable Firefox build

### 6.1 The archive URL pattern

`archive.mozilla.org` **and** its alias `ftp.mozilla.org` are both egress-blocked from this
container, so I could not enumerate a live directory. I reconstructed the pattern from
**Mozilla's own `mozdownload` tool**, whose test fixtures hard-code the expected remote paths —
a Mozilla-owned, primary-adjacent source.

From https://raw.githubusercontent.com/mozilla/mozdownload/master/tests/release_scraper/test_release_scraper.py :

```python
({'application': 'firefox', 'platform': 'linux64', 'version': '23.0.1'},
 'firefox-23.0.1.en-US.linux64.tar.xz',
 'firefox/releases/23.0.1/linux-x86_64/en-US/firefox-23.0.1.tar.xz')
```

From `tests/release_scraper/test_release_scraper_latest.py` in the same repo (ESR form):

```python
'thunderbird/releases/17.0.1esr/linux-x86_64/en-US/thunderbird-17.0.1esr.tar.bz2'
```

Therefore the canonical pattern is:

```
https://archive.mozilla.org/pub/firefox/releases/<VERSION>/<PLATFORM>/<LOCALE>/firefox-<VERSION>.<EXT>
```

**Path segments needed for a Linux x86-64 tarball:**

| Segment | Value |
|---|---|
| Platform | **`linux-x86_64`** (32-bit is `linux-i686`) |
| Locale | **`en-US`** |
| Filename | **`firefox-<VERSION>.tar.xz`** |

Note the asymmetry the fixtures reveal: the **platform directory** is `linux-x86_64` while the
**local filename** mozdownload writes uses `linux64`. The remote path is the one that matters.

Worked examples for the CVE-2025-9180 boundary — **construct these, but verify they resolve, since I
could not**:

```
# last vulnerable mainline release
https://archive.mozilla.org/pub/firefox/releases/141.0/linux-x86_64/en-US/firefox-141.0.tar.xz
# first fixed mainline release
https://archive.mozilla.org/pub/firefox/releases/142.0/linux-x86_64/en-US/firefox-142.0.tar.xz
# last vulnerable ESR on each line (note the 'esr' suffix appears in BOTH dir and filename)
https://archive.mozilla.org/pub/firefox/releases/115.26.0esr/linux-x86_64/en-US/firefox-115.26.0esr.tar.xz
https://archive.mozilla.org/pub/firefox/releases/128.13.0esr/linux-x86_64/en-US/firefox-128.13.0esr.tar.xz
https://archive.mozilla.org/pub/firefox/releases/140.1.0esr/linux-x86_64/en-US/firefox-140.1.0esr.tar.xz
```

**UNVERIFIED in the above:** (a) that these exact directory names exist — ESR directories carry a
three-part version plus `esr` (e.g. `128.13.0esr`), and whether a given ESR point release is
`128.13.0esr` or `128.13.1esr` **must be checked against the live listing**; (b) the `.tar.xz` vs
`.tar.bz2` cutover version — **both extensions are attested in the mozdownload fixtures**
(`.tar.xz` for Firefox 23.0.1, `.tar.bz2` for an older Thunderbird ESR), so Mozilla switched at some
point I did not pin down. Try `.tar.xz` first for anything modern.

Real indexed directory-listing URLs confirming the segment order (from search results, host is the
`ftp.mozilla.org` alias of the same archive):
`https://ftp.mozilla.org/pub/firefox/releases/61.0/linux-x86_64/en-US/`,
`.../86.0/linux-x86_64/en-US/`, `.../100.0/linux-x86_64/en-US/`.

**Operational note (advice, not a citation):** run any archived build with a throwaway profile
(`-profile /tmp/ff-test -no-remote`) and updates disabled, or it will silently self-update out of
your vulnerable version.

### 6.2 Playwright's Firefox is versioned separately — confirmed, with the mapping

**Confirmed: Playwright's Firefox "revision" numbers are Playwright-internal build IDs with no
relation to upstream Firefox version numbers.** Current example — revision **1553** corresponds to
upstream Firefox **156.0**:

From https://raw.githubusercontent.com/microsoft/playwright/main/packages/playwright-core/browsers.json :
```
"name": "firefox", "revision": "1553", "installByDefault": true, "browserVersion": "156.0"
```
(for contrast, `chromium` revision `1247` ↔ `155.0.8059.12`; `webkit` revision `2368` ↔ `26.6`)

**The three-step mapping method — fully verified end to end:**

1. **Revision → marketing version.** Read `packages/playwright-core/browsers.json` at the Playwright
   tag you care about; take `browserVersion` for the entry named `firefox`. → `156.0`
2. **Revision → exact upstream source commit.** Read
   `browser_patches/firefox/UPSTREAM_CONFIG.sh` at that same Playwright tag:
   https://raw.githubusercontent.com/microsoft/playwright/main/browser_patches/firefox/UPSTREAM_CONFIG.sh
   ```sh
   REMOTE_URL="https://github.com/mozilla-firefox/firefox"
   BASE_BRANCH="release"
   BASE_REVISION="3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1"
   ```
3. **Confirm the version from Gecko itself.** Read `browser/config/version.txt` at that revision:
   https://raw.githubusercontent.com/mozilla-firefox/firefox/3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1/browser/config/version.txt
   → **`156.0`** — an exact match with step 1. **The mapping is verified, not inferred.**

Corroborating detail: the pinned commit
https://github.com/mozilla-firefox/firefox/commit/3bf8f468258c2181f455e23d4ffcd6acb8f4cdb1
is "No Bug - Update configs after merge day operations a=release" by Release Engineering
Landoscript, touching `.arcconfig` (callsign `FIREFOXBETA` → `FIREFOXRELEASE`) and `CLOBBER`
("Merge day clobber 2026-09-09") — i.e. the exact merge-day commit where 156 became release.

**Where Playwright's own builds live.** From
`packages/playwright-core/src/server/registry/index.ts` the download paths are templated on the
revision (`%s`):
```
'ubuntu22.04-x64': 'builds/firefox/%s/firefox-ubuntu-22.04.zip',
'ubuntu24.04-x64': 'builds/firefox/%s/firefox-ubuntu-24.04.zip',
'ubuntu26.04-x64': 'builds/firefox/%s/firefox-ubuntu-24.04.zip',
'debian12-arm64':  'builds/firefox/%s/firefox-debian-12-arm64.zip',
'debian13-x64':    'builds/firefox/%s/firefox-debian-13.zip',
'debian13-arm64':  'builds/firefox/%s/firefox-debian-13-arm64.zip',
```
So for revision 1553 the Linux artifact is `builds/firefox/1553/firefox-ubuntu-22.04.zip`.
**UNVERIFIED: the CDN host prefix** — it is defined elsewhere in that same file and I did not read it.

**Two caveats that matter for CVE work:**

1. **Playwright's Firefox is a *patched* build.** It applies `browser_patches/firefox/patches` and
   adds the Juggler automation protocol. It is **not byte-identical to any released Firefox**, so a
   negative result under Playwright Firefox is not proof that stock Firefox is unaffected — and vice
   versa. For reproducing CVE-2025-9180 specifically, use the real archive.mozilla.org build.
2. **Playwright tracks the `release` branch and is not version-pinnable to arbitrary Firefox
   versions.** You cannot ask Playwright for "Firefox 141"; you get whatever revision that
   Playwright release pinned. **To test a specific pre-patch version you must download from
   archive.mozilla.org (§6.1) and drive it with `launchOptions.executablePath`, or use
   `mozregression`.** Playwright is the wrong tool for version-boundary bisection.

---

## 7. Everything I could NOT verify

Ranked by how much it would matter to the suite.

1. **Whether a public POC exists for CVE-2025-9180, and whether bug 1979782 is still restricted.**
   No POC found; the bug's Bugzilla title never surfaced in searches (unlike peers), suggesting it
   is still security-restricted — **not proven**, because `bugzilla.mozilla.org` is blocked.
2. **Shipped default values of `dom.origin_agent_cluster.default` and
   `dom.origin_agent_cluster.enabled`.** `StaticPrefList.yaml` exceeds GitHub code-search's index
   limit and is too large to fetch whole. Check `about:config` locally. This is the one gap that
   could change §4's conclusion.
3. **Any crisp Firefox-vs-Chromium divergence on `blob:` origin inheritance or
   `sandbox="allow-scripts allow-same-origin"`,** beyond the Firefox-only
   `privacy.partition.bloburl_per_partition_key` pref. The six Bugzilla tickets in §5 hold the
   answer and I could read only their titles. Needs first-hand differential testing.
4. **The exact Chrome version that disabled the `document.domain` setter.** Deliberately not quoted;
   `developer.chrome.com` and `chromium.googlesource.com` both blocked.
5. **That my constructed archive.mozilla.org URLs resolve**, and the exact ESR directory spellings
   (`128.13.0esr` vs `128.13.1esr` etc.). Archive host blocked. Also the `.tar.bz2` → `.tar.xz`
   cutover version.
6. **Three CVE IDs I found descriptions for but refuse to guess:** the MFSA 2024-29..32 cross-origin
   permissions race (Andreas Farre, bug 1890748); the MFSA 2023-05 drag-and-drop cross-origin image
   size leak (Dohyun Lee, bugs 1813376 / 1437126); the MFSA 2025-81 Android fake-address-bar issue
   (Hafiizh & kang ali, bug 1980808).
7. **`fixed_in` strings for sibling/ESR advisories I did not individually fetch** — marked inline
   throughout §2 and §3. The Firefox-mainline `fixed_in` for each cluster *is* verified.
8. **CVE-2025-10290's MFSA ID and fixed version** (Focus iOS context-menu address-bar spoof, bug
   1975566) — Bugzilla title only.
9. **Which CVE in MFSA 2026-69 carries the "exploit code for this is public" note.**
10. **Mechanisms for the 2025–2026 standardised-title SOP bypasses** (§2.2, §2.3) — Mozilla ships
    these with a title and no `description` field, so component names are all that is public.
11. **The CDN host prefix for Playwright's browser downloads** (path template verified; host not).
12. **Whether Mozilla flipped the origin-keyed-by-default behaviour in any 2026 release** — no
    release note or advisory found saying so, but I could not read `www.firefox.com` release notes
    or MDN Firefox release pages directly (both hosts blocked/unfetched).
