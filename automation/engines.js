/**
 * Engine discovery and launch.
 *
 * Playwright normally downloads its own browser builds, but this container has
 * cdn.playwright.dev blocked at the egress proxy, so discovery has to work from
 * whatever is already on disk. That constraint is worth keeping even where the
 * CDN is reachable: it means the suite runs against a *named, pinned* binary you
 * can point at a deliberately old build, which is the entire point when the
 * question is "which version is this bug present in".
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const PW_ROOT = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';

/** Candidate on-disk locations, most specific first. */
const CANDIDATES = {
  chromium: [
    () => process.env.SOP_CHROMIUM,
    () => path.join(PW_ROOT, 'chromium', 'chrome'),
    ...globbed('chromium-*', 'chrome-linux/chrome'),
    ...globbed('chromium_headless_shell-*', 'chrome-linux/headless_shell'),
    () => '/usr/bin/chromium',
    () => '/usr/bin/chromium-browser',
    () => '/usr/bin/google-chrome',
    () => '/usr/bin/google-chrome-stable',
    () => '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ],
  firefox: [
    () => process.env.SOP_FIREFOX,
    ...globbed('firefox-*', 'firefox/firefox'),
    () => '/usr/bin/firefox',
    () => '/usr/bin/firefox-esr',
    () => '/usr/lib/firefox/firefox',
    () => '/usr/lib/firefox-esr/firefox-esr',
    () => '/opt/firefox/firefox',
    () => '/Applications/Firefox.app/Contents/MacOS/firefox',
  ],
  webkit: [
    () => process.env.SOP_WEBKIT,
    ...globbed('webkit-*', 'pw_run.sh'),
    ...globbed('webkit-*', 'minibrowser-gtk/MiniBrowser'),
  ],
};

function globbed(dirPattern, tail) {
  // Resolved lazily: PW_ROOT may not exist on the machine reading this module.
  return [() => {
    if (!fs.existsSync(PW_ROOT)) return null;
    const rx = new RegExp('^' + dirPattern.replace('*', '\\d+') + '$');
    const dirs = fs.readdirSync(PW_ROOT).filter((d) => rx.test(d)).sort().reverse();
    for (const d of dirs) {
      const p = path.join(PW_ROOT, d, tail);
      if (fs.existsSync(p)) return p;
    }
    return null;
  }];
}

function resolveEngine(engine) {
  const list = CANDIDATES[engine] || [];
  for (const fn of list) {
    let p = null;
    try { p = fn(); } catch (_) { continue; }
    if (!p) continue;
    try {
      const st = fs.statSync(p);
      // A symlink to a directory (a stale playwright link) is not an executable.
      if (st.isFile()) return p;
    } catch (_) { /* keep looking */ }
  }
  return null;
}

/** The engine's own self-reported version string, straight from the binary. */
function binaryVersion(engine, execPath) {
  if (!execPath) return null;
  const flag = engine === 'firefox' ? '--version' : '--version';
  try {
    return execFileSync(execPath, [flag], {
      timeout: 20000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || null;
  } catch (_) { return null; }
}

/** Playwright revision directory a path sits in, if any — pins the build. */
function playwrightRevision(execPath) {
  if (!execPath) return null;
  const m = String(execPath).match(/(chromium|firefox|webkit|chromium_headless_shell)-(\d+)/);
  return m ? { channelDir: m[1], revision: m[2] } : null;
}

function discover() {
  const out = {};
  for (const engine of Object.keys(CANDIDATES)) {
    const execPath = resolveEngine(engine);
    out[engine] = {
      engine,
      available: Boolean(execPath),
      executablePath: execPath,
      binaryVersion: binaryVersion(engine, execPath),
      playwrightBuild: playwrightRevision(execPath),
    };
  }
  return out;
}

/**
 * Launch flags.
 *
 * --ignore-certificate-errors is required because the lab serves HTTPS under a
 * locally generated CA. HTTPS is not optional: several primitives under test are
 * secure-context gated, and http://victim.sop-lab.test is not a secure context
 * (only http://localhost gets that exemption, and localhost cannot give us the
 * sibling subdomains the document.domain probes need).
 *
 * Nothing here weakens the Same-Origin Policy itself. Flags such as
 * --disable-web-security would invalidate every result in the suite, so they are
 * deliberately absent — see assertNoSopWeakeningFlags below, which fails the run
 * if one is ever introduced.
 */
const LAUNCH = {
  chromium: (opts) => ({
    executablePath: opts.executablePath,
    headless: opts.headless !== false,
    args: [
      '--ignore-certificate-errors',
      '--no-sandbox',                   // container has no user namespaces
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--no-first-run',
      '--disable-features=Translate,MediaRouter',
      // Chromium on Linux honours http_proxy/https_proxy from the environment.
      // In a sandboxed container those point at an egress proxy that denies the
      // lab's own hostnames, so every navigation dies with ERR_CONNECTION_RESET.
      // The lab is entirely loopback, so going direct is both correct and the
      // only thing that works.
      '--no-proxy-server',
      ...(opts.extraArgs || []),
    ],
  }),
  firefox: (opts) => ({
    executablePath: opts.executablePath,
    headless: opts.headless !== false,
    firefoxUserPrefs: {
      'security.enterprise_roots.enabled': true,
      'network.stricttransportsecurity.preloadlist': false,
      // Same reasoning as --no-proxy-server above: 0 == direct connection.
      'network.proxy.type': 0,
      // Gecko needs to be told the lab's CA-signed certs are acceptable; the
      // runner also passes ignoreHTTPSErrors at the context level.
      'security.cert_pinning.enforcement_level': 0,
      ...(opts.prefs || {}),
    },
    args: opts.extraArgs || [],
  }),
  webkit: (opts) => ({
    executablePath: opts.executablePath,
    headless: opts.headless !== false,
    args: opts.extraArgs || [],
  }),
};

/** Guard: any flag that switches SOP off makes the whole run meaningless. */
const SOP_WEAKENING = [
  '--disable-web-security',
  '--allow-file-access-from-files',
  '--disable-site-isolation-trials',
  '--disable-features=IsolateOrigins',
  '--disable-features=site-per-process',
  '--allow-running-insecure-content',
];

function assertNoSopWeakeningFlags(args) {
  const bad = (args || []).filter((a) =>
    SOP_WEAKENING.some((w) => String(a).startsWith(w.split('=')[0])
      && String(a).includes(w.replace(/^--disable-features=/, '') === w ? '' : w.split('=')[1] || '')
      && SOP_WEAKENING.some((x) => String(a) === x || String(a).startsWith(x))));
  if (bad.length) {
    throw new Error('refusing to run: SOP-weakening launch flags present ('
      + bad.join(', ') + '). Every verdict would be worthless.');
  }
}

module.exports = {
  PW_ROOT, discover, resolveEngine, binaryVersion, playwrightRevision,
  LAUNCH, assertNoSopWeakeningFlags, SOP_WEAKENING,
};
