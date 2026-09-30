#!/usr/bin/env node
/**
 * Report exactly which browser builds this machine can actually drive.
 *
 * Three independent sources are collected per engine, because they disagree and
 * the disagreements matter:
 *
 *   binaryVersion   what `--version` prints
 *   pwVersion       what Playwright's browser.version() reports over the
 *                   automation protocol
 *   uaFull          the full UA / navigator data as the page sees it, including
 *                   the userAgentData brand list where present
 *
 * Only the third is what a probe's feature detection reacts to, while only the
 * first tells you which security fixes the build contains. A suite that records
 * one and reasons about the other produces claims it cannot support.
 */
'use strict';

const { discover, LAUNCH, assertNoSopWeakeningFlags } = require('./engines');

async function inspect(engine, info) {
  if (!info.available) {
    return { engine, available: false, reason: 'no binary found on this machine' };
  }
  let pw;
  try { pw = require('playwright-core'); } catch (_) {
    return { engine, available: true, reason: 'playwright-core not installed',
      ...info };
  }
  const opts = LAUNCH[engine]({ executablePath: info.executablePath, headless: true });
  assertNoSopWeakeningFlags(opts.args);

  let browser = null;
  try {
    browser = await pw[engine].launch(opts);
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    // about:blank is enough; no network needed for UA introspection.
    const ua = await page.evaluate(() => ({
      userAgent: navigator.userAgent,
      appVersion: navigator.appVersion,
      platform: navigator.platform,
      vendor: navigator.vendor,
      hardwareConcurrency: navigator.hardwareConcurrency,
      uaData: navigator.userAgentData ? {
        brands: navigator.userAgentData.brands,
        mobile: navigator.userAgentData.mobile,
        platform: navigator.userAgentData.platform,
      } : null,
      // Feature flags the probe set branches on.
      features: {
        navigationAPI: typeof window.navigation !== 'undefined',
        documentDomainSetter: (function () {
          try {
            const d = Object.getOwnPropertyDescriptor(Document.prototype, 'domain');
            return Boolean(d && d.set);
          } catch (_) { return false; }
        })(),
        originAgentCluster: 'originAgentCluster' in window,
        crossOriginIsolated: typeof crossOriginIsolated !== 'undefined'
          ? crossOriginIsolated : null,
        sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
        reportingObserver: typeof ReportingObserver !== 'undefined',
        fencedFrame: typeof HTMLFencedFrameElement !== 'undefined',
      },
    }));
    const out = {
      engine, available: true,
      executablePath: info.executablePath,
      binaryVersion: info.binaryVersion,
      playwrightBuild: info.playwrightBuild,
      pwVersion: browser.version(),
      playwrightCore: require('playwright-core/package.json').version,
      ...ua,
    };
    await browser.close();
    return out;
  } catch (e) {
    if (browser) { try { await browser.close(); } catch (_) {} }
    return {
      engine, available: true, launchFailed: true,
      executablePath: info.executablePath,
      binaryVersion: info.binaryVersion,
      playwrightBuild: info.playwrightBuild,
      error: String(e && e.message ? e.message : e).split('\n').slice(0, 4).join(' | '),
    };
  }
}

async function main() {
  const found = discover();
  const results = [];
  for (const engine of ['chromium', 'firefox', 'webkit']) {
    results.push(await inspect(engine, found[engine]));
  }
  const asJson = process.argv.includes('--json');
  if (asJson) {
    console.log(JSON.stringify({ generatedAt: new Date().toISOString(), results }, null, 2));
    return;
  }
  console.log('Browser engines available to this suite');
  console.log('='.repeat(72));
  for (const r of results) {
    console.log('\n' + r.engine.toUpperCase());
    if (!r.available) { console.log('  unavailable — ' + r.reason); continue; }
    console.log('  path            ' + r.executablePath);
    console.log('  binary version  ' + (r.binaryVersion || '(unknown)'));
    if (r.playwrightBuild) {
      console.log('  pw build rev    ' + r.playwrightBuild.channelDir
        + '-' + r.playwrightBuild.revision);
    }
    if (r.launchFailed) { console.log('  LAUNCH FAILED   ' + r.error); continue; }
    console.log('  protocol ver    ' + r.pwVersion);
    console.log('  playwright-core ' + r.playwrightCore);
    console.log('  user agent      ' + r.userAgent);
    if (r.uaData && r.uaData.brands) {
      console.log('  UA brands       ' + r.uaData.brands
        .map((b) => b.brand + '/' + b.version).join(', '));
    }
    console.log('  features        ' + Object.entries(r.features)
      .map(([k, v]) => k + '=' + v).join(' '));
  }
  console.log('');
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
module.exports = { inspect };
