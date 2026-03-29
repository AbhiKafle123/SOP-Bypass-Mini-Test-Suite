#!/usr/bin/env node
/**
 * SOP Bypass Mini Test Suite V2.0 — Automated Test Runner
 *
 * Runs all POC tests across Brave (Chromium), Firefox, and Safari (WebKit)
 * using Playwright. Captures results via the window.__sopTestResults hook
 * and console messages.
 *
 * Usage:
 *   node runner.js --all                    # All browsers
 *   node runner.js --browser chromium       # Brave/Chrome only
 *   node runner.js --browser firefox        # Firefox only
 *   node runner.js --browser webkit         # Safari only
 *   node runner.js --all --report           # Generate HTML report
 *   node runner.js --all --headed           # Watch tests run visually
 *   node runner.js --url https://abhikafle.com.np/sop  # Test deployed site
 */

const { chromium, firefox, webkit } = require('playwright');
const http = require('http');
const fs = require('fs');
const path = require('path');

// ─── Configuration ───────────────────────────────────────────────────────────

const TESTS = [
  // UXSS / SOP Bypass
  { id: 'UXSS-CHROME-01', file: 'tests/uxss/chrome/uxss-chrome-01-navigation-api-entries.html', button: 'Execute Test', browsers: ['chromium'], timeout: 10000 },
  { id: 'UXSS-CHROME-02', file: 'tests/uxss/chrome/uxss-chrome-02-link-header-referrer-leak.html', button: 'Execute Client-Side Test', browsers: ['chromium'], timeout: 8000 },
  { id: 'UXSS-CHROME-03', file: 'tests/uxss/chrome/uxss-chrome-03-blob-url-partition-bypass.html', button: 'Test Blob URL Cross-Origin Access', browsers: ['chromium'], timeout: 10000 },
  { id: 'UXSS-SAFARI-01', file: 'tests/uxss/safari/uxss-safari-01-navigation-api-sop-bypass.html', button: 'Detection Only', browsers: ['webkit'], timeout: 8000 },
  { id: 'UXSS-SAFARI-02', file: 'tests/uxss/safari/uxss-safari-02-iframe-subframe-overflow.html', button: 'Test Subframe Overflow', browsers: ['webkit'], timeout: 15000 },
  { id: 'UXSS-FIREFOX-01', file: 'tests/uxss/firefox/uxss-firefox-01-canvas2d-sop-bypass.html', button: 'Test Canvas Taint Bypass', browsers: ['firefox'], timeout: 10000 },
  { id: 'UXSS-OPERA-01', file: 'tests/uxss/opera/uxss-opera-01-intent-url-uxss.html', button: 'Test Intent URL Handling', browsers: ['chromium'], timeout: 8000 },
  { id: 'UXSS-XB-01', file: 'tests/uxss/cross-browser/uxss-xb-01-postmessage-null-origin.html', button: 'Test Null Origin Sources', browsers: ['chromium', 'firefox', 'webkit'], timeout: 10000 },
  { id: 'UXSS-XB-02', file: 'tests/uxss/cross-browser/uxss-xb-02-sandbox-escape.html', button: 'Test Sandbox Escape', browsers: ['chromium', 'firefox', 'webkit'], timeout: 8000 },
  { id: 'UXSS-XB-03', file: 'tests/uxss/cross-browser/uxss-xb-03-performance-timing-leak.html', button: 'Test Resource Timing Leaks', browsers: ['chromium', 'firefox', 'webkit'], timeout: 8000 },
  { id: 'UXSS-XB-04', file: 'tests/uxss/cross-browser/uxss-xb-04-window-open-race.html', button: 'Test Classic Race', browsers: ['chromium', 'firefox', 'webkit'], timeout: 10000 },

  // URL Spoofing
  { id: 'SPOOF-CHROME-01', file: 'tests/url-spoofing/chrome/spoof-chrome-01-toolbar-domain-spoof.html', button: 'Test replaceState Spoofing', browsers: ['chromium'], timeout: 8000 },
  { id: 'SPOOF-CHROME-02', file: 'tests/url-spoofing/chrome/spoof-chrome-02-omnibox-ui.html', button: 'Test Omnibox Behavior', browsers: ['chromium'], timeout: 8000 },
  { id: 'SPOOF-SAFARI-01', file: 'tests/url-spoofing/safari/spoof-safari-01-blob-url-display.html', button: 'Open Blob URL Popup', browsers: ['webkit'], timeout: 8000, needsPopup: true },
  { id: 'SPOOF-FIREFOX-01', file: 'tests/url-spoofing/firefox/spoof-firefox-01-long-hostname.html', button: 'Analyze URL Display Behavior', browsers: ['firefox'], timeout: 8000 },
  { id: 'SPOOF-OPERA-01', file: 'tests/url-spoofing/opera/spoof-opera-01-rtl-arabic.html', button: 'Test RTL URL Rendering', browsers: ['chromium'], timeout: 8000 },
  { id: 'SPOOF-OPERA-02', file: 'tests/url-spoofing/opera/spoof-opera-02-fullscreen-spoof.html', button: 'Check Fullscreen Notification', browsers: ['chromium', 'firefox', 'webkit'], timeout: 8000 },
  { id: 'SPOOF-XB-01', file: 'tests/url-spoofing/cross-browser/spoof-xb-01-meta-refresh-race.html', button: 'Test Meta Refresh Race', browsers: ['chromium', 'firefox', 'webkit'], timeout: 10000 },
  { id: 'SPOOF-XB-02', file: 'tests/url-spoofing/cross-browser/spoof-xb-02-auth-url-confusion.html', button: 'Analyze Userinfo URL Handling', browsers: ['chromium', 'firefox', 'webkit'], timeout: 8000 },
  { id: 'SPOOF-XB-03', file: 'tests/url-spoofing/cross-browser/spoof-xb-03-data-uri-title.html', button: 'Open data: URI Tab', browsers: ['chromium', 'firefox', 'webkit'], timeout: 8000, needsPopup: true },
];

// ─── CLI Args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const runAll = args.includes('--all');
const generateReport = args.includes('--report');
const headed = args.includes('--headed');
const browserArg = args.find((_, i, a) => a[i - 1] === '--browser');
const customUrl = args.find((_, i, a) => a[i - 1] === '--url');

const browsersToRun = runAll
  ? ['chromium', 'firefox', 'webkit']
  : browserArg
    ? [browserArg]
    : ['chromium']; // default

// ─── Static file server ──────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.php': 'text/html',
};

function startServer(rootDir, port) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let filePath = path.join(rootDir, decodeURIComponent(req.url.split('?')[0]));
      if (filePath.endsWith('/')) filePath += 'index.html';

      fs.readFile(filePath, (err, data) => {
        if (err) {
          // For cross-origin target requests, return a simple page
          if (req.url.includes('ebniw.com') || req.headers.host !== `localhost:${port}`) {
            res.writeHead(200, { 'Content-Type': 'text/html', 'Access-Control-Allow-Origin': '*' });
            res.end('<html><body><div id="secret-data">XORIGIN_TEST</div></body></html>');
            return;
          }
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        const ext = path.extname(filePath);
        res.writeHead(200, {
          'Content-Type': MIME[ext] || 'application/octet-stream',
          'Access-Control-Allow-Origin': '*',
        });
        res.end(data);
      });
    });

    server.listen(port, () => {
      console.log(`  Local server: http://localhost:${port}`);
      resolve(server);
    });
  });
}

// ─── Test Runner ─────────────────────────────────────────────────────────────

const ENGINE_MAP = { chromium, firefox, webkit };
const ENGINE_NAMES = { chromium: 'Brave/Chrome (Chromium)', firefox: 'Firefox (Gecko)', webkit: 'Safari (WebKit)' };

async function runTestInBrowser(browserType, test, baseUrl, headless) {
  const engine = ENGINE_MAP[browserType];
  const browser = await engine.launch({
    headless,
    args: browserType === 'chromium' ? ['--disable-web-security', '--allow-popups'] : [],
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    permissions: ['clipboard-read'],
    bypassCSP: true,
  });

  // Allow popups for tests that need them
  if (test.needsPopup) {
    context.on('page', () => {}); // accept new pages
  }

  const page = await context.newPage();
  const results = [];
  const consoleLogs = [];

  // Capture console output
  page.on('console', (msg) => {
    consoleLogs.push({ type: msg.type(), text: msg.text() });
  });

  // Capture page errors
  page.on('pageerror', (err) => {
    consoleLogs.push({ type: 'error', text: err.message });
  });

  const url = `${baseUrl}/${test.file}`;

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

    // Click the test button
    const btn = page.getByRole('button', { name: test.button });
    if (await btn.isVisible({ timeout: 3000 }).catch(() => false)) {
      await btn.click();
    } else {
      // Fallback: find by text content
      const fallbackBtn = page.locator(`button:has-text("${test.button}")`);
      if (await fallbackBtn.count() > 0) {
        await fallbackBtn.first().click();
      }
    }

    // Wait for results
    await page.waitForTimeout(test.timeout);

    // Collect results from window.__sopTestResults
    const pageResults = await page.evaluate(() => {
      return window.__sopTestResults || [];
    }).catch(() => []);

    results.push(...pageResults);

    // Also scrape the output box for any visible results
    const outputText = await page.locator('#output').textContent().catch(() => '');
    if (results.length === 0 && outputText) {
      const vulnerable = outputText.includes('VULNERABLE') && !outputText.includes('NOT VULNERABLE');
      results.push({
        testName: test.id,
        passed: vulnerable,
        details: outputText.substring(0, 200).trim(),
        timestamp: Date.now(),
      });
    }

  } catch (err) {
    results.push({
      testName: test.id,
      passed: false,
      details: `Runner error: ${err.message}`,
      timestamp: Date.now(),
    });
  }

  await browser.close();

  return {
    testId: test.id,
    browser: browserType,
    browserName: ENGINE_NAMES[browserType],
    results,
    consoleLogs: consoleLogs.filter(l => l.type === 'error' || l.text.includes('UXSS') || l.text.includes('VULNERABLE')),
  };
}

// ─── Report Generator ────────────────────────────────────────────────────────

function generateHtmlReport(allResults) {
  const timestamp = new Date().toISOString();
  let rows = '';

  for (const r of allResults) {
    const status = r.results.length > 0
      ? r.results.some(x => x.passed) ? '🔴 VULNERABLE' : '🟢 Patched'
      : '⚪ No result';
    const color = r.results.some(x => x.passed) ? '#f85149' : '#3fb950';
    const details = r.results.map(x => x.details).join('; ') || 'N/A';

    rows += `<tr>
      <td>${r.testId}</td>
      <td>${r.browserName}</td>
      <td style="color:${color};font-weight:bold;">${status}</td>
      <td style="font-size:0.85em;color:#8b949e;">${details.substring(0, 150)}</td>
    </tr>\n`;
  }

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SOP Test Report - ${timestamp}</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:system-ui; padding:20px; }
  h1 { color:#58a6ff; } table { border-collapse:collapse; width:100%; margin-top:20px; }
  th, td { padding:10px 12px; border:1px solid #30363d; text-align:left; }
  th { background:#161b22; color:#58a6ff; }
  tr:hover { background:#161b22; }
  .summary { display:flex; gap:20px; margin:20px 0; }
  .stat { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 24px; }
  .stat h3 { font-size:0.8em; color:#8b949e; } .stat .num { font-size:2em; font-weight:bold; }
</style></head><body>
<h1>SOP Bypass Test Suite V2.0 — Automated Report</h1>
<p style="color:#8b949e;">Generated: ${timestamp}</p>
<div class="summary">
  <div class="stat"><h3>Total Tests Run</h3><div class="num">${allResults.length}</div></div>
  <div class="stat"><h3 style="color:#f85149;">Vulnerable</h3><div class="num" style="color:#f85149;">${allResults.filter(r => r.results.some(x => x.passed)).length}</div></div>
  <div class="stat"><h3 style="color:#3fb950;">Patched</h3><div class="num" style="color:#3fb950;">${allResults.filter(r => r.results.length > 0 && !r.results.some(x => x.passed)).length}</div></div>
  <div class="stat"><h3>No Result</h3><div class="num">${allResults.filter(r => r.results.length === 0).length}</div></div>
</div>
<table><thead><tr><th>Test ID</th><th>Browser</th><th>Status</th><th>Details</th></tr></thead>
<tbody>${rows}</tbody></table>
</body></html>`;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║   SOP Bypass Mini Test Suite V2.0 — Automated Runner   ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  const PORT = 8080;
  const rootDir = path.resolve(__dirname, '..');
  let baseUrl;
  let server;

  if (customUrl) {
    baseUrl = customUrl.replace(/\/$/, '');
    console.log(`  Testing deployed site: ${baseUrl}`);
  } else {
    server = await startServer(rootDir, PORT);
    baseUrl = `http://localhost:${PORT}`;
  }

  console.log(`  Browsers: ${browsersToRun.map(b => ENGINE_NAMES[b]).join(', ')}`);
  console.log(`  Headed: ${headed ? 'yes' : 'no (use --headed to watch)'}`);
  console.log('');

  const allResults = [];
  let total = 0;
  let vulnerable = 0;
  let patched = 0;
  let noResult = 0;

  for (const browserType of browsersToRun) {
    console.log(`\n── ${ENGINE_NAMES[browserType]} ${'─'.repeat(50 - ENGINE_NAMES[browserType].length)}`);

    const testsForBrowser = TESTS.filter(t => t.browsers.includes(browserType));
    console.log(`   ${testsForBrowser.length} tests to run\n`);

    for (const test of testsForBrowser) {
      process.stdout.write(`   ${test.id.padEnd(20)} `);

      try {
        const result = await runTestInBrowser(browserType, test, baseUrl, !headed);
        allResults.push(result);
        total++;

        if (result.results.length === 0) {
          process.stdout.write('⚪ No result\n');
          noResult++;
        } else if (result.results.some(r => r.passed)) {
          process.stdout.write(`🔴 VULNERABLE — ${result.results.find(r => r.passed).details.substring(0, 60)}\n`);
          vulnerable++;
        } else {
          process.stdout.write(`🟢 Patched — ${result.results[0].details.substring(0, 60)}\n`);
          patched++;
        }
      } catch (err) {
        process.stdout.write(`⚠️  Error: ${err.message.substring(0, 60)}\n`);
        allResults.push({
          testId: test.id, browser: browserType, browserName: ENGINE_NAMES[browserType],
          results: [{ testName: test.id, passed: false, details: err.message }],
          consoleLogs: [],
        });
        total++;
        noResult++;
      }
    }
  }

  // Summary
  console.log('\n══════════════════════════════════════════════════════════');
  console.log(`  TOTAL: ${total}  |  🔴 Vulnerable: ${vulnerable}  |  🟢 Patched: ${patched}  |  ⚪ No result: ${noResult}`);
  console.log('══════════════════════════════════════════════════════════\n');

  // Generate report
  if (generateReport) {
    const reportPath = path.join(rootDir, 'automation', `report-${Date.now()}.html`);
    fs.writeFileSync(reportPath, generateHtmlReport(allResults));
    console.log(`  📄 HTML report saved: ${reportPath}\n`);
  }

  // Save JSON results
  const jsonPath = path.join(rootDir, 'automation', `results-${Date.now()}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(allResults, null, 2));
  console.log(`  📊 JSON results saved: ${jsonPath}\n`);

  if (server) server.close();
  process.exit(vulnerable > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(2);
});
