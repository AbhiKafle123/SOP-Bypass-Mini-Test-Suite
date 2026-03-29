/**
 * SOP Bypass Mini Test Suite V2.0 - Shared Utilities
 * Hosted on: abhikafle.com.np
 * Cross-origin target: ebniw.com
 */

const CONFIG = {
    PRIMARY_DOMAIN: 'abhikafle.com.np',
    XORIGIN_DOMAIN: 'ebniw.com',
    PRIMARY_ORIGIN: 'https://abhikafle.com.np',
    XORIGIN_ORIGIN: 'https://ebniw.com',
};

/**
 * Detect browser engine and version
 */
function detectBrowser() {
    const ua = navigator.userAgent;
    let browser = 'Unknown';
    let engine = 'Unknown';
    let version = '';

    if (ua.includes('OPR/') || ua.includes('Opera')) {
        browser = 'Opera';
        engine = 'Blink';
        version = (ua.match(/OPR\/(\d+[\.\d]*)/) || [])[1] || '';
    } else if (ua.includes('Edg/')) {
        browser = 'Edge';
        engine = 'Blink';
        version = (ua.match(/Edg\/(\d+[\.\d]*)/) || [])[1] || '';
    } else if (ua.includes('Chrome/') && !ua.includes('Chromium/')) {
        browser = 'Chrome';
        engine = 'Blink';
        version = (ua.match(/Chrome\/(\d+[\.\d]*)/) || [])[1] || '';
    } else if (ua.includes('Safari/') && !ua.includes('Chrome/')) {
        browser = 'Safari';
        engine = 'WebKit';
        version = (ua.match(/Version\/(\d+[\.\d]*)/) || [])[1] || '';
    } else if (ua.includes('Firefox/')) {
        browser = 'Firefox';
        engine = 'Gecko';
        version = (ua.match(/Firefox\/(\d+[\.\d]*)/) || [])[1] || '';
    } else if (ua.includes('SamsungBrowser/')) {
        browser = 'Samsung Internet';
        engine = 'Blink';
        version = (ua.match(/SamsungBrowser\/(\d+[\.\d]*)/) || [])[1] || '';
    }

    const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);

    return { browser, engine, version, isMobile, ua };
}

/**
 * Log a test result to the output area and console
 */
function logResult(elementId, message, type) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const entry = document.createElement('div');
    entry.className = 'log-entry log-' + (type || 'info');
    const ts = new Date().toLocaleTimeString();
    entry.textContent = '[' + ts + '] ' + message;
    el.appendChild(entry);
    el.scrollTop = el.scrollHeight;
    console.log('[' + type + '] ' + message);
}

/**
 * Attempt to read a property from a cross-origin window/frame
 */
function tryCrossOriginRead(frameRef, property, label) {
    try {
        let val;
        if (property === 'document.cookie') {
            val = frameRef.document.cookie;
        } else if (property === 'document.body.innerHTML') {
            val = frameRef.document.body.innerHTML;
        } else if (property === 'document.domain') {
            val = frameRef.document.domain;
        } else if (property === 'location.href') {
            val = frameRef.location.href;
        } else {
            val = frameRef[property];
        }
        return { success: true, value: val, label: label };
    } catch (e) {
        return { success: false, error: e.message, label: label };
    }
}

/**
 * Create a standard test page header
 */
function createTestHeader(testId, title, cve, browsers, category) {
    return '<a href="../index.html" class="btn btn-back">&larr; Back to Suite</a>' +
        '<h1>' + title + '</h1>' +
        '<div class="meta">' +
        '<span>ID: ' + testId + '</span>' +
        (cve ? '<span>CVE: ' + cve + '</span>' : '') +
        '<span>Browsers: ' + browsers.join(', ') + '</span>' +
        '<span>Category: ' + category + '</span>' +
        '</div>';
}

/**
 * Report test result with visual indicator
 */
function reportResult(outputId, testName, passed, details) {
    const el = document.getElementById(outputId);
    if (!el) return;
    const color = passed ? '#3fb950' : '#f85149';
    const status = passed ? 'VULNERABLE' : 'NOT VULNERABLE (Patched/Mitigated)';
    el.innerHTML += '<div style="color:' + color + ';margin:5px 0;">' +
        '<strong>[' + status + ']</strong> ' + testName +
        (details ? '<br><span style="color:#8b949e;font-size:0.9em;">' + details + '</span>' : '') +
        '</div>';

    // Emit event for automated test runner (Playwright)
    window.__sopTestResults = window.__sopTestResults || [];
    var result = { testName: testName, passed: passed, details: details || '', timestamp: Date.now() };
    window.__sopTestResults.push(result);
    window.dispatchEvent(new CustomEvent('sop-test-result', { detail: result }));
}
