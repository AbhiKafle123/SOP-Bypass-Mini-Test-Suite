SOP Bypass Mini Test Suite V2.0
================================

Open-source browser security research suite for testing Same-Origin Policy bypasses,
Universal Cross-Site Scripting (UXSS), and URL/address bar spoofing across modern browsers.

**Primary domain:** abhikafle.com.np
**Cross-origin target:** ebniw.com

## Test Categories

### UXSS / SOP Bypass (11 tests)

| ID | Test | CVE/Reference | Browsers |
|----|------|---------------|----------|
| UXSS-CHROME-01 | Navigation API entries() Cross-Origin Leak | CVE-2022-4908 variant | Chrome, Opera, Edge |
| UXSS-CHROME-02 | Link Header Referrer Policy Leak | CVE-2025-4664 | Chrome (pre-136) |
| UXSS-CHROME-03 | Blob URL Cross-Origin Partition Bypass | Chrome 137 hardening | Chrome (pre-137) |
| UXSS-SAFARI-01 | NavigateEvent.canIntercept SOP Bypass | CVE-2026-20643 | Safari, iOS |
| UXSS-SAFARI-02 | iframe Subframe Counter Overflow | Project Zero #2099/#2100 | Safari, iOS |
| UXSS-FIREFOX-01 | Canvas2D Same-Origin Policy Bypass | CVE-2025-9180 | Firefox (pre-142) |
| UXSS-OPERA-01 | Android Intent Scheme UXSS | CVE-2025-58485 pattern | Opera, Samsung (Android) |
| UXSS-XB-01 | postMessage Null Origin Confusion | Design issue | All browsers |
| UXSS-XB-02 | Sandbox allow-scripts+allow-same-origin Escape | Design issue | All browsers |
| UXSS-XB-03 | Performance API Cross-Origin Timing Leak | Side-channel | All browsers |
| UXSS-XB-04 | window.open() Race Condition | Classic UXSS updated | All browsers |

### URL Spoofing (9 tests)

| ID | Test | CVE/Reference | Browsers |
|----|------|---------------|----------|
| SPOOF-CHROME-01 | Chrome Android Toolbar Domain Spoof | CVE-2025-14373 | Chrome Android |
| SPOOF-CHROME-02 | Chromium Omnibox UI Spoofing | CVE-2025-12435 | Chromium-based |
| SPOOF-SAFARI-01 | Blob URL Address Bar Display | Design issue | Safari, all |
| SPOOF-FIREFOX-01 | Long Hostname Address Bar Spoof | CVE-2025-23109 | Firefox iOS |
| SPOOF-OPERA-01 | RTL/Arabic Character Address Bar Spoof | CVE-2019-12278, 2023 bugs | Opera Android |
| SPOOF-OPERA-02 | Fullscreen API Fake Browser Chrome | BitM technique | Opera, Safari, all |
| SPOOF-XB-01 | Meta Refresh Rapid Redirect Race | Timing attack | All browsers |
| SPOOF-XB-02 | URL Userinfo (@) Domain Confusion | URL spec issue | Firefox, Opera |
| SPOOF-XB-03 | data: URI Tab Title Spoofing | Design issue | Firefox, Safari |

### Legacy Tests (19 tests from V1.0)

Original test suite from Rafay Baloch's Blackhat talk "Bypassing Browser Security Policies
For Fun And Profit" (2016). Covers CVE-2014-6041, CVE-2014-3160, and other 2012-2016 era bypasses.

## Setup

### Client-side only (most tests)
1. Host the files on abhikafle.com.np
2. Open `index.html` in the browser you want to test

### Server-side tests (CVE-2025-4664, redirects)
1. Deploy `payloads/collect.php` or `payloads/link-header-server.js` on ebniw.com
2. Deploy `payloads/redirect.php` on both domains
3. For long hostname tests, set up wildcard DNS: `*.abhikafle.com.np`

### Cross-origin target (ebniw.com)
Deploy `payloads/xorigin-target.html` on ebniw.com as the cross-origin target page.

## Credits

- **V2.0:** Abhi Kafle (abhikafle.com.np)
- **V1.0:** Rafay Baloch (original SOP Bypass Mini Test Suite)
- **Researchers cited:** Khalil Zhani, Tom Van Goethem, Thomas Espach, Vsevolod Kokorin, Renwa, Ryan Pickren, Google Project Zero, SquareX, Voorivex Team

## Disclaimer

This test suite is for **authorized security research and responsible disclosure only**.
Do not use against systems you do not own or have explicit permission to test.
