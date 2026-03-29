<?php
/**
 * Server-side redirect helper for SOP bypass tests.
 * Deploy on abhikafle.com.np or ebniw.com.
 *
 * Usage:
 *   /payloads/redirect.php?url=https://target.com&status=302
 *   /payloads/redirect.php?url=javascript:alert(1)&status=302
 *   /payloads/redirect.php?url=data:text/html,...&status=302
 */

$url = $_GET['url'] ?? '';
$status = intval($_GET['status'] ?? 302);

if (empty($url)) {
    http_response_code(400);
    echo 'Missing ?url= parameter';
    exit;
}

// Allow various redirect status codes
$validCodes = [301, 302, 303, 307, 308];
if (!in_array($status, $validCodes)) {
    $status = 302;
}

http_response_code($status);
header('Location: ' . $url);
header('Cache-Control: no-store');
exit;
