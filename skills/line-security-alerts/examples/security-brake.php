<?php
// Emergency brake page (optional). Copy it into your web root under any name, put its public address into
// `brake_url` and a long random `brake_secret` into the config (environment variable), and make your admin
// area ask $alerts->adminLocked($ip) on every request. URGENT alerts then end with a link to this page.
//
// Opening the link only shows a page with a button: chat apps open links to build previews, and that must
// never lock anything. The button (a POST with the signed token) locks the admin area for `brake_hours`.
// A link works once and expires. An invalid link gets "Not found". Nothing here can unlock or change
// anything else; unlocking is `--unlock` on the server. The lock is announced on the next scheduled run.

require __DIR__ . '/../lib/SecurityAlerts.php';                 // adjust to where you copied the library
$config = require __DIR__ . '/security-alerts.config.php';     // adjust to where you keep the config (outside the web root)

$alerts = new SecurityAlerts($config);
$token = isset($_POST['t']) ? (string) $_POST['t'] : (isset($_GET['t']) ? (string) $_GET['t'] : '');
$ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';   // behind a proxy/CDN: the same trusted client IP as the rest of your site
$r = $alerts->brakeRequest(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET', $token, $ip);

http_response_code($r['status']);
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Robots-Tag: noindex');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('X-Frame-Options: DENY');
echo $r['html'];
