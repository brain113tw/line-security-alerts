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
