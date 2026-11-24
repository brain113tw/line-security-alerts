<?php
/**
 * LINE Security Alerts — a small, framework-agnostic intrusion alert module for PHP websites.
 *
 * It stays quiet while everything is normal and pushes a LINE message only when something
 * looks wrong:
 *   1. Admin logins: too many failures in an hour; a successful login from a device/network
 *      that account has never used before.
 *   2. Admin accounts: an account is created or deleted, its role/permissions, e-mail or
 *      password change, 2FA is turned off, a new passkey is added.
 *   3. Server files: new code files, code files changed or deleted, code files inside upload
 *      folders, or content that looks like a web shell / backdoor.
 *   4. Firewall / rate limiter: too many blocked requests in an hour.
 *   5. Money: a burst of manual refunds, cancelled paid orders or manual balance adjustments,
 *      or a single unusually large one.
 *   6. Your pages, read from outside (optional): a script, frame or form target from a site that was not
 *      there before, a redirect away, new links to other sites, and links or scripts that only search
 *      engines or visitors coming from Google are shown. These are changes made in the database or the
 *      settings, which the file scan cannot see.
 *
 * Announcing your own updates: `expectChanges()` (`--expect 30m` on the command line) opens a window in which
 * ordinary code-file changes are summed up in one message afterwards instead of a notice per scan. Anything
 * that looks like a backdoor is still reported at once.
 *
 * Design rules
 *   - Your application calls tiny "hooks" (loginFailed(), firewallBlocked(), …) that only append
 *     one line to a log file. They never call LINE, so they cannot slow down or break a request.
 *   - tick() (from cron every 5 minutes, or piggy-backed on normal page views) reads the logs,
 *     decides what is abnormal and sends ONE combined message.
 *   - The same finding is reported at most once per quiet window (default 6 h); at most
 *     `daily_cap` messages a day, except URGENT ones.
 *   - Telegram and Discord are built in as well. A message goes to the first channel that takes it:
 *     your own notifier → Telegram → Discord → LINE → e-mail (only the ones you set up). With
 *     `line_min_level` LINE can be kept for the alerts that matter, which are then tried there first.
 *   - First run records a baseline (admin list, devices, file fingerprints) and reports nothing.
 *   - Everything is stored as files in `state_dir`; no database tables are created.
 *   - It watches itself: a weekly "still on duty" message that carries one fingerprint of all code
 *     files (your chat history becomes an off-server reference), alerts when its records are wiped,
 *     and an optional check-in URL that an outside service watches in case the schedule stops.
 *
 * Requirements: PHP 7.4+ (tested up to 8.5), ext-json, and ext-curl or allow_url_fopen (or your own `transport` callable).
 * License: MIT. Origin: built for and battle-tested at 沂恩精緻洗衣 (EN Laundry), Taiwan.
 */

final class SecurityAlerts
{
    const LOG = 0;      // keep a record only
    const NOTICE = 1;   // worth a message
    const URGENT = 2;   // send even if the daily cap is reached
    const BRAKE_MARK = "\u{1F6D1} ";   // starts the emergency-brake line at the end of an URGENT message
    const VERSION = '1.5.0';

    /** @var array */
    private $cfg;
    /** @var resource|null */
    private $lockHandle = null;
    /** @var array  Telegram groups seen moving to a supergroup during this run: old id => new id (never stored) */
    private $tgMoved = array();
    /** @var array|null  LINE's allowance as asked during this run: array('at' => clock, 'q' => answer) */
    private $quotaMemo = null;
    /** @var array|null  built-in rules minus `disable_rules` plus `extra_rules` */
    private $rules = null;
    /** @var array  id => words for the message, for extra rules that bring their own */
    private $ruleLabels = array();
    /** @var array  ids of extra rules that were dropped (not a valid pattern) */
    private $badRules = array();
    /** @var bool  the next run scans the files whether or not a scan is due (set by expectChanges()) */
    private $forceScan = false;

    public static function defaults()
    {
        return array(
            'enabled'            => true,
            'site_name'          => 'Website',
            'language'           => 'en',          // 'en', 'zh-TW' or 'ja'
            'state_dir'          => '',            // REQUIRED. Writable, ideally outside the web root.
            'timezone'           => '',            // e.g. 'Asia/Taipei'; '' = PHP default
            /* Old sites sometimes have file or account names that are not UTF-8 (a folder made by an FTP client in
               Big5, GBK, Latin-1…). Name the encoding here (e.g. 'BIG5') and they are shown properly in messages;
               left empty, the bytes that are not UTF-8 are shown as "?". Detection works either way. */
            'input_charset'      => '',

            /* LINE Messaging API (https://developers.line.biz/) */
            'line_channel_access_token' => '',
            'line_to'            => array(),       // userId(s) "U…" or groupId(s) "C…"
            'line_api_base'      => 'https://api.line.me',   // point to a fake server in tests
            'line_timeout'       => 8,             // seconds; also used for Telegram and Discord
            /* Once a week (with the check-in) ask LINE how many messages this account has sent this month and what
               its limit is. When the limit is reached LINE stops delivering, so it is better to see it coming.
               Asked only when LINE is really in use: not when it is just a backup that sent nothing that week. */
            'line_quota_check'   => true,
            /* Which messages may use LINE (to keep its monthly allowance for what matters).
               0 = every message (default). 1 = alerts only: the "all is well" weekly check-in goes elsewhere.
               2 = URGENT alerts only: notices and the check-in go to Telegram / Discord / your notifier / e-mail.
               With 1 or 2 the messages LINE does take are tried on LINE first. When no other channel is set up,
               everything still goes to LINE rather than nowhere (and --status points it out). */
            'line_min_level'     => 0,
            /* The LINE key sits on this server. If the server is broken into, whoever reads it can message every
               friend of that official account: with the account your customers follow, that is all of them.
               Once a week (and on --status / --test-all) the module asks LINE roughly how many friends the
               account has, and above this number it warns: alerts belong in an account of their own.
               0 = do not ask. */
            'line_friends_warn'  => 20,

            /* Telegram (optional): a bot token from @BotFather and the chat to write to (a number, negative for a
               group; one id or an array). To write into one topic of a group with topics, add "/" and the topic
               number: '-1001234567890/12' (`--telegram-chats` prints these for you). No link previews. The token
               gives full control of the bot: keep it out of version control. */
            'telegram_bot_token' => '',
            'telegram_chat_id'   => '',
            'telegram_api_base'  => 'https://api.telegram.org',   // point to a fake server in tests

            /* Discord (optional): a channel webhook address (one or an array). The address IS the key: whoever has
               it can post to that channel. Mentions such as @everyone in a message never ping anybody. To post into
               one thread of the channel, or one post of a forum channel (a forum needs it), add
               ?thread_id=<its id> to the address. */
            'discord_webhook_url' => '',

            /* How messages sound and look (1.4.0).
               ring_level: messages at or above this level ring; the others arrive quietly, in the chat all the same
               (LINE: no notification; Telegram: a notification without sound; Discord: no notification, only the
               unread mark). 2 = only URGENT alerts ring (default); 1 = notices too; 0 = everything, the weekly
               check-in included. URGENT alerts and test messages always ring. E-mail is not affected; a notifier
               gets it as its third argument. */
            'ring_level'         => 2,
            /* Telegram: bold titles, the advice folded away, buttons; Discord: one coloured card per finding.
               false = plain text everywhere, as before 1.4. Whatever the rich form trips over, the plain one is sent. */
            'rich_messages'      => true,
            /* The "what to do" button / link in alerts on Telegram and Discord: 'auto' = this package's guide in your
               language (on GitHub), '' = none, or the address of your own copy. */
            'guide_url'          => 'auto',

            /* E-mail fallback (PHP mail()) */
            'mail_to'            => '',
            'mail_from'          => '',

            /* Pacing */
            'tick_seconds'       => 300,
            'quiet_hours'        => 6,
            'daily_cap'          => 10,
            'keep_days'          => 14,

            /* "Still on duty" message. A system that is silent when all is well is also silent when it is
               broken, so once every N days it says hello. 0 = never. Sent in the daytime only. */
            'heartbeat_days'     => 7,
            'heartbeat_hour'     => 9,             // not before this hour (local time), and not after 21:00

            /* Optional tamper check: a small file OUTSIDE state_dir (e.g. in your home folder). If someone
               empties state_dir to reset the detection, this file is still there and you get an URGENT alert. */
            'witness_file'       => '',

            /* Optional check-in address ("dead man's switch"), e.g. from healthchecks.io or any service that
               gives you a URL to call and warns you when the calls stop. It is requested (GET) after every
               completed run, so a dead cron job is noticed within minutes instead of a week. Treat the URL as
               a secret: it is never written to the logs or put into a message. A slow or failing check-in
               never affects the checks themselves. */
            'ping_url'           => '',
            'ping_timeout'       => 5,             // seconds

            /* Thresholds (per rolling hour unless noted). Tune them to your own traffic.
               Money amounts are in your currency; 0 turns that rule off. */
            'login_fail_hour'      => 10,
            'login_fail_ip_hour'   => 5,
            'login_new_device'     => true,
            'device_memory_days'   => 90,
            'firewall_hour'        => 50,
            'firewall_ip_hour'     => 20,
            'refund_hour_count'    => 3,
            'refund_hour_sum'      => 0,
            'refund_single'        => 0,
            'cancel_hour_count'    => 5,
            'cancel_paid_hour_sum' => 0,
            'adjust_hour_count'    => 3,
            'adjust_hour_sum'      => 0,
            'adjust_single'        => 0,

            /* Admin account snapshot (optional): callable returning
               array(username => array('role' => ..., 'perms' => ..., 'email' => ..., 'password' => <hash>, '2fa' => bool, 'passkeys' => int)) */
            'admin_snapshot'     => null,

            /* File integrity scan */
            'file_scan'          => true,
            'site_root'          => '',            // REQUIRED for the scan. Absolute path; every dir below is relative to it.
            'scan_dirs'          => array(),       // sub-dirs to scan; default = the whole site_root
            'exclude_dirs'       => array('.git', '.svn', 'node_modules'),   // e.g. your cache / compiled-template dirs
            'upload_dirs'        => array('uploads'),     // where users upload files: code files never belong here
            'runtime_dirs'       => array(),       // dirs whose code files your app rewrites itself: log only unless suspicious
            'scan_hours'         => 1,             // 0 = on every run (the scan only re-reads files whose size or times changed)
            'rehash_days'        => 7,             // every N days EVERY file is re-read, whatever its size and times say; 0 = never
            /* Optional, OFF by default: when a NEW program file (.php, .phtml, …) appears inside `upload_dirs`,
               rename it at once so the web server no longer runs it ("avatar.jpg.php" becomes
               "avatar_jpg_php-20260101-031500.quarantined", same folder). Nothing is deleted and nothing else is
               ever touched: not files outside upload_dirs, not files that were already there, not .htaccess.
               The alert names the new file name; renaming it back undoes it. */
            'quarantine_uploads' => false,
            'scan_time_budget'   => 25,            // seconds per tick; the rest continues next tick
            'max_scan_bytes'     => 2097152,
            /* Your own "looks like a backdoor" patterns, on top of the built-in ones:
               id => '/regex/'   or   id => array('pattern' => '/regex/', 'label' => 'words for the message').
               Matched against code files (not .htaccess / .user.ini). */
            'extra_rules'        => array(),
            'disable_rules'      => array(),       // ids of built-in rules to switch off (see suspiciousRules())

            /* Page watch (optional). Many break-ins on small shops change no file at all: card-skimming code is
               added to a footer setting, gambling links to an article, a redirect for visitors coming from Google
               to the database. So every `page_watch_hours` these pages are read four ways (a desktop browser, a
               phone, Google's crawler, a phone arriving from a Google search) and the sites they pull code from,
               embed, send forms to, redirect to and link to are compared with what was there before.
               Reported: a NEW site for scripts, frames, form targets or redirects (URGENT); anything that only the
               crawler or Google visitors are shown (URGENT: that is how spam injections hide from the owner);
               new links to other sites (Notice). The first check records what is there and sends nothing.
               Runs only from the scheduled job (command line), never inside a visitor's page view. */
            'page_watch'         => array(),       // full addresses of your own pages, e.g. array('https://example.com/', 'https://example.com/cart')
            'page_watch_hours'   => 1,
            'page_allow'         => array(),       // other sites your pages use on purpose, e.g. 'googletagmanager.com' (sub-domains included)
            'page_links'         => true,          // false = do not report plain new links (scripts, forms, redirects and hidden-from-you content still are)
            'page_timeout'       => 10,            // seconds per request
            'page_max_bytes'     => 2097152,

            /* Emergency brake (optional, off until both are set). URGENT alerts end with a link that locks the
               admin area for `brake_hours` — the shop itself stays open — for the owner who gets an alert at
               3 a.m. and cannot reach anyone. Opening the link only shows a page with a button (chat apps open
               links to build previews); the button locks. A link is signed, works once and expires after
               `brake_link_hours`. It can only LOCK: unlocking is `--unlock` on the server.
               Your admin area must ask adminLocked() on every request (see integration.md); without that the
               link locks nothing. */
            'brake_url'          => '',            // public address of examples/security-brake.php copied into your site
            'brake_secret'       => '',            // 32+ random characters, from an environment variable; never in a message
            'brake_hours'        => 4,
            'brake_link_hours'   => 24,
            'brake_allow_ips'    => array(),       // IPs never locked out (e.g. your developer's office), exact match

            /* Your own channel (Slack, ntfy, SMS…): function(string $text, int $level, bool $silent = false): bool.
               Tried first; when it returns false (or is not set) the message goes on to Telegram, Discord, LINE,
               then e-mail. */
            'notifier'           => null,

            /* Dependency injection (tests, custom HTTP / mail) */
            'transport'          => null,          // function(string $url, array $headers, string $body, string $method = 'POST'): array(int $status, string $body)
            'ping_transport'     => null,          // function(string $url, int $timeout): int $status
            'page_transport'     => null,          // function(string $url, array $headers, int $timeout): array(int $status, string $body, string $location)
            'renamer'            => null,          // function(string $from, string $to): bool  (used by quarantine_uploads)
            'mailer'             => null,          // function(string $to, string $subject, string $text, string $from): bool
            'clock'              => null,          // function(): int
            'sleeper'            => null,          // function(float $seconds): void  (the short wait after "too many requests")
        );
    }

    public function __construct(array $config)
    {
        $this->cfg = array_merge(self::defaults(), $config);
        if ($this->cfg['state_dir'] === '' || !is_string($this->cfg['state_dir']))
        {
            throw new InvalidArgumentException('SecurityAlerts: state_dir is required');
        }
        $this->cfg['state_dir'] = rtrim($this->cfg['state_dir'], '/\\');
        $this->cfg['state_dir'] = str_replace('\\', '/', $this->cfg['state_dir']);
        $rel = array();
        foreach ($this->cfg['scan_dirs'] ? (array) $this->cfg['scan_dirs'] : array('') as $d)
        {
            $rel[] = trim(str_replace('\\', '/', (string) $d), '/');
        }
        $this->cfg['scan_rel'] = $rel;   // relative to whichever root is walked (site_root, or a clean copy in manifest())
        if ($this->cfg['site_root'] === '' || !is_string($this->cfg['site_root']))
        {
            $this->cfg['site_root'] = '';
            $this->cfg['file_scan'] = false;
        }
        else
        {
            $root = rtrim(str_replace('\\', '/', $this->cfg['site_root']), '/');
            $this->cfg['site_root'] = $root;
            $dirs = array();
            foreach ($rel as $d)
            {
                $dirs[] = $d === '' ? $root : $root . '/' . $d;
            }
            $this->cfg['scan_dirs'] = $dirs;
        }
        if ($this->cfg['timezone'] !== '')
        {
            date_default_timezone_set($this->cfg['timezone']);
        }
    }

    /* ======================================================================
     * Hooks — call these from your application. They only append to a log.
     * ====================================================================== */

    /** A failed admin login. $knownAccount: true if the username really exists (helps the message). */
    public function loginFailed($user, $ip, $userAgent = '', $knownAccount = null)
    {
        $this->record('login_fail', array('user' => (string) $user, 'ip' => (string) $ip, 'ua' => (string) $userAgent, 'known' => $knownAccount));
    }

    /** A successful admin login. */
    public function loginSucceeded($user, $ip, $userAgent = '')
    {
        $this->record('login_ok', array('user' => (string) $user, 'ip' => (string) $ip, 'ua' => (string) $userAgent));
    }

    /**
     * Something about an admin account changed. $what: created | deleted | role | permissions |
     * email | password | 2fa_disabled | passkey_added | other.
     */
    public function accountChanged($what, $target, $actor = '', $detail = '')
    {
        $this->record('account', array('what' => (string) $what, 'target' => (string) $target, 'actor' => (string) $actor, 'detail' => (string) $detail));
    }

    /** Your firewall / WAF / rate limiter blocked a request. */
    public function firewallBlocked($ip, $rule = '', $path = '')
    {
        $this->record('firewall', array('ip' => (string) $ip, 'rule' => (string) $rule, 'path' => $this->cut((string) $path, 200)));
    }

    /** $type: refund | cancel | cancel_paid | balance_adjust. $amount: absolute value in your currency. */
    public function moneyEvent($type, $amount, $actor = '', $ref = '')
    {
        $this->record('money', array('type' => (string) $type, 'amount' => abs((float) $amount), 'actor' => (string) $actor, 'ref' => (string) $ref));
    }

    /** Anything else worth a message. Same $key = treated as the same finding (quiet window). */
    public function custom($title, array $lines = array(), $level = self::NOTICE, $key = '')
    {
        $this->record('custom', array('title' => (string) $title, 'lines' => array_values($lines), 'level' => (int) $level, 'key' => (string) $key));
    }

    /* ======================================================================
     * Periodic work
     * ====================================================================== */

    /**
     * Cheap enough to call on every page view: returns immediately unless `tick_seconds` passed.
     * From cron, call tick(true) or run().
     */
    public function tick($force = false)
    {
        if (!$this->cfg['enabled'])
        {
            return array('skipped' => 'disabled');
        }
        $stamp = $this->path('tick.txt');
        $now = $this->now();
        if (!$force && is_file($stamp) && ($now - (int) @file_get_contents($stamp)) < $this->cfg['tick_seconds'])
        {
            return array('skipped' => 'not yet');
        }
        @file_put_contents($stamp, (string) $now, LOCK_EX);
        return $this->run();
    }

    /** Runs every check now and sends what needs sending. Returns a summary (for logs/tests). */
    public function run()
    {
        if (!$this->lock())
        {
            return array('skipped' => 'another run in progress');
        }
        try
        {
            $now = $this->now();
            $this->quotaMemo = null;
            $state = $this->loadState();
            $since = isset($state['last_run']) ? (int) $state['last_run'] : 0;
            /* "fresh" = recorded since the previous run (first run: the last hour; after a long pause: at most 2 days).
               Events stamped in the same second as the previous run are read again; finding keys make that harmless. */
            $from = $since > 0 ? max($since - 1, $now - 2 * 86400) : $now - 3600;
            $events = $this->readEvents($from, $now);
            $hour = $this->readEvents($now - 3600, $now);

            $findings = array();
            $findings = array_merge($findings, $this->checkTamper($state, $now));
            $findings = array_merge($findings, $this->checkLogins($hour, $events, $state));
            $findings = array_merge($findings, $this->checkAccounts($events, $state));
            $findings = array_merge($findings, $this->checkFirewall($hour));
            $findings = array_merge($findings, $this->checkMoney($hour, $events));
            $findings = array_merge($findings, $this->checkCustom($events));
            $findings = array_merge($findings, $this->checkBrake($events));
            $scan = array('ran' => false, 'quarantined' => 0);
            if ($this->cfg['file_scan'] && $this->cfg['scan_dirs'])
            {
                $scan = $this->checkFiles($state, $now);
                $findings = array_merge($findings, $scan['findings']);
            }
            $pages = $this->checkPages($state, $now);
            $findings = array_merge($findings, $pages['findings']);

            $state['last_run'] = $now;
            $sent = $this->dispatch($findings, $state, $now);
            /* alerts that could not be delivered on an earlier run; pointless to try when this run just failed too */
            $resent = $sent === 'failed' ? 0 : $this->flushOutbox($state, $now);
            $beat = $this->heartbeat($state, $now);
            $this->saveState($state);
            $this->prune($now);
            /* Last of all, and only when everything above went through: tell the outside watcher we are alive. */
            $ping = $this->ping($state, $now);

            return array('findings' => count($findings), 'sent' => $sent, 'file_scan' => $scan['ran'] ? ($scan['complete'] ? 'complete' : 'partial') : 'not due',
                'quarantined' => (int) $scan['quarantined'], 'pages' => $pages['result'], 'resent' => $resent, 'heartbeat' => $beat, 'ping' => $ping);
        }
        finally
        {
            $this->unlock();
        }
    }

    /**
     * Sends one test message right now (ignores the quiet window and the daily cap), the way a notice would go.
     * Returns the channel that took it: 'custom' | 'telegram' | 'discord' | 'line' | 'mail' | 'failed'.
     */
    public function sendTest()
    {
        return $this->deliver($this->testMsg(), self::NOTICE, true);
    }

    /**
     * Sends the test message to EVERY channel that is set up, each on its own, so a setup mistake on one of
     * them is not hidden by the next one taking over. Read-only otherwise. Test messages always ring.
     *
     * @return array channel => array('ok' => bool, 'why' => short reason when it failed, e.g. "HTTP 401: Unauthorized",
     *               'hint' => what to do about it, in plain words)
     */
    public function testEachChannel()
    {
        $msg = $this->testMsg();
        $out = array();
        foreach (array_keys($this->channels()) as $ch)
        {
            $r = $this->sendVia($ch, $msg, self::NOTICE, true);
            $out[$ch] = array('ok' => $r[0], 'why' => $r[0] ? '' : $r[1], 'hint' => $r[0] ? '' : $this->failHint($r[2]));
        }
        return $out;
    }

    private function testMsg()
    {
        $head = $this->t('header', $this->cfg['site_name'], date('m/d H:i', $this->now()));
        return array('kind' => 'test', 'head' => $head, 'items' => array($this->item(-1, '', array($this->t('test_body')))),
            'note' => '', 'brake' => '', 'warn' => false, 'plain' => $head . "\n\n" . $this->t('test_body'));
    }

    /**
     * Every channel that is set up, checked WITHOUT sending a message: Telegram shows "typing…" for a moment in
     * the chat, Discord is asked about its webhook, LINE about its key and each recipient (a LINE push to someone
     * who blocked the account is accepted and silently dropped, so this is the only way to see it). E-mail and a
     * notifier of your own cannot be checked without sending ('ok' => null). The weekly check-in runs this when
     * there is a backup channel, because a backup is only used when the main one fails — the worst moment to find
     * out it stopped working. The answer is kept for status().
     *
     * @return array channel => array('ok' => true | false | null, 'code' => short word (see failHint()), 'why' => details)
     */
    public function checkChannels()
    {
        $this->quotaMemo = null;   // asked afresh, whatever an earlier call in this run heard
        return $this->checkAll();
    }

    /** checkChannels() without forgetting LINE's allowance as already asked during this run (the weekly check-in) */
    private function checkAll()
    {
        $out = array();
        foreach (array_keys($this->channels()) as $ch)
        {
            try
            {
                $out[$ch] = $this->checkChannel($ch);
            }
            catch (Throwable $e)
            {
                $out[$ch] = array('ok' => false, 'code' => 'other', 'why' => 'an error while checking');
            }
        }
        @file_put_contents($this->path('channels.json'), (string) $this->json(array('at' => $this->now(), 'channels' => $out)), LOCK_EX);
        return $out;
    }

    private function checkChannel($ch)
    {
        $good = array('ok' => true, 'code' => '', 'why' => '');
        if ($ch === 'telegram')
        {
            $token = trim((string) $this->cfg['telegram_bot_token']);
            if (!preg_match('/^[0-9]+:[A-Za-z0-9_-]+$/', $token))
            {
                return array('ok' => false, 'code' => 'token', 'why' => 'the bot token is not in the "123456789:ABC..." form');
            }
            $base = rtrim((string) $this->cfg['telegram_api_base'], '/') . '/bot' . $token . '/';
            $this->tgMoved = array();
            foreach ($this->listOf($this->cfg['telegram_chat_id']) as $spec)
            {
                list($chat, $topic) = $this->telegramTarget($spec);
                /* getChat: can the bot see the chat at all, and what is it. A channel cannot show "typing…": there
                   the bot (one of its admins) must still be allowed to post. Elsewhere "typing…" is what shows a
                   person who blocked the bot, or a topic that was deleted. */
                $r = $this->telegramCall($base, 'getChat', $chat, 0, array(), false);
                if ($r[0] && isset($r[5]['result']['type']) && $r[5]['result']['type'] === 'channel')
                {
                    $bot = (string) strstr($token, ':', true);
                    $m = $this->telegramCall($base, 'getChatMember', $r[4], 0, array('user_id' => PHP_INT_SIZE >= 8 ? (int) $bot : $bot), false);
                    if (!$m[0])
                    {
                        return array('ok' => false, 'code' => $m[3], 'why' => $m[1]);
                    }
                    $st = isset($m[5]['result']['status']) && is_scalar($m[5]['result']['status']) ? (string) $m[5]['result']['status'] : '';
                    if (!($st === 'creator' || ($st === 'administrator' && !empty($m[5]['result']['can_post_messages']))))
                    {
                        return array('ok' => false, 'code' => 'kicked', 'why' => 'the bot may not post in this channel (it is "' . $this->cut($this->clean($st), 20) . '" there, without "Post messages")');
                    }
                }
                elseif ($r[0])
                {
                    $r = $this->telegramCall($base, 'sendChatAction', $r[4], $topic, array('action' => 'typing'), false);
                }
                if (!$r[0])
                {
                    return array('ok' => false, 'code' => $r[3], 'why' => $r[1]);
                }
            }
            /* a group that became a supergroup: still reached (each message follows Telegram's answer), but say so */
            return $this->tgMoved ? array('ok' => true, 'code' => '', 'why' => '', 'moved' => count($this->tgMoved)) : $good;
        }
        if ($ch === 'discord')
        {
            foreach ($this->listOf($this->cfg['discord_webhook_url']) as $url)
            {
                if (!preg_match('#^https?://\S+$#i', $url))
                {
                    return array('ok' => false, 'code' => 'webhook_bad', 'why' => 'the webhook address does not start with https://');
                }
                $gone = $this->discordGone($url);
                if ($gone !== null)
                {
                    return array('ok' => false, 'code' => $gone['code'], 'why' => $this->goneWhy($gone));   // Discord: do not ask again
                }
                /* the address without ?thread_id=…: Discord describes the webhook itself */
                $r = (array) $this->http((string) preg_replace('/\?.*$/', '', $url), array($this->ua(true)), '', 'GET');
                $status = isset($r[0]) ? (int) $r[0] : 0;
                if ($status < 200 || $status >= 300)
                {
                    $resp = isset($r[1]) ? (string) $r[1] : '';
                    $code = $this->failCode('discord', $status, json_decode($resp, true));
                    if ($status === 404)
                    {
                        $this->discordGoneSet($url, $code === 'forum_thread' ? 'forum_thread' : 'webhook_gone');
                    }
                    return array('ok' => false, 'code' => $code, 'why' => $this->failReason($status, $resp));
                }
            }
            return $good;
        }
        if ($ch === 'line')
        {
            $base = rtrim((string) $this->cfg['line_api_base'], '/');
            $headers = array('Authorization: Bearer ' . (string) $this->cfg['line_channel_access_token']);
            $paths = array('/v2/bot/info');
            foreach ($this->listOf($this->cfg['line_to']) as $to)
            {
                if ($to[0] === 'U')
                {
                    $paths[] = '/v2/bot/profile/' . rawurlencode($to);   // 404 = blocked the account, or never added it
                }
                elseif ($to[0] === 'C')
                {
                    $paths[] = '/v2/bot/group/' . rawurlencode($to) . '/summary';   // 404 = the account is not in the group
                }
            }
            foreach ($paths as $i => $p)
            {
                $r = (array) $this->http($base . $p, $headers, '', 'GET');
                $status = isset($r[0]) ? (int) $r[0] : 0;
                if ($status < 200 || $status >= 300)
                {
                    $resp = isset($r[1]) ? (string) $r[1] : '';
                    $code = ($i > 0 && $status === 404) ? 'recipient_gone' : $this->failCode('line', $status, json_decode($resp, true));
                    return array('ok' => false, 'code' => $code, 'why' => $this->failReason($status, $resp));
                }
            }
            /* a backup whose monthly allowance is used up would answer every push with 429 */
            $q = $this->lineQuota();
            if ($q !== null && $q['used'] >= $q['limit'])
            {
                return array('ok' => false, 'code' => 'quota', 'why' => "this month's allowance is used up (about " . $q['used'] . ' of ' . $q['limit'] . ')');
            }
            return $good;
        }
        return array('ok' => null, 'code' => '', 'why' => '');
    }

    /**
     * For setting up telegram_chat_id: the chats that recently wrote to the bot, read with getUpdates (Telegram
     * keeps them for about a day; reading them here does not mark them as read). A person appears after pressing
     * Start, a group after a command there such as /start@YourBot (bots only see commands in groups unless their
     * privacy mode is off), a topic of a group after a command in that topic. Nothing is sent.
     *
     * @return array array('ok' => bool, 'why' => reason when not ok, 'chats' => list of
     *               array('id' => what to put into telegram_chat_id, 'type' => private | group | supergroup | channel | topic, 'name' => …),
     *               'moved' => old id => new id, for ids in telegram_chat_id that Telegram says became a supergroup)
     */
    public function telegramChats()
    {
        $token = trim((string) $this->cfg['telegram_bot_token']);
        if (!preg_match('/^[0-9]+:[A-Za-z0-9_-]+$/', $token))
        {
            return array('ok' => false, 'why' => 'telegram_bot_token is missing or not in the "123456789:ABC..." form that @BotFather gives', 'chats' => array(), 'moved' => array());
        }
        $base = rtrim((string) $this->cfg['telegram_api_base'], '/') . '/bot' . $token . '/';
        /* the configured groups that moved: asked of Telegram itself, never taken from a file */
        $moved = array();
        foreach ($this->listOf($this->cfg['telegram_chat_id']) as $spec)
        {
            list($chat) = $this->telegramTarget($spec);
            if (!isset($moved[$chat]))
            {
                $g = $this->post($base . 'getChat', (string) $this->json(array('chat_id' => $chat)));
                $new = $g[0] ? '' : $this->migratedTo($g[3]);
                if ($new !== '')
                {
                    $moved[$chat] = $new;
                }
            }
        }
        $r = (array) $this->http($base . 'getUpdates', array('Content-Type: application/json'), (string) json_encode(array('limit' => 100, 'timeout' => 0)));
        $status = isset($r[0]) ? (int) $r[0] : 0;
        $resp = isset($r[1]) ? (string) $r[1] : '';
        $j = json_decode($resp, true, 64, JSON_BIGINT_AS_STRING);
        if ($status < 200 || $status >= 300 || !is_array($j) || empty($j['ok']))
        {
            $why = $status === 409
                ? 'this bot has a webhook set, so its messages cannot be read here: remove the webhook (deleteWebhook) or ask whoever set it up'
                : $this->failReason($status, $resp) . ' - ' . $this->failHint($this->failCode('telegram', $status, $j));
            return array('ok' => false, 'why' => $why, 'chats' => array(), 'moved' => $moved);
        }
        $chats = array();
        $s = function ($v) { return is_scalar($v) ? (string) $v : ''; };
        foreach (isset($j['result']) && is_array($j['result']) ? $j['result'] : array() as $u)
        {
            foreach (array('message', 'edited_message', 'channel_post', 'my_chat_member') as $k)
            {
                if (!is_array($u) || !isset($u[$k]['chat']['id']) || !is_scalar($u[$k]['chat']['id']) || !is_array($u[$k]['chat']))
                {
                    continue;
                }
                $m = $u[$k];
                $c = $m['chat'];
                $id = (string) $c['id'];
                $name = isset($c['title']) ? $s($c['title'])
                    : trim((isset($c['first_name']) ? $s($c['first_name']) : '') . ' ' . (isset($c['last_name']) ? $s($c['last_name']) : ''));
                if ($name === '' && isset($c['username']) && $s($c['username']) !== '')
                {
                    $name = '@' . $s($c['username']);
                }
                $chats[$id] = array('id' => $id, 'type' => isset($c['type']) ? $this->clean($s($c['type'])) : '', 'name' => $this->clean($name));
                if (!empty($m['is_topic_message']) && isset($m['message_thread_id']) && is_numeric($m['message_thread_id']))
                {
                    $topic = (int) $m['message_thread_id'];
                    $tname = isset($m['reply_to_message']['forum_topic_created']['name']) ? $s($m['reply_to_message']['forum_topic_created']['name'])
                        : (isset($m['forum_topic_created']['name']) ? $s($m['forum_topic_created']['name']) : '');
                    $chats[$id . '/' . $topic] = array('id' => $id . '/' . $topic, 'type' => 'topic', 'name' => $this->clean($name . ($tname !== '' ? ' › ' . $tname : '')));
                }
                break;
            }
        }
        return array('ok' => true, 'why' => '', 'chats' => array_values($chats), 'moved' => $moved);
    }

    /** Forget all file fingerprints; the next scan records a fresh baseline silently. */
    public function resetFileBaseline()
    {
        @unlink($this->path('files.json'));
        $state = $this->loadState();
        unset($state['files_complete_at'], $state['files_baselined'], $state['files_partial'], $state['files_seen'], $state['files_upgraded'],
            $state['files_deep'], $state['files_deep_at']);
        $state['files_reset_at'] = $this->now();   // the next run tells the owner that the baseline was reset on purpose
        $this->saveState($state);
    }

    /**
     * "We are about to upload an update": opens a window of $minutes (1 to 240) in which ordinary code-file
     * changes are not reported one notice at a time. When the window closes they come as ONE message that sums
     * them up. Never covered by the window, always reported at once: content that looks like a backdoor, any
     * program inside an upload folder, a change with its modification time put back.
     *
     * When no window is open yet, every check runs first (with a file scan), so whatever changed BEFORE the
     * announcement is reported as usual and cannot slip into the window. Calling it while a window is open
     * extends that window.
     *
     * @return array array('ok' => bool, 'until' => timestamp, 'run' => what run() returned for the first check
     *               (null when an open window was extended), 'why' => reason when not ok)
     */
    public function expectChanges($minutes)
    {
        $minutes = max(1, min(240, (int) $minutes));
        if (!$this->cfg['enabled'] || !$this->cfg['file_scan'] || !$this->cfg['scan_dirs'])
        {
            return array('ok' => false, 'until' => null, 'run' => null, 'why' => 'the file scan is off (no site_root), so there is nothing to announce');
        }
        $cur = $this->expectState();
        if ($cur !== null && $this->now() <= $this->expectEnd($cur))
        {
            $cur['until'] = max((int) $cur['until'], $this->now() + $minutes * 60);
            unset($cur['end']);
            $this->saveExpect($cur);
            return array('ok' => true, 'until' => (int) $cur['until'], 'run' => null, 'why' => '');
        }
        $this->forceScan = true;
        $r = $this->run();
        $this->forceScan = false;
        if (isset($r['skipped']))
        {
            return array('ok' => false, 'until' => null, 'run' => $r, 'why' => 'another check is running right now: try again in a minute');
        }
        if ($r['file_scan'] !== 'complete')
        {
            /* a big site: the scan did not finish within scan_time_budget. Opening the window now would let the
               changes that are still unread count as "expected". */
            return array('ok' => false, 'until' => null, 'run' => $r, 'why' => 'the file scan did not finish in one go: run --expect again in a few minutes (or raise scan_time_budget)');
        }
        $now = $this->now();
        $this->saveExpect(array('from' => $now, 'until' => $now + $minutes * 60, 'files' => array(), 'more' => 0));
        $this->append('findings.ndjson', array('t' => $now, 'level' => self::LOG, 'kind' => 'system', 'key' => 'expect:open:' . $now,
            'title' => $this->t('exp_title'), 'lines' => array($this->t('exp_opened', date('m/d H:i', $now), date('H:i', $now + $minutes * 60))), 'status' => 'logged'));
        return array('ok' => true, 'until' => $now + $minutes * 60, 'run' => $r, 'why' => '');
    }

    /** Closes the update window now; the next run (call run() right after) sends the summary. @return bool false = no window was open */
    public function endExpect()
    {
        $cur = $this->expectState();
        if ($cur === null)
        {
            return false;
        }
        $cur['end'] = min($this->now(), isset($cur['end']) ? (int) $cur['end'] : PHP_INT_MAX) - 1;
        $this->saveExpect($cur);
        return true;
    }

    /**
     * Roughly how many people can receive messages from the LINE account that sends the alerts (friends minus
     * those who blocked it, as LINE counted them for yesterday, Japan time). Remembered for status().
     *
     * @return int|null null = LINE is not set up, line_friends_warn is 0, or LINE did not say
     */
    public function lineFriendCount()
    {
        $token = (string) $this->cfg['line_channel_access_token'];
        if ((int) $this->cfg['line_friends_warn'] <= 0 || $token === '' || !$this->listOf($this->cfg['line_to']))
        {
            return null;
        }
        $base = rtrim((string) $this->cfg['line_api_base'], '/');
        $headers = array('Authorization: Bearer ' . $token);
        try
        {
            /* LINE needs about a day to count a date: yesterday first, then the day before */
            for ($back = 1; $back <= 3; $back++)
            {
                $date = gmdate('Ymd', $this->now() + 9 * 3600 - $back * 86400);
                $r = (array) $this->http($base . '/v2/bot/insight/followers?date=' . $date, $headers, '', 'GET');
                $j = isset($r[0], $r[1]) && $r[0] >= 200 && $r[0] < 300 ? json_decode((string) $r[1], true) : null;
                if (!is_array($j) || !isset($j['status']))
                {
                    return null;
                }
                if ($j['status'] === 'ready' && isset($j['followers']) && is_numeric($j['followers']))
                {
                    $n = max(0, (int) $j['followers'] - (isset($j['blocks']) && is_numeric($j['blocks']) ? (int) $j['blocks'] : 0));
                    @file_put_contents($this->path('line-friends.json'), (string) $this->json(array('n' => $n, 'at' => $this->now())), LOCK_EX);
                    return $n;
                }
                if ($j['status'] !== 'unready')
                {
                    return null;
                }
            }
        }
        catch (Throwable $e)
        {
        }
        return null;
    }

    /* ----------------------------------------------------------------------
     * Emergency brake
     * ---------------------------------------------------------------------- */

    /**
     * Ask this at the top of EVERY admin request (and in the login handler), before anything else:
     *     if ($alerts->adminLocked($ip)) { http_response_code(503); exit('The admin area is locked for security.'); }
     * True while the emergency brake is on. IPs in `brake_allow_ips` are never locked out. Cheap: one small file.
     */
    public function adminLocked($ip = '')
    {
        if ($ip !== '' && in_array(trim((string) $ip), $this->listOf($this->cfg['brake_allow_ips']), true))
        {
            return false;
        }
        return $this->adminLockedUntil() !== null;
    }

    /** @return int|null until when the admin area is locked; null = not locked */
    public function adminLockedUntil()
    {
        $f = $this->cfg['state_dir'] . '/brake.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        if (!is_array($j) || !isset($j['until']) || (int) $j['until'] <= $this->now())
        {
            return null;
        }
        return (int) $j['until'];
    }

    /** Locks the admin area now (the command line's --lock, or the brake page). Returns until when. Announced on the next run. */
    public function lockAdmin($hours = null, $by = 'command', $ip = '')
    {
        $hours = max(0.25, min(72.0, (float) ($hours === null ? $this->cfg['brake_hours'] : $hours)));
        $now = $this->now();
        $until = max((int) $this->adminLockedUntil(), $now + (int) round($hours * 3600));
        @file_put_contents($this->path('brake.json'), (string) $this->json(array('until' => $until, 'at' => $now, 'by' => (string) $by)), LOCK_EX);
        $this->record('brake', array('what' => 'locked', 'by' => (string) $by, 'ip' => (string) $ip, 'until' => $until));
        return $until;
    }

    /** Ends the lock early (the command line's --unlock). Announced on the next run. @return bool false = it was not locked */
    public function unlockAdmin()
    {
        $was = $this->adminLockedUntil() !== null;
        @unlink($this->path('brake.json'));
        if ($was)
        {
            $this->record('brake', array('what' => 'unlocked', 'by' => 'command', 'ip' => '', 'until' => 0));
        }
        return $was;
    }

    /**
     * The brake page: everything examples/security-brake.php needs. GET (or HEAD) only shows what the button
     * does — chat apps open links to make previews, so opening must never lock. POST with a valid token locks.
     * An invalid token gets a plain "not found": the page tells a stranger nothing.
     *
     * @return array array('status' => HTTP status, 'html' => a small complete page, 'locked' => bool)
     */
    public function brakeRequest($method, $token, $ip = '')
    {
        $method = strtoupper((string) $method);
        $site = htmlspecialchars((string) $this->cfg['site_name'], ENT_QUOTES, 'UTF-8');
        $page = function ($status, $body, $locked = false) use ($site) {
            $html = '<!doctype html><html lang="' . ($this->cfg['language'] === 'zh-TW' ? 'zh-Hant-TW' : ($this->cfg['language'] === 'ja' ? 'ja' : 'en')) . '"><head><meta charset="utf-8">'
                . '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
                . '<title>' . htmlspecialchars($this->t('brake_title'), ENT_QUOTES, 'UTF-8') . '</title>'
                . '<style>body{font:1.125rem/1.6 system-ui,sans-serif;max-width:34rem;margin:2rem auto;padding:0 1rem}'
                . 'button{font:inherit;padding:.8rem 1.4rem;border:0;border-radius:.5rem;background:#b42318;color:#fff;cursor:pointer}</style>'
                . '</head><body><h1>' . htmlspecialchars($this->t('brake_title'), ENT_QUOTES, 'UTF-8') . '</h1><p><strong>' . $site . '</strong></p>' . $body . '</body></html>';
            return array('status' => $status, 'html' => $html, 'locked' => $locked);
        };
        $check = $this->brakeToken((string) $token);
        if ($check === 'bad' || !$this->brakeReady())
        {
            return array('status' => 404, 'html' => '<!doctype html><title>Not found</title><p>Not found.</p>', 'locked' => false);
        }
        $when = function ($t) { return date('m/d H:i', (int) $t); };
        if ($check === 'expired')
        {
            return $page(410, '<p>' . htmlspecialchars($this->t('brake_expired', (int) $this->cfg['brake_link_hours']), ENT_QUOTES, 'UTF-8') . '</p>');
        }
        $until = $this->adminLockedUntil();
        if ($check === 'used')
        {
            return $page(409, '<p>' . htmlspecialchars($until !== null ? $this->t('brake_used', $when($until)) : $this->t('brake_used_open'), ENT_QUOTES, 'UTF-8') . '</p>', $until !== null);
        }
        if ($method !== 'POST')
        {
            return $page(200, '<p>' . htmlspecialchars($this->t('brake_confirm', (int) $this->cfg['brake_hours']), ENT_QUOTES, 'UTF-8') . '</p>'
                . ($until !== null ? '<p>' . htmlspecialchars($this->t('brake_already', $when($until)), ENT_QUOTES, 'UTF-8') . '</p>' : '')
                . '<form method="post"><input type="hidden" name="t" value="' . htmlspecialchars((string) $token, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="submit">' . htmlspecialchars($this->t('brake_button', (int) $this->cfg['brake_hours']), ENT_QUOTES, 'UTF-8') . '</button></form>');
        }
        $this->brakeTokenUse((string) $token);
        $until = $this->lockAdmin(null, 'link', (string) $ip);
        return $page(200, '<p>' . htmlspecialchars($this->t('brake_done', $when($until)), ENT_QUOTES, 'UTF-8') . '</p>', true);
    }

    /** A fresh brake link (valid `brake_link_hours`, once), or '' when the brake is not set up. */
    public function brakeLink()
    {
        if (!$this->brakeReady())
        {
            return '';
        }
        $exp = $this->now() + (int) round(max(1.0, (float) $this->cfg['brake_link_hours']) * 3600);
        $nonce = bin2hex(random_bytes(8));
        $url = trim((string) $this->cfg['brake_url']);
        return $url . (strpos($url, '?') === false ? '?' : '&') . 't=' . $exp . '.' . $nonce . '.' . $this->brakeSign($exp, $nonce);
    }

    private function brakeReady()
    {
        return preg_match('#^https?://\S+$#i', trim((string) $this->cfg['brake_url'])) && strlen((string) $this->cfg['brake_secret']) >= 32;
    }

    private function brakeSign($exp, $nonce)
    {
        return substr(hash_hmac('sha256', 'brake|' . (int) $exp . '|' . $nonce, (string) $this->cfg['brake_secret']), 0, 32);
    }

    /** @return string 'ok' | 'expired' | 'used' | 'bad' */
    private function brakeToken($token)
    {
        if (!$this->brakeReady() || !preg_match('/^([0-9]{9,11})\.([0-9a-f]{16})\.([0-9a-f]{32})$/', $token, $m)
            || !hash_equals($this->brakeSign((int) $m[1], $m[2]), $m[3]))
        {
            return 'bad';
        }
        if ((int) $m[1] < $this->now())
        {
            return 'expired';
        }
        $used = $this->brakeUsed();
        return isset($used[$m[2]]) ? 'used' : 'ok';
    }

    private function brakeUsed()
    {
        $f = $this->cfg['state_dir'] . '/brake-used.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        $out = array();
        foreach (is_array($j) ? $j : array() as $nonce => $exp)
        {
            if ((int) $exp >= $this->now()) { $out[(string) $nonce] = (int) $exp; }   // expired links need no memory
        }
        return $out;
    }

    private function brakeTokenUse($token)
    {
        if (preg_match('/^([0-9]+)\.([0-9a-f]{16})\./', $token, $m))
        {
            $used = $this->brakeUsed();
            $used[$m[2]] = (int) $m[1];
            @file_put_contents($this->path('brake-used.json'), (string) $this->json($used), LOCK_EX);
        }
    }

    /** The brake was pulled or released since the last run: say so (URGENT: someone judged it an emergency). */
    private function checkBrake(array $fresh)
    {
        $out = array();
        foreach ($fresh as $e)
        {
            if ($e['k'] !== 'brake')
            {
                continue;
            }
            $d = $e['d'];
            if ($d['what'] === 'locked')
            {
                $out[] = $this->finding('brake', 'brake:lock:' . $e['t'], self::URGENT, $this->t('brake_locked_title'),
                    array($this->t($d['by'] === 'link' ? 'brake_locked_link' : 'brake_locked_cmd', date('m/d H:i', $e['t']), date('m/d H:i', (int) $d['until']),
                        $d['ip'] !== '' ? $d['ip'] : '?'), $this->hint('brake_locked_hint')), 1);
            }
            else
            {
                $out[] = $this->finding('brake', 'brake:unlock:' . $e['t'], self::NOTICE, $this->t('brake_unlocked_title'),
                    array($this->t('brake_unlocked_body', date('m/d H:i', $e['t']))), 1);
            }
        }
        return $out;
    }

    /**
     * Reads every page in `page_watch` now, the four ways the page watch does, and lists the other sites each
     * one uses. For looking at what the baseline will be (or was) made of: the first check trusts what is there,
     * so links that are already hidden from you would become "normal". Nothing is sent and nothing is saved.
     * Not time-limited: call it from the command line.
     *
     * @return array url => array(
     *     'views'    => view => array(category => sorted list of sites) or a reason string when that view failed,
     *     'only_bots' => category => sites that the crawler or Google visitors get but the browser and phone do not,
     *     'outside'  => category => sites that are neither this site nor in page_allow, in any view)
     *   view: browser | mobile | crawler | from_google; category: script | frame | form | redirect | link
     */
    public function pagesNow()
    {
        $out = array();
        foreach ($this->listOf($this->cfg['page_watch']) as $url)
        {
            $got = $this->readPage($url);
            $views = array();
            foreach ($got['views'] as $v => $cats)
            {
                $views[$v] = array();
                foreach ($cats as $cat => $hosts)
                {
                    $list = array_keys($hosts);
                    sort($list, SORT_STRING);
                    $views[$v][$cat] = $list;
                }
            }
            foreach ($got['why'] as $v => $why)
            {
                $views[$v] = $why;
            }
            $outside = array();
            foreach ($got['views'] as $cats)
            {
                foreach ($cats as $cat => $hosts)
                {
                    foreach ($hosts as $h => $_)
                    {
                        if (!$this->allowedHost($h, $url)) { $outside[$cat][$h] = true; }
                    }
                }
            }
            $only = array();
            foreach ($this->hiddenFromOwner($got['views'], $url) as $cat => $hosts)
            {
                $only[$cat] = array_keys($hosts);
            }
            $out[$url] = array('views' => $views, 'only_bots' => $only, 'outside' => array_map('array_keys', $outside));
        }
        return $out;
    }

    /**
     * One fingerprint for the whole recorded baseline: SHA-256 over the list "<file hash>  <path>" of every
     * code file, sorted by path. The weekly check-in prints its short form, so the owner's chat history is a
     * copy of it that nobody on the server can rewrite.
     *
     * @return array|null array('code' => 'xxxx-xxxx-xxxx-xxxx', 'full' => 64 hex, 'files' => int); null = no baseline yet
     */
    public function fingerprint()
    {
        $rows = array();
        foreach ($this->loadBase() as $rel => $row)
        {
            $rows[$rel] = isset($row['h']) ? (string) $row['h'] : '';
        }
        if (!$rows)
        {
            return null;
        }
        $fp = self::fingerprintOf(self::manifestText($rows));
        $fp['files'] = count($rows);
        return $fp;
    }

    /**
     * The same list computed from the files as they are on disk right now, in `sha256sum` format
     * ("<hash>  <path>\n", sorted by path). $root = another copy of the site (e.g. the clean source on your
     * own computer); default = site_root. `scan_dirs` and `exclude_dirs` apply relative to that root.
     * fingerprintOf(manifest()) of a clean copy must equal fingerprint() of the server; when it does not,
     * compare the two lists to see which files differ.
     */
    public function manifest($root = null)
    {
        $rows = array();
        foreach ($this->filesIn($root) as $rel => $f)
        {
            if (!$this->isCodeFile($rel) || isset($rows[$rel]))
            {
                continue;
            }
            $hash = @hash_file('sha256', $f->getPathname());
            if ($hash !== false)
            {
                $rows[$rel] = $hash;   // unreadable files are left out, exactly as the scan leaves them out
            }
        }
        return self::manifestText($rows);
    }

    /** @param array $rows path => file hash */
    public static function manifestText(array $rows)
    {
        $paths = array_map('strval', array_keys($rows));
        sort($paths, SORT_STRING);
        $out = '';
        foreach ($paths as $rel)
        {
            $out .= $rows[$rel] . '  ' . $rel . "\n";
        }
        return $out;
    }

    /** @return array array('code' => first 16 hex digits in groups of four, 'full' => all 64) */
    public static function fingerprintOf($manifestText)
    {
        $full = hash('sha256', (string) $manifestText);
        return array('code' => implode('-', str_split(substr($full, 0, 16), 4)), 'full' => $full);
    }

    /**
     * Reads EVERY code file and checks it against the current rules, whatever the baseline says. Use it once
     * right after installing (the first run trusts what is already on the server — a backdoor that was there
     * before becomes part of the baseline) and after adding rules. It only reads; nothing is sent or changed.
     * Not time-limited, so call it from the command line.
     *
     * @return array path => array('ids' => rule ids, 'why' => the same in words)
     */
    public function audit()
    {
        $out = array();
        if ($this->cfg['site_root'] === '')
        {
            return $out;
        }
        foreach ($this->filesIn() as $rel => $f)
        {
            if (!$this->isCodeFile($rel) || isset($out[$rel]))
            {
                continue;
            }
            $ids = $this->scanContent($f->getPathname(), $rel);
            $inUpload = $this->inDirList($rel, $this->cfg['upload_dirs']);
            if ($ids || $inUpload)
            {
                $out[$rel] = array('ids' => $ids, 'why' => $this->why($ids, $inUpload));
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    /** Ids of `extra_rules` entries that were ignored because the pattern does not compile. */
    public function ignoredRules()
    {
        $this->rules();
        return $this->badRules;
    }

    /**
     * Where things stand right now, for the person who installed it or is asked "is it still working?".
     * Read-only: nothing is sent, nothing is changed. No token, recipient or chat id, webhook or check-in address
     * is included: only how many there are.
     *
     * @param  int $recent how many of the latest findings to include
     * @return array see the keys below; 'problems' lists what needs a look (empty = fine)
     */
    public function status($recent = 10)
    {
        $now = $this->now();
        $dir = $this->cfg['state_dir'];
        $state = is_file($dir . '/state.json') ? json_decode((string) @file_get_contents($dir . '/state.json'), true) : array();
        if (!is_array($state))
        {
            $state = array();
        }
        $hb = $this->tally($state, $now);
        $box = isset($state['outbox']) && is_array($state['outbox']) ? array_values($state['outbox']) : array();
        $scan = (bool) $this->cfg['file_scan'];
        $fp = ($scan && !empty($state['files_baselined'])) ? $this->fingerprint() : null;
        $days = (int) $this->cfg['heartbeat_days'];
        $on = $this->channels();
        $line = isset($on['line']);
        $out = array(
            'now'          => $now,
            'site_name'    => (string) $this->cfg['site_name'],
            'enabled'      => (bool) $this->cfg['enabled'],
            'installed_at' => !empty($state['installed_at']) ? (int) $state['installed_at'] : null,
            'last_run'     => !empty($state['last_run']) ? (int) $state['last_run'] : null,
            'delivery'     => array(
                'notifier' => isset($on['custom']),
                'telegram' => isset($on['telegram']),
                'telegram_chats' => isset($on['telegram']) ? count($this->listOf($this->cfg['telegram_chat_id'])) : 0,
                'discord' => isset($on['discord']),
                'discord_webhooks' => isset($on['discord']) ? count($this->listOf($this->cfg['discord_webhook_url'])) : 0,
                'line' => $line,
                'line_recipients' => $line ? count($this->listOf($this->cfg['line_to'])) : 0,
                'mail' => isset($on['mail']),
                'line_min_level' => (int) $this->cfg['line_min_level'],
                /* the order channels are tried in, for each kind of message (only the ones set up) */
                'route' => array('urgent' => $this->route(self::URGENT), 'notice' => $this->route(self::NOTICE), 'checkin' => $this->route(self::LOG)),
            ),
            'sent_today'   => (isset($state['push_day']) && $state['push_day'] === date('Y-m-d', $now)) ? (int) $state['push_count'] : 0,
            'daily_cap'    => (int) $this->cfg['daily_cap'],
            'waiting'      => array('count' => count($box), 'oldest' => $box && isset($box[0]['t']) ? (int) $box[0]['t'] : null),
            'files'        => array(
                'scan' => $scan,
                'watched' => isset($state['files_count']) ? (int) $state['files_count'] : 0,
                'baseline_ready' => !empty($state['files_baselined']),
                'last_scan' => !empty($state['files_complete_at']) ? (int) $state['files_complete_at'] : null,
                'scan_unfinished' => !empty($state['files_partial']),
                'last_full_reread' => !empty($state['files_deep_at']) ? (int) $state['files_deep_at'] : null,
                'fingerprint' => is_array($fp) ? $fp['code'] : null,
                'fingerprint_at_last_checkin' => isset($state['hb_fp']) ? (string) $state['hb_fp'] : null,
            ),
            'checkin'      => array(
                'every_days' => $days,
                'counting_since' => (int) $hb['at'],
                'next_due' => $days > 0 ? (int) $hb['at'] + $days * 86400 : null,
                'runs' => (int) $hb['runs'], 'reported' => (int) $hb['sent'], 'urgent' => (int) $hb['urgent'],
            ),
            'outside_checkin' => array(
                'configured' => trim((string) $this->cfg['ping_url']) !== '',
                'failing' => isset($state['ping_fail']['n']) ? (int) $state['ping_fail']['n'] : 0,
                'failing_since' => isset($state['ping_fail']['since']) ? (int) $state['ping_fail']['since'] : null,
            ),
            'pages'        => $this->pagesStatus(),
            'brake'        => array('ready' => $this->brakeReady(), 'locked_until' => $this->adminLockedUntil()),
            'expect'       => null,
            /* the last answer from lineFriendCount(): array('n' => about how many friends, 'at' => when asked) */
            'line_friends' => null,
            /* the last checkChannels(): array('at' => when, 'channels' => channel => array('ok', 'code', 'why')) */
            'channels'     => null,
            /* how many ids in telegram_chat_id were groups that became supergroups, at the last channel check (each
               message follows Telegram's answer to the new id; telegramChats() asks Telegram and names both) */
            'telegram_moved' => 0,
            /* Discord webhooks (of discord_webhook_url) that Discord said do not exist: when it said so, oldest first */
            'discord_gone' => array(),
            'recent'       => array(),
            'problems'     => array(),
        );
        /* the latest findings: read only the end of the file */
        $log = $dir . '/findings.ndjson';
        if ($recent > 0 && is_file($log) && ($fh = @fopen($log, 'rb')))
        {
            $size = (int) filesize($log);
            fseek($fh, max(0, $size - 131072));
            $lines = explode("\n", trim((string) stream_get_contents($fh)));
            fclose($fh);
            if ($size > 131072)
            {
                array_shift($lines);   // the first line is probably cut in half
            }
            foreach (array_slice($lines, -$recent) as $l)
            {
                $e = json_decode($l, true);
                if (is_array($e) && isset($e['t'], $e['title']))
                {
                    $out['recent'][] = array('t' => (int) $e['t'], 'level' => isset($e['level']) ? (int) $e['level'] : 0,
                        'title' => (string) $e['title'], 'status' => isset($e['status']) ? (string) $e['status'] : '');
                }
            }
        }
        /* what deserves a look */
        $p = array();
        if (!$out['enabled']) { $p[] = 'the module is switched off (enabled = false)'; }
        if (!is_dir($dir) || !is_writable($dir)) { $p[] = 'the state folder is missing or not writable'; }
        $stale = max(900, 3 * (int) $this->cfg['tick_seconds']);
        if ($out['last_run'] === null) { $p[] = 'the checks have never run here'; }
        elseif ($now - $out['last_run'] > $stale) { $p[] = 'no check for ' . (int) round(($now - $out['last_run']) / 60) . ' minutes: is the scheduled job still there?'; }
        $chat = array_values(array_diff(array_keys($on), array('custom', 'mail')));   // the chat apps that are set up
        $names = array('custom' => 'your notifier', 'telegram' => 'Telegram', 'discord' => 'Discord', 'line' => 'LINE', 'mail' => 'e-mail');
        if (!$on) { $p[] = 'nowhere to send alerts: no LINE, Telegram or Discord, no e-mail, no notifier'; }
        elseif (!isset($on['custom']) && !isset($on['mail']) && count($chat) === 1) { $p[] = 'no fallback e-mail (mail_to): when ' . $names[$chat[0]] . ' refuses, alerts wait instead of arriving'; }
        $min = (int) $this->cfg['line_min_level'];
        if ($min > 0 && $line && count($on) === 1)
        {
            $p[] = 'line_min_level is ' . $min . ', but no other channel is set up (Telegram, Discord, notifier or e-mail): every message still goes to LINE';
        }
        elseif ($min > 0 && !$line && $on)
        {
            $first = $this->route(self::URGENT);
            $p[] = 'line_min_level is ' . $min . ', but LINE is not set up: urgent alerts go to ' . $names[$first[0]] . ' like everything else';
        }
        $cf = $dir . '/channels.json';
        $cj = is_file($cf) ? json_decode((string) @file_get_contents($cf), true) : null;
        if (is_array($cj) && isset($cj['channels']) && is_array($cj['channels']))
        {
            $at = isset($cj['at']) && is_numeric($cj['at']) ? (int) $cj['at'] : 0;
            $out['channels'] = array('at' => $at, 'channels' => $cj['channels']);
            foreach ($cj['channels'] as $ch => $h)
            {
                if (!isset($on[$ch], $names[$ch]) || !is_array($h))
                {
                    continue;
                }
                if (isset($h['ok']) && $h['ok'] === false)
                {
                    $hint = $this->failHint(isset($h['code']) && is_scalar($h['code']) ? (string) $h['code'] : '');
                    $p[] = $names[$ch] . ' does not work (checked ' . date('m/d H:i', $at) . '): '
                        . ($hint !== '' ? $hint : (isset($h['why']) && is_scalar($h['why']) ? (string) $h['why'] : 'it refused'));
                }
                if ($ch === 'telegram' && isset($h['moved']) && is_numeric($h['moved']) && (int) $h['moved'] > 0)
                {
                    $out['telegram_moved'] = (int) $h['moved'];
                    /* no ids here (status never shows one): --telegram-chats asks Telegram and prints the old and the new id */
                    $p[] = 'a Telegram group in telegram_chat_id became a supergroup and has a new id (seen ' . date('m/d H:i', $at)
                        . '); alerts still reach it. Run --telegram-chats to see the new id and put it into telegram_chat_id';
                }
            }
        }
        $gone = array('webhook_gone' => array(), 'forum_thread' => array());
        foreach ($this->listOf($this->cfg['discord_webhook_url']) as $url)
        {
            $g = $this->discordGone($url);
            if ($g !== null)
            {
                $out['discord_gone'][] = $g['at'];
                $gone[$g['code']][] = $g['at'];
            }
        }
        sort($out['discord_gone']);
        if ($gone['webhook_gone'])
        {
            $p[] = 'Discord said on ' . date('m/d H:i', min($gone['webhook_gone'])) . ' that a webhook in discord_webhook_url does not exist: create a new one and put its address in (Discord asks that the old one is not tried again, so it is not)';
        }
        if ($gone['forum_thread'])
        {
            $p[] = 'Discord said on ' . date('m/d H:i', min($gone['forum_thread'])) . ' that the thread named by ?thread_id= in discord_webhook_url does not exist: put the right thread id in (the address is not tried again until it changes)';
        }
        if ($out['waiting']['count'] > 0) { $p[] = $out['waiting']['count'] . ' alert(s) could not be delivered yet and are waiting to be re-sent'; }
        if ($out['outside_checkin']['failing'] >= 3) { $p[] = 'the outside check-in address has failed ' . $out['outside_checkin']['failing'] . ' times in a row'; }
        if ($scan && !$out['files']['baseline_ready'] && $out['last_run'] !== null) { $p[] = 'the file baseline is not complete yet'; }
        if ($this->cfg['site_root'] === '') { $p[] = 'file scan is off (site_root is not set)'; }
        if (trim((string) $this->cfg['brake_url']) !== '' && !$this->brakeReady())
        {
            $p[] = 'brake_url is set, but brake_secret is missing or shorter than 32 characters (or the address is not http/https): no emergency-brake link is added';
        }
        if ($out['brake']['locked_until'] !== null)
        {
            $p[] = 'the admin area is LOCKED by the emergency brake until ' . date('Y-m-d H:i', $out['brake']['locked_until']) . ' (--unlock ends it early)';
        }
        $exp = $this->expectState();
        if ($exp !== null)
        {
            $n = $this->expectCounts($exp);
            $out['expect'] = array('from' => (int) $exp['from'], 'until' => $this->expectEnd($exp), 'open' => $now <= $this->expectEnd($exp),
                'new' => $n[0], 'changed' => $n[1], 'deleted' => $n[2]);
        }
        $pg = $out['pages'];
        if ($pg['watched'] > 0)
        {
            if ($pg['checked'] === 0 && !empty($state['pages_web_only']))
            {
                $p[] = 'page_watch is set but no page has been read yet: it runs only when the checks are started from the command line (php …), not from a page view';
            }
            foreach ($pg['failing'] as $f)
            {
                if ($f['times'] >= 3)
                {
                    $p[] = 'page ' . $f['page'] . ': the ' . $f['view'] . ' view could not be read ' . $f['times'] . ' times in a row (' . $f['why'] . ')'
                        . ($f['view'] === 'crawler' ? '; a firewall that blocks fake search-engine visits does this: that view is then skipped' : '');
                }
            }
        }
        $fr = $this->path('line-friends.json');
        $j = is_file($fr) ? json_decode((string) @file_get_contents($fr), true) : null;
        if ($line && is_array($j) && isset($j['n'], $j['at']))
        {
            $out['line_friends'] = array('n' => (int) $j['n'], 'at' => (int) $j['at']);
            $warn = (int) $this->cfg['line_friends_warn'];
            if ($warn > 0 && (int) $j['n'] > $warn)
            {
                $p[] = 'the LINE account that sends the alerts has about ' . (int) $j['n'] . ' friends: its key is on this server, and whoever breaks in can message all of them. Use an official account of its own for alerts';
            }
        }
        $out['problems'] = $p;
        return $out;
    }

    /* ======================================================================
     * Checks
     * ====================================================================== */

    private function checkLogins(array $hour, array $fresh, array &$state)
    {
        $out = array();
        $fails = array_values(array_filter($hour, function ($e) { return $e['k'] === 'login_fail'; }));
        if ($fails)
        {
            $byIp = array();
            $real = array();
            $other = array();
            foreach ($fails as $e)
            {
                $ip = $e['d']['ip'];
                $byIp[$ip] = isset($byIp[$ip]) ? $byIp[$ip] + 1 : 1;
                if ($e['d']['known'] === true)
                {
                    $real[$e['d']['user']] = true;
                }
                elseif ($e['d']['user'] !== '')
                {
                    $other[strtolower($e['d']['user'])] = true;
                }
            }
            arsort($byIp);
            $total = count($fails);
            $topN = reset($byIp);
            if ($total >= $this->cfg['login_fail_hour'] || $topN >= $this->cfg['login_fail_ip_hour'])
            {
                $lines = array($this->t('login_fail_body', $total, count($byIp)));
                $i = 0;
                foreach ($byIp as $ip => $n)
                {
                    if (++$i > 3) { break; }
                    $lines[] = $this->t('ip_count', $ip, $n);
                }
                if ($real)
                {
                    $lines[] = $this->t('login_fail_real', implode(', ', array_slice(array_keys($real), 0, 5)));
                }
                if ($other)
                {
                    $lines[] = $this->t('login_fail_other', count($other));
                }
                $big = $total >= $this->cfg['login_fail_hour'] * 3;
                $out[] = $this->finding('login', 'login_fail', $big ? self::URGENT : self::NOTICE, $this->t('login_fail_title'), $lines);
            }
        }

        if ($this->cfg['login_new_device'])
        {
            /* Per account we remember the networks (IPv4 /24, IPv6 /48) and the exact browsers it signed in from.
               A login is "new" only when BOTH are unfamiliar: a staff member on mobile data (new network, same
               browser) or on a new phone at the office (new browser, same network) stays quiet. */
            $devices = isset($state['devices']) && is_array($state['devices']) ? $state['devices'] : array();
            $forget = (int) $this->cfg['device_memory_days'] * 86400;
            foreach ($fresh as $e)
            {
                if ($e['k'] !== 'login_ok')
                {
                    continue;
                }
                $u = strtolower($e['d']['user']);
                $net = $this->ipPrefix($e['d']['ip']);
                $ua = substr(sha1($e['d']['ua']), 0, 16);   // a short lookup key for "same browser", not a security fingerprint
                $mem = isset($devices[$u]) ? $devices[$u] : null;
                if ($mem)
                {
                    foreach (array('n', 'b') as $f)
                    {
                        foreach ($mem[$f] as $k => $t)
                        {
                            if ($e['t'] - $t > $forget) { unset($mem[$f][$k]); }
                        }
                    }
                }
                $isNew = $mem !== null && !isset($mem['n'][$net]) && !isset($mem['b'][$ua]);
                if ($mem === null)
                {
                    $mem = array('n' => array(), 'b' => array());   // first login we ever see for this account: learn it
                }
                $mem['n'][$net] = $e['t'];
                $mem['b'][$ua] = $e['t'];
                foreach (array('n', 'b') as $f)
                {
                    if (count($mem[$f]) > 30)
                    {
                        asort($mem[$f]);
                        $mem[$f] = array_slice($mem[$f], -30, null, true);
                    }
                }
                $devices[$u] = $mem;
                if ($isNew)
                {
                    $out[] = $this->finding('login', 'newdev:' . $u . ':' . $net . ':' . $ua, self::NOTICE, $this->t('new_device_title', $e['d']['user']),
                        array($this->t('new_device_body', $this->uaLabel($e['d']['ua']), $e['d']['ip'], date('m/d H:i', $e['t'])), $this->hint('new_device_hint')));
                }
            }
            $state['devices'] = $devices;
        }
        return $out;
    }

    private function checkAccounts(array $fresh, array &$state)
    {
        $out = array();
        foreach ($fresh as $e)
        {
            if ($e['k'] !== 'account')
            {
                continue;
            }
            $d = $e['d'];
            $urgent = in_array($d['what'], array('created', 'role', 'permissions', '2fa_disabled'), true);
            $lines = array($this->t('acct_line', $d['target'], $this->t('acct_' . $d['what']), $d['actor'] !== '' ? $d['actor'] : '?'));
            if ($d['detail'] !== '')
            {
                $lines[] = $d['detail'];
            }
            $out[] = $this->finding('account', 'acct:' . $d['what'] . ':' . $d['target'] . ':' . $e['t'], $urgent ? self::URGENT : self::NOTICE,
                $this->t('acct_title'), $lines, 1);
        }

        /* Optional snapshot diff: catches changes made outside your admin UI (direct DB edits, a second admin tool…). */
        if (is_callable($this->cfg['admin_snapshot']))
        {
            $now = array();
            $raw = array();   // the values the fingerprints are made of; kept in memory only, for old-format records
            foreach ((array) call_user_func($this->cfg['admin_snapshot']) as $name => $row)
            {
                $row = (array) $row;
                $name = $this->cleanId((string) $name);
                $raw[$name] = array(
                    'perms'    => isset($row['perms']) ? (is_array($row['perms']) ? implode(',', $row['perms']) : (string) $row['perms']) : null,
                    'email'    => isset($row['email']) ? strtolower(trim((string) $row['email'])) : null,
                    'password' => isset($row['password']) ? (string) $row['password'] : null,
                );
                $now[$name] = array(
                    'role'     => isset($row['role']) ? $this->clean((string) $row['role']) : '',
                    'perms'    => $raw[$name]['perms'] === null ? '' : hash('sha256', $raw[$name]['perms']),
                    'email'    => $raw[$name]['email'] === null ? '' : hash('sha256', $raw[$name]['email']),
                    'password' => $raw[$name]['password'] === null ? '' : hash('sha256', $raw[$name]['password']),
                    '2fa'      => !empty($row['2fa']),
                    'passkeys' => isset($row['passkeys']) ? (int) $row['passkeys'] : 0,
                );
            }
            if (!isset($state['admins']))
            {
                $state['admins'] = $now;   // baseline
            }
            else
            {
                $was = (array) $state['admins'];
                foreach ($now as $name => $r)
                {
                    if (!isset($was[$name]))
                    {
                        $out[] = $this->finding('account', 'snap:new:' . $name, self::URGENT, $this->t('acct_title'), array($this->t('snap_new', $name)));
                        continue;
                    }
                    $o = (array) $was[$name];
                    $changes = array();
                    $diff = array();
                    foreach (array('role', 'perms', 'email', 'password') as $f)
                    {
                        $before = isset($o[$f]) ? (string) $o[$f] : '';
                        if ($f !== 'role' && strlen($before) === 40)
                        {
                            /* A record written by an earlier build (SHA-1). Compare in the old format so the
                               upgrade does not look like "everything changed"; it is stored as SHA-256 below. */
                            $diff[$f] = $before !== ($raw[$name][$f] === null ? '' : sha1($raw[$name][$f]));
                        }
                        else
                        {
                            $diff[$f] = $before !== $r[$f];
                        }
                        if ($diff[$f]) { $changes[] = $this->t('acct_' . ($f === 'perms' ? 'permissions' : $f)); }
                    }
                    if (!empty($o['2fa']) && empty($r['2fa'])) { $changes[] = $this->t('acct_2fa_disabled'); }
                    if ($r['passkeys'] > (isset($o['passkeys']) ? (int) $o['passkeys'] : 0)) { $changes[] = $this->t('acct_passkey_added'); }
                    if ($changes)
                    {
                        $lvl = ($diff['role'] || $diff['perms'] || (!empty($o['2fa']) && empty($r['2fa']))) ? self::URGENT : self::NOTICE;
                        $out[] = $this->finding('account', 'snap:chg:' . $name . ':' . md5((string) $this->json($r)), $lvl, $this->t('acct_title'),
                            array($this->t('snap_changed', $name, implode($this->t('name_sep'), $changes))));
                    }
                }
                foreach ($was as $name => $r)
                {
                    if (!isset($now[$name]))
                    {
                        $out[] = $this->finding('account', 'snap:del:' . $name, self::NOTICE, $this->t('acct_title'), array($this->t('snap_deleted', $name)));
                    }
                }
                $state['admins'] = $now;
            }
        }
        return $out;
    }

    private function checkFirewall(array $hour)
    {
        $blocks = array_values(array_filter($hour, function ($e) { return $e['k'] === 'firewall'; }));
        if (!$blocks)
        {
            return array();
        }
        $byIp = array();
        $byRule = array();
        foreach ($blocks as $e)
        {
            $byIp[$e['d']['ip']] = isset($byIp[$e['d']['ip']]) ? $byIp[$e['d']['ip']] + 1 : 1;
            $r = $e['d']['rule'] !== '' ? $e['d']['rule'] : '?';
            $byRule[$r] = isset($byRule[$r]) ? $byRule[$r] + 1 : 1;
        }
        arsort($byIp);
        arsort($byRule);
        $total = count($blocks);
        if ($total < $this->cfg['firewall_hour'] && reset($byIp) < $this->cfg['firewall_ip_hour'])
        {
            return array();
        }
        $lines = array($this->t('fw_body', $total, count($byIp)));
        $i = 0;
        foreach ($byIp as $ip => $n)
        {
            if (++$i > 3) { break; }
            $lines[] = $this->t('ip_count', $ip, $n);
        }
        $lines[] = $this->t('fw_rules', implode(', ', array_slice(array_map(function ($k, $v) { return $k . '×' . $v; }, array_keys($byRule), $byRule), 0, 4)));
        return array($this->finding('firewall', 'firewall', $total >= $this->cfg['firewall_hour'] * 3 ? self::URGENT : self::NOTICE, $this->t('fw_title'), $lines));
    }

    private function checkMoney(array $hour, array $fresh)
    {
        $out = array();
        $groups = array('refund' => array(), 'cancel' => array(), 'balance_adjust' => array());
        foreach ($hour as $e)
        {
            if ($e['k'] !== 'money') { continue; }
            $t = $e['d']['type'] === 'cancel_paid' ? 'cancel' : $e['d']['type'];
            if (isset($groups[$t])) { $groups[$t][] = $e; }
        }
        $rules = array(
            'refund'         => array($this->cfg['refund_hour_count'], $this->cfg['refund_hour_sum'], $this->cfg['refund_single']),
            'cancel'         => array($this->cfg['cancel_hour_count'], $this->cfg['cancel_paid_hour_sum'], 0),
            'balance_adjust' => array($this->cfg['adjust_hour_count'], $this->cfg['adjust_hour_sum'], $this->cfg['adjust_single']),
        );
        foreach ($groups as $type => $list)
        {
            if (!$list) { continue; }
            list($maxN, $maxSum, $single) = $rules[$type];
            $sum = 0;
            $paidSum = 0;
            $actors = array();
            foreach ($list as $e)
            {
                $sum += $e['d']['amount'];
                if ($e['d']['type'] === 'cancel_paid') { $paidSum += $e['d']['amount']; }
                if ($e['d']['actor'] !== '') { $actors[$e['d']['actor']] = true; }
            }
            $sumForRule = $type === 'cancel' ? $paidSum : $sum;
            if (count($list) >= $maxN || ($maxSum > 0 && $sumForRule >= $maxSum))
            {
                $out[] = $this->finding('money', 'money:' . $type, self::NOTICE, $this->t('money_title_' . $type),
                    array($this->t('money_burst', count($list), $this->money($sumForRule)), $this->t('money_actors', $actors ? implode(', ', array_keys($actors)) : '?')));
            }
        }
        foreach ($fresh as $e)
        {
            if ($e['k'] !== 'money') { continue; }
            $type = $e['d']['type'] === 'cancel_paid' ? 'cancel' : $e['d']['type'];
            $single = isset($rules[$type]) ? $rules[$type][2] : 0;
            if ($single > 0 && $e['d']['amount'] >= $single)
            {
                $out[] = $this->finding('money', 'money1:' . $type . ':' . $e['d']['ref'] . ':' . $e['t'], self::NOTICE, $this->t('money_title_' . $type),
                    array($this->t('money_single', $this->money($e['d']['amount']), $e['d']['ref'] !== '' ? $e['d']['ref'] : '?', $e['d']['actor'] !== '' ? $e['d']['actor'] : '?')), 1);
            }
        }
        return $out;
    }

    private function checkCustom(array $fresh)
    {
        $out = array();
        foreach ($fresh as $e)
        {
            if ($e['k'] !== 'custom') { continue; }
            $d = $e['d'];
            $key = $d['key'] !== '' ? 'custom:' . $d['key'] : 'custom:' . md5($d['title'] . (string) $this->json($d['lines']));
            $out[] = $this->finding('custom', $key, max(self::LOG, min(self::URGENT, (int) $d['level'])), $d['title'], $d['lines']);
        }
        return $out;
    }

    /* ----------------------------------------------------------------------
     * File integrity
     * ---------------------------------------------------------------------- */

    /** Patterns that are common in web shells and injected backdoors. Each has an id; a file's
        baseline remembers which ids it already had, so only NEW ids on a changed file count. */
    public static function suspiciousRules()
    {
        return array(
            'cmd'    => '/\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i',
            'sysv'   => '/\b(?:system|exec)\s*\(\s*\$/i',
            'evalx'  => '/\b(?:eval|assert)\s*\(\s*(?:\$_|\$\{|base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|stripslashes\s*\(\s*\$_)/i',
            'callin' => '/\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]]{0,60}\]\s*\(/',
            'crfn'   => '/\bcreate_function\s*\(/i',
            'pregE'  => '/preg_replace\s*\(\s*([\'"])[^\'"]{0,200}\/[imsxuADSUX]*e[imsxuADSUX]*\1/',
            'blob'   => '/[A-Za-z0-9+\/]{3000,}={0,2}/',
            'hex'    => '/(?:\\\\x[0-9a-fA-F]{2}){30,}/',
            /* well-known web-shell names, split up so this file does not match its own rule or an antivirus signature */
            'shell'  => '/\b(?:Files' . 'Man|b37' . '4k|WSOset' . 'cookie|c99' . 'shell|r57' . 'shell|Indo' . 'Xploit|Anonymous' . 'Fox|alfa' . 'shell)\b/i',
            'upin'   => '/move_uploaded_file\s*\([^;]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)/i',
            'htx'    => '/^\s*(?:AddHandler|SetHandler|AddType\s+application\/x-httpd|php_value\s+auto_(?:prepend|append)_file|auto_(?:prepend|append)_file\s*=)/im',
        );
    }

    /** The rules in force: built-in, minus `disable_rules`, plus `extra_rules`. */
    private function rules()
    {
        if ($this->rules === null)
        {
            $rules = self::suspiciousRules();
            foreach ((array) $this->cfg['disable_rules'] as $id)
            {
                unset($rules[(string) $id]);
            }
            foreach ((array) $this->cfg['extra_rules'] as $id => $def)
            {
                $id = (string) $id;
                $re = is_array($def) ? (isset($def['pattern']) ? (string) $def['pattern'] : '') : (string) $def;
                if (!preg_match('/^[A-Za-z0-9_.-]{1,40}$/', $id) || $re === '' || @preg_match($re, '') === false)
                {
                    $this->badRules[] = $id;   // a pattern that does not compile is skipped, never fatal
                    continue;
                }
                $rules[$id] = $re;
                if (is_array($def) && isset($def['label']) && (string) $def['label'] !== '')
                {
                    $this->ruleLabels[$id] = (string) $def['label'];
                }
            }
            $this->rules = $rules;
        }
        return $this->rules;
    }

    /**
     * Every file below the scanned folders of $root (default: site_root), as relative path => SplFileInfo.
     * `exclude_dirs` and the module's own state folder are skipped. Callers pick the code files.
     */
    private function filesIn($root = null)
    {
        $root = $root === null ? $this->cfg['site_root'] : rtrim(str_replace('\\', '/', (string) $root), '/');
        if ($root === '')
        {
            return;
        }
        $stateDir = $this->cfg['state_dir'] . '/';
        foreach ($this->cfg['scan_rel'] as $sub)
        {
            $dir = $sub === '' ? $root : $root . '/' . $sub;
            if (!is_dir($dir))
            {
                continue;
            }
            $it = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                    function ($cur) use ($root, $stateDir) {
                        if (!$cur->isDir())
                        {
                            return true;
                        }
                        $abs = str_replace('\\', '/', $cur->getPathname());
                        $rel = ltrim(substr($abs, strlen($root)), '/');
                        return !$this->inDirList($rel, $this->cfg['exclude_dirs']) && strpos($abs . '/', $stateDir) !== 0;
                    }
                ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            foreach ($it as $f)
            {
                yield ltrim(substr(str_replace('\\', '/', $f->getPathname()), strlen($root)), '/') => $f;
            }
        }
    }

    private function loadBase()
    {
        $file = $this->path('files.json');
        $raw = is_file($file) ? json_decode((string) @file_get_contents($file), true) : array();
        $base = array();
        foreach (is_array($raw) ? $raw : array() as $k => $row)
        {
            $base[$this->unpackPath((string) $k)] = $row;
        }
        return $base;
    }

    private function saveBase($file, array $base)
    {
        $out = array();
        foreach ($base as $rel => $row)
        {
            $out[$this->packPath((string) $rel)] = $row;
        }
        $json = json_encode($out);
        return $json !== false && @file_put_contents($file, $json, LOCK_EX) !== false;
    }

    /**
     * File names are bytes, JSON is UTF-8. A name that is not valid UTF-8 (a folder created years ago by an
     * FTP client in Big5, GBK, Latin-1…) would make the whole fingerprint file impossible to save. Such a name
     * is stored as a NUL byte followed by its hex form — a NUL can never be part of a real file name.
     */
    private function packPath($rel)
    {
        return preg_match('//u', $rel) ? $rel : "\0" . bin2hex($rel);
    }

    private function unpackPath($key)
    {
        if (isset($key[0]) && $key[0] === "\0")
        {
            $bin = @hex2bin(substr($key, 1));
            return $bin === false ? $key : $bin;
        }
        return $key;
    }

    /**
     * Text from outside (a file name, a user name passed to a hook) made safe for messages and JSON.
     * Valid UTF-8 passes through untouched. Otherwise it is converted from `input_charset` when that is set
     * and a converter is available; failing that, every invalid byte becomes "?".
     */
    private function clean($s, &$lossy = false)
    {
        $s = (string) $s;
        $lossy = false;
        if ($s === '' || preg_match('//u', $s))
        {
            return $s;
        }
        $from = (string) $this->cfg['input_charset'];
        if ($from !== '')
        {
            $out = false;
            if (function_exists('mb_convert_encoding') && in_array(strtolower($from), array_map('strtolower', mb_list_encodings()), true))
            {
                $out = @mb_convert_encoding($s, 'UTF-8', $from);
            }
            elseif (function_exists('iconv'))
            {
                $out = @iconv($from, 'UTF-8//IGNORE', $s);
            }
            if (is_string($out) && $out !== '' && preg_match('//u', $out))
            {
                return $out;
            }
        }
        /* keep every well-formed UTF-8 sequence, replace each stray byte */
        $lossy = true;
        return (string) preg_replace_callback(
            '/[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]'
            . '|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}|(.)/s',
            function ($m) { return isset($m[1]) && $m[1] !== '' ? '?' : $m[0]; },
            $s
        );
    }

    /**
     * clean() for text that is also used to tell things apart (account names). Two different names must not
     * collapse into the same "???", so a name that had to be repaired gets a short tag made from its bytes.
     */
    private function cleanId($s)
    {
        $s = (string) $s;
        $lossy = false;
        $out = $this->clean($s, $lossy);
        return $lossy ? $out . '~' . substr(md5($s), 0, 4) : $out;
    }

    /** json_encode that cannot fail on a stray byte (it is replaced), so a record is never lost or emptied. */
    private function json($value, $flags = 0)
    {
        $flags |= defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : JSON_PARTIAL_OUTPUT_ON_ERROR;
        return json_encode($value, $flags);
    }

    private function isCodeFile($rel)
    {
        $base = strtolower(basename($rel));
        return in_array($base, array('.htaccess', '.user.ini', 'php.ini'), true)
            || (bool) preg_match('/\.(php\d?|phtml|pht|phps|phar|inc|cgi|pl|py|sh|asp|aspx|jsp)$/i', $base);
    }

    private function inDirList($rel, array $dirs)
    {
        foreach ($dirs as $d)
        {
            $d = trim(str_replace('\\', '/', $d), '/');
            if ($d !== '' && ($rel === $d || strpos($rel, $d . '/') === 0))
            {
                return true;
            }
        }
        return false;
    }

    private function scanContent($abs, $rel)
    {
        $base = strtolower(basename($rel));
        $content = @file_get_contents($abs, false, null, 0, (int) $this->cfg['max_scan_bytes']);
        if ($content === false || $content === '')
        {
            return array();
        }
        $isConf = in_array($base, array('.htaccess', '.user.ini', 'php.ini'), true);
        $hit = array();
        foreach ($this->rules() as $id => $re)
        {
            if (($id === 'htx') !== $isConf)
            {
                continue;
            }
            if (@preg_match($re, $content))
            {
                $hit[] = (string) $id;
            }
        }
        if (strncmp(ltrim($content), '<?php', 5) === 0 && preg_match('/\.(jpe?g|png|gif|webp)\./i', $base)
            && !in_array('imgphp', (array) $this->cfg['disable_rules'], true))
        {
            $hit[] = 'imgphp';   // "photo.jpg.php" style
        }
        return $hit;
    }

    private function checkFiles(array &$state, $now)
    {
        $res = array('ran' => false, 'complete' => false, 'findings' => array(), 'quarantined' => 0);
        /* an update window announced with expectChanges(); once it has ended, the next run scans at once to send the summary */
        $exp = $this->expectState();
        $closing = $exp !== null && $now > $this->expectEnd($exp);
        $due = empty($state['files_complete_at']) || ($now - (int) $state['files_complete_at']) >= (float) $this->cfg['scan_hours'] * 3600
            || !empty($state['files_partial']) || $this->forceScan || $closing;
        if (!$due)
        {
            return $res;
        }
        $res['ran'] = true;
        clearstatcache();
        $baseFile = $this->path('files.json');
        $base = $this->loadBase();
        $baselined = !empty($state['files_baselined']);
        /* Counts successful saves of a changed baseline. It is part of every finding key below: a second change
           to the same file gets a new key (and is reported), while the same change found again because the
           baseline could not be saved keeps its key (and stays quiet). */
        $gen = isset($state['files_gen']) ? (int) $state['files_gen'] : 0;
        $upgraded = isset($state['files_upgraded']) ? (int) $state['files_upgraded'] : 0;
        /* Normally a file is only re-read when its size or times changed. Every `rehash_days` the whole set is
           re-read regardless, so a change that left size and times untouched cannot stay hidden for long.
           (A scan that was cut short by the time budget keeps its mode until it has finished.) */
        $deep = !empty($state['files_deep']);
        if (!$deep && empty($state['files_partial']) && $baselined && (float) $this->cfg['rehash_days'] > 0
            && (empty($state['files_deep_at']) || ($now - (int) $state['files_deep_at']) >= (float) $this->cfg['rehash_days'] * 86400))
        {
            $deep = true;
        }
        $notes = array();
        if (!empty($state['files_reset_at']))
        {
            /* resetFileBaseline() was called. Fine if it was the owner; worth a word in case it was not. */
            $notes[] = $this->finding('files', 'files:reset:' . (int) $state['files_reset_at'], self::NOTICE, $this->t('file_reset_title'),
                array($this->t('file_reset_body', date('m/d H:i', (int) $state['files_reset_at']))), 1);
            unset($state['files_reset_at']);
        }
        elseif ($baselined && !$base && (!isset($state['files_count']) || (int) $state['files_count'] > 0))
        {
            /* We had fingerprints and now they are gone, and nobody asked for a reset: the classic way to
               blind a file monitor. We cannot say what changed, so say that — loudly — and start over. */
            $notes[] = $this->finding('files', 'files:lost:' . date('Ymd', $now), self::URGENT, $this->t('file_lost_title'),
                array($this->t('file_lost_body'), $this->hint('file_lost_hint')), 24);
            $baselined = false;
            $upgraded = 0;
            $deep = false;
            unset($state['files_baselined'], $state['files_complete_at'], $state['files_partial'], $state['files_seen'], $state['files_upgraded'], $state['files_deep']);
        }
        $seen = array();
        foreach (isset($state['files_seen']) && is_array($state['files_seen']) ? $state['files_seen'] : array() as $k => $_)
        {
            $seen[$this->unpackPath((string) $k)] = 1;
        }
        $deadline = microtime(true) + (float) $this->cfg['scan_time_budget'];
        $new = $changed = array();
        $moved = array();   // quarantine_uploads: original path => new path, or false when the rename failed
        $complete = true;

        foreach ($this->filesIn() as $rel => $f)
        {
            if (microtime(true) > $deadline)
            {
                $complete = false;
                break;
            }
            if (!$this->isCodeFile($rel) || isset($seen[$rel]))
            {
                continue;
            }
            $seen[$rel] = 1;
            $abs = $f->getPathname();
            $size = (int) $f->getSize();
            $mtime = (int) $f->getMTime();
            $ctime = (int) $f->getCTime();   // on Linux, "touch -r" can fake mtime but not ctime
            $old = isset($base[$rel]) && is_array($base[$rel]) && isset($base[$rel]['h']) ? $base[$rel] : null;
            /* Records written by an earlier build carry a 40-digit SHA-1; today's are 64-digit SHA-256. */
            $legacy = $old !== null && strlen((string) $old['h']) !== 64;
            if (!$deep && $old && !$legacy && empty($old['r']) && isset($old['s'], $old['m'], $old['c'])
                && (int) $old['s'] === $size && (int) $old['m'] === $mtime && (int) $old['c'] === $ctime)
            {
                continue;
            }
            $hash = @hash_file('sha256', $abs);
            if ($hash === false)
            {
                continue;   // unreadable right now (locked, permissions, quarantined by antivirus); next scan retries
            }
            $same = false;
            if ($old && $legacy)
            {
                /* Upgrade without a false alarm: first check the file against its OLD fingerprint, in the old
                   format. Unchanged -> swap in the SHA-256 quietly. Changed -> report it like any other change. */
                $before = @sha1_file($abs);
                $same = $before !== false && $before === (string) $old['h'];
                if ($same)
                {
                    $upgraded++;
                }
            }
            elseif ($old)
            {
                $same = (string) $old['h'] === $hash;
            }
            $was = $old && isset($old['x']) ? (array) $old['x'] : array();
            $sus = $same ? $was : $this->scanContent($abs, $rel);
            $entry = array('s' => $size, 'm' => $mtime, 'c' => $ctime, 'h' => $hash, 'x' => $sus);
            if (abs(time() - $mtime) <= 2)
            {
                /* Written within the last two seconds: it could be written once more in the same second and keep
                   the same time. Marked "fresh", so the next scan re-reads it instead of trusting size and times. */
                $entry['r'] = 1;
            }
            $base[$rel] = $entry;
            if (!$baselined)
            {
                continue;
            }
            if (!$old)
            {
                $new[$rel] = $sus;
                if ($this->cfg['quarantine_uploads'] && $this->isUploadedProgram($rel))
                {
                    $moved[$rel] = $this->quarantine($abs, $rel, $now);
                    if ($moved[$rel] !== false)
                    {
                        unset($base[$rel]);   // it is no longer there under that name; the renamed file is not a code file
                    }
                }
            }
            elseif (!$same)
            {
                $more = array_values(array_diff($sus, $was));
                if (!$legacy && isset($old['m']) && (int) $old['m'] === $mtime && empty($old['r'])
                    && !in_array('stealth', (array) $this->cfg['disable_rules'], true))
                {
                    /* The content is different but the modification time is exactly what it was: somebody put the
                       time back (or wrote the file in a way that does not touch it). Ordinary edits and
                       deployments never look like this, so it is reported as URGENT whatever the content. */
                    $more[] = 'stealth';
                }
                $changed[$rel] = $more;
            }
        }
        $res['quarantined'] = count(array_filter($moved, 'is_string'));

        $deleted = array();
        if ($complete)
        {
            foreach ($base as $rel => $_)
            {
                if (!isset($seen[$rel]))
                {
                    if ($baselined) { $deleted[] = $rel; }
                    unset($base[$rel]);
                }
            }
            if ($upgraded > 0 && $baselined)
            {
                /* Said once, when the whole conversion is done, so the owner knows why the fingerprints look
                   different — and so that a "conversion" nobody asked for does not pass unnoticed. */
                $notes[] = $this->finding('files', 'files:sha256:' . $now, self::NOTICE, $this->t('file_algo_title'),
                    array($this->t('file_algo_body', $upgraded), $this->hint('file_algo_hint')), 1);
            }
            if ($deep || !$baselined)
            {
                $state['files_deep_at'] = $now;   // every file was read in full during this scan
            }
            $state['files_complete_at'] = $now;
            $state['files_baselined'] = true;
            $state['files_count'] = count($base);
            unset($state['files_partial'], $state['files_seen'], $state['files_upgraded'], $state['files_deep']);
        }
        else
        {
            $state['files_partial'] = true;
            $state['files_seen'] = array();
            foreach ($seen as $k => $_)
            {
                $state['files_seen'][$this->packPath((string) $k)] = 1;
            }
            $state['files_upgraded'] = $upgraded;
            if ($deep)
            {
                $state['files_deep'] = true;
            }
        }
        $saved = $this->saveBase($baseFile, $base);
        if ($saved && ($new || $changed || $deleted))
        {
            $state['files_gen'] = $gen + 1;
        }
        if ($exp !== null && $baselined)
        {
            /* Inside an announced update window the ordinary changes are collected, not reported one by one.
               What fileFindings() would call URGENT stays here and is reported right away. */
            $up = $this->cfg['upload_dirs'];
            foreach ($new as $rel => $sus)
            {
                if (!$sus && !$this->inDirList($rel, $up)) { $this->expectAdd($exp, $rel, '+'); unset($new[$rel]); }
            }
            foreach ($changed as $rel => $more)
            {
                if (!$more && !$this->inDirList($rel, $this->cfg['runtime_dirs'])) { $this->expectAdd($exp, $rel, '~'); unset($changed[$rel]); }
            }
            foreach ($deleted as $i => $rel)
            {
                $this->expectAdd($exp, $rel, '-');
                unset($deleted[$i]);
            }
            $deleted = array_values($deleted);
            if ($closing && $complete)
            {
                $notes[] = $this->expectSummary($exp, $gen);
                $this->dropExpect();
            }
            else
            {
                $this->saveExpect($exp, true);
            }
        }
        $res['complete'] = $complete;
        $res['findings'] = array_merge($notes, $this->fileFindings($new, $changed, $deleted, $gen, $moved));
        return $res;
    }

    /* ----------------------------------------------------------------------
     * Update window ("we are about to upload": expectChanges())
     * ---------------------------------------------------------------------- */

    /** @return array|null the open (or ended but not yet summed up) window */
    private function expectState()
    {
        $f = $this->cfg['state_dir'] . '/expect.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        if (!is_array($j) || !isset($j['from'], $j['until']))
        {
            return null;
        }
        $j['files'] = isset($j['files']) && is_array($j['files']) ? $j['files'] : array();
        $j['more'] = isset($j['more']) ? (int) $j['more'] : 0;
        return $j;
    }

    /**
     * When the window ends: the announced time, or earlier when it was closed by hand. Never more than 4 hours
     * after it opened, whatever the file says: someone who breaks in could write a window "until 2099" to keep
     * the monitor quiet. The worst they get is a few hours, and the summary still lists their changes.
     */
    private function expectEnd(array $exp)
    {
        $end = min((int) $exp['until'], (int) $exp['from'] + 4 * 3600);
        return isset($exp['end']) ? min($end, (int) $exp['end']) : $end;
    }

    /**
     * $merge: written from a scan, while the command line may have extended or closed the window in the
     * meantime: keep the later announced end and an earlier hand-closing.
     */
    private function saveExpect(array $exp, $merge = false)
    {
        if ($merge && ($cur = $this->expectState()) !== null)
        {
            $exp['until'] = max((int) $exp['until'], (int) $cur['until']);
            if (isset($cur['end']))
            {
                $exp['end'] = isset($exp['end']) ? min((int) $exp['end'], (int) $cur['end']) : (int) $cur['end'];
            }
        }
        @file_put_contents($this->path('expect.json'), (string) $this->json($exp), LOCK_EX);
    }

    private function dropExpect()
    {
        @unlink($this->path('expect.json'));
    }

    /** One change seen inside the window. A file created and then deleted again cancels out. */
    private function expectAdd(array &$exp, $rel, $sign)
    {
        $k = $this->packPath((string) $rel);
        if (isset($exp['files'][$k]))
        {
            if ($sign === '-' && $exp['files'][$k] === '+') { unset($exp['files'][$k]); }
            elseif ($sign === '-' || $sign === '+') { $exp['files'][$k] = $sign === '+' ? '~' : '-'; }   // deleted and put back = changed
            return;
        }
        if (count($exp['files']) >= 5000)
        {
            $exp['more']++;   // a very large update: counted, not listed
            return;
        }
        $exp['files'][$k] = $sign;
    }

    /** @return array array(new, changed, deleted) */
    private function expectCounts(array $exp)
    {
        $n = array('+' => 0, '~' => 0, '-' => 0);
        foreach ($exp['files'] as $sign)
        {
            if (isset($n[$sign])) { $n[$sign]++; }
        }
        return array($n['+'], $n['~'] + (int) $exp['more'], $n['-']);
    }

    private function expectSummary(array $exp, $gen)
    {
        list($a, $c, $d) = $this->expectCounts($exp);
        $lines = array($this->t('exp_window', date('m/d H:i', (int) $exp['from']), date('H:i', $this->expectEnd($exp))));
        if ($a + $c + $d === 0)
        {
            $lines[] = $this->t('exp_none');
            return $this->finding('system', 'files:exp:' . (int) $exp['from'], self::LOG, $this->t('exp_title'), $lines, 1);
        }
        $lines[] = $this->t('file_summary', $a, $c, $d);
        $marks = array('+' => '＋ ', '~' => '✎ ', '-' => '－ ');
        $groups = array('+' => array(), '~' => array(), '-' => array());
        foreach ($exp['files'] as $k => $sign)
        {
            if (isset($groups[$sign])) { $groups[$sign][] = $this->clean($this->unpackPath((string) $k)); }
        }
        $list = array();
        foreach ($groups as $sign => $names)   // new, changed, deleted: the order of the notices outside a window
        {
            sort($names, SORT_STRING);
            foreach ($names as $name) { $list[] = $marks[$sign] . $name; }
        }
        $total = $a + $c + $d;
        if ($total > 5)
        {
            $list = array_slice($list, 0, 4);
            $list[] = $this->t('file_more', $total - 4);
        }
        /* 1 window + 1 counts + at most 5 files + 1 hint = the 8 lines that are sent */
        return $this->finding('files', 'files:exp:' . (int) $exp['from'] . ':' . $gen, self::NOTICE, $this->t('exp_title'),
            array_merge($lines, $list, array($this->hint('exp_hint'))), 168);
    }

    /** A program (not a server config file) inside an upload folder: the only thing quarantine_uploads acts on. */
    private function isUploadedProgram($rel)
    {
        return $this->inDirList($rel, $this->cfg['upload_dirs'])
            && (bool) preg_match('/\.(php\d?|phtml|pht|phps|phar|inc|cgi|pl|py|sh|asp|aspx|jsp)$/i', basename($rel));
    }

    /**
     * Renames one file in place so the web server stops treating it as a program. The new name keeps no dot
     * from the old one (so no ".php" is left for a server that looks at every extension) and ends in
     * ".quarantined". The file is not deleted, not moved elsewhere and not modified: it is evidence.
     *
     * @return string|false the new path relative to site_root, or false when it could not be renamed
     */
    private function quarantine($abs, $rel, $now)
    {
        $abs = str_replace('\\', '/', $abs);
        $dir = dirname($abs);
        $stem = substr(preg_replace('/[^A-Za-z0-9_-]+/', '_', basename($rel)), 0, 80) . '-' . date('Ymd-His', $now);
        $name = $stem . '.quarantined';
        for ($i = 2; file_exists($dir . '/' . $name) && $i <= 50; $i++)
        {
            $name = $stem . '-' . $i . '.quarantined';
        }
        if (file_exists($dir . '/' . $name))
        {
            return false;
        }
        try
        {
            $ok = is_callable($this->cfg['renamer'])
                ? (bool) call_user_func($this->cfg['renamer'], $abs, $dir . '/' . $name)
                : @rename($abs, $dir . '/' . $name);
        }
        catch (Throwable $e)
        {
            $ok = false;
        }
        if (!$ok)
        {
            return false;
        }
        $relDir = str_replace('\\', '/', dirname($rel));
        return ($relDir === '.' || $relDir === '' ? '' : $relDir . '/') . $name;
    }

    private function fileFindings(array $new, array $changed, array $deleted, $gen = 0, array $moved = array())
    {
        $out = array();
        $up = $this->cfg['upload_dirs'];
        $rt = $this->cfg['runtime_dirs'];
        $urgentLines = array();
        $tail = array();
        foreach ($new as $rel => $sus)
        {
            if ($sus || $this->inDirList($rel, $up))
            {
                $why = $this->why($sus, $this->inDirList($rel, $up));
                if (isset($moved[$rel]) && is_string($moved[$rel]))
                {
                    $urgentLines[] = $this->t('file_new_quarantined', $this->clean($rel), $why, $this->clean($moved[$rel]));
                    $tail['ok'] = $this->hint('file_quarantine_hint');
                }
                elseif (isset($moved[$rel]))
                {
                    $urgentLines[] = $this->t('file_new_bad', $this->clean($rel), $why);
                    $tail['failed'] = $this->t('file_quarantine_failed');
                }
                else
                {
                    $urgentLines[] = $this->t('file_new_bad', $this->clean($rel), $why);
                }
            }
        }
        foreach ($changed as $rel => $sus)
        {
            if ($sus)
            {
                $urgentLines[] = $this->t('file_changed_bad', $this->clean($rel), $this->why($sus, false));
            }
        }
        if ($urgentLines)
        {
            /* at most 8 lines of a finding are sent: keep room for the closing advice, and say so when files are left out */
            $room = 7 - count($tail);
            $shown = $urgentLines;
            if (count($urgentLines) > $room)
            {
                $shown = array_slice($urgentLines, 0, $room - 1);
                $shown[] = $this->t('file_more', count($urgentLines) - ($room - 1));
            }
            $out[] = $this->finding('files', 'files:bad:' . $gen . ':' . md5(implode('|', $urgentLines)), self::URGENT, $this->t('file_bad_title'),
                array_merge($shown, array_values($tail), array($this->hint('file_bad_hint'))), 168);
        }

        $plainNew = array_keys(array_filter($new, function ($sus, $rel) use ($up) { return !$sus && !$this->inDirList($rel, $up); }, ARRAY_FILTER_USE_BOTH));
        $plainChanged = array_keys(array_filter($changed, function ($sus, $rel) use ($rt) { return !$sus && !$this->inDirList($rel, $rt); }, ARRAY_FILTER_USE_BOTH));
        $runtimeChanged = array_keys(array_filter($changed, function ($sus, $rel) use ($rt) { return !$sus && $this->inDirList($rel, $rt); }, ARRAY_FILTER_USE_BOTH));
        if ($plainNew || $plainChanged || $deleted)
        {
            $lines = array($this->t('file_summary', count($plainNew), count($plainChanged), count($deleted)));
            foreach (array_slice(array_merge(
                array_map(function ($r) { return '＋ ' . $this->clean($r); }, $plainNew),
                array_map(function ($r) { return '✎ ' . $this->clean($r); }, $plainChanged),
                array_map(function ($r) { return '－ ' . $this->clean($r); }, $deleted)), 0, 6) as $l)   // 1 summary + 6 files + 1 closing line = the 8 that are sent
            {
                $lines[] = $l;
            }
            $lines[] = $this->hint('file_plain_hint');
            $out[] = $this->finding('files', 'files:chg:' . $gen . ':' . md5(implode('|', array_merge($plainNew, array('/'), $plainChanged, array('/'), $deleted))),
                self::NOTICE, $this->t('file_title'), $lines, 168);
        }
        if ($runtimeChanged)
        {
            $out[] = $this->finding('files', 'files:rt:' . $gen . ':' . md5(implode('|', $runtimeChanged)), self::LOG, $this->t('file_runtime_title'), array_map(array($this, 'clean'), array_slice($runtimeChanged, 0, 20)));
        }
        return $out;
    }

    /* ----------------------------------------------------------------------
     * Page watch: what your pages pull in from other sites, as four kinds of visitor see them
     * ---------------------------------------------------------------------- */

    /** @return array array('result' => 'off' | 'not due' | 'command line only' | 'read N page(s)', 'findings' => array) */
    private function checkPages(array &$state, $now)
    {
        $res = array('result' => 'off', 'findings' => array());
        $pages = $this->listOf($this->cfg['page_watch']);
        if (!$pages)
        {
            return $res;
        }
        if (PHP_SAPI !== 'cli' && !is_callable($this->cfg['page_transport']))
        {
            /* Reading your own pages from inside a visitor's page view could tie up the server (and on some hosts
               wait for itself). The scheduled job does it. */
            $state['pages_web_only'] = $now;
            $res['result'] = 'command line only';
            return $res;
        }
        unset($state['pages_web_only']);
        $rec = $this->loadPages();
        if (!$rec && !empty($state['pages_baselined']))
        {
            $res['findings'][] = $this->finding('pages', 'pages:lost:' . date('Ymd', $now), self::NOTICE, $this->t('page_lost_title'), array($this->t('page_lost_body')), 24);
            unset($state['pages_baselined']);
        }
        $every = max(0.0, (float) $this->cfg['page_watch_hours']) * 3600;
        $todo = array();
        foreach ($pages as $url)
        {
            $at = isset($rec[$url]['at']) ? (int) $rec[$url]['at'] : 0;
            if ($at === 0 || $now - $at >= $every)
            {
                $todo[$url] = $at;
            }
        }
        if (!$todo)
        {
            $res['result'] = 'not due';
            return $res;
        }
        asort($todo);   // the longest unchecked first; what does not fit in this run is first in the next
        $deadline = microtime(true) + 45;
        $found = array('hidden' => array(), 'code' => array(), 'links' => array());
        $n = 0;
        foreach (array_keys($todo) as $url)
        {
            if ($n > 0 && microtime(true) > $deadline)
            {
                break;
            }
            $row = isset($rec[$url]) && is_array($rec[$url]) ? $rec[$url] : array();
            foreach ($this->checkPage((string) $url, $row, $now) as $type => $lines)
            {
                $found[$type] = array_merge($found[$type], $lines);
            }
            $rec[$url] = $row;
            $n++;
        }
        foreach (array_keys($rec) as $url)
        {
            if (!in_array((string) $url, $pages, true))
            {
                unset($rec[$url]);   // no longer watched
            }
        }
        $this->savePages($rec);
        foreach ($rec as $row)
        {
            if (isset($row['k']))
            {
                $state['pages_baselined'] = true;
                break;
            }
        }
        $res['result'] = 'read ' . $n . ' page(s)';
        $kinds = array(
            'hidden' => array(self::URGENT, 'page_hidden_title', 'page_hidden_hint'),
            'code'   => array(self::URGENT, 'page_code_title', 'page_code_hint'),
            'links'  => array(self::NOTICE, 'page_links_title', 'page_links_hint'),
        );
        foreach ($kinds as $type => $def)
        {
            if (!$found[$type])
            {
                continue;
            }
            $lines = $found[$type];
            if (count($lines) > 7)
            {
                $lines = array_slice($lines, 0, 6);
                $lines[] = $this->t('page_more', count($found[$type]) - 6);
            }
            $lines[] = $this->hint($def[2]);
            $res['findings'][] = $this->finding('pages', 'pages:' . $type . ':' . md5(implode('|', $found[$type])), $def[0], $this->t($def[1]), $lines, 168);
        }
        return $res;
    }

    /**
     * Reads one page and compares it with its record ($row: 'at' last read, 'k' category => site => first seen,
     * 'f' / 'w' view => failures in a row / last reason). The first successful read is the baseline.
     *
     * @return array 'hidden' | 'code' | 'links' => message lines
     */
    private function checkPage($url, array &$row, $now)
    {
        $got = $this->readPage($url);
        $row['at'] = $now;
        $fails = isset($row['f']) && is_array($row['f']) ? $row['f'] : array();
        $whys = isset($row['w']) && is_array($row['w']) ? $row['w'] : array();
        foreach (array_keys($this->pageViews()) as $v)
        {
            if (isset($got['why'][$v]))
            {
                $fails[$v] = (isset($fails[$v]) ? (int) $fails[$v] : 0) + 1;
                $whys[$v] = $got['why'][$v];
            }
            else
            {
                unset($fails[$v], $whys[$v]);
            }
        }
        $row['f'] = $fails;
        $row['w'] = $whys;
        if (!$got['views'])
        {
            return array();   // nothing read: the site is down or refuses us; not this module's business beyond status()
        }
        $all = array();
        foreach ($got['views'] as $cats)
        {
            foreach ($cats as $cat => $hosts)
            {
                foreach ($hosts as $h => $_) { $all[$cat][$h] = true; }
            }
        }
        $known = isset($row['k']) && is_array($row['k']) ? $row['k'] : null;
        if ($known === null)
        {
            $row['k'] = array();
            foreach ($all as $cat => $hosts)
            {
                foreach ($hosts as $h => $_) { $row['k'][$cat][$h] = $now; }
            }
            $this->capKnown($row['k']);
            return array();
        }
        $out = array('hidden' => array(), 'code' => array(), 'links' => array());
        $label = $this->pageLabel($url);
        $hidden = $this->hiddenFromOwner($got['views'], $url);
        $who = array();
        foreach ($hidden as $cat => $hosts)
        {
            foreach ($hosts as $h => $views)
            {
                if (!isset($known[$cat][$h]))
                {
                    $who[(isset($views['crawler']) ? 'c' : '') . (isset($views['from_google']) ? 'g' : '')][$h] = true;
                }
            }
        }
        foreach ($who as $w => $hosts)
        {
            $out['hidden'][] = $this->t('page_hidden_line', $label, $this->t('page_who_' . $w), $this->hostList(array_keys($hosts)));
        }
        $code = array('script' => array(), 'frame' => array(), 'form' => array(), 'redirect' => array());
        $links = array();
        foreach ($all as $cat => $hosts)
        {
            foreach ($hosts as $h => $_)
            {
                if (isset($known[$cat][$h]) || isset($hidden[$cat][$h]) || $this->allowedHost($h, $url))
                {
                    continue;
                }
                if ($cat === 'link') { $links[] = $h; }
                elseif (isset($code[$cat])) { $code[$cat][] = $h; }
            }
        }
        foreach ($code as $cat => $hosts)
        {
            if ($hosts)
            {
                $out['code'][] = $this->t('page_new_' . $cat, $label, $this->hostList($hosts));
            }
        }
        if ($links && $this->cfg['page_links'])
        {
            $out['links'][] = $this->t('page_new_links', $label, $this->hostList($links));
        }
        foreach ($all as $cat => $hosts)
        {
            foreach ($hosts as $h => $_)
            {
                if (!isset($known[$cat][$h])) { $known[$cat][$h] = $now; }   // reported once, then part of the record
            }
        }
        $this->capKnown($known);
        $row['k'] = $known;
        return $out;
    }

    /** At most 500 sites per category and page, the most recently added kept. */
    private function capKnown(array &$known)
    {
        foreach ($known as $cat => $hosts)
        {
            if (count($hosts) > 500)
            {
                arsort($hosts);
                $known[$cat] = array_slice($hosts, 0, 500, true);
            }
        }
    }

    /**
     * Sites that the crawler or a visitor from Google get, but neither the desktop browser nor the phone does
     * (compared within the same category). Needs both of those to have answered: a phone layout differs from
     * the desktop one, and comparing against one of them alone would mistake that for hiding.
     *
     * @return array category => site => array(view => true)
     */
    private function hiddenFromOwner(array $views, $url)
    {
        if (!isset($views['browser'], $views['mobile']))
        {
            return array();
        }
        $seen = array();
        foreach (array('browser', 'mobile') as $v)
        {
            foreach ($views[$v] as $cat => $hosts)
            {
                foreach ($hosts as $h => $_) { $seen[$cat][$h] = true; }
            }
        }
        $out = array();
        foreach (array('crawler', 'from_google') as $v)
        {
            if (!isset($views[$v]))
            {
                continue;
            }
            foreach ($views[$v] as $cat => $hosts)
            {
                foreach ($hosts as $h => $_)
                {
                    if (!isset($seen[$cat][$h]) && !$this->allowedHost($h, $url))
                    {
                        $out[$cat][$h][$v] = true;
                    }
                }
            }
        }
        return $out;
    }

    /** The four ways a page is read. Request headers only; nothing else differs. */
    private function pageViews()
    {
        $base = array('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language: ' . ($this->cfg['language'] === 'zh-TW' ? 'zh-TW,zh;q=0.9,en;q=0.8' : ($this->cfg['language'] === 'ja' ? 'ja,en;q=0.8' : 'en;q=0.9,*;q=0.5')));
        $desktop = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
        $phone = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';
        /* the form Google gives for its smartphone crawler; injected spam looks for "Googlebot" in it */
        $crawler = 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.204 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        return array(
            'browser'     => array_merge($base, array('User-Agent: ' . $desktop)),
            'mobile'      => array_merge($base, array('User-Agent: ' . $phone)),
            'crawler'     => array_merge($base, array('User-Agent: ' . $crawler)),
            'from_google' => array_merge($base, array('User-Agent: ' . $phone, 'Referer: https://www.google.com/')),
        );
    }

    /** @return array array('views' => view => category => site => true, 'why' => view => reason it could not be read) */
    private function readPage($url)
    {
        $views = array();
        $why = array();
        foreach ($this->pageViews() as $v => $headers)
        {
            if (!preg_match('#^https?://[^/\s?\#]+#i', $url))
            {
                $why[$v] = 'not an http(s) address';
                continue;
            }
            $r = $this->fetchPage($url, $headers);
            if ($r['ok'])
            {
                $views[$v] = $this->pageHosts($url, $r['body'], $r['redirect']);
            }
            else
            {
                $why[$v] = $r['why'];
            }
        }
        return array('views' => $views, 'why' => $why);
    }

    /**
     * GET one page. Redirects within the same site are followed (http -> https, adding "www", at most 5);
     * a redirect to another site is not followed: the site it points to is the result ('redirect').
     *
     * @return array array('ok' => bool, 'body' => string, 'redirect' => site or '', 'why' => string)
     */
    private function fetchPage($url, array $headers)
    {
        $timeout = max(1, min(60, (int) $this->cfg['page_timeout']));
        $max = max(65536, (int) $this->cfg['page_max_bytes']);
        $cur = $url;
        for ($hop = 0; $hop < 6; $hop++)
        {
            try
            {
                $r = is_callable($this->cfg['page_transport'])
                    ? (array) call_user_func($this->cfg['page_transport'], $cur, $headers, $timeout)
                    : $this->requestPage($cur, $headers, $timeout, $max);
            }
            catch (Throwable $e)
            {
                return array('ok' => false, 'body' => '', 'redirect' => '', 'why' => 'an error while reading the page');
            }
            $code = isset($r[0]) && is_numeric($r[0]) ? (int) $r[0] : 0;
            $loc = isset($r[2]) && is_scalar($r[2]) ? trim((string) $r[2]) : '';
            if ($code >= 200 && $code < 300)
            {
                return array('ok' => true, 'body' => substr(isset($r[1]) && is_scalar($r[1]) ? (string) $r[1] : '', 0, $max), 'redirect' => '', 'why' => '');
            }
            if ($code >= 300 && $code < 400 && $loc !== '')
            {
                $next = $this->resolveUrl($cur, $loc);
                $h = $this->hostOf($next);
                if ($h !== '' && $this->ownHost($h, $url))
                {
                    $cur = $next;
                    continue;
                }
                return array('ok' => true, 'body' => '', 'redirect' => $h !== '' ? $h : '?', 'why' => '');
            }
            return array('ok' => false, 'body' => '', 'redirect' => '', 'why' => $code > 0 ? 'HTTP ' . $code : 'no answer (could not connect, or it timed out)');
        }
        return array('ok' => false, 'body' => '', 'redirect' => '', 'why' => 'too many redirects');
    }

    /** @return array array(int $status, string $body, string $location); status 0 = no answer */
    private function requestPage($url, array $headers, $timeout, $max)
    {
        if (!function_exists('curl_init'))
        {
            $ctx = stream_context_create(array('http' => array('method' => 'GET', 'header' => implode("\r\n", $headers), 'timeout' => $timeout,
                'ignore_errors' => true, 'follow_location' => 0)));
            $fp = @fopen($url, 'rb', false, $ctx);
            if (!$fp)
            {
                return array(0, '', '');
            }
            $meta = stream_get_meta_data($fp);
            $body = (string) stream_get_contents($fp, $max);
            fclose($fp);
            $code = 0;
            $loc = '';
            foreach (isset($meta['wrapper_data']) ? (array) $meta['wrapper_data'] : array() as $h)
            {
                if (preg_match('/^HTTP\/\S+\s+(\d{3})/', (string) $h, $m)) { $code = (int) $m[1]; $loc = ''; }
                elseif (preg_match('/^Location:\s*(\S.*?)\s*$/i', (string) $h, $m)) { $loc = $m[1]; }
            }
            return array($code, $body, $loc);
        }
        $body = '';
        $loc = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_HTTPHEADER => $headers, CURLOPT_HTTPGET => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => min(5, $timeout), CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => function ($c, $line) use (&$loc) {
                if (preg_match('/^Location:\s*(\S.*?)\s*$/i', $line, $m)) { $loc = $m[1]; }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($c, $chunk) use (&$body, $max) {
                $body .= $chunk;
                return strlen($body) > $max ? 0 : strlen($chunk);   // enough read: stop
            },
        ));
        curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (PHP_VERSION_ID < 80000)
        {
            curl_close($ch);
        }
        return array($code, substr($body, 0, $max), $loc);
    }

    /** $loc from a Location header, made absolute against $base. */
    private function resolveUrl($base, $loc)
    {
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $loc))
        {
            return $loc;
        }
        if (!preg_match('#^([a-z][a-z0-9+.-]*:)//([^/?\#]*)([^?\#]*)#i', $base, $b))
        {
            return $loc;
        }
        if (strncmp($loc, '//', 2) === 0)
        {
            return $b[1] . $loc;
        }
        if (isset($loc[0]) && $loc[0] === '/')
        {
            return $b[1] . '//' . $b[2] . $loc;
        }
        $dir = substr($b[3], 0, (int) strrpos($b[3], '/') + 1);
        return $b[1] . '//' . $b[2] . ($dir === '' ? '/' : $dir) . $loc;
    }

    /**
     * The other sites one page uses, by category: script (code it runs), frame (pages and objects it embeds),
     * form (where forms send what is typed), redirect, link. This site's own addresses are left out.
     *
     * @return array category => site => true
     */
    private function pageHosts($pageUrl, $html, $redirect)
    {
        $cats = array('script' => array(), 'frame' => array(), 'form' => array(), 'redirect' => array(), 'link' => array());
        $add = function ($cat, $u) use (&$cats, $pageUrl) {
            $h = $this->hostOf($u);
            if ($h !== '' && count($cats[$cat]) < 500 && !$this->ownHost($h, $pageUrl))
            {
                $cats[$cat][$h] = true;
            }
        };
        if ($redirect !== '')
        {
            $cats['redirect'][$redirect] = true;
        }
        list($scripts, $rest) = $this->htmlParts((string) $html);
        foreach ($scripts as $s)
        {
            $a = $this->attrs($s[0]);
            if (isset($a['src']))
            {
                $add('script', $a['src']);
                continue;
            }
            $type = isset($a['type']) ? strtolower(trim($a['type'])) : '';
            if ($type !== '' && !in_array($type, array('text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript'), true))
            {
                continue;   // JSON-LD, templates: data, not code
            }
            /* addresses written inside the code: what a loader script will fetch ("https:\/\/" in JSON form too) */
            if (preg_match_all('#(?:https?:)?//([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,63})(?![A-Za-z0-9-])#',
                str_replace('\\/', '/', $s[1]), $u))
            {
                foreach ($u[1] as $h) { $add('script', '//' . $h); }
            }
        }
        if (preg_match_all('/<(a|area|iframe|frame|embed|object|form|button|input|meta|link)\b([^>]*)>/i', $rest, $t, PREG_SET_ORDER))
        {
            foreach ($t as $tag)
            {
                $a = $this->attrs($tag[2]);
                switch (strtolower($tag[1]))
                {
                    case 'a':
                    case 'area':
                        if (isset($a['href'])) { $add('link', $a['href']); }
                        break;
                    case 'iframe':
                    case 'frame':
                    case 'embed':
                        if (isset($a['src'])) { $add('frame', $a['src']); }
                        break;
                    case 'object':
                        if (isset($a['data'])) { $add('frame', $a['data']); }
                        break;
                    case 'form':
                        if (isset($a['action'])) { $add('form', $a['action']); }
                        break;
                    case 'button':
                    case 'input':
                        if (isset($a['formaction'])) { $add('form', $a['formaction']); }
                        break;
                    case 'meta':
                        if (isset($a['http-equiv'], $a['content']) && strtolower(trim($a['http-equiv'])) === 'refresh'
                            && preg_match('/url\s*=\s*[\'"]?([^\'"\s;]+)/i', $a['content'], $mm))
                        {
                            $add('redirect', $mm[1]);
                        }
                        break;
                    case 'link':
                        $rel = isset($a['rel']) ? strtolower($a['rel']) : '';
                        if (isset($a['href']) && (strpos($rel, 'modulepreload') !== false
                            || (strpos($rel, 'preload') !== false && isset($a['as']) && strtolower(trim($a['as'])) === 'script')))
                        {
                            $add('script', $a['href']);
                        }
                        break;
                }
            }
        }
        return $cats;
    }

    /**
     * Splits a page into its <script> elements (attributes, content) and the rest, with comments, scripts and
     * styles taken out of the rest. A plain left-to-right walk rather than one big regular expression: a page
     * with a huge inline script must not make the pattern give up (PCRE's backtracking limit) and the page
     * look empty — which is exactly what someone hiding something would want.
     *
     * @return array array(list of array(string $attributes, string $content), string $rest)
     */
    private function htmlParts($html)
    {
        $scripts = array();
        $rest = '';
        $len = strlen($html);
        $pos = 0;
        while ($pos < $len)
        {
            $lt = strpos($html, '<', $pos);
            if ($lt === false)
            {
                $rest .= substr($html, $pos);
                break;
            }
            $rest .= substr($html, $pos, $lt - $pos);
            if (substr($html, $lt, 4) === '<!--')
            {
                $end = strpos($html, '-->', $lt + 4);
                $pos = $end === false ? $len : $end + 3;
                $rest .= ' ';
                continue;
            }
            if (preg_match('/\G<(script|style)\b/i', $html, $m, 0, $lt))
            {
                $gt = strpos($html, '>', $lt);
                if ($gt === false)
                {
                    break;
                }
                $open = strlen($m[0]);
                $close = stripos($html, '</' . $m[1], $gt + 1);
                if (strtolower($m[1]) === 'script')
                {
                    $scripts[] = array(substr($html, $lt + $open, $gt - $lt - $open),
                        $close === false ? (string) substr($html, $gt + 1) : (string) substr($html, $gt + 1, $close - $gt - 1));
                }
                $end = $close === false ? false : strpos($html, '>', $close);
                $pos = $end === false ? $len : $end + 1;
                $rest .= ' ';
                continue;
            }
            $rest .= '<';
            $pos = $lt + 1;
        }
        return array($scripts, $rest);
    }

    /** The attributes of one tag, lower-case names, entities decoded. The first of a repeated name wins (as in browsers). */
    private function attrs($s)
    {
        $out = array();
        if (preg_match_all('/([^\s=\/>"\']+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>"\']+))/', (string) $s, $m, PREG_SET_ORDER))
        {
            foreach ($m as $x)
            {
                $k = strtolower($x[1]);
                if (isset($out[$k]))
                {
                    continue;
                }
                $v = isset($x[4]) && $x[4] !== '' ? $x[4] : (isset($x[3]) && $x[3] !== '' ? $x[3] : $x[2]);
                $out[$k] = html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            }
        }
        return $out;
    }

    /**
     * The site an address points to, the way a browser reads it: tabs and line breaks dropped, "\" taken as
     * "/", a "user@" part skipped. '' = this site (a relative address) or not a web address (mailto:, tel:,
     * javascript:…). 'data:' = code or content written into the address itself.
     */
    private function hostOf($u)
    {
        $u = str_replace('\\', '/', (string) preg_replace('/[\x00-\x20]+/', '', (string) $u));
        if ($u === '')
        {
            return '';
        }
        if (strncasecmp($u, 'data:', 5) === 0)
        {
            return 'data:';
        }
        if (!preg_match('#^(?:([a-z][a-z0-9+.-]*):)?//([^/?\#]*)#i', $u, $m))
        {
            return '';
        }
        if ($m[1] !== '' && !in_array(strtolower($m[1]), array('http', 'https'), true))
        {
            return '';
        }
        $auth = $m[2];
        if (($at = strrpos($auth, '@')) !== false)
        {
            $auth = substr($auth, $at + 1);
        }
        if (preg_match('/^\[[^\]]*\]/', $auth, $mm))
        {
            return strtolower($mm[0]);
        }
        $h = strtolower(rtrim((string) preg_replace('/:\d*$/', '', $auth), '.'));
        if ($h === '' || strlen($h) > 253)
        {
            return '';
        }
        return $this->clean($h);
    }

    /** The page's own site: the same host, or the same name without "www." and any sub-domain of it. */
    private function ownHost($h, $pageUrl)
    {
        $p = $this->hostOf($pageUrl);
        if ($p === '' || $h === '' || $h === 'data:')
        {
            return false;
        }
        $base = (string) preg_replace('/^www\./', '', $p);
        return $h === $p || $h === $base || substr($h, -strlen($base) - 1) === '.' . $base;
    }

    /** This site, or a site in `page_allow` (sub-domains included). */
    private function allowedHost($h, $pageUrl)
    {
        if ($this->ownHost($h, $pageUrl))
        {
            return true;
        }
        foreach ($this->listOf($this->cfg['page_allow']) as $a)
        {
            $a = strtolower($a);
            if ($a === 'data:')
            {
                if ($h === 'data:') { return true; }
                continue;
            }
            $a = strpos($a, '//') !== false ? $this->hostOf($a) : rtrim((string) preg_replace(array('#^\*?\.#', '#[/:].*$#'), '', $a), '.');
            if ($a !== '' && ($h === $a || substr($h, -strlen($a) - 1) === '.' . $a))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Site names for a message, at most four. Written as "example[.]com": chat apps turn a bare domain into a
     * link, and these may be an attacker's sites.
     */
    private function hostList(array $hosts)
    {
        $hosts = array_values(array_unique(array_map('strval', $hosts)));
        sort($hosts, SORT_STRING);
        $shown = array();
        foreach (array_slice($hosts, 0, 4) as $h)
        {
            $shown[] = $h === 'data:' ? $this->t('page_data_url') : str_replace('.', '[.]', $h);
        }
        return implode(', ', $shown) . (count($hosts) > 4 ? ' ' . $this->t('page_and_more', count($hosts) - 4) : '');
    }

    /** "home page", "/cart" — or with the host in front when the watched pages are on more than one site. */
    private function pageLabel($url)
    {
        $hosts = array();
        foreach ($this->listOf($this->cfg['page_watch']) as $u)
        {
            $hosts[$this->hostOf($u)] = true;
        }
        $p = preg_match('#^[a-z][a-z0-9+.-]*://[^/?\#]*([^\#]*)#i', $url, $m) ? $m[1] : '';
        $path = $p === '' || $p === '/' ? $this->t('page_home') : $p;
        return $this->cut((count($hosts) > 1 ? $this->hostOf($url) . ' ' : '') . $path, 70);
    }

    private function loadPages()
    {
        $f = $this->cfg['state_dir'] . '/pages.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        return is_array($j) ? $j : array();
    }

    private function savePages(array $rec)
    {
        $json = $this->json($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json !== false)
        {
            @file_put_contents($this->path('pages.json'), $json, LOCK_EX);
        }
    }

    /** For status(): how the page watch is doing, without reading any page. */
    private function pagesStatus()
    {
        $list = $this->listOf($this->cfg['page_watch']);
        $rec = $list ? $this->loadPages() : array();
        $out = array('watched' => count($list), 'checked' => 0, 'last_check' => null, 'failing' => array());
        foreach ($list as $url)
        {
            if (!isset($rec[$url]) || !is_array($rec[$url]))
            {
                continue;
            }
            $row = $rec[$url];
            if (isset($row['k'])) { $out['checked']++; }
            if (!empty($row['at'])) { $out['last_check'] = max((int) $out['last_check'], (int) $row['at']); }
            foreach (isset($row['f']) && is_array($row['f']) ? $row['f'] : array() as $v => $n)
            {
                $out['failing'][] = array('page' => $this->pageLabel($url), 'view' => (string) $v, 'times' => (int) $n,
                    'why' => isset($row['w'][$v]) ? (string) $row['w'][$v] : '');
            }
        }
        return $out;
    }

    /* ======================================================================
     * Dispatch
     * ====================================================================== */

    private function finding($kind, $key, $level, $title, array $lines, $quietHours = null)
    {
        return array('kind' => $kind, 'key' => $key, 'level' => (int) $level, 'title' => (string) $title, 'lines' => $lines, 'quiet' => $quietHours);
    }

    private function dispatch(array $findings, array &$state, $now)
    {
        $alerted = isset($state['alerted']) && is_array($state['alerted']) ? $state['alerted'] : array();
        foreach ($alerted as $k => $t)
        {
            if ($now - (int) $t > 7 * 86400) { unset($alerted[$k]); }
        }
        $send = array();
        $status = array();
        foreach ($findings as $i => $f)
        {
            $status[$i] = 'logged';
            if ($f['level'] < self::NOTICE) { continue; }
            $quiet = $f['quiet'] !== null ? (int) $f['quiet'] : (int) $this->cfg['quiet_hours'];
            if (isset($alerted[$f['key']]) && ($now - (int) $alerted[$f['key']]) < $quiet * 3600)
            {
                $status[$i] = 'repeat';
                continue;
            }
            $send[] = $i;
        }
        $result = 'none';
        if ($send)
        {
            $day = date('Y-m-d', $now);
            $used = (isset($state['push_day']) && $state['push_day'] === $day) ? (int) $state['push_count'] : 0;
            $urgent = false;
            foreach ($send as $i) { if ($findings[$i]['level'] >= self::URGENT) { $urgent = true; } }
            if (!$urgent && $used >= $this->cfg['daily_cap'])
            {
                foreach ($send as $i)
                {
                    $status[$i] = 'capped';   // kept in findings.ndjson; not retried every tick
                    $alerted[$findings[$i]['key']] = $now;
                }
                $result = 'capped';
            }
            else
            {
                usort($send, function ($a, $b) use ($findings) { return $findings[$b]['level'] - $findings[$a]['level']; });
                $msg = $this->composeMsg(array_map(function ($i) use ($findings) { return $findings[$i]; }, $send), $now);
                if ($urgent)
                {
                    $msg = $this->withBrake($msg);
                }
                $r = $this->deliver($msg, $urgent ? self::URGENT : self::NOTICE);
                foreach ($send as $i)
                {
                    $status[$i] = $r;
                    $alerted[$findings[$i]['key']] = $now;   // delivered, or queued just below: either way it is not found "again"
                }
                if ($this->isChat($r))
                {
                    $state['push_day'] = $day;
                    $state['push_count'] = $used + 1;
                }
                if ($r === 'failed')
                {
                    /* Nothing could take the message (LINE down or refusing, and no e-mail). Keep it and try again
                       on the following runs: a one-time finding — a changed file, a new admin account — is seen
                       only once, so without this it would end up in the log and nowhere else. */
                    $item = array('t' => $now, 'text' => $msg['plain'], 'msg' => $msg, 'urgent' => $urgent ? 1 : 0, 'n' => count($send), 'u' => 0, 'files' => 0);
                    foreach ($send as $i)
                    {
                        if ($findings[$i]['level'] >= self::URGENT) { $item['u']++; }
                        if ($findings[$i]['kind'] === 'files') { $item['files']++; }
                    }
                    $hbNow = $this->tally($state, $now);
                    $item['hb'] = (int) $hbNow['at'];
                    $box = isset($state['outbox']) && is_array($state['outbox']) ? array_values($state['outbox']) : array();
                    $box[] = $item;
                    $state['outbox'] = array_slice($box, -20);
                }
                if ($r !== 'failed')
                {
                    /* tallies for the weekly "still on duty" message */
                    $hb = $this->tally($state, $now);
                    $hb['sent'] += count($send);
                    foreach ($send as $i) { if ($findings[$i]['level'] >= self::URGENT) { $hb['urgent']++; } }
                    if ($r === 'line') { $hb['line']++; }
                    $state['hb'] = $hb;
                }
                $result = $r;
            }
        }
        $state['alerted'] = $alerted;
        $hb = $this->tally($state, $now);
        foreach ($findings as $i => $f)
        {
            if ($status[$i] === 'repeat') { continue; }   // same finding again within the quiet window
            if ($f['kind'] === 'files')
            {
                /* Every one of these means the recorded baseline moved. The weekly check-in uses the two counts
                   to explain a changed fingerprint: the owner was told / it was only written to the log. */
                $hb[$this->isChat($status[$i]) || $status[$i] === 'mail' ? 'files_sent' : 'files_quiet']++;
            }
            $this->append('findings.ndjson', array('t' => $now, 'level' => $f['level'], 'kind' => $f['kind'], 'key' => $f['key'],
                'title' => $f['title'], 'lines' => $this->flat($f['lines']), 'status' => $status[$i]));
        }
        $state['hb'] = $hb;
        return $result;
    }

    /**
     * Sends what could not be sent earlier (see dispatch()). Oldest first, at most three per run; stops at the
     * first one that still fails, so a channel that is still down costs one attempt per run, not twenty.
     * A message that has waited seven days is given up (it stays in findings.ndjson).
     *
     * @return int how many were delivered now
     */
    private function flushOutbox(array &$state, $now)
    {
        $box = isset($state['outbox']) && is_array($state['outbox']) ? array_values($state['outbox']) : array();
        if (!$box)
        {
            return 0;
        }
        $done = 0;
        $keep = array();
        $stop = false;
        foreach ($box as $item)
        {
            if (!is_array($item) || !isset($item['t'], $item['text']))
            {
                continue;
            }
            $when = date('m/d H:i', (int) $item['t']);
            if ($now - (int) $item['t'] > 7 * 86400)
            {
                $this->append('findings.ndjson', array('t' => $now, 'level' => self::LOG, 'kind' => 'system', 'key' => 'late:expired',
                    'title' => $this->t('late_title'), 'lines' => array($this->t('late_expired', $when)), 'status' => 'expired'));
                continue;
            }
            if ($stop || $done >= 3)
            {
                $keep[] = $item;
                continue;
            }
            /* kept by 1.4+ with its layout; an older record has the text only */
            $late = isset($item['msg']) && is_array($item['msg']) && isset($item['msg']['plain']) ? $item['msg'] : $this->plainMsg((string) $item['text']);
            $late['note'] = $this->t('late_note', $when);
            $late['plain'] = $this->cut($late['note'] . "\n\n" . (string) $late['plain'], 4700);
            if (!empty($item['urgent']))
            {
                $late = $this->withBrake($late);   // the link in the kept text may have expired by now: a fresh one
            }
            $r = $this->deliver($late, !empty($item['urgent']) ? self::URGENT : self::NOTICE);
            if ($r === 'failed')
            {
                $stop = true;
                $keep[] = $item;
                continue;
            }
            $done++;
            if ($this->isChat($r))
            {
                $day = date('Y-m-d', $now);
                $state['push_count'] = ((isset($state['push_day']) && $state['push_day'] === $day) ? (int) $state['push_count'] : 0) + 1;
                $state['push_day'] = $day;
            }
            $hb = $this->tally($state, $now);
            $hb['sent'] += isset($item['n']) ? (int) $item['n'] : 1;
            $hb['urgent'] += isset($item['u']) ? (int) $item['u'] : 0;
            if ($r === 'line') { $hb['line']++; }
            $files = isset($item['files']) ? (int) $item['files'] : 0;
            if ($files > 0)
            {
                /* the weekly check-in explains a changed fingerprint by "N notices were sent": now they were */
                $hb['files_sent'] += $files;
                if (isset($item['hb']) && (int) $item['hb'] === (int) $hb['at'])
                {
                    $hb['files_quiet'] = max(0, (int) $hb['files_quiet'] - $files);
                }
            }
            $state['hb'] = $hb;
            $this->append('findings.ndjson', array('t' => $now, 'level' => self::LOG, 'kind' => 'system', 'key' => 'late',
                'title' => $this->t('late_title'), 'lines' => array($this->t('late_note', $when)), 'status' => $r));
        }
        if ($keep)
        {
            $state['outbox'] = $keep;
        }
        else
        {
            unset($state['outbox']);
        }
        return $done;
    }

    /** The counters behind the weekly check-in, with every field present (older state files lack some). */
    private function tally(array $state, $now)
    {
        $hb = isset($state['hb']) && is_array($state['hb']) ? $state['hb'] : array();
        return $hb + array('at' => $now, 'runs' => 0, 'sent' => 0, 'urgent' => 0, 'files_sent' => 0, 'files_quiet' => 0, 'line' => 0);
    }

    /**
     * The module watching itself. Someone who breaks in and knows about the monitor will try to reset it,
     * so "the records are gone" is itself an alert. (Lost file fingerprints are handled in checkFiles().)
     */
    private function checkTamper(array &$state, $now)
    {
        $out = array();
        $fresh = empty($state['installed_at']);
        $witness = (string) $this->cfg['witness_file'];
        if ($fresh && $witness !== '' && is_file($witness))
        {
            $since = trim((string) @file_get_contents($witness));
            $out[] = $this->finding('system', 'state:lost:' . date('Ymd', $now), self::URGENT, $this->t('state_lost_title'),
                array($this->t('state_lost_body', preg_match('/^[0-9]+$/', $since) ? date('Y-m-d', (int) $since) : '?'), $this->hint('file_lost_hint')), 24);
        }
        if ($fresh)
        {
            $state['installed_at'] = $now;
        }
        if ($witness !== '' && !is_file($witness))
        {
            @file_put_contents($witness, (string) $state['installed_at'], LOCK_EX);
        }
        return $out;
    }

    /**
     * Once every `heartbeat_days`, in the daytime, say "still on duty" with a few numbers. If the cron job
     * dies, the token expires or the server is rebuilt without the module, the owner notices because the
     * weekly message stops coming. Returns 'off' | 'not due' | 'waiting for daytime' | a channel name (see deliver()) | 'failed'.
     */
    private function heartbeat(array &$state, $now)
    {
        $hb = $this->tally($state, $now);
        $hb['runs']++;
        $state['hb'] = $hb;
        $days = (int) $this->cfg['heartbeat_days'];
        if ($days <= 0)
        {
            return 'off';
        }
        if (($now - (int) $hb['at']) < $days * 86400)
        {
            return 'not due';
        }
        $hour = (int) date('G', $now);
        if ($hour < (int) $this->cfg['heartbeat_hour'] || $hour >= 21)
        {
            return 'waiting for daytime';
        }
        if ($this->expectState() !== null)
        {
            /* the changes of an update window are told in its summary; a check-in now would see a new
               fingerprint with no change on record yet. At most a few hours: windows are capped. */
            return 'waiting for the update window';
        }
        $body = array(
            $this->t('hb_counts', max(1, (int) round(($now - (int) $hb['at']) / 86400)), (int) $hb['runs'], (int) $hb['sent'], (int) $hb['urgent']),
        );
        $warn = false;
        if ($this->cfg['file_scan'] && !empty($state['files_complete_at']))
        {
            $body[] = $this->t('hb_files', isset($state['files_count']) ? (int) $state['files_count'] : 0, date('m/d H:i', (int) $state['files_complete_at']));
        }
        /* The fingerprint of all code files. It is recorded here, in a place the server cannot rewrite (the
           owner's chat), and compared with the one in the previous check-in. A different fingerprint is fine
           when file changes were reported in between; with no change on record it means the fingerprint
           records themselves were edited. */
        $code = null;
        $fp = ($this->cfg['file_scan'] && !empty($state['files_baselined'])) ? $this->fingerprint() : null;
        if ($fp === null)
        {
            unset($state['hb_fp']);   // no settled baseline right now: nothing to compare the next one with
        }
        else
        {
            $code = $fp['code'];
            $prev = isset($state['hb_fp']) ? (string) $state['hb_fp'] : '';
            if ($prev === '')
            {
                $body[] = $this->t('hb_fp_first', $code);
            }
            elseif ($prev === $code)
            {
                $body[] = $this->t('hb_fp_same', $code);
            }
            elseif ((int) $hb['files_sent'] > 0)
            {
                $body[] = $this->t('hb_fp_diff_sent', $code, $prev, (int) $hb['files_sent']);
            }
            elseif ((int) $hb['files_quiet'] > 0)
            {
                $body[] = $this->t('hb_fp_diff_quiet', $code, $prev, (int) $hb['files_quiet']);
            }
            else
            {
                $body[] = $this->t('hb_fp_diff_none', $code, $prev);
                $warn = true;
            }
        }
        if (trim((string) $this->cfg['ping_url']) !== '')
        {
            if (isset($state['ping_fail']) && is_array($state['ping_fail']) && (int) $state['ping_fail']['n'] >= 3)
            {
                /* three in a row: not a hiccup any more (a single missed call is absorbed by the service's grace time) */
                $body[] = $this->t('hb_ping_bad', (int) $state['ping_fail']['n'], date('m/d H:i', (int) $state['ping_fail']['since']));
                $warn = true;
            }
            else
            {
                $body[] = $this->t('hb_ping_ok');
            }
        }
        /* LINE's monthly allowance, only when LINE is really in use: the main channel (or the one kept for urgent
           alerts), or a backup that did have to carry something since the last check-in */
        $quota = ($this->lineIsMain() || (int) $hb['line'] > 0) ? $this->lineQuota() : null;
        if ($quota !== null)
        {
            if ($quota['used'] >= $quota['limit'])
            {
                $body[] = $this->t('hb_quota_out', $quota['limit'], $quota['used']);
                $warn = true;
            }
            elseif ($quota['used'] >= 0.8 * $quota['limit'])
            {
                $body[] = $this->t('hb_quota_low', $quota['used'], $quota['limit']);
                $warn = true;
            }
            else
            {
                $body[] = $this->t('hb_quota', $quota['used'], $quota['limit']);
            }
        }
        /* asked whenever a LINE key is set up, used or not: the risk is the key lying on the server */
        $friends = $this->lineFriendCount();
        if ($friends !== null && $friends > (int) $this->cfg['line_friends_warn'])
        {
            $body[] = $this->t('hb_friends', $friends);
            $warn = true;
        }
        /* Every channel checked without sending anything (1.4.0) — when there is more than one place a message can go:
           a backup is used only when the main channel fails, which is the worst moment to find out that it stopped
           working weeks ago; and a LINE recipient who blocked the account still gets "sent" from LINE. With a
           single place, this check-in arriving is the check. */
        if ($this->destinations() > 1)
        {
            $good = array();
            $bad = array();
            $on = $this->channels();
            $codes = array('blocked', 'kicked', 'chat_not_found', 'topic_gone', 'token', 'webhook_gone', 'webhook_bad', 'forum_thread',
                'recipient_gone', 'quota', 'rate', 'server', 'network');
            /* A check-in that could not be delivered is tried again on every run: the channels are asked at most
               once in 20 hours (a check by --status counts), not on each of those tries. */
            $cj = json_decode((string) @file_get_contents($this->cfg['state_dir'] . '/channels.json'), true);
            $fresh = is_array($cj) && isset($cj['at'], $cj['channels']) && is_numeric($cj['at']) && is_array($cj['channels'])
                && $now >= (int) $cj['at'] && $now - (int) $cj['at'] < 20 * 3600;
            foreach ($fresh ? $cj['channels'] : $this->checkAll() as $ch => $h)
            {
                if (!isset($on[$ch]) || !is_array($h) || !array_key_exists('ok', $h))
                {
                    continue;
                }
                if ($h['ok'] === true)
                {
                    $good[] = $this->t('ch_name_' . $ch);
                }
                elseif ($h['ok'] === false)
                {
                    $code = isset($h['code']) && in_array($h['code'], $codes, true) ? $h['code'] : 'other';
                    $bad[] = $this->t('ch_with_reason', $this->t('ch_name_' . $ch), $this->t('chw_' . $code));
                }
            }
            if ($bad)
            {
                $body[] = $this->t('hb_channels_bad', implode($this->t('list_sep'), $bad));
                $warn = true;
            }
            elseif ($good)
            {
                $body[] = $this->t('hb_channels_ok', implode($this->t('name_sep'), $good));
            }
        }
        $body[] = $this->hint('hb_since', date('Y-m-d', (int) $state['installed_at']));
        $body[] = $this->hint('hb_hint');
        $head = $this->t($warn ? 'hb_header_warn' : 'hb_header', $this->cfg['site_name'], date('m/d H:i', $now));
        $lines = array_merge(array($head, ''), $this->flat($body));
        $r = $this->deliver(array('kind' => 'checkin', 'head' => $head, 'note' => '', 'brake' => '', 'warn' => $warn,
            'items' => array($this->item(-1, '', $body)), 'plain' => implode("\n", $lines)), $warn ? self::NOTICE : self::LOG);
        $today = date('Y-m-d', $now);
        if ($r !== 'failed')
        {
            $state['hb'] = array('at' => $now, 'runs' => 0, 'sent' => 0, 'urgent' => 0, 'files_sent' => 0, 'files_quiet' => 0, 'line' => 0);
            if ($code !== null)
            {
                $state['hb_fp'] = $code;
            }
            unset($state['hb_failed_on']);
        }
        elseif (isset($state['hb_failed_on']) && $state['hb_failed_on'] === $today)
        {
            return $r;   // already logged today; it is retried on every run until it goes out
        }
        else
        {
            $state['hb_failed_on'] = $today;
        }
        $this->append('findings.ndjson', array('t' => $now, 'level' => self::LOG, 'kind' => 'heartbeat', 'key' => 'heartbeat',
            'title' => $this->t('hb_title'), 'lines' => array_slice($lines, 2), 'status' => $r));
        return $r;
    }

    /** The plain text of an alert: what LINE, e-mail and a notifier get, and what every channel falls back to. */
    private function compose(array $list, $now)
    {
        $lines = array($this->t('header', $this->cfg['site_name'], date('m/d H:i', $now)));
        foreach ($list as $f)
        {
            $lines[] = '';
            $lines[] = '【' . $this->t('level_' . $f['level']) . '】' . $f['title'];
            foreach ($this->flat(array_slice($f['lines'], 0, 8)) as $l) { $lines[] = $l; }
        }
        $text = implode("\n", $lines);
        $cut = $this->cut($text, 4480);   // LINE's text limit is 5000 characters
        if ($cut !== $text)
        {
            $text = $cut . "\n…";
        }
        return $text;
    }

    /**
     * A message as handed to deliver(). 'plain' is the text above, exactly; the rest lets Telegram and Discord lay
     * it out (bold titles, the advice set apart, buttons, coloured cards).
     *   kind  'alert' | 'checkin' | 'test' | 'plain'        head  the first line (site, time)
     *   items list of array('level' => -1..2, 'title', 'lines' => list, 'hints' => list)   (null = plain only)
     *   note  '' or the "Delayed" note       brake  '' or the emergency-brake address       warn  check-in with a ⚠
     */
    private function composeMsg(array $list, $now)
    {
        $items = array();
        foreach ($list as $f)
        {
            $items[] = $this->item((int) $f['level'], (string) $f['title'], array_slice($f['lines'], 0, 8));
        }
        return array('kind' => 'alert', 'head' => $this->t('header', $this->cfg['site_name'], date('m/d H:i', $now)), 'items' => $items,
            'note' => '', 'brake' => '', 'warn' => false, 'plain' => $this->compose($list, $now));
    }

    /** A message that is text only (an older outbox record, a caller's own text). */
    private function plainMsg($text)
    {
        return array('kind' => 'plain', 'head' => '', 'items' => null, 'note' => '', 'brake' => '', 'warn' => false, 'plain' => (string) $text);
    }

    /** One finding (or the check-in body) for the rich layouts: the advice lines apart from the others. */
    private function item($level, $title, array $lines)
    {
        $plain = array();
        $hints = array();
        foreach ($lines as $l)
        {
            if (is_array($l))
            {
                $hints[] = isset($l['hint']) && is_scalar($l['hint']) ? (string) $l['hint'] : '';
            }
            else
            {
                $plain[] = (string) $l;
            }
        }
        return array('level' => (int) $level, 'title' => (string) $title, 'lines' => $plain, 'hints' => array_values(array_filter($hints, 'strlen')));
    }

    /**
     * A line of advice ("what to do"). In plain text it is a line like any other; Telegram folds it away under
     * the facts, Discord puts it in a box of its own. Same arguments as t().
     */
    private function hint($key)
    {
        return array('hint' => call_user_func_array(array($this, 't'), func_get_args()));
    }

    /** Finding lines as plain strings (advice included, in place). */
    private function flat(array $lines)
    {
        $out = array();
        foreach ($lines as $l)
        {
            $out[] = is_array($l) ? (isset($l['hint']) && is_scalar($l['hint']) ? (string) $l['hint'] : '') : (string) $l;
        }
        return $out;
    }

    /**
     * The last line of an URGENT message: the emergency-brake link (replacing an older one), when the brake is set
     * up. The same link goes into 'brake', for the button on Telegram.
     */
    private function withBrake(array $msg)
    {
        $plain = $this->withoutBrake($msg);
        $link = $this->brakeLink();
        $msg['brake'] = $link;
        $msg['plain'] = $link === '' ? $plain : $plain . "\n\n" . $this->t('brake_line', (int) $this->cfg['brake_hours'], $link);
        return $msg;
    }

    /**
     * The plain text without the brake line that withBrake() put at its end — that line only: a finding line that
     * merely looks like it (a finding can say anything) stays where it is. A message kept from 1.3 has no 'brake';
     * its line is recognised by the signed token it ends with.
     */
    private function withoutBrake(array $msg)
    {
        $plain = (string) $msg['plain'];
        $end = (string) $msg['brake'] !== '' ? preg_quote((string) $msg['brake'], '/') : '\S*[?&]t=[0-9]{9,11}\.[0-9a-f]{16}\.[0-9a-f]{32}';
        $out = preg_replace('/\n\n' . self::BRAKE_MARK . '[^\n]*' . $end . '$/u', '', $plain);
        return is_string($out) ? $out : $plain;
    }

    /** Does a message of this level arrive without ringing? (see ring_level; URGENT ones and tests always ring) */
    private function silent($level, array $msg)
    {
        return $msg['kind'] !== 'test' && (int) $level < max(0, min(self::URGENT, (int) $this->cfg['ring_level']));
    }

    /** The "what to do" address for alerts on Telegram and Discord, or ''. */
    private function guideUrl()
    {
        $g = is_scalar($this->cfg['guide_url']) ? trim((string) $this->cfg['guide_url']) : '';
        if ($g === 'auto')
        {
            return 'https://github.com/brain113tw/line-security-alerts/blob/main/skills/line-security-alerts/reference/when-an-alert-arrives'
                . ($this->cfg['language'] === 'zh-TW' ? '.zh-TW' : ($this->cfg['language'] === 'ja' ? '.ja' : '')) . '.md';
        }
        return preg_match('#^https?://[^\s<>"]+$#i', $g) ? $g : '';
    }

    /**
     * Calls the check-in address, if one is configured. Whatever happens here stays here: the checks and the
     * alerts of this run are already done and saved. The address itself is never logged; only a failing
     * streak is remembered, so the weekly check-in can say that the outside watcher is not being reached.
     *
     * @return string 'off' | 'ok' | 'failed'
     */
    private function ping(array &$state, $now)
    {
        $url = trim((string) $this->cfg['ping_url']);
        if ($url === '' || !$this->cfg['enabled'])
        {
            return 'off';
        }
        $ok = false;
        if (preg_match('#^https?://\S+$#i', $url))
        {
            $timeout = max(1, min(30, (int) $this->cfg['ping_timeout']));
            try
            {
                if (is_callable($this->cfg['ping_transport']))
                {
                    $code = (int) call_user_func($this->cfg['ping_transport'], $url, $timeout);
                }
                else
                {
                    $res = $this->request('GET', $url, array('User-Agent: line-security-alerts'), '', $timeout);
                    $code = (int) $res[0];
                }
                $ok = $code >= 200 && $code < 300;
            }
            catch (Throwable $e)
            {
                $ok = false;
            }
        }
        $failing = isset($state['ping_fail']) && is_array($state['ping_fail']);
        try
        {
            if ($ok && $failing)
            {
                unset($state['ping_fail']);
                $this->saveState($state);
            }
            elseif (!$ok)
            {
                $state['ping_fail'] = array('n' => ($failing ? (int) $state['ping_fail']['n'] : 0) + 1,
                    'since' => $failing ? (int) $state['ping_fail']['since'] : (int) $now);
                $this->saveState($state);
            }
        }
        catch (Throwable $e)
        {
        }
        return $ok ? 'ok' : 'failed';
    }

    /**
     * Sends one message through the first channel that takes it (see route()).
     *
     * @param  array|string $msg    a message from composeMsg() and friends, or plain text
     * @param  bool         $manual sent because a person asked (a test): also tries a Discord webhook remembered as deleted
     * @return string the channel that took it: 'custom' | 'telegram' | 'discord' | 'line' | 'mail'; or 'failed'
     */
    private function deliver($msg, $level = self::NOTICE, $manual = false)
    {
        if (!is_array($msg))
        {
            $msg = $this->plainMsg((string) $msg);
        }
        foreach ($this->route((int) $level) as $ch)
        {
            $r = $this->sendVia($ch, $msg, $level, $manual);
            if ($r[0])
            {
                return $ch;
            }
        }
        return 'failed';
    }

    /** The channels that are set up, in the order they are normally tried. @return array name => true */
    private function channels()
    {
        $on = array();
        if (is_callable($this->cfg['notifier'])) { $on['custom'] = true; }
        if (trim((string) $this->cfg['telegram_bot_token']) !== '' && $this->listOf($this->cfg['telegram_chat_id'])) { $on['telegram'] = true; }
        if ($this->listOf($this->cfg['discord_webhook_url'])) { $on['discord'] = true; }
        if ((string) $this->cfg['line_channel_access_token'] !== '' && $this->listOf($this->cfg['line_to'])) { $on['line'] = true; }
        if ((string) $this->cfg['mail_to'] !== '') { $on['mail'] = true; }
        return $on;
    }

    /** How many places a message can go: each Telegram chat, Discord webhook and LINE recipient, the notifier, e-mail. */
    private function destinations()
    {
        $n = 0;
        foreach (array_keys($this->channels()) as $ch)
        {
            $n += $ch === 'telegram' ? count($this->listOf($this->cfg['telegram_chat_id']))
                : ($ch === 'discord' ? count($this->listOf($this->cfg['discord_webhook_url'])) : ($ch === 'line' ? count($this->listOf($this->cfg['line_to'])) : 1));
        }
        return $n;
    }

    /**
     * The order the channels are tried in for a message of this level. Normally: your notifier, Telegram,
     * Discord, LINE, e-mail. With `line_min_level`, LINE goes first for the messages at or above that level and
     * is left out for the others, unless nothing else is set up (better on LINE than nowhere).
     */
    private function route($level)
    {
        $on = array_keys($this->channels());
        $min = (int) $this->cfg['line_min_level'];
        if ($min <= 0 || !in_array('line', $on, true))
        {
            return $on;
        }
        $others = array_values(array_diff($on, array('line')));
        if ($level >= $min)
        {
            return array_merge(array('line'), $others);
        }
        return $others ? $others : array('line');
    }

    /** LINE carries messages of its own, not only as a backup behind other channels. */
    private function lineIsMain()
    {
        foreach (array(self::URGENT, self::NOTICE) as $level)
        {
            $r = $this->route($level);
            if ($r && $r[0] === 'line')
            {
                return true;
            }
        }
        return false;
    }

    /** Delivered to a chat app (counts towards daily_cap). */
    private function isChat($r)
    {
        return in_array($r, array('custom', 'telegram', 'discord', 'line'), true);
    }

    /** '' / one value / an array of values -> a list of the non-empty ones */
    private function listOf($v)
    {
        $out = array();
        foreach ((array) $v as $x)
        {
            if (is_scalar($x) && trim((string) $x) !== '')
            {
                $out[] = trim((string) $x);
            }
        }
        return $out;
    }

    /**
     * @return array array(bool $delivered, string $whyNot, string $failCode); the reason never contains a token or
     *               an address; the code is a short word for it (see failCode())
     */
    private function sendVia($ch, array $msg, $level = self::NOTICE, $manual = false)
    {
        $silent = $this->silent($level, $msg);
        try
        {
            switch ($ch)
            {
                case 'custom':
                    /* Your own channel. If it says no (or breaks), the next channel is tried. */
                    return call_user_func($this->cfg['notifier'], $msg['plain'], (int) $level, $silent)
                        ? array(true, '', '') : array(false, 'the notifier returned false', 'other');
                case 'telegram':
                    return $this->sendTelegram($msg, $silent);
                case 'discord':
                    return $this->sendDiscord($msg, $silent, $manual);
                case 'line':
                    return $this->sendLine($msg['plain'], $silent);
                case 'mail':
                    return $this->sendMail($msg['plain']);
            }
        }
        catch (Throwable $e)
        {
            return array(false, 'an error inside the ' . $ch . ' channel', 'other');   // the exception text could quote an address: not shown
        }
        return array(false, 'unknown channel', 'other');
    }

    /** $silent: no push notification on the phone (the message is in the chat all the same) */
    private function sendLine($text, $silent = false)
    {
        $ok = 0;
        $why = '';
        $code = '';
        $url = rtrim((string) $this->cfg['line_api_base'], '/') . '/v2/bot/message/push';
        $headers = array('Content-Type: application/json', 'Authorization: Bearer ' . (string) $this->cfg['line_channel_access_token']);
        foreach ($this->listOf($this->cfg['line_to']) as $to)
        {
            $req = array('to' => $to, 'messages' => array(array('type' => 'text', 'text' => $text)));
            if ($silent)
            {
                $req['notificationDisabled'] = true;
            }
            $r = (array) $this->http($url, $headers, (string) $this->json($req, JSON_UNESCAPED_UNICODE));
            $status = isset($r[0]) ? (int) $r[0] : 0;
            if ($status >= 200 && $status < 300)
            {
                $ok++;
            }
            else
            {
                $resp = isset($r[1]) ? (string) $r[1] : '';
                $why = $this->failReason($status, $resp);
                $code = $this->failCode('line', $status, json_decode($resp, true));
            }
        }
        return array($ok > 0, $ok > 0 ? '' : $why, $ok > 0 ? '' : $code);
    }

    private function sendMail($text)
    {
        $subject = $this->t('mail_subject', $this->cfg['site_name']);
        $sent = is_callable($this->cfg['mailer'])
            ? (bool) call_user_func($this->cfg['mailer'], $this->cfg['mail_to'], $subject, $text, $this->cfg['mail_from'])
            : @mail($this->cfg['mail_to'], '=?UTF-8?B?' . base64_encode($subject) . '?=', $text,
                'Content-Type: text/plain; charset=UTF-8' . ($this->cfg['mail_from'] !== '' ? "\r\nFrom: " . $this->cfg['mail_from'] : ''));
        return array((bool) $sent, $sent ? '' : 'the mail function did not accept the message', $sent ? '' : 'other');
    }

    /**
     * Telegram Bot API, sendMessage, no link previews. With rich_messages: HTML (bold titles, the advice in a
     * blockquote that opens on a tap) and buttons (the emergency brake, "what to do"). Telegram refusing any of
     * that (a 400) means the same message is sent again as plain text, so a formatting slip never costs an alert.
     * Plain text has no parse_mode: "_" or "*" in a file name stay as they are. Up to 4096 characters a message;
     * a longer one goes in parts, as plain text. The token is part of the address: the address is never written anywhere.
     */
    private function sendTelegram(array $msg, $silent = false)
    {
        $token = trim((string) $this->cfg['telegram_bot_token']);
        if (!preg_match('/^[0-9]+:[A-Za-z0-9_-]+$/', $token))
        {
            return array(false, 'the bot token does not look like "123456789:ABC..." (the form @BotFather gives)', 'token');
        }
        $base = rtrim((string) $this->cfg['telegram_api_base'], '/') . '/bot' . $token . '/';
        $rich = $this->cfg['rich_messages'] && is_array($msg['items']) && $this->units($msg['plain']) <= 4000;
        $html = $rich ? $this->telegramHtml($msg) : '';
        $keys = $rich ? $this->telegramButtons($msg) : null;
        $parts = null;
        $ok = 0;
        $why = '';
        $code = '';
        foreach ($this->listOf($this->cfg['telegram_chat_id']) as $spec)
        {
            list($chat, $topic) = $this->telegramTarget($spec);
            $done = false;
            if ($rich)
            {
                $p = array('text' => $html, 'parse_mode' => 'HTML');
                if ($keys !== null)
                {
                    $p['reply_markup'] = $keys;
                }
                $r = $this->telegramCall($base, 'sendMessage', $chat, $topic, $p, $silent);
                $chat = $r[4];   // a group that turned into a supergroup has a new id: the plain retry goes there too
                if ($r[0])
                {
                    $done = true;
                }
                elseif ($r[2] !== 400)
                {
                    $why = $r[1];      // not a formatting problem: plain text would be refused just the same
                    $code = $r[3];
                    continue;
                }
            }
            if (!$done)
            {
                if ($parts === null)
                {
                    $parts = $this->split($msg['plain'], 4000);
                }
                $done = true;
                foreach ($parts as $part)
                {
                    $r = $this->telegramCall($base, 'sendMessage', $chat, $topic, array('text' => $part), $silent);
                    $chat = $r[4];
                    if (!$r[0])
                    {
                        $done = false;
                        $why = $r[1];
                        $code = $r[3];
                        break;
                    }
                }
            }
            if ($done)
            {
                $ok++;
            }
        }
        return array($ok > 0, $ok > 0 ? '' : $why, $ok > 0 ? '' : $code);
    }

    /**
     * One Bot API call for one chat. When a group has been turned into a supergroup, Telegram refuses the old id and
     * names the new one: the call is repeated there once. Nothing is stored: every message follows Telegram's own
     * answer, so no file on the server can send alerts elsewhere. The move is counted in $tgMoved for the channel
     * check (--status then asks you to update telegram_chat_id).
     *
     * @return array array(bool $ok, string $whyNot, int $httpStatus, string $failCode, string $chatIdUsed, mixed $decodedAnswer)
     */
    private function telegramCall($base, $method, $chat, $topic, array $params, $silent)
    {
        for ($hop = 0; $hop < 2; $hop++)
        {
            $p = array_merge(array('chat_id' => $chat), $params);
            if ($topic > 0)
            {
                $p['message_thread_id'] = $topic;
            }
            if ($method === 'sendMessage')
            {
                $p['link_preview_options'] = array('is_disabled' => true);
                if ($silent)
                {
                    $p['disable_notification'] = true;
                }
            }
            $r = $this->post($base . $method, (string) $this->json($p, JSON_UNESCAPED_UNICODE));
            if ($r[0])
            {
                return array(true, '', 0, '', $chat, $r[3]);
            }
            $j = $r[3];
            $new = $hop === 0 ? $this->migratedTo($j) : '';
            if ($new !== '')
            {
                $this->tgMoved[(string) $chat] = $new;
                $chat = $new;
                continue;
            }
            return array(false, $r[1], (int) $r[2], $this->failCode('telegram', (int) $r[2], $j), $chat, $j);
        }
        return array(false, 'the group moved more than once', 0, 'chat_not_found', $chat, null);
    }

    /** The supergroup id in Telegram's "group chat was upgraded" answer, or '' (a supergroup id always starts with -100). */
    private function migratedTo($j)
    {
        $x = is_array($j) && isset($j['parameters']) && is_array($j['parameters']) && isset($j['parameters']['migrate_to_chat_id'])
            ? $j['parameters']['migrate_to_chat_id'] : null;
        return is_scalar($x) && preg_match('/^-100[0-9]{1,17}$/', (string) $x) ? (string) $x : '';
    }

    /** "-1001234567890/12" = topic 12 of that group. @return array array(chat id, topic number or 0) */
    private function telegramTarget($spec)
    {
        $spec = trim((string) $spec);
        $topic = 0;
        if (preg_match('#^(.+)/([0-9]{1,12})$#', $spec, $m))
        {
            $spec = $m[1];
            $topic = (int) $m[2];
        }
        return array($spec, $topic);
    }

    /** The message in Telegram's HTML: only <b>, <i> and <blockquote expandable>; every text escaped. */
    private function telegramHtml(array $msg)
    {
        $e = function ($s) { return htmlspecialchars((string) $s, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8'); };
        $out = array();
        if ($msg['note'] !== '')
        {
            $out[] = '<i>' . $e($msg['note']) . '</i>';
            $out[] = '';
        }
        if ($msg['head'] !== '')
        {
            $out[] = '<b>' . $e($msg['head']) . '</b>';
        }
        foreach ((array) $msg['items'] as $it)
        {
            $out[] = '';
            if ($it['title'] !== '')
            {
                $out[] = '<b>' . $e(($it['level'] >= 0 ? '【' . $this->t('level_' . $it['level']) . '】' : '') . $it['title']) . '</b>';
            }
            foreach ($it['lines'] as $l)
            {
                $out[] = $e($l);
            }
            if ($it['hints'])
            {
                $out[] = '<blockquote expandable>' . implode("\n", array_map($e, $it['hints'])) . '</blockquote>';
            }
        }
        return trim(implode("\n", $out));
    }

    /** Buttons under an alert: the emergency brake (URGENT, when set up) and "what to do". */
    private function telegramButtons(array $msg)
    {
        $rows = array();
        if ($msg['brake'] !== '')
        {
            $rows[] = array(array('text' => $this->t('btn_brake', (int) $this->cfg['brake_hours']), 'url' => $msg['brake']));
        }
        $g = $this->guideUrl();
        if ($msg['kind'] === 'alert' && $g !== '')
        {
            $rows[] = array(array('text' => $this->t('btn_guide'), 'url' => $g));
        }
        return $rows ? array('inline_keyboard' => $rows) : null;
    }

    /**
     * Discord webhook. Mentions never ping (allowed_mentions empty). With rich_messages, one card per finding
     * coloured by level (red URGENT, orange notice, green check-in), the facts in a code block (shown exactly as
     * written: a file name like __init__.php is not underlined, nothing in it becomes a link), the advice in a box
     * of its own, the brake / "what to do" links in a last card (links inside cards get no preview).
     * Too long for cards, or Discord refusing them (a 400): the plain form, the whole text in code blocks.
     * Sent with ?wait=true, so "accepted" means Discord saved the message. A webhook that Discord says does not
     * exist (404) is not used again until the address changes, as Discord asks (see discordGone()); a test sent
     * by a person ($manual) tries it once more. The address is the key: it is never written anywhere.
     */
    private function sendDiscord(array $msg, $silent = false, $manual = false)
    {
        $card = ($this->cfg['rich_messages'] && is_array($msg['items'])) ? $this->discordCard($msg, $silent) : null;
        $parts = null;
        $ok = 0;
        $why = '';
        $code = '';
        foreach ($this->listOf($this->cfg['discord_webhook_url']) as $url)
        {
            if (!preg_match('#^https?://\S+$#i', $url))
            {
                $why = 'the webhook address does not start with https://';
                $code = 'webhook_bad';
                continue;
            }
            $gone = $this->discordGone($url);
            if ($gone !== null && !$manual)
            {
                $why = $this->goneWhy($gone);
                $code = $gone['code'];
                continue;
            }
            $r = null;
            if ($card !== null)
            {
                $r = $this->post($this->discordUrl($url), (string) $this->json($card, JSON_UNESCAPED_UNICODE), true);
            }
            if ($r === null || (!$r[0] && (int) $r[2] === 400))
            {
                if ($parts === null)
                {
                    $parts = $this->discordPlain($msg, $silent);
                }
                foreach ($parts as $body)
                {
                    $r = $this->post($this->discordUrl($url), (string) $this->json($body, JSON_UNESCAPED_UNICODE), true);
                    if (!$r[0])
                    {
                        break;
                    }
                }
            }
            if ($r[0])
            {
                $ok++;
                if ($gone !== null)
                {
                    $this->discordGoneSet($url, '');
                }
                continue;
            }
            $why = $r[1];
            $code = $this->failCode('discord', (int) $r[2], $r[3]);
            if ((int) $r[2] === 404)
            {
                $this->discordGoneSet($url, $code === 'forum_thread' ? 'forum_thread' : 'webhook_gone');
            }
        }
        return array($ok > 0, $ok > 0 ? '' : $why, $ok > 0 ? '' : $code);
    }

    /** The webhook address with ?wait=true added (kept as it is when it already says). */
    private function discordUrl($url)
    {
        if (preg_match('/[?&]wait=/i', $url))
        {
            return $url;
        }
        return $url . (strpos($url, '?') === false ? '?' : '&') . 'wait=true';
    }

    /**
     * Discord's rate-limit documentation asks callers not to use a webhook again once it answered 404; repeated
     * tries earn the sending address a temporary restriction. Remembered by a fingerprint of the address
     * (?thread_id= included), never the address itself, with what the 404 was about: the webhook itself
     * ('webhook_gone') or the thread named by ?thread_id= ('forum_thread').
     *
     * @return array|null array('at' => when Discord said so, 'code' => 'webhook_gone' | 'forum_thread'); null = not remembered
     */
    private function discordGone($url)
    {
        $f = $this->cfg['state_dir'] . '/discord-gone.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        $k = hash('sha256', (string) $url);
        if (!is_array($j) || !isset($j[$k]) || !is_array($j[$k]) || !isset($j[$k]['at']) || !is_numeric($j[$k]['at']))
        {
            return null;
        }
        return array('at' => (int) $j[$k]['at'], 'code' => isset($j[$k]['code']) && $j[$k]['code'] === 'forum_thread' ? 'forum_thread' : 'webhook_gone');
    }

    /** $code: 'webhook_gone' | 'forum_thread' to remember the 404, '' to forget it */
    private function discordGoneSet($url, $code)
    {
        $f = $this->cfg['state_dir'] . '/discord-gone.json';
        $j = is_file($f) ? json_decode((string) @file_get_contents($f), true) : null;
        $j = is_array($j) ? $j : array();
        $k = hash('sha256', (string) $url);
        if ($code !== '')
        {
            $j[$k] = array('at' => $this->now(), 'code' => $code);
        }
        else
        {
            unset($j[$k]);
        }
        @file_put_contents($this->path('discord-gone.json'), (string) $this->json($j), LOCK_EX);
    }

    private function goneWhy(array $gone)
    {
        return 'Discord said on ' . date('Y-m-d H:i', $gone['at']) . ' that ' . ($gone['code'] === 'forum_thread' ? 'the thread in ?thread_id= does not exist'
            : 'this webhook does not exist') . ' (HTTP 404); this address is not tried again until it changes (a test you send tries it once more)';
    }

    /** The User-Agent header: Discord asks for "DiscordBot (address, version)". */
    private function ua($discord = false)
    {
        return 'User-Agent: ' . ($discord ? 'DiscordBot (https://github.com/brain113tw/line-security-alerts, ' . self::VERSION . ')'
            : 'line-security-alerts/' . self::VERSION);
    }

    /**
     * The plain form (as in 1.2 / 1.3): the text in a code block, where everything shows exactly as written and
     * nothing is a link; no backticks inside can close it (see noFence()). 2000 characters a message; longer goes
     * in parts. The emergency-brake line goes AFTER the block, so its link can be tapped — the line withBrake()
     * wrote, nothing else: a finding line that looks like it stays inside the block.
     * flags: 4 = no link previews, 4096 = no notification (silent).
     */
    private function discordPlain(array $msg, $silent)
    {
        $text = (string) $msg['plain'];
        $tail = '';
        if ((string) $msg['brake'] !== '')
        {
            $without = $this->withoutBrake($msg);
            if ($without !== $text)
            {
                $tail = (string) substr($text, strlen($without) + 2);   // after the "\n\n"
                $text = $without;
            }
        }
        $text = $this->noFence($text);
        $parts = $this->split($text, 1990 - 8 - ($tail === '' ? 0 : $this->units($tail) + 1));
        $last = count($parts) - 1;
        $out = array();
        foreach ($parts as $i => $part)
        {
            $out[] = array('content' => "```\n" . $part . "\n```" . ($i === $last && $tail !== '' ? "\n" . $tail : ''),
                'allowed_mentions' => array('parse' => array()), 'flags' => 4 | ($silent ? 4096 : 0));
        }
        return $out;
    }

    /** @return array|null the webhook body with cards, or null when the message does not fit Discord's card limits */
    private function discordCard(array $msg, $silent)
    {
        $colors = array(2 => 0xD92D20, 1 => 0xF79009, 0 => 0x12B76A, -1 => 0x12B76A);
        $embeds = array();
        $total = 0;
        foreach ((array) $msg['items'] as $it)
        {
            if ($msg['kind'] === 'test')
            {
                $color = 0x2E90FA;
            }
            elseif ($msg['kind'] === 'checkin')
            {
                $color = $msg['warn'] ? 0xF79009 : 0x12B76A;
            }
            else
            {
                $color = isset($colors[$it['level']]) ? $colors[$it['level']] : 0x98A2B3;
            }
            $e = array('color' => $color);
            if ($it['title'] !== '')
            {
                $e['title'] = $this->cutUnits($this->discordTitle(($it['level'] >= 0 ? '【' . $this->t('level_' . $it['level']) . '】' : '') . $it['title']), 256);
                $total += $this->units($e['title']);
            }
            if ($it['lines'])
            {
                $d = "```\n" . $this->noFence(implode("\n", $it['lines'])) . "\n```";
                if ($this->units($d) > 4096)
                {
                    return null;
                }
                $e['description'] = $d;
                $total += $this->units($d);
            }
            if ($it['hints'])
            {
                $v = $this->discordMd(implode("\n", $it['hints']));
                if ($this->units($v) > 1024)
                {
                    return null;
                }
                $e['fields'] = array(array('name' => $this->t('what_to_do'), 'value' => $v));
                $total += $this->units($v) + $this->units($this->t('what_to_do'));
            }
            if (count($e) > 1)
            {
                $embeds[] = $e;
            }
        }
        if (!$embeds)
        {
            return null;
        }
        /* the links go in a card of their own (the colour of the first one): a link inside a card gets no preview */
        $links = array();
        if ($msg['brake'] !== '')
        {
            $links[] = $this->discordLink($this->t('btn_brake', (int) $this->cfg['brake_hours']), $msg['brake']);
        }
        $g = $this->guideUrl();
        if ($msg['kind'] === 'alert' && $g !== '')
        {
            $links[] = $this->discordLink($this->t('btn_guide'), $g);
        }
        if ($links)
        {
            $d = implode("\n", $links);
            $embeds[] = array('color' => $embeds[0]['color'], 'description' => $d);
            $total += $this->units($d);
        }
        if (count($embeds) > 10 || $total > 5800)
        {
            return null;
        }
        $content = array();
        if ($msg['note'] !== '')
        {
            $content[] = '*' . $this->discordMd($msg['note']) . '*';
        }
        if ($msg['head'] !== '')
        {
            $content[] = '**' . $this->discordMd($msg['head']) . '**';
        }
        /* the titles in the message text as well: they are what a phone notification shows, and all that is left
           for someone whose Discord is set not to show embeds */
        foreach ((array) $msg['items'] as $it)
        {
            if ($it['title'] !== '')
            {
                $content[] = $this->discordMd(($it['level'] >= 0 ? '【' . $this->t('level_' . $it['level']) . '】' : '') . $it['title']);
            }
        }
        $c = implode("\n", $content);
        if ($this->units($c) > 2000)
        {
            return null;
        }
        return array('content' => $c, 'embeds' => $embeds, 'allowed_mentions' => array('parse' => array()), 'flags' => $silent ? 4096 : 0);
    }

    /**
     * Text for inside a Discord code block: every backtick followed by an invisible zero-width space, so no run of
     * them (```, or five in a row, which would leave a closing ``` behind) can end the block early.
     */
    private function noFence($s)
    {
        return str_replace('`', "`\u{200B}", (string) $s);
    }

    /** Discord reads markdown in message text and card fields: this shows text exactly as written, nothing a link. */
    private function discordMd($s)
    {
        $s = (string) preg_replace('/([\\\\*_~`|<>\[\]()#])/', '\\\\$1', (string) $s);
        $s = (string) preg_replace('/^(\s*)([-+]|[0-9]+\.)(\s)/m', '$1\\\\$2$3', $s);   // list markers at a line start
        return str_replace(array('://', '@everyone', '@here'), array(":\u{200B}//", "@\u{200B}everyone", "@\u{200B}here"), $s);
    }

    /** A card title: no masked links, no bare links, no mentions (titles are not escaped: see discordMd()). */
    private function discordTitle($s)
    {
        return str_replace(array('](', '://', '<@', '<#', '<t:', '@everyone', '@here'),
            array("]\u{200B}(", ":\u{200B}//", "<\u{200B}@", "<\u{200B}#", "<\u{200B}t:", "@\u{200B}everyone", "@\u{200B}here"), (string) $s);
    }

    /** [text](address) for inside a card: the text escaped, the address with nothing in it that could end the link early. */
    private function discordLink($text, $url)
    {
        return '[' . $this->discordMd($text) . '](' . str_replace(array('(', ')', ' ', '<', '>'), array('%28', '%29', '%20', '%3C', '%3E'), (string) $url) . ')';
    }

    /**
     * One JSON POST to Telegram or Discord. On "too many requests" with a short wait asked for (3 seconds at
     * most) it waits and tries once more; a longer wait is not sat out (this may run inside a page view): the
     * message goes on to the next channel instead.
     *
     * @return array array(bool $ok, string $whyNot, int $httpStatus, mixed $decodedAnswer)
     */
    private function post($url, $body, $discord = false)
    {
        for ($try = 0; ; $try++)
        {
            $r = (array) $this->http($url, array('Content-Type: application/json', $this->ua($discord)), $body);
            $code = isset($r[0]) ? (int) $r[0] : 0;
            $resp = isset($r[1]) ? (string) $r[1] : '';
            $json = json_decode($resp, true, 64, JSON_BIGINT_AS_STRING);   // Telegram chat ids can pass 32 bits
            /* Telegram says {"ok":false,…} on errors; Discord answers 204 with no body (200 and the message with ?wait=true) */
            if ($code >= 200 && $code < 300 && !(is_array($json) && isset($json['ok']) && $json['ok'] === false))
            {
                return array(true, '', $code, $json);
            }
            if ($code === 429 && $try === 0)
            {
                $wait = $this->retryAfter($json);
                if ($wait !== null && $wait <= 3)
                {
                    $this->pause($wait);
                    continue;
                }
            }
            return array(false, $this->failReason($code, $resp) . ($code === 429 && $try > 0 ? ' (after one retry)' : ''), $code, $json);
        }
    }

    /** Seconds to wait from a 429 answer: Telegram {"parameters":{"retry_after":5}}, Discord {"retry_after":0.5}. */
    private function retryAfter($json)
    {
        if (!is_array($json))
        {
            return null;
        }
        if (isset($json['parameters']['retry_after']) && is_numeric($json['parameters']['retry_after']))
        {
            return max(0.0, (float) $json['parameters']['retry_after']);
        }
        if (isset($json['retry_after']) && is_numeric($json['retry_after']))
        {
            return max(0.0, (float) $json['retry_after']);
        }
        return null;
    }

    private function pause($seconds)
    {
        if (is_callable($this->cfg['sleeper']))
        {
            call_user_func($this->cfg['sleeper'], (float) $seconds);
            return;
        }
        usleep((int) round((min(3.0, $seconds) + 0.1) * 1000000));
    }

    /** "HTTP 401: Unauthorized": the service's own short explanation, with every secret of ours taken out. */
    private function failReason($code, $resp)
    {
        if ($code <= 0)
        {
            return 'no answer (could not connect, or it timed out)';
        }
        $msg = '';
        $json = json_decode((string) $resp, true);
        if (is_array($json))
        {
            foreach (array('description', 'message') as $k)   // Telegram; Discord and LINE
            {
                if (isset($json[$k]) && is_string($json[$k]))
                {
                    $msg = $json[$k];
                    break;
                }
            }
        }
        $secrets = array_merge(array(trim((string) $this->cfg['telegram_bot_token']), (string) $this->cfg['line_channel_access_token']),
            $this->listOf($this->cfg['discord_webhook_url']));
        foreach ($secrets as $s)
        {
            if (strlen($s) >= 8)
            {
                $msg = str_replace($s, '…', $msg);
            }
        }
        $msg = trim((string) preg_replace('/\s+/u', ' ', $this->clean($msg)));
        return 'HTTP ' . (int) $code . ($msg !== '' ? ': ' . $this->cut($msg, 120) : '');
    }

    /**
     * A short word for why a channel refused, from its answer: blocked | kicked | chat_not_found | topic_gone |
     * token | webhook_gone | webhook_bad | forum_thread | recipient_gone | quota | rate | server | network | other.
     * failHint() and the "chw_" texts turn it into plain words. Telegram's error texts are not a promise of its
     * documentation ("subject to change"): a text not recognised is simply 'other'.
     */
    private function failCode($ch, $code, $json)
    {
        $d = '';
        if (is_array($json))
        {
            foreach (array('description', 'message') as $k)
            {
                if (isset($json[$k]) && is_string($json[$k]))
                {
                    $d = strtolower($json[$k]);
                    break;
                }
            }
        }
        $code = (int) $code;
        if ($code <= 0)
        {
            return 'network';
        }
        if ($code === 429)
        {
            return ($ch === 'line' && strpos($d, 'monthly limit') !== false) ? 'quota' : 'rate';
        }
        if ($code >= 500)
        {
            return 'server';
        }
        if ($ch === 'telegram')
        {
            if (strpos($d, 'blocked') !== false) { return 'blocked'; }
            if (strpos($d, 'kicked') !== false || strpos($d, 'not a member') !== false || strpos($d, 'not enough rights') !== false) { return 'kicked'; }
            if (strpos($d, 'thread not found') !== false) { return 'topic_gone'; }
            if (strpos($d, 'chat not found') !== false || strpos($d, "can't initiate") !== false || strpos($d, 'deactivated') !== false
                || strpos($d, 'chat was deleted') !== false) { return 'chat_not_found'; }
            if ($code === 401 || $code === 404) { return 'token'; }
        }
        elseif ($ch === 'discord')
        {
            $dc = is_array($json) && isset($json['code']) && is_numeric($json['code']) ? (int) $json['code'] : 0;
            if (in_array($dc, array(220001, 220002, 220003, 10003), true)) { return 'forum_thread'; }   // forum needs a thread; unknown thread
            if ($code === 404) { return 'webhook_gone'; }
            if ($code === 401 || $code === 403) { return 'webhook_bad'; }
        }
        elseif ($ch === 'line')
        {
            if ($code === 401) { return 'token'; }
        }
        return 'other';
    }

    /** What to do about a failCode(), in plain English (for the command line: --test-all, --status). */
    private function failHint($code)
    {
        $h = array(
            'blocked'        => 'the bot was blocked: open the bot in Telegram and tap Restart (or unblock it)',
            'kicked'         => 'the bot is no longer in that group, or may not post there: add it again / let it send messages',
            'chat_not_found' => 'no such chat for this bot: check telegram_chat_id (run --telegram-chats), and press Start in the bot first',
            'topic_gone'     => 'the topic after "/" in telegram_chat_id does not exist (deleted?): run --telegram-chats for the current number',
            'forum_thread'   => 'this webhook is in a forum channel, or ?thread_id= names a post that is gone: put ?thread_id=<the post\'s id> at the end of discord_webhook_url',
            'token'          => 'the key is wrong or was revoked: get the current one (@BotFather for Telegram, the LINE Developers console for LINE)',
            'webhook_gone'   => 'the webhook was deleted: create a new one and update discord_webhook_url',
            'webhook_bad'    => 'the webhook address is wrong or cut short: copy it again',
            'recipient_gone' => 'a recipient in line_to blocked the account or never added it as a friend (or the account is not in that group)',
            'quota'          => "LINE's monthly allowance is used up",
            'rate'           => 'too many requests right now: it should pass in a minute',
            'server'         => 'the service had an error on its side: usually passes by itself',
            'network'        => 'no answer: the server could not reach the service (network, firewall, DNS)',
        );
        return isset($h[$code]) ? $h[$code] : '';
    }

    /**
     * Splits a message at line breaks into parts of at most $limit UTF-16 code units (the unit Telegram and
     * Discord count in: an emoji is two). When there is more than one part, each starts with "(1/2) " and so
     * on. At most 4 parts; the rest is cut with "…" (messages are composed much shorter than that anyway).
     */
    private function split($text, $limit)
    {
        if ($this->units($text) <= $limit)
        {
            return array($text);
        }
        $budget = max(16, $limit - 8);   // room for "(1/4) "; never so small that a part could hold nothing
        $parts = array();
        $cur = '';
        foreach (explode("\n", $text) as $line)
        {
            while ($this->units($line) > $budget)   // one line longer than a whole part: fill up the part, go on in the next
            {
                $room = $cur === '' ? $budget : $budget - $this->units($cur) - 1;
                if ($room < 2)   // 2 = the widest character
                {
                    $parts[] = $cur;
                    $cur = '';
                    continue;
                }
                $head = $this->cutUnits($line, $room);
                $parts[] = $cur === '' ? $head : $cur . "\n" . $head;
                $cur = '';
                $line = (string) substr($line, strlen($head));
            }
            $try = $cur === '' ? $line : $cur . "\n" . $line;
            if ($cur !== '' && $this->units($try) > $budget)
            {
                $parts[] = $cur;
                $cur = $line;
            }
            else
            {
                $cur = $try;
            }
        }
        if ($cur !== '')
        {
            $parts[] = $cur;
        }
        if (count($parts) > 4)
        {
            $parts = array_slice($parts, 0, 4);
            $parts[3] = $this->cutUnits($parts[3], $budget - 2) . "\n…";
        }
        $n = count($parts);
        foreach ($parts as $i => $p)
        {
            $parts[$i] = '(' . ($i + 1) . '/' . $n . ') ' . $p;
        }
        return $parts;
    }

    /** Length in UTF-16 code units, without needing ext-mbstring. */
    private function units($s)
    {
        $cp = @preg_match_all('/./us', (string) $s);
        if ($cp === false)
        {
            return strlen((string) $s);   // not valid UTF-8: bytes, which can only over-count
        }
        return $cp + (int) preg_match_all('/[\x{10000}-\x{10FFFF}]/u', (string) $s);
    }

    /** The longest start of $s that is at most $n UTF-16 code units, cut between characters. */
    private function cutUnits($s, $n)
    {
        if ($this->units($s) <= $n)
        {
            return $s;
        }
        if (!@preg_match_all('/./us', $s, $m))
        {
            return substr($s, 0, max(1, $n));
        }
        $out = '';
        $u = 0;
        foreach ($m[0] as $ch)
        {
            $w = strlen($ch) === 4 ? 2 : 1;
            if ($u + $w > $n)
            {
                break;
            }
            $out .= $ch;
            $u += $w;
        }
        return $out === '' ? $m[0][0] : $out;   // always move forward, even with an absurdly small $n
    }

    private function http($url, array $headers, $body, $method = 'POST')
    {
        if (is_callable($this->cfg['transport']))
        {
            return call_user_func($this->cfg['transport'], $url, $headers, $body, $method);
        }
        return $this->request($method, $url, $headers, $body, (int) $this->cfg['line_timeout']);
    }

    /**
     * How much of this month's LINE allowance is used. Only pushes count (one per recipient); the figure LINE
     * returns is approximate and includes whatever else the same official account sent this month.
     *
     * @return array|null array('used' => int, 'limit' => int); null = the plan has no limit, LINE is not
     *                    configured, the check is switched off, or LINE did not answer
     */
    private function lineQuota()
    {
        /* asked once per run at most: the weekly check-in and the channel check both want it */
        $now = $this->now();
        if ($this->quotaMemo === null || $this->quotaMemo['at'] !== $now)
        {
            $this->quotaMemo = array('at' => $now, 'q' => $this->lineQuotaAsk());
        }
        return $this->quotaMemo['q'];
    }

    private function lineQuotaAsk()
    {
        $token = (string) $this->cfg['line_channel_access_token'];
        if (!$this->cfg['line_quota_check'] || $token === '' || !$this->cfg['line_to'])
        {
            return null;
        }
        $base = rtrim($this->cfg['line_api_base'], '/');
        $headers = array('Authorization: Bearer ' . $token);
        try
        {
            $r = (array) $this->http($base . '/v2/bot/message/quota', $headers, '', 'GET');
            $limit = isset($r[0], $r[1]) && $r[0] >= 200 && $r[0] < 300 ? json_decode((string) $r[1], true) : null;
            if (!is_array($limit) || !isset($limit['type'], $limit['value']) || $limit['type'] !== 'limited' || (int) $limit['value'] <= 0)
            {
                return null;
            }
            $r = (array) $this->http($base . '/v2/bot/message/quota/consumption', $headers, '', 'GET');
            $used = isset($r[0], $r[1]) && $r[0] >= 200 && $r[0] < 300 ? json_decode((string) $r[1], true) : null;
            if (!is_array($used) || !isset($used['totalUsage']))
            {
                return null;
            }
            return array('used' => max(0, (int) $used['totalUsage']), 'limit' => (int) $limit['value']);
        }
        catch (Throwable $e)
        {
            return null;
        }
    }

    /** @return array array(int $status, string $body); status 0 = no answer (could not connect, timed out) */
    private function request($method, $url, array $headers, $body, $timeout)
    {
        $timeout = max(1, (int) $timeout);
        $get = ($method === 'GET');
        if (!function_exists('curl_init'))
        {
            /* No curl: plain PHP streams (needs allow_url_fopen and the openssl extension for https). */
            $http = array('method' => $method, 'header' => implode("\r\n", $headers), 'timeout' => $timeout, 'ignore_errors' => true);
            if ($get)
            {
                $http['follow_location'] = 0;
            }
            else
            {
                $http['content'] = $body;
            }
            $ctx = stream_context_create(array('http' => $http));
            $fp = @fopen($url, 'rb', false, $ctx);
            if (!$fp)
            {
                return array(0, '');
            }
            $meta = stream_get_meta_data($fp);
            $resp = (string) stream_get_contents($fp);
            fclose($fp);
            $code = 0;
            foreach (isset($meta['wrapper_data']) ? (array) $meta['wrapper_data'] : array() as $h)
            {
                if (preg_match('/^HTTP\/\S+\s+(\d{3})/', (string) $h, $m))
                {
                    $code = (int) $m[1];   // the last status line wins (after redirects)
                }
            }
            return array($code, $resp);
        }
        $ch = curl_init($url);
        $opt = array(CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(5, $timeout));
        if ($get)
        {
            $opt[CURLOPT_HTTPGET] = true;
        }
        else
        {
            $opt[CURLOPT_POST] = true;
            $opt[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opt);
        $resp = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if (PHP_VERSION_ID < 80000)
        {
            curl_close($ch);   // a no-op since PHP 8.0 and deprecated in 8.5
        }
        return array($code, (string) $resp);
    }

    /* ======================================================================
     * Storage (plain files in state_dir)
     * ====================================================================== */

    private function path($name)
    {
        $dir = $this->cfg['state_dir'];
        if (!is_dir($dir))
        {
            @mkdir($dir, 0700, true);
            @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
            @file_put_contents($dir . '/index.html', '');
        }
        return $dir . '/' . $name;
    }

    private function record($kind, array $data)
    {
        if (!$this->cfg['enabled']) { return; }
        /* Whatever the application hands over is made valid UTF-8 here, once, so nothing further down can choke on it.
           Names that identify someone keep a short tag when bytes had to be replaced, so two of them stay distinct. */
        foreach ($data as $k => $v)
        {
            if (is_string($v))
            {
                $data[$k] = in_array($k, array('user', 'target', 'actor'), true) ? $this->cleanId($v) : $this->clean($v);
            }
            elseif (is_array($v))
            {
                $data[$k] = array_map(function ($x) { return is_string($x) ? $this->clean($x) : $x; }, $v);
            }
        }
        $this->append('events-' . date('Ymd', $this->now()) . '.ndjson', array('t' => $this->now(), 'k' => $kind, 'd' => $data));
    }

    private function append($file, array $row)
    {
        $json = $this->json($row, JSON_UNESCAPED_UNICODE);
        if ($json !== false)
        {
            @file_put_contents($this->path($file), $json . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    private function readEvents($from, $to)
    {
        $out = array();
        for ($d = strtotime(date('Y-m-d', $from)); $d <= $to; $d = strtotime('+1 day', $d))
        {
            $f = $this->path('events-' . date('Ymd', $d) . '.ndjson');
            if (!is_file($f)) { continue; }
            foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line)
            {
                $e = json_decode($line, true);
                if (is_array($e) && $e['t'] > $from && $e['t'] <= $to) { $out[] = $e; }
            }
        }
        return $out;
    }

    private function loadState()
    {
        $f = $this->path('state.json');
        $s = is_file($f) ? json_decode((string) file_get_contents($f), true) : array();
        return is_array($s) ? $s : array();
    }

    private function saveState(array $s)
    {
        $json = $this->json($s, JSON_UNESCAPED_UNICODE);
        if ($json !== false)   // never replace the state with nothing
        {
            @file_put_contents($this->path('state.json'), $json, LOCK_EX);
        }
    }

    private function prune($now)
    {
        foreach (glob($this->path('events-*.ndjson')) ?: array() as $f)
        {
            if (preg_match('/events-(\d{8})\.ndjson$/', $f, $m) && strtotime($m[1]) < $now - $this->cfg['keep_days'] * 86400)
            {
                @unlink($f);
            }
        }
        $fl = $this->path('findings.ndjson');
        if (is_file($fl) && filesize($fl) > 5 * 1024 * 1024)
        {
            @rename($fl, $fl . '.1');
        }
    }

    private function lock()
    {
        $this->lockHandle = @fopen($this->path('.lock'), 'c');
        return $this->lockHandle && flock($this->lockHandle, LOCK_EX | LOCK_NB);
    }

    private function unlock()
    {
        if ($this->lockHandle) { flock($this->lockHandle, LOCK_UN); fclose($this->lockHandle); $this->lockHandle = null; }
    }

    /* ======================================================================
     * Small helpers
     * ====================================================================== */

    private function now()
    {
        return is_callable($this->cfg['clock']) ? (int) call_user_func($this->cfg['clock']) : time();
    }

    /** The "network" of an IP: IPv4 /24, IPv6 /48 (usually stable for one ISP in one area). */
    private function ipPrefix($ip)
    {
        $ip = trim((string) $ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
        {
            $p = explode('.', $ip);
            return $p[0] . '.' . $p[1] . '.' . $p[2] . '.0/24';
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6))
        {
            $h = bin2hex((string) inet_pton($ip));
            return substr($h, 0, 4) . ':' . substr($h, 4, 4) . ':' . substr($h, 8, 4) . '::/48';
        }
        return $ip;
    }

    /** "iPhone / Safari" style label for people to read. */
    private function uaLabel($ua)
    {
        $ua = (string) $ua;
        $os = '?';
        foreach (array('iPhone' => 'iPhone', 'iPad' => 'iPad', 'Android' => 'Android', 'Windows' => 'Windows', 'Macintosh' => 'Mac',
                       'CrOS' => 'ChromeOS', 'Linux' => 'Linux') as $needle => $name)
        {
            if (stripos($ua, $needle) !== false) { $os = $name; break; }
        }
        $br = '?';
        foreach (array('Line/' => 'LINE in-app', 'FBAN' => 'Facebook in-app', 'Edg/' => 'Edge', 'OPR/' => 'Opera',
                       'SamsungBrowser' => 'Samsung Internet', 'CriOS' => 'Chrome', 'FxiOS' => 'Firefox', 'Firefox/' => 'Firefox',
                       'Chrome/' => 'Chrome', 'Safari/' => 'Safari', 'curl' => 'curl (script)', 'python' => 'Python (script)') as $needle => $name)
        {
            if (stripos($ua, $needle) !== false) { $br = $name; break; }
        }
        return $os . ' / ' . $br;
    }

    /** First $n characters of a UTF-8 string, without needing ext-mbstring. */
    private function cut($s, $n)
    {
        if (function_exists('mb_substr'))
        {
            return mb_substr($s, 0, $n, 'UTF-8');
        }
        if (strlen($s) <= $n)
        {
            return $s;
        }
        return preg_match('/^.{0,' . (int) $n . '}/us', $s, $m) ? $m[0] : substr($s, 0, $n);
    }

    private function money($n)
    {
        return number_format((float) $n, 0);
    }

    /** Rule ids -> words a shop owner can read ("a program dressed up as an image"). */
    private function why(array $ids, $inUploadDir)
    {
        $out = array();
        if ($inUploadDir)
        {
            $out[] = $this->t('file_in_upload');
        }
        foreach ($ids as $id)
        {
            $label = isset($this->ruleLabels[$id]) ? $this->ruleLabels[$id] : $this->t('sus_' . $id);
            if ($label === 'sus_' . $id)
            {
                $label = $this->t('sus_custom', $id);   // an extra rule without its own wording
            }
            if (!in_array($label, $out, true))
            {
                $out[] = $label;
            }
        }
        return implode($this->t('list_sep'), $out);
    }

    private function t($key)
    {
        static $s = array(
            'en' => array(
                'header' => "🔒 Security alert | %s (%s)",
                'level_0' => 'Log', 'level_1' => 'Notice', 'level_2' => 'URGENT',
                'mail_subject' => 'Security alert: %s',
                'ip_count' => '・%s: %d',
                'test_body' => 'This is a test. If you can read this, real alerts will reach you too.',
                'login_fail_title' => 'Too many failed admin logins',
                'login_fail_body' => '%d failed admin logins in the last hour from %d IP(s).',
                'login_fail_real' => 'Real admin accounts were targeted: %s. Make sure they have long passwords and 2FA.',
                'login_fail_other' => '%d non-existent usernames were also tried.',
                'new_device_title' => 'Admin "%s" signed in from a new device and network',
                'new_device_body' => '%s, IP %s, at %s. This account has not used this browser or this network recently.',
                'new_device_hint' => 'A staff member on a new phone or travelling? Then ignore this. If not: change the password, sign out all sessions, check recent admin changes.',
                'acct_title' => 'Admin account changed',
                'acct_line' => '%s: %s (by %s)',
                'acct_created' => 'account created', 'acct_deleted' => 'account deleted', 'acct_role' => 'role changed',
                'acct_permissions' => 'permissions changed', 'acct_email' => 'e-mail changed', 'acct_password' => 'password changed',
                'acct_2fa_disabled' => '2FA turned off', 'acct_passkey_added' => 'new passkey added', 'acct_other' => 'changed',
                'snap_new' => 'New admin account appeared: %s', 'snap_deleted' => 'Admin account removed: %s', 'snap_changed' => '%s: %s',
                'fw_title' => 'The firewall is blocking a lot of requests',
                'fw_body' => '%d requests blocked in the last hour from %d IP(s).', 'fw_rules' => 'Top rules: %s',
                'money_title_refund' => 'Unusual refunds', 'money_title_cancel' => 'Unusual order cancellations',
                'money_title_balance_adjust' => 'Unusual manual balance adjustments',
                'money_burst' => '%d in the last hour, total %s.', 'money_actors' => 'By: %s',
                'money_single' => 'A single one of %s (ref %s, by %s).',
                'file_bad_title' => 'Possible backdoor on the server',
                'file_new_bad' => 'New: %s (%s)', 'file_changed_bad' => 'Changed: %s (now: %s)', 'file_in_upload' => 'code file inside an upload folder',
                'list_sep' => '; ',
                'sus_cmd' => 'can run system commands', 'sus_sysv' => 'runs a system command taken from a variable',
                'sus_evalx' => 'executes code passed in from outside', 'sus_callin' => 'calls whatever function a visitor names',
                'sus_crfn' => 'builds code at run time', 'sus_pregE' => 'builds code at run time',
                'sus_blob' => 'contains a large encoded blob', 'sus_hex' => 'contains a large encoded blob',
                'sus_shell' => 'carries the name of a known web shell', 'sus_upin' => 'saves uploads wherever a visitor says',
                'sus_htx' => 'changes which files run as programs', 'sus_imgphp' => 'a program dressed up as an image',
                'sus_custom' => 'matches your own rule "%s"',
                'sus_stealth' => 'its content changed but its modification time was put back, as if to hide the edit',
                'late_title' => 'Delayed alert',
                'late_note' => '⏱ Delayed: this alert is from %s. It could not be delivered then (every channel failed), so here it is now.',
                'late_expired' => 'An alert from %s could not be delivered for 7 days and was given up. What it said is in the entries above.',
                'file_more' => '…and %d more file(s)',
                'file_new_quarantined' => 'New: %s (%s) → renamed to %s',
                'file_quarantine_hint' => 'The renamed file(s) can no longer run. Nothing was deleted: they are evidence of how someone got in. If one was put there by your own people, rename it back.',
                'file_quarantine_failed' => 'Automatic renaming was tried and failed (no permission): that file can still run.',
                'file_algo_title' => 'File fingerprints upgraded to SHA-256',
                'file_algo_body' => 'After the module update, the fingerprints of %d code file(s) were recalculated with SHA-256 (they were SHA-1). Each file was first checked against its old fingerprint: unchanged files were converted quietly, changed ones are reported as usual.',
                'file_algo_hint' => 'You see this once, right after an update. If nobody updated the module, someone swapped the records for old-format ones: treat it as a break-in.',
                'file_bad_hint' => 'Check these files now. If you did not put them there, take the site offline and restore from a clean backup.',
                'file_title' => 'Code files changed on the server',
                'file_summary' => '%d new, %d changed, %d deleted.',
                'file_plain_hint' => 'If this was your own deployment, you can ignore this message.',
                'file_runtime_title' => 'Files rewritten by the application',
                'file_reset_title' => 'The file baseline was reset by hand',
                'file_reset_body' => 'Someone ran the "rebaseline" command at %s. From now on the files as they are today count as normal. If that was not you or your developer, treat it as a break-in.',
                'file_lost_title' => 'The file fingerprints have disappeared',
                'file_lost_body' => 'The record of what your code files looked like is gone or unreadable, and nobody asked for a reset. Changes made since the last scan cannot be listed.',
                'file_lost_hint' => 'Wiping the records is how an intruder blinds a monitor. Check who has been on the server, compare the site with your last good backup, and change passwords. Monitoring restarts from the current state.',
                'state_lost_title' => 'The monitoring records were wiped',
                'state_lost_body' => 'The module is starting from an empty state folder, but it was installed here before (since %s).',
                'hb_header' => "✅ Weekly check-in | %s (%s)",
                'hb_title' => 'Weekly check-in',
                'hb_counts' => 'Still on duty. Last %d day(s): %d checks run, %d thing(s) reported (%d urgent).',
                'hb_files' => 'Watching %d code files; last full scan %s.',
                'hb_header_warn' => "⚠️ Weekly check-in, with something to look at | %s (%s)",
                'hb_fp_first' => 'Code fingerprint: %s. It comes with every check-in from now on; scroll up to compare with the one before.',
                'hb_fp_same' => 'Code fingerprint: %s (same as the last check-in: no code changed in between).',
                'hb_fp_diff_sent' => 'Code fingerprint: %s (was %s). %d code-change notice(s) were sent in between; if those were all your own work, fine.',
                'hb_fp_diff_quiet' => 'Code fingerprint: %s (was %s). %d change(s) in between were written to the log but not sent to you; have your developer read the log.',
                'hb_fp_diff_none' => '⚠ Code fingerprint: %s (was %s). It changed, yet no code change is on record in between: the fingerprint records may have been tampered with. Handle it as a possible backdoor.',
                'hb_ping_ok' => 'Outside check-in: working (if the schedule stops, that service tells you).',
                'hb_quota' => 'LINE messages this month: about %d of %d used.',
                'hb_quota_low' => '⚠ LINE messages this month: about %d of %d used. Once the limit is reached LINE stops delivering; alerts then go to your other channels (Telegram, Discord, e-mail), or wait until they can be sent.',
                'hb_quota_out' => '⚠ LINE messages this month: the limit of %d is used up (about %d sent). Alerts cannot reach LINE until next month or a bigger plan; make sure another channel (e-mail, Telegram or Discord) is set.',
                'hb_ping_bad' => '⚠ The outside check-in address has failed %d time(s) in a row (since %s). Have your developer check ping_url, or nobody will tell you when the schedule stops.',
                'hb_since' => 'Records go back to %s. If that date is newer than you remember, the records were reset: ask why.',
                'hb_hint' => 'You get this once a week. If a week passes without it, the checks have stopped running.',
                'hb_friends' => '⚠ The LINE account that sends these alerts has about %d friends. Its key is on this server: whoever breaks in can message all of them. Alerts belong in an official account of their own (see the README).',
                'exp_title' => 'Code changes during your announced update',
                'exp_opened' => 'Update window announced: %s until %s.',
                'exp_window' => 'Update window %s–%s (announced on the server with --expect).',
                'exp_none' => 'No code file changed during the window.',
                'exp_hint' => 'Fine if this was your update. If nobody updated the site then, treat it as a break-in: someone on the server may have announced the window to hide these changes.',
                'page_home' => 'home page',
                'page_code_title' => 'A page started using another site',
                'page_new_script' => '%s: runs code from %s',
                'page_new_frame' => '%s: embeds %s',
                'page_new_form' => '%s: a form now sends what visitors type to %s',
                'page_new_redirect' => '%s: sends visitors on to %s',
                'page_code_hint' => 'If you or your developer did not just add this (a chat box, a payment or analytics service), someone may have put it into your settings or database to steal what customers type or to send them elsewhere. Have your developer find where it comes from; if it is yours, add the site to page_allow. Names are written as name[.]com on purpose, so they cannot be opened by a tap.',
                'page_hidden_title' => 'Your pages show search engines something you do not see',
                'page_hidden_line' => '%s: only %s get %s',
                'page_who_c' => 'search engines', 'page_who_g' => 'visitors coming from a Google search', 'page_who_cg' => 'search engines and visitors from Google',
                'page_hidden_hint' => 'This is how gambling and spam-link injections hide: the site looks normal to you, while Google sees (or sends your customers to) something else. Have your developer search the database (articles, settings, footer) and the code for these names, then ask Google to review the site in Search Console. Names are written as name[.]com on purpose, so they cannot be opened by a tap.',
                'page_links_title' => 'New links to other sites on your pages',
                'page_new_links' => '%s: %s',
                'page_links_hint' => 'Fine if you or your staff added them (a new article, a partner). If nobody did, links may have been slipped into the page: check it. Names are written as name[.]com on purpose, so they cannot be opened by a tap.',
                'page_more' => '…and %d more',
                'page_and_more' => '(+%d more)',
                'page_data_url' => 'code written into the page itself (a data: address)',
                'page_lost_title' => 'The page-watch records have disappeared',
                'page_lost_body' => 'What your pages looked like is no longer on record; the next check starts over from the pages as they are now. If nobody reset the monitor, someone may be covering their tracks.',
                'brake_line' => "\u{1F6D1} Not your doing, and nobody to call? Lock the admin area for %d hours (the shop stays open): %s",
                'brake_title' => 'Emergency brake',
                'brake_confirm' => 'This locks the admin area for %d hours: nobody can sign in or use it, you included. The shop stays open for customers. Use it when an alert says something is wrong and you cannot reach your developer.',
                'brake_button' => 'Lock the admin area for %d hours',
                'brake_already' => 'It is already locked until %s; pressing the button keeps it locked at least that long.',
                'brake_done' => 'Locked until %s. The shop is still open. A message confirming the lock is on its way. Your developer can unlock it early with --unlock on the server.',
                'brake_expired' => 'This link has expired (a link works for %d hours). Use the link in a newer alert, or ask your developer to lock the admin area with --lock on the server.',
                'brake_used' => 'This link has already been used. The admin area is locked until %s.',
                'brake_used_open' => 'This link has already been used, and the lock has ended since. Use the link in a newer alert to lock again.',
                'brake_locked_title' => 'The admin area is locked',
                'brake_locked_link' => 'Locked with the emergency link at %s, until %s (pressed from IP %s). Customers can still use the shop; nobody can use the admin area until then.',
                'brake_locked_cmd' => 'Locked by command on the server at %s, until %s. Customers can still use the shop; nobody can use the admin area until then.',
                'brake_locked_hint' => 'If nobody on your side did this, someone has your alert messages or is on the server: tell your developer. To end it early: --unlock on the server.',
                'brake_unlocked_title' => 'The admin area is unlocked',
                'brake_unlocked_body' => 'The emergency lock was ended by command on the server at %s.',
                'btn_brake' => "\u{1F6D1} Lock the admin area for %d hours",
                'btn_guide' => "\u{1F4D6} What to do",
                'what_to_do' => 'What to do',
                'name_sep' => ', ',
                'hb_channels_ok' => 'Channels checked without sending a message: %s OK.',
                'hb_channels_bad' => '⚠ Not working right now: %s. Messages that would go there go to the next channel instead, or wait. Have your developer run --test-all.',
                'ch_with_reason' => '%s (%s)',
                'ch_name_telegram' => 'Telegram', 'ch_name_discord' => 'Discord', 'ch_name_line' => 'LINE', 'ch_name_mail' => 'e-mail', 'ch_name_custom' => 'your own channel',
                'chw_blocked' => 'the bot was blocked',
                'chw_kicked' => 'the bot was removed from the group',
                'chw_chat_not_found' => 'the chat was not found',
                'chw_topic_gone' => 'the topic was not found',
                'chw_forum_thread' => 'the forum post (thread_id) is missing or gone',
                'chw_token' => 'the key is wrong or was revoked',
                'chw_webhook_gone' => 'the webhook was deleted',
                'chw_webhook_bad' => 'the webhook address is wrong',
                'chw_recipient_gone' => 'a recipient blocked the account or is not a friend',
                'chw_quota' => 'the monthly allowance is used up',
                'chw_rate' => 'too many requests for now',
                'chw_server' => 'the service had an error',
                'chw_network' => 'no answer',
                'chw_other' => 'it refused',
            ),
            'zh-TW' => array(
                'header' => "🔒 網站安全提醒｜%s（%s）",
                'level_0' => '紀錄', 'level_1' => '注意', 'level_2' => '緊急',
                'mail_subject' => '網站安全提醒：%s',
                'ip_count' => '・%s：%d 次',
                'test_body' => '這是測試訊息。看得到這則，代表真的出事時你也收得到通知。',
                'login_fail_title' => '後台登入失敗太多次',
                'login_fail_body' => '一小時內後台登入失敗 %d 次（%d 個 IP）。',
                'login_fail_real' => '被猜的是真的後台帳號：%s。這幾個帳號的密碼要夠長、要開兩步驟驗證。',
                'login_fail_other' => '另外亂猜了 %d 個不存在的帳號。',
                'new_device_title' => '後台帳號「%s」從新的裝置和網路登入',
                'new_device_body' => '%s，IP %s，時間 %s。這個帳號最近沒用過這個瀏覽器，也沒從這個網路登入過。',
                'new_device_hint' => '是同事換手機、在外面用行動網路就不用理會；不是的話：改密碼、登出所有裝置、檢查最近的後台變動。',
                'acct_title' => '後台帳號有變動',
                'acct_line' => '%s：%s（操作者 %s）',
                'acct_created' => '新增帳號', 'acct_deleted' => '刪除帳號', 'acct_role' => '角色被改',
                'acct_permissions' => '權限被改', 'acct_email' => 'Email 被改', 'acct_password' => '密碼被改',
                'acct_2fa_disabled' => '關掉兩步驟驗證', 'acct_passkey_added' => '新增 Face ID／通行金鑰', 'acct_other' => '有變動',
                'snap_new' => '多了一個後台帳號：%s', 'snap_deleted' => '後台帳號被移除：%s', 'snap_changed' => '%s：%s',
                'fw_title' => '防火牆擋下很多次',
                'fw_body' => '一小時內擋下 %d 次（%d 個 IP）。', 'fw_rules' => '最多的規則：%s',
                'money_title_refund' => '退款異常', 'money_title_cancel' => '取消訂單異常',
                'money_title_balance_adjust' => '手動調整儲值金異常',
                'money_burst' => '一小時內 %d 筆，合計 %s。', 'money_actors' => '操作者：%s',
                'money_single' => '單筆 %s（單號 %s，操作者 %s）。',
                'file_bad_title' => '主機上可能有後門程式',
                'file_new_bad' => '新檔：%s（%s）', 'file_changed_bad' => '被改：%s（現在%s）', 'file_in_upload' => '上傳資料夾裡不該有程式檔',
                'list_sep' => '；',
                'sus_cmd' => '可以執行系統指令', 'sus_sysv' => '會把外來的內容當系統指令執行',
                'sus_evalx' => '會執行外面傳進來的程式碼', 'sus_callin' => '訪客指定什麼函式就執行什麼',
                'sus_crfn' => '執行時才拼出程式碼', 'sus_pregE' => '執行時才拼出程式碼',
                'sus_blob' => '藏了一大段編碼過的內容', 'sus_hex' => '藏了一大段編碼過的內容',
                'sus_shell' => '出現已知後門工具的名稱', 'sus_upin' => '會照訪客指定的位置存上傳檔',
                'sus_htx' => '會改變哪些檔案被當成程式執行', 'sus_imgphp' => '檔名偽裝成圖片的程式',
                'sus_custom' => '符合你自己加的規則「%s」',
                'sus_stealth' => '內容變了，修改時間卻被調回原樣，像是刻意隱藏',
                'late_title' => '補發的通知',
                'late_note' => '⏱ 補發：這則是 %s 的通知。當時所有管道都發不出去，現在補上。',
                'late_expired' => '%s 的一則通知連續 7 天都發不出去，已經放棄。內容在上面的紀錄裡。',
                'file_more' => '…另外還有 %d 支',
                'file_new_quarantined' => '新檔：%s（%s）→ 已改名為 %s',
                'file_quarantine_hint' => '改過名的檔已經不能執行。沒有刪除任何東西：它是查出對方怎麼進來的證據。如果是自己人放的，把檔名改回去就還原了。',
                'file_quarantine_failed' => '想自動改名但失敗了（沒有權限），那支檔案現在還能執行。',
                'file_algo_title' => '檔案指紋已升級成 SHA-256',
                'file_algo_body' => '模組更新後，%d 支程式檔的指紋從 SHA-1 重算成 SHA-256。重算前先跟舊指紋對過：內容沒變的安靜換新，有變的照常另外通知。',
                'file_algo_hint' => '這則只會在更新模組之後出現一次。沒有人更新卻收到，代表紀錄被換成舊格式，請當成被入侵處理。',
                'file_bad_hint' => '請馬上檢查這些檔案。如果不是你們放的，先把網站下線，再用乾淨的備份還原。',
                'file_title' => '主機上的程式檔有變動',
                'file_summary' => '新增 %d、修改 %d、刪除 %d。',
                'file_plain_hint' => '如果是你們自己剛上傳的更新，可以不用理會。',
                'file_runtime_title' => '程式自己改寫的檔案',
                'file_reset_title' => '檔案基準被手動重設',
                'file_reset_body' => '有人在 %s 執行了「重設基準」。從現在起，主機上目前的檔案都算正常。如果不是你或你的工程師做的，請當成被入侵處理。',
                'file_lost_title' => '檔案指紋紀錄不見了',
                'file_lost_body' => '用來比對程式檔的紀錄被清空或讀不到，而且沒有人下過重設指令。上次檢查之後被改了什麼，現在列不出來。',
                'file_lost_hint' => '清掉紀錄是入侵者讓監控失效的常見手法。請確認這段時間誰動過主機、拿最近一份乾淨的備份比對、更換密碼。偵測會從現在的狀態重新開始。',
                'state_lost_title' => '偵測紀錄被清空',
                'state_lost_body' => '偵測現在是從空的紀錄資料夾重新開始，但這裡之前裝過（從 %s 開始）。',
                'hb_header' => "✅ 每週報平安｜%s（%s）",
                'hb_title' => '每週報平安',
                'hb_counts' => '偵測持續運作中。過去 %d 天：檢查 %d 次、回報 %d 件事（其中緊急 %d 件）。',
                'hb_files' => '目前看著 %d 支程式檔，上次完整檢查 %s。',
                'hb_header_warn' => "⚠️ 每週報平安（有一件事要確認）｜%s（%s）",
                'hb_fp_first' => '程式總指紋：%s。之後每週都會附上，往上滑就能跟前一則對照。',
                'hb_fp_same' => '程式總指紋：%s（跟上次報平安一樣，這段時間程式沒被動過）。',
                'hb_fp_diff_sent' => '程式總指紋：%s（上次是 %s）。這段時間通知過 %d 次程式變動；都是你們自己做的就沒事。',
                'hb_fp_diff_quiet' => '程式總指紋：%s（上次是 %s）。這段時間有 %d 次變動只寫進紀錄、沒有發通知，請工程師看一下紀錄。',
                'hb_fp_diff_none' => '⚠ 程式總指紋：%s（上次是 %s）。指紋變了，但這段時間沒有任何程式變動的紀錄，指紋紀錄可能被動過手腳。請當成「主機上可能有後門」處理。',
                'hb_ping_ok' => '外部報到：正常（排程一停，外部服務會另外通知你）。',
                'hb_quota' => '這個月 LINE 大約發了 %d 則，上限 %d 則。',
                'hb_quota_low' => '⚠ 這個月 LINE 大約發了 %d 則，上限 %d 則，快用完了。用完之後 LINE 就發不出去：通知會改走其他管道（Telegram、Discord、Email），都沒設就先留著，等能發再補。',
                'hb_quota_out' => '⚠ 這個月 LINE 的 %d 則已經用完（大約發了 %d 則）。到下個月或升級方案之前，通知到不了 LINE；請確認有設定其他管道（Email、Telegram 或 Discord）。',
                'hb_ping_bad' => '⚠ 外部報到網址已經連續失敗 %d 次（從 %s 起）。請工程師檢查設定裡的 ping_url，不然排程停了不會有人通知你。',
                'hb_since' => '紀錄從 %s 開始。這個日期如果比你記得的新，代表紀錄被重設過，要問清楚原因。',
                'hb_hint' => '這則每週一次。哪一週沒收到，代表檢查沒在跑。',
                'hb_friends' => '⚠ 發這些通知的 LINE 官方帳號大約有 %d 個好友。它的金鑰放在這台主機上：網站被入侵時，對方可以用它發訊息給所有好友。通知請改用一個只發通知的官方帳號（見 README）。',
                'exp_title' => '預告的更新時段內，程式有這些變動',
                'exp_opened' => '已預告更新時段：%s 到 %s。',
                'exp_window' => '更新時段 %s～%s（在主機上用 --expect 預告的）。',
                'exp_none' => '這段時間沒有程式檔變動。',
                'exp_hint' => '是你們的更新就沒事。如果那段時間其實沒有人更新網站，請當成被入侵處理：可能是有人進了主機，用預告來掩護這些變動。',
                'page_home' => '首頁',
                'page_code_title' => '網頁開始用到別的網站',
                'page_new_script' => '%s：多了來自 %s 的程式',
                'page_new_frame' => '%s：嵌入了 %s',
                'page_new_form' => '%s：表單改成把客人填的資料送到 %s',
                'page_new_redirect' => '%s：會把客人轉到 %s',
                'page_code_hint' => '如果不是你們剛加的（客服聊天、金流、分析工具），可能有人改了網站設定或資料庫，想偷客人輸入的資料或把客人導走。請工程師查這段是從哪裡來的；確定是自己加的，把網域加進 page_allow 就不會再提醒。網域寫成 name[.]com 是故意的，避免不小心點開。',
                'page_hidden_title' => '網頁給搜尋引擎看的，跟你看到的不一樣',
                'page_hidden_line' => '%s：只有%s看得到 %s',
                'page_who_c' => '搜尋引擎', 'page_who_g' => '從 Google 搜尋點進來的客人', 'page_who_cg' => '搜尋引擎和從 Google 點進來的客人',
                'page_hidden_hint' => '這是博弈、垃圾連結入侵的典型手法：你自己打開一切正常，Google 看到的（或把客人送去的）卻是別的東西。請工程師在資料庫（文章、設定、頁尾）和程式裡搜尋這些網域，清乾淨後到 Google Search Console 要求重新審查。網域寫成 name[.]com 是故意的，避免不小心點開。',
                'page_links_title' => '網頁上多了連往別的網站的連結',
                'page_new_links' => '%s：%s',
                'page_links_hint' => '如果是你們自己加的（新文章、合作夥伴）就沒事；沒有人加過的話，可能是被塞了連結，請檢查那一頁。網域寫成 name[.]com 是故意的，避免不小心點開。',
                'page_more' => '…另外還有 %d 項',
                'page_and_more' => '（另外 %d 個）',
                'page_data_url' => '直接寫在網頁裡的程式（data: 網址）',
                'page_lost_title' => '網頁監看的紀錄不見了',
                'page_lost_body' => '原本記下的網頁樣子不見了，下次檢查會從網頁現在的樣子重新開始。如果沒有人重設過，可能是有人在湮滅痕跡。',
                'brake_line' => "\u{1F6D1} 不是你們做的、又聯絡不到人？按這裡把後台鎖住 %d 小時（前台照常營業）：%s",
                'brake_title' => '緊急煞車',
                'brake_confirm' => '按下去之後，後台會鎖住 %d 小時：任何人都不能登入或使用後台，包括你自己。前台照常讓客人購物。收到通知說出事了、又聯絡不到工程師的時候用。',
                'brake_button' => '把後台鎖住 %d 小時',
                'brake_already' => '後台已經鎖到 %s；再按一次，至少會鎖到那個時間。',
                'brake_done' => '已經鎖到 %s。前台照常營業。確認的通知稍後會傳給你。工程師可以在主機上用 --unlock 提早解鎖。',
                'brake_expired' => '這個連結已經過期（每個連結只能在 %d 小時內使用）。請用比較新的通知裡的連結，或請工程師在主機上用 --lock 鎖住後台。',
                'brake_used' => '這個連結已經用過了。後台鎖到 %s。',
                'brake_used_open' => '這個連結已經用過了，而且那次的鎖已經結束。要再鎖一次，請用比較新的通知裡的連結。',
                'brake_locked_title' => '後台已經鎖住',
                'brake_locked_link' => '%s 有人按了緊急煞車連結，鎖到 %s（從 IP %s 按的）。客人照常可以購物；在那之前任何人都不能用後台。',
                'brake_locked_cmd' => '%s 在主機上用指令鎖住，鎖到 %s。客人照常可以購物；在那之前任何人都不能用後台。',
                'brake_locked_hint' => '如果不是你們這邊按的，代表有人拿到了你的通知訊息，或已經在主機上：請告訴工程師。要提早解鎖：在主機上執行 --unlock。',
                'brake_unlocked_title' => '後台已經解鎖',
                'brake_unlocked_body' => '%s 在主機上用指令結束了緊急鎖定。',
                'btn_brake' => "\u{1F6D1} 把後台鎖住 %d 小時",
                'btn_guide' => "\u{1F4D6} 收到通知怎麼辦",
                'what_to_do' => '怎麼做',
                'name_sep' => '、',
                'hb_channels_ok' => '通知管道正常：%s（沒有發訊息，只確認連得上）。',
                'hb_channels_bad' => '⚠ 有通知管道現在不能用：%s。原本要走它的訊息會改走下一個管道，或先留著。請工程師跑 --test-all 看原因。',
                'ch_with_reason' => '%s（%s）',
                'ch_name_telegram' => 'Telegram', 'ch_name_discord' => 'Discord', 'ch_name_line' => 'LINE', 'ch_name_mail' => 'Email', 'ch_name_custom' => '自訂管道',
                'chw_blocked' => '機器人被封鎖了',
                'chw_kicked' => '機器人被移出群組',
                'chw_chat_not_found' => '找不到這個聊天室',
                'chw_topic_gone' => '找不到這個討論主題',
                'chw_forum_thread' => '論壇頻道要指定貼文（thread_id），或那篇貼文不在了',
                'chw_token' => '金鑰錯了或被撤銷',
                'chw_webhook_gone' => 'Webhook 被刪掉了',
                'chw_webhook_bad' => 'Webhook 網址不對',
                'chw_recipient_gone' => '有收件人封鎖了帳號，或還不是好友',
                'chw_quota' => '這個月的則數用完了',
                'chw_rate' => '請求太多，暫時被擋',
                'chw_server' => '對方伺服器出錯',
                'chw_network' => '連不上',
                'chw_other' => '被拒絕',
            ),
            'ja' => array(
                'header' => "🔒 セキュリティ通知｜%s（%s）",
                'level_0' => '記録', 'level_1' => '注意', 'level_2' => '緊急',
                'mail_subject' => 'セキュリティ通知：%s',
                'ip_count' => '・%s：%d 回',
                'test_body' => 'これはテストです。これが読めていれば、本当の通知もちゃんと届きます。',
                'login_fail_title' => '管理画面のログイン失敗が多すぎる',
                'login_fail_body' => '直近 1 時間で、管理画面のログイン失敗が %d 回ありました（%d 個の IP から）。',
                'login_fail_real' => '実在する管理者アカウントが狙われています：%s。これらのアカウントに、長いパスワードと 2 段階認証が設定されているか確認してください。',
                'login_fail_other' => 'ほかに、存在しないアカウント名も %d 個試されました。',
                'new_device_title' => '管理者「%s」が新しい端末・ネットワークからログインした',
                'new_device_body' => '%s、IP %s、日時 %s。このアカウントは最近、このブラウザもこのネットワークも使っていませんでした。',
                'new_device_hint' => 'スタッフがスマホを替えた、外出先でモバイル回線を使った、といったことなら気にしなくて大丈夫です。心当たりがなければ、パスワードを変え、すべての端末からログアウトさせ、最近の管理画面の変更を確認してください。',
                'acct_title' => '管理者アカウントが変更された',
                'acct_line' => '%s：%s（操作者：%s）',
                'acct_created' => 'アカウントの追加', 'acct_deleted' => 'アカウントの削除', 'acct_role' => '役割の変更',
                'acct_permissions' => '権限の変更', 'acct_email' => 'メールアドレスの変更', 'acct_password' => 'パスワードの変更',
                'acct_2fa_disabled' => '2 段階認証の無効化', 'acct_passkey_added' => '新しいパスキーの追加', 'acct_other' => '変更あり',
                'snap_new' => '管理者アカウントが増えました：%s', 'snap_deleted' => '管理者アカウントが削除されました：%s', 'snap_changed' => '%s：%s',
                'fw_title' => 'ファイアウォールが大量にブロックしている',
                'fw_body' => '直近 1 時間で %d 回ブロックしました（%d 個の IP から）。', 'fw_rules' => '多かったルール：%s',
                'money_title_refund' => '返金がいつもと違う', 'money_title_cancel' => '注文のキャンセルがいつもと違う',
                'money_title_balance_adjust' => '残高の手動調整がいつもと違う',
                'money_burst' => '直近 1 時間で %d 件、合計 %s。', 'money_actors' => '操作者：%s',
                'money_single' => '1 件の金額が %s（番号 %s、操作者：%s）。',
                'file_bad_title' => 'サーバーにバックドアがあるかもしれない',
                'file_new_bad' => '新規：%s（%s）', 'file_changed_bad' => '変更：%s（%s）', 'file_in_upload' => 'アップロード用フォルダにあるプログラムファイル',
                'list_sep' => '／',
                'sus_cmd' => 'システムコマンドを実行できる', 'sus_sysv' => '外から来た内容をシステムコマンドとして実行する',
                'sus_evalx' => '外から渡されたコードを実行する', 'sus_callin' => '訪問者が指定した関数を何でも実行する',
                'sus_crfn' => '実行時にコードを組み立てる', 'sus_pregE' => '実行時にコードを組み立てる',
                'sus_blob' => 'エンコードされた長いデータを含む', 'sus_hex' => 'エンコードされた長いデータを含む',
                'sus_shell' => '既知のバックドアツールの名前が入っている', 'sus_upin' => '訪問者が指定した場所にアップロードファイルを保存する',
                'sus_htx' => 'どのファイルをプログラムとして実行するかを変える', 'sus_imgphp' => '画像のふりをしたプログラム',
                'sus_custom' => '自分で追加したルール「%s」に一致',
                'sus_stealth' => '中身が変わったのに、変更を隠すように更新日時が元に戻されている',
                'late_title' => '送信が遅れた通知',
                'late_note' => '⏱ 遅れて届いた通知：これは %s の通知です。そのときはどのチャネルでも送れなかったので、今お送りしています。',
                'late_expired' => '%s の通知は 7 日間送れなかったため、送るのをあきらめました。内容は上の記録にあります。',
                'file_more' => '…ほかに %d 本',
                'file_new_quarantined' => '新規：%s（%s）→ %s に名前を変更',
                'file_quarantine_hint' => '名前を変えたファイルは、もう実行されません。削除はしていません。相手がどうやって入ってきたかを示す証拠だからです。身内が置いたものなら、名前を元に戻してください。',
                'file_quarantine_failed' => '自動で名前を変えようとしましたが、失敗しました（権限がない）。そのファイルはまだ実行できます。',
                'file_algo_title' => 'ファイルの指紋が SHA-256 に移行された',
                'file_algo_body' => 'モジュールの更新後、%d 本のプログラムファイルの指紋を SHA-256 で計算し直しました（以前は SHA-1）。先に各ファイルを古い指紋と照合し、変わっていないものは黙って移行し、変わっていたものはいつもどおり通知します。',
                'file_algo_hint' => 'このお知らせは、更新の直後に一度だけ届きます。誰もモジュールを更新していないのに届いたなら、誰かが記録を古い形式のものに差し替えています。侵入として扱ってください。',
                'file_bad_hint' => '今すぐこれらのファイルを確認してください。自分たちで置いたものでなければ、サイトを止めて、きれいなバックアップから戻してください。',
                'file_title' => 'サーバーのプログラムファイルが変わった',
                'file_summary' => '新規 %d 本、変更 %d 本、削除 %d 本。',
                'file_plain_hint' => '自分たちでアップロードした更新なら、このメッセージは気にしなくて大丈夫です。',
                'file_runtime_title' => 'サイトが自分で書き換えたファイル',
                'file_reset_title' => 'ファイルの基準が手動でリセットされた',
                'file_reset_body' => '%s に、誰かが --rebaseline（基準のリセット）を実行しました。これからは、今あるファイルがすべて正常とみなされます。あなたか開発者がしたのでなければ、侵入として扱ってください。',
                'file_lost_title' => 'ファイルの指紋の記録が消えた',
                'file_lost_body' => 'プログラムファイルの状態を記録したデータが、消えたか読めなくなっています。リセットの指示は誰も出していません。前回のチェック以降に何が変わったかは、もう一覧にできません。',
                'file_lost_hint' => '記録を消すのは、侵入者が監視を無効にするときの手口です。この間に誰がサーバーを触ったかを確認し、最後のきれいなバックアップとサイトを比べ、パスワードを変えてください。監視は今の状態から始め直します。',
                'state_lost_title' => '監視の記録が消された',
                'state_lost_body' => '監視が空の記録フォルダから始まりましたが、このサイトには前から入っていました（%s から）。',
                'hb_header' => "✅ 週 1 回の動作報告｜%s（%s）",
                'hb_title' => '週 1 回の動作報告',
                'hb_counts' => '監視はまだ動いています。過去 %d 日間：チェック %d 回、報告 %d 件（うち緊急 %d 件）。',
                'hb_files' => 'プログラムファイル %d 本を見張っています（前回すべて読み直したのは %s）。',
                'hb_header_warn' => "⚠️ 週 1 回の動作報告（確認してほしいことがあります）｜%s（%s）",
                'hb_fp_first' => 'コード指紋：%s。これからは毎回の動作報告に付くので、さかのぼれば前回のものと見比べられます。',
                'hb_fp_same' => 'コード指紋：%s（前回の動作報告と同じ。この間、プログラムは変わっていません）。',
                'hb_fp_diff_sent' => 'コード指紋：%s（前回は %s）。この間にプログラム変更の通知を %d 通送りました。どれも自分たちの作業なら問題ありません。',
                'hb_fp_diff_quiet' => 'コード指紋：%s（前回は %s）。この間の %d 件の変更は記録に書いただけで、あなたには送っていません。開発者に記録を見てもらってください。',
                'hb_fp_diff_none' => '⚠ コード指紋：%s（前回は %s）。変わっているのに、この間のプログラムの変更が記録にありません。指紋の記録が書き換えられた可能性があります。「バックドアがあるかもしれない」ときと同じ対応をしてください。',
                'hb_ping_ok' => '外部チェックイン：正常（定期実行が止まれば、そのサービスが知らせてくれます）。',
                'hb_quota' => '今月の LINE の送信数：約 %d 通（上限 %d 通）。',
                'hb_quota_low' => '⚠ 今月の LINE の送信数：約 %d 通（上限 %d 通）。上限に達すると LINE では届かなくなり、通知はほかのチャネル（Telegram、Discord、メール）に回るか、送れるようになるまで待つことになります。',
                'hb_quota_out' => '⚠ 今月の LINE の送信数：上限の %d 通を使い切りました（送信は約 %d 通）。来月になるかプランを上げるまで、通知は LINE に届きません。ほかのチャネル（メール、Telegram、Discord）が設定されているか確認してください。',
                'hb_ping_bad' => '⚠ 外部チェックインの URL への報告が %d 回続けて失敗しています（%s から）。開発者に ping_url を確認してもらってください。このままでは、定期実行が止まっても誰も知らせてくれません。',
                'hb_since' => '記録の開始日：%s。覚えているより新しい日付なら、記録がリセットされています。理由を確認してください。',
                'hb_hint' => 'このメッセージは週に 1 回届きます。届かない週があれば、チェックが止まっています。',
                'hb_friends' => '⚠ この通知を送っているLINE公式アカウントには、友だちが約 %d 人います。そのトークンはこのサーバーにあるので、侵入した人はその全員にメッセージを送れてしまいます。通知は、通知専用のLINE公式アカウントから送ってください（README を参照）。',
                'exp_title' => '予告した更新の時間内に変わったプログラム',
                'exp_opened' => '更新を予告しました：%s から %s まで。',
                'exp_window' => '予告された更新の時間：%s～%s（サーバーで --expect を使って予告）。',
                'exp_none' => 'この時間内に変わったプログラムファイルはありません。',
                'exp_hint' => '自分たちの更新なら問題ありません。その時間に誰も更新していなければ、侵入として扱ってください。サーバーに入った誰かが、これらの変更を隠すために予告したのかもしれません。',
                'page_home' => 'トップページ',
                'page_code_title' => 'ページがほかのサイトを使い始めた',
                'page_new_script' => '%s：%s のプログラムを読み込んでいます',
                'page_new_frame' => '%s：%s を埋め込んでいます',
                'page_new_form' => '%s：フォームに入力された内容が %s へ送られるようになりました',
                'page_new_redirect' => '%s：訪問者を %s へ転送しています',
                'page_code_hint' => 'あなたや開発者が追加したばかりのもの（チャット、決済、アクセス解析などのサービス）でなければ、誰かがサイトの設定やデータベースに仕込み、お客さんの入力内容を盗むか、お客さんをよそへ送ろうとしているのかもしれません。どこから来ているかを開発者に探してもらってください。自分たちのものなら、そのサイトを page_allow に入れれば次からは知らせません。サイト名が name[.]com のように書かれているのはわざとで、タップで開かないようにするためです。',
                'page_hidden_title' => 'ページが検索エンジンにだけ違うものを見せている',
                'page_hidden_line' => '%s：%sにだけ %s が出ています',
                'page_who_c' => '検索エンジン', 'page_who_g' => 'Google 検索から来たお客さん', 'page_who_cg' => '検索エンジンと、Google 検索から来たお客さん',
                'page_hidden_hint' => 'ギャンブルやスパムリンクを仕込む侵入が隠れる、典型的な手口です。自分で開くと普通に見えるのに、Google には別のものが見えています（または、お客さんが別の場所へ送られています）。開発者に、データベース（記事、設定、フッター）とプログラムの中でこれらのサイト名を探して取り除いてもらい、そのあと Google Search Console で審査を依頼してください。サイト名が name[.]com のように書かれているのはわざとで、タップで開かないようにするためです。',
                'page_links_title' => 'ページにほかのサイトへの新しいリンクが増えた',
                'page_new_links' => '%s：%s',
                'page_links_hint' => '自分やスタッフが追加したもの（新しい記事、取引先など）なら問題ありません。誰も追加していなければ、リンクを仕込まれたのかもしれないので、そのページを確認してください。サイト名が name[.]com のように書かれているのはわざとで、タップで開かないようにするためです。',
                'page_more' => '…ほかに %d 件',
                'page_and_more' => '（ほか %d 件）',
                'page_data_url' => 'data: URL（ページに直接書き込まれたコード）',
                'page_lost_title' => 'ページ監視の記録が消えた',
                'page_lost_body' => '記録していたページの状態がなくなりました。次のチェックは、今のページの状態から始め直します。誰も監視をリセットしていなければ、誰かが痕跡を消そうとしているのかもしれません。',
                'brake_line' => "\u{1F6D1} 自分たちがしたことではなく、開発者にも連絡がつかないときは、管理画面を %d 時間ロックできます（お店はそのまま営業）：%s",
                'brake_title' => '緊急ブレーキ',
                'brake_confirm' => 'ボタンを押すと、管理画面が %d 時間ロックされます。その間は、あなたも含めて誰もログインも操作もできません。お客さんはいつもどおり買い物できます。通知で異常を知らされたのに、開発者に連絡がつかないときに使ってください。',
                'brake_button' => '管理画面を %d 時間ロックする',
                'brake_already' => 'すでに %s までロックされています。ボタンを押しても、少なくともその時刻まではロックが続きます。',
                'brake_done' => '%s までロックしました。お店はそのまま開いています。ロックしたことを知らせるメッセージがまもなく届きます。開発者はサーバーで --unlock を実行すれば、早めに解除できます。',
                'brake_expired' => 'このリンクは期限切れです（リンクが使えるのは発行から %d 時間です）。もっと新しい通知のリンクを使うか、開発者にサーバーで --lock を実行して管理画面をロックしてもらってください。',
                'brake_used' => 'このリンクはすでに使われています。管理画面は %s までロックされています。',
                'brake_used_open' => 'このリンクはすでに使われていて、そのときのロックはもう終わっています。もう一度ロックするには、もっと新しい通知のリンクを使ってください。',
                'brake_locked_title' => '管理画面がロックされた',
                'brake_locked_link' => '%s に緊急ブレーキのリンクでロックされました（%s まで、IP %s から押されました）。お客さんはいつもどおり買い物できますが、それまでは誰も管理画面を使えません。',
                'brake_locked_cmd' => '%s に、サーバーのコマンドでロックされました（%s まで）。お客さんはいつもどおり買い物できますが、それまでは誰も管理画面を使えません。',
                'brake_locked_hint' => '自分たちの誰もしていないなら、誰かがあなたの通知メッセージを読めるか、すでにサーバーに入っています。開発者に伝えてください。早めに解除するには、サーバーで --unlock を実行します。',
                'brake_unlocked_title' => '管理画面のロックが解除された',
                'brake_unlocked_body' => '%s に、サーバーのコマンドで緊急ロックが解除されました。',
                'btn_brake' => "\u{1F6D1} 管理画面を %d 時間ロック",
                'btn_guide' => "\u{1F4D6} 通知が届いたら",
                'what_to_do' => 'どうするか',
                'name_sep' => '、',
                'hb_channels_ok' => '通知チャネルは正常です：%s（メッセージは送らずに確かめました）。',
                'hb_channels_bad' => '⚠ 今使えないチャネルがあります：%s。そこに送るはずのメッセージは、次のチャネルに回るか、送れるまで保管されます。開発者に --test-all を実行してもらってください。',
                'ch_with_reason' => '%s（%s）',
                'ch_name_telegram' => 'Telegram', 'ch_name_discord' => 'Discord', 'ch_name_line' => 'LINE', 'ch_name_mail' => 'メール', 'ch_name_custom' => '自作の通知チャネル',
                'chw_blocked' => 'ボットがブロックされた',
                'chw_kicked' => 'ボットがグループから外された',
                'chw_chat_not_found' => 'チャットが見つからない',
                'chw_topic_gone' => 'トピックが見つからない',
                'chw_forum_thread' => 'フォーラムの投稿を thread_id で指定していないか、その投稿がなくなった',
                'chw_token' => 'キーが間違っているか、無効にされた',
                'chw_webhook_gone' => 'ウェブフックが削除された',
                'chw_webhook_bad' => 'ウェブフックの URL が間違っている',
                'chw_recipient_gone' => '送り先の誰かがアカウントをブロックしたか、友だちになっていない',
                'chw_quota' => '今月の送信数の上限に達した',
                'chw_rate' => 'リクエストが多すぎて一時的に止められた',
                'chw_server' => 'サービス側でエラーが起きた',
                'chw_network' => '応答がない',
                'chw_other' => '拒否された',
            ),
        );
        $lang = isset($s[$this->cfg['language']]) ? $this->cfg['language'] : 'en';
        $args = func_get_args();
        $fmt = isset($s[$lang][$key]) ? $s[$lang][$key] : (isset($s['en'][$key]) ? $s['en'][$key] : $key);
        return count($args) > 1 ? vsprintf($fmt, array_slice($args, 1)) : $fmt;
    }
}
