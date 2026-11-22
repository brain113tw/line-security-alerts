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
 *
 * Design rules
 *   - Your application calls tiny "hooks" (loginFailed(), firewallBlocked(), …) that only append
 *     one line to a log file. They never call LINE, so they cannot slow down or break a request.
 *   - tick() (from cron every 5 minutes, or piggy-backed on normal page views) reads the logs,
 *     decides what is abnormal and sends ONE combined message.
 *   - The same finding is reported at most once per quiet window (default 6 h); at most
 *     `daily_cap` messages a day, except URGENT ones.
 *   - If LINE fails (token missing, monthly quota used up) it falls back to e-mail.
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

    /** @var array */
    private $cfg;
    /** @var resource|null */
    private $lockHandle = null;
    /** @var array|null  built-in rules minus `disable_rules` plus `extra_rules` */
    private $rules = null;
    /** @var array  id => words for the message, for extra rules that bring their own */
    private $ruleLabels = array();
    /** @var array  ids of extra rules that were dropped (not a valid pattern) */
    private $badRules = array();

    public static function defaults()
    {
        return array(
            'enabled'            => true,
            'site_name'          => 'Website',
            'language'           => 'en',          // 'en' or 'zh-TW'
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
            'line_timeout'       => 8,
            /* Once a week (with the check-in) ask LINE how many messages this account has sent this month and what
               its limit is. When the limit is reached LINE stops delivering, so it is better to see it coming. */
            'line_quota_check'   => true,

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

            /* Your own channel (Telegram, Slack, Discord, ntfy, SMS…): function(string $text, int $level): bool.
               Tried first; when it returns false (or is not set) the message goes to LINE, then to e-mail. */
            'notifier'           => null,

            /* Dependency injection (tests, custom HTTP / mail) */
            'transport'          => null,          // function(string $url, array $headers, string $body, string $method = 'POST'): array(int $status, string $body)
            'ping_transport'     => null,          // function(string $url, int $timeout): int $status
            'renamer'            => null,          // function(string $from, string $to): bool  (used by quarantine_uploads)
            'mailer'             => null,          // function(string $to, string $subject, string $text, string $from): bool
            'clock'              => null,          // function(): int
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
            $scan = array('ran' => false, 'quarantined' => 0);
            if ($this->cfg['file_scan'] && $this->cfg['scan_dirs'])
            {
                $scan = $this->checkFiles($state, $now);
                $findings = array_merge($findings, $scan['findings']);
            }

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
                'quarantined' => (int) $scan['quarantined'], 'resent' => $resent, 'heartbeat' => $beat, 'ping' => $ping);
        }
        finally
        {
            $this->unlock();
        }
    }

    /** Sends one test message right now (ignores the quiet window and the daily cap). Returns 'custom' | 'line' | 'mail' | 'failed'. */
    public function sendTest()
    {
        return $this->deliver($this->t('header', $this->cfg['site_name'], date('m/d H:i', $this->now())) . "\n\n" . $this->t('test_body'));
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
     * Read-only: nothing is sent, nothing is changed. No token, recipient id or check-in address is included.
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
        $line = (string) $this->cfg['line_channel_access_token'] !== '' && (bool) $this->cfg['line_to'];
        $out = array(
            'now'          => $now,
            'site_name'    => (string) $this->cfg['site_name'],
            'enabled'      => (bool) $this->cfg['enabled'],
            'installed_at' => !empty($state['installed_at']) ? (int) $state['installed_at'] : null,
            'last_run'     => !empty($state['last_run']) ? (int) $state['last_run'] : null,
            'delivery'     => array(
                'notifier' => is_callable($this->cfg['notifier']),
                'line' => $line,
                'line_recipients' => $line ? count((array) $this->cfg['line_to']) : 0,
                'mail' => (string) $this->cfg['mail_to'] !== '',
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
        if (!$out['delivery']['notifier'] && !$line && !$out['delivery']['mail']) { $p[] = 'nowhere to send alerts: no LINE token/recipient, no e-mail, no notifier'; }
        elseif (!$out['delivery']['notifier'] && $line && !$out['delivery']['mail']) { $p[] = 'no fallback e-mail (mail_to): when LINE refuses, alerts wait instead of arriving'; }
        if ($out['waiting']['count'] > 0) { $p[] = $out['waiting']['count'] . ' alert(s) could not be delivered yet and are waiting to be re-sent'; }
        if ($out['outside_checkin']['failing'] >= 3) { $p[] = 'the outside check-in address has failed ' . $out['outside_checkin']['failing'] . ' times in a row'; }
        if ($scan && !$out['files']['baseline_ready'] && $out['last_run'] !== null) { $p[] = 'the file baseline is not complete yet'; }
        if ($this->cfg['site_root'] === '') { $p[] = 'file scan is off (site_root is not set)'; }
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
                        array($this->t('new_device_body', $this->uaLabel($e['d']['ua']), $e['d']['ip'], date('m/d H:i', $e['t'])), $this->t('new_device_hint')));
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
                            array($this->t('snap_changed', $name, implode(', ', $changes))));
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
        $due = empty($state['files_complete_at']) || ($now - (int) $state['files_complete_at']) >= (float) $this->cfg['scan_hours'] * 3600
            || !empty($state['files_partial']);
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
                array($this->t('file_lost_body'), $this->t('file_lost_hint')), 24);
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
                    array($this->t('file_algo_body', $upgraded), $this->t('file_algo_hint')), 1);
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
        $res['complete'] = $complete;
        $res['findings'] = array_merge($notes, $this->fileFindings($new, $changed, $deleted, $gen, $moved));
        return $res;
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
                    $tail['ok'] = $this->t('file_quarantine_hint');
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
                array_merge($shown, array_values($tail), array($this->t('file_bad_hint'))), 168);
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
            $lines[] = $this->t('file_plain_hint');
            $out[] = $this->finding('files', 'files:chg:' . $gen . ':' . md5(implode('|', array_merge($plainNew, array('/'), $plainChanged, array('/'), $deleted))),
                self::NOTICE, $this->t('file_title'), $lines, 168);
        }
        if ($runtimeChanged)
        {
            $out[] = $this->finding('files', 'files:rt:' . $gen . ':' . md5(implode('|', $runtimeChanged)), self::LOG, $this->t('file_runtime_title'), array_map(array($this, 'clean'), array_slice($runtimeChanged, 0, 20)));
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
                $text = $this->compose(array_map(function ($i) use ($findings) { return $findings[$i]; }, $send), $now);
                $r = $this->deliver($text, $urgent ? self::URGENT : self::NOTICE);
                foreach ($send as $i)
                {
                    $status[$i] = $r;
                    $alerted[$findings[$i]['key']] = $now;   // delivered, or queued just below: either way it is not found "again"
                }
                if ($r === 'line' || $r === 'custom')
                {
                    $state['push_day'] = $day;
                    $state['push_count'] = $used + 1;
                }
                if ($r === 'failed')
                {
                    /* Nothing could take the message (LINE down or refusing, and no e-mail). Keep it and try again
                       on the following runs: a one-time finding — a changed file, a new admin account — is seen
                       only once, so without this it would end up in the log and nowhere else. */
                    $item = array('t' => $now, 'text' => $text, 'urgent' => $urgent ? 1 : 0, 'n' => count($send), 'u' => 0, 'files' => 0);
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
                $hb[in_array($status[$i], array('line', 'mail', 'custom'), true) ? 'files_sent' : 'files_quiet']++;
            }
            $this->append('findings.ndjson', array('t' => $now, 'level' => $f['level'], 'kind' => $f['kind'], 'key' => $f['key'],
                'title' => $f['title'], 'lines' => $f['lines'], 'status' => $status[$i]));
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
            $r = $this->deliver($this->cut($this->t('late_note', $when) . "\n\n" . (string) $item['text'], 4900), !empty($item['urgent']) ? self::URGENT : self::NOTICE);
            if ($r === 'failed')
            {
                $stop = true;
                $keep[] = $item;
                continue;
            }
            $done++;
            if ($r === 'line' || $r === 'custom')
            {
                $day = date('Y-m-d', $now);
                $state['push_count'] = ((isset($state['push_day']) && $state['push_day'] === $day) ? (int) $state['push_count'] : 0) + 1;
                $state['push_day'] = $day;
            }
            $hb = $this->tally($state, $now);
            $hb['sent'] += isset($item['n']) ? (int) $item['n'] : 1;
            $hb['urgent'] += isset($item['u']) ? (int) $item['u'] : 0;
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
        return $hb + array('at' => $now, 'runs' => 0, 'sent' => 0, 'urgent' => 0, 'files_sent' => 0, 'files_quiet' => 0);
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
                array($this->t('state_lost_body', preg_match('/^[0-9]+$/', $since) ? date('Y-m-d', (int) $since) : '?'), $this->t('file_lost_hint')), 24);
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
     * weekly message stops coming. Returns 'off' | 'not due' | 'waiting for daytime' | 'custom' | 'line' | 'mail' | 'failed'.
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
        $quota = $this->lineQuota();
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
        $body[] = $this->t('hb_since', date('Y-m-d', (int) $state['installed_at']));
        $body[] = $this->t('hb_hint');
        $lines = array_merge(array($this->t($warn ? 'hb_header_warn' : 'hb_header', $this->cfg['site_name'], date('m/d H:i', $now)), ''), $body);
        $r = $this->deliver(implode("\n", $lines), $warn ? self::NOTICE : self::LOG);
        $today = date('Y-m-d', $now);
        if ($r !== 'failed')
        {
            $state['hb'] = array('at' => $now, 'runs' => 0, 'sent' => 0, 'urgent' => 0, 'files_sent' => 0, 'files_quiet' => 0);
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

    private function compose(array $list, $now)
    {
        $lines = array($this->t('header', $this->cfg['site_name'], date('m/d H:i', $now)));
        foreach ($list as $f)
        {
            $lines[] = '';
            $lines[] = '【' . $this->t('level_' . $f['level']) . '】' . $f['title'];
            foreach (array_slice($f['lines'], 0, 8) as $l) { $lines[] = $l; }
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

    /** @return string 'custom' | 'line' | 'mail' | 'failed' */
    private function deliver($text, $level = self::NOTICE)
    {
        if (is_callable($this->cfg['notifier']))
        {
            /* Your own channel first. If it says no (or breaks), LINE and e-mail below are still tried. */
            try
            {
                if (call_user_func($this->cfg['notifier'], $text, (int) $level))
                {
                    return 'custom';
                }
            }
            catch (Throwable $e)
            {
            }
        }
        $ok = 0;
        $token = (string) $this->cfg['line_channel_access_token'];
        if ($token !== '' && $this->cfg['line_to'])
        {
            foreach ((array) $this->cfg['line_to'] as $to)
            {
                $body = $this->json(array('to' => (string) $to, 'messages' => array(array('type' => 'text', 'text' => $text))), JSON_UNESCAPED_UNICODE);
                list($code) = $this->http(rtrim($this->cfg['line_api_base'], '/') . '/v2/bot/message/push',
                    array('Content-Type: application/json', 'Authorization: Bearer ' . $token), $body);
                if ($code >= 200 && $code < 300) { $ok++; }
            }
        }
        if ($ok > 0)
        {
            return 'line';
        }
        if ($this->cfg['mail_to'] !== '')
        {
            $subject = $this->t('mail_subject', $this->cfg['site_name']);
            $sent = is_callable($this->cfg['mailer'])
                ? (bool) call_user_func($this->cfg['mailer'], $this->cfg['mail_to'], $subject, $text, $this->cfg['mail_from'])
                : @mail($this->cfg['mail_to'], '=?UTF-8?B?' . base64_encode($subject) . '?=', $text,
                    'Content-Type: text/plain; charset=UTF-8' . ($this->cfg['mail_from'] !== '' ? "\r\nFrom: " . $this->cfg['mail_from'] : ''));
            if ($sent) { return 'mail'; }
        }
        return 'failed';
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
                'late_note' => '⏱ Delayed: this alert is from %s. It could not be delivered then (LINE and e-mail both failed), so here it is now.',
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
                'hb_quota_low' => '⚠ LINE messages this month: about %d of %d used. Once the limit is reached LINE stops delivering; alerts then go by e-mail, or wait until they can be sent.',
                'hb_quota_out' => '⚠ LINE messages this month: the limit of %d is used up (about %d sent). Alerts cannot reach LINE until next month or a bigger plan; make sure a fallback e-mail is set.',
                'hb_ping_bad' => '⚠ The outside check-in address has failed %d time(s) in a row (since %s). Have your developer check ping_url, or nobody will tell you when the schedule stops.',
                'hb_since' => 'Records go back to %s. If that date is newer than you remember, the records were reset: ask why.',
                'hb_hint' => 'You get this once a week. If a week passes without it, the checks have stopped running.',
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
                'late_note' => '⏱ 補發：這則是 %s 的通知。當時 LINE 和 Email 都發不出去，現在補上。',
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
                'hb_quota_low' => '⚠ 這個月 LINE 大約發了 %d 則，上限 %d 則，快用完了。用完之後 LINE 就發不出去：通知會改寄 Email，沒設 Email 就先留著，等能發再補。',
                'hb_quota_out' => '⚠ 這個月 LINE 的 %d 則已經用完（大約發了 %d 則）。到下個月或升級方案之前，通知到不了 LINE；請確認有設定備援的 Email。',
                'hb_ping_bad' => '⚠ 外部報到網址已經連續失敗 %d 次（從 %s 起）。請工程師檢查設定裡的 ping_url，不然排程停了不會有人通知你。',
                'hb_since' => '紀錄從 %s 開始。這個日期如果比你記得的新，代表紀錄被重設過，要問清楚原因。',
                'hb_hint' => '這則每週一次。哪一週沒收到，代表檢查沒在跑。',
            ),
        );
        $lang = isset($s[$this->cfg['language']]) ? $this->cfg['language'] : 'en';
        $args = func_get_args();
        $fmt = isset($s[$lang][$key]) ? $s[$lang][$key] : (isset($s['en'][$key]) ? $s['en'][$key] : $key);
        return count($args) > 1 ? vsprintf($fmt, array_slice($args, 1)) : $fmt;
    }
}
