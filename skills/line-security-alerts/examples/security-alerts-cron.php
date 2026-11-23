<?php
// Command-line entry point. Schedule it every 5 minutes, e.g. with crontab:
//
//   */5 * * * *  /usr/bin/php /path/to/security-alerts-cron.php >> /path/to/var/security-alerts-cron.log 2>&1
//
//   php security-alerts-cron.php               run every check now
//   php security-alerts-cron.php --status      where things stand: last run, files watched, what was reported,
//                                              anything waiting, anything that needs a look (sends nothing)
//   php security-alerts-cron.php --test        send one test message (it goes where a notice would go)
//   php security-alerts-cron.php --test-all    send the test message to EVERY channel that is set up, each on
//                                              its own, and say which one failed and why (for setting up)
//   php security-alerts-cron.php --rebaseline  forget file fingerprints (after a big deployment you trust)
//   php security-alerts-cron.php --audit       read every code file and list the ones that look suspicious
//                                              (once after installing: the first run trusts what is already there)
//   php security-alerts-cron.php --fingerprint the code fingerprint from the weekly check-in, checked against the disk
//   php security-alerts-cron.php --manifest    every code file with its SHA-256, in sha256sum format
//   php security-alerts-cron.php --expect 30m  "we are about to upload an update": runs every check first, then for
//                                              30 minutes (or 2h; at most 4h) ordinary code-file changes are summed up
//                                              in ONE message afterwards. Backdoor-like content, programs in upload
//                                              folders and hidden edits are still reported at once.
//   php security-alerts-cron.php --expect off  the update is done: close the window now and send the summary
//   php security-alerts-cron.php --pages       read the pages in page_watch now, the four ways, and list the other
//                                              sites each one uses; marks what only search engines / visitors from
//                                              Google get (once after setting it up: the first check trusts what is there)
//
// Refuses to run from a browser.

if (PHP_SAPI !== 'cli')
{
    http_response_code(404);
    exit;
}

require __DIR__ . '/../lib/SecurityAlerts.php';                 // adjust to where you copied the library
$config = require __DIR__ . '/security-alerts.config.php';     // adjust to where you keep the config

$alerts = new SecurityAlerts($config);
$arg = isset($argv[1]) ? $argv[1] : '';

if ($arg === '--status')
{
    $alerts->lineFriendCount();   // asks LINE how many people the alert account reaches (remembered; status() reports it)
    $s = $alerts->status(10);
    $at = function ($t) { return $t ? date('Y-m-d H:i', $t) : 'never'; };
    $ago = function ($t) use ($s) {
        if (!$t) { return ''; }
        $m = (int) round(($s['now'] - $t) / 60);
        return ' (' . ($m < 120 ? $m . ' min ago' : ($m < 2880 ? round($m / 60) . ' h ago' : round($m / 1440) . ' days ago')) . ')';
    };
    $d = $s['delivery'];
    $n = function ($k, $word) { return $k . ' ' . $word . ($k === 1 ? '' : 's'); };
    $label = array('custom' => 'your own notifier', 'telegram' => 'Telegram (' . $n($d['telegram_chats'], 'chat') . ')',
        'discord' => 'Discord (' . $n($d['discord_webhooks'], 'webhook') . ')', 'line' => 'LINE (' . $n($d['line_recipients'], 'recipient') . ')', 'mail' => 'e-mail');
    $path = function (array $route) use ($label) {
        return $route ? implode(', then ', array_map(function ($c) use ($label) { return $label[$c]; }, $route)) : 'nowhere';
    };
    $ping = !$s['outside_checkin']['configured'] ? 'not set'
        : ($s['outside_checkin']['failing'] > 0 ? 'FAILING ' . $s['outside_checkin']['failing'] . ' time(s) in a row since ' . $at($s['outside_checkin']['failing_since']) : 'working');
    echo 'Status of "' . $s['site_name'] . '" at ' . $at($s['now']) . "\n";
    echo '  checks            : ' . ($s['enabled'] ? 'on' : 'OFF') . ', last run ' . $at($s['last_run']) . $ago($s['last_run']) . "\n";
    echo '  records go back to: ' . ($s['installed_at'] ? date('Y-m-d', $s['installed_at']) : '-') . "\n";
    /* the first channel that takes a message stops the line */
    echo '  alerts go to      : ' . $path($d['route']['notice']) . ($d['mail'] ? '' : '  (no e-mail fallback)') . "\n";
    if ($d['route']['urgent'] !== $d['route']['notice']) { echo '  urgent ones       : ' . $path($d['route']['urgent']) . '  (line_min_level ' . $d['line_min_level'] . ")\n"; }
    if ($d['route']['checkin'] !== $d['route']['notice']) { echo '  check-in goes to  : ' . $path($d['route']['checkin']) . "\n"; }
    if ($s['line_friends'] !== null) { echo '  LINE account      : about ' . $s['line_friends']['n'] . " friend(s) can receive its messages\n"; }
    echo '  sent today        : ' . $s['sent_today'] . ' of ' . $s['daily_cap'] . " (urgent ones are not limited)\n";
    echo '  waiting to re-send: ' . $s['waiting']['count'] . ($s['waiting']['count'] ? ', oldest from ' . $at($s['waiting']['oldest']) : '') . "\n";
    if ($s['files']['scan'])
    {
        echo '  code files        : ' . $s['files']['watched'] . ' watched, last scan ' . $at($s['files']['last_scan'])
            . ($s['files']['scan_unfinished'] ? ' (a scan is still in progress)' : '') . ', last full re-read ' . $at($s['files']['last_full_reread']) . "\n";
        echo '  code fingerprint  : ' . ($s['files']['fingerprint'] !== null ? $s['files']['fingerprint'] : '(no baseline yet)')
            . ($s['files']['fingerprint_at_last_checkin'] !== null ? '   (the last weekly check-in showed ' . $s['files']['fingerprint_at_last_checkin'] . ')' : '') . "\n";
    }
    else
    {
        echo "  code files        : not scanned\n";
    }
    if ($s['expect'] !== null)
    {
        echo '  update window     : ' . ($s['expect']['open'] ? 'OPEN until ' . date('H:i', $s['expect']['until']) : 'ended ' . date('H:i', $s['expect']['until']) . ', summary goes with the next run')
            . '; so far ' . $s['expect']['new'] . ' new, ' . $s['expect']['changed'] . ' changed, ' . $s['expect']['deleted'] . " deleted\n";
    }
    $pg = $s['pages'];
    echo '  pages watched     : ' . ($pg['watched'] ? $pg['watched'] . ', last read ' . $at($pg['last_check']) : 'none (page_watch)') . "\n";
    echo '  weekly check-in   : ' . ($s['checkin']['every_days'] > 0 ? 'next one due ' . $at($s['checkin']['next_due']) : 'off')
        . '; since ' . $at($s['checkin']['counting_since']) . ': ' . $s['checkin']['runs'] . ' checks, ' . $s['checkin']['reported'] . ' reported, ' . $s['checkin']['urgent'] . " urgent\n";
    echo '  outside check-in  : ' . $ping . "\n";
    echo "  latest findings   :\n";
    $names = array(0 => 'log   ', 1 => 'notice', 2 => 'URGENT');
    foreach ($s['recent'] as $e)
    {
        echo '    ' . date('m/d H:i', $e['t']) . '  ' . (isset($names[$e['level']]) ? $names[$e['level']] : '?     ') . '  ' . $e['title'] . '  [' . $e['status'] . "]\n";
    }
    if (!$s['recent']) { echo "    (none yet)\n"; }
    foreach ($s['problems'] as $p) { echo '  !! ' . $p . "\n"; }
    if (!$s['problems']) { echo "  nothing needs a look.\n"; }
    exit($s['problems'] ? 1 : 0);
}
if ($arg === '--test')
{
    $r = $alerts->sendTest();
    echo date('Y-m-d H:i:s') . ' test message: ' . ($r === 'failed' ? 'FAILED on every channel (try --test-all to see why)' : 'sent via ' . $r) . "\n";
    exit($r === 'failed' ? 1 : 0);
}
if ($arg === '--test-all')
{
    $all = $alerts->testEachChannel();
    foreach ($all as $ch => $res)
    {
        echo '  ' . str_pad($ch === 'custom' ? 'notifier' : $ch, 9) . ($res['ok'] ? 'sent' : 'FAILED: ' . $res['why']) . "\n";
    }
    if (!$all) { echo "  no channel is set up\n"; }
    $friends = $alerts->lineFriendCount();
    if ($friends !== null)
    {
        $defaults = SecurityAlerts::defaults();
        echo '  LINE account: about ' . $friends . ' friend(s)' . ($friends > (int) (isset($config['line_friends_warn']) ? $config['line_friends_warn'] : $defaults['line_friends_warn'])
            ? ' - too many for an alert account: its key is on this server, and whoever breaks in could message all of them. Use an official account of its own.'
            : '') . "\n";
    }
    $bad = count(array_filter($all, function ($res) { return !$res['ok']; }));
    exit(!$all || $bad ? 1 : 0);
}
if ($arg === '--expect')
{
    $v = isset($argv[2]) ? strtolower($argv[2]) : '';
    if ($v === 'off' || $v === 'done' || $v === 'end')
    {
        if (!$alerts->endExpect())
        {
            echo "no update window is open\n";
            exit(0);
        }
        $r = $alerts->run();
        echo date('Y-m-d H:i:s') . ' update window closed; summary: ' . (isset($r['sent']) ? $r['sent'] : json_encode($r)) . "\n";
        exit(0);
    }
    if (!preg_match('/^(\d+)(m|min|h)?$/', $v, $m))
    {
        echo "usage: --expect 30m | 2h | off   (at most 4 hours)\n";
        exit(2);
    }
    $minutes = (int) $m[1] * (isset($m[2]) && $m[2] === 'h' ? 60 : 1);
    $r = $alerts->expectChanges($minutes);
    if (!$r['ok'])
    {
        echo 'not opened: ' . $r['why'] . "\n";
        exit(1);
    }
    echo date('Y-m-d H:i:s') . ' ' . ($r['run'] === null ? 'update window extended' : 'checked everything first (' . json_encode($r['run']) . '); update window open')
        . ' until ' . date('H:i', $r['until']) . ".\n"
        . "  Ordinary code-file changes until then come as ONE summary afterwards. Backdoor-like content, programs in\n"
        . "  upload folders and hidden edits are still reported at once. Done early? --expect off\n";
    exit(0);
}
if ($arg === '--pages')
{
    $names = array('browser' => 'desktop browser', 'mobile' => 'phone', 'crawler' => 'Google crawler', 'from_google' => 'phone from Google');
    $all = $alerts->pagesNow();
    foreach ($all as $url => $p)
    {
        echo $url . "\n";
        foreach ($p['views'] as $v => $cats)
        {
            if (is_string($cats)) { echo '  ' . str_pad($names[$v], 18) . ' could not be read: ' . $cats . "\n"; }
        }
        foreach (array('script' => 'code from', 'frame' => 'embeds', 'form' => 'forms send to', 'redirect' => 'redirects to', 'link' => 'links to') as $cat => $words)
        {
            if (!empty($p['outside'][$cat])) { echo '  ' . str_pad($words, 18) . ' ' . implode(', ', $p['outside'][$cat]) . "\n"; }
        }
        foreach ($p['only_bots'] as $cat => $hosts)
        {
            echo '  !! ONLY search engines / visitors from Google get (' . $cat . '): ' . implode(', ', $hosts) . "\n";
        }
        if (!$p['only_bots']) { echo "  everybody gets the same outside sites.\n"; }
    }
    if (!$all) { echo "page_watch is empty: nothing to read\n"; }
    echo "This site and the sites in page_allow are left out. Anything you do not recognise: ask your developer before it becomes the baseline.\n";
    exit(0);
}
if ($arg === '--rebaseline')
{
    $alerts->resetFileBaseline();
    echo date('Y-m-d H:i:s') . " file fingerprints cleared; the next run records a new baseline silently\n";
    exit(0);
}
if ($arg === '--audit')
{
    $hits = $alerts->audit();
    foreach ($alerts->ignoredRules() as $id)
    {
        echo "warning: extra rule \"$id\" was ignored (its pattern does not compile)\n";
    }
    foreach ($hits as $rel => $hit)
    {
        echo $rel . "\n    " . $hit['why'] . "\n";
    }
    echo count($hits) . " code file(s) worth a look. Legitimate code can match too: open each one and decide.\n";
    exit(0);
}
if ($arg === '--manifest')
{
    echo $alerts->manifest();
    exit(0);
}
if ($arg === '--fingerprint')
{
    $recorded = $alerts->fingerprint();
    $manifest = $alerts->manifest();
    $disk = SecurityAlerts::fingerprintOf($manifest);
    if ($recorded === null)
    {
        echo "recorded baseline : (none yet - run the checks once first)\n";
    }
    else
    {
        echo 'recorded baseline : ' . $recorded['code'] . '  (' . $recorded['files'] . " code files) - this is the one the weekly check-in prints\n";
    }
    echo 'files on disk now : ' . $disk['code'] . '  (' . substr_count($manifest, "\n") . ' code files)'
        . ($recorded === null ? '' : ($recorded['full'] === $disk['full'] ? ' - same' : ' - DIFFERENT: files changed since the last scan (the next scan reports them), or the records were edited')) . "\n";
    echo 'full value        : ' . $disk['full'] . "\n";
    $defaults = SecurityAlerts::defaults();
    $exclude = isset($config['exclude_dirs']) ? (array) $config['exclude_dirs'] : $defaults['exclude_dirs'];
    $only = isset($config['scan_dirs']) ? (array) $config['scan_dirs'] : array();
    echo "To check a clean copy on your own computer (it must print the same fingerprint):\n";
    echo '  php scripts/fingerprint.php /path/to/clean/copy --exclude=' . implode(',', $exclude) . ($only ? ' --only=' . implode(',', $only) : '') . "\n";
    exit($recorded !== null && $recorded['full'] !== $disk['full'] ? 1 : 0);
}

$r = $alerts->run();
echo date('Y-m-d H:i:s') . ' ' . json_encode($r) . "\n";
