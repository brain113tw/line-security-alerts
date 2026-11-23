<?php
/**
 * Self-test for SecurityAlerts.php — no network, no real LINE account needed.
 *
 *   php scripts/selftest.php
 *
 * Every scenario runs against a throw-away temp folder with a fake clock and a fake LINE transport,
 * then checks what would have been sent. Exit code 0 = all passed.
 *
 * ANTIVIRUS NOTE — please read before running:
 * To prove that backdoors are detected, the "Files" part writes a few tiny look-alike samples (one line
 * each, never executed, deleted when the test ends) into a folder named "lsa-selftest-…" inside the
 * system temp directory. Antivirus software (Windows Defender and others) may pop up "threat found"
 * and block or quarantine one of them. That is the sample doing its job as bait: nothing was installed,
 * nothing is running, your computer is not infected. You can read every sample below — they are the
 * strings passed to bait(). A blocked sample is simply skipped by the scanner.
 */

require __DIR__ . '/../lib/SecurityAlerts.php';

/**
 * The samples are written with "~" breaking up the tell-tale parts, and bait() removes the "~" at run
 * time. This keeps THIS file from looking like malware to antivirus tools and to the module's own scan.
 */
function bait($s)
{
    return str_replace('~', '', $s);
}

$pass = 0;
$fail = 0;
function check($name, $ok, $extra = '')
{
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ok   $name\n"; }
    else { $fail++; echo "  FAIL $name" . ($extra !== '' ? "\n       $extra" : '') . "\n"; }
}

$TMP_DIRS = array();
function tmpdir($tag)
{
    global $TMP_DIRS;
    static $n = 0;   // a counter, not a random number: this is called dozens of times and two folders must never coincide
    $d = str_replace('\\', '/', sys_get_temp_dir()) . '/lsa-selftest-' . $tag . '-' . getmypid() . '-' . mt_rand(1000, 9999) . '-' . (++$n);
    mkdir($d, 0700, true);
    $TMP_DIRS[] = $d;
    return $d;
}
register_shutdown_function(function () {
    global $TMP_DIRS;
    foreach ($TMP_DIRS as $d) { @rrmdir($d); }
});

function rrmdir($d)
{
    if (!is_dir($d)) { return; }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($d, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname()); }
    rmdir($d);
}

/**
 * The fake LINE's answer to "how many messages may I send this month / how many have I sent".
 * $box['quota']: not set = a plan without a limit; array(used, limit); 'down' = LINE does not answer.
 */
function fake_quota($url, &$box)
{
    if (strpos($url, '/v2/bot/insight/followers') !== false)
    {
        /* "how many friends": counted apart from the allowance questions. $box['friends']: not set = LINE says
           "not counted yet" for every date; array(followers, blocks); 'down' = no answer */
        $box['friend_gets'] = (isset($box['friend_gets']) ? $box['friend_gets'] : 0) + 1;
        $box['friend_urls'][] = $url;
        $f = isset($box['friends']) ? $box['friends'] : null;
        if ($f === 'down') { return array(500, ''); }
        return array(200, json_encode($f ? array('status' => 'ready', 'followers' => $f[0], 'targetedReaches' => 0, 'blocks' => $f[1])
            : array('status' => 'unready', 'followers' => null, 'targetedReaches' => null, 'blocks' => null)));
    }
    $box['gets'] = (isset($box['gets']) ? $box['gets'] : 0) + 1;
    $q = isset($box['quota']) ? $box['quota'] : null;
    if ($q === 'down') { return array(500, ''); }
    if (substr($url, -18) === '/quota/consumption') { return array(200, json_encode(array('totalUsage' => $q ? $q[0] : 0))); }
    return array(200, json_encode($q ? array('type' => 'limited', 'value' => $q[1]) : array('type' => 'none')));
}

/** Builds an instance wired to a fake clock + fake LINE. $box collects what was "sent". */
function make(&$box, &$clock, array $extra = array())
{
    $box = array('line' => array(), 'mail' => array(), 'status' => 200);
    $cfg = array_merge(array(
        'site_name' => 'Test shop',
        'state_dir' => tmpdir('state'),
        'line_channel_access_token' => 'dummy',
        'line_to' => array('Uxxxxxxxx'),
        'mail_to' => 'owner@example.com',
        'clock' => function () use (&$clock) { return $clock; },
        'transport' => function ($url, $headers, $body, $method = 'POST') use (&$box) {
            if ($method === 'GET') { return fake_quota($url, $box); }
            $box['line'][] = json_decode($body, true)['messages'][0]['text'];
            return array($box['status'], '{}');
        },
        'mailer' => function ($to, $subject, $text) use (&$box) { $box['mail'][] = $text; return true; },
    ), $extra);
    return new SecurityAlerts($cfg);
}

$T0 = 1767225600;   // fixed start time; the tests move it forward by hand

/* ------------------------------------------------------------------ */
echo "Logins\n";
$clock = $T0;
$a = make($box, $clock);
$r = $a->run();
check('quiet when nothing happened', $box['line'] === array() && $r['sent'] === 'none');

for ($i = 0; $i < 9; $i++) { $a->loginFailed('admin', '203.0.113.' . (7 + $i % 3), 'curl/8', true); }   // 9 total, 3 per IP
$clock += 60;
$a->run();
check('below the threshold: nothing sent', count($box['line']) === 0);

$a->loginFailed('admin', '203.0.113.7', 'curl/8', true);
$a->loginFailed('nosuchuser', '198.51.100.2', 'curl/8', false);
$clock += 60;
$a->run();
check('10 failures in an hour: one message', count($box['line']) === 1, json_encode($box['line']));
check('message names the targeted real account', isset($box['line'][0]) && strpos($box['line'][0], 'admin') !== false);

for ($i = 0; $i < 5; $i++) { $a->loginFailed('admin', '203.0.113.7', 'curl/8', true); }
$clock += 300;
$a->run();
check('same finding again within the quiet window: not repeated', count($box['line']) === 1);

/* ------------------------------------------------------------------ */
echo "New device\n";
$clock = $T0;
$a = make($box, $clock);
$office = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';
$phone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
$a->loginSucceeded('alice', '192.0.2.10', $office);
$clock += 60; $a->run();
check('first login ever seen for an account: learned silently', count($box['line']) === 0);

$a->loginSucceeded('alice', '100.64.9.9', $office);       // same browser, mobile data
$clock += 60; $a->run();
check('same browser, new network: quiet', count($box['line']) === 0);

$a->loginSucceeded('alice', '192.0.2.77', $phone);        // new phone, office network
$clock += 60; $a->run();
check('new browser, same network: quiet', count($box['line']) === 0);

$a->loginSucceeded('alice', '203.0.113.50', 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0');
$clock += 60; $a->run();
check('new browser AND new network: alert', count($box['line']) === 1, json_encode($box['line']));
check('alert reads "Linux / Firefox"', isset($box['line'][0]) && strpos($box['line'][0], 'Linux / Firefox') !== false);

/* ------------------------------------------------------------------ */
echo "Admin accounts\n";
$clock = $T0;
$a = make($box, $clock);
$a->accountChanged('role', 'bob', 'alice', 'editor -> administrator');
$clock += 60; $a->run();
check('role change is reported', count($box['line']) === 1 && strpos($box['line'][0], 'URGENT') !== false, json_encode($box['line']));

$admins = array('alice' => array('role' => 'owner', 'password' => 'h1', '2fa' => true));
$a = make($box, $clock, array('admin_snapshot' => function () use (&$admins) { return $admins; }));
$a->run();
check('snapshot: first run is a silent baseline', count($box['line']) === 0);
$admins['mallory'] = array('role' => 'owner', 'password' => 'h2');
$admins['alice']['2fa'] = false;
$clock += 300; $a->run();
check('snapshot: new admin + 2FA off reported in one message', count($box['line']) === 1
    && strpos($box['line'][0], 'mallory') !== false && strpos($box['line'][0], '2FA turned off') !== false, json_encode($box['line']));

/* ------------------------------------------------------------------ */
echo "Firewall\n";
$clock = $T0;
$a = make($box, $clock);
for ($i = 0; $i < 20; $i++) { $a->firewallBlocked('198.51.100.9', 'sqli', '/search?q=x'); }
$clock += 60; $a->run();
check('20 blocks from one IP: reported', count($box['line']) === 1 && strpos($box['line'][0], 'sqli') !== false, json_encode($box['line']));

/* ------------------------------------------------------------------ */
echo "Money\n";
$clock = $T0;
$a = make($box, $clock, array('adjust_single' => 5000));
$a->moneyEvent('refund', 100, 'carol', 'A1');
$a->moneyEvent('refund', 200, 'carol', 'A2');
$clock += 60; $a->run();
check('2 refunds: quiet', count($box['line']) === 0);
$a->moneyEvent('refund', 300, 'carol', 'A3');
$clock += 60; $a->run();
check('3 refunds in an hour: reported', count($box['line']) === 1 && strpos($box['line'][0], 'carol') !== false, json_encode($box['line']));
$a->moneyEvent('balance_adjust', 8000, 'dave', 'M9');
$clock += 60; $a->run();
check('one large balance adjustment: reported', count($box['line']) === 2 && strpos($box['line'][1], 'M9') !== false, json_encode($box['line']));

/* ------------------------------------------------------------------ */
echo "Files   (writing harmless bait files to the temp folder now - an antivirus pop-up at this point is expected, see the note at the top of this file)\n";
$clock = $T0;
$site = tmpdir('site');
mkdir($site . '/uploads', 0700, true);
mkdir($site . '/cache', 0700, true);
file_put_contents($site . '/index.php', "<?php echo 'hello';\n");
file_put_contents($site . '/lib.php', "<?php function f() { return 1; }\n");
file_put_contents($site . '/old.php', "<?php // to be deleted\n");
$a = make($box, $clock, array('site_root' => $site, 'exclude_dirs' => array('cache')));
$a->run();
check('first scan: baseline only, nothing sent', count($box['line']) === 0);

file_put_contents($site . '/new-page.php', "<?php echo 'new';\n");
file_put_contents($site . '/lib.php', "<?php function f() { return 2 + 2; }\n");
unlink($site . '/old.php');
file_put_contents($site . '/cache/compiled.php', bait("<?php \$~_GET['f'](\$~_POST['a']);\n"));   // bait inside an excluded dir
$clock += 5 * 3600; $a->run();
check('plain new/changed/deleted code files: one notice', count($box['line']) === 1
    && strpos($box['line'][0], 'new-page.php') !== false && strpos($box['line'][0], 'lib.php') !== false && strpos($box['line'][0], 'old.php') !== false, json_encode($box['line']));
check('excluded dir is ignored', isset($box['line'][0]) && strpos($box['line'][0], 'compiled.php') === false);
check('plain changes are a Notice, not URGENT', isset($box['line'][0]) && strpos($box['line'][0], 'URGENT') === false);

/* Bait files (see the antivirus note at the top). They are deliberately mild one-liners; the nastier
   patterns are only checked in memory further below, never written to disk. */
file_put_contents($site . '/wp.php', bait("<?php \$~_GET['f'](\$~_POST['a']);\n"));
file_put_contents($site . '/uploads/avatar.jpg.php', "<?php echo 1;\n");
file_put_contents($site . '/uploads/.htaccess', bait("Add~Handler application/x-httpd-php .jpg\n"));
file_put_contents($site . '/index.php', bait("<?php echo 'hello'; @sys~tem(\$~_GET['cmd']);\n"));
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('web shell, code in uploads, .htaccess handler, injected index: URGENT', strpos($m, 'URGENT') !== false
    && strpos($m, 'wp.php') !== false && strpos($m, 'avatar.jpg.php') !== false && strpos($m, 'uploads/.htaccess') !== false
    && strpos($m, 'index.php') !== false, $m);
check('the reason is written in plain words, not rule ids', strpos($m, 'calls whatever function a visitor names') !== false
    && strpos($m, 'runs a system command taken from a variable') !== false && strpos($m, 'a program dressed up as an image') !== false
    && strpos($m, 'changes which files run as programs') !== false && strpos($m, 'code file inside an upload folder') !== false
    && strpos($m, 'callin') === false && strpos($m, 'imgphp') === false, $m);

/* Attacker-style edit: same size, then put the old modification time back. */
clearstatcache();
$prevM = filemtime($site . '/lib.php');
if (PHP_OS_FAMILY !== 'Windows')
{
    /* PHP reports change times in whole seconds, so the edit must land in a later second than the
       recorded one for the difference to be visible (in real life it always does). */
    $guard = microtime(true) + 3;
    while (time() <= filectime($site . '/lib.php') && microtime(true) < $guard) { usleep(100000); clearstatcache(); }
}
file_put_contents($site . '/lib.php', "<?php function f() { return 2 + 3; }\n");
touch($site . '/lib.php', $prevM);
clearstatcache();
$clock += 5 * 3600; $a->run();
if (PHP_OS_FAMILY === 'Windows')
{
    echo "  skip same-size edit with the mtime put back (Windows has no inode change time; Linux servers do)\n";
}
else
{
    check('same-size edit with the mtime put back is still caught', isset($box['line'][2]) && strpos($box['line'][2], 'lib.php') !== false,
        isset($box['line'][2]) ? $box['line'][2] : '(no message)');
}

echo "Suspicious-content rules (in memory)\n";
$samples = array(   // id => (must hit, must not hit); only ever held in memory
    'cmd'    => array('<?php shell_ex~ec($c);', '<?php $x = "shell_ex~ec is disabled";'),
    'sysv'   => array('<?php sys~tem($~_GET["c"]);', '<?php $this->sys~tem("x");'),
    'evalx'  => array('<?php ev~al(base64_dec~ode($p));', '<?php // evaluate later'),
    'callin' => array('<?php $~_REQUEST["f"]($~_REQUEST["a"]);', '<?php $f = $~_REQUEST["f"];'),
    'crfn'   => array('<?php create_func~tion("", $b);', '<?php // no dynamic functions'),
    'pregE'  => array('<?php preg_rep~lace("/x/e", $r, $s);', '<?php preg_rep~lace("/x/i", $r, $s);'),
    'blob'   => array('<?php $d = "' . str_repeat('QUJD', 800) . '";', '<?php $d = "' . str_repeat('QUJD', 100) . '";'),
    'hex'    => array('<?php $s = "' . str_repeat('\\x41', 40) . '";', '<?php $s = "\\x41\\x42";'),
    'shell'  => array('<?php /* Files~Man */', '<?php /* file manager */'),
    'upin'   => array('<?php move_uploaded_f~ile($_FILES["f"]["tmp_name"], $~_POST["to"]);', '<?php move_uploaded_f~ile($tmp, $safe);'),
    'htx'    => array("Add~Handler application/x-httpd-php .jpg\n", "Options -Indexes\n"),
);
$rules = SecurityAlerts::suspiciousRules();
foreach ($samples as $id => $pair)
{
    check("rule $id: hits the bad sample, ignores the harmless one", preg_match($rules[$id], bait($pair[0])) === 1 && preg_match($rules[$id], bait($pair[1])) === 0);
}

/* The package must not look like malware to itself (or it would raise an alert when you install it). */
foreach (array('lib/SecurityAlerts.php', 'scripts/selftest.php', 'scripts/demo.php', 'scripts/fingerprint.php', 'scripts/fake_line_server.php',
               'examples/security-alerts-cron.php', 'examples/security-alerts.config.example.php') as $own)
{
    $src = (string) file_get_contents(__DIR__ . '/../' . $own);
    $hits = array();
    foreach ($rules as $id => $re)
    {
        if ($id !== 'htx' && preg_match($re, $src)) { $hits[] = $id; }
    }
    check("$own does not trip the module's own rules", $hits === array(), implode(',', $hits));
}
/* Owners read the message, not the rule id: every rule needs wording in both languages. */
$missing = array();
foreach (array('en', 'zh-TW') as $lang)
{
    $probe = make($pbox, $clock, array('language' => $lang));
    foreach (array_merge(array_keys($rules), array('imgphp')) as $id)
    {
        $label = (function () use ($id) { return $this->t('sus_' . $id); })->call($probe);
        if ($label === 'sus_' . $id || $label === '') { $missing[] = "$lang:$id"; }
    }
}
check('every rule has a plain-language label in both languages', $missing === array(), implode(' ', $missing));

/* ------------------------------------------------------------------ */
echo "Demo script\n";
if (function_exists('exec'))
{
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/demo.php') . ' --json', $lines, $code);
    $demo = json_decode(implode("\n", $lines), true);
    $msgs = is_array($demo) ? array_values(array_filter($demo, function ($r) { return $r['kind'] === 'message'; })) : array();
    check('demo.php replays the story: 2 notices, 1 URGENT, then two weekly check-ins', $code === 0 && count($msgs) === 5
        && strpos($msgs[0]['text'], 'admin/shortcuts.php') !== false && strpos($msgs[2]['text'], 'URGENT') !== false
        && strpos($msgs[2]['text'], 'uploads/avatar.jpg.php') !== false && strpos($msgs[3]['text'], 'Weekly check-in') !== false
        && preg_match('/Code fingerprint: ([0-9a-f]{4}(?:-[0-9a-f]{4}){3})\./', $msgs[3]['text'], $fpm) === 1
        && strpos($msgs[4]['text'], 'Code fingerprint: ' . $fpm[1] . ' (same as the last check-in') !== false,
        "exit=$code messages=" . count($msgs));
}
else
{
    echo "  skip demo.php (exec() is disabled on this PHP)\n";
}

/* ------------------------------------------------------------------ */
echo "Weekly check-in\n";
$clock = strtotime('2026-03-02 22:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC'));
$r = $a->run();
check('just installed: no check-in yet', $r['heartbeat'] === 'not due' && count($box['line']) === 0);
$clock = strtotime('2026-03-09 23:30:00 UTC');
$r = $a->run();
check('a week later but late at night: waits for the daytime', $r['heartbeat'] === 'waiting for daytime' && count($box['line']) === 0);
$a->custom('something', array('x'), SecurityAlerts::URGENT, 'hb1');
$clock = strtotime('2026-03-10 09:05:00 UTC');
$r = $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('next morning: one check-in, after the alert of that run', $r['heartbeat'] === 'line' && count($box['line']) === 2
    && strpos($m, 'Weekly check-in') !== false, json_encode($box['line']));
check('check-in carries the numbers (3 checks, 1 thing reported, 1 urgent) and the start date', strpos($m, '3 checks run') !== false
    && strpos($m, '1 thing(s) reported (1 urgent)') !== false && strpos($m, '2026-03-02') !== false, $m);
$clock += 3600;
$r = $a->run();
check('an hour later: not repeated', $r['heartbeat'] === 'not due' && count($box['line']) === 2);

$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC', 'heartbeat_days' => 0));
$a->run();
$clock = strtotime('2026-04-02 10:00:00 UTC');
$r = $a->run();
check('heartbeat_days = 0 turns it off', $r['heartbeat'] === 'off' && count($box['line']) === 0);

$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC', 'mail_to' => ''));
$a->run();
$box['status'] = 500;
$clock = strtotime('2026-03-09 10:00:00 UTC');
$r1 = $a->run();
$box['status'] = 200;
$clock += 300;
$r2 = $a->run();
check('check-in that could not be delivered is retried on the next run', $r1['heartbeat'] === 'failed' && $r2['heartbeat'] === 'line');

/* ------------------------------------------------------------------ */
echo "Tampering with the monitor itself\n";
$clock = $T0;
$site2 = tmpdir('site2');
$state2 = tmpdir('state2');
file_put_contents($site2 . '/index.php', "<?php echo 'hello';\n");
file_put_contents($site2 . '/about.php', "<?php echo 'about';\n");
$a = make($box, $clock, array('site_root' => $site2, 'state_dir' => $state2));
$a->run();
unlink($state2 . '/files.json');                       // what an intruder would do to blind the file check
file_put_contents($site2 . '/planted.php', "<?php echo 'x';\n");
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('fingerprints deleted behind our back: URGENT', count($box['line']) === 1 && strpos($m, 'URGENT') !== false
    && strpos($m, 'fingerprints have disappeared') !== false, json_encode($box['line']));
check('...and not a flood of "new file" lines', strpos($m, 'index.php') === false && strpos($m, 'about.php') === false);
file_put_contents($site2 . '/later.php', "<?php echo 'later';\n");
$clock += 5 * 3600; $a->run();
check('monitoring carries on from the new baseline', count($box['line']) === 2 && strpos($box['line'][1], 'later.php') !== false
    && strpos($box['line'][1], 'planted.php') === false, json_encode($box['line']));

$a->resetFileBaseline();
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('a deliberate rebaseline is announced once (Notice, not URGENT)', count($box['line']) === 3
    && strpos($m, 'baseline was reset by hand') !== false && strpos($m, 'URGENT') === false && strpos($m, 'disappeared') === false, json_encode($box['line']));
$clock += 5 * 3600; $a->run();
check('...and then it is quiet again', count($box['line']) === 3);

$witness = $state2 . '-witness.txt';
$TMP_DIRS[] = $witness;
$clock = $T0;
$state3 = tmpdir('state3');
$a = make($box, $clock, array('state_dir' => $state3, 'witness_file' => $witness));
$a->run();
check('witness file is written outside the state folder, nothing sent', is_file($witness) && count($box['line']) === 0);
rrmdir($state3);                                       // the whole state folder wiped
$clock += 86400;
$a = make($box, $clock, array('state_dir' => $state3, 'witness_file' => $witness));
$a->run();
check('state folder wiped while the witness survives: URGENT', count($box['line']) === 1
    && strpos($box['line'][0], 'monitoring records were wiped') !== false && strpos($box['line'][0], 'URGENT') !== false, json_encode($box['line']));
$clock += 300; $a->run();
check('...reported once, not on every run', count($box['line']) === 1);
@unlink($witness);

/* ------------------------------------------------------------------ */
echo "Repeated changes to the same file\n";
$clock = $T0;
$site4 = tmpdir('site4');
$state4 = tmpdir('state4');
mkdir($site4 . '/uploads', 0700, true);
file_put_contents($site4 . '/index.php', "<?php echo 1;\n");
$a = make($box, $clock, array('site_root' => $site4, 'state_dir' => $state4));
$a->run();
file_put_contents($site4 . '/index.php', "<?php echo 22;\n");
$clock += 5 * 3600; $a->run();
file_put_contents($site4 . '/index.php', "<?php echo 333;\n");
$clock += 2 * 86400; $a->run();
check('the same file changed again two days later is reported again', count($box['line']) === 2, json_encode($box['line']));
file_put_contents($site4 . '/uploads/a.php', "<?php echo 1;\n");
$clock += 5 * 3600; $a->run();
unlink($site4 . '/uploads/a.php');
$clock += 5 * 3600; $a->run();
file_put_contents($site4 . '/uploads/a.php', "<?php echo 1;\n");
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][4]) ? $box['line'][4] : '';
check('a file removed and then planted again under the same name is URGENT again', count($box['line']) === 5
    && strpos($m, 'URGENT') !== false && strpos($m, 'uploads/a.php') !== false, json_encode($box['line']));

@chmod($state4 . '/files.json', 0444);
if (@file_put_contents($state4 . '/files.json', 'x', FILE_APPEND) !== false)
{
    echo "  skip a baseline that cannot be saved (this user can write to read-only files)\n";
}
else
{
    file_put_contents($site4 . '/extra.php', "<?php echo 'extra';\n");
    $clock += 5 * 3600; $a->run();
    $clock += 5 * 3600; $a->run();
    $clock += 5 * 3600; $a->run();
    check('a baseline that cannot be saved does not repeat the same finding on every scan', count($box['line']) === 6
        && strpos($box['line'][5], 'extra.php') !== false, json_encode(array_slice($box['line'], 5)));
}
@chmod($state4 . '/files.json', 0644);

$clock = $T0;
$site4b = tmpdir('site4b');
file_put_contents($site4b . '/index.php', "<?php echo 1;\n");
$a = make($box, $clock, array('site_root' => $site4b, 'scan_hours' => 0));
$a->run();
file_put_contents($site4b . '/added.php', "<?php echo 'added';\n");
$clock += 300; $r = $a->run();
check('scan_hours = 0: files are checked on every run (5 minutes later)', $r['file_scan'] === 'complete' && count($box['line']) === 1
    && strpos($box['line'][0], 'added.php') !== false, json_encode($box['line']));

/* ------------------------------------------------------------------ */
echo "Fingerprints are SHA-256; records left by an earlier build (SHA-1) are upgraded quietly\n";
$clock = $T0;
$site5 = tmpdir('site5');
$state5 = tmpdir('state5');
mkdir($site5 . '/lib', 0700, true);
file_put_contents($site5 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site5 . '/lib/a.php', "<?php function a() { return 1; }\n");
file_put_contents($site5 . '/lib/b.php', "<?php function b() { return 2; }\n");
file_put_contents($site5 . '/.htaccess', "Options -Indexes\n");
$a = make($box, $clock, array('site_root' => $site5, 'state_dir' => $state5));
$a->run();
$rec = json_decode((string) file_get_contents($state5 . '/files.json'), true);
$allSha256 = is_array($rec) && count($rec) === 4;
foreach ((array) $rec as $rel => $row)
{
    if ($row['h'] !== hash_file('sha256', $site5 . '/' . $rel)) { $allSha256 = false; }
}
check('each code file is recorded with the SHA-256 of its content', $allSha256, json_encode($rec));

/* Turn the records into what an earlier build would have written: the same fields, 40-digit SHA-1. */
function as_old_build($stateDir, $siteDir)
{
    $rec = json_decode((string) file_get_contents($stateDir . '/files.json'), true);
    foreach ($rec as $rel => $row) { $rec[$rel]['h'] = sha1_file($siteDir . '/' . $rel); }
    file_put_contents($stateDir . '/files.json', json_encode($rec));
}
function all_sha256($stateDir)
{
    $rec = json_decode((string) file_get_contents($stateDir . '/files.json'), true);
    if (!is_array($rec) || !$rec) { return false; }
    foreach ($rec as $row) { if (strlen($row['h']) !== 64) { return false; } }
    return true;
}
as_old_build($state5, $site5);
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('upgrade with nothing changed: ONE explanatory notice, not "every file changed"', count($box['line']) === 1
    && strpos($m, 'upgraded to SHA-256') !== false && strpos($m, '4 code file(s)') !== false
    && strpos($m, 'index.php') === false && strpos($m, 'lib/a.php') === false && strpos($m, 'URGENT') === false, json_encode($box['line']));
check('...and the records are SHA-256 afterwards', all_sha256($state5));
$clock += 5 * 3600; $a->run();
check('...said once: the next scan is quiet', count($box['line']) === 1);

as_old_build($state5, $site5);
file_put_contents($site5 . '/lib/b.php', "<?php function b() { return 'changed while the old records were still in place'; }\n");
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('a file that really changed during the upgrade is still reported, the other three are not', count($box['line']) === 2
    && strpos($m, 'lib/b.php') !== false && strpos($m, '3 code file(s)') !== false
    && strpos($m, 'index.php') === false && strpos($m, 'lib/a.php') === false, $m);
file_put_contents($site5 . '/lib/a.php', "<?php function a() { return 'an ordinary edit after the upgrade'; }\n");
$clock += 5 * 3600; $a->run();
check('after the upgrade, changes are detected as before', count($box['line']) === 3 && strpos($box['line'][2], 'lib/a.php') !== false
    && strpos($box['line'][2], 'SHA-256') === false && all_sha256($state5), json_encode(array_slice($box['line'], 2)));

$clock = $T0;
$state5b = tmpdir('state5b');
$admins = array('alice' => array('role' => 'owner', 'perms' => 'orders,members', 'email' => 'Alice@Example.com', 'password' => 'hash-1', '2fa' => true));
$a = make($box, $clock, array('state_dir' => $state5b, 'admin_snapshot' => function () use (&$admins) { return $admins; }));
$a->run();
$st = json_decode((string) file_get_contents($state5b . '/state.json'), true);
check('admin snapshot keeps SHA-256 fingerprints, never the values', strlen($st['admins']['alice']['password']) === 64
    && strlen($st['admins']['alice']['email']) === 64 && strpos(json_encode($st['admins']), 'hash-1') === false
    && stripos(json_encode($st['admins']), 'alice@example.com') === false);
function snapshot_as_old_build($stateDir)
{
    $st = json_decode((string) file_get_contents($stateDir . '/state.json'), true);
    $st['admins']['alice']['perms'] = sha1('orders,members');
    $st['admins']['alice']['email'] = sha1('alice@example.com');
    $st['admins']['alice']['password'] = sha1('hash-1');
    file_put_contents($stateDir . '/state.json', json_encode($st));
}
snapshot_as_old_build($state5b);
$clock += 300; $a->run();
$st = json_decode((string) file_get_contents($state5b . '/state.json'), true);
check('admin snapshot written by an earlier build: upgraded without a "password changed" alarm', count($box['line']) === 0
    && strlen($st['admins']['alice']['password']) === 64, json_encode($box['line']));
snapshot_as_old_build($state5b);
$admins['alice']['password'] = 'hash-2';
$clock += 300; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('...and a real password change in the same step is still reported (and only that)', count($box['line']) === 1
    && strpos($m, 'password changed') !== false && strpos($m, 'e-mail changed') === false && strpos($m, 'permissions changed') === false, $m);

/* ------------------------------------------------------------------ */
echo "Code fingerprint in the weekly check-in\n";
function expected_fingerprint($root, array $rels)
{
    sort($rels, SORT_STRING);
    $text = '';
    foreach ($rels as $rel) { $text .= hash_file('sha256', $root . '/' . $rel) . '  ' . $rel . "\n"; }
    return array(implode('-', str_split(substr(hash('sha256', $text), 0, 16), 4)), $text);
}
$site6 = tmpdir('site6');
$state6 = tmpdir('state6');
mkdir($site6 . '/gen', 0700, true);
mkdir($site6 . '/cache', 0700, true);
file_put_contents($site6 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site6 . '/lib.php', "<?php function f() { return 1; }\n");
file_put_contents($site6 . '/gen/conf.php', "<?php return array('v' => 1);\n");
file_put_contents($site6 . '/cache/tpl.php', "<?php // compiled, excluded\n");
file_put_contents($site6 . '/logo.png', 'not code');
$rels6 = array('index.php', 'lib.php', 'gen/conf.php');
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site6, 'state_dir' => $state6, 'exclude_dirs' => array('cache'), 'runtime_dirs' => array('gen')));
$a->run();
list($code1, $text1) = expected_fingerprint($site6, $rels6);
$fp = $a->fingerprint();
check('fingerprint() = SHA-256 over the sorted "<hash>  <path>" list (sha256sum format), first 16 digits', is_array($fp) && $fp['code'] === $code1
    && $fp['full'] === hash('sha256', $text1) && $fp['files'] === 3 && preg_match('/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/', $fp['code']) === 1, json_encode($fp));
check('manifest() lists the files on disk in that same format', $a->manifest() === $text1, $a->manifest());

$copy6 = tmpdir('copy6');
mkdir($copy6 . '/gen', 0700, true);
mkdir($copy6 . '/cache', 0700, true);
foreach ($rels6 as $rel) { copy($site6 . '/' . $rel, $copy6 . '/' . $rel); }
file_put_contents($copy6 . '/cache/other.php', "<?php // a different cache on the other machine\n");
$fpCopy = SecurityAlerts::fingerprintOf($a->manifest($copy6));
check('a clean copy elsewhere gives the same fingerprint (excluded folders do not count)', $fpCopy['code'] === $code1);
file_put_contents($copy6 . '/lib.php', "<?php function f() { return 1; } \n");   // one extra space
$fpCopy = SecurityAlerts::fingerprintOf($a->manifest($copy6));
check('...and a one-byte difference gives another one', $fpCopy['code'] !== $code1);

$clock = strtotime('2026-03-09 10:00:00 UTC'); $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('first check-in carries the fingerprint', count($box['line']) === 1 && strpos($m, 'Code fingerprint: ' . $code1) !== false
    && strpos($m, 'from now on') !== false && strpos($m, 'Weekly check-in |') !== false, $m);
$clock = strtotime('2026-03-16 10:00:00 UTC'); $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('nothing changed for a week: "same as the last check-in"', count($box['line']) === 2 && strpos($m, $code1) !== false
    && strpos($m, 'same as the last check-in') !== false, $m);

file_put_contents($site6 . '/lib.php', "<?php function f() { return 'a deployment'; }\n");
$clock = strtotime('2026-03-18 10:00:00 UTC'); $a->run();
$clock = strtotime('2026-03-23 10:00:00 UTC'); $a->run();
list($code2) = expected_fingerprint($site6, $rels6);
$m = isset($box['line'][3]) ? $box['line'][3] : '';
check('a reported change: new fingerprint, the old one, and "1 code-change notice(s) were sent"', count($box['line']) === 4 && $code2 !== $code1
    && strpos($m, 'Code fingerprint: ' . $code2 . ' (was ' . $code1 . ')') !== false && strpos($m, '1 code-change notice(s)') !== false
    && strpos($m, '⚠') === false, $m);

file_put_contents($site6 . '/gen/conf.php', "<?php return array('v' => 2, 'written' => 'by the application itself');\n");
$clock = strtotime('2026-03-25 10:00:00 UTC'); $a->run();
$clock = strtotime('2026-03-30 10:00:00 UTC'); $a->run();
list($code3) = expected_fingerprint($site6, $rels6);
$m = isset($box['line'][4]) ? $box['line'][4] : '';
check('a change that was only logged (runtime folder): says so instead of crying wolf', count($box['line']) === 5
    && strpos($m, $code3 . ' (was ' . $code2 . ')') !== false && strpos($m, '1 change(s) in between were written to the log') !== false
    && strpos($m, '⚠') === false, $m);

/* What the fingerprint is for: a file is replaced AND the records are edited to match, so the scan sees nothing. */
file_put_contents($site6 . '/lib.php', "<?php function f() { return 'replaced quietly, and the records edited to match'; }\n");
clearstatcache();
$rec = json_decode((string) file_get_contents($state6 . '/files.json'), true);
$rec['lib.php'] = array('s' => filesize($site6 . '/lib.php'), 'm' => filemtime($site6 . '/lib.php'), 'c' => filectime($site6 . '/lib.php'),
    'h' => hash_file('sha256', $site6 . '/lib.php'), 'x' => array());
file_put_contents($state6 . '/files.json', json_encode($rec));
$clock = strtotime('2026-04-01 10:00:00 UTC'); $a->run();
check('records edited to hide a change: the scan itself sees nothing...', count($box['line']) === 5);
$clock = strtotime('2026-04-06 10:00:00 UTC'); $a->run();
list($code4) = expected_fingerprint($site6, $rels6);
$m = isset($box['line'][5]) ? $box['line'][5] : '';
check('...but the check-in does: fingerprint changed with no change on record -> warning', count($box['line']) === 6
    && strpos($m, $code4 . ' (was ' . $code3 . ')') !== false && strpos($m, 'may have been tampered with') !== false
    && strpos($m, 'something to look at') !== false, $m);
$clock = strtotime('2026-04-13 10:00:00 UTC'); $a->run();
$m = isset($box['line'][6]) ? $box['line'][6] : '';
check('the week after, with nothing new: back to a plain check-in', count($box['line']) === 7 && strpos($m, 'same as the last check-in') !== false
    && strpos($m, '⚠') === false, $m);

if (function_exists('exec'))
{
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/fingerprint.php') . ' ' . escapeshellarg($site6) . ' --exclude=cache', $lines, $code);
    check('scripts/fingerprint.php prints the same fingerprint for that folder', $code === 0 && isset($lines[0]) && strpos($lines[0], $code4) !== false,
        "exit=$code " . implode(' / ', $lines));
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/fingerprint.php') . ' ' . escapeshellarg($site6) . ' --exclude=cache --list', $lines, $code);
    list(, $text4) = expected_fingerprint($site6, $rels6);
    check('scripts/fingerprint.php --list prints the sha256sum-style list', $code === 0 && implode("\n", $lines) . "\n" === $text4, implode(' / ', $lines));

    /* The command-line entry point from examples/, run the way a site would run it. */
    $app = tmpdir('app');
    mkdir($app . '/lib', 0700, true);
    mkdir($app . '/bin', 0700, true);
    copy(__DIR__ . '/../lib/SecurityAlerts.php', $app . '/lib/SecurityAlerts.php');
    copy(__DIR__ . '/../examples/security-alerts-cron.php', $app . '/bin/security-alerts-cron.php');
    file_put_contents($app . '/bin/security-alerts.config.php', '<?php return ' . var_export(array(
        'state_dir' => $state6, 'site_root' => $site6, 'exclude_dirs' => array('cache'), 'runtime_dirs' => array('gen'), 'upload_dirs' => array('gen'),
        'heartbeat_days' => 0,
    ), true) . ";\n");
    $cron = escapeshellarg($app . '/bin/security-alerts-cron.php');
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . $cron . ' --fingerprint', $lines, $code);
    $out = implode("\n", $lines);
    check('cron entry --fingerprint: recorded = on disk, and it prints the command for a clean copy', $code === 0
        && substr_count($out, $code4) === 2 && strpos($out, '- same') !== false && strpos($out, 'fingerprint.php /path/to/clean/copy --exclude=cache') !== false, $out);
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . $cron . ' --manifest', $lines, $code);
    check('cron entry --manifest: the same list', $code === 0 && implode("\n", $lines) . "\n" === $text4, implode(' / ', $lines));
    file_put_contents($site6 . '/index.php', "<?php echo 'changed after the last scan';\n");
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . $cron . ' --fingerprint', $lines, $code);
    check('cron entry --fingerprint: says DIFFERENT (exit 1) when the disk no longer matches the records', $code === 1
        && strpos(implode("\n", $lines), 'DIFFERENT') !== false, "exit=$code " . implode(' / ', $lines));
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . $cron . ' --audit', $lines, $code);
    check('cron entry --audit: lists the code file sitting in an upload folder', $code === 0 && strpos(implode("\n", $lines), 'gen/conf.php') !== false
        && strpos(implode("\n", $lines), '1 code file(s) worth a look') !== false, implode(' / ', $lines));
}
else
{
    echo "  skip the command-line tools (exec() is disabled on this PHP)\n";
}

/* ------------------------------------------------------------------ */
echo "Audit (what was already there) and your own rules\n";
$clock = $T0;
$site7 = tmpdir('site7');
mkdir($site7 . '/lib', 0700, true);
mkdir($site7 . '/uploads', 0700, true);
file_put_contents($site7 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site7 . '/lib/old-tool.php', bait("<?php \$f = create_func~tion('', \$body);\n"));   // already there before the module was installed
file_put_contents($site7 . '/uploads/thumb.php', "<?php echo 1;\n");
$a = make($box, $clock, array('site_root' => $site7));
$a->run();
check('first run trusts what is already on the server (nothing sent)...', count($box['line']) === 0);
$audit = $a->audit();
check('...so audit() lists it: a run-time code builder and a code file in uploads, not the clean file', array_keys($audit) === array('lib/old-tool.php', 'uploads/thumb.php')
    && $audit['lib/old-tool.php']['ids'] === array('crfn') && $audit['lib/old-tool.php']['why'] === 'builds code at run time'
    && $audit['uploads/thumb.php']['why'] === 'code file inside an upload folder', json_encode($audit));
check('audit() only reads: nothing sent, baseline untouched', count($box['line']) === 0);

$site7b = tmpdir('site7b');
file_put_contents($site7b . '/index.php', "<?php echo 'home';\n");
$a = make($box, $clock, array('site_root' => $site7b, 'disable_rules' => array('crfn'), 'extra_rules' => array(
    'incident' => array('pattern' => '/evil-corp\.example/i', 'label' => 'mentions the domain from our last incident'),
    'marker'   => '/zzz_marker_[0-9]+/',
    'broken'   => '/unclosed(',
)));
$a->run();
file_put_contents($site7b . '/a.php', "<?php // loads https://evil-corp.example/x.js\n");
file_put_contents($site7b . '/b.php', "<?php \$zzz_marker_42 = 1;\n");
file_put_contents($site7b . '/c.php', bait("<?php \$f = create_func~tion('', \$body);\n"));
$clock += 5 * 3600; $a->run();
$all = implode("\n", $box['line']);
check('extra_rules: a match is URGENT, in your own words (or naming the rule)', strpos($all, 'URGENT') !== false
    && strpos($all, 'a.php (mentions the domain from our last incident)') !== false
    && strpos($all, 'b.php (matches your own rule "marker")') !== false, $all);
check('disable_rules: a switched-off built-in rule no longer makes a file URGENT', strpos($all, '＋ c.php') !== false && strpos($all, 'c.php (') === false, $all);
check('a pattern that does not compile is skipped and reported by ignoredRules()', $a->ignoredRules() === array('broken'), json_encode($a->ignoredRules()));

/* ------------------------------------------------------------------ */
echo "Outside check-in (ping_url)\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$state8 = tmpdir('state8');
$secretUrl = 'https://checkin.example/ping/3f6c1b9e-SECRET-TOKEN';
$pings = array();
$pingAnswer = 200;
$order = array();
$pingCfg = array('timezone' => 'UTC', 'state_dir' => $state8, 'ping_url' => $secretUrl, 'ping_timeout' => 3,
    'ping_transport' => function ($url, $timeout) use (&$pings, &$pingAnswer, &$order) {
        $pings[] = array($url, $timeout);
        $order[] = 'ping';
        if ($pingAnswer === 'throw') { throw new RuntimeException('network down'); }
        return $pingAnswer;
    });
$lineTransport = function ($url, $headers, $body, $method = 'POST') use (&$box, &$order) {
    if ($method === 'GET') { return fake_quota($url, $box); }
    $order[] = 'line';
    $j = json_decode($body, true);
    $box['line'][] = $j['messages'][0]['text'];
    return array($box['status'], '{}');
};
$a = make($box, $clock, $pingCfg + array('transport' => $lineTransport));
$a->custom('disk almost full', array('92% used'), SecurityAlerts::URGENT, 'p1');
$clock += 60; $r = $a->run();
check('one check-in per completed run, with the configured address and timeout', $r['ping'] === 'ok' && $pings === array(array($secretUrl, 3)), json_encode($r));
check('...after the alert of that run has gone out, not before', $order === array('line', 'ping'), json_encode($order));

$pingAnswer = 500;
$a->custom('second thing', array('x'), SecurityAlerts::URGENT, 'p2');
$clock += 300; $r = $a->run();
check('the check-in service answers 500: the run and its alert are unaffected', $r['ping'] === 'failed' && $r['sent'] === 'line' && count($box['line']) === 2, json_encode($r));
$pingAnswer = 'throw';
$a->custom('third thing', array('x'), SecurityAlerts::URGENT, 'p3');
$clock += 300; $r = $a->run();
check('the check-in throws (network down): still unaffected', $r['ping'] === 'failed' && $r['sent'] === 'line' && count($box['line']) === 3, json_encode($r));

$leak = array();
foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($state8, FilesystemIterator::SKIP_DOTS)) as $f)
{
    if (strpos((string) file_get_contents($f->getPathname()), 'SECRET-TOKEN') !== false) { $leak[] = $f->getFilename(); }
}
check('the address is not written to any record, nor put into a message', $leak === array() && strpos(implode("\n", $box['line']), 'SECRET-TOKEN') === false
    && strpos(json_encode($r), 'SECRET-TOKEN') === false, implode(',', $leak));

$pingAnswer = 0;   // no answer at all
$clock += 300; $r = $a->run();
$clock = strtotime('2026-03-09 10:05:00 UTC'); $r = $a->run();
$m = isset($box['line'][3]) ? $box['line'][3] : '';
check('weekly check-in says the outside check-in keeps failing (3 in a row), under a warning header', $r['heartbeat'] === 'line'
    && strpos($m, 'has failed 3 time(s) in a row') !== false && strpos($m, 'something to look at') !== false, $m);
$pingAnswer = 204;
$clock += 300; $r = $a->run();
check('any 2xx answer counts as delivered', $r['ping'] === 'ok');
$pingAnswer = 500;
$clock = strtotime('2026-03-16 10:00:00 UTC'); $a->run();   // one hiccup just before the check-in is due
$pingAnswer = 200;
$clock = strtotime('2026-03-16 10:10:00 UTC'); $a->run();
$m = isset($box['line'][4]) ? $box['line'][4] : '';
check('...and once it works again the check-in says so (a single hiccup is not a warning)', strpos($m, 'Outside check-in: working') !== false
    && strpos($m, '⚠') === false, $m);

$before = count($pings);
$r1 = $a->tick();
$r2 = $a->tick();
check('a tick() that is skipped does not check in', isset($r2['skipped']) && count($pings) === $before + 1);

$pings = array();
$a = make($box, $clock, array('ping_transport' => $pingCfg['ping_transport']));
$r = $a->run();
check('no ping_url: nothing is called', $r['ping'] === 'off' && $pings === array());
$a = make($box, $clock, array('ping_url' => 'ftp://not-http.example/x', 'ping_transport' => $pingCfg['ping_transport']));
$r = $a->run();
check('an address that is not http(s) is never requested', $r['ping'] === 'failed' && $pings === array());
$a = make($box, $clock, array('enabled' => false, 'ping_url' => $secretUrl, 'ping_transport' => $pingCfg['ping_transport']));
$r = $a->run();
check('module disabled: no check-in either (so the outside service notices)', $r['ping'] === 'off' && $pings === array());

/* ------------------------------------------------------------------ */
echo "Your own channel (notifier)\n";
$clock = $T0;
$got = array();
$answer = true;
$a = make($box, $clock, array('daily_cap' => 1, 'notifier' => function ($text, $level) use (&$got, &$answer) {
    if ($answer === 'throw') { throw new RuntimeException('webhook down'); }
    $got[] = array($text, $level);
    return $answer;
}));
$a->custom('to my own channel', array('one'), SecurityAlerts::NOTICE, 'n1');
$clock += 60; $r = $a->run();
check('notifier takes the message (with its level); LINE is not used', $r['sent'] === 'custom' && count($got) === 1 && $got[0][1] === SecurityAlerts::NOTICE
    && strpos($got[0][0], 'to my own channel') !== false && count($box['line']) === 0, json_encode($r));
$a->custom('over the cap', array('two'), SecurityAlerts::NOTICE, 'n2');
$clock += 60; $r = $a->run();
check('messages sent through the notifier count towards the daily cap', $r['sent'] === 'capped' && count($got) === 1, json_encode($r));
$answer = false;
$a->custom('channel says no', array('three'), SecurityAlerts::URGENT, 'n3');
$clock += 60; $r = $a->run();
check('notifier returns false: falls back to LINE', $r['sent'] === 'line' && count($box['line']) === 1 && strpos($box['line'][0], 'channel says no') !== false
    && $got[1][1] === SecurityAlerts::URGENT, json_encode($r));
$answer = 'throw';
$a->custom('channel breaks', array('four'), SecurityAlerts::URGENT, 'n4');
$clock += 60; $r = $a->run();
check('notifier throws: falls back to LINE', $r['sent'] === 'line' && count($box['line']) === 2, json_encode($r));

/* ------------------------------------------------------------------ */
echo "Automatic quarantine in upload folders (optional, off by default)\n";
$clock = strtotime('2026-03-02 03:15:00 UTC');
$site9 = tmpdir('site9');
mkdir($site9 . '/uploads/2026', 0700, true);
mkdir($site9 . '/lib', 0700, true);
file_put_contents($site9 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site9 . '/uploads/old-helper.php', "<?php // was here before the module was installed\n");
$planted = "<?php echo 'planted';\n";

$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site9));
$a->run();
file_put_contents($site9 . '/uploads/2026/avatar.jpg.php', $planted);
$clock += 2 * 3600; $r = $a->run();
check('off by default: a program in uploads is reported and left exactly where it is', count($box['line']) === 1 && $r['quarantined'] === 0
    && is_file($site9 . '/uploads/2026/avatar.jpg.php') && strpos($box['line'][0], 'renamed') === false, json_encode($box['line']));
unlink($site9 . '/uploads/2026/avatar.jpg.php');

$state9 = tmpdir('state9');
$renameWorks = true;
$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site9, 'state_dir' => $state9, 'quarantine_uploads' => true, 'scan_hours' => 0,
    'renamer' => function ($from, $to) use (&$renameWorks) { return $renameWorks ? rename($from, $to) : false; }));
$a->run();   // baseline: uploads/old-helper.php is already there
file_put_contents($site9 . '/uploads/2026/avatar.jpg.php', $planted);
file_put_contents($site9 . '/uploads/.htaccess', "Options -Indexes\n");
file_put_contents($site9 . '/lib/new-lib.php', bait("<?php \$f = create_func~tion('', \$b);\n"));              // suspicious, but not in uploads
file_put_contents($site9 . '/uploads/old-helper.php', "<?php // was here before the install, edited afterwards\n");   // in uploads, but not new
$clock = strtotime('2026-03-02 09:30:00 UTC'); $r = $a->run();
$m = implode("\n", $box['line']);
$q1 = 'uploads/2026/avatar_jpg_php-20260302-093000.quarantined';
check('switched on: the new program in uploads is renamed, same folder, same bytes, nothing deleted', $r['quarantined'] === 1
    && !file_exists($site9 . '/uploads/2026/avatar.jpg.php') && is_file($site9 . '/' . $q1)
    && file_get_contents($site9 . '/' . $q1) === $planted, json_encode(glob($site9 . '/uploads/2026/*')));
check('the new name has one dot only and no ".php" left in it', substr_count(basename($q1), '.') === 1 && stripos(basename($q1), '.php') === false);
check('the alert is URGENT, gives both names and says how to undo it', count($box['line']) === 1 && strpos($m, 'URGENT') !== false
    && strpos($m, 'New: uploads/2026/avatar.jpg.php (') !== false && strpos($m, '→ renamed to ' . $q1) !== false
    && strpos($m, 'rename it back') !== false && strpos($m, 'Nothing was deleted') !== false, $m);
check('nothing else is touched: .htaccess in uploads, a suspicious file elsewhere, a file that was already there', is_file($site9 . '/uploads/.htaccess')
    && is_file($site9 . '/lib/new-lib.php') && is_file($site9 . '/uploads/old-helper.php')
    && strpos($m, 'uploads/.htaccess') !== false && strpos($m, 'lib/new-lib.php') !== false && substr_count($m, 'renamed to') === 1, $m);
$rec = json_decode((string) file_get_contents($state9 . '/files.json'), true);
check('the renamed file is not tracked as code (neither name is in the records)', !isset($rec['uploads/2026/avatar.jpg.php']) && !isset($rec[$q1])
    && isset($rec['uploads/.htaccess']), json_encode(array_keys((array) $rec)));
$clock += 300; $a->run();
check('the next scan is quiet', count($box['line']) === 1, json_encode(array_slice($box['line'], 1)));

file_put_contents($site9 . '/uploads/2026/avatar.jpg.php', $planted);   // planted again under the same name
$clock += 300; $r = $a->run();
$q2 = 'uploads/2026/avatar_jpg_php-20260302-094000.quarantined';
check('planted again: quarantined again (the first copy is kept) and reported again', $r['quarantined'] === 1 && count($box['line']) === 2
    && is_file($site9 . '/' . $q1) && is_file($site9 . '/' . $q2) && strpos($box['line'][1], $q2) !== false, json_encode(glob($site9 . '/uploads/2026/*')));

file_put_contents($site9 . '/uploads/2026/x.y.php', $planted);          // two names that become the same quarantine name...
file_put_contents($site9 . '/uploads/2026/x_y.php', $planted . "// second\n");   // ...in the same second
$clock += 300; $r = $a->run();
$q3 = 'uploads/2026/x_y_php-20260302-094500';
check('two files that would get the same new name: neither overwrites the other', $r['quarantined'] === 2 && count($box['line']) === 3
    && is_file($site9 . '/' . $q3 . '.quarantined') && is_file($site9 . '/' . $q3 . '-2.quarantined')
    && filesize($site9 . '/' . $q3 . '.quarantined') !== filesize($site9 . '/' . $q3 . '-2.quarantined'), json_encode(glob($site9 . '/uploads/2026/*')));

$renameWorks = false;
file_put_contents($site9 . '/uploads/2026/no-permission.php', $planted);
$clock += 600; $r = $a->run();
$m = isset($box['line'][3]) ? $box['line'][3] : '';
check('renaming fails (no permission): the file stays, and the alert says it can still run', $r['quarantined'] === 0 && is_file($site9 . '/uploads/2026/no-permission.php')
    && strpos($m, 'uploads/2026/no-permission.php') !== false && strpos($m, 'tried and failed') !== false && strpos($m, 'renamed to') === false, $m);
$clock += 600; $a->run();
check('...reported once, not on every scan', count($box['line']) === 4);

$clock = $T0;
$site9b = tmpdir('site9b');
mkdir($site9b . '/uploads', 0700, true);
file_put_contents($site9b . '/index.php', "<?php echo 'home';\n");
$a = make($box, $clock, array('site_root' => $site9b));
$a->run();
for ($i = 1; $i <= 9; $i++) { file_put_contents($site9b . '/uploads/p' . $i . '.php', "<?php echo $i;\n"); }
for ($i = 1; $i <= 10; $i++) { file_put_contents($site9b . '/page' . $i . '.php', "<?php echo 'page $i';\n"); }
$clock += 5 * 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('many files at once: the message says how many are not listed, and the advice lines are not cut off', count($box['line']) === 1
    && strpos($m, '…and 3 more file(s)') !== false && strpos($m, 'Check these files now') !== false
    && strpos($m, '10 new, 0 changed, 0 deleted') !== false && strpos($m, 'If this was your own deployment') !== false, $m);

/* ------------------------------------------------------------------ */
echo "Hidden edits: the modification time put back, and the weekly full re-read\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$site10 = tmpdir('site10');
file_put_contents($site10 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site10 . '/a.php', "<?php return 'aaaa';\n");
file_put_contents($site10 . '/b.php', "<?php return 'bbbb';\n");
$longAgo = time() - 3600;   // files that were last touched an hour ago, like any file on a real site
foreach (array('index.php', 'a.php', 'b.php') as $f) { touch($site10 . '/' . $f, $longAgo); }
clearstatcache();
$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site10, 'heartbeat_days' => 0));
$a->run();

file_put_contents($site10 . '/a.php', "<?php return 'aaaa'; /* something added */\n");
touch($site10 . '/a.php', $longAgo);
clearstatcache();
$clock += 2 * 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('a file is edited and its modification time put back: URGENT, and the message says so', count($box['line']) === 1 && strpos($m, 'URGENT') !== false
    && strpos($m, 'a.php') !== false && strpos($m, 'modification time was put back') !== false, $m);

file_put_contents($site10 . '/b.php', "<?php return 'BBBB';\n");   // same length as before
touch($site10 . '/b.php', $longAgo);
clearstatcache();
$clock += 2 * 3600; $a->run();
$seenEarly = count($box['line']);
$clock += 8 * 86400; $a->run();   // more than rehash_days later: every file is read again in full
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('same size AND the time put back: found at the latest by the weekly full re-read, as URGENT', count($box['line']) === 2 && strpos($m, 'URGENT') !== false
    && strpos($m, 'b.php') !== false && strpos($m, 'modification time was put back') !== false, json_encode(array_slice($box['line'], 1)));
if (PHP_OS_FAMILY === 'Windows')
{
    check('(here size and both times were identical, so the ordinary scan could not see it: only the full re-read did)', $seenEarly === 1);
}
else
{
    echo "  note on this system the ordinary scan already saw it (the inode change time moved): " . ($seenEarly === 2 ? 'yes' : 'no, the full re-read did') . "\n";
}
file_put_contents($site10 . '/index.php', "<?php echo 'home, edited the ordinary way';\n");
$clock += 2 * 3600; $a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('an ordinary edit (it gets a new modification time) stays a plain Notice', count($box['line']) === 3 && strpos($m, 'index.php') !== false
    && strpos($m, 'URGENT') === false && strpos($m, 'put back') === false, $m);
$clock += 8 * 86400; $a->run();
check('a full re-read that finds nothing is silent', count($box['line']) === 3, json_encode(array_slice($box['line'], 3)));

$site10b = tmpdir('site10b');
file_put_contents($site10b . '/a.php', "<?php return 'aaaa';\n");
touch($site10b . '/a.php', $longAgo);
clearstatcache();
$a = make($box, $clock, array('site_root' => $site10b, 'disable_rules' => array('stealth'), 'heartbeat_days' => 0));
$a->run();
file_put_contents($site10b . '/a.php', "<?php return 'aaaa'; /* something added */\n");
touch($site10b . '/a.php', $longAgo);
clearstatcache();
$clock += 2 * 3600; $a->run();
check('disable_rules = stealth: the same edit is reported as an ordinary change', count($box['line']) === 1 && strpos($box['line'][0], 'a.php') !== false
    && strpos($box['line'][0], 'URGENT') === false, json_encode($box['line']));

/* ------------------------------------------------------------------ */
echo "Alerts that could not be delivered are sent later\n";
/* A transport that keeps only what "LINE" accepted, and counts the attempts. */
$attempts = 0;
$strict = function ($url, $headers, $body, $method = 'POST') use (&$box, &$attempts) {
    if ($method === 'GET') { return fake_quota($url, $box); }
    $attempts++;
    if ($box['status'] >= 300) { return array($box['status'], '{}'); }
    $j = json_decode($body, true);
    $box['line'][] = $j['messages'][0]['text'];
    return array(200, '{}');
};
$clock = strtotime('2026-03-02 10:00:00 UTC');
$site11 = tmpdir('site11');
$state11 = tmpdir('state11');
file_put_contents($site11 . '/index.php', "<?php echo 'home';\n");
$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site11, 'state_dir' => $state11, 'mail_to' => '', 'transport' => $strict));
$a->run();
$clock = strtotime('2026-03-09 10:00:00 UTC'); $a->run();   // first weekly check-in (carries the fingerprint)
check('(set-up) the first check-in went out', count($box['line']) === 1 && strpos($box['line'][0], 'Code fingerprint') !== false, json_encode($box['line']));

$box['status'] = 500;   // LINE refuses and there is no e-mail address
file_put_contents($site11 . '/added.php', "<?php echo 'added during the outage';\n");
$a->accountChanged('created', 'mallory', 'alice');
$clock = strtotime('2026-03-10 12:00:00 UTC'); $r = $a->run();
check('LINE and e-mail both fail: the run reports "failed" and loses nothing yet', $r['sent'] === 'failed' && $r['resent'] === 0 && count($box['line']) === 1, json_encode($r));
$before = $attempts;
$clock += 300; $r = $a->run();
check('still down on the next run: one more attempt, still kept', $r['resent'] === 0 && $attempts === $before + 1 && count($box['line']) === 1, json_encode($r));
$box['status'] = 200;
$clock += 300; $r = $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('delivery works again: the held alert arrives, marked as delayed, with what it originally said', $r['resent'] === 1 && count($box['line']) === 2
    && strpos($m, 'Delayed') !== false && strpos($m, '03/10 12:00') !== false && strpos($m, 'added.php') !== false && strpos($m, 'mallory') !== false, $m);
$clock += 300; $r = $a->run();
check('...once only', $r['resent'] === 0 && count($box['line']) === 2, json_encode($r));
$clock = strtotime('2026-03-16 10:00:00 UTC'); $a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('the weekly check-in then counts it as a notice that was sent (not "only logged")', strpos($m, '1 code-change notice(s) were sent') !== false
    && strpos($m, 'written to the log') === false && strpos($m, '⚠') === false, $m);

$clock = strtotime('2026-03-02 10:00:00 UTC');
$state11b = tmpdir('state11b');
$a = make($box, $clock, array('timezone' => 'UTC', 'state_dir' => $state11b, 'mail_to' => '', 'heartbeat_days' => 0, 'transport' => $strict));
$box['status'] = 500;
for ($i = 1; $i <= 5; $i++)
{
    $a->custom('held number ' . $i, array('x'), SecurityAlerts::URGENT, 'held' . $i);
    $clock += 300; $a->run();
}
$box['status'] = 200;
$clock += 300; $r1 = $a->run();
$firstBatch = implode('|', array_map(function ($t) { return preg_match('/held number (\d)/', $t, $mm) ? $mm[1] : '?'; }, $box['line']));
$clock += 300; $r2 = $a->run();
$allOf = implode('|', array_map(function ($t) { return preg_match('/held number (\d)/', $t, $mm) ? $mm[1] : '?'; }, $box['line']));
$clock += 300; $r3 = $a->run();
check('five held alerts: oldest first, three per run, none twice', $r1['resent'] === 3 && $firstBatch === '1|2|3' && $r2['resent'] === 2 && $allOf === '1|2|3|4|5'
    && $r3['resent'] === 0 && count($box['line']) === 5, "$firstBatch / $allOf");

$a->custom('too old to send', array('x'), SecurityAlerts::URGENT, 'old1');
$box['status'] = 500;
$clock += 300; $a->run();
$box['status'] = 200;
$clock += 8 * 86400; $r = $a->run();
check('held for more than 7 days: given up (and logged), not sent as stale news', $r['resent'] === 0 && count($box['line']) === 5
    && strpos((string) file_get_contents($state11b . '/findings.ndjson'), '"status":"expired"') !== false, json_encode($r));

/* ------------------------------------------------------------------ */
echo "Names that are not UTF-8 (old folders and accounts in Big5, Latin-1...)\n";
$big5Folder = "\xA4\xA4\xA4\xE5";                  // "中文" as an old FTP client would have written it: not valid UTF-8
$oddPath = 'old/' . $big5Folder . '/tool.php';
$canConvert = (function_exists('mb_convert_encoding') && in_array('big5', array_map('strtolower', mb_list_encodings()), true)) || function_exists('iconv');
$clock = $T0;
$probe = make($pbox, $clock);
$packed = (function () use ($oddPath) { return $this->packPath($oddPath); })->call($probe);
check('such a path is stored in a form JSON accepts, and comes back byte for byte', $packed !== $oddPath && json_encode(array($packed => 1)) !== false
    && (function () use ($packed) { return $this->unpackPath($packed); })->call($probe) === $oddPath
    && (function () { return $this->packPath('lib/ordinary.php') . $this->packPath('lib/正常.php'); })->call($probe) === 'lib/ordinary.phplib/正常.php');

$site12 = tmpdir('site12');
$state12 = tmpdir('state12');
file_put_contents($site12 . '/index.php', "<?php echo 'home';\n");
foreach (array('' => '?', 'BIG5' => $canConvert ? '中文' : '?') as $charset => $expect)
{
    $st = $state12 . ($charset === '' ? '' : '-b');
    if ($charset !== '') { $TMP_DIRS[] = $st; }
    $a = make($box, $clock, array('site_root' => $site12, 'state_dir' => $st, 'heartbeat_days' => 0, 'input_charset' => $charset));
    $a->run();
    /* the record a Linux server would hold for a file with that name; the file itself is gone, so the next scan reports it */
    $rec = json_decode((string) file_get_contents($st . '/files.json'), true);
    $rec[$packed] = array('s' => 10, 'm' => 1, 'c' => 1, 'h' => str_repeat('a', 64), 'x' => array());
    file_put_contents($st . '/files.json', json_encode($rec));
    $clock += 2 * 3600; $r = $a->run();
    $m = isset($box['line'][0]) ? $box['line'][0] : '';
    check('a file with such a name is reported in a message that is valid UTF-8' . ($charset === '' ? ' ("?" for the odd bytes)' : ' (input_charset = BIG5' . ($canConvert ? ': shown as 中文)' : ', no converter in this PHP: "?")')),
        count($box['line']) === 1 && preg_match('//u', $m) === 1 && strpos($m, 'old/' . $expect) !== false && strpos($m, '/tool.php') !== false, bin2hex(substr($m, 0, 200)));
    $after = json_decode((string) file_get_contents($st . '/files.json'), true);
    $state = json_decode((string) file_get_contents($st . '/state.json'), true);
    check('...and the records are still intact afterwards', is_array($after) && isset($after['index.php']) && is_array($state) && !empty($state['files_baselined']));
}

$wang = "\xA4\xFD\xA4p\xA9\xFA";                    // an account name in Big5
$state12c = tmpdir('state12c');
$a = make($box, $clock, array('state_dir' => $state12c, 'heartbeat_days' => 0));
for ($i = 0; $i < 10; $i++) { $a->loginFailed($wang, '203.0.113.9', "curl/8 \xE9t\xE9", true); }
$clock += 60; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
$state = json_decode((string) file_get_contents($state12c . '/state.json'), true);
$eventsOk = true;
foreach (glob($state12c . '/*.ndjson') as $f)
{
    foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) { if (!is_array(json_decode($line, true))) { $eventsOk = false; } }
}
check('hooks given non-UTF-8 text: the alert still goes out, as valid UTF-8', count($box['line']) === 1 && preg_match('//u', $m) === 1 && strpos($m, '10 failed admin logins') !== false, bin2hex(substr($m, 0, 120)));
check('...and every record written is valid JSON (nothing emptied, nothing lost)', $eventsOk && is_array($state) && !empty($state['last_run']));
$clock += 60; $a->run();
check('...and it is not repeated on the next run', count($box['line']) === 1);

$admins = array("\xA4\xFD" => array('role' => 'owner', 'password' => 'h1'), "\xA7\xF5" => array('role' => 'staff', 'password' => 'h2'));   // two names that would both become "?"
$a = make($box, $clock, array('admin_snapshot' => function () use (&$admins) { return $admins; }, 'heartbeat_days' => 0));
$a->run();
$clock += 300; $a->run();
check('two accounts whose names are not UTF-8: learned once, no "new account" alarm on every run', count($box['line']) === 0, json_encode($box['line']));
$admins["\xA7\xF5"]['password'] = 'h3';
$clock += 300; $a->run();
check('...and a real change to one of them is reported once, for that one only', count($box['line']) === 1 && substr_count($box['line'][0], 'password changed') === 1
    && preg_match('//u', $box['line'][0]) === 1, json_encode($box['line']));

if (PHP_OS_FAMILY !== 'Windows')
{
    $site12d = tmpdir('site12d');
    file_put_contents($site12d . '/index.php', "<?php echo 'home';\n");
    $oddDir = $site12d . '/old_' . $big5Folder;
    if (@mkdir($oddDir) && @file_put_contents($oddDir . '/tool.php', "<?php echo 1;\n") !== false)
    {
        $state12d = tmpdir('state12d');
        $a = make($box, $clock, array('site_root' => $site12d, 'state_dir' => $state12d, 'heartbeat_days' => 0));
        $a->run();
        $rec = json_decode((string) file_get_contents($state12d . '/files.json'), true);
        check('a real file in a folder with a non-UTF-8 name: the baseline is saved', is_array($rec) && count($rec) === 2, (string) file_get_contents($state12d . '/files.json'));
        $clock += 2 * 3600; $a->run();
        check('...nothing is reported while nothing changes', count($box['line']) === 0, json_encode($box['line']));
        file_put_contents($oddDir . '/tool.php', "<?php echo 'changed';\n");
        $clock += 2 * 3600; $a->run();
        check('...a change to that file is reported once, in valid UTF-8', count($box['line']) === 1 && preg_match('//u', $box['line'][0]) === 1
            && strpos($box['line'][0], '/tool.php') !== false, bin2hex(isset($box['line'][0]) ? $box['line'][0] : ''));
        $clock += 2 * 3600; $a->run();
        check('...and not again', count($box['line']) === 1);
    }
    else
    {
        echo "  skip a real file with a non-UTF-8 name (this file system does not accept such names)\n";
    }
}
else
{
    echo "  skip a real file with a non-UTF-8 name (Windows file names are always Unicode; this part only runs on Linux)\n";
}

/* ------------------------------------------------------------------ */
echo "LINE's monthly allowance in the weekly check-in\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC'));
$a->run();
$box['quota'] = array(120, 200);
$clock = strtotime('2026-03-09 10:00:00 UTC'); $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('the check-in says how many LINE messages are used this month', count($box['line']) === 1 && strpos($m, 'LINE messages this month: about 120 of 200 used.') !== false
    && strpos($m, '⚠') === false, $m);
$box['quota'] = array(170, 200);
$clock = strtotime('2026-03-16 10:00:00 UTC'); $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('80% used: a warning line, and the check-in is marked "something to look at"', strpos($m, '⚠ LINE messages this month: about 170 of 200 used.') !== false
    && strpos($m, 'something to look at') !== false, $m);
$box['quota'] = array(203, 200);
$clock = strtotime('2026-03-23 10:00:00 UTC'); $a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('used up: says the limit is reached', strpos($m, 'the limit of 200 is used up') !== false && strpos($m, 'something to look at') !== false, $m);
unset($box['quota']);
$clock = strtotime('2026-03-30 10:00:00 UTC'); $a->run();
$m = isset($box['line'][3]) ? $box['line'][3] : '';
check('a plan without a limit: no line about it', count($box['line']) === 4 && strpos($m, 'LINE messages this month') === false && strpos($m, 'Weekly check-in |') !== false, $m);
$box['quota'] = 'down';
$clock = strtotime('2026-04-06 10:00:00 UTC'); $r = $a->run();
$m = isset($box['line'][4]) ? $box['line'][4] : '';
check('LINE does not answer the question: the check-in goes out anyway, without that line', $r['heartbeat'] === 'line' && count($box['line']) === 5
    && strpos($m, 'LINE messages this month') === false, $m);
$before = $box['gets'];
$clock += 300; $a->run();
check('LINE is only asked when a check-in is actually sent (not on every run)', $box['gets'] === $before, $box['gets'] - $before);

$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC', 'line_quota_check' => false));
$a->run();
$box['quota'] = array(120, 200);
$clock = strtotime('2026-03-09 10:00:00 UTC'); $a->run();
check('line_quota_check = false: LINE is never asked', count($box['line']) === 1 && !isset($box['gets']) && strpos($box['line'][0], 'LINE messages this month') === false,
    json_encode($box));

/* ------------------------------------------------------------------ */
echo "status(): where things stand\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$site13 = tmpdir('site13');
$state13 = tmpdir('state13');
file_put_contents($site13 . '/index.php', "<?php echo 'home';\n");
file_put_contents($site13 . '/lib.php', "<?php function f() { return 1; }\n");
$secretCfg = array('timezone' => 'UTC', 'site_root' => $site13, 'state_dir' => $state13, 'site_name' => 'Status shop',
    'line_channel_access_token' => 'TOKEN-SECRET-9f2c', 'line_to' => array('Usecret0123456789'), 'mail_to' => '',
    'ping_url' => 'https://checkin.example/ping/PING-SECRET-77', 'ping_transport' => function () { return 200; });
$a = make($box, $clock, $secretCfg);
$s = $a->status();
check('before the first run: says the checks have never run here', $s['last_run'] === null && in_array('the checks have never run here', $s['problems'], true), json_encode($s['problems']));
$a->run();
$stateBefore = (string) file_get_contents($state13 . '/state.json');
$s = $a->status();
$fp = $a->fingerprint();
check('after a run: last run, files watched, the current fingerprint, who gets the alerts', $s['last_run'] === $clock && $s['files']['watched'] === 2
    && $s['files']['fingerprint'] === $fp['code'] && $s['delivery']['line'] === true && $s['delivery']['line_recipients'] === 1
    && $s['outside_checkin']['configured'] === true && $s['checkin']['every_days'] === 7, json_encode($s));
check('it points out that there is no fallback e-mail', count($s['problems']) === 1 && strpos($s['problems'][0], 'no fallback e-mail') !== false, json_encode($s['problems']));
check('no token, recipient id or check-in address in it', strpos(json_encode($s), 'SECRET') === false && strpos(json_encode($s), 'Usecret') === false);
check('asking for the status changes nothing and sends nothing', (string) file_get_contents($state13 . '/state.json') === $stateBefore && count($box['line']) === 0);

$a->custom('something happened', array('x'), SecurityAlerts::URGENT, 'st1');
$clock += 300; $a->run();
$s = $a->status();
$last = $s['recent'] ? $s['recent'][count($s['recent']) - 1] : array();
check('the latest findings are listed with how they were delivered', $s['sent_today'] === 1 && isset($last['title']) && $last['title'] === 'something happened'
    && $last['status'] === 'line' && $last['level'] === SecurityAlerts::URGENT, json_encode($s['recent']));
$box['status'] = 500;
$a->custom('cannot be delivered', array('x'), SecurityAlerts::URGENT, 'st2');
$clock += 300; $a->run();
$s = $a->status();
check('an alert that is waiting to be re-sent shows up as a problem', $s['waiting']['count'] === 1 && $s['waiting']['oldest'] === $clock
    && count(array_filter($s['problems'], function ($p) { return strpos($p, 'waiting to be re-sent') !== false; })) === 1, json_encode($s['problems']));
$clock += 2 * 3600;
$s = $a->status();
check('two hours without a run: "is the scheduled job still there?"', count(array_filter($s['problems'], function ($p) { return strpos($p, 'no check for 120 minutes') !== false; })) === 1,
    json_encode($s['problems']));
$b = make($box, $clock, array('enabled' => false, 'line_channel_access_token' => '', 'line_to' => array(), 'mail_to' => ''));
$s = $b->status();
check('switched off, and nowhere to send to: both are named', in_array('the module is switched off (enabled = false)', $s['problems'], true)
    && count(array_filter($s['problems'], function ($p) { return strpos($p, 'nowhere to send alerts') !== false; })) === 1, json_encode($s['problems']));

if (function_exists('exec'))
{
    $app2 = tmpdir('app2');
    mkdir($app2 . '/lib', 0700, true);
    mkdir($app2 . '/bin', 0700, true);
    copy(__DIR__ . '/../lib/SecurityAlerts.php', $app2 . '/lib/SecurityAlerts.php');
    copy(__DIR__ . '/../examples/security-alerts-cron.php', $app2 . '/bin/security-alerts-cron.php');
    file_put_contents($app2 . '/bin/security-alerts.config.php', '<?php return ' . var_export(array(
        'state_dir' => $state13, 'site_root' => $site13, 'site_name' => 'Status shop', 'timezone' => 'UTC',
        'line_channel_access_token' => 'TOKEN-SECRET-9f2c', 'line_to' => array('Usecret0123456789'), 'ping_url' => 'https://checkin.example/ping/PING-SECRET-77',
    ), true) . ";\n");
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($app2 . '/bin/security-alerts-cron.php') . ' --status', $lines, $code);
    $out = implode("\n", $lines);
    check('cron entry --status: prints the picture in plain lines, exit 1 because something needs a look, no secrets', $code === 1
        && strpos($out, 'Status shop') !== false && strpos($out, $fp['code']) !== false && strpos($out, 'waiting to be re-sent') !== false
        && strpos($out, 'something happened') !== false && strpos($out, 'SECRET') === false && strpos($out, 'Usecret') === false, "exit=$code\n" . $out);
}
else
{
    echo "  skip --status from the command line (exec() is disabled on this PHP)\n";
}

/* ------------------------------------------------------------------ */
echo "Telegram and Discord\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$calls = array();
$answer = array();   // service => list of array(status, body) to answer in turn; nothing listed = accepted
$slept = array();
$net = function ($url, $headers, $body, $method = 'POST') use (&$calls, &$answer, &$box) {
    $svc = strpos($url, '/sendMessage') !== false ? 'telegram' : (strpos($url, '/api/webhooks/') !== false ? 'discord' : 'line');
    if ($svc === 'line' && $method === 'GET') { return fake_quota($url, $box); }
    $calls[] = array('svc' => $svc, 'url' => $url, 'body' => json_decode($body, true));
    if (!empty($answer[$svc])) { $next = array_shift($answer[$svc]); if ($next === 'throw') { throw new RuntimeException('boom at ' . $url); } return $next; }
    return $svc === 'telegram' ? array(200, '{"ok":true,"result":{"message_id":1}}') : ($svc === 'discord' ? array(204, '') : array(200, '{}'));
};
$via = function ($svc) use (&$calls) { return array_values(array_filter($calls, function ($c) use ($svc) { return $c['svc'] === $svc; })); };
$order = function () use (&$calls) { return implode(',', array_map(function ($c) { return $c['svc']; }, $calls)); };
$units = function ($s) { return preg_match_all('/./us', $s) + preg_match_all('/[\x{10000}-\x{10FFFF}]/u', $s); };
$tg = array('telegram_bot_token' => '123456:TG-SECRET-abc', 'telegram_chat_id' => '-100777', 'telegram_api_base' => 'https://tg.example');
$dc = array('discord_webhook_url' => 'https://discord.example/api/webhooks/1/DC-SECRET-xyz');
$noLine = array('line_channel_access_token' => '', 'mail_to' => '');
$base = array('timezone' => 'UTC', 'transport' => $net, 'sleeper' => function ($s) use (&$slept) { $slept[] = $s; });

$a = make($box, $clock, array_merge($base, $tg, $noLine));
$a->custom('Telegram path', array('file __init__.php and *stars* <b>'), SecurityAlerts::NOTICE, 'tg1');
$r = $a->run();
$t = $via('telegram');
$b = $t ? $t[0]['body'] : array();
check('Telegram only: the alert goes to Telegram', $r['sent'] === 'telegram' && count($t) === 1, json_encode($calls));
check('Telegram: sendMessage to the chat, plain text (no parse_mode), no link preview',
    $t && $t[0]['url'] === 'https://tg.example/bot123456:TG-SECRET-abc/sendMessage'
    && $b['chat_id'] === '-100777' && strpos($b['text'], 'file __init__.php and *stars* <b>') !== false && !isset($b['parse_mode'])
    && $b['link_preview_options'] === array('is_disabled' => true), json_encode($b));

$calls = array();
$a = make($box, $clock, array_merge($base, $dc, $noLine));
$a->custom('Discord path', array('account "@everyone" tried [reset](https://evil.example) ``` and __x__'), SecurityAlerts::NOTICE, 'dc1');
$r = $a->run();
$d = $via('discord');
$c = $d ? $d[0]['body'] : array();
check('Discord only: the alert goes to the webhook; 204 (no body) counts as delivered', $r['sent'] === 'discord' && count($d) === 1 && $d[0]['url'] === $dc['discord_webhook_url'], json_encode($calls));
check('Discord: mentions switched off, no link previews, the text in one code block that a name cannot close early',
    isset($c['allowed_mentions']) && $c['allowed_mentions'] === array('parse' => array()) && $c['flags'] === 4
    && strpos($c['content'], "```\n") === 0 && substr($c['content'], -4) === "\n```" && substr_count($c['content'], '```') === 2
    && strpos($c['content'], '@everyone') !== false && strpos($c['content'], '[reset](https://evil.example)') !== false, json_encode($c));

$calls = array();
$a = make($box, $clock, array_merge($base, $tg, $dc));   // plus LINE and e-mail from make()
$a->custom('order', array('one'), SecurityAlerts::URGENT, 'or1');
$r = $a->run();
check('everything set up: Telegram goes first and nobody else is bothered', $r['sent'] === 'telegram' && $order() === 'telegram' && count($box['mail']) === 0, $order());
$answer['telegram'] = array(array(500, '{"ok":false,"error_code":500,"description":"Internal Server Error"}'));
$a->custom('order', array('two'), SecurityAlerts::NOTICE, 'or2');
$clock += 300; $calls = array(); $r = $a->run();
check('Telegram answers 500: Discord takes it', $r['sent'] === 'discord' && $order() === 'telegram,discord', $order());
$answer = array('telegram' => array(array(401, '{"ok":false,"error_code":401,"description":"Unauthorized"}')), 'discord' => array(array(404, '{"message":"Unknown Webhook","code":10015}')));
$a->custom('order', array('three'), SecurityAlerts::NOTICE, 'or3');
$clock += 300; $calls = array(); $r = $a->run();
check('Telegram and Discord refuse: LINE takes it', $r['sent'] === 'line' && $order() === 'telegram,discord,line', $order());
$answer = array('telegram' => array(array(0, '')), 'discord' => array('throw'), 'line' => array(array(429, '{"message":"You have reached your monthly limit."}')));
$a->custom('order', array('four'), SecurityAlerts::NOTICE, 'or4');
$clock += 300; $calls = array(); $r = $a->run();
check('no answer, an exception, LINE out of messages: e-mail takes it', $r['sent'] === 'mail' && $order() === 'telegram,discord,line' && count($box['mail']) === 1, $order());
$answer = array('telegram' => array(array(200, '{"ok":false,"error_code":400,"description":"Bad Request"}')));
$a->custom('order', array('five'), SecurityAlerts::NOTICE, 'or5');
$clock += 300; $calls = array(); $r = $a->run();
check('Telegram saying {"ok":false} is not taken as delivered', $r['sent'] === 'discord', $order());

$got = 0;
$calls = array();
$a = make($box, $clock, array_merge($base, $tg, array('notifier' => function ($text, $level) use (&$got) { $got++; return false; })));
$a->custom('notifier first', array('x'), SecurityAlerts::NOTICE, 'nf');
$r = $a->run();
check('your own notifier still comes first; when it says no, Telegram is next', $got === 1 && $r['sent'] === 'telegram' && $order() === 'telegram');

$calls = array(); $slept = array();
$answer = array('telegram' => array(array(429, '{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 2","parameters":{"retry_after":2}}')));
$a = make($box, $clock, array_merge($base, $tg));
$a->custom('rate', array('x'), SecurityAlerts::NOTICE, 'rl1');
$r = $a->run();
check('Telegram 429 with a short wait: waits as asked, tries once more, delivered', $r['sent'] === 'telegram' && $slept === array(2.0) && $order() === 'telegram,telegram', json_encode($slept) . ' ' . $order());
$calls = array(); $slept = array();
$answer = array('discord' => array(array(429, '{"message":"You are being rate limited.","retry_after":0.25,"global":false}')));
$a = make($box, $clock, array_merge($base, $dc));
$a->custom('rate', array('x'), SecurityAlerts::NOTICE, 'rl2');
$r = $a->run();
check('Discord 429 (retry_after in fractions of a second): same', $r['sent'] === 'discord' && $slept === array(0.25) && $order() === 'discord,discord', json_encode($slept) . ' ' . $order());
$calls = array(); $slept = array();
$answer = array('telegram' => array(array(429, '{"ok":false,"error_code":429,"parameters":{"retry_after":30}}')));
$a = make($box, $clock, array_merge($base, $tg));
$a->custom('rate', array('x'), SecurityAlerts::NOTICE, 'rl3');
$r = $a->run();
check('a long wait (30 s) is not sat out: the next channel takes it at once', $r['sent'] === 'line' && $slept === array() && $order() === 'telegram,line', json_encode($slept) . ' ' . $order());
$calls = array(); $slept = array();
$answer = array('telegram' => array(array(429, '{"ok":false,"parameters":{"retry_after":1}}'), array(429, '{"ok":false,"parameters":{"retry_after":1}}')));
$a = make($box, $clock, array_merge($base, $tg));
$a->custom('rate', array('x'), SecurityAlerts::NOTICE, 'rl4');
$r = $a->run();
check('still 429 after the one retry: the next channel takes it (no endless waiting)', $r['sent'] === 'line' && count($slept) === 1 && $order() === 'telegram,telegram,line', $order());

$full = '';
$calls = array();
$a = make($box, $clock, array_merge($base, $tg, $noLine, array('language' => 'zh-TW', 'notifier' => function ($text) use (&$full) { $full = $text; return false; })));
for ($i = 0; $i < 12; $i++) { $a->custom('長訊息 ' . $i, array_fill(0, 8, '🔒' . str_repeat('後台帳號變動', 10) . ' ' . $i), SecurityAlerts::URGENT, 'long' . $i); }
$r = $a->run();
$t = $via('telegram');
$joined = implode("\n", array_map(function ($c) { return preg_replace('/^\(\d\/\d\) /', '', $c['body']['text']); }, $t));
$sizes = array_map(function ($c) use ($units) { return $units($c['body']['text']); }, $t);
check('Telegram: a message over 4096 characters (emoji count twice) goes in numbered parts, each within the limit, nothing lost',
    $r['sent'] === 'telegram' && count($t) === 2 && max($sizes) <= 4096 && $units($full) > 4096 && $joined === $full
    && strpos($t[0]['body']['text'], '(1/2) ') === 0 && strpos($t[1]['body']['text'], '(2/2) ') === 0 && preg_match('//u', $t[1]['body']['text']) === 1,
    'parts=' . count($t) . ' sizes=' . json_encode($sizes) . ' full=' . $units($full));
$calls = array();
$a = make($box, $clock, array_merge($base, $dc, $noLine, array('language' => 'zh-TW', 'notifier' => function ($text) use (&$full) { $full = $text; return false; })));
for ($i = 0; $i < 12; $i++) { $a->custom('長訊息 ' . $i, array_fill(0, 8, '🔒' . str_repeat('後台帳號變動', 10) . ' ' . $i), SecurityAlerts::URGENT, 'long' . $i); }
$r = $a->run();
$d = $via('discord');
$inner = array_map(function ($c) { return substr($c['body']['content'], 4, -4); }, $d);
$joined = implode("\n", array_map(function ($s) { return preg_replace('/^\(\d\/\d\) /', '', $s); }, $inner));
$sizes = array_map(function ($c) use ($units) { return $units($c['body']['content']); }, $d);
$closed = count(array_filter($d, function ($c) { return strpos($c['body']['content'], "```\n(") === 0 && substr($c['body']['content'], -4) === "\n```"; }));
check('Discord: over 2000 characters goes in parts, each its own closed code block within the limit, nothing lost',
    $r['sent'] === 'discord' && count($d) === 3 && max($sizes) <= 2000 && $closed === 3 && $joined === $full,
    'parts=' . count($d) . ' sizes=' . json_encode($sizes));
$calls = array();
$a = make($box, $clock, array_merge($base, $dc, $noLine));
$a->custom('one enormous line', array(str_repeat('x', 4500)), SecurityAlerts::NOTICE, 'huge');
$r = $a->run();
$sizes = array_map(function ($c) use ($units) { return $units($c['body']['content']); }, $via('discord'));
check('a single line longer than a whole message is cut into pieces too', $r['sent'] === 'discord' && count($sizes) === 3 && max($sizes) <= 2000, json_encode($sizes));

/* line_min_level: keep LINE for what matters */
$calls = array();
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array_merge($base, $tg, array('line_min_level' => 2)));
$box['quota'] = array(37, 200);
$a->custom('just a notice', array('x'), SecurityAlerts::NOTICE, 'm1');
$r = $a->run();
check('line_min_level 2: a notice goes to Telegram, LINE is not touched', $r['sent'] === 'telegram' && $order() === 'telegram', $order());
$a->custom('urgent one', array('x'), SecurityAlerts::URGENT, 'm2');
$clock += 300; $calls = array(); $r = $a->run();
check('line_min_level 2: an URGENT alert goes to LINE first', $r['sent'] === 'line' && $order() === 'line', $order());
$answer = array('line' => array(array(429, '{"message":"You have reached your monthly limit."}')));
$a->custom('urgent two', array('x'), SecurityAlerts::URGENT, 'm3');
$clock += 300; $calls = array(); $r = $a->run();
check('line_min_level 2: LINE refuses an urgent one, Telegram still takes it', $r['sent'] === 'telegram' && $order() === 'line,telegram', $order());
$clock = strtotime('2026-03-09 10:00:00 UTC'); $calls = array(); $r = $a->run();
$t = $via('telegram');
check('line_min_level 2: the weekly check-in goes to Telegram and still shows LINE\'s allowance (LINE is kept for urgent ones)',
    $r['heartbeat'] === 'telegram' && $order() === 'telegram' && strpos($t[0]['body']['text'], 'LINE messages this month: about 37 of 200 used.') !== false,
    $r['heartbeat'] . ' ' . $order());
$s = $a->status();
check('status(): the route for each kind of message', $s['delivery']['route'] === array('urgent' => array('line', 'telegram', 'mail'),
    'notice' => array('telegram', 'mail'), 'checkin' => array('telegram', 'mail')) && $s['delivery']['telegram'] && $s['delivery']['telegram_chats'] === 1
    && $s['delivery']['line_min_level'] === 2 && !array_filter($s['problems'], function ($p) { return strpos($p, 'line_min_level') !== false || strpos($p, 'refuses') !== false; }),
    json_encode($s['delivery']) . json_encode($s['problems']));

$calls = array();
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array_merge($base, array('line_min_level' => 1)));   // LINE and e-mail only
$a->custom('a notice', array('x'), SecurityAlerts::NOTICE, 'n1');
$r = $a->run();
check('line_min_level 1: alerts still go to LINE', $r['sent'] === 'line');
$clock = strtotime('2026-03-09 10:00:00 UTC'); $calls = array(); $r = $a->run();
check('line_min_level 1: the "all is well" check-in goes by e-mail instead', $r['heartbeat'] === 'mail' && $order() === '' && count($box['mail']) === 1, $r['heartbeat'] . ' ' . $order());

$calls = array();
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array_merge($base, array('line_min_level' => 2, 'mail_to' => '')));   // LINE only
$a->custom('a notice', array('x'), SecurityAlerts::NOTICE, 'o1');
$r = $a->run();
$s = $a->status();
check('line_min_level 2 with nothing else set up: still LINE (better than nowhere), and status() says so', $r['sent'] === 'line'
    && count(array_filter($s['problems'], function ($p) { return strpos($p, 'line_min_level is 2, but no other channel is set up') !== false; })) === 1, json_encode($s['problems']));
$a = make($box, $clock, array_merge($base, $tg, $noLine, array('line_min_level' => 2)));
$s = $a->status();
check('line_min_level without LINE: status() says the setting does nothing', count(array_filter($s['problems'], function ($p) { return strpos($p, 'LINE is not set up: urgent alerts go to Telegram') !== false; })) === 1
    && count(array_filter($s['problems'], function ($p) { return strpos($p, 'when Telegram refuses') !== false; })) === 1, json_encode($s['problems']));

/* LINE's allowance only when LINE is really in use */
$calls = array();
unset($box['gets']);
$clock = strtotime('2026-03-02 10:00:00 UTC');
$a = make($box, $clock, array_merge($base, $tg));   // Telegram first, LINE as a backup
$box['quota'] = array(150, 200);
$a->run();
$clock = strtotime('2026-03-09 10:00:00 UTC'); $calls = array(); $r = $a->run();
$t = $via('telegram');
check('LINE only as a backup that sent nothing: no LINE line in the check-in, LINE is not even asked',
    $r['heartbeat'] === 'telegram' && strpos($t[0]['body']['text'], 'LINE messages') === false && !isset($box['gets']), json_encode($t));
$answer = array('telegram' => array(array(500, '')));
$a->custom('carried by LINE', array('x'), SecurityAlerts::NOTICE, 'bk1');
$clock += 300; $r = $a->run();
$clock = strtotime('2026-03-16 10:00:00 UTC'); $calls = array(); $r = $a->run();
$t = $via('telegram');
check('…but once the backup had to carry an alert, the next check-in shows LINE\'s allowance',
    $r['heartbeat'] === 'telegram' && strpos($t[0]['body']['text'], 'LINE messages this month: about 150 of 200 used.') !== false, json_encode($t));

$calls = array();
$a = make($box, $clock, array_merge($base, $tg, array('daily_cap' => 1)));
$a->custom('first', array('x'), SecurityAlerts::NOTICE, 'cap1');
$clock += 60; $a->run();
$a->custom('second', array('x'), SecurityAlerts::NOTICE, 'cap2');
$clock += 60; $r = $a->run();
check('messages on Telegram count towards daily_cap like LINE ones', $r['sent'] === 'capped' && count($via('telegram')) === 1, $order());

$calls = array();
$answer = array('discord' => array(array(404, '{"message":"Unknown Webhook","code":10015}')),
    'telegram' => array(array(400, '{"ok":false,"error_code":400,"description":"Bad Request: chat not found for 123456:TG-SECRET-abc"}')));
$a = make($box, $clock, array_merge($base, $tg, $dc));
$each = $a->testEachChannel();
check('testEachChannel(): every channel tried on its own, with the reason when it fails, and no key in the reason',
    array_keys($each) === array('telegram', 'discord', 'line', 'mail') && !$each['telegram']['ok'] && strpos($each['telegram']['why'], 'HTTP 400: Bad Request: chat not found') === 0
    && strpos($each['telegram']['why'], 'TG-SECRET') === false && $each['discord'] === array('ok' => false, 'why' => 'HTTP 404: Unknown Webhook')
    && $each['line']['ok'] && $each['mail']['ok'] && $order() === 'telegram,discord,line', json_encode($each));
$calls = array();
$a = make($box, $clock, array_merge($base, $tg, $noLine, array('telegram_bot_token' => 'not a token/../x')));
$each = $a->testEachChannel();
check('a Telegram token that is not in the BotFather form is not sent anywhere', !$each['telegram']['ok'] && strpos($each['telegram']['why'], 'BotFather') !== false && $order() === '', json_encode($each));
$calls = array();
$a = make($box, $clock, array_merge($base, $tg, $noLine, array('telegram_chat_id' => array('-1', '-2'))));
$answer = array('telegram' => array(array(400, '{"ok":false,"description":"Bad Request: chat not found"}')));
$a->custom('two chats', array('x'), SecurityAlerts::NOTICE, 'two');
$r = $a->run();
check('two Telegram chats, one wrong: still delivered to the other', $r['sent'] === 'telegram' && count($via('telegram')) === 2);

$secretsDir = tmpdir('state-secrets');
$a = make($box, $clock, array_merge($base, $tg, $dc, array('state_dir' => $secretsDir)));
$answer = array('telegram' => array(array(500, '')), 'discord' => array(array(500, '')), 'line' => array(array(500, '')));
$a->custom('cannot go out', array('x'), SecurityAlerts::URGENT, 'sec1');
$a->run();
$a->custom('goes out', array('x'), SecurityAlerts::URGENT, 'sec2');
$clock += 300; $a->run();
$all = '';
foreach (glob($secretsDir . '/*') as $f) { $all .= (string) file_get_contents($f); }
$s = json_encode($a->status());
check('no Telegram token or Discord address in the records or in status()', $all !== '' && strpos($all . $s, 'TG-SECRET') === false && strpos($all . $s, 'DC-SECRET') === false
    && strpos($s, '-100777') === false);
$answer = array();

if (function_exists('exec'))
{
    $app3 = tmpdir('app3');
    mkdir($app3 . '/lib', 0700, true);
    mkdir($app3 . '/bin', 0700, true);
    copy(__DIR__ . '/../lib/SecurityAlerts.php', $app3 . '/lib/SecurityAlerts.php');
    copy(__DIR__ . '/../examples/security-alerts-cron.php', $app3 . '/bin/security-alerts-cron.php');
    file_put_contents($app3 . '/bin/security-alerts.config.php', '<?php return ' . var_export(array(
        'state_dir' => tmpdir('state-cron3'), 'site_name' => 'Route shop', 'timezone' => 'UTC', 'line_min_level' => 2,
        'line_channel_access_token' => 'TOKEN-SECRET-9f2c', 'line_to' => array('Usecret0123456789'),
        'telegram_bot_token' => '123456:TG-SECRET-abc', 'telegram_chat_id' => '-100777', 'discord_webhook_url' => 'https://discord.example/api/webhooks/1/DC-SECRET-xyz',
    ), true) . ";\n");
    $lines = array();
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($app3 . '/bin/security-alerts-cron.php') . ' --status', $lines, $code);
    $out = implode("\n", $lines);
    check('cron entry --status: the route in plain words (urgent ones on LINE first), no keys or ids',
        strpos($out, 'alerts go to      : Telegram (1 chat), then Discord (1 webhook)  (no e-mail fallback)') !== false
        && strpos($out, 'urgent ones       : LINE (1 recipient), then Telegram (1 chat), then Discord (1 webhook)  (line_min_level 2)') !== false
        && strpos($out, 'SECRET') === false && strpos($out, 'Usecret') === false && strpos($out, '-100777') === false, $out);
}

/* ------------------------------------------------------------------ */
echo "Announced updates (--expect)\n";
$clock = strtotime('2026-03-02 10:00:00 UTC');
$site = tmpdir('site');
mkdir($site . '/uploads', 0700, true);
mkdir($site . '/lib', 0700, true);
file_put_contents($site . '/index.php', "<?php echo 'v1';\n");
file_put_contents($site . '/about.php', "<?php echo 'about';\n");
$sd = tmpdir('state');
$xcfg = array('timezone' => 'UTC', 'site_root' => $site, 'state_dir' => $sd, 'scan_hours' => 0, 'heartbeat_days' => 0);
$a = make($box, $clock, $xcfg);
$a->run();   // baseline
file_put_contents($site . '/before.php', "<?php // changed before the announcement\n");
$clock += 600;
$e = $a->expectChanges(30);
check('announcing first runs every check: a change made BEFORE the announcement is reported as usual', $e['ok'] && $e['until'] === $clock + 1800
    && is_array($e['run']) && count($box['line']) === 1 && strpos($box['line'][0], 'before.php') !== false, json_encode(array($e, $box['line'])));
file_put_contents($site . '/lib/new.php', "<?php // part of the update\n");
file_put_contents($site . '/index.php', "<?php echo 'v2';\n");
unlink($site . '/about.php');
$clock += 300; $r = $a->run();
check('inside the window: ordinary changes are not reported one by one', count($box['line']) === 1 && $r['file_scan'] === 'complete', json_encode($box['line']));
file_put_contents($site . '/uploads/avatar.jpg.php', "<?php echo 1;\n");
file_put_contents($site . '/lib/helper.php', bait("<?php \$~_GET['f'](\$~_POST['a']);\n"));
$clock += 300; $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('...but a program in an upload folder and backdoor-like content are URGENT at once, window or not', count($box['line']) === 2
    && strpos($m, 'URGENT') !== false && strpos($m, 'avatar.jpg.php') !== false && strpos($m, 'helper.php') !== false && strpos($m, 'lib/new.php') === false, $m);
$s = $a->status();
check('status() shows the open window and what it collected so far', $s['expect'] !== null && $s['expect']['open']
    && $s['expect']['new'] === 1 && $s['expect']['changed'] === 1 && $s['expect']['deleted'] === 1, json_encode($s['expect']));
$clock += 1500;   // 35 minutes after the announcement: the 30-minute window is over
$a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('after the window: ONE message sums the update up, with the file names, as a Notice', count($box['line']) === 3
    && strpos($m, 'Code changes during your announced update') !== false && strpos($m, '1 new, 1 changed, 1 deleted') !== false
    && strpos($m, 'lib/new.php') !== false && strpos($m, 'index.php') !== false && strpos($m, 'about.php') !== false
    && strpos($m, 'helper.php') === false && strpos($m, 'URGENT') === false && !is_file($sd . '/expect.json'), $m);
file_put_contents($site . '/after.php', "<?php // after the window\n");
$clock += 300; $a->run();
check('after the summary, changes are reported one by one again', count($box['line']) === 4 && strpos($box['line'][3], 'after.php') !== false);
$a->expectChanges(60);
file_put_contents($site . '/lib/new.php', "<?php // part of update 2\n");
file_put_contents($site . '/lib/tmp.php', "<?php // made and removed during the update\n");
$clock += 60; $a->run();
unlink($site . '/lib/tmp.php');
$clock += 60;
$ended = $a->endExpect();
$a->run();
check('--expect off: closes at once, the summary comes with the next run; a file made and removed inside the window cancels out',
    $ended && count($box['line']) === 5 && strpos($box['line'][4], '0 new, 1 changed, 0 deleted') !== false && strpos($box['line'][4], 'tmp.php') === false,
    isset($box['line'][4]) ? $box['line'][4] : '');
$e1 = $a->expectChanges(20);
$clock += 60;
$e2 = $a->expectChanges(60);
check('announcing again while a window is open extends it (no second full check)', $e1['ok'] && $e2['ok'] && $e2['run'] === null && $e2['until'] === $clock + 3600);
$clock += 3700; $a->run();
check('a window in which nothing changed closes quietly (it is only written to the log)', count($box['line']) === 5 && !is_file($sd . '/expect.json'));
file_put_contents($sd . '/expect.json', json_encode(array('from' => $clock, 'until' => $clock + 10 * 365 * 86400, 'files' => array(), 'more' => 0)));
file_put_contents($site . '/sneaky.php', "<?php // planted under a forged window\n");
$clock += 3600; $a->run();
$quiet = count($box['line']) === 5;
$clock += 3 * 3600 + 60; $a->run();
check('a window written by hand "for ten years" still ends after 4 hours, and its summary names the planted file',
    $quiet && count($box['line']) === 6 && strpos($box['line'][5], 'sneaky.php') !== false, json_encode($box['line']));
$e = make($box, $clock)->expectChanges(30);
check('without a file scan there is nothing to announce', !$e['ok'] && strpos($e['why'], 'file scan is off') !== false);

$clock = strtotime('2026-03-02 10:00:00 UTC');
$site2 = tmpdir('site');
file_put_contents($site2 . '/index.php', "<?php echo 1;\n");
$a = make($box, $clock, array('timezone' => 'UTC', 'site_root' => $site2, 'scan_hours' => 0));
$a->run();
$clock += 7 * 86400 - 600;
$a->expectChanges(30);
$clock += 900;   // the weekly check-in is due now, the window is still open
$r1 = $a->run();
$clock += 1200;
$r2 = $a->run();
check('the weekly check-in waits while an update window is open, and goes out once it closed', $r1['heartbeat'] === 'waiting for the update window' && $r2['heartbeat'] === 'line',
    $r1['heartbeat'] . ' / ' . $r2['heartbeat']);

/* ------------------------------------------------------------------ */
echo "The LINE key on the server, and how many people it can reach\n";
$clock = strtotime('2026-03-09 10:00:00 UTC');
$a = make($box, $clock, array('timezone' => 'UTC'));
$box['friends'] = array(150, 10);
$n = $a->lineFriendCount();
check('asks LINE about yesterday (Japan time): friends minus those who blocked the account', $n === 140 && $box['friend_gets'] === 1
    && substr($box['friend_urls'][0], -14) === '?date=20260308', json_encode($box));
$s = $a->status();
check('status() remembers it and says that alerts belong in an account of their own', $s['line_friends']['n'] === 140
    && count(preg_grep('/about 140 friends/', $s['problems'])) === 1, json_encode($s['problems']));
$box['friends'] = array(4, 0);
$a->lineFriendCount();
$s = $a->status();
check('a handful of friends (the owner and staff): nothing to say', $s['line_friends']['n'] === 4 && count(preg_grep('/friends/', $s['problems'])) === 0);
unset($box['friends']);
$box['friend_gets'] = 0;
check('"not counted yet" for every day: three days are tried, then no answer', $a->lineFriendCount() === null && $box['friend_gets'] === 3);
$a = make($box, $clock, array('line_friends_warn' => 0));
$box['friends'] = array(500, 0);
check('line_friends_warn = 0: LINE is not asked', $a->lineFriendCount() === null && !isset($box['friend_gets']));
$a = make($box, $clock, array('line_channel_access_token' => ''));
$box['friends'] = array(500, 0);
check('no LINE set up: not asked', $a->lineFriendCount() === null && !isset($box['friend_gets']) && $a->status()['line_friends'] === null);
foreach (array(array(300, 0), array(3, 0)) as $f)
{
    $clock = strtotime('2026-03-02 10:00:00 UTC');
    $a = make($box, $clock, array('timezone' => 'UTC'));
    $box['friends'] = $f;
    $a->run();
    $clock += 7 * 86400;
    $r = $a->run();
    $hb = (string) end($box['line']);
    if ($f[0] === 300)
    {
        check('weekly check-in: an alert account with 300 friends is a warning', $r['heartbeat'] === 'line' && strpos($hb, 'about 300 friends') !== false
            && strpos($hb, 'something to look at') !== false, $hb);
    }
    else
    {
        check('...with 3 friends nothing is said about it', $r['heartbeat'] === 'line' && strpos($hb, 'friends') === false && strpos($hb, 'something to look at') === false, $hb);
    }
}

/* ------------------------------------------------------------------ */
echo "Page watch (a fake site in memory, read the four ways)\n";
function shop_html(array $head = array(), array $body = array())
{
    return '<!doctype html><html><head><title>Shop</title><script src="/js/app.js"></script>'
        . '<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>'
        . '<script>(function(){var s=document.createElement("script");s.src="https:\/\/connect.facebook.net\/en_US\/sdk.js";})();</script>'
        . '<script type="application/ld+json">{"sameAs":["https://instagram.com/shop"]}</script>'
        . implode('', $head) . '</head><body>'
        . '<a href="/about">About</a><a href="https://shop.example/cart">Cart</a><a href="//cdn.shop.example/x.pdf">PDF</a>'
        . '<a href="https://www.shop.example/">Home</a><a href="mailto:hi@shop.example">Mail</a><a href="https://www.facebook.com/shop">FB</a>'
        . '<form action="/search"></form><!-- <script src="https://commented.example/x.js"></script> -->'
        . implode('', $body) . '</body></html>';
}
$web = array();     // address => page html, or function(view) => array(status, body, location)
$reads = array();
$pageNet = function ($url, $headers, $timeout) use (&$web, &$reads) {
    $ua = '';
    $ref = '';
    foreach ($headers as $h)
    {
        if (stripos($h, 'User-Agent: ') === 0) { $ua = substr($h, 12); }
        if (stripos($h, 'Referer: ') === 0) { $ref = substr($h, 9); }
    }
    $view = stripos($ua, 'Googlebot') !== false ? 'crawler' : ($ref !== '' ? 'from_google' : (stripos($ua, 'Mobile') !== false ? 'mobile' : 'browser'));
    $reads[] = array('url' => $url, 'view' => $view, 'ref' => $ref);
    if (!isset($web[$url])) { return array(404, 'not found', ''); }
    if (is_array($web[$url])) { return $web[$url]; }
    return is_callable($web[$url]) ? call_user_func($web[$url], $view) : array(200, $web[$url], '');
};
$U = 'https://shop.example/';
$clock = strtotime('2026-03-02 10:00:00 UTC');
$web[$U] = shop_html();
$sd = tmpdir('state');
$pw = array('timezone' => 'UTC', 'state_dir' => $sd, 'page_watch' => array($U), 'page_transport' => $pageNet, 'heartbeat_days' => 0);
$a = make($box, $clock, $pw);
$r = $a->run();
$rec = json_decode((string) file_get_contents($sd . '/pages.json'), true);
$k = isset($rec[$U]['k']) ? $rec[$U]['k'] : array();
check('first read: the baseline, nothing sent', $r['pages'] === 'read 1 page(s)' && count($box['line']) === 0, json_encode($r));
$views = array_map(function ($x) { return $x['view']; }, $reads);
sort($views);
check('read four ways: desktop, phone, Google\'s crawler, a phone arriving from a Google search', $views === array('browser', 'crawler', 'from_google', 'mobile')
    && count(array_filter($reads, function ($x) { return $x['view'] === 'from_google' && $x['ref'] === 'https://www.google.com/'; })) === 1, json_encode($reads));
check('recorded: outside scripts (also one a script loads), outside links; not this site, its sub-domains, JSON-LD data, comments or mail links',
    isset($k['script']['www.googletagmanager.com'], $k['script']['connect.facebook.net'], $k['link']['www.facebook.com'])
    && !isset($k['script']['instagram.com']) && !isset($k['link']['instagram.com']) && !isset($k['script']['commented.example'])
    && !isset($k['link']['shop.example']) && !isset($k['link']['www.shop.example']) && !isset($k['link']['cdn.shop.example']) && empty($k['form']), json_encode($k));
$clock += 1800; $r = $a->run();
check('read again only after page_watch_hours', $r['pages'] === 'not due' && count($reads) === 4);

$web[$U] = shop_html(array('<script src="https://cdn-evil.example/s.js"></script>', '<script src="data:text/javascript;base64,QUJD"></script>'),
    array('<form action="https://collect.evil.example/p" method="post"><input name="card"></form>'));
$clock += 1800; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('a skimming script and a form that posts elsewhere: URGENT, in words', count($box['line']) === 1 && strpos($m, 'URGENT') !== false
    && strpos($m, 'A page started using another site') !== false && strpos($m, 'home page: runs code from cdn-evil[.]example') !== false
    && strpos($m, 'code written into the page itself') !== false && strpos($m, 'a form now sends what visitors type to collect[.]evil[.]example') !== false, $m);
check('site names are written as name[.]com, so a tap cannot open them', strpos($m, 'cdn-evil.example') === false && strpos($m, 'collect.evil.example') === false);
$clock += 3600; $a->run();
check('the same sites an hour later: not repeated', count($box['line']) === 1);

$skim = array('<script src="https://cdn-evil.example/s.js"></script>', '<script src="data:text/javascript;base64,QUJD"></script>');
$web[$U] = function ($view) use ($skim) {
    if ($view === 'from_google') { return array(302, '', 'https://spam-landing.example/?from=shop'); }
    return array(200, shop_html($skim, $view === 'crawler' ? array('<div style="display:none"><a href="https://casino-spam.example/">x</a></div>') : array()), '');
};
$clock += 3600; $a->run();
$m = isset($box['line'][1]) ? $box['line'][1] : '';
check('links only for the crawler, a redirect only for visitors from Google: URGENT "shown to search engines, not to you"', count($box['line']) === 2
    && strpos($m, 'URGENT') !== false && strpos($m, 'Your pages show search engines something you do not see') !== false
    && strpos($m, 'only search engines get casino-spam[.]example') !== false
    && strpos($m, 'only visitors coming from a Google search get spam-landing[.]example') !== false
    && strpos($m, 'New links to other sites') === false, $m);

$web[$U] = shop_html($skim, array('<a href="https://partner.example/">our partner</a>'));
$clock += 3600; $a->run();
$m = isset($box['line'][2]) ? $box['line'][2] : '';
check('an ordinary new link that everybody sees: a Notice', count($box['line']) === 3 && strpos($m, 'New links to other sites on your pages') !== false
    && strpos($m, 'partner[.]example') !== false && strpos($m, 'URGENT') === false, $m);

$a = make($box, $clock, array_merge($pw, array('page_links' => false, 'page_allow' => array('newwidget.example'))));
$web[$U] = function ($view) use ($skim) {
    $head = array_merge($skim, array('<script src="https://cdn.newwidget.example/w.js"></script>'));
    if ($view !== 'browser') { $head[] = '<script src="https://m-chat.example/c.js"></script>'; }   // a chat box in the phone layout only
    return array(200, shop_html($head, array('<a href="https://partner2.example/">p2</a>')), '');
};
$clock += 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('page_allow: a site you use on purpose is not reported; page_links = false: new links are not either', count($box['line']) === 1
    && strpos($m, 'newwidget') === false && strpos($m, 'partner2') === false, $m);
check('a script in the phone layout only is a new script, not "hidden from you" (the phone view has it)',
    strpos($m, 'runs code from m-chat[.]example') !== false && strpos($m, 'only search engines') === false, $m);

$sd2 = tmpdir('state');
$web['https://shop.example/old'] = array(301, '', '/new');
$web['https://shop.example/new'] = shop_html();
$reads = array();
$a = make($box, $clock, array_merge($pw, array('state_dir' => $sd2, 'page_watch' => array('https://shop.example/old'))));
$a->run();
check('a redirect within the site is followed', count($reads) === 8 && $reads[1]['url'] === 'https://shop.example/new'
    && count($box['line']) === 0, json_encode($reads));
$web['https://shop.example/new'] = array(302, '', 'https://evil-redirect.example/x');
$clock += 3600; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
check('...a redirect to another site is not: it is reported', strpos($m, '/old: sends visitors on to evil-redirect[.]example') !== false, $m);

$sd3 = tmpdir('state');
$web['https://shop.example/x'] = function ($view) { return $view === 'crawler' ? array(403, 'fake bot', '') : array(200, shop_html(), ''); };
$web['https://shop.example/down'] = array(503, '', '');
$a = make($box, $clock, array_merge($pw, array('state_dir' => $sd3, 'page_watch' => array('https://shop.example/x', 'https://shop.example/down'))));
for ($i = 0; $i < 3; $i++) { $a->run(); $clock += 3600; }
$p = implode("\n", $a->status()['problems']);
check('pages that cannot be read: no alert (watching uptime is another service\'s job), but status() says so', count($box['line']) === 0
    && strpos($p, 'page /down: the browser view could not be read 3 times in a row (HTTP 503)') !== false
    && strpos($p, 'page /x: the crawler view could not be read 3 times in a row (HTTP 403); a firewall that blocks fake search-engine visits') !== false, $p);

$web[$U] = function ($view) use ($skim) {
    if ($view === 'from_google') { return array(302, '', 'https://spam-landing.example/?from=shop'); }
    return array(200, shop_html($skim, $view === 'crawler' ? array('<a href="https://casino-spam.example/">x</a>') : array()), '');
};
$before = (string) file_get_contents($sd . '/pages.json');
$a = make($box, $clock, $pw);
$now = $a->pagesNow();
$o = isset($now[$U]) ? $now[$U] : array();
check('pagesNow() (--pages) lists what only the crawler and Google visitors get, and saves nothing',
    isset($o['only_bots']['link'], $o['only_bots']['redirect']) && $o['only_bots']['link'] === array('casino-spam.example')
    && $o['only_bots']['redirect'] === array('spam-landing.example') && in_array('cdn-evil.example', $o['outside']['script'], true)
    && (string) file_get_contents($sd . '/pages.json') === $before && count($box['line']) === 0, json_encode($o));

$web['https://shop.example/tricks'] = '<html><body>'
    . '<a href="https://shop.example@evil-at.example/">1</a><a href="java&#x09;script:alert(1)">2</a><a href=" HTTPS:\\\\back.example\\x">3</a>'
    . '<A HREF=\'https://upper.example/\'>4</A><a href=https://unquoted.example/x>5</a><a href="tel:123">6</a>'
    . '<iframe src="//frame.example/"></iframe><object data="https://obj.example/o"></object>'
    . '<link rel="modulepreload" href="https://mod.example/m.js"><link rel="stylesheet" href="https://css.example/s.css">'
    . '<button formaction="https://fa.example/x">go</button><meta http-equiv="refresh" content="5; url=https://meta-redirect.example/">'
    . '</body></html>';
$a = make($box, $clock, array_merge($pw, array('state_dir' => tmpdir('state'), 'page_watch' => array('https://shop.example/tricks'))));
$now = $a->pagesNow();
$v = isset($now['https://shop.example/tricks']['views']['browser']) ? $now['https://shop.example/tricks']['views']['browser'] : array();
check('addresses read the way a browser reads them ("user@", tabs, backslashes, upper case, no quotes)',
    isset($v['link']) && $v['link'] === array('back.example', 'evil-at.example', 'unquoted.example', 'upper.example'), json_encode($v));
check('frames, objects, module scripts, form buttons and meta refresh each land in their category; style sheets are not counted',
    $v['frame'] === array('frame.example', 'obj.example') && $v['script'] === array('mod.example') && $v['form'] === array('fa.example')
    && $v['redirect'] === array('meta-redirect.example'), json_encode($v));

$web['https://shop.example/big'] = '<html><head><script>var cfg = "' . str_repeat('x', 1200000) . '";</script>'
    . '<script src="https://after-big.example/x.js"></script><style>a{}</style></head><body><a href="https://link-after.example/">a</a><!-- unclosed comment';
$a = make($box, $clock, array_merge($pw, array('state_dir' => tmpdir('state'), 'page_watch' => array('https://shop.example/big'))));
$now = $a->pagesNow();
$v = isset($now['https://shop.example/big']['views']['browser']) ? $now['https://shop.example/big']['views']['browser'] : array();
check('a 1.2 MB inline script does not hide what comes after it', isset($v['script'], $v['link']) && $v['script'] === array('after-big.example')
    && $v['link'] === array('link-after.example'), json_encode($v));

unlink($sd . '/pages.json');
$web[$U] = shop_html($skim);
$a = make($box, $clock, $pw);
$clock += 3600; $a->run();
check('page records deleted behind our back: said once, then read afresh', count($box['line']) === 1
    && strpos($box['line'][0], 'The page-watch records have disappeared') !== false && is_file($sd . '/pages.json'), json_encode($box['line']));
$a = make($box, $clock, array('page_watch' => array()));
check('no page_watch: no page is read', $a->run()['pages'] === 'off');

$zh = make($box, $clock, array('language' => 'zh-TW'));
$en = make($box, $clock);
$tm = new ReflectionMethod('SecurityAlerts', 't');
if (PHP_VERSION_ID < 80100) { $tm->setAccessible(true); }
$missing = array();
foreach (array('hb_friends', 'exp_title', 'exp_opened', 'exp_window', 'exp_none', 'exp_hint', 'page_home', 'page_code_title', 'page_new_script',
    'page_new_frame', 'page_new_form', 'page_new_redirect', 'page_code_hint', 'page_hidden_title', 'page_hidden_line', 'page_who_c', 'page_who_g',
    'page_who_cg', 'page_hidden_hint', 'page_links_title', 'page_links_hint', 'page_more', 'page_and_more', 'page_data_url', 'page_lost_title', 'page_lost_body',
    'brake_line', 'brake_title', 'brake_confirm', 'brake_button', 'brake_already', 'brake_done', 'brake_expired', 'brake_used', 'brake_used_open',
    'brake_locked_title', 'brake_locked_link', 'brake_locked_cmd', 'brake_locked_hint', 'brake_unlocked_title', 'brake_unlocked_body') as $key)
{
    if ($tm->invoke($zh, $key) === $tm->invoke($en, $key) || $tm->invoke($en, $key) === $key) { $missing[] = $key; }
}
check('every new message exists in English and in Chinese', $missing === array(), implode(' ', $missing));

/* ------------------------------------------------------------------ */
echo "Emergency brake\n";
$clock = strtotime('2026-03-02 03:00:00 UTC');
$brake = array('timezone' => 'UTC', 'site_name' => 'Shop <b>&', 'brake_url' => 'https://shop.example/brake.php', 'brake_secret' => str_repeat('k7', 20));
$a = make($box, $clock, $brake);
$a->custom('Something bad', array('x'), SecurityAlerts::URGENT, 'b1');
$a->custom('Something minor', array('y'), SecurityAlerts::NOTICE, 'b2');
$clock += 60; $a->run();
$m = isset($box['line'][0]) ? $box['line'][0] : '';
$link = preg_match('#(https://shop\.example/brake\.php\?t=([0-9]+\.[0-9a-f]{16}\.[0-9a-f]{32}))$#', $m, $lm) ? $lm[2] : '';
check('an URGENT message ends with the brake link (signed token, on the site\'s own address)', $link !== '' && strpos($m, 'Lock the admin area for 4 hours') !== false, $m);
$a->custom('Only a notice', array('z'), SecurityAlerts::NOTICE, 'b3');
$clock += 60; $a->run();
check('...a Notice-only message does not', isset($box['line'][1]) && strpos($box['line'][1], 'brake.php') === false);
$g = $a->brakeRequest('GET', $link, '198.51.100.7');
check('opening the link (as a chat app does for its preview) only shows the button; nothing is locked', $g['status'] === 200 && !$g['locked']
    && strpos($g['html'], '<form method="post">') !== false && !$a->adminLocked() && strpos($g['html'], 'Shop &lt;b&gt;&amp;') !== false, $g['html']);
$p = $a->brakeRequest('POST', $link, '198.51.100.7');
check('pressing the button locks the admin area for brake_hours', $p['status'] === 200 && $p['locked'] && $a->adminLocked()
    && $a->adminLockedUntil() === $clock + 4 * 3600, $p['html']);
$u = $a->brakeRequest('POST', $link, '198.51.100.7');
check('the same link a second time: "already used" (a link works once)', $u['status'] === 409 && strpos($u['html'], 'already been used') !== false);
$before = count($box['line']);
$clock += 60; $a->run();
$m = (string) end($box['line']);
check('the lock is announced on the next run (URGENT, with the time and the IP the button was pressed from)', count($box['line']) === $before + 1
    && strpos($m, 'The admin area is locked') !== false && strpos($m, '198.51.100.7') !== false && strpos($m, 'URGENT') !== false, $m);
$parts = explode('.', $link);
$forged = $parts[0] . '.' . $parts[1] . '.' . str_repeat('0', 32);
$a = make($box, $clock, $brake);
check('a forged or mangled token: a plain "not found", nothing locked', $a->brakeRequest('POST', $forged)['status'] === 404
    && $a->brakeRequest('GET', 'x')['status'] === 404 && $a->brakeRequest('POST', $link . 'a')['status'] === 404 && !$a->adminLocked());
check('a link signed with another secret: not found', make($box, $clock, array_merge($brake, array('brake_secret' => str_repeat('z9', 20))))->brakeRequest('POST', $link)['status'] === 404);
$clock += 25 * 3600;
$x = $a->brakeRequest('POST', $link);
check('a link older than brake_link_hours: "expired", nothing locked', $x['status'] === 410 && !$a->adminLocked());
$a = make($box, $clock, array_merge($brake, array('brake_secret' => 'short')));
$a->custom('Bad', array('x'), SecurityAlerts::URGENT, 'b9');
$clock += 60; $a->run();
check('a secret shorter than 32 characters: no link in messages, status() says why, the page answers "not found"',
    isset($box['line'][0]) && strpos($box['line'][0], 'brake.php') === false && $a->brakeRequest('GET', $link)['status'] === 404
    && count(preg_grep('/brake_secret is missing or shorter/', $a->status()['problems'])) === 1);
$a = make($box, $clock, array_merge($brake, array('brake_allow_ips' => array('203.0.113.9'))));
$until = $a->lockAdmin(2, 'command');
check('--lock (lockAdmin): locked for the hours asked; an allowed IP is not locked out', $until === $clock + 7200 && $a->adminLocked('198.51.100.1')
    && !$a->adminLocked('203.0.113.9') && count(preg_grep('/the admin area is LOCKED/', $a->status()['problems'])) === 1);
$clock += 2 * 3600 + 1;
check('the lock ends by itself at its time', !$a->adminLocked() && $a->adminLockedUntil() === null);
$a->lockAdmin(1, 'command');
check('--unlock (unlockAdmin) ends it early, and says so on the next run', $a->unlockAdmin() && !$a->adminLocked() && !$a->unlockAdmin());
$clock += 60; $a->run();
check('...the run after it tells of both the lock and the unlock', count($box['line']) === 1 && strpos($box['line'][0], 'The admin area is locked') !== false
    && strpos($box['line'][0], 'The admin area is unlocked') !== false, json_encode($box['line']));
$calls = array();
$a = make($box, $clock, array_merge($brake, $base, $dc, $noLine));
$a->custom('Discord urgent', array('x'), SecurityAlerts::URGENT, 'bd');
$clock += 60; $a->run();
$d = $via('discord');
$c = $d ? (string) $d[0]['body']['content'] : '';
check('on Discord the link comes after the code box, so it can be tapped', preg_match('/```\n\x{1F6D1} [^\n]*https:\/\/shop\.example\/brake\.php\?t=\S+$/u', $c) === 1
    && substr_count($c, '```') === 2, $c);
$calls = array();
$a = make($box, $clock, array_merge($brake, $base, $tg, $noLine));
$answer = array('telegram' => array(array(500, '{"ok":false,"description":"down"}')));
$a->custom('Late urgent', array('x'), SecurityAlerts::URGENT, 'bl');
$clock += 60; $a->run();
$first = $via('telegram');
$old = $first ? $first[0]['body']['text'] : '';
$clock += 30 * 3600; $a->run();
$t = $via('telegram');
$new = count($t) > 1 ? $t[count($t) - 1]['body']['text'] : '';
preg_match('/t=([0-9]+)\./', $old, $o1);
preg_match('/t=([0-9]+)\./', $new, $o2);
check('a delayed URGENT alert carries a fresh link (the kept one would have expired)', strpos($new, 'Delayed') !== false && substr_count($new, 'brake.php') === 1
    && isset($o1[1], $o2[1]) && (int) $o2[1] > (int) $o1[1], $new);

/* ------------------------------------------------------------------ */
echo "Daily cap, urgent bypass, fallback\n";
$clock = $T0;
$a = make($box, $clock, array('daily_cap' => 1));
$a->custom('first', array('one'), SecurityAlerts::NOTICE, 'k1');
$clock += 60; $a->run();
$a->custom('second', array('two'), SecurityAlerts::NOTICE, 'k2');
$clock += 60; $a->run();
check('daily cap: second notice held back', count($box['line']) === 1);
$a->custom('third', array('three'), SecurityAlerts::URGENT, 'k3');
$clock += 60; $a->run();
check('urgent goes through even when capped', count($box['line']) === 2 && strpos($box['line'][1], 'third') !== false);

$box['status'] = 429;   // LINE monthly quota used up
$a->custom('fourth', array('four'), SecurityAlerts::URGENT, 'k4');
$clock += 60; $r = $a->run();
check('LINE refuses: falls back to e-mail', $r['sent'] === 'mail' && count($box['mail']) === 1 && strpos($box['mail'][0], 'fourth') !== false);

$a = make($box, $clock, array('enabled' => false));
$a->custom('x', array('y'), SecurityAlerts::URGENT);
$r = $a->run();
check('disabled: records nothing, sends nothing', count($box['line']) === 0);

$a = make($box, $clock, array('language' => 'zh-TW'));
check('test message (zh-TW)', $a->sendTest() === 'line' && strpos($box['line'][0], '測試訊息') !== false);

$a = make($box, $clock, array('language' => 'zh-TW'));
for ($i = 0; $i < 12; $i++) { $a->custom('長訊息 ' . $i, array_fill(0, 8, str_repeat('後台帳號變動', 12)), SecurityAlerts::URGENT, 'long' . $i); }
$clock += 60; $a->run();
$msg = isset($box['line'][0]) ? $box['line'][0] : '';
$chars = preg_match_all('/./us', $msg);
check('very long message is cut below LINE\'s 5000 characters, still valid UTF-8', $chars > 4000 && $chars <= 5000 && preg_match('//u', $msg) === 1, "chars=$chars");

$a = make($box, $clock);
$r1 = $a->tick();
$r2 = $a->tick();
check('tick(): second call within tick_seconds is skipped', isset($r1['findings']) && isset($r2['skipped']));

echo "\n$pass passed, $fail failed\n";
exit($fail ? 1 : 0);
