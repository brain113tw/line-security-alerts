<?php
/**
 * A few days at a small shop, replayed: see what the alerts look like without a LINE account,
 * without a network connection and without touching a real website.
 *
 *   php scripts/demo.php                     English
 *   php scripts/demo.php --lang=zh-TW        中文
 *   php scripts/demo.php --site="My Shop"    use your own shop name in the messages
 *   php scripts/demo.php --json              machine-readable (used to draw the picture in the README)
 *
 * What it does: builds a pretend website in a throw-away folder ("lsa-demo-…" in the system temp
 * directory), makes the changes described on screen, runs the real module after each one and prints
 * the exact message the owner's phone would show. Nothing is sent anywhere; the folder is deleted
 * at the end.
 *
 * The first two alerts are modelled on what actually happened at 沂恩精緻洗衣 (EN Laundry) on the day
 * this example was written: the owner's own deployments were reported, as designed. The last one is a
 * simulation of the case the module exists for.
 *
 * Antivirus: the "intruder" here is a harmless one-line file whose only crime is its NAME and location
 * (uploads/avatar.jpg.php). No malware look-alike is written, so antivirus tools should stay quiet.
 */

require __DIR__ . '/../lib/SecurityAlerts.php';

$opt = array('lang' => 'en', 'site' => '', 'json' => false);
foreach (array_slice($argv, 1) as $arg)
{
    if ($arg === '--json') { $opt['json'] = true; }
    elseif (strpos($arg, '--lang=') === 0) { $opt['lang'] = substr($arg, 7); }
    elseif (strpos($arg, '--site=') === 0) { $opt['site'] = substr($arg, 7); }
}
$zh = ($opt['lang'] === 'zh-TW');
if ($opt['site'] === '')
{
    $opt['site'] = $zh ? '我的商店' : 'My Shop';
}

$say = $zh ? array(
    'install'   => '裝好了。第一次執行只把網站現在的樣子記下來。',
    'none'      => '（沒有發任何訊息）',
    'deploy1'   => '你上傳了一次更新：新增 2 支程式、改了 1 支。',
    'scan'      => '下一次定時檢查。手機收到：',
    'mine'      => '是你自己傳的，不用理會。重點是：如果你那天「沒有」上傳任何東西卻收到這則，就代表有別人動了你的網站。',
    'deploy2'   => '你更新了一支程式庫。',
    'mine2'     => '同樣是自己人。每次上傳都會有這麼一則，等於多一份「上線紀錄」。',
    'intruder'  => '半夜。上傳資料夾裡多了一支沒人放過的檔案，同時有人在猜後台密碼。',
    'urgent'    => '這次不是你。訊息標成「緊急」，而且直接告訴你下一步。',
    'quiet'     => '裝好滿一週的早上。沒事的時候它完全安靜，所以每週說一聲「我還在」：',
    'beat'      => '哪一週沒收到這則，就代表檢查停了（排程壞了、金鑰過期、主機重灌…）。',
    'quiet2'    => '再過一週。這一週沒有人動過程式。',
    'same'      => '「程式總指紋」跟上一則一樣，代表這一週程式沒被動過。這串字留在你的 LINE 裡，進得了主機的人也改不到；哪天指紋變了、你卻沒收過「程式檔有變動」，訊息會直接警告你。',
    'end'       => '示範結束。上面每一則都是模組實際產生的文字。',
) : array(
    'install'   => 'Installed. The first run only records what the site looks like right now.',
    'none'      => '(nothing is sent)',
    'deploy1'   => 'You upload an update: 2 new code files, 1 changed.',
    'scan'      => 'The next scheduled check. Your phone shows:',
    'mine'      => 'That was you, so ignore it. The point: if you had NOT uploaded anything that day, this same message means somebody else changed your site.',
    'deploy2'   => 'You update one library file.',
    'mine2'     => 'You again. Every deployment produces one of these — a free deployment log.',
    'intruder'  => 'The middle of the night. A file nobody on the team uploaded appears in the upload folder, while someone is guessing the admin password.',
    'urgent'    => 'This time it was not you. The message is marked URGENT and tells you what to do first.',
    'quiet'     => 'A week after installing, in the morning. It is silent when all is well, so once a week it says "still here":',
    'beat'      => 'A week without this message means the checks have stopped (cron broke, token expired, server rebuilt…).',
    'quiet2'    => 'One more week. Nobody touched the code this week.',
    'same'      => 'The "code fingerprint" equals the one in the previous message: no code changed this week. It sits in your LINE chat, where someone who got into the server cannot edit it; if it ever changes without a "code files changed" notice in between, the message warns you.',
    'end'       => 'End of the demo. Every message above is the module\'s real output.',
);

/* ---------------------------------------------------------------- the pretend website */
$tmp = rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/lsa-demo-' . getmypid() . '-' . mt_rand(1000, 9999);
$site = $tmp . '/site';
foreach (array('', '/admin', '/lib', '/uploads') as $d) { mkdir($site . $d, 0700, true); }
file_put_contents($site . '/index.php', "<?php echo 'welcome';\n");
file_put_contents($site . '/admin/login.php', "<?php // admin login form\n");
file_put_contents($site . '/admin/menu.php', "<?php \$menu = array('orders', 'members');\n");
file_put_contents($site . '/lib/Mailer.php', "<?php // library, version 1\n");
file_put_contents($site . '/uploads/photo-001.jpg', 'not really a jpeg');

register_shutdown_function(function () use ($tmp) {
    if (!is_dir($tmp)) { return; }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) { $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname()); }
    @rmdir($tmp);
});

$clock = 0;
$sent = array();
$alerts = new SecurityAlerts(array(
    'site_name'  => $opt['site'],
    'language'   => $zh ? 'zh-TW' : 'en',
    'timezone'   => 'Asia/Taipei',
    'state_dir'  => $tmp . '/state',
    'site_root'  => $site,
    'upload_dirs' => array('uploads'),
    'scan_hours' => 1,
    'line_channel_access_token' => 'demo',
    'line_to'    => array('Udemo'),
    'clock'      => function () use (&$clock) { return $clock; },
    'transport'  => function ($url, $headers, $body) use (&$sent) {
        $j = json_decode($body, true);
        $sent[] = $j['messages'][0]['text'];
        return array(200, '{}');
    },
));

$log = array();
$step = function ($when, $text) use (&$clock, &$log) {
    $clock = strtotime($when);
    $log[] = array('kind' => 'step', 'time' => date('m/d H:i', $clock), 'text' => $text);
};
$run = function ($comment) use ($alerts, &$sent, &$log, &$clock, $say) {
    $sent = array();
    $alerts->run();
    if (!$sent)
    {
        $log[] = array('kind' => 'none', 'time' => date('m/d H:i', $clock), 'text' => $say['none']);
    }
    foreach ($sent as $text)
    {
        $log[] = array('kind' => 'message', 'time' => date('m/d H:i', $clock), 'text' => $text);
    }
    if ($comment !== '')
    {
        $log[] = array('kind' => 'comment', 'time' => date('m/d H:i', $clock), 'text' => $comment);
    }
};

/* ---------------------------------------------------------------- the story */
$step('2026-11-20 22:00', $say['install']);
$run('');

$step('2026-11-21 21:30', $say['deploy1']);
file_put_contents($site . '/admin/shortcuts.php', "<?php // new page: menu shortcuts\n");
file_put_contents($site . '/lib/Shortcuts.php', "<?php // new library for the shortcuts page\n");
file_put_contents($site . '/admin/menu.php', "<?php \$menu = array('orders', 'members', 'shortcuts');\n");
$step('2026-11-22 07:00', $say['scan']);
$run($say['mine']);

$step('2026-11-22 10:55', $say['deploy2']);
file_put_contents($site . '/lib/Mailer.php', "<?php // library, version 2 (bug fix)\n");
$step('2026-11-22 10:57', $say['scan']);
$run($say['mine2']);

$step('2026-11-25 03:00', $say['intruder']);
file_put_contents($site . '/uploads/avatar.jpg.php', "<?php echo 1;\n");   // harmless content; the name and place are the problem
for ($i = 0; $i < 14; $i++)
{
    $clock = strtotime('2026-11-25 03:00') + $i * 55;
    $alerts->loginFailed('admin', '203.0.113.9', 'curl/8.5', true);
}
$step('2026-11-25 03:15', $say['scan']);
$run($say['urgent']);

$step('2026-11-28 09:05', $say['quiet']);
$run($say['beat']);

$step('2026-12-05 09:05', $say['quiet2']);
$run($say['same']);

$log[] = array('kind' => 'end', 'time' => '', 'text' => $say['end']);

/* ---------------------------------------------------------------- output */
if ($opt['json'])
{
    echo json_encode($log, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT), "\n";
    exit(0);
}
foreach ($log as $row)
{
    if ($row['kind'] === 'step')
    {
        echo "\n== " . $row['time'] . '  ' . $row['text'] . "\n";
    }
    elseif ($row['kind'] === 'message')
    {
        echo "   +------------------------------------------------------------\n";
        foreach (explode("\n", $row['text']) as $line) { echo '   | ' . $line . "\n"; }
        echo "   +------------------------------------------------------------\n";
    }
    elseif ($row['kind'] === 'end')
    {
        echo "\n" . $row['text'] . "\n";
    }
    else
    {
        echo '   ' . ($row['kind'] === 'comment' ? '-> ' : '') . $row['text'] . "\n";
    }
}
