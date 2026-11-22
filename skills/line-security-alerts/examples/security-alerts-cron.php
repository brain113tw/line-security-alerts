<?php
// Command-line entry point. Schedule it every 5 minutes, e.g. with crontab:
//
//   */5 * * * *  /usr/bin/php /path/to/security-alerts-cron.php >> /path/to/var/security-alerts-cron.log 2>&1
//
//   php security-alerts-cron.php               run every check now
//   php security-alerts-cron.php --test        send one test message
//   php security-alerts-cron.php --rebaseline  forget file fingerprints (after a big deployment you trust)
//   php security-alerts-cron.php --audit       read every code file and list the ones that look suspicious
//                                              (once after installing: the first run trusts what is already there)
//   php security-alerts-cron.php --fingerprint the code fingerprint from the weekly check-in, checked against the disk
//   php security-alerts-cron.php --manifest    every code file with its SHA-256, in sha256sum format
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

if ($arg === '--test')
{
    $r = $alerts->sendTest();
    echo date('Y-m-d H:i:s') . " test message: $r\n";
    exit($r === 'failed' ? 1 : 0);
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
