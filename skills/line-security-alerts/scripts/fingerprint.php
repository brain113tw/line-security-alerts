<?php
/**
 * The code fingerprint of a folder — the same number the weekly check-in prints for your server.
 *
 *   php scripts/fingerprint.php /path/to/clean/copy
 *   php scripts/fingerprint.php /path/to/clean/copy --exclude=.git,node_modules,var   same exclude_dirs as your config
 *   php scripts/fingerprint.php /path/to/clean/copy --only=public,app                 same scan_dirs as your config
 *   php scripts/fingerprint.php /path/to/clean/copy --list                            every code file with its SHA-256
 *
 * Use it on your own computer, on the exact files you uploaded. If the fingerprint equals the one in
 * LINE, the code on the server is byte-for-byte what you uploaded. If not, run it with --list on both
 * sides (on the server: "php security-alerts-cron.php --manifest") and compare the two lists; the
 * lines that differ are the files that differ.
 *
 * It needs no configuration and no LINE account; it reads files and prints, nothing else.
 * The list is in `sha256sum` format, and the full fingerprint is the SHA-256 of that list.
 */

require __DIR__ . '/../lib/SecurityAlerts.php';

$dir = '';
$opt = array('exclude' => null, 'only' => null, 'list' => false);
foreach (array_slice($argv, 1) as $arg)
{
    if ($arg === '--list') { $opt['list'] = true; }
    elseif (strpos($arg, '--exclude=') === 0) { $opt['exclude'] = array_values(array_filter(explode(',', substr($arg, 10)), 'strlen')); }
    elseif (strpos($arg, '--only=') === 0) { $opt['only'] = array_values(array_filter(explode(',', substr($arg, 7)), 'strlen')); }
    elseif ($dir === '' && strpos($arg, '--') !== 0) { $dir = $arg; }
}
if ($dir === '' || !is_dir($dir))
{
    fwrite(STDERR, "Usage: php fingerprint.php <folder> [--exclude=dir1,dir2] [--only=dir1,dir2] [--list]\n");
    exit(2);
}

$defaults = SecurityAlerts::defaults();
$alerts = new SecurityAlerts(array(
    'state_dir'    => rtrim(str_replace('\\', '/', sys_get_temp_dir()), '/') . '/lsa-fingerprint-unused',   // never created: nothing is stored
    'site_root'    => realpath($dir),
    'exclude_dirs' => $opt['exclude'] !== null ? $opt['exclude'] : $defaults['exclude_dirs'],
    'scan_dirs'    => $opt['only'] !== null ? $opt['only'] : array(),
));

$manifest = $alerts->manifest();
if ($opt['list'])
{
    echo $manifest;
    exit(0);
}
$fp = SecurityAlerts::fingerprintOf($manifest);
echo 'fingerprint : ' . $fp['code'] . "\n";
echo 'full value  : ' . $fp['full'] . "\n";
echo 'code files  : ' . substr_count($manifest, "\n") . "\n";
