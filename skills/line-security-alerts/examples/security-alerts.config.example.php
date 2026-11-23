<?php
/**
 * Example configuration. Copy it next to your app (NOT into a public web folder), rename it to
 * security-alerts.config.php, and keep it out of version control — it holds your LINE / Telegram / Discord keys.
 *
 * Every key is optional except state_dir; see SecurityAlerts::defaults() for the full list.
 */

return array(
    'site_name' => 'My Shop',
    'language'  => 'en',                     // 'en' or 'zh-TW'
    'timezone'  => 'Asia/Taipei',

    /* Where the module keeps its logs and fingerprints. Must be writable by PHP AND by the cron user.
       Best: outside the web root. If it has to be inside, the module writes a deny-all .htaccess
       (Apache); on nginx add:  location ^~ /path/to/state { deny all; }  */
    'state_dir' => __DIR__ . '/../var/security-alerts',

    /* LINE Messaging API. Prefer environment variables (or a file outside the web root) over literals.
       Use an official account made ONLY for these alerts, not the one your customers follow: the key lives on
       this server, and whoever breaks in can message every friend of that account. --status and the weekly
       check-in warn when the account has more than line_friends_warn (20) friends. */
    'line_channel_access_token' => (string) getenv('LINE_ALERT_TOKEN'),
    'line_to'                   => array_filter(explode(',', (string) getenv('LINE_ALERT_TO'))),   // "Uxxxxxxxx…" (you) or "Cxxxxxxxx…" (a group)
    // 'line_api_base'         => 'http://127.0.0.1:8765',   // the fake server in scripts/, for trying things out
    // 'line_quota_check'      => false,                     // do not ask LINE once a week how much of the monthly allowance is used

    /* Telegram and Discord (optional; leave empty to not use them). Setup steps are in the README.
       A message goes to the first channel that takes it: Telegram, then Discord, then LINE, then e-mail. */
    'telegram_bot_token'  => (string) getenv('TELEGRAM_ALERT_TOKEN'),      // "123456789:ABC…" from @BotFather
    'telegram_chat_id'    => (string) getenv('TELEGRAM_ALERT_CHAT'),       // e.g. 123456789 (you) or -1001234567890 (a group)
    'discord_webhook_url' => (string) getenv('DISCORD_ALERT_WEBHOOK'),     // https://discord.com/api/webhooks/…
    // 'line_min_level'   => 2,     // keep LINE for URGENT alerts only (tried there first); everything else goes to
                                    // Telegram / Discord / e-mail. 1 = everything except the "all is well" weekly check-in.

    /* If the channels above refuse (no token, monthly quota used up), alerts go here instead. */
    'mail_to'   => (string) getenv('ALERT_MAIL_TO'),
    'mail_from' => '',

    /* File-integrity scan. Paths below are relative to site_root. */
    'site_root'    => realpath(__DIR__ . '/..'),
    'exclude_dirs' => array('.git', 'node_modules', 'var', 'storage/cache'),    // caches, compiled templates, logs…
    'upload_dirs'  => array('public/uploads'),                                  // code files never belong here
    'runtime_dirs' => array(),                                                  // code your app writes on its own (generated config…)

    // 'scan_hours'   => 1,                                                     // how often files are checked; 0 = on every run
    // 'rehash_days'  => 7,                                                     // how often EVERY file is re-read in full; 0 = never
    // 'input_charset' => 'BIG5',                                               // only for old sites with file/account names that are not UTF-8

    /* Optional, OFF by default: rename (never delete) a NEW program file that appears inside upload_dirs, so
       the server stops running it. Only that: nothing outside upload_dirs, nothing that was already there,
       no .htaccess. Run without it for a while first and make sure upload_dirs is right. */
    // 'quarantine_uploads' => true,

    /* Optional page watch: a few of your own pages, read once an hour the way a desktop browser, a phone,
       Google's crawler and a visitor arriving from a Google search see them. It reports a NEW outside site for
       scripts, frames, form targets or redirects (card skimming, redirects), anything only the crawler or
       Google visitors get (gambling / spam-link injections), and new outside links. These hide in the
       database, where the file scan cannot see them. Pick stable pages (home, a product, the cart), not ones
       whose links change every day. Runs from the scheduled job only. After setting it, run --pages once. */
    // 'page_watch' => array('https://example.com/', 'https://example.com/cart'),
    // 'page_allow' => array('googletagmanager.com', 'your-payment-provider.example'),   // sub-domains included

    /* Optional emergency brake: URGENT alerts end with a link that locks the admin area for brake_hours (the
       shop stays open). Copy examples/security-brake.php into the web root, put its address here, and make
       the admin area ask adminLocked() on every request (integration.md, section 16). The secret: 32+ random
       characters, e.g. from  php -r "echo bin2hex(random_bytes(24));"  — environment variable, not git. */
    // 'brake_url'       => 'https://example.com/security-brake.php',
    // 'brake_secret'    => (string) getenv('ALERT_BRAKE_SECRET'),
    // 'brake_hours'     => 4,
    // 'brake_allow_ips' => array('203.0.113.10'),   // your developer's fixed IP, never locked out

    /* The monitor watching itself.
       - Once a week it says "still on duty" (0 = never) and prints one fingerprint of all code files, so
         your chat history holds a copy that nobody on the server can rewrite.
         A week without that message = the checks stopped.
       - witness_file: a path OUTSIDE state_dir and outside the web root. If someone empties state_dir to
         reset the detection, this file is still there and you get an URGENT alert.
       - ping_url (optional): a check-in address from a "tell me when my cron job stops" service, e.g.
         healthchecks.io. It is called after every completed run; set that service to expect a call every
         5 minutes with about 10 minutes of grace, and it will tell you within minutes when the schedule
         dies. Keep the address secret (anyone who has it can check in for you): environment variable, not
         version control. The module never logs it. */
    'heartbeat_days' => 7,
    'witness_file'   => (string) getenv('HOME') !== '' ? getenv('HOME') . '/.security-alerts-witness' : '',
    'ping_url'       => (string) getenv('ALERT_PING_URL'),

    /* Thresholds — start with the defaults, then tune after a week of real traffic. Money amounts are in
       your own currency; 0 disables that rule. */
    'refund_single'        => 0,
    'adjust_single'        => 0,
    'cancel_paid_hour_sum' => 0,

    /* Optional: lets the module notice admin-account changes made outside your admin UI (e.g. straight in
       the database). Return username => fields; secrets are hashed before they are stored. */
    // 'admin_snapshot' => function () {
    //     $pdo = new PDO(getenv('DB_DSN'), getenv('DB_USER'), getenv('DB_PASS'));
    //     $out = array();
    //     foreach ($pdo->query('SELECT username, role, email, password_hash, totp_enabled FROM admin_users') as $r) {
    //         $out[$r['username']] = array('role' => $r['role'], 'email' => $r['email'], 'password' => $r['password_hash'], '2fa' => (bool) $r['totp_enabled']);
    //     }
    //     return $out;
    // },

    /* Optional: your own "looks like a backdoor" patterns, e.g. a string found during a past incident.
       A new or changed code file that matches is URGENT. `--audit` checks every existing file against them. */
    // 'extra_rules'   => array(
    //     'incident-2025' => array('pattern' => '/bad-domain\.example/i', 'label' => 'mentions the domain from our last incident'),
    // ),
    // 'disable_rules' => array('blob'),      // switch off a built-in rule that keeps matching your own code

    /* Optional: a channel that is not built in — Slack, ntfy, SMS… It is tried before all the others.
       Return true when the message was accepted; return false and the next channel is used as usual.
       $level: 0 = weekly check-in, 1 = notice, 2 = urgent. Check your service's documentation for the
       exact request it wants; this is only the shape. */
    // 'notifier' => function ($text, $level) {
    //     $ch = curl_init((string) getenv('ALERT_WEBHOOK_URL'));
    //     curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 8,
    //         CURLOPT_HTTPHEADER => array('Content-Type: application/json'), CURLOPT_POSTFIELDS => json_encode(array('text' => $text))));
    //     curl_exec($ch);
    //     return curl_getinfo($ch, CURLINFO_HTTP_CODE) < 300 && curl_getinfo($ch, CURLINFO_HTTP_CODE) >= 200;
    // },
);
