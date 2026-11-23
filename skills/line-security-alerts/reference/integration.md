# Integration guide

Examples are plain PHP; translate them to the framework you find (controller, middleware, event
listener, plugin hook…). The names `$db`, `admin_users`, `verify_password()` etc. are placeholders.

## A shared instance

```php
function security_alerts()
{
    static $a = null;
    if ($a === null) {
        require_once __DIR__ . '/lib/SecurityAlerts.php';
        $a = new SecurityAlerts(require '/path/outside/webroot/security-alerts.config.php');
    }
    return $a;
}
```

If the config file can be missing on some machines (a developer laptop), return a disabled
instance instead of failing: `new SecurityAlerts(array('enabled' => false, 'state_dir' => sys_get_temp_dir()))`.

## Client IP

Use whatever the application already trusts. If the site sits behind a CDN or reverse proxy, only
read the forwarded header when `REMOTE_ADDR` is one of that proxy's addresses; otherwise anyone can
send `X-Forwarded-For: 1.2.3.4` and choose the IP that appears in your alerts.

## 1. Admin login

```php
$user = trim((string) $_POST['username']);
$row  = find_admin_by_username($user);                    // null if no such account
$ok   = $row && verify_password($_POST['password'], $row['password_hash']);

if ($ok) {
    security_alerts()->loginSucceeded($row['username'], client_ip(), (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
    // … start the session as before
} else {
    security_alerts()->loginFailed($user, client_ip(), (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), $row !== null);
    // … show the same error as before (do not reveal whether the account exists)
}
```

- Also call `loginFailed()` for a wrong 2FA code, and `loginSucceeded()` for passkey / "remember
  me" logins that start a new admin session.
- Do not call `loginSucceeded()` on every request of an existing session — only when a session starts.
- `$accountExists` only changes the wording ("real admin accounts were targeted"). Pass `null` if
  you cannot know.

What it reports:

- more than `login_fail_hour` failures in an hour overall, or `login_fail_ip_hour` from one IP;
  URGENT when the hourly total reaches 3× the threshold;
- a successful login whose browser **and** network (IPv4 /24, IPv6 /48) are both new for that
  account within `device_memory_days`. The first login the module ever sees for an account is
  learned silently.

## 2. Admin accounts

```php
security_alerts()->accountChanged('created', $newUser, $currentAdmin);
security_alerts()->accountChanged('role', $target, $currentAdmin, "$oldRole -> $newRole");
security_alerts()->accountChanged('permissions', $target, $currentAdmin);
security_alerts()->accountChanged('email', $target, $currentAdmin);
security_alerts()->accountChanged('password', $target, $currentAdmin);
security_alerts()->accountChanged('2fa_disabled', $target, $currentAdmin);
security_alerts()->accountChanged('passkey_added', $target, $currentAdmin);
security_alerts()->accountChanged('deleted', $target, $currentAdmin);
```

Call it after the change is saved. `created`, `role`, `permissions` and `2fa_disabled` are URGENT.
Changes in the "safer" direction (turning 2FA on, removing a passkey) need no hook.

Never put the new password, e-mail or tokens into `$detail` — the text goes to LINE.

### Optional snapshot

When admin data can change behind the UI's back, give the module a read-only callable:

```php
'admin_snapshot' => function () {
    $out = array();
    foreach (db_rows('SELECT username, role, permissions, email, password_hash, totp_enabled, passkey_count FROM admin_users') as $r) {
        $out[$r['username']] = array(
            'role' => $r['role'], 'perms' => $r['permissions'], 'email' => $r['email'],
            'password' => $r['password_hash'], '2fa' => (bool) $r['totp_enabled'], 'passkeys' => (int) $r['passkey_count'],
        );
    }
    return $out;
},
```

Only SHA-256 fingerprints of e-mail, permissions and password hash are stored in `state.json`.
The first run records the list silently; afterwards new accounts, removed accounts and changed
fields are reported. (Fingerprints written by an earlier build were SHA-1; they are recognised and
converted on the next run without a "password changed" alarm.)

## 3. Firewall / rate limiter

```php
if ($blockedBy = my_firewall_check($_SERVER['REQUEST_URI'], $_GET, $_POST)) {
    security_alerts()->firewallBlocked(client_ip(), $blockedBy, $_SERVER['REQUEST_URI']);
    http_response_code(403);
    exit;
}
```

Rule names show up in the message (`Top rules: sqli×31, traversal×4`), so use short stable names.
Only the first 200 characters of the path are kept. Internet background noise is normal; the
default thresholds (`firewall_hour`, `firewall_ip_hour`) are meant to fire only on a focused attack.

## 4. Money done by staff

```php
security_alerts()->moneyEvent('refund', $amount, $currentAdmin, $orderNo);
security_alerts()->moneyEvent('cancel_paid', $paidAmount, $currentAdmin, $orderNo);   // cancelling an order that was paid
security_alerts()->moneyEvent('cancel', 0, $currentAdmin, $orderNo);                  // cancelling an unpaid order
security_alerts()->moneyEvent('balance_adjust', abs($delta), $currentAdmin, $memberRef);
```

Hook only actions a person performs in the admin; automatic refunds from a payment provider callback
are not insider risk. Reports a burst within an hour (count or sum) and single large amounts.
Amount thresholds default to 0 (off) because they depend on your currency and prices — set them.

## 5. Your own checks

```php
// e.g. from a backup script
if (!$backupOk) {
    security_alerts()->custom('Nightly backup failed', array($errorSummary), SecurityAlerts::NOTICE, 'backup-failed');
}
```

The key makes repeated calls count as one finding inside the quiet window.

## 6. File integrity

Configure, don't hook:

- `site_root` — required for the scan; everything else is relative to it.
- `exclude_dirs` — caches, compiled templates, logs, `.git`, dependency folders you do not deploy.
- `upload_dirs` — any `.php`/`.phtml`/`.htaccess`/… file appearing here is URGENT.
- `runtime_dirs` — places where the app legitimately writes code files; changes there are only
  logged unless they contain a suspicious pattern.

What counts as a code file: `.php .php3-8 .phtml .pht .phps .phar .inc .cgi .pl .py .sh .asp .aspx
.jsp`, plus `.htaccess`, `.user.ini`, `php.ini`.

Severity:

| Situation | Level |
|---|---|
| New code file containing a suspicious pattern, or any code file in an upload folder | URGENT |
| Existing file changed and now contains a pattern it did not have before | URGENT |
| New / changed / deleted code files, nothing suspicious | Notice (one combined message) |
| Changes inside `runtime_dirs` | Log only |

Each code file is recorded with the SHA-256 of its content. A file is re-hashed when its size, mtime
or ctime changes. On Linux `touch -r` can fake the mtime but not the ctime, so a same-size edit with
the old timestamp put back is still caught. (PHP reports ctime in whole seconds, and on Windows it is
the creation time, so this extra check only helps on Linux/Unix servers — which is where websites live.)

The scan spends at most `scan_time_budget` seconds per run and continues where it stopped on the
next run, so large sites are fine.

**The full re-read.** Comparing sizes and times is fast, but it trusts them. Every `rehash_days`
(default 7; 0 = never) one scan reads EVERY code file again and compares fingerprints, whatever the
size and times say. That closes the remaining gap: an edit that keeps the length and has every
timestamp put back (possible on Windows servers, and for anyone able to set the inode change time).
A full re-read respects `scan_time_budget` too and simply continues on the following runs.

**An edit with its timestamp put back is URGENT.** When a file's content is different but its
modification time is exactly what it was at the previous scan, somebody restored the time (or wrote
the file in a way that does not touch it). Normal edits and deployments always produce a new
modification time, so this is reported as "its content changed but its modification time was put
back, as if to hide the edit" — URGENT, whatever the content looks like. One exception keeps it
honest: a file that was recorded within two seconds of being written is marked "fresh" and simply
re-read on the next scan, because it could legitimately be written twice in the same second.
`'disable_rules' => array('stealth')` turns the escalation off (the change is still reported).

**How often.** `scan_hours` (default 1) is the pause between two file checks. A check that finds
nothing new only lists the folders and compares sizes and times — it reads no file content — so on an
ordinary site it is cheap, and `'scan_hours' => 0` (check on every run, i.e. every 5 minutes with the
suggested cron line) is a reasonable setting. It cannot go faster than your cron interval; shared
hosting has no way to watch files continuously.

After a deployment you get a Notice listing what changed — that is the point: if you did not deploy,
someone else did. Every change is reported, including a second change to the same file a day later
or a file that was removed and then planted again under the same name. After a big, trusted change
you can run `php security-alerts-cron.php --rebaseline`. The next run then announces "the file
baseline was reset by hand", so a reset can never happen quietly.

**Upgrading from an earlier build (SHA-1 records).** Nothing to do. The scan recognises the old
40-digit fingerprints, checks each file against its old fingerprint first, and only then replaces it
with the SHA-256: unchanged files are converted quietly, files that really changed are reported as
usual. When the conversion is complete you get ONE Notice, "File fingerprints upgraded to SHA-256
(N files)". If that Notice ever arrives without an update of the module, treat it as tampering.

## 7. Running the checks

Cron (preferred):

```
*/5 * * * *  /usr/bin/php /path/to/security-alerts-cron.php >> /path/to/var/security-alerts-cron.log 2>&1
```

Use the PHP CLI binary your host documents (often `/usr/local/bin/php` on shared hosting). If the
config depends on `$_SERVER['HTTP_HOST']`, set it for the CLI too.

Without cron:

```php
register_shutdown_function(function () {
    if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
    security_alerts()->tick();      // returns at once unless 5 minutes have passed
});
```

## 8. Files the module writes

| File in `state_dir` | Content |
|---|---|
| `events-YYYYMMDD.ndjson` | one line per hook call; pruned after `keep_days` |
| `findings.ndjson` | every finding with its delivery status (`line`, `mail`, `custom`, `failed`, `capped`, `logged`) |
| `state.json` | last run, quiet-window keys, daily counter, known devices, admin snapshot fingerprints, alerts waiting to be re-sent |
| `files.json` | size / mtime / ctime / SHA-256 / pattern ids per code file |
| `.htaccess`, `index.html` | deny-all for Apache, empty index |

The check-in address (`ping_url`) is not written to any of them.

### Is it still working? `--status`

`php security-alerts-cron.php --status` (or `$alerts->status()` from code) answers that without
sending or changing anything: last run, where alerts go, messages sent today, alerts waiting to be
re-sent, files watched with the last scan and the last full re-read, the current code fingerprint next
to the one in the last check-in, the outside check-in, and the latest findings with how each was
delivered. Lines starting with `!!` need a look (no run for a while, nowhere to send to, no fallback
e-mail, alerts stuck, check-in address failing…); the exit code is 1 when there is at least one. The
token, the recipient ids and the check-in address are never printed.

### LINE's monthly allowance

A LINE Official Account may push a limited number of messages a month (how many depends on its
plan), counted per recipient; when the limit is reached LINE answers 429 and delivers nothing. With
each weekly check-in the module asks LINE for the limit and the number sent so far and adds one line:
"LINE messages this month: about 120 of 200 used". From 80% it is a warning. The number is LINE's own,
approximate, and includes everything else the same account sent (campaign messages too). A plan
without a limit, or a LINE that does not answer the question, simply means no line. Two small GET
requests once a week; `'line_quota_check' => false` turns it off. A custom `transport` receives
`'GET'` as its fourth argument for these.

### When an alert cannot be delivered

LINE refuses or is unreachable and there is no e-mail fallback (or that fails too): the composed
message is kept in `state.json` and tried again on the following runs — oldest first, at most three
per run, stopping at the first that still fails. When it finally goes out it starts with "Delayed:
this alert is from MM/DD HH:MM", so nobody mistakes old news for new. The cron summary shows
`"sent":"failed"` on the run that could not send and `"resent":N` on the run that did. A message that
has waited seven days is given up (logged with status `expired`); at most 20 are kept. This matters
most for one-time findings — a changed file, a new admin account — which are only ever seen once.

### File and account names that are not UTF-8

Old sites sometimes carry a folder that an FTP client created in Big5, GBK or Latin-1, or account
names stored in such an encoding. JSON cannot hold those bytes, so:

- in `files.json` such a path is stored as a NUL byte followed by its hex form (a real file name can
  never contain NUL) and turned back into the original bytes when read;
- in messages it is shown converted from `input_charset` when you set that (e.g. `'input_charset' =>
  'BIG5'`; needs the mbstring or iconv extension), otherwise with `?` for each byte that is not UTF-8;
- text arriving through hooks (user names, details) and the keys of `admin_snapshot` get the same
  treatment once, on the way in; an account name that had to be repaired keeps a 4-character tag so two
  different names never merge into one;
- nothing is ever written as an empty file because of a bad byte.

The self-test covers this with constructed records and hook input on every platform; the part that
creates a real file with such a name can only run on Linux. If your site has such names, run
`php scripts/selftest.php` on the server itself once and check that it ends with `0 failed`.

## 9. The monitor watching itself

A monitor that an intruder can quietly switch off is not worth much, and a monitor that is silent
when all is well is also silent when it is broken. These cover that:

| What | How it shows up |
|---|---|
| **Weekly check-in** (`heartbeat_days`, default 7; 0 = off) | One "still on duty" message a week, in the daytime (not before `heartbeat_hour`, not after 21:00), with the number of checks run, things reported, files watched and the date the records go back to. If the cron job dies, the token expires or the server is rebuilt without the module, the message stops coming — and the owner notices. |
| **Code fingerprint** (part of the weekly check-in) | One short string for all code files (section 10). The copy in the owner's chat cannot be rewritten from the server. The message compares it with the previous one: same / changed and N notices were sent / changed and only logged / **changed with no change on record** — the last one means `files.json` was edited to hide a change, and turns the check-in into a warning. |
| **Fingerprints gone** | `files.json` deleted, emptied or corrupted without `--rebaseline` → URGENT "the file fingerprints have disappeared". The baseline is rebuilt silently (no flood of "new file" lines) and monitoring continues. |
| **Whole state folder wiped** (`witness_file`, optional) | Give the module a path OUTSIDE `state_dir` (e.g. in the home folder, not in the web root). It writes its install date there once. If it ever starts from an empty state folder while that file exists → URGENT "the monitoring records were wiped". Without a witness file the weekly check-in still gives it away: its "records go back to" date jumps to a recent day. |
| **Outside check-in** (`ping_url`, optional) | After every completed run the module requests (GET) an address given by a cron-monitoring service. When the requests stop, that service — which runs somewhere else — tells the owner within minutes instead of a week. |

None of this stops an attacker who has the same file access as the website from doing damage;
it makes sure that blinding the monitor is itself noticed.

### Setting up the outside check-in

1. Create a check at a cron-monitoring service (healthchecks.io is one; any service that gives you
   an address to call and alerts when the calls stop will do). Set it to expect a call every
   5 minutes — your cron interval — with about 10 minutes of grace, and choose how it should reach
   the owner (e-mail is fine; pick something the owner actually reads).
2. Put the address into the config as `ping_url`, from an environment variable. Use the `https://`
   address exactly as given; redirects are not followed.
3. Run the cron script once: the JSON summary must say `"ping":"ok"`, and the check turns green on
   the service's page. `"ping":"failed"` means the address did not answer with a 2xx status within
   `ping_timeout` seconds (default 5).
4. Prove it: disable the cron line for 20 minutes and see that the owner is told. Re-enable it.

Details that matter:

- The request is made last, after the alerts of that run were sent and the state was saved. A slow
  or dead check-in service costs at most `ping_timeout` seconds and changes nothing else.
- Only a completed run checks in. A run that crashes, a `tick()` that is not due yet, and a module
  switched off with `enabled => false` do not — so those are noticed too.
- Nothing about the site is sent: one empty GET request.
- The address is a secret (whoever has it can check in on your behalf). It is never written to
  `state_dir` or put into a message. The cron log line shows only `ok` / `failed`.
- If the address keeps failing, the weekly check-in says so ("has failed N time(s) in a row").
- Without cron (the `tick()` setup) the check-in happens inside a visitor's request, after the
  response was flushed. It still works, but a site nobody visits at night will look "stopped".

## 10. Comparing the code fingerprint

The fingerprint is the SHA-256 of a plain list: one line per code file, `<sha256 of the file>`, two
spaces, the path relative to `site_root`, sorted by path — the format `sha256sum` prints. The
weekly message shows the first 16 hex digits in groups of four.

| Question | How |
|---|---|
| Did code change since last week? | Read the check-in; it says "same as the last check-in" or what happened in between. To verify, scroll up and compare the two strings. |
| What is the fingerprint right now? | `php security-alerts-cron.php --fingerprint` prints the recorded one (what the check-in shows), the one computed from the disk this minute, and whether they agree. |
| Is the server running exactly what I uploaded? | On your own computer, on the files you uploaded: `php scripts/fingerprint.php /path/to/clean/copy --exclude=…` with the same `exclude_dirs` (the server command prints the exact line to use). Equal strings = byte-for-byte the same code. |
| They differ. Which files? | `php security-alerts-cron.php --manifest > server.txt` on the server, `php scripts/fingerprint.php /path/to/clean/copy --exclude=… --list > clean.txt` on your computer, then compare the two lists with any diff tool. |

Things that make an honest copy differ: uploading in FTP "ASCII" mode or a Git setting that converts
line endings (compare against the bytes you actually uploaded), files that exist on only one side
(a config file kept out of version control — add its folder to `exclude_dirs` or expect the
difference), and folders your site rewrites by itself.

What it proves and what it does not: equal fingerprints prove that the code files in scope are
identical. They say nothing about the database, about files outside the scan, or about an intruder
who has replaced the monitor's own code — which is why the comparison against a clean copy is done on
YOUR computer with YOUR copy of `fingerprint.php`, not on the server.

## 11. What was already there, and your own rules

The first run takes the server as it is for "normal". Run this once after installing, and again
whenever you add rules:

```
php security-alerts-cron.php --audit
```

It reads every code file, checks it against the current rules and lists the files that match or that
sit in an upload folder, each with the reason in words. It sends nothing and changes nothing.
Legitimate code matches too (a library that really does run shell commands, an old plugin that
builds code at run time), so the list is for a person to go through, not a verdict.

The built-in rules look for: running system commands, executing code that arrives in a request,
calling whatever function a visitor names, building code at run time, large encoded blobs, names of
well-known web shells, saving uploads wherever a visitor says, `.htaccess` / `.user.ini` lines that
make other file types run as programs, and programs named like images. They are deliberately few and
plain. They will not recognise carefully obfuscated malware — the module's real strength is
reporting ANY change to code, suspicious-looking or not.

```php
'extra_rules' => array(
    // id => regex, or id => array('pattern' => regex, 'label' => words for the message)
    'incident-2025' => array('pattern' => '/bad-domain\.example/i', 'label' => 'mentions the domain from our last incident'),
),
'disable_rules' => array('blob'),   // ids from SecurityAlerts::suspiciousRules(); 'imgphp' also works
```

A new or changed code file that matches an extra rule is URGENT, like the built-in ones. A pattern
that does not compile is skipped (and named by `--audit`); it can never stop a scan. Existing,
unchanged files are only checked against new rules by `--audit`. Do not load rules from the internet
at run time: a rule list is code that decides what you are told, so update it the way you update code.

## 12. Optional: automatic quarantine in upload folders

Off by default. The module is a reporter; this is the single thing it can be told to DO.

```php
'quarantine_uploads' => true,
```

| | |
|---|---|
| Acts on | a program file (`.php .phtml .pht .phps .phar .inc .cgi .pl .py .sh .asp .aspx .jsp`) that is **new** since the last scan **and** lies inside `upload_dirs` |
| Never acts on | files outside `upload_dirs`; files that were already there (even if they change); `.htaccess`, `.user.ini`, `php.ini` (a protective `.htaccess` must not be disabled by mistake — those are reported only) |
| What it does | renames the file in its own folder: every character except letters, digits, `_` and `-` becomes `_`, then `-YYYYMMDD-HHMMSS.quarantined`. `avatar.jpg.php` → `avatar_jpg_php-20260101-031500.quarantined`. No dot of the old name survives, so no `.php` is left for a server that looks at every extension. If that name exists, `-2`, `-3`… is added; nothing is overwritten |
| What it does not do | delete, move elsewhere, change the content or the permissions |
| In the alert | `New: uploads/avatar.jpg.php (…) → renamed to uploads/avatar_jpg_php-….quarantined`, plus how to undo it. The cron summary shows `"quarantined":1` |
| If renaming fails | the file is reported as usual, with "Automatic renaming was tried and failed: that file can still run" |
| Undo | rename the file back. The next scan then reports it as new again (and renames it again if the setting is still on) — so exclude that folder or fix `upload_dirs` first |

Before switching it on:

- Run without it for a week or two. Every "code file inside an upload folder" alert you received in
  that time would have been a rename. If any of them was legitimate (an application that drops
  placeholder `index.php` files into upload folders, a plugin that keeps code there), move that folder
  to `exclude_dirs` or take it out of `upload_dirs` first.
- PHP needs write permission on the upload folders to rename (it normally has it — they are upload
  folders).

What it is worth: it removes the easiest next step for an intruder (requesting the file they just
uploaded) without a person being awake. It does not undo what happened before the scan ran, it does
not help against a file planted outside the upload folders, and a server that has been told to run
EVERY file in that folder as a program (a planted `.htaccess` — which is reported as URGENT) would
still run the renamed file. Treat the alert exactly as you would without it.

## 13. Telegram, Discord, or a channel of your own

The detection does not depend on LINE; only the last step does.

```php
'telegram_bot_token'  => getenv('TELEGRAM_ALERT_TOKEN'),   // "123456789:AAH…" from BotFather
'telegram_chat_id'    => getenv('TELEGRAM_ALERT_CHAT'),    // a number, negative for a group; or an array
'discord_webhook_url' => getenv('DISCORD_ALERT_WEBHOOK'),  // https://discord.com/api/webhooks/…; or an array
'line_min_level'      => 2,                                // optional: LINE for URGENT only
```

A message goes to **one** channel: the first in this order that takes it — your `notifier`, Telegram,
Discord, LINE, e-mail (only the ones that are set up). When all of them fail, the message waits in the
outbox and is re-sent later.

`line_min_level` keeps LINE for what matters: 0 = every message may use LINE (default); 1 = not the
"all is well" weekly check-in; 2 = URGENT alerts only. The messages LINE does take are tried there
FIRST (then the others if LINE refuses); the rest skip LINE. With nothing else set up, LINE is still
used, and `--status` says so. The "LINE messages this month" line of the weekly check-in appears only
when LINE is really in use: the main channel, the one kept for urgent alerts, or a backup that had to
carry something since the last check-in.

How the two are sent:

- **Telegram**: `POST {telegram_api_base}/bot<token>/sendMessage` with `chat_id`, `text` and
  `link_preview_options: {is_disabled: true}`. No `parse_mode`: plain text, so `_` and `*` in a file
  name stay as they are. Messages over 4096 characters (UTF-16 units: an emoji counts twice) go in
  numbered parts. A reply with `"ok": false` counts as failed.
- **Discord**: `POST <webhook address>` with `content`, `allowed_mentions: {parse: []}` (an
  `@everyone` in an account or file name pings nobody) and `flags: 4` (no link previews). The text is
  wrapped in a code block, because Discord reads markdown everywhere: `__init__.php` would come out
  underlined and `[text](https://…)` in an account name would become a disguised link. Three backticks
  inside the text are broken up so they cannot close the block. 2000 characters per message; longer
  ones go in numbered parts, each its own block. `204 No Content` is success.
- **Too many requests (429)**: when the service asks for a short wait (3 seconds at most) the module
  waits and tries once more; a longer wait is not sat out (this may run inside a page view): the
  message goes on to the next channel at once.
- The Telegram token is part of the request address and the Discord address is the key itself, so
  neither is ever written to a record, an error reason or `--status`; a reason the service sends back
  is cleaned of both before it is shown. `line_timeout` is the time limit for all three services.

`php security-alerts-cron.php --test-all` sends the test message to each channel on its own and
prints, per channel, `sent` or the service's reason ("HTTP 401: Unauthorized" = wrong token,
"HTTP 400: Bad Request: chat not found" = wrong chat id or the bot was never started,
"HTTP 404: Unknown Webhook" = the webhook was deleted). The fake server in `scripts/` plays both
services, including 429, 500 and a slow answer; the modes are listed at the top of that file.

For anything else (Slack, ntfy, SMS…) there is `notifier`:

```php
'notifier' => function ($text, $level) {      // 0 = weekly check-in, 1 = notice, 2 = urgent
    return my_send_somewhere($text);          // true = delivered; false = let the next channel try
},
```

It is tried before all the others. If it returns false or throws, the message goes on down the line.
Messages sent through any chat channel (yours included) count towards `daily_cap`; e-mail does not.
Try yours against `scripts/fake_line_server.php` (`POST /hook/anything`) before pointing it at the
real service.

## 14. When an alert arrives

Give the owner the checklist in their language and ask them to keep it on their phone:

- English: [when-an-alert-arrives.md](when-an-alert-arrives.md)
- 繁體中文: [when-an-alert-arrives.zh-TW.md](when-an-alert-arrives.zh-TW.md)
