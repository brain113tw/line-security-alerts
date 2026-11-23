# LINE Security Alerts — hear about trouble on your website, on LINE

[中文](README.md) | [日本語](README.ja.md)

Intrusion alerts for small PHP websites (online shops, booking sites, self-hosted CMSs). Silent
while everything is normal; when something looks wrong you get one LINE message saying what
happened and what to do first.

It started at **沂恩精緻洗衣 (EN Laundry)**, a laundry shop in Taiwan. A small business has no
security team and nobody reads server logs, but everybody reads LINE. It worked well for us, so
here is a generic version for anyone.

## A real example

![What the alerts look like on a phone: two notices after the owner's own deployments on the left, a simulated backdoor on the right](docs/example-en.png)

**Left: recreated from the alerts the shop really received on one ordinary day** (file names and
counts made generic):

- A new admin feature was uploaded the evening before; the 7:00 AM scheduled check listed exactly
  which files were new and which had changed.
- One more file was updated later that morning; another notice arrived at the next check. (How often
  files are checked is up to you — every hour by default — and you can run a check by hand at any time.)

Both were the owner's own work, so a glance and a swipe is all they need. **That is exactly why it
is useful**: every time code on the site changes, you hear about it. The day you receive the same
message without having uploaded anything, somebody else changed your site — and you know that day,
not months later.

**Right: a simulation of "it was not you"** — a program dressed up as an image appears in the upload
folder while someone is guessing the admin password. The message is marked URGENT, everything found
in one run arrives as a single message, and it tells you what to do first.

Replay it yourself (no LINE account, no network, no real website involved):

```
php skills/line-security-alerts/scripts/demo.php --site="My Shop"
```

Every message in the picture is the real output of that demo script, not separately written copy.

**And when nothing is wrong?** Silence, except one check-in a week. A week without it tells you the
checks have stopped:

```
✅ Weekly check-in | EN Laundry (11/28 09:05)

Still on duty. Last 7 day(s): 2016 checks run, 4 thing(s) reported (1 urgent).
Watching 1850 code files; last full scan 11/28 07:00.
Code fingerprint: 3f9a-0c1d-77b2-e4a8. It comes with every check-in from now on; scroll up to compare with the one before.
LINE messages this month: about 37 of 200 used.
Records go back to 2026-11-20. If that date is newer than you remember, the records were reset: ask why.
You get this once a week. If a week passes without it, the checks have stopped running.
```

The line about LINE messages is asked from LINE once a week: an official account may only send so
many messages a month, and once they are used up nothing is delivered. From 80% on it becomes a
warning, in time to raise the plan or make sure the fallback e-mail is set. When LINE is only a
backup (your alerts normally go to Telegram or Discord) and was not needed that week, the line is left out.

What to do when a message arrives is written up for owners, not programmers:
**[When an alert arrives](skills/line-security-alerts/reference/when-an-alert-arrives.md)** (keep it on your phone).

### What is that "code fingerprint"?

Every code file on the site, boiled down to one short string. Change, add or delete any one of them
and the string changes.

The point: **the string is kept in your LINE chat history, not on the server.** Someone who breaks
in can change code and also edit the monitor's records so that everything "looks fine" — but they
cannot edit last week's message on your phone.

You do not have to compare by hand; the message states the conclusion:

| The message says | Meaning |
|---|---|
| same as the last check-in | No code changed this week |
| was xxxx; N code-change notice(s) were sent in between | It changed and you were told. If those were your own uploads, fine |
| was xxxx; N change(s) were written to the log but not sent | Files the site rewrites by itself, or the daily cap was reached. Have your developer read the log |
| ⚠ it changed, yet no code change is on record | The monitor's records may have been edited. Handle it as "possible backdoor" |

To check for yourself, scroll up to the previous check-in and compare the two strings. Your
developer can also compute the same string from the clean source on their own computer and compare
it with the one in LINE (see [integration.md, section 10](skills/line-security-alerts/reference/integration.md)):
if they are equal, the code on the server is exactly what you uploaded.

### When the schedule itself stops: outside check-in

The weekly check-in has one weakness: if the cron job dies, you only find out when "this week's
message did not come". To know sooner, use a "cron check-in" service such as healthchecks.io (it has
a free plan): it gives you an address, you put it in `ping_url`, and the module calls it after every
completed run. When the calls stop for longer than you allow (suggested: expected every 5 minutes,
10 minutes of grace), that service e-mails you or notifies you the way you chose.

It is optional; without it the module never connects anywhere but LINE. A failed check-in never
affects the checks, and the address is never written to a record or a message. If the address is
wrong and keeps failing, the weekly check-in gains a warning line.

## What it watches

| Area | When it speaks up | Level |
|---|---|---|
| Admin logins | Too many failures in an hour (overall or from one IP); a successful login from a browser **and** network that account has not used | Notice (URGENT when massive) |
| Admin accounts | Account created/deleted, role or permissions changed, e-mail/password changed, 2FA turned off, passkey added | URGENT / Notice |
| Server files | New code files, code files changed or deleted, code files inside upload folders, content that looks like a web shell, an edit whose modification time was put back | URGENT / Notice |
| Firewall | Too many blocked requests in an hour (overall or from one IP) | Notice |
| Money | A burst of manual refunds, paid-order cancellations or balance adjustments, or one unusually large one | Notice |
| Page content (optional) | A page starts loading code from another site, a form starts sending to another site, visitors get redirected away; spam links only Google is shown; new outside links | URGENT / Notice |
| Emergency brake (optional) | Someone pressed the brake link in an alert and the admin area is locked; unlocked by command | URGENT / Notice |
| Custom | Your own checks (e.g. a failed backup) | You choose |
| Itself | Fingerprints erased, the state folder wiped, the baseline reset by hand — trying to blind the monitor is itself reported | URGENT / Notice |
| Weekly check-in | One "still on duty" message a week with the number of checks run and things reported, plus a "code fingerprint" to compare with last week's | (not an alert) |
| Schedule stopped (optional) | Checks in with an outside service after every run; when the schedule dies, that service tells you within minutes | sent by that service |

Principles:

- **Quiet by default** — the same finding is reported once per 6 hours; at most `daily_cap`
  messages a day (URGENT ones always go out); the first run only records a baseline.
- **Never slows the site** — your code only appends a log line; LINE is called from a cron job
  every 5 minutes, not inside a visitor's request.
- **One channel fails, the next one takes over**: when LINE refuses (e.g. the free plan's monthly
  quota is used up) the message goes to Telegram, Discord or e-mail. If none can be reached, the alert
  is kept and sent as soon as delivery works again, marked with the time it is really from — it does
  not end up in a log file on the server and nowhere else.
- **Files are compared every hour, and all of them are re-read in full once a week.** The hourly
  check only re-reads files whose size or times changed (cheap); the weekly one ignores size and
  times, so even "edited, same length, modification time put back" cannot stay hidden.
- **One PHP file, no database tables** — state lives in a folder you choose. PHP 7.4–8.x, no framework.

It is **not** a firewall: it blocks nothing and repairs nothing, and it does not replace backups,
updates and strong passwords. Its job is to make sure you know, fast. By default it only reports and
never touches a file of your site. The one exception is the "automatic quarantine" below, which you
have to switch on yourself.

### Automatic quarantine (optional, off by default)

With `'quarantine_uploads' => true`, **a new program file that appears inside an upload folder** is
renamed at once so that the server no longer runs it. `uploads/avatar.jpg.php`, for example, becomes
`avatar_jpg_php-20261125-031500.quarantined` in the same folder; the alert gives both names.

It is deliberately small:

- **Renamed, never deleted.** The file is the evidence of how someone got in.
- **Only NEW program files inside upload folders.** Files anywhere else, files that were already
  there, and server config files such as `.htaccess` are never touched, only reported.
- **To undo it, rename the file back.**
- If renaming fails (no permission), the alert says plainly that the file can still run.

Before switching it on, check two things: `upload_dirs` really lists folders meant for pictures and
documents only; and during the time you ran without quarantine you never received a "program in an
upload folder" alert that turned out to be your own people. If you did, exclude that folder first.

It is a speed bump, not a wall. Checks run at intervals (every hour by default, every cron run at
best), so the file may have been used before it is renamed. Everything you would do after such an
alert — change passwords, find out how they got in — still has to be done.

One limit to be clear about: it runs on the same server and as the same user as your website. An
intruder with the same rights as the site could, in principle, alter the monitor itself. That is why
some things are kept OUTSIDE the server — every alert and the weekly fingerprint in your LINE chat,
and the outside check-in — so that doing it without leaving a trace is hard.

### Something slipped into your pages: page watch (optional)

On many small sites a break-in changes no file at all. It changes **content in the database**, where
comparing files cannot see it:

- **Gambling or adult spam links** added to an article or a footer setting, often shown only to
  Google's crawler. The site looks normal to you; you find out when search results show casino titles.
- **Card skimming**: a script from another site added to a footer setting, sending what customers type
  at checkout elsewhere.
- **Visitors from Google sent away**: only people arriving from a search result are redirected, so
  typing the address yourself shows nothing wrong.

Name a few pages to watch:

```php
'page_watch' => array('https://example.com/', 'https://example.com/cart'),
```

Every hour the scheduled job reads them four ways: a desktop browser, a phone, Google's crawler, and a
phone arriving from a Google search. For each page it notes which **other sites** it uses (code it
loads, things it embeds, where forms send, redirects, outside links) and compares with last time:

| Found | Level |
|---|---|
| Links, code or a redirect that only the crawler or visitors from Google get | URGENT |
| A new outside site for code, embedded frames, form targets or redirects | URGENT |
| New outside links that everybody sees | Notice |

The first read only records what is there. So after setting it up, run `--pages` once: it lists the
outside sites of each page as they are now and marks what only search engines get. Make sure nothing
in there is strange before it becomes the baseline.

Good to know:

- Pick pages whose content is **stable** (home, one product, the cart), not a list that gains links to
  new articles every day.
- Adding a chat box, a payment or analytics service of your own causes one alert. When it is yours,
  put the site into `page_allow` and it stays quiet.
- Site names are written as `example[.]com` on purpose: chat apps turn a bare domain into a link, and
  this may be an attacker's site.
- It runs from the scheduled job (command line) only, never while a visitor is loading a page.
- It plays Google's crawler from inside your server, which only goes so far: some injections check for
  Google's real IP addresses before showing spam. Google Search Console's "Security issues" report
  covers that part.
- If a firewall in front of the site blocks fake Google crawlers, the crawler view keeps failing;
  `--status` says so, and the other three views are compared as usual.

### Announce your own updates (--expect)

When every upload sets off alerts, people stop reading them, and the one that matters gets swiped
away with the rest. Before uploading, run:

```
php security-alerts-cron.php --expect 30m
```

It first runs every check (whatever changed before is reported as usual). For the next 30 minutes,
ordinary code changes are not reported one at a time; when the window ends they come as **one
message**: "Code changes during your announced update: 3 new, 12 changed, 1 deleted", with the names.
Done early? `--expect off` sends it right away.

An announcement is no cover:

- Backdoor-like content, programs in upload folders and edits with the modification time put back are
  **still reported at once**, window or not.
- A window lasts at most 4 hours. Even if someone on the server secretly writes "expect changes until
  2099", the summary still comes 4 hours later and lists what they changed.
- The summary ends with: if nobody updated the site at that time, treat it as a break-in.

With automated deployments, put `--expect 20m` at the start of the deploy and `--expect off` at the end.

### Emergency brake (optional)

An URGENT alert at 3 a.m., and no developer to call: what can an owner who does not code do? Once set
up, every URGENT alert ends with one more line:

```
🛑 Not your doing, and nobody to call? Lock the admin area for 4 hours (the shop stays open): https://example.com/security-brake.php?t=…
```

Opening the link only shows a page with a button (LINE opens links to build previews, so opening must
never lock anything). **Pressing the button** locks the admin area for 4 hours: nobody can sign in or
use it, including whoever is already signed in; customers keep shopping. The next run sends "The
admin area is locked", with the time and the IP the button was pressed from.

- The link is signed, works once and expires after 24 hours; a tampered link just gets "Not found".
- The web side can **only lock**. Unlocking is `--unlock` on the server, or waiting.
- Worst case, someone who can read your alerts presses it: the admin area is locked for a few hours,
  and you are told at once.
- Your developer does three things: puts `examples/security-brake.php` into the site, sets `brake_url`
  and a `brake_secret` of 32+ characters, and adds one `adminLocked()` check at the top of every admin
  page ([integration.md, section 16](skills/line-security-alerts/reference/integration.md)). Without
  that check, pressing locks nothing.

## Where it fits among other tools

What this package is for: **shared hosting, no root access, a custom or hand-written PHP site, and
an owner who reads LINE all day**. Other tools do some things better, and they combine well:

| Your situation | Suggestion |
|---|---|
| The site is WordPress | Install a security plugin such as Wordfence or Sucuri. They know what every WordPress file is supposed to look like and have malware signatures maintained by a team — two things this package does not have. It can run next to them and add the LINE alerts |
| You want attacks stopped before they arrive | Put a service such as Cloudflare in front of the site. Blocking belongs outside the server; this package reports, it does not block |
| Your host offers malware scanning (Imunify360, maldet…) | Ask them to switch it on. It scans the whole account and can quarantine; this package only watches the code files in your site folder |
| You run your own server (VPS, root) | Wazuh or AIDE (file-integrity monitoring whose baseline can be kept on another machine; Wazuh can also watch in real time) and fail2ban or CrowdSec (automatic blocking) are available to you. They cannot be installed on shared hosting |
| "Is my cron job still running?" | A cron check-in service such as healthchecks.io; put its address into `ping_url` |
| "Can people open my site?" | An outside uptime monitor such as UptimeRobot. This package runs inside the server: if the whole server is down, it cannot send anything |
| "Does Google think my site was hacked?" | Google Search Console, "Security issues". It sees what Google's real crawler gets, including injections the page watch cannot trigger from your server |

Legal duties after a breach differ by country. The [Traditional Chinese README](README.md) sums up
Taiwan's (personal data law, the 72-hour rule for online retailers) and the
[Japanese README](README.ja.md) Japan's (APPI reporting, the IPA EC-site guideline, the credit-card
security guideline), each with official sources. Not legal advice.

It uses the **LINE Messaging API**. LINE Notify, which many older guides rely on, was shut down on
31 March 2025.

This package covers "tell me when it happened". What to do beforehand — upload folders that cannot
run programs, one more door in front of the admin area… — is collected in the
**[prevention checklist](skills/line-security-alerts/reference/hardening-checklist.md)**; several
items came from readers.

## Install

### A. Let Claude Code wire it in (recommended)

```
/plugin marketplace add brain113tw/line-security-alerts
/plugin install line-security-alerts@line-security-tools
```

Then, inside your website's project, ask Claude: "Add LINE security alerts to my site."
Claude surveys where logins, admin accounts, uploads and money operations live, confirms with you,
adds the hooks, tests everything against the bundled fake LINE server, and only then asks you to
send one real test message.

**To install a fixed, reviewed version** (advisable for a security tool), add the release tag:

```
/plugin marketplace add brain113tw/line-security-alerts#v1.3.0
/plugin install line-security-alerts@line-security-tools
```

The code then does not change under you (third-party marketplaces do not auto-update by default
anyway). To upgrade, read [CHANGELOG.md](CHANGELOG.md), then remove the marketplace and add it again
with the new tag. From 1.3.0 on, every release on GitHub's Releases page lists the SHA-256 of
`lib/SecurityAlerts.php`, to compare with the file you got (`sha256sum`, or
`php skills/line-security-alerts/scripts/fingerprint.php`).

### B. Copy the skill only

Copy `skills/line-security-alerts/` to `~/.claude/skills/` (all projects) or to `.claude/skills/`
inside a project.

### C. Without Claude

```php
require 'lib/SecurityAlerts.php';
$alerts = new SecurityAlerts(require '/outside/webroot/security-alerts.config.php');

$alerts->loginFailed($user, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '', $accountExists);
$alerts->loginSucceeded($user, $ip, $_SERVER['HTTP_USER_AGENT'] ?? '');
$alerts->accountChanged('role', $targetUser, $actingAdmin, 'editor -> administrator');
$alerts->firewallBlocked($ip, 'sqli', $_SERVER['REQUEST_URI']);
$alerts->moneyEvent('refund', 1200, $actingAdmin, $orderNo);
```

Every 5 minutes:

```
*/5 * * * *  /usr/bin/php /path/to/security-alerts-cron.php >> /path/to/security-alerts-cron.log 2>&1
```

After installing and running it once, run:

```
php security-alerts-cron.php --audit
```

The first run takes the server as it is today for "normal". If a backdoor was already there before
you installed the module, it becomes part of normal too. `--audit` reads every code file and lists
the ones that look suspicious or sit in an upload folder, for you or your developer to go through.
Legitimate code can match as well, so it only prints a list: nothing is sent, no file is touched.

Later, to answer "is it still all right?", run:

```
php security-alerts-cron.php --status
```

It shows when the checks last ran, how many files are watched, what was reported recently, whether
any alert is stuck waiting, and marks with `!!` whatever needs a look. Read-only as well (it only asks
LINE how many friends the alert account has).

Before uploading an update, run `--expect 30m` (see "Announce your own updates" above). With page
watch set up, run `--pages` once.

Where each hook goes and how to configure the file scan:
[skills/line-security-alerts/reference/integration.md](skills/line-security-alerts/reference/integration.md).

## What you need from LINE

1. **A LINE Official Account made only for these alerts** — not the one your customers follow — with
   the Messaging API enabled. The reason: the key lives on your web server, so whoever breaks in has it
   too. With your customers' account, they could message every customer you have (a fake "payment
   failed, tap here", say). An alerts-only account has you and a few colleagues as friends; a stolen
   key there can do little. `--status`, `--test-all` and the weekly check-in ask LINE roughly how many
   friends the account has and warn above 20.
2. A **long-lived channel access token** from the LINE Developers console.
3. **Your user ID** (starts with `U`, under Basic settings) as the recipient; add the account as a
   friend on your phone.
4. Run `php security-alerts-cron.php --test`. If your phone buzzes, you are done.

Step by step, with an error-code table: [reference/line-setup.md](skills/line-security-alerts/reference/line-setup.md).

## Telegram or Discord instead (or as well)

LINE's free allowance is limited (about 200 messages a month on the free plan; plans differ by country)
and more costs money. Telegram and Discord are built in as well, and both are free. Use one of them,
or set up several so they back each other up.

| | LINE | Telegram | Discord |
|---|---|---|---|
| Cost | Free plan about 200 messages a month, then a paid plan | Free | Free |
| Setting up | Medium: official account, Messaging API, token and user ID | Easy: ask `@BotFather` for a token, then look up the chat id | Easy: create a webhook in the server settings, copy its address |
| Seen at once? | In Taiwan nearly everyone has LINE open all day | The app must be installed with notifications on | The app must be installed, and this channel's notifications set to "All" (many servers notify only on mentions by default) |
| If the key leaks | Messages can be sent from your official account to **everyone** who added it, using up your allowance. Hence an account made only for alerts | Full control of the bot: send as it, receive what people send to it | Anything can be posted to that channel, and the webhook can be deleted (alerts then go to the next channel automatically) |

Whatever you use, keep the key like the LINE token: environment variable, not version control, no screenshots.

### Setting up Telegram

1. In Telegram, find `@BotFather` (the official one, with the blue check), send `/newbot` and answer
   its questions. You get a token like `123456789:AAH…`: that is `telegram_bot_token`.
2. On your phone, open the new bot and tap START. For a group: add the bot to the group and send
   `/start` there.
3. Open `https://api.telegram.org/bot<token>/getUpdates` in a browser (your token in place of `<token>`)
   and find the number after `"chat":{"id":`: that is `telegram_chat_id` (negative for a group).
   The address contains your token: do not share a screenshot of it.
4. Run `php security-alerts-cron.php --test-all`. If your phone buzzes, you are done.

### Setting up Discord

1. Open Server Settings → Integrations → Create Webhook, pick the channel that should get the
   alerts from the drop-down, then press Copy Webhook URL. You need permission to manage webhooks
   (you have it on a server you created).
2. Put the address into `discord_webhook_url`.
3. On your phone, long-press the channel → Notification Settings → All.
4. Run `php security-alerts-cron.php --test-all`.

On Discord the message is shown in a grey code box. That keeps underscores and asterisks in file names
from turning into formatting, and an account name containing `@everyone` or a fake link neither pings
the whole server nor becomes something to click.

### Several channels set up: where does a message go?

To one place only. They are tried in the order **Telegram → Discord → LINE → e-mail**; the first one
that takes the message stops the line, so nothing arrives twice. (A `notifier` of your own is tried
before all of them.)

To keep LINE's allowance for what really matters, add:

```php
'line_min_level' => 2,
```

With 2, **URGENT alerts go to LINE first** (and to the others if LINE refuses), while notices and the
weekly check-in go to Telegram, Discord or e-mail. With 1, only the weekly check-in stays off LINE. If
nothing but LINE is set up, LINE is still used (better than nowhere) and `--status` points it out.

`--test-all` sends a test to every channel that is set up, each on its own, and says why one failed
(for example "HTTP 401: Unauthorized" = wrong token). `--test` sends one message the way a notice
would go and says which channel took it.

**Other channels (Slack, SMS…):** set `notifier` to a function of your own. It is tried first; when it
succeeds nothing else is used. The shape is at the end of the config template.

## Main settings

| Key | Default | Meaning |
|---|---|---|
| `state_dir` | (required) | Logs and fingerprints; ideally outside the web root |
| `line_channel_access_token`, `line_to` | | LINE token and recipients (environment variables, not version control) |
| `telegram_bot_token`, `telegram_chat_id` | | Telegram bot token and chat (optional); token in an environment variable |
| `discord_webhook_url` | | Discord channel webhook address (optional); the address itself is the key |
| `line_min_level` | 0 | Which messages may use LINE: 0 = all; 1 = not the weekly check-in; 2 = URGENT only (tried on LINE first) |
| `mail_to` | | E-mail, when every other channel fails |
| `language` | `en` | `en` or `zh-TW` |
| `site_root`, `exclude_dirs`, `upload_dirs`, `runtime_dirs` | | File-scan scope; exclude cache folders |
| `scan_hours` | 1 | Hours between file checks; 0 = on every run (every 5 minutes). Only files whose size or times changed are re-read |
| `rehash_days` | 7 | Days between full re-reads of every file (0 = never) |
| `input_charset` | | For old sites whose file or account names are not UTF-8: name the encoding (e.g. `BIG5`) and they show properly in messages; left empty they show as `?`. Detection works either way |
| `extra_rules`, `disable_rules` | | Your own suspicious patterns (e.g. a string from a past incident); switch off a built-in rule that matches your own code |
| `quarantine_uploads` | off | Rename (never delete) new program files that appear in upload folders; see "Automatic quarantine" above |
| `page_watch` | | Addresses of pages to watch (optional); see "page watch" above |
| `page_allow` | | Outside sites your pages use on purpose (e.g. `googletagmanager.com`, sub-domains included): never reported |
| `page_watch_hours` / `page_links` | 1 / on | Hours between page reads / whether new outside links are reported |
| `line_friends_warn` | 20 | Warn when the LINE account that sends alerts has more friends than this (0 = do not ask) |
| `brake_url`, `brake_secret` | | Emergency brake (optional): the brake page's address, a secret of 32+ characters; see "Emergency brake" above |
| `brake_hours` / `brake_link_hours` | 4 / 24 | Hours the admin area stays locked / hours a link stays valid |
| `brake_allow_ips` | | IPs never locked out (e.g. your developer's fixed IP) |
| `quiet_hours` / `daily_cap` | 6 / 10 | Repeat window / messages per day |
| `heartbeat_days` | 7 | Days between "still on duty" messages (0 = never) |
| `line_quota_check` | on | With the weekly check-in, ask LINE how many messages were sent this month and what the limit is |
| `witness_file` | | A small file OUTSIDE the state folder; reveals a wiped state folder |
| `ping_url` | | Address from an outside "cron check-in" service (optional). Keep it like a password: environment variable |
| `notifier` | | A channel of your own (optional, e.g. Slack, SMS); tried first |
| `login_fail_hour` / `login_fail_ip_hour` | 10 / 5 | Failed logins per hour before an alert |
| `firewall_hour` / `firewall_ip_hour` | 50 / 20 | Blocked requests per hour before an alert |
| `refund_*`, `cancel_*`, `adjust_*` | counts 3–5, amounts 0 (off) | Set amounts for your currency |

The full list is `SecurityAlerts::defaults()`. Thresholds are starting points — tune after a week.

## Testing (no LINE account needed)

```
php skills/line-security-alerts/scripts/selftest.php
```

261 scenario checks (logins, devices, accounts, firewall, money, files, web-shell patterns, weekly
check-in and fingerprint, wiped or edited records, upgrading old fingerprints, outside check-in,
quarantine, timestamps put back, delayed delivery, non-UTF-8 names, daily cap, e-mail fallback,
Telegram / Discord order, long messages in parts, "too many requests", update windows, LINE friend
count, page watch read four ways and links shown only to the crawler, the emergency brake…), no network. On every change GitHub runs them again on Linux (PHP 7.4–8.5)
and Windows.

> **⚠️ Your antivirus may raise a warning — that is expected**
>
> To prove that backdoors really are detected, the self-test writes a few **look-alike bait files**
> into a folder named `lsa-selftest-…` in the system temp directory. Each is a single line, is never
> executed, and is deleted when the test ends. Windows Defender and other antivirus tools may pop up
> "threat found" and block or quarantine one of them.
>
> That means the bait is convincing. **Your computer is not infected and this package does not ship
> malware**: nothing is installed and nothing keeps running. Every bait is readable in
> `scripts/selftest.php` (the strings passed to `bait()`). A blocked bait is simply skipped; the
> other checks still run.
>
> `lib/SecurityAlerts.php` also contains a list of web-shell signatures to match against. The
> signature strings are split up so scanners do not mistake the list for the real thing; if your
> host's malware scanner flags the file anyway, whitelist it.

To see real HTTP requests, run the bundled fake LINE server:

```
php -S 127.0.0.1:18765 skills/line-security-alerts/scripts/fake_line_server.php
```

and set `'line_api_base' => 'http://127.0.0.1:18765'`; messages are printed in that terminal. The same
fake server also plays the outside check-in service (`'ping_url' => 'http://127.0.0.1:18765/ping/test'`),
so you can try that without signing up anywhere. It plays Telegram and Discord too, including
"too many requests", server errors and slow answers (see the top of `scripts/fake_line_server.php`).
It also has a fake shop at `/shop/`: open `/shop/hack` and it turns "hacked" (a skimming script, links
only the crawler gets, visitors from Google redirected away), for trying the page watch.

## Security and privacy

- Keep the token in environment variables or a config file outside the web root and out of version
  control. The same goes for the check-in address (`ping_url`): whoever has it can check in for you.
  The Telegram token becomes part of the address a message is sent to, and a Discord webhook address
  is itself the key, so these addresses are never written to a record, an error or `--status`.
- File fingerprints are SHA-256. The admin snapshot stores only SHA-256 fingerprints of e-mail,
  password hash and permissions, never the values.
- Messages carry summaries only (account names, IPs, file names, amounts) — no passwords, no customer data.
- The outside check-in is one empty request: no site name, file name or alert text is sent to that service.
- The page watch reads only the addresses you list, from your own server. The pages go nowhere; only
  "which outside sites they use" is kept in the state folder.
- Test on a local or staging copy; never attack your production site to "see if it works".
- Found a security problem in this package itself? Please do not publish the details; see
  [SECURITY.md](SECURITY.md).

### What this skill tells Claude to do, and not to do

Installing someone else's skill means letting it instruct your Claude, so here it is plainly.
[SKILL.md](skills/line-security-alerts/SKILL.md) is plain text; read it yourself. It tells Claude:

- **To do**: read your site's code to find logins, accounts and uploads, and confirm them with you
  first; copy `lib/SecurityAlerts.php` into your project and add one line at each of those places;
  test locally against the bundled fake servers; send one real test message **only with your OK**.
- **Not to do**: download or run any other code from the internet; put keys, user IDs or webhook
  addresses into messages, logs, version control or its own replies; sign you up for outside
  services; attack your live site to test; delete files or block IPs on its own; change server
  settings or DNS; switch on anything that acts (quarantine, emergency brake) unless you ask.
- The plugin ships no hooks, no MCP server and nothing that runs in the background: documents and PHP
  files only.

What changed in each version is in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. Use it, change it, share it.
