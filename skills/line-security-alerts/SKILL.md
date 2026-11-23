---
name: line-security-alerts
description: Add "something looks wrong" security alerts to a PHP website, pushed to the owner's LINE (Telegram and Discord built in too, with e-mail fallback). Covers failed or new-device admin logins, admin account changes, new/changed code files and web shells, firewall blocks, unusual refunds or balance adjustments, and pages that start loading code, sending forms or linking to other sites (card skimming, spam links shown only to Google). Stays silent when nothing is wrong. Use when someone wants intrusion alerts, file-integrity monitoring, defacement or SEO-spam detection, or admin-login alerts on LINE for a small PHP site, shop or CMS. Also for requests in Japanese (LINEでセキュリティ通知、サイト改ざん検知、不正ログイン通知).
license: MIT
---

# LINE Security Alerts

A single-file PHP module (`lib/SecurityAlerts.php`) plus a way of wiring it in. It was built for a
small business that has no security team: the owner should hear about trouble on the phone they
already watch all day, and hear **nothing** the rest of the time.

How it works, in one paragraph: the site calls tiny hooks (`loginFailed()`, `firewallBlocked()`, …)
that only append a line to a log file. Every 5 minutes a cron job (or `tick()` on normal page
views) reads those logs, walks the code files, decides what is abnormal and sends **one** combined
LINE message. The same finding is not repeated for 6 hours, at most `daily_cap` messages go out a
day (URGENT ones always go out), and if LINE refuses, the message goes to the next channel (Telegram,
Discord, e-mail — whichever are set up). The first run
learns a baseline and sends nothing. Because silence could also mean "broken", it sends one "still
on duty" message a week, and it raises an alert if its own records are wiped or reset. That weekly
message carries one fingerprint of all code files, so the owner's chat history is a reference copy
outside the server; and an optional check-in address (`ping_url`) lets an outside service report a
dead cron job within minutes.

Read these when you need them:

- [reference/integration.md](reference/integration.md) — where each hook goes, with plain-PHP examples; how the monitor watches itself; the outside check-in; comparing the code fingerprint; `--audit` and custom rules; the optional quarantine of uploaded programs; using another channel than LINE
- [reference/when-an-alert-arrives.md](reference/when-an-alert-arrives.md) / [繁體中文](reference/when-an-alert-arrives.zh-TW.md) / [日本語](reference/when-an-alert-arrives.ja.md) — the owner's checklist: what each message means and what to do first
- [reference/hardening-checklist.md](reference/hardening-checklist.md) / [繁體中文](reference/hardening-checklist.zh-TW.md) / [日本語](reference/hardening-checklist.ja.md) — the prevention side: what makes a break-in less likely in the first place
- [reference/line-setup.md](reference/line-setup.md) — getting a channel access token and the user/group ID
- [examples/](examples/) — a config template, the cron entry point (`--status`, `--test`, `--test-all`, `--audit`, `--pages`, `--expect 30m` / `--expect off`, `--lock` / `--unlock`, `--fingerprint`, `--manifest`, `--rebaseline`) and the optional emergency-brake page (`security-brake.php`)
- `scripts/selftest.php` — 261 checks, no network; `scripts/fake_line_server.php` — a local stand-in for LINE, Telegram, Discord, the check-in service, a webhook, and a small shop that can be switched to "hacked" (`/shop/hack`) for trying the page watch
- `scripts/fingerprint.php` — the code fingerprint of any folder, to compare a clean local copy with the one the server reports
- `scripts/demo.php` — replays a few days at a small shop and prints the exact messages the owner
  would get (`--lang=zh-TW`, `--site="Their shop"`). Run it and show the output when the user asks
  "what will I actually receive?" — before installing anything. It writes only harmless files to a
  temp folder and sends nothing.

## Workflow

Follow these steps in order. Tell the user what you found at step 1 before changing anything.

### 1. Survey the site (read-only)

Find and note, with file paths:

1. PHP version (`php -v` on the server if possible, or the hosting panel). The module needs 7.4+.
2. **The admin login handler**: the code path where a password (or passkey / 2FA) is checked and the
   result is known. Note whether it can tell "wrong password for a real account" from "no such user".
3. **Admin account management**: where admin users are created, deleted, and where role,
   permissions, e-mail, password, 2FA and passkeys change.
4. **Request filtering**: an existing firewall / WAF function, rate limiter or login throttle that
   decides to block a request. If there is none, skip the firewall hook (do not write a WAF now).
5. **Money operations done by staff**: manual refunds, cancelling paid orders, manual balance or
   points adjustments. Note the currency, because the money thresholds are amounts.
6. **Folders**: web root; where users upload files; cache / compiled-template folders; any folder
   where the application itself writes `.php` files (generated config, plugin installs).
7. **Scheduling**: can they add a cron job (hosting panel "Cron Jobs", `crontab -e`)? If not,
   plan to use `tick()` on page views.
8. **Secrets handling**: does the project already keep secrets in environment variables or in a
   config file outside version control? Use the same place for the LINE token (and the Telegram
   token or Discord webhook address, if the user wants one of those).
9. **Channel**: LINE, Telegram, Discord, or several? Show the user the comparison in the README
   (cost, setup, whether they will see it at once, what a leaked key allows). For a Taiwanese shop
   owner LINE is usually the one they see first; Telegram or Discord can carry the routine messages
   with `line_min_level => 2`. Let them create the bot or webhook themselves.
   **For LINE, ask which official account they mean to use.** If it is the one their customers follow
   (it already has a token because the site sends order messages, say), explain why alerts need an
   account of their own: the token lives on the server, and whoever breaks in could message every
   customer. Recommend a new, alerts-only account; the module warns about one with more than 20 friends.
10. **Outside monitoring**: does the user already use a cron-monitoring / uptime service? If so, its
   check-in address can go into `ping_url`. If not, mention the option and let the user decide and
   sign up themselves.
11. **Pages worth watching** (optional `page_watch`): content kept in the database (articles, footer or
   header settings, widgets, "extra code" fields) can be changed without touching a file. Suggest two
   or three stable pages: the home page, one product page, the cart or checkout page if it can be
   opened without logging in. Not news lists that gain new outside links every day. Note the outside
   services the pages use on purpose (analytics, chat, payment) for `page_allow`, but only the ones
   the user recognises.

### 2. Install the library

- Copy `lib/SecurityAlerts.php` into the project's library folder. Do not rename the class unless it
  collides with an existing one.
- Create the config from `examples/security-alerts.config.example.php`. Put it outside the web root
  if possible and add it to `.gitignore`. Never write the token into a file that is committed.
- `state_dir` must be writable by both the web server user and the cron user. Prefer a folder
  outside the web root. If it must be inside, the module drops a deny-all `.htaccess` (Apache);
  for nginx, add a `deny all` location and verify with a request that it returns 403/404.
- Set `exclude_dirs` (caches, compiled templates, logs), `upload_dirs` and `runtime_dirs` from step 1.
- Set `witness_file` to a path outside both the web root and `state_dir` (the account's home folder
  is a good place). It lets the module raise an alert if someone wipes its records.
- Leave `heartbeat_days` at 7 unless the user objects: the weekly "still on duty" message is how they
  find out that the checks have stopped, and it carries the code fingerprint.
- `ping_url` (optional): only if the user gives you a check-in address from a service they chose.
  It goes where the token goes (environment variable / config outside version control), never into
  a committed file, a log or your replies. Settings on that service: a call expected every 5 minutes
  (the cron interval), about 10 minutes of grace.
- `scan_hours`: 1 by default. On a site of ordinary size `0` (check files on every run) is fine and
  shortens the time to notice from an hour to minutes; say what you chose and why. Leave
  `rehash_days` at 7 (the weekly full re-read of every file).
- `input_charset`: only if the survey found file or account names that are not UTF-8 (old sites with
  Big5 / GBK / Latin-1 names). Then also run the self-test on the server itself.
- `page_watch` / `page_allow`: from step 1.11, if the user wants it. Only the user's own pages, never
  someone else's site. It runs from the cron job only (not from `tick()` in a page view).
- Emergency brake (only if the user asks for it): copy `examples/security-brake.php` into the web root,
  set `brake_url` and have the user put a `brake_secret` of 32+ random characters into the environment;
  then add `adminLocked($ip)` at the top of EVERY admin request and in the login handler (integration.md,
  section 16), leaving out machine callbacks (payments, webhooks, cron URLs). Test it on a local copy:
  `--lock 1h` must lock you out of the admin, `--unlock` must let you back in.

### 3. Add the hooks

Place each hook **after** the outcome is known and never let it change the outcome. Hooks do not
throw on I/O problems, but wrap them anyway if the surrounding code is fragile. Construct the object
once per request (a small helper function that returns a shared instance is fine).

| Event | Call |
|---|---|
| Admin login failed | `loginFailed($user, $ip, $ua, $accountExists)` |
| Admin login succeeded | `loginSucceeded($user, $ip, $ua)` |
| Admin account changed | `accountChanged($what, $target, $actor, $detail)` — `$what`: created, deleted, role, permissions, email, password, 2fa_disabled, passkey_added |
| Request blocked | `firewallBlocked($ip, $ruleName, $path)` |
| Staff money action | `moneyEvent('refund' \| 'cancel' \| 'cancel_paid' \| 'balance_adjust', $amount, $actor, $orderRef)` |
| Anything else | `custom($title, $lines, SecurityAlerts::NOTICE, $dedupeKey)` |

Use the IP the rest of the app trusts. Behind a proxy/CDN, only take the forwarded header when the
request really came from that proxy — otherwise attackers can choose the IP you log.

Details and examples: [reference/integration.md](reference/integration.md).

If admin accounts can change outside the admin UI (another tool, direct database edits), also set
the `admin_snapshot` callable so the module diffs the admin list on every run.

### 4. Schedule the checks

Preferred: cron every 5 minutes running `examples/security-alerts-cron.php` (adjust its two
`require` paths). Without cron: call `$alerts->tick()` at the end of requests, ideally after
`fastcgi_finish_request()`, so a visitor never waits for the file scan.

### 5. Verify — in this order

1. `php scripts/selftest.php` on the server's PHP version → must print `0 failed`.
   **Before you run it, tell the user**: the test writes a few one-line look-alike backdoor samples
   ("bait") into a `lsa-selftest-…` folder in the system temp directory and deletes them afterwards;
   antivirus software (e.g. Windows Defender) may pop up "threat found" and quarantine one. That is
   the bait working, not an infection, and nothing is installed. Do not run the self-test without
   saying this first — an unexplained antivirus alert looks exactly like you planting malware.
2. Start `php -S 127.0.0.1:18765 scripts/fake_line_server.php`, set `line_api_base` to it, run
   `php security-alerts-cron.php --test` (with Telegram or Discord also `telegram_api_base` /
   a webhook address on the fake server, see the top of that file, and `--test-all`), then trigger
   one finding on a **staging or local copy**
   (e.g. several wrong passwords) and run the cron script; read what the fake server printed.
   Stop the fake server afterwards (by its PID).
3. Remove `line_api_base` (and the fake Telegram / Discord addresses), put the real keys in, run
   `--test-all` once and ask the user to confirm that every channel arrived on their phone. A failing
   channel prints the service's reason (e.g. "HTTP 400: Bad Request: chat not found").
4. Run the cron script once more: the first real run records the baseline and must send nothing.
5. **Look at what was already there.** The baseline trusts the server as it is; a backdoor planted
   before the install would become "normal". Run `php security-alerts-cron.php --audit` and go
   through every listed file with the user: open it, say what it is, and decide together. Expect
   legitimate hits (libraries that run commands, old code that builds functions at run time). Do not
   delete, move or "clean" anything on your own — a suspicious file is evidence; report it.
   With `page_watch`, do the same for the pages: `php security-alerts-cron.php --pages` lists the
   outside sites each page uses, read four ways, and marks with `!!` what only search engines or
   visitors from Google get. Go through the list with the user; anything they do not recognise
   (especially an `!!` line, a script from an unknown site, a form sending elsewhere) is looked at
   before the first run turns it into the baseline. Locally, `/shop/` on the fake server plays a site
   that can be switched to "hacked".
6. Check the cron log after the first scheduled runs: each line is a JSON summary. With `ping_url`
   set it must contain `"ping":"ok"`, and the user should see the check turn green on the service's
   own page. To try the check-in without a real service, point `ping_url` at the fake server
   (`http://127.0.0.1:18765/ping/test`).
7. `php security-alerts-cron.php --fingerprint` shows the code fingerprint the weekly message will
   carry and whether the files on disk still match the records.
8. `php security-alerts-cron.php --status` must end with "nothing needs a look" (or only with lines
   you have explained to the user, such as a missing fallback e-mail). Use the same command first
   whenever the user later asks whether the alerts still work; it never prints a token, a recipient
   or chat id, a webhook or the check-in address. It shows the order the channels are tried in and
   roughly how many friends the LINE account has (`!!` above 20: see step 1.9).

### 6. Hand-over to the user

Tell the user, in their language:

- what each kind of message means and the first thing to do: give them the checklist in their
  language ([English](reference/when-an-alert-arrives.md), [繁體中文](reference/when-an-alert-arrives.zh-TW.md),
  [日本語](reference/when-an-alert-arrives.ja.md); README.ja.md for a Japanese-speaking owner — the alert texts
  themselves are English or Traditional Chinese, so say which `language` you chose)
  and ask them to keep it on their phone, not only on the server;
- that after their own deployments they will get a "code files changed" notice — expected. Better:
  run `--expect 30m` before uploading (and `--expect off` when done): the changes then come as one
  summary, while anything backdoor-like is still reported at once. In a deploy script, put those two
  around the upload. After a big trusted deployment they can also run `--rebaseline` (itself announced);
- with the emergency brake: the last line of an URGENT alert locks the admin area for a few hours
  (opening the link only shows a button; the button locks), the shop stays open, only the developer
  can unlock (`--unlock`), and pressing it is announced. Who should press it, when: the owner, when an
  alert is not their own doing and nobody can be reached;
- with `page_watch`: what the three page alerts mean (a new outside script / form target / redirect;
  something only search engines or Google visitors get; new outside links), that site names are
  written as `name[.]com` on purpose, and that adding a service of their own means one alert, after
  which the site goes into `page_allow`;
- that once a week they get a short "still on duty" message, and that a week WITHOUT it means the
  checks have stopped and they should call you or their developer;
- that the weekly message ends with a "code fingerprint" and says whether it equals last week's.
  They should not delete those messages: the chat history is the copy an intruder cannot rewrite.
  A check-in that starts with ⚠ needs attention the same day;
- if `ping_url` is set: which service will contact them when the schedule stops, and through what
  (e-mail, app…), so that message is not mistaken for spam;
- that a message starting with "Delayed" is an older alert that could not be delivered at the time;
  the time in it is when the thing happened;
- where the logs are (`state_dir/findings.ndjson` keeps every finding, sent or not), and that
  `--status` summarises them;
- the prevention checklist in their language. Point out the items your survey showed are missing
  (for example an upload folder that can run programs), but do not change server settings, add
  password protection or touch DNS on your own: describe the step and let them decide;
- that the weekly message also says how much of the month's LINE allowance is used, and that a ⚠ on
  that line means: raise the LINE plan or make sure the fallback e-mail is set;
- that thresholds are starting points to tune after a week of real traffic.

## Rules for you (the agent)

- Never print, log or commit the channel access token, user IDs, the Telegram bot token or chat id,
  the Discord webhook address, the check-in address (`ping_url`), or the contents of config files that
  hold them. A `getUpdates` page or a webhook address in a screenshot is a leaked key. Ask the user to paste them into the config
  themselves if needed.
- Do not sign the user up for outside services (cron monitoring, chat webhooks) and do not choose
  one for them silently; explain the option, they create the account.
- The module only reports. Do not add automatic deletion or IP blocking on your own initiative: a
  false positive would take the site down or lock the owner out. If the user asks for that, explain
  the risk first and build it as a separate, reversible step.
- `page_watch` lists the user's own pages only. Do not put a site into `page_allow` that the user has
  not recognised as theirs: the allow list is exactly where an injected skimmer would want to be.
- The emergency brake stays off unless the user asks for it. Never print `brake_secret` or a brake
  link with a valid token in your replies or logs (a link is a key to locking their admin). Never press
  a brake link or run `--lock` on a live site yourself.
- `--expect` is for the user's own announced updates. Do not open a window to make your own test
  changes look quiet; say what you are about to change instead.
- `quarantine_uploads` (rename new program files that appear in upload folders) stays OFF unless the
  user asks for it. Before turning it on: confirm `upload_dirs` with the user, check that the site
  itself never writes program files there (look at past alerts and at the folders), and tell them
  that files are renamed, not deleted, and how to rename one back. See integration.md, section 12.
- When upgrading an existing installation, keep `state_dir` as it is. Old (SHA-1) fingerprints are
  converted on the next scan and announced once; do not "fix" that by running `--rebaseline`.
- Do not "test" by attacking production (no real web shells, no password spraying against the
  live login). Use a local/staging copy, the self-test, and the fake LINE server.
- Never create backdoor-like test files without telling the user first, never inside the live web
  root, and always delete them. Copy only `lib/SecurityAlerts.php` (plus the config and cron entry)
  to the site — `scripts/` stays out of the web root.
- Do not send real LINE messages without the user's OK; each push counts against their monthly quota.
  The same goes for Telegram and Discord: a test lands in a real chat or channel.
- Adding hooks must not change behaviour: same responses, same redirects, same timing for the user.
- Keep the module's defaults unless the user asks; explain any threshold you change and why.
- If the site already has an alerting system, integrate with it (feed its events in with `custom()`,
  or send through it with the `notifier` setting); do not run two systems that send the same alert twice.
