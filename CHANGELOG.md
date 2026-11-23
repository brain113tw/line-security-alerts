# Changelog / 更新紀錄

## 1.2.0 — 2026-11-23

- **Telegram and Discord built in.** `telegram_bot_token` + `telegram_chat_id`, `discord_webhook_url`.
  A message goes to the first channel that takes it: your notifier → Telegram → Discord → LINE →
  e-mail. Plain text on Telegram; on Discord inside a code block, with mentions switched off, so a
  name containing `@everyone` or a fake link stays harmless. Long messages go in numbered parts; a
  short "too many requests" wait is honoured once, a long one hands over to the next channel.
  Thanks to a suggestion on Threads.
  內建 Telegram 和 Discord，可以取代 LINE，也可以互相備援。感謝 Threads 上的建議。
- **`line_min_level`** keeps LINE's monthly allowance for what matters: 2 = only URGENT alerts use
  LINE (and are tried there first), notices and the weekly check-in go elsewhere; 1 = only the weekly
  check-in stays off LINE. With nothing else set up LINE is still used, and `--status` says so.
  新增「只有緊急的才用 LINE」的設定，省 LINE 的則數。
- The "LINE messages this month" line of the weekly check-in appears only when LINE is really in use.
- **`--test-all`** (and `testEachChannel()`): a test message to every channel on its own, with the
  service's reason when one fails. `--status` shows the order the channels are tried in.
- The fake server plays Telegram and Discord too (429, 500, slow, gone, too long).
- Japanese documentation: [README.ja.md](README.ja.md), the owner's guide and the prevention checklist in
  日本語 (translations; the alert texts themselves stay English / Traditional Chinese).
  日本語版の説明を追加しました。
- The "Delayed" note now says "every channel failed" instead of naming LINE and e-mail only.
- Self-test: 204 checks.

Upgrading from 1.1.x: replace `lib/SecurityAlerts.php` (and the cron entry for `--test-all` and the
new `--status` lines). Nothing changes until you add a Telegram or Discord key.

## 1.1.1 — 2026-11-23

- New: a prevention checklist ([English](skills/line-security-alerts/reference/hardening-checklist.md),
  [繁體中文](skills/line-security-alerts/reference/hardening-checklist.zh-TW.md)) — upload folders that
  cannot run programs, an extra door in front of the admin area (identity check at a CDN, or the host's
  folder password), what to mind when a CDN sits in front (real visitor IP, locking the origin), SSH
  on your own server. Several items were suggested by readers. Documentation only; no code change.
  新增「預防清單」，整理網友回饋的預防做法。只加文件，程式沒有變。

## 1.1.0 — 2026-11-23

- **LINE allowance in the weekly check-in.** Once a week the module asks LINE how many messages the
  account has sent this month and what its limit is, and adds one line; from 80% it is a warning.
  `line_quota_check => false` turns it off.
  每週報平安多一行「這個月 LINE 大約發了幾則、上限幾則」，用到八成會警告。
- **`--status`** (and `status()` in the library): where things stand — last run, where alerts go,
  what is waiting to be re-sent, files watched, the current fingerprint, the latest findings — and
  `!!` lines for whatever needs a look. Read-only; prints no token, recipient or check-in address.
  新增「現在狀況」指令，只看不動。
- A custom `transport` callable now receives the HTTP method as a fourth argument (`'GET'` for the
  allowance lookup, `'POST'` for messages). Existing three-argument callables keep working.
- `SECURITY.md` (how to report a vulnerability privately) and this changelog.
- Self-test: 170 checks. CI: `actions/checkout@v7`.

Upgrading from 1.0.0: replace `lib/SecurityAlerts.php` (and the cron entry if you want `--status`).
No change to the records; nothing is re-reported.

## 1.0.0 — 2026-11-22

First public release.

- Alerts on LINE (e-mail fallback, or your own channel through `notifier`) for: failed and new-device
  admin logins, admin account changes, new / changed / deleted code files, code in upload folders,
  web-shell patterns, edits with the modification time put back, firewall bursts, unusual staff
  refunds / cancellations / balance adjustments, and your own `custom()` checks.
- Quiet by design: one message per run, a quiet window per finding, a daily cap (URGENT bypasses it),
  first run is a silent baseline.
- Watches itself: weekly check-in with a fingerprint of all code files, alerts when its records are
  wiped or reset, optional outside check-in address (`ping_url`), alerts that could not be delivered
  are re-sent later.
- File fingerprints are SHA-256; a weekly full re-read; `--audit`, `--fingerprint`, `--manifest`,
  `scripts/fingerprint.php`; your own rules (`extra_rules`, `disable_rules`).
- Optional, off by default: quarantine (rename, never delete) of new program files in upload folders.
- Names that are not UTF-8 (old Big5 / GBK / Latin-1 folders and accounts) are handled; `input_charset`.
- One PHP file, no database tables, PHP 7.4+; self-test, demo and a fake LINE server included.
