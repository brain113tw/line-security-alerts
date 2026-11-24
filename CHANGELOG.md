# Changelog / 更新紀錄

## 1.4.0 — 2026-11-24

- **Only URGENT alerts ring** (`ring_level`, default 2). Notices and the weekly check-in still arrive,
  quietly: LINE without a notification (`notificationDisabled`), Telegram without a sound
  (`disable_notification`), Discord without a notification (flag 4096). URGENT alerts and test
  messages always ring. `1` = notices ring too; `0` = everything, as before. A `notifier` gets
  `$silent` as its third argument.
  只有緊急的會響；一般通知和每週報平安一樣送到，只是不響。想跟以前一樣全部都響：`'ring_level' => 0`。
- **Telegram, easier to read**: bold titles, the advice folded away in a quote that opens on a tap,
  and buttons under the message — "🛑 Lock the admin area for N hours" on URGENT alerts (with the
  emergency brake set up) and "📖 What to do" (`guide_url`, by default this package's guide). Anything
  Telegram refuses (a 400) is sent again at once as plain text.
  Telegram：粗體標題、「該怎麼做」收起來點了才展開、煞車和說明做成按鈕；排版被拒就自動改純文字重發。
- **Discord, as cards**: one card per finding — red URGENT, orange notice, green check-in — the facts
  in a code block, the advice in a box of its own, the brake and guide links in a last card. Too much
  for cards, or refused: the plain form as before. Sent with `?wait=true`, so "accepted" means saved. A
  webhook that Discord says does not exist (404) is not tried again until its address changes, as
  Discord asks; `--status` asks for a new one.
  Discord：每件事一張彩色卡片；被刪掉的 Webhook 不再一直試（Discord 規定一直試會被暫時封鎖）。
- **Easier setup**: `--telegram-chats` lists the people, groups and topics that wrote to the bot, with
  the id to use (nothing is sent, nothing marked as read). `--test-all` adds what to do about each
  failure. A Telegram group that became a supergroup is followed to its new id at once and `--status`
  asks to update the setting. A Discord forum channel without `?thread_id=` is explained.
  設定更簡單：`--telegram-chats` 直接列出聊天室代號；`--test-all` 失敗時寫出怎麼修；群組升級自動跟過去。
- **Backups checked without sending**: whenever a message has more than one place to go, the weekly
  check-in asks every channel whether it still works — Telegram shows "typing…" for a moment, the
  Discord webhook and LINE's key and recipients are only asked — and says so in one line, or warns.
  LINE answers "sent" even to a recipient who blocked the account; this is how that shows up.
  `--status` runs the same check (`checkChannels()`).
  備援管道每週檢查一次（不發訊息）；LINE 收件人封鎖了帳號也查得出來。
- **Several sites in one place**: Telegram topics (`telegram_chat_id` like `-1001234567890/12`) and
  Discord threads (`?thread_id=` on the webhook address).
  好幾個網站：用 Telegram 的主題、Discord 的討論串分開放。
- `'rich_messages' => false` keeps plain text on Telegram and Discord. LINE and e-mail get exactly the
  same text as in 1.3.
- **Fixed (Discord, since 1.2 / 1.3)**: a name with five or more backticks in a row could end the code
  block early and put a working link inside an alert; a finding line that imitated the emergency-brake
  line was placed after the block like the real one; and a very long such line could make the plain
  form loop until PHP ran out of memory, so nothing was sent. Every backtick inside a block is now
  followed by an invisible space, only the brake line the module wrote goes after the block, and
  message parts can no longer come out empty. Upgrade recommended if you use Discord.
  修正 Discord 的三個問題（1.2／1.3 就有）：帳號名稱裡連續五個反引號可以讓程式碼框提早結束、
  假的煞車連結會被放到框外、太長的假煞車行會讓程式一直跑到記憶體用完。用 Discord 的請升級。
- Self-test: 311 checks. The fake server checks Telegram's HTML, button addresses and Discord's card
  limits the way the services do, and plays a blocked bot, a group that moved, a forum channel and a
  deleted webhook.

Upgrading from 1.3.x: replace `lib/SecurityAlerts.php` and the cron entry (`--telegram-chats`, the new
`--status` and `--test-all` lines). Without touching the config, three things change: notices and the
check-in stop ringing (`'ring_level' => 0` for the old behaviour); Telegram and Discord get the new
layout (`'rich_messages' => false` for the old one); and with more than one place to send to, the
weekly check-in checks each channel (a few GET requests, and a moment of "typing…" on Telegram).
從 1.3.x 升級：換掉 lib 和排程檔。不改設定時會變的三件事：一般通知不再響（要全部響設 `ring_level => 0`）、
Telegram／Discord 用新排版（要純文字設 `rich_messages => false`）、每週報平安會順便檢查各管道。

## 1.3.0 — 2026-11-23

- **Page watch** (`page_watch`, optional): a few of your own pages are read every hour four ways — a
  desktop browser, a phone, Google's crawler, a phone arriving from a Google search — and the other
  sites they use are compared with last time. URGENT: a new site for scripts, frames, form targets or
  redirects (card skimming, redirects), and anything only the crawler or Google visitors get (spam
  links hidden from the owner). Notice: new outside links. These changes usually live in the database,
  where the file scan cannot see them. `page_allow` for services you use on purpose; `--pages` lists
  what each page uses right now. Site names in messages are written `name[.]com`.
  網頁監看：資料庫裡被塞的側錄程式、只給 Google 看的垃圾連結、從 Google 點進來被轉走，檔案比對看不到的這些現在也會通知。
- **Announced updates**: `--expect 30m` runs every check first, then collects ordinary code changes
  for that time and sends ONE summary afterwards (`--expect off` to finish early). Backdoor-like
  content, programs in upload folders and edits with the time put back are still reported at once; a
  window lasts 4 hours at most, whatever its file says.
  上傳更新前先預告，更新的變動合成一則；像後門的東西照樣立刻通知。
- **The LINE key on the server**: `--status`, `--test-all` and the weekly check-in ask LINE roughly how
  many friends the alert account has and warn above `line_friends_warn` (20). If the server is broken
  into, that key can message every friend: alerts belong in an account of their own. The docs now say
  so plainly.
  提醒通知要用專用的 LINE 帳號：金鑰在主機上，被偷就能發訊息給所有好友。
- **Emergency brake** (optional; `brake_url`, `brake_secret`, `examples/security-brake.php`): URGENT
  alerts end with a signed, one-time, expiring link. Opening it shows a button (chat-app previews
  lock nothing); the button locks the admin area for `brake_hours` while the shop stays open. The
  site asks `adminLocked()` on every admin request. Only `--unlock` on the server unlocks; the lock is
  announced. `--lock 4h` from the server.
  緊急煞車：緊急通知最後一行可以把後台鎖住幾小時，前台照常營業；網頁那邊只能鎖、不能解鎖。
- **Installing a fixed version**: the READMEs show `#v1.3.0` installs; from this release on, the
  Releases page lists the SHA-256 of `lib/SecurityAlerts.php`. The CI pins its actions to full
  commits. The READMEs say what the skill tells Claude to do and not to do.
  說明怎麼裝固定版本、怎麼比對檔案指紋，以及這個 skill 會叫 Claude 做什麼、不做什麼。
- Prevention checklist: a decoy key (canarytokens) that tells you when someone reads your server's
  files, and Google Search Console's "Security issues".
  預防清單加上「誘餌金鑰」和 Google Search Console。
- Japanese README: how the package relates to IPA's EC-site guideline, the credit-card security
  guideline 6.1 and breach reporting under the APPI (with sources). Traditional Chinese guide: the
  notification duties under Taiwan's personal data law (with sources).
  日本語：IPA・クレジットカードガイドライン・個人情報保護法との関係。中文：台灣個資法的通知義務。
- The fake server has a shop (`/shop/`, `/shop/hack`) and answers LINE's friend-count question.
- Self-test: 261 checks.

Upgrading from 1.2.x: replace `lib/SecurityAlerts.php` and the cron entry (for `--expect`, `--pages`,
`--lock` / `--unlock` and the new `--status` lines). Nothing else changes until you set `page_watch`
or the brake; the friend-count question is a GET to LINE once a week (`'line_friends_warn' => 0`
turns it off).

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
