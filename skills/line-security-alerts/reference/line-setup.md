# LINE setup (about 10 minutes)

The module sends with the **LINE Messaging API** "push message" call. You need a LINE Official
Account with the Messaging API turned on, a channel access token, and the ID of the person (or
group) who should receive the alerts.

Screens change over time; if a step does not match, look for the same words in the current UI.

## 1. An official account with the Messaging API

1. Create a LINE Official Account (LINE Official Account Manager). A separate account just for
   alerts is cleanest — customers never see it.
2. In the Official Account Manager: **Settings → Messaging API → Enable**, and choose or create a
   provider. This creates the Messaging API channel in the LINE Developers console.
3. Optional but recommended: in the Official Account Manager turn **off** auto-reply and greeting
   messages for this account, so it stays quiet.

## 2. Channel access token

LINE Developers console → your provider → the channel → **Messaging API** tab → **Channel access
token (long-lived)** → Issue. Put it into the config (or an environment variable) yourself. Treat it
like a password: anyone with it can send messages as your account.

## 3. Who receives the alerts

- **Just you**: in the same channel, **Basic settings** tab → **Your user ID** (starts with `U`,
  33 characters). Then add the official account as a friend from your phone (QR code on the
  **Messaging API** tab). Without the friendship the message is not delivered.
- **Several people**: each adds the account as a friend; list their user IDs in `line_to`. Other
  people's IDs are not shown in the console — they arrive in the `follow` webhook event when they
  add the account, so this needs a webhook URL once. A group is often simpler:
- **A group**: allow the account to join groups (Official Account Manager → Settings → Account
  settings), invite it to a LINE group, and read the `groupId` (starts with `C`) from the `join`
  webhook event. This also needs a webhook URL once; afterwards the webhook can be turned off.

## 4. Test

```
php security-alerts-cron.php --test
```

Prints `sent via line` when LINE accepted the message (or the name of another channel that is tried
before LINE, see below). `FAILED` means every channel refused. `--test-all` sends to each channel
on its own and prints the reason next to the one that failed, e.g. `FAILED: HTTP 401: Unauthorized`:

| What you see | Usual cause |
|---|---|
| HTTP 401 | Token wrong, expired, or re-issued since |
| HTTP 400 | `line_to` is not a valid user/group ID for this channel |
| HTTP 429 | Monthly message quota used up (free plans have a small quota) or rate limit |
| `line` but nothing on the phone | You have not added the account as a friend, or blocked it |

To see the request itself, point `line_api_base` at `scripts/fake_line_server.php`.

Telegram and Discord are set up in the README ("Telegram or Discord instead"). When several channels
are set up they are tried in the order Telegram → Discord → LINE → e-mail, so a test reports the
first one that took it; with `line_min_level => 2` LINE carries only URGENT alerts.

## Quota

Every alert is one push message per recipient. With the defaults (one combined message per run,
the same finding not repeated for 6 hours, at most `daily_cap` non-urgent messages a day) a normal
month uses very few. When the quota runs out LINE answers 429 and the module goes on to the next
channel (Telegram, Discord, e-mail — whichever are set up); set at least `mail_to`. To spend the
allowance only on what matters, use `line_min_level => 2` together with Telegram or Discord.
