# When an alert arrives

For the owner or manager of the site. No programming knowledge needed. Print it, or keep it in the
notes app on your phone. ([中文版](when-an-alert-arrives.zh-TW.md) / [日本語](when-an-alert-arrives.ja.md))

## Three things first

1. **Look at the level.** 【Notice】 means check when you have a moment. 【URGENT】 means deal with it now, not tomorrow.
   (Normally only 【URGENT】 makes your phone ring; notices and the weekly check-in arrive quietly in the chat.)
2. **Ask "was that us?"** Most notices are your own people: a deployment, a new phone, a busy refund day. Ask the person named. If yes, you are done.
3. **If it was not you, follow the matching section below.** When unsure, treat it as "not us".

> One thing never to do: **do not simply delete the suspicious file to make the problem go away.**
> The file is evidence. Without it nobody can tell how the intruder got in, and they will be back.

---

## 【Notice】 Too many failed admin logins

**Meaning**: someone (usually a bot) is guessing your admin password. Every site on the internet
gets this; being guessed at is not being broken into.

**Do**

- Make sure every admin password is long (12+ characters) and not reused anywhere else.
- Turn on two-step verification, above all for the accounts named in the message.
- If one IP keeps coming back, have your host or developer block it.
- Account names like `admin` or `test` are guessed first. Rename them if you can.

## 【Notice】 Admin signed in from a new device and network

**Meaning**: the login succeeded, from a browser and a network this account has not used before.

**Do**

- Ask the account's owner: "Was that you just now?" A new phone or mobile data while travelling causes this.
- **Not them**: change that password now → sign that account out everywhere → review what the
  account did after signing in (settings, data viewed, refunds, price changes).

## 【URGENT / Notice】 Admin account changed

**Meaning**: an admin account was created or deleted, or its permissions, password, e-mail or
two-step verification changed.

**Do**

- Ask the team who did it. If somebody did, fine.
- **Nobody did**: disable that account (do not delete it), change every admin's password, then
  review recent admin activity.
- An unknown extra account is the door an intruder leaves open for next time.

## 【Notice】 Code files changed on the server

**Meaning**: program files were added, changed or deleted.

**Do**

- Did you or your developer deploy today, and do the listed files match? Then ignore it.
- **Nobody deployed anything today**: this is the signal. Follow the URGENT section below.
- A mismatch (you changed one file, ten are listed) also deserves a question.

## 【URGENT】 Possible backdoor on the server

**Meaning**: a file that looks like a backdoor appeared, or a program showed up in the folder meant
for uploaded pictures. This is the one to act on immediately.

**In this order**

1. **Check it was not your own developer.** If not, continue.
2. **Put the site in maintenance mode** or take it offline. Every extra minute is a minute for them.
3. **Do not delete.** Have your developer copy the listed files somewhere safe, then remove them from the site.
4. **Restore from a clean backup** — one from before the incident. If you cannot tell when it began, go further back.
5. **Change every password and key**: admin, hosting panel, database, FTP, payment provider, LINE, mail service. If they got in, assume they read them.
6. **Find out how they got in** before reopening: an outdated system or plugin? An upload form that checks nothing? A guessed password? Reopening without the cause is opening the door again.
7. If the site holds customer or order data, establish whether it was seen or taken, and follow the
   rules where you operate about notifying customers and authorities.

**When the message says "its content changed but its modification time was put back"**

Someone edited that file and then set its "last modified" time back to what it was, so that it
would look untouched. An ordinary upload never does that, which is why it is URGENT whatever was
changed. Ask your developer whether an unusual deployment tool was used; if not, follow steps 1–7 above.

**When the message says "→ renamed to …"**

You have "automatic quarantine" switched on. The new program in the upload folder was renamed
automatically and the server no longer runs it. The file was not deleted; it is still in the same folder.

- That only holds the door. Steps 1–7 above still apply: how the file got there is not solved.
- Do not delete the renamed file. Leave it for your developer to examine.
- If it really was put there by your own people: have your developer rename it back AND take that
  folder out of the "upload folders" setting, or the next check will rename it again.
- If the message says "automatic renaming was tried and failed": the file can still run. Act as if
  there were no quarantine, immediately.

## 【URGENT】 The file fingerprints have disappeared / the monitoring records were wiped

**Meaning**: the monitor's own records were erased and nobody asked for that. Intruders do this to blind it.

**Do**

- Ask your developer first: was the server moved, a folder cleaned up, something reinstalled? If so, fine.
- If not: handle it as "Possible backdoor" above. What changed in the meantime can no longer be
  listed; only a comparison with a backup will tell.

## 【Notice】 The file baseline was reset by hand

**Meaning**: someone gave the "treat the current files as normal" command.

**Do**: ask your developer whether it was them (common after a big release). If not, see the section above.

## 【Notice】 File fingerprints upgraded to SHA-256

**Meaning**: the monitor itself was just updated and now records files with a newer kind of
fingerprint. Before switching, every file was checked against its old fingerprint; only unchanged
files were converted quietly.

**Do**

- Ask your developer: was the monitor updated recently? If yes, this is the one-time note about it. Nothing to do.
- **Nobody updated it**: someone swapped the records for old-format ones. Handle it as "the file
  fingerprints have disappeared" above.

## 【Notice】 The firewall is blocking a lot of requests

**Meaning**: someone is probing your site in bulk and being stopped. The firewall is doing its job.

**Do**

- Open the site on your phone and place a test order to confirm real customers are fine.
- If one IP persists, have your host or CDN block it outright.
- If this message keeps coming, ask your developer which feature is being probed; it deserves attention.

## 【Notice】 Unusual refunds / cancellations / balance adjustments

**Meaning**: many manual refunds or cancellations in a short time, or one unusually large amount.

**Do**

- Ask the staff member named in the message. The end of a promotion or a compensation round looks like this.
- **They say it was not them**: treat their account as stolen (see "new device" above) and check each of those transactions.

## 【URGENT】 A page started using another site

(Only if your developer set up the "page watch".)

**Meaning**: one of your pages now loads code from a site it did not use before, embeds one, sends
what customers type in a form to one, or sends visitors on to one. Site names are written like
`cdn-evil[.]example` on purpose: **do not open them**.

**Do**

- Ask your developer and staff: did anyone add a chat box, a payment, analytics or advertising service
  today? If yes, and the name matches, fine — your developer adds it to the allowed list.
- **Nobody added anything**: assume someone changed your site's settings or database to read
  customers' card details or send them elsewhere. If the page takes payments or personal details,
  have your developer take that page (or the shop) offline now, find where the code comes from (often
  a "footer / header code" setting or an article) and remove it, then follow "Possible backdoor"
  above: passwords, how they got in, which customers may be affected.

## 【URGENT】 Your pages show search engines something you do not see

**Meaning**: Google's crawler, or customers arriving from a Google search, get links or a redirect
that you do not see when you open the site yourself. This is how gambling and spam-link injections
hide from shop owners; the site may soon show up in Google with casino titles, or Google may warn
visitors away from it.

**Do**

- Do not try the links. Have your developer search the database (articles, settings, footer) and the
  code for the names in the message and remove what they find, then follow "Possible backdoor" above.
- After cleaning up, have them check Google Search Console ("Security issues") and ask Google to
  review the site.

## 【Notice】 New links to other sites on your pages

**Meaning**: a watched page now links to a site it did not link to before, and everybody sees it.

**Do**: did you or your staff add an article, a partner, a social link? Then ignore it. If nobody did,
look at that page with your developer: links can be slipped in the same way as the hidden ones above.

## The last line "🛑 Not your doing, and nobody to call? Lock the admin area…"

(Only if your developer set up the emergency brake. On Telegram it is the button "🛑 Lock the admin area
for 4 hours" under the message; on Discord, the link in the last card.)

**When to use it**: the alert above it is URGENT, it is not something you or your staff did, and you
cannot reach your developer. Tap the link and press the button on the page. The admin area is then
locked for a few hours — nobody can use it, including whoever broke in and your own staff — while
customers keep shopping. Opening the link alone does nothing; only the button locks.

Then keep trying to reach your developer. Only they can unlock it early (on the server). If you are
unsure, pressing is the safe side: the worst outcome is a few hours without the admin area.

## 【URGENT】 The admin area is locked

**Meaning**: someone pressed the emergency brake (the message says when, and from which IP), or your
developer locked the admin area from the server.

**Do**: if it was you, nothing more — wait for your developer. **If nobody on your side pressed it**,
someone can read your alert messages or is on the server: tell your developer today.

## 【Notice】 Code changes during your announced update

**Meaning**: before uploading an update, your developer ran `--expect`. During that time the code
changes were collected instead of reported one by one; this message lists them.

**Do**: was there really an update at the time shown? Then nothing to do. **If nobody was updating
the site then**, someone on the server announced the window to hide their changes: follow "Possible
backdoor" above.

## A message that starts with "⏱ Delayed: this alert is from …"

**Meaning**: this is about something that happened earlier. At that moment no channel could be
reached (LINE down or its monthly quota used up, no Telegram, Discord or e-mail set…), so the alert was
kept and is delivered now.

**Do**

- Look at the original time in the message and handle the alert as usual: it happened then, not now.
- If delayed alerts keep coming, the channel is unreliable: have your developer check the LINE
  monthly quota and make sure a second channel is set (e-mail, Telegram or Discord).

## Weekly check-in

**Meaning**: nothing is wrong. Once a week the monitor says it is still alive.

**The thing to notice is its absence**: more than a week without it means the checks are not
running (the scheduled job stopped, the LINE token expired, the server was rebuilt without the
monitor). Ask your developer. And if the "records go back to" date in the message suddenly becomes
recent, the records were reset — ask why.

### Reading the "code fingerprint" in that message

The string (like `3f9a-0c1d-77b2-e4a8`) is computed from every code file on the site. Touch any one
of them and it changes. It sits in your LINE chat, where someone who got into the server cannot edit
it — so **do not delete these weekly messages**.

Just read what follows it:

| The message says | What you do |
|---|---|
| same as the last check-in | Nothing. No code changed this week |
| was xxxx; N code-change notice(s) were sent in between | Think back: were those N all your own uploads? If yes, fine |
| was xxxx; N change(s) were written to the log but not sent | Have your developer read the log. Usually files the site rewrites itself, or a day with too many messages |
| starts with ⚠ and says "no code change is on record" | **Deal with it the same day.** Code changed but the monitor recorded nothing, so its records may have been edited. Follow "Possible backdoor on the server" |

To check for yourself, scroll up to the previous check-in and compare the two strings; that tells
you whether the message is telling the truth.

### The line "LINE messages this month: about N of M used"

A LINE Official Account may only push a limited number of messages a month (depending on its plan).
The monitor asks LINE once a week; the number covers everything that account sent, campaign messages
to customers included.

- No ⚠: nothing to do.
- **⚠ "about N of M" or "used up"**: once the limit is reached LINE delivers nothing, security alerts
  included. Do one or both: raise the plan in the LINE Official Account Manager; have your developer
  make sure a second channel is set (e-mail, Telegram or Discord: alerts go there when LINE refuses).
  Telegram and Discord are free; with `line_min_level => 2` LINE is kept for urgent alerts only.

### An extra line: "⚠ The LINE account that sends these alerts has about N friends"

**Meaning**: the alerts come from an official account that many people follow — probably the one
your customers use. Its key is stored on your web server; if the server is ever broken into, the
intruder could send a message from your shop's account to all of those people.

**Do**: create a new LINE Official Account used only for alerts (you and a few colleagues as friends)
and have your developer switch the alerts to it. Keep the customer account for customers.

### The line "Channels checked…" or "⚠ Not working right now: …"

**What it means**: when your alerts have more than one place to go (say Telegram, with LINE as a
backup), the check-in also makes sure each channel still works. Nothing is sent for that; the services
are only asked.

- "Channels checked without sending a message: … OK.": nothing to do.
- **"⚠ Not working right now: …"**: the reason is in brackets (the bot was blocked, the webhook was
  deleted, a recipient blocked the LINE account…). Alerts still reach you through the other channels,
  but the backup is broken: have your developer fix it this week (`--test-all` shows them how). When it
  says a recipient blocked the account, ask your colleagues first: someone may have blocked or removed
  the alert account; adding it back is enough.

### An extra line: "⚠ The outside check-in address has failed…"

**Meaning**: you set up "an outside service tells me when the schedule stops", but the module
cannot reach that service's address. The checks still run; only, if the schedule stopped, nobody
would tell you.

**Do**: have your developer check the address in the settings (pasted wrongly? is the account at
that service still there?).

## A message from the outside service (not LINE): "no check-in received"

**Meaning**: if you use the outside check-in, this comes from that service, usually by e-mail. It
says the site's scheduled checks have not reported for longer than allowed.

**Do**

- Open the site on your phone. If the site is down too, it is a hosting problem: call your host.
- Site fine, only the checks stopped: have your developer look at the schedule (server moved,
  settings changed, maintenance at the host?).
- Nobody touched the schedule and it stopped anyway: take it seriously. Switching the schedule off
  is one way to silence a monitor.

---

## Have these ready beforehand

When something happens it is too late to start looking for them:

- **Backups**: daily and automatic, with at least one copy that is not on the same server. Twice a
  year, actually restore one to prove it works.
- **A list**: your host's support number, your developer's contact, the admin addresses of every
  service you use. On your phone, not only inside the site's admin.
- **Passwords**: one account per person, never shared; two-step verification everywhere; accounts
  disabled the day someone leaves.
- **Updates**: install security updates for your system and plugins. Most break-ins use old holes
  that were fixed long ago.
