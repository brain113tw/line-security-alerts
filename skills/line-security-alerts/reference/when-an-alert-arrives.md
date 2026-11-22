# When an alert arrives

For the owner or manager of the site. No programming knowledge needed. Print it, or keep it in the
notes app on your phone. ([中文版](when-an-alert-arrives.zh-TW.md))

## Three things first

1. **Look at the level.** 【Notice】 means check when you have a moment. 【URGENT】 means deal with it now, not tomorrow.
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

## A message that starts with "⏱ Delayed: this alert is from …"

**Meaning**: this is about something that happened earlier. At that moment neither LINE nor e-mail
could be reached (LINE down, monthly quota used up and no e-mail set…), so the alert was kept and is
delivered now.

**Do**

- Look at the original time in the message and handle the alert as usual: it happened then, not now.
- If delayed alerts keep coming, the channel is unreliable: have your developer check the LINE
  monthly quota and make sure a fallback e-mail address is set.

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
  make sure a fallback e-mail address is set (then alerts go by e-mail when LINE refuses).

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
