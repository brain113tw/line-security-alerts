# Prevention checklist: what to do before an alert ever fires

This package tells you when something happened. This list is the other half: making it less likely to
happen. You want both, because any single layer can fail.

(Several items were suggested by readers after the first public release — thank you.)
[繁體中文](hardening-checklist.zh-TW.md)

## 1. Ten minutes each — do these first

**1. Upload folders must not run programs**

A folder where customers or staff upload pictures should hold pictures and documents, nothing else.
The most common break-in is a program dressed up as an image, uploaded and then requested. Tell the
server never to serve program files from that folder and the trick stops working.

Apache (most shared hosting): put a `.htaccess` in that folder:

```
<FilesMatch "\.(php\d?|phtml|pht|phar|inc|cgi|pl|py|sh)$">
    Require all denied
</FilesMatch>
```

nginx has no `.htaccess`; ask your host or developer to do the same for that folder in the server
configuration. Then prove it: put a test `.php` file there, request it in a browser — it must be
refused — and delete it. This package's "code file inside an upload folder" alert is the backstop
for this rule: if someone removes the protection, you hear about it.

**2. Two-step verification (or passkeys) on every admin account**

One account per person, never shared. Do not call an account `admin`. Disable an account the day
its owner leaves.

**3. Backups kept off the server — and restored once for real**

A backup that has never been restored is a backup you are not sure you have.

**4. Two services that watch from outside**

- Can people open the site? An outside uptime monitor.
- Is the schedule still running? A cron check-in service, its address in this package's `ping_url`.

**5. Install security updates for the system and its plugins**

Most break-ins use old holes that were fixed long ago.

## 2. One more door in front of the admin area

Two-step verification protects the *account*: a guessed password still does not get in. An outer
door protects the *whole admin area*: someone who has not passed it cannot reach any admin page at
all, including one that happens to have a bug. They do different jobs; have both if you can.

**Option A: an identity check at the service in front of your site** (Cloudflare Access, for example)

If the site already sits behind such a service, this is a setting: the admin address requires an
identity check first (a Google account works; it does not have to be an e-mailed code). Mind:

- **Restore the real visitor IP.** Once the service is in front, every connection the server sees
  comes from that service. The server or the application must read the real address it forwards —
  and trust it only when the connection really comes from that service. Skip this and every alert
  from this package shows the same IP and the per-IP thresholds misfire. The IP you pass to
  `loginFailed()` and `firewallBlocked()` must be the restored one.
- **Lock the origin.** Anyone who knows the server's real address can go around the service. Make
  the server accept admin requests only from that service.
- **Let machines through.** Addresses called by other systems — payment provider, LINE, a phone
  system — must not be put behind the door.
- Do it on a test copy first and check payments, message callbacks and scheduled jobs before production.

**Option B: your host's "password-protect this folder"**

Most hosting panels offer it: a user name and password on the admin folder, asked by the browser
before any page inside is served. No domain settings change; switch it off if it does not work out. Mind:

- Use a long random password. This door usually has no "lock after N wrong guesses".
- Let machines through here too.
- **Try it on real phones.** Mobile browsers, in-app browsers of chat apps and web apps installed
  to the home screen do not all handle that prompt the same way. If staff use the admin on their
  phones every day, test before you switch it on for everyone.

## 3. If you run the whole server yourself (VPS)

- Do not leave remote login (SSH) open to the world: keys only, a firewall that limits who can
  connect — or keep it closed and use your provider's console when you need it.
- On shared hosting this layer is your host's job; it is fair to ask them how they handle it.

## 4. Going further with uploads

If a programmable service sits in front of your site, uploads can pass through it first: size and
type are checked outside, only acceptable files are forwarded, and the server verifies that the
request really came from that layer and checks the file again. That is one more layer, not the only
one. "It looks like an image" does not stop a program hidden behind a real image — rule 1 is still
the real protection.

## What this list does not replace

Detection. Every item above lowers the odds; none of them is a guarantee. Something still has to
tell you, the same day, when it happened anyway.
