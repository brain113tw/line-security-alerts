# Security policy / 安全問題回報

This is a security tool, so a weakness in it matters. Thank you for telling us before telling everyone.

## How to report

**Please do not put the details in a public issue.**

1. On this repository, open the **Security** tab and use **Report a vulnerability** (GitHub's private
   reporting). Only the maintainer sees what you write there.
2. If that button is not shown, open an ordinary issue that says only "I have a security report" —
   no details — and a private channel will be arranged from there.

It helps to include: what you found, which file or function, how to reproduce it, the version
(`.claude-plugin/plugin.json`) and your PHP version.

This project is maintained by a small shop, not by a security team. A reply may take some days.
Fixes are published with credit to the reporter unless you prefer otherwise.

## What counts

In scope — `skills/line-security-alerts/lib/SecurityAlerts.php` and the examples and scripts in this
repository. For example, a way to:

- make the module miss, or stay silent about, a change it claims to report;
- hide tampering with its own records from the weekly check-in;
- get the LINE token, the recipient ids or the check-in address written to a log or a message;
- make the optional quarantine rename anything other than a new program file inside an upload folder;
- forge, reuse or extend an emergency-brake link, or make the brake page unlock or change anything;
- make the page watch read anything other than the configured pages, or hide an injected script from it;
- open an `--expect` window that hides a backdoor-like change or lasts longer than 4 hours;
- break or slow down the host site through the hooks.

Out of scope:

- the limit stated in the README: someone with the same file access as the website can alter the
  monitor itself (the weekly fingerprint and the outside check-in exist to make that visible, not
  impossible);
- your own integration code, your server configuration, or the LINE platform;
- the look-alike samples the self-test writes to the temp folder (they are bait, described in the README).

## Supported versions

The latest release. Please update before reporting.

## Checking what you installed

- Releases are git tags (`v1.5.0`…). Install a tag rather than the default branch:
  `/plugin marketplace add brain113tw/line-security-alerts#v1.5.0`.
- From 1.3.0 on, each release on the Releases page lists the SHA-256 of `lib/SecurityAlerts.php`.
  Compare it with your copy (`sha256sum lib/SecurityAlerts.php`).
- The automated tests pin every GitHub Action to a full commit and run with read-only permissions.

---

## 中文

這是一個資安工具，它自己有漏洞是很嚴重的事。謝謝你先告訴我們。

**請不要把細節寫在公開的 issue 裡。**

1. 到這個專案的 **Security** 分頁，按 **Report a vulnerability**（GitHub 的私下回報），內容只有維護者看得到。
2. 如果沒有那顆按鈕，請開一個只寫「我有安全問題要回報」的 issue，不要寫細節，我們再約私下的管道。

請附上：發現了什麼、在哪一支檔或哪個函式、怎麼重現、版本（`.claude-plugin/plugin.json`）和 PHP 版本。

這個專案是一家小店在維護，不是資安團隊，回覆可能要幾天。修正發布時會註明回報的人，除非你不想具名。

README 裡講明的限制不算漏洞：跟網站有同樣檔案權限的人，可以改掉偵測本身；每週總指紋和外部報到是讓這件事「看得出來」，不是讓它「做不到」。

**確認裝到的是哪一版**：請安裝版本標籤（`/plugin marketplace add brain113tw/line-security-alerts#v1.5.0`），不要直接裝最新的主分支。
從 1.3.0 起，Releases 頁每一版都附上 `lib/SecurityAlerts.php` 的 SHA-256，可以跟你手上的檔案比對。
