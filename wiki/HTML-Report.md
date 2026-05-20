# HTML Report Guide

The HTML report is the primary output of `infostealer_audit.py`. This
page explains each tab in detail.

## File layout

```
reports/
├── infostealer_<timestamp>.html              # default
├── infostealer_showpassword_<timestamp>.html # with --showpassword
└── audit_aggressive_<timestamp>.log          # console log from pwd_audit --aggressive
```

## Top banner

The banner at the top has:

- A risk colour (CRITICAL / HIGH / MEDIUM / LOW) for your **overall**
  exposure.
- Quick stats: number of browsers, decrypted vs. protected credentials,
  number of outdated browsers, number of infostealer targets present,
  number of recovery tools available.

A short paragraph under the banner explains what the report represents
and reminds you that the password mode (masked vs. plaintext) is shown.

## Tab 1 — Overview

The first thing you see after the banner. It contains the **version
comparison matrix**:

| Column | Meaning |
|---|---|
| Browser | Name of the detected browser |
| Installed | Version currently installed on this machine |
| Current stable | Latest stable version fetched live from the vendor |
| Δ | Difference in major version. `+0` = up-to-date; `+1` = one major behind; `+N` for older |
| Risk | OK / LOW / MEDIUM / HIGH / CRITICAL based on the gap |

Rows with `Risk = OK` are green. Anything else is amber/red.

## Tab 2 — Accounts per browser

For each browser and each profile, a collapsible table with one row per
saved credential. Columns:

| Column | Meaning |
|---|---|
| URL | The site this credential is for |
| Username | The username (left as stored) |
| Password | Masked (`M*****a`) or plaintext if `--showpassword`. For v20-protected, shows `[v20-PROTECTED]` |
| Cipher | Which encryption scheme was used to store this credential. Colour-coded. |
| Category | Auto-classification: Banking / Email / Cloud-Dev / Gaming / Social / Shopping / Router / etc. |
| Risk | CRITICAL / HIGH / MEDIUM / LOW based on the site category |

Sort order: by *decryptability first* (decrypted on top), then by site
criticality, then by URL.

### Cipher legend

| Tag | Meaning | Risk |
|---|---|---|
| `v10 (AES-GCM + DPAPI user)` | Chrome 80–126 scheme. User-mode infostealer can decrypt in seconds. | 9/10 |
| `v20 (ABE - DECRYPTED!)` | Chrome 127+ App-Bound Encryption, but the tool managed to decrypt it. Indicates aggressive-mode or external help. | 8/10 |
| `v20-ABE protected` | Chrome 127+ ABE, the tool could **not** decrypt. Best protection currently. | 2/10 |
| `pre-v10 (DPAPI direct)` | Chrome <80 scheme. Trivial to decrypt. | 10/10 |
| `NSS PBKDF2+AES-256` | Firefox scheme. Decryptable in user-mode unless a Primary Password is set. | 6/10 |

## Tab 3 — Versions & CVE

Reproduces the version comparison from Overview plus, for each
installed browser, the list of **bypass techniques** known to work
against that version, sourced from the KB.

Each bypass technique is shown as a card with:

- **Name** of the technique
- **Complexity** tag
- **Description**
- **Used by** list of infostealer families that have implemented it
- **Ref** link to the public research

At the bottom: a "Fix" call-out with the milestone version and release
date that fixed each technique.

## Tab 4 — Targets

A table of nine classic infostealer targets:

| Target | Description |
|---|---|
| Discord Token | `%APPDATA%\discord\Local Storage\leveldb` |
| Steam autologin | `loginusers.vdf` + `ssfn*` files |
| Crypto wallets (browser ext.) | 25+ wallet extension IDs |
| Telegram Desktop session | `tdata` folder |
| SSH private keys | `~/.ssh/id_rsa`, `id_ed25519`, etc. |
| GPG keyring | `~/AppData/Roaming/gnupg` |
| FileZilla saved sites | `sitemanager.xml` |
| Windows Credential Manager | total entry count |
| VPN client configs | OpenVPN `.ovpn`, WireGuard configs |

Each row is colour-coded: amber if present, grey if not. Value column
shows the severity rating for an attacker.

## Tab 5 — LaZagne Light

Built-in pure-Python replica of the most useful LaZagne categories.
Each subsection has its own table:

- **Wi-Fi profiles** — SSID, auth, cipher, key (cleartext if
  `--showpassword`)
- **PuTTY sessions** — host, port, user, protocol (no passwords by
  design)
- **WinSCP sessions** — host, user, **decrypted password** (XOR
  algorithm)
- **Git credentials** — URL, user, password (`~/.git-credentials` is
  plaintext!)
- **OpenVPN configs** — config file, auth file, username/password if
  saved
- **FileZilla saved sites** — host, user, password (base64)
- **Thunderbird credentials** — same NSS scheme as Firefox
- **Pidgin chat accounts** — protocol, name, password (plaintext)
- **DBVisualizer databases** — alias, URL, user, password
- **RDP files** — host, user, whether DPAPI-encrypted password is
  attached
- **Cisco AnyConnect profiles** — host list
- **Chat/messaging apps** — Slack/Teams/Telegram/Signal/WhatsApp
  presence

If your PC is a desktop without a wireless adapter you will see "Wi-Fi
profiles (n/a)" instead of an empty table — the tool detects the
`wlansvc` service not running.

## Tab 6 — Legacy credentials

- **Windows Credential Manager** — table of `cmdkey /list` entries
  (target, type, user, persistence). The actual cleartext password is
  not extracted by default; this section just shows what's there.
- **IE / Edge Legacy Vault** — count of `.vcrd` / `.vpol` files in
  `%LOCALAPPDATA%\Microsoft\Vault\`. Decryption is documented but not
  implemented (LaZagne has it if you really need it).
- **Wi-Fi profiles** — same as in the LaZagne Light tab, duplicated
  here for legacy parity.
- **Outlook profiles** — registry entries enumerated.

## Tab 7 — Recovery tools

Status of the optional external Python tools the audit can leverage:

- `pypykatz` — mimikatz pure-Python
- `firepwd_internal` — our built-in Firefox NSS decryptor
- `browser_cookie3` — cookie extractor
- `LaZagne` — opt-in only (PUA-flagged)

Each card shows: installed yes/no, whether it was newly installed or
upgraded on this run, the GitHub URL, and use-case examples.

## Tab 8 — Fix recommendations

Ordered by priority: CRITICAL first. Each card has:

- **Action** — what to do, one sentence.
- **Why** — the rationale, citing risk level and threat model.
- **How** — exact steps.

Examples:

- *"Update Chrome to 148"* — because outdated browsers expose more
  techniques.
- *"Disable Save Password in the browser"* — because reducing the
  attack surface is better than relying on encryption.
- *"Migrate to a password manager"* — because v10 is decryptable in
  seconds and v20 protection cannot keep up with every infostealer
  release.

## Tab 9 — ABE Timeline

Chrome version ranges from `< 127` to `>= 148`, each annotated with:

- **Label** for that era ("Pre-ABE", "Inner AES wrapping", ...)
- **Decrypt difficulty**
- **Description**
- **Applicable bypasses** as code-formatted IDs
- **Fix** — milestone version + release date

The row matching **your** Chrome version is highlighted in blue.

This is the most useful tab for understanding *why* the answer is what
it is. Read it top-to-bottom.

## Multilanguage support

The HTML report is fully localised in **five languages**:

| Code | Language | Auto-detected from |
|---|---|---|
| `it` | Italiano | Windows locale `it-IT`, `it-CH`, etc. |
| `en` | English | Any locale not matched below (default) |
| `fr` | Français | Windows locale `fr-*` |
| `de` | Deutsch | Windows locale `de-*` (also `--lang du`) |
| `es` | Español | Windows locale `es-*` |

The language is **auto-detected** from the Windows registry key
`HKCU\Control Panel\International\LocaleName` at runtime. You can
override it with `--lang`:

```powershell
py infostealer_audit.py --lang fr
py pwd_audit.py --lang de
```

Every string in the report — tab names, column headers, stat-box
labels, warning messages, fix recommendations wording — is translated.
The `<html lang="xx">` attribute is also set correctly, which helps
screen readers and browser spell-checkers.

Translations live in `modules/i18n.py`. See
[Architecture](Architecture.md) for details, and
[Adding a Browser](Adding-a-Browser.md) for the extension pattern
(the same applies to adding a new language).

### Preview without running the tool

Five sanitized demo reports (one per language) are available in
[`wiki/demo-reports/`](demo-reports/):

| Report | Language |
|---|---|
| [IT\_infostealer\_demo.html](demo-reports/IT_infostealer_demo.html) | 🇮🇹 Italiano |
| [EN\_infostealer\_demo.html](demo-reports/EN_infostealer_demo.html) | 🇬🇧 English |
| [FR\_infostealer\_demo.html](demo-reports/FR_infostealer_demo.html) | 🇫🇷 Français |
| [DE\_infostealer\_demo.html](demo-reports/DE_infostealer_demo.html) | 🇩🇪 Deutsch |
| [ES\_infostealer\_demo.html](demo-reports/ES_infostealer_demo.html) | 🇪🇸 Español |

All personal data in those files has been replaced with fictional
placeholders. See [Demo Reports](Demo-Reports.md) for the full
description.

---

## Saving and sharing reports

- The HTML is **self-contained** (no external CSS or JS). You can
  email it, attach to a ticket, or print to PDF.
- If you used `--showpassword`, **do not share the report** — it
  contains plaintext credentials. Either redact, regenerate without
  the flag, or delete after use.
- The HTML uses `localStorage` only for the LaZagne tab interactivity
  in some versions; no remote tracking, no analytics.
