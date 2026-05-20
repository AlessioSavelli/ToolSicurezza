# ToolSicurezza Wiki

Welcome. This wiki explains how to install, run, and extend
`ToolSicurezza` — a defensive infostealer audit suite for Windows.

> ⚠️ **Read [`DISCLAIMER.md`](../DISCLAIMER.md) before doing anything else.**
> By using the software you accept its terms.

## Navigation

### Getting started

- [Installation](Installation.md)
- [Quick Start](Quick-Start.md)
- [CLI Reference](CLI-Reference.md)
- [HTML Report](HTML-Report.md)
- [Demo Reports](Demo-Reports.md) ← preview without running the tool

### Understanding the tool

- [Architecture](Architecture.md)
- [Knowledge Base](Knowledge-Base.md)
- [Threat Model](Threat-Model.md)

### Extending

- [Adding a Browser](Adding-a-Browser.md)
- [Contributing to the KB](Contributing-KB.md)

### Help

- [FAQ](FAQ.md)
- [Troubleshooting](Troubleshooting.md)

### Legal & ethics

- [Legal and Ethics](Legal-and-Ethics.md)

---

## Recent changes (v2.1 — 2026-05-20)

- **Multilanguage HTML reports** — auto-detects your Windows OS locale
  and renders the report in Italian, English, French, German, or Spanish.
  Override with `--lang it/en/fr/de/es`. Both `infostealer_audit.py` and
  `pwd_audit.py` support this flag.
- **Knowledge Base v1.1** — 20 infostealer families (up from 17),
  added Storm, REMUS, Shai-Hulud, PennyWise; corrected VoidStealer v2.0
  bypass data (no elevation required); new `browser_cves` section with 12
  Chrome/Windows CVEs sourced from zero-day.cz; new
  `server-side-exfil-decrypt` bypass technique.
- **Demo reports** — five sanitized HTML reports (one per language) in
  `wiki/demo-reports/` so you can preview the report format before
  running the tool. See [Demo Reports](Demo-Reports.md).

---

## What this project is, in one paragraph

When an infostealer (RedLine, Lumma, Vidar, Kepavll, Glove Stealer, ...)
runs on a Windows PC, it does a known set of things: read the master
keys out of Chrome/Edge/Brave/Firefox local files, decrypt the saved
passwords, harvest cookies and Discord tokens, list browser-installed
crypto wallets, dump Windows Credential Manager, scan for SSH keys,
and so on. `ToolSicurezza` does exactly the same enumeration on the
user's **own** machine, locally, with no exfiltration — so the user can
see **what would be lost** if such malware ran.

## Why this project exists

Most people, even technical users, do not really know:

- Which saved passwords are in their browser right now.
- Whether their saved passwords are protected by Chrome's modern
  App-Bound Encryption (v20) or by the legacy v10 scheme that a
  user-mode infostealer breaks in seconds.
- Whether their installed browser is up-to-date with the latest ABE
  hardening.
- Whether they have a Discord token, Steam autologin, or `.git-credentials`
  file sitting in plaintext.
- Which infostealer families historically targeted their setup.

Without that knowledge, "I should change my passwords after an incident"
is a guess. `ToolSicurezza` turns it into a measurement.

## What this project is *not*

- It is not malware.
- It does not target third-party systems.
- It does not perform network exfiltration.
- It does not include sample binaries, exploit kits, or weaponised
  payloads.
- It will not bypass authentication you do not legitimately hold.

## License

[MIT](../LICENSE) + Acceptable Use Notice + [DISCLAIMER](../DISCLAIMER.md).
