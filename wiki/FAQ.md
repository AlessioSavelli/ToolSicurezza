# FAQ

## Is this malware?

No. The tool is **defensive**, runs locally on your own machine, never
transmits data over the network, and is open source. It replicates what
malware *would* do, so you can see the consequences and harden your
system before they happen.

## Why does Windows Defender flag the LaZagne install?

Because LaZagne, in its original form, *is* a credential-recovery
binary, and Defender classifies all such binaries as PUA
(Potentially Unwanted Application). That's why our `infostealer_audit.py`
**does not auto-install LaZagne by default**, and **replicates the
useful parts internally** in `modules/lazagne_light.py` (pure Python,
no external binary).

If you really need the full LaZagne, opt-in with
`--install-flagged-tools`.

## Does the tool need internet access?

Only for the live version-check step. Use `--no-online` to disable it.
Everything else operates strictly on local data.

## Does the tool need admin?

No, for the default audit. Yes, for `pwd_audit.py --aggressive` (which
attempts the v20 ABE bypass via SYSTEM elevation).

## Why aren't my Chrome passwords decrypted?

Most likely because they are protected by **App-Bound Encryption (v20)**,
introduced in Chrome 127 (July 2024). The default user-mode audit can
**not** decrypt these — and that's a *good thing*. It means even a
user-mode infostealer running as you would fail to steal them.

You will see them in the report as `v20-protected`. The Cipher column
will be coloured green.

If you want to verify this is correct, run `pwd_audit.py --aggressive`.
It will try to bypass v20 via SYSTEM elevation. On Chrome 131+ it will
fail at "Stratum 3" (the chrome.dll constant). That's expected and is
exactly the level of protection that Google designed.

## Why does it say "57 v20-protected" but show 0 in the accounts tab?

It's an authorisation thing: in default mode we show how many credentials
are protected but **do not** show their URLs or usernames — because we
literally can't decrypt them. With `--aggressive` (if successful), the
v20 entries would be decrypted and displayed.

## What if my browser is very old?

The tool will flag it as outdated in the **Versions & CVE** tab and
generate a fix recommendation. Old Chrome versions are extremely
vulnerable (v10 era and earlier). Update.

## I have a desktop without Wi-Fi — why does it say "0 profiles"?

Recent versions detect the Windows wireless service (`wlansvc`) state
and show "Wi-Fi (n/a): wireless service not running" instead of "0
profiles". If you still see "0 profiles", you are on an older version
of the tool — pull the latest.

## Can I run this on Linux/macOS?

No. The tool uses Windows DPAPI through `crypt32.dll`. Adding Linux/macOS
support would require a completely different implementation (Linux Chrome
uses libsecret/kwallet, macOS Chrome uses Keychain). Contributions
welcome, but it's a significant undertaking.

## Can I run this in a VM?

Yes, but the audit will reflect the **VM's** user profile, not the
host's. DPAPI keys are bound to the user account inside the VM. If you
want to audit the host, run it on the host.

## Does it work with corporate-managed Chrome (group policy)?

Yes, but with caveats:

- If the corporate policy disables "save password", there will be
  nothing to decrypt — the audit will show 0 credentials.
- If the corporate policy enforces a Primary Password, Firefox audit
  will fail unless you provide that password (currently a CLI flag is
  not exposed for this).

## How accurate is the "current stable" version check?

The tool fetches from the same APIs Chrome/Firefox/Edge themselves use
for updates:

- Chromium Dash for Chrome
- product-details.mozilla.org for Firefox
- edgeupdates.microsoft.com for Edge
- api.github.com/repos/brave/brave-browser/releases/latest for Brave

These are authoritative. The cached value is refreshed every 24 hours.

It's possible for the tool to show "you are *more* recent than the
latest stable" if you're on a beta/dev channel. That's expected.

## Why does the report contain my passwords in clear text?

Only if you passed `--showpassword`. Without it, passwords are masked
(`M*****a`). Delete the report after use, or regenerate without the
flag.

## Where does the tool store its data?

- `./reports/` — HTML and JSON output, kept until you delete them.
- `%TEMP%\pwd_audit_*.json` — small JSON caches, expire after 24h.
- `%TEMP%\<random>` — transient files for aggressive mode, deleted
  immediately after use.

Nothing is written to the registry, system paths, or outside the
project directory.

## Will running this make Defender alert on me?

The tool itself is a regular Python script and should not trigger
Defender. However:

- If you opt-in to install LaZagne, Defender will alert on the install.
- In aggressive mode, the scheduled-task-as-SYSTEM step *can* be
  reported by behavioural detection on some EDR products.

If you see alerts, that's good. It means your security is working. The
tool's behaviour is documented and intentional.

## Can the tool be misused?

In principle, anyone with administrative access to a Windows machine
can audit credentials on that machine, with or without our tool.
LaZagne, mimikatz, NirSoft, and many other tools have existed for over
a decade.

What our tool offers over those is:

- A **defensive** framing (no exfiltration, no exploits, no malware
  samples included).
- A **threat-model-aware** report (what is decryptable vs. protected,
  ranked by criticality).
- An **education** layer (the timeline, the bypass technique catalogue).

If misused, the legal and ethical responsibility lies with the user.
See [`DISCLAIMER.md`](../DISCLAIMER.md).

## How often should I re-run it?

Reasonable cadences:

- **After a security incident**: immediately, then again 24 h later to
  verify nothing was missed.
- **After a browser major-version update**: to verify the new ABE
  protection level applied.
- **Quarterly**: to check that you haven't accumulated unnecessary
  saved credentials.
- **After migrating to a password manager**: to confirm the browser is
  now empty.

## I'm a security researcher. Can I cite this project?

Sure. Suggested citation:

```
ToolSicurezza: Defensive infostealer audit suite for Windows.
GitHub: https://github.com/AlessioSavelli/ToolSicurezza
2026.
```

If you publish research that updates the KB, please open a PR with
the relevant additions and citations.
