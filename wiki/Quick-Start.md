# Quick Start

This page walks you through the first run.

## TL;DR

```powershell
cd ToolSicurezza
py infostealer_audit.py
```

Then open the generated HTML report in `./reports/`.

## Step-by-step first run

### 1. Run the main audit

```powershell
cd ToolSicurezza
py infostealer_audit.py
```

You will see something like:

```
========================================================================
infostealer_audit.py v2 - audit surface + accounts + tools
========================================================================
Windows user: alice
Showpassword:   False

[1/9] KB loaded (Chrome stable reference: 148)

[2/9] Detecting installed browsers...
    Chrome       148.0.7778.168
    Edge         148.0.3967.70
    Brave        NOT INSTALLED
    Firefox      NOT INSTALLED
    [...]

[3/9] Live check for current stable versions from official sources...
    Chrome   latest: 148.0.7778.98 (2026-05-12)
    Firefox  latest: 150.0.3 (2026-05-12)
    Edge     latest: 148.0.3967.70 (2026-05-15)
    Brave    latest: 1.90.122 (2026-05-13)

[4/9] Verifying + auto-installing Python recovery tools...
    [tool] pypykatz                [pip] Installing...   [+] Installed
    [tool] browser_cookie3         [pip] Installing...   [+] Installed
    [tool] firepwd_internal        [ok] Already available
    [tool] lazagne                 [skip] PUA-flagged

[5/9] Matching browser versions against the KB...
    Chrome v148: score 1/10, decrypt difficulty VERY_HARD
    Edge v148:   score 1/10, decrypt difficulty VERY_HARD

[6/9] Decrypting Chromium credentials...
    Chrome/Default:   0 v10 decrypted, 57 v20-protected
    Edge/Default:     2 v10 decrypted, 0 v20-protected

[7/9] Infostealer target detection + legacy creds...
    [!] Discord Token: PRESENT [HIGH]
    Credential Manager entries: 8

[8/9] LaZagne Light: Wi-Fi/PuTTY/WinSCP/Git/...
    Wi-Fi:        n/a (wireless service not running)
    PuTTY:        0 sessions
    WinSCP:       0 sessions
    Git creds:    0
    OpenVPN:      0 configs
    [...]

[9/9] 2 fix recommendations generated

[OK] HTML report: D:\Desktop\ToolSicurezza\reports\infostealer_20260518_224717.html
```

### 2. Open the report

Open the path printed at the end in any browser. Passwords are shown
**masked** (e.g. `M*****a`) by default.

### 3. Read the tabs in order

Each tab tells a different part of the story:

1. **Overview** — top-line stats and overall risk banner
2. **Accounts per browser** — every credential decrypted, grouped by
   browser and profile
3. **Versions & CVE** — installed vs. latest stable, with bypass
   techniques applicable to your version
4. **Infostealer targets** — Discord, Steam, wallets, SSH, etc.
5. **LaZagne Light** — Wi-Fi, PuTTY/WinSCP, Git, OpenVPN, ...
6. **Legacy credentials** — Windows Credential Manager, IE Vault
7. **Recovery tools** — which external tools are available
8. **Fix recommendations** — what to do now
9. **ABE Timeline** — Chrome 127→148 evolution

### 4. Act on the fix recommendations

Open the **Fix recommendations** tab. Recommendations are ordered
CRITICAL → HIGH → MEDIUM → LOW. Each one tells you:

- What to do
- Why
- The exact steps to do it

Work through them top-down.

### 5. Run again

After you've changed passwords / disabled save-password / updated
browser / migrated to a password manager, run the audit again to see
the residual surface area shrink.

## Common follow-up commands

### Generate the report in a specific language

```powershell
py infostealer_audit.py --lang en   # English
py infostealer_audit.py --lang fr   # Français
py infostealer_audit.py --lang de   # Deutsch  (alias: --lang du)
py infostealer_audit.py --lang es   # Español
py infostealer_audit.py --lang it   # Italiano
```

By default the report language is **auto-detected** from your Windows
locale. If you are on an Italian Windows install you do not need
`--lang it` — it just works.

Want to preview what the report looks like before running the tool?
See the [Demo Reports](Demo-Reports.md).

### See the actual passwords (for verification)

```powershell
py infostealer_audit.py --showpassword
```

The HTML report will contain plaintext passwords. Delete the report
after use.

### Skip the live online check

```powershell
py infostealer_audit.py --no-online
```

Useful on offline machines or to avoid the 5-10 second network
roundtrip.

### Skip the auto-install of Python tools

```powershell
py infostealer_audit.py --no-tools
```

Useful if you've already installed everything or are on a restricted
network.

### Try the aggressive v20 ABE bypass

```powershell
py pwd_audit.py --aggressive
```

This will prompt UAC and attempt to decrypt v20-protected passwords by
elevating to NT AUTHORITY\SYSTEM. On modern Chrome (131+) this will
**fail by design** at the "Stratum 3" inner AES wrapping. That is the
expected and correct result.

### Export raw JSON

```powershell
py infostealer_audit.py --json out.json
```

Machine-readable output, no HTML. Useful for piping into another tool.

## What "good" looks like

On a well-maintained machine you should see:

- Both Chrome and Edge at `VERY_HARD` decrypt difficulty with risk score
  1/10.
- Few or zero v10-decrypted passwords (only legacy entries Chrome hasn't
  re-encrypted yet).
- 0 outdated browsers.
- The "Targets" tab mostly empty.
- Fix recommendations only of severity MEDIUM or below.

On a machine that has not been audited recently you may see:

- Browsers several major versions behind.
- 50+ v10-decrypted passwords (Chrome < 127 or legacy entries).
- Multiple SHA-256-identical passwords reused on many sites.
- Discord token present, Telegram session present, multiple crypto
  wallet extensions installed.
- 10+ HIGH/CRITICAL fix recommendations.

The bigger the gap between the two pictures, the more this tool has
helped you.
