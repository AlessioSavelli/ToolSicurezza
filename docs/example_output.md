# Example output

Reference output for a "well-maintained" Windows 11 machine running
modern Chrome and Edge, with Discord installed and a few entries in
Windows Credential Manager.

## Console output

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
    Vivaldi      NOT INSTALLED
    Firefox      NOT INSTALLED
    Opera        NOT INSTALLED

[3/9] Live check for current stable versions from official sources...
    [cache] using cached versions (age < 24h)
    Chrome   latest: 148.0.7778.98 (2026-05-12) [chromiumdash.appspot.com]
    Firefox  latest: 150.0.3 (2026-05-12) [product-details.mozilla.org]
    Edge     latest: 148.0.3967.70 (2026-05-15) [edgeupdates.microsoft.com]
    Brave    latest: 1.90.122 (2026-05-13) [github.com/brave/brave-browser]

[4/9] Verifying + auto-installing Python recovery tools...
  [tool] pypykatz - Mimikatz pure-Python (DPAPI, LSASS, SAM)
    [ok] Already installed
  [tool] firepwd_internal - Firefox NSS decrypt (internal impl)
    [ok] Already installed
  [tool] browser_cookie3 - Multi-browser cookie extractor
    [ok] Already installed
  [tool] lazagne - LaZagne - multi-source credential dumper
    [skip] PUA-flagged, skipping auto-install.

[5/9] Matching browser versions against the KB...
    Chrome v148.0.7778.168: score 1/10, decrypt difficulty VERY_HARD
    Edge v148.0.3967.70:    score 1/10, decrypt difficulty VERY_HARD

[6/9] Decrypting Chromium credentials...
    Chrome/Default:   0 v10 decrypted, 57 v20-protected
    Edge/Default:     2 v10 decrypted, 0 v20-protected

[7/9] Infostealer target detection + legacy creds...
    [!] Discord Token: PRESENT [HIGH]
         Found 6 .ldb + 1 .log in 1 Discord install
         [!] 'v10_' encrypted token pattern detected in leveldb
    [ok] Steam autologin            not found
    [ok] Crypto wallets             not found
    [ok] Telegram Desktop session   not found
    [ok] SSH private keys           not found
    [ok] GPG keyring                not found
    [ok] FileZilla sitemanager      not found
    [ok] Windows Credential Manager not found
    [ok] VPN client configs         not found
    Credential Manager entries: 8
    Wi-Fi profiles: 0

[8/9] LaZagne Light: Wi-Fi/PuTTY/WinSCP/Git/OpenVPN/...
    Wi-Fi:        n/a (wireless service not running)
    PuTTY:        0 sessions
    WinSCP:       0 sessions (0 with decrypted pwd)
    Git creds:    0 (.git-credentials plaintext)
    OpenVPN:      0 configs (0 with auth file)
    FileZilla:    0 sites (0 with pwd)
    Thunderbird:  0 credentials
    Pidgin:       0 chat accounts
    DBVisualizer: 0 databases
    RDP files:    0
    TOTAL extra credentials found: 0

[9/9] 2 fix recommendations generated

[OK] HTML report: D:\Desktop\ToolSicurezza\reports\infostealer_20260518_224717.html
```

## JSON output (excerpt, sanitised)

```json
{
  "showpassword": false,
  "browsers_installed": {
    "Chrome": "148.0.7778.168",
    "Edge": "148.0.3967.70",
    "Brave": null,
    "Vivaldi": null,
    "Firefox": null,
    "Opera": null
  },
  "latest_versions": {
    "Chrome": {
      "browser": "Chrome",
      "version": "148.0.7778.98",
      "major": 148,
      "release_date": "2026-05-12",
      "channel": "Stable",
      "source": "chromiumdash.appspot.com"
    },
    "Firefox": {
      "browser": "Firefox",
      "version": "150.0.3",
      "major": 150,
      "release_date": "2026-05-12",
      "source": "product-details.mozilla.org"
    }
  },
  "version_comparison": [
    {
      "browser": "Chrome",
      "installed": "148.0.7778.168",
      "latest": "148.0.7778.98",
      "latest_date": "2026-05-12",
      "is_outdated": false,
      "major_gap": 0,
      "risk_level": "OK"
    },
    {
      "browser": "Edge",
      "installed": "148.0.3967.70",
      "latest": "148.0.3967.70",
      "latest_date": "2026-05-15",
      "is_outdated": false,
      "major_gap": 0,
      "risk_level": "OK"
    }
  ],
  "browser_summary": [
    {
      "browser": "Chrome",
      "version": "148.0.7778.168",
      "major": 148,
      "abe_status": "ABE_V3_DBSC",
      "decrypt_difficulty": "VERY_HARD",
      "score": 1,
      "outdated": false,
      "current_stable": "148"
    }
  ],
  "chromium_accounts": {
    "Chrome": [
      {
        "profile": "Default",
        "credentials": [],
        "v10_decrypted": 0,
        "v20_total": 57,
        "v20_decrypted": 0,
        "v20_protected": 57
      }
    ],
    "Edge": [
      {
        "profile": "Default",
        "credentials": [
          {
            "url": "http://192.168.1.1/",
            "username": "admin",
            "password": "<REDACTED>",
            "format": "v10",
            "blob_len": 41,
            "decryptable": true
          }
        ],
        "v10_decrypted": 2,
        "v20_protected": 0
      }
    ]
  },
  "target_results": [
    {
      "target": "Discord Token",
      "found": true,
      "paths": ["C:\\Users\\alice\\AppData\\Roaming\\discord\\Local Storage\\leveldb"],
      "ldb_files": 6,
      "log_files": 1,
      "encrypted_token_pattern_found": true,
      "value": "HIGH",
      "description": "Token API Discord ..."
    }
  ],
  "fix_recs": [
    {
      "priority": "MEDIUM",
      "browser": "Chrome",
      "action": "Disable 'Save passwords' in the browser",
      "reason": "Even with v20 ABE active, reducing the attack surface is better than protecting it.",
      "how": "Settings > Password manager > disable 'Offer to save passwords'."
    }
  ]
}
```

## What the HTML looks like

A 9-tab interactive report. Screenshots in
[`docs/screenshots/`](screenshots/). High-level layout:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Infostealer Audit Report                                            │
│ Generated: 2026-05-18 22:47 — user: alice — machine: PC-ALICE       │
├─────────────────────────────────────────────────────────────────────┤
│ Overall risk: LOW                                          (green)  │
├─────────────────────────────────────────────────────────────────────┤
│ ╔═══════════╦═══════════╦═══════════╦═══════════╦═══════════╗       │
│ ║ Browsers  ║ Decrypted ║ Protected ║ Outdated  ║ Targets   ║       │
│ ║    2      ║    2      ║   57      ║    0      ║    1      ║       │
│ ╚═══════════╩═══════════╩═══════════╩═══════════╩═══════════╝       │
├─────────────────────────────────────────────────────────────────────┤
│ [Overview] [Accounts] [Versions&CVE] [Targets] [LaZagne Light]      │
│ [Legacy] [Tools] [Fixes] [ABE Timeline]                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [contents of the active tab, table or cards]                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```
