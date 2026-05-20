# Architecture

This page describes how `ToolSicurezza` is structured internally.

## Module map

```
┌──────────────────────────────────────────────────────────────────┐
│ infostealer_audit.py (orchestrator, ~1000 LOC)                   │
│                                                                  │
│  9-step workflow:                                                │
│   1. Load KB                  ──► browser_versions.load_kb()     │
│   2. Detect installed         ──► browser_versions.detect_*()    │
│   3. Online version check     ──► online_versions.fetch_all()    │
│   4. Tool auto-install        ──► external_tools.ensure_*()      │
│   5. Match version vs KB      ──► browser_versions.render_*()    │
│   6. Decrypt Chromium creds   ──► chromium_decrypt.extract_all() │
│      Decrypt Firefox creds    ──► firefox_nss.decrypt_*()        │
│   7. Detect targets+legacy    ──► infostealer_targets +          │
│                                    legacy_decrypt                │
│   8. LaZagne Light            ──► lazagne_light.run_*()          │
│   9. Generate fix recs        ──► browser_versions.generate_*()  │
└──────────────────────────────────────────────────────────────────┘
                       │
                       ├─ detect language ──► i18n.detect_system_language()
                       │                      i18n.get_strings(lang)
                       ▼
         render_html(state) → reports/infostealer_*.html
```

## Module responsibilities

### `modules/browser_versions.py`

- Detect installed browser versions from registry and file `VersionInfo`.
- Load `kb/vulnerabilities.json`.
- Match a (browser, version) tuple against KB entries.
- Generate fix recommendations.

No side effects, no filesystem writes.

### `modules/chromium_decrypt.py`

- DPAPI wrapper via `ctypes` + `crypt32.dll`.
- Read `Local State` JSON, extract and decrypt master key.
- Decrypt `Login Data` SQLite blobs in v10 and v20 formats.
- Discover all Chromium-based browser profiles.

Pure local operation. Writes nothing outside `%TEMP%` (transient
SQLite copies, deleted after use).

### `modules/firefox_nss.py`

- Parse ASN.1 structures (manual parser, no `pyasn1` dependency).
- Compute PBKDF2-HMAC-SHA256 key from `globalSalt` + (optional)
  Primary Password.
- Decrypt `key4.db` master via AES-256-CBC.
- Decrypt `logins.json` entries via 3DES-CBC (legacy) or AES (modern).

### `modules/online_versions.py`

- HTTP GET against:
  - `https://chromiumdash.appspot.com/fetch_releases` for Chrome
  - `https://product-details.mozilla.org/1.0/firefox_versions.json` for Firefox
  - `https://edgeupdates.microsoft.com/api/products` for Edge
  - `https://api.github.com/repos/brave/brave-browser/releases/latest` for Brave
- Cache results in `%TEMP%\pwd_audit_versions_cache.json` for 24h.
- Compare installed vs latest, compute major-version gap and risk.

### `modules/external_tools.py`

- Maintain a registry of optional Python tools.
- Check each one for availability (importable / on PATH).
- Auto-install missing tools via pip.
- Auto-upgrade installed tools every 24h.
- Defender-PUA-flagged tools are opt-in only via `--install-flagged-tools`.

### `modules/infostealer_targets.py`

- Detection-only scans for nine target categories.
- Returns structured dicts with presence flag, severity tag, and free-form
  details.

No decryption or extraction of third-party data, only enumeration.

### `modules/lazagne_light.py`

- Built-in replica of the most useful LaZagne categories.
- Each function returns a list of dicts (or one dict).
- Algorithms are public:
  - WinSCP: published XOR-based scheme.
  - FileZilla: base64 (not encrypted by design).
  - Pidgin: plaintext XML.
  - Thunderbird: NSS (reuses `firefox_nss.py`).
- For each category, no third-party scraping or network calls.

### `modules/legacy_decrypt.py`

- Windows Credential Manager enumeration via `cmdkey /list`.
- IE Legacy Vault file detection (no decryption — out of scope).
- Outlook profile enumeration via registry.

### `modules/i18n.py`

- Holds all user-visible strings for the HTML report in five languages:
  `it`, `en`, `fr`, `de`, `es`.
- `detect_system_language()` reads `HKCU\Control Panel\International\LocaleName`
  via `winreg`, splits on `-` to get the 2-letter code, and returns it if
  it is in the supported set. Falls back to the `locale` module, then to
  `"en"`.
- `get_strings(lang)` returns the flat `dict[str, str]` for the requested
  language. Unknown codes fall back to English.
- `SUPPORTED = {"it", "en", "fr", "de", "es"}` is the authoritative set.
  The CLI also accepts `"du"` as an alias for `"de"`, resolved in
  `main()` before `get_strings()` is called.
- Both `infostealer_audit.py` and `pwd_audit.py` import this module.
- Adding a new language requires only a new key in the `_S` dictionary.
  See [Adding a Browser](Adding-a-Browser.md) for the analogous pattern.

No side effects. No file I/O. No network calls.

### `kb/vulnerabilities.json`

A JSON file with four top-level sections:

- `_meta` — schema version (currently **1.1**), last updated,
  current stable versions, sources.
- `browser_cves` — *(new in v1.1)* array of CVE objects for Chrome/Edge/
  Windows with CVSS score, in-wild flag, affected version range, and fix
  version. Sourced from NVD, zero-day.cz, and vendor advisories.
- `chromium_abe_timeline` — array of version-range entries.
- `bypass_techniques` — keyed by technique-ID (`com-elevator-path-bypass`,
  `dll-injection-chrome-exe`, `debugger-attach-voidstealer`,
  `server-side-exfil-decrypt`, etc.).
- `browsers` — per-browser metadata (config path, CLSID, etc.).
- `known_infostealers` — **20 families** keyed by family name
  (RedLine, Lumma, VoidStealer 2.0, Storm, REMUS, ...).
- `infostealer_targets` — keyed by target category.

## Data flow for "decrypt all Chromium passwords"

```
Local State (JSON)
   │
   ├─ os_crypt.encrypted_key (base64)
   │     │
   │     ├─ strip "DPAPI" prefix
   │     ├─ CryptUnprotectData()  ── user-context
   │     └─► MASTER_KEY_v10 (32 bytes)
   │
   └─ os_crypt.app_bound_encrypted_key (base64, Chrome 127+)
         │
         ├─ strip "APPB" prefix + 4-byte version
         ├─ CryptUnprotectData()  ── needs SYSTEM context (aggressive mode)
         ├─ inner: another DPAPI blob, user-context
         └─► MASTER_KEY_v20 (32 bytes)   [aggressive mode only]

Login Data (SQLite)
   │
   └─ logins.password_value (BLOB)
         │
         if blob[:3] == b"v10":
            nonce  = blob[3:15]
            ct_tag = blob[15:]
            AESGCM(MASTER_KEY_v10).decrypt(nonce, ct_tag) → plaintext
         elif blob[:3] == b"v20":
            (requires MASTER_KEY_v20)
            AESGCM(MASTER_KEY_v20).decrypt(nonce, ct_tag) → opaque header + plaintext
         else:
            CryptUnprotectData(blob) → plaintext  (pre-v10)
```

## Data flow for "online version check"

```
fetch_all_latest()
   │
   ├─ Check %TEMP%\pwd_audit_versions_cache.json
   │  └─ if age < 24h: return cached
   │
   ├─ HTTP GET chromiumdash.appspot.com
   ├─ HTTP GET product-details.mozilla.org
   ├─ HTTP GET edgeupdates.microsoft.com
   ├─ HTTP GET api.github.com (brave releases)
   │
   ├─ Parse + normalise to {version, major, release_date, source}
   ├─ Save to cache
   └─ Return dict
```

## Data flow for aggressive mode

```
User runs: py pwd_audit.py --aggressive
   │
   ├─ is_admin()? → no
   │  └─ ShellExecuteW(verb="runas", file=python.exe, args=...)
   │     └─ UAC prompt → user accepts
   │        └─ Elevated console starts the same script with admin token
   │
   ├─ get_app_bound_key_aggressive(local_state)
   │  ├─ user-DPAPI unwrap outer blob
   │  ├─ Write inner blob to %TEMP%\pa<rnd>i.bin
   │  ├─ Write helper script to %TEMP%\pa<rnd>h.py
   │  ├─ Write batch wrapper to %TEMP%\pa<rnd>w.bat
   │  ├─ schtasks /Create /RU SYSTEM /TR <wrapper.bat>
   │  ├─ schtasks /Run
   │  ├─ Wait for output file
   │  ├─ Read output (SYSTEM-decrypted inner blob)
   │  ├─ Try brute-force 32-byte windows against a known v20 sample
   │  └─ schtasks /Delete + remove temp files
   │
   └─ If brute-force succeeds → MASTER_KEY_v20 → decrypt all v20 entries
      If brute-force fails → "Stratum 3 resists" → fall back to v20-protected
```

## Threading and concurrency

The tool is **strictly single-threaded**. Operations are sequential.
This is intentional:

- The output is more predictable and easier to debug.
- DPAPI and registry access are I/O bound; concurrency would not help
  much.
- Avoids race conditions on shared temp files.

The only "parallel" operation is the `subprocess` invocation of
`schtasks` and `netsh`, which are atomic from our perspective.

## Error handling philosophy

- **Never crash the whole audit because one source failed.** Every
  module function wraps its work in a try/except and returns an empty
  result on failure.
- **Always log what was attempted.** Failure messages go to stderr
  with the module name and a short reason.
- **Defensive timeouts.** Every `subprocess.run` has a `timeout`
  argument so a hanging external process can't lock up the audit.

## File system footprint

The tool writes only to:

- `./reports/` — HTML and JSON output (excluded from git via
  `.gitignore`).
- `./wiki/demo-reports/` — sanitized demo HTML reports committed to
  the repository (personal data stripped by `sanitize_demo_reports.py`).
- `%TEMP%\pwd_audit_*.json` — small caches.
- `%TEMP%\<random>` — transient SQLite copies and helper scripts in
  aggressive mode, deleted immediately after use.

Nothing is written to the registry. Nothing is written to system
paths. Nothing is written outside the project directory or `%TEMP%`.
