# Knowledge Base

`kb/vulnerabilities.json` is a curated, public-research-based database
that maps **Chrome versions** to **bypass techniques** to **infostealer
families** to **fix milestones**. The audit tool reads it to produce
context for every detected browser.

This page explains the schema and how to update it.

## Top-level structure

```json
{
  "_meta": { ... },
  "chromium_abe_timeline": [ ... ],
  "bypass_techniques": { ... },
  "browsers": { ... },
  "known_infostealers": { ... },
  "infostealer_targets": { ... }
}
```

## `_meta`

```json
"_meta": {
  "schema_version": "1.1",
  "last_updated": "2026-05-20",
  "current_chrome_stable": "148",
  "current_chrome_stable_date": "2026-05-05",
  "current_firefox_stable": "150",
  "current_edge_stable": "148",
  "sources": [ "https://...", ... ],
  "disclaimer": "..."
}
```

Bump `last_updated` and `current_*` whenever you update the KB.

**Schema changelog:**

| Version | Changes |
|---|---|
| 1.0 | Initial schema — `chromium_abe_timeline`, `bypass_techniques`, `browsers`, `known_infostealers`, `infostealer_targets` |
| 1.1 | Added `browser_cves` section; 20 infostealer families (up from 17: Storm, REMUS, Shai-Hulud, PennyWise); corrected `debugger-attach-voidstealer` `requires_admin` field for v2.0+; new `server-side-exfil-decrypt` bypass technique; 12 Chrome/Windows CVEs with CVSS, in-wild flag, fix version |

## `browser_cves` *(new in v1.1)*

Array of CVE objects for Chrome, Edge, and Windows components:

```json
{
  "cve_id": "CVE-2026-3910",
  "component": "V8 JavaScript Engine",
  "browser": "Chrome",
  "type": "Type confusion",
  "cvss_score": 8.8,
  "exploited_in_wild": true,
  "affected_versions": "< 136.0.7103.113",
  "fixed_in": "136.0.7103.113",
  "fix_date": "2026-04-15",
  "ref": "https://chromereleases.googleblog.com/..."
}
```

### Field semantics

- `exploited_in_wild`: `true` if Google / MSRC confirmed active
  exploitation at the time of the advisory.
- `cvss_score`: NVD base score. Use `null` if not yet assigned.
- `affected_versions`: semver range. Use `< N` for "fixed in N",
  `>= A, < B` for a bounded range.

Sources accepted for `browser_cves`: NVD (nvd.nist.gov),
Google Chrome Releases blog, Microsoft MSRC, zero-day.cz.

## `chromium_abe_timeline`

Array of objects. Each object describes a Chrome version range and the
security regime of that era.

```json
{
  "version_range": "131 - 135",
  "label": "Inner AES wrapping (Stratum 3)",
  "abe_status": "ABE_V2",
  "decrypt_difficulty": "HARD",
  "description": "Aggiunto strato finale di AES con constant key hardcoded in chrome.dll...",
  "applicable_bypasses": [
    "chrome-dll-signature-scanning",
    "dll-injection-chrome-exe",
    "reflective-process-hollowing",
    "debugger-attach-voidstealer"
  ],
  "released_date": "2024-11-12",
  "fix": {
    "fixed_in": "136+",
    "fixed_date": "2025-04-29",
    "milestone": "Remote debugging port restriction"
  }
}
```

### Field semantics

- `version_range`: `< N`, `>= N`, `N`, `N.x`, `N - M`. Used by
  `_version_in_range()`.
- `decrypt_difficulty`: `TRIVIAL`, `LOW`, `MEDIUM`, `HARD`, `VERY_HARD`.
  Drives the colour and risk score in the report.
- `applicable_bypasses`: array of technique-IDs that point into
  `bypass_techniques`.
- `fix.fixed_in`: the major version that mitigated the issue, e.g.
  `131+` means "fixed in 131 and later".

## `bypass_techniques`

Dictionary keyed by technique-ID:

```json
"chrome-dll-signature-scanning": {
  "name": "chrome.dll constant key extraction (Stratum 3 bypass)",
  "complexity": "VERY_HIGH",
  "requires_admin": false,
  "requires_system": true,
  "description": "Pattern-scan chrome.dll for the constant AES key used in the final wrap...",
  "used_by": ["Lumma Pro 2025", "Stealc V2"],
  "detection": "File access pattern, YARA on known signatures",
  "ref": "https://..."
}
```

`complexity`: `TRIVIAL`, `LOW`, `MEDIUM`, `HIGH`, `VERY_HIGH`.

`used_by` and `ref` should always cite **public** research. We do not
include private threat-intelligence.

### Current technique IDs

| ID | Name | Added |
|---|---|---|
| `com-elevator-path-bypass` | COM IElevator path validation bypass | v1.0 |
| `dll-injection-chrome-exe` | DLL injection into chrome.exe | v1.0 |
| `reflective-process-hollowing` | Reflective process hollowing | v1.0 |
| `chrome-dll-signature-scanning` | chrome.dll constant-key extraction (Stratum 3) | v1.0 |
| `remote-debugging-port` | `--remote-debugging-port` abuse | v1.0 |
| `debugger-attach-voidstealer` | Debugger attach + hardware breakpoint (VoidStealer v2.0) | v1.0 / corrected v1.1 |
| `server-side-exfil-decrypt` | Server-side blob exfiltration + remote decryption (Storm) | v1.1 |

## `browsers`

Per-browser metadata:

```json
"Chrome": {
  "vendor": "Google",
  "engine": "Chromium",
  "abe_enabled": true,
  "config_path": "%LOCALAPPDATA%\\Google\\Chrome\\User Data",
  "version_registry": ["HKLM\\SOFTWARE\\Google\\Chrome\\BLBeacon", "..."],
  "version_binary": "%PROGRAMFILES%\\Google\\Chrome\\Application\\chrome.exe",
  "current_stable": "148",
  "release_cycle_weeks": 4,
  "notes": "..."
}
```

## `known_infostealers`

Documented infostealer families (**20 entries** as of KB v1.1). Each
entry is **public** information from threat-intelligence reports.

### Current families

| Family | First seen | Notable bypass |
|---|---|---|
| RedLine | 2020-03 | DPAPI user-mode |
| Vidar | 2018-10 | DPAPI user-mode |
| Lumma C2 | 2022-08 | Dual injection / chrome.dll scan |
| Phemedrone | 2023-12 | COM IElevator |
| Meduza | 2023-06 | COM IElevator |
| StealC | 2023-01 | DPAPI user-mode |
| Rhadamanthys | 2022-09 | COM IElevator + reflective hollowing |
| WhiteSnake | 2023-02 | COM IElevator |
| Meta Stealer | 2022-03 | DPAPI user-mode |
| Lumar | 2023-07 | DPAPI user-mode |
| Glove Stealer | 2024-11 | COM IElevator |
| Kepavll | 2024-01 | DPAPI user-mode |
| Stealc V2 | 2024-06 | chrome.dll signature scanning |
| Lumma Pro 2025 | 2025-01 | chrome.dll signature scanning |
| PureLogs | 2023-04 | DPAPI user-mode |
| Atomic (AMOS) | 2023-04 | macOS-native (no ABE bypass) |
| VoidStealer | 2025-06 | Debugger attach + hardware breakpoint (v2.0: no elevation) |
| Storm | 2026-01 | Server-side encrypted blob exfiltration |
| REMUS | 2026-02 | IndexedDB password manager harvesting |
| Shai-Hulud | 2026-03 | npm supply chain |
| PennyWise | 2026-04 | YouTube distribution |

> PennyWise (2026 revival) should not be confused with the 2022 variant.

```json
"Lumma C2": {
  "first_seen": "2022-08",
  "ttp_summary": "MaaS very active 2024-2025. v20 bypass via dual-injection (Cybereason 2024)...",
  "browser_targets": ["Chrome", "Edge", "Brave", "Vivaldi", "Opera", "Firefox", "Tor"],
  "abe_bypass": "Dual injection + COM IElevator (early variants) / chrome.dll scan",
  "max_chrome_supported": "current",
  "ref": "https://cyble.com/blog/dual-injection-undermines-chromes-encryption/"
}
```

We do **not** include:

- Sample SHA256 hashes (could be used as IoCs against innocent parties)
- Operational C2 domain lists
- Detailed YARA rules
- Detonation procedures

We **do** include:

- Documented TTPs
- Browser/OS targets
- Bypass technique families
- Public research links

## `infostealer_targets`

Catalogue of the bersagli (target categories), with severity. Used by
the report to colour-code the Targets tab and the LaZagne Light tab.

## Updating the KB

When you contribute to the KB:

1. Pick a clear source. Acceptable sources are:
   - Peer-reviewed papers
   - Vendor security advisories (Google, Microsoft, Mozilla)
   - Reputable security-firm blog posts (Cybereason, Mandiant,
     CrowdStrike, BlackBerry, etc.)
   - Public threat-intel reports

2. Update `_meta.last_updated`, `_meta.current_chrome_stable`, etc.

3. If you are documenting a new era, add a new entry to
   `chromium_abe_timeline`. Make sure the previous entry's
   `version_range` ends where yours begins.

4. If you are documenting a new bypass technique, add it to
   `bypass_techniques` **and** reference it from the relevant timeline
   entries.

5. If you are documenting a new infostealer family, add it to
   `known_infostealers`.

6. Add the URL to `_meta.sources` if it's a new source.

7. Open a PR. Cite the source in the PR description.

## Schema validation

The KB is loaded with `json.load`. There is no formal schema validator
yet (planned for a future release using `jsonschema`). For now, please
ensure the file is valid JSON before committing:

```powershell
py -c "import json; json.load(open('kb/vulnerabilities.json', encoding='utf-8')); print('KB OK')"
```

## Why JSON and not YAML / TOML

- JSON parses identically across all Python versions.
- Easy to validate.
- Tooling-friendly (`jq`, online viewers, etc.).
- The KB is human-edited but machine-read; comments would be nice but
  we live without them.

Comments (where useful) are inserted as keys prefixed with `_note`,
`_comment`, etc.
