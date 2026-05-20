# CLI Reference

All commands assume you are in the project root.

## `infostealer_audit.py`

The main entry point. Performs the full 9-step audit.

### Synopsis

```
py infostealer_audit.py [OPTIONS]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--showpassword` | off | Reveal decrypted passwords in chiaro in the HTML report. Output filename is suffixed `_showpassword_`. |
| `--no-online` | off | Skip live version check against vendor APIs. Useful offline. |
| `--no-tools` | off | Skip auto-install / auto-update of external Python tools. |
| `--install-flagged-tools` | off | Opt-in to install Defender-PUA-flagged tools (LaZagne). Use at your own risk. |
| `--force-tool-update` | off | Run `pip install --upgrade` on every tool even if the 24h cache says we already checked. |
| `--no-html` | off | Don't write HTML, only CLI summary. |
| `--out PATH` | `reports/infostealer_<ts>.html` | Override HTML output path. |
| `--json PATH` | (none) | Also export structured JSON. Useful for piping into other tools. |
| `--lang LANG` | auto | Force HTML report language. Accepted values: `it` `en` `fr` `de` `du` `es`. Default: auto-detected from `HKCU\Control Panel\International\LocaleName`. `du` is an alias for `de` (Deutsch). |
| `-h`, `--help` | | Show built-in help and exit. |

### Examples

Default audit:

```powershell
py infostealer_audit.py
```

Full audit with passwords visible, JSON export, custom HTML path:

```powershell
py infostealer_audit.py --showpassword --json audit.json --out C:\Audit\report.html
```

Quick offline check:

```powershell
py infostealer_audit.py --no-online --no-tools --no-html
```

Force a full re-check of upstream tools and version data:

```powershell
py infostealer_audit.py --force-tool-update
```

Generate the report in a specific language:

```powershell
py infostealer_audit.py --lang fr          # French
py infostealer_audit.py --lang de          # German (also: --lang du)
py infostealer_audit.py --no-online --lang es   # Spanish, offline
```

## `pwd_audit.py`

The legacy deep password audit, focused exclusively on Chromium-based
browsers. Useful for the `--aggressive` v20 ABE bypass attempt.

### Synopsis

```
py pwd_audit.py [OPTIONS]
```

### Options

| Option | Default | Description |
|---|---|---|
| `--browsers LIST` | all | Comma-separated browsers: `chrome,edge,brave,vivaldi,opera,chromium`. |
| `--reveal` | off | Show plaintext passwords (alias for the `--showpassword` flag of the other tool). |
| `--aggressive` | off | Attempt v20 ABE bypass via UAC + SYSTEM-elevation scheduled task. Implies `--reveal`. |
| `--no-elevate` | off | If `--aggressive` is set and the process is not admin, exit with error instead of UAC-prompting. Useful in scripts. |
| `--no-html` | off | Skip HTML. |
| `--no-pause` | off | In `--aggressive` mode, don't pause for ENTER at the end (the elevated console closes immediately on exit). |
| `--out PATH` | `reports/audit_<ts>.html` | Override HTML output path. |
| `--lang LANG` | auto | Force HTML report language: `it` `en` `fr` `de` `du` `es`. Same auto-detection logic as `infostealer_audit.py`. |

### Aggressive mode workflow

1. Run from a non-admin shell:
   ```powershell
   py pwd_audit.py --aggressive
   ```
2. A UAC prompt appears — accept it.
3. A new elevated console window opens and runs the audit.
4. A scheduled task is created with `/RU SYSTEM`, executed once,
   then deleted automatically.
5. The script prints the result and pauses for ENTER (set
   `--no-pause` to disable).
6. A log file is also written under `reports/audit_aggressive_<ts>.log`
   so you can read the output even if the elevated console closes.

### What `--aggressive` will NOT do

- Will not work against another user's account on the same machine.
- Will not work over the network.
- Will not bypass Chrome v20 inner AES wrapping (Stratum 3) — that
  protection is by design beyond plain SYSTEM elevation.

If you see *"Master key v20 (ABE): bypass FAILED. Strato 3 resists"*
in the output, this is the **expected and correct** result on Chrome
131+.

## Environment variables

The tool reads a few environment variables but does not require any to
be set:

| Variable | Used for |
|---|---|
| `USERPROFILE` | Locate user home (browser profiles, .ssh, etc.) |
| `LOCALAPPDATA` | Locate Chrome/Edge/Brave User Data folders |
| `APPDATA` | Locate Firefox/Thunderbird/Discord/Telegram data |
| `PROGRAMDATA` | Locate Cisco AnyConnect profiles |
| `TEMP` | Working directory for transient SQLite copies and caches |
| `COMPUTERNAME` | Embedded in HTML report header |

## Cache and state files

| File | Purpose | TTL |
|---|---|---|
| `%TEMP%\pwd_audit_versions_cache.json` | Cached online vendor versions | 24 h |
| `%TEMP%\pwd_audit_tools_state.json` | Last time pip-check ran | 24 h |
| `./reports/*.html` | HTML reports | until deleted |
| `./reports/*.json` | JSON exports | until deleted |
| `./reports/audit_aggressive_*.log` | Logs from elevated `--aggressive` runs | until deleted |

All caches are safe to delete at any time — they will be regenerated.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Generic error (read the stderr trace) |
| 2 | Invalid CLI arguments |
