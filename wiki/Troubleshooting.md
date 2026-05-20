# Troubleshooting

## "Sintassi OK" but the tool exits silently

Make sure you didn't accidentally pipe stdin somewhere. Run with `--no-html`
first to see all console output.

## "cryptography" import error

Install or upgrade:

```powershell
py -m pip install --upgrade cryptography
```

## "py is not recognized"

The Python launcher is not in PATH. Either:

- Reinstall Python from python.org with "Add Python to PATH" checked, **or**
- Use `python` instead of `py`.

## "No module named modules"

You are running the script from outside the project root. `cd` into
`ToolSicurezza/` first.

## "Master key v10: failed"

Either your Local State is corrupted, or you're trying to read a profile
belonging to another user. Verify:

```powershell
Get-Content "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" | Select-String "encrypted_key"
```

You should see a base64 string. If empty, the browser profile is not
initialised (browser hasn't been launched yet).

## "DPAPI fail err=-2146893813 (0x8009000B)"

Translation: `NTE_BAD_DATA`. The blob you tried to decrypt is not valid
DPAPI data, or the data was encrypted with a different user's key.

If this happens in `--aggressive` mode, it likely means the blob format
has changed in a newer Chrome — please open an issue with your Chrome
version.

## Aggressive mode: "schtasks /Create failed (/TR > 261 chars)"

This was a bug fixed in v3. We now use a `.bat` wrapper to keep the
`/TR` short. If you still see it, you're on an older build — pull
latest.

## Aggressive mode: brute-force key not found

Expected on Chrome 131+. The v20 ABE has an additional Stratum 3
(chrome.dll constant) that prevents key recovery by SYSTEM-DPAPI alone.
Read [HTML Report](HTML-Report.md) tab "ABE Timeline" for details.

## "Wi-Fi profiles: 0" on a laptop

The tool detects `wlansvc not running` automatically. If the service is
actually running but you still get 0, try:

```powershell
netsh wlan show profiles
```

If that command shows profiles but the tool still finds none, please
file an issue with the exact `netsh` output (with SSIDs redacted).

## "External tools" tab shows "lazagne installed" but I never installed it

In v2 we had a false-positive on the LaZagne detection. v3 fixes this
using `shutil.which` + module-presence checks. If you still see false
positives, please file an issue.

## Browser version detection fails

The tool tries multiple methods: registry keys, file `VersionInfo` of
the `.exe`, and `EdgeUpdate` for Edge. If all fail:

- Make sure the browser is installed via official installer (not a
  portable zip).
- Run as the same user who installed the browser.
- Try `py -c "from modules.browser_versions import detect_chrome_version; print(detect_chrome_version())"`.

## Online version check fails / "unavailable"

- Check internet connectivity.
- Try `--force-tool-update` to invalidate the cache.
- Some corporate networks block GitHub API or Mozilla's product-details
  endpoint. Use `--no-online` if so.

## HTML report is 0 bytes / corrupted

Something errored after the file was opened but before content was
written. Run with `--no-html` to see if a Python exception is thrown,
and report it.

## "Defender deleted my LaZagne install"

Expected. Defender flags LaZagne as PUA. Either:

- Don't install LaZagne (the default — our `lazagne_light` replaces
  most of it natively), **or**
- Add a Defender exclusion for the install path (only on dedicated
  audit machines).

## Aggressive mode shows the elevated console for 1 second and closes

You're running with `--no-pause`. Remove that flag to keep the console
open. The log is also written to `reports/audit_aggressive_*.log` —
read it there.

## "Permission denied" on `reports/`

The directory may be read-only or owned by a different user. Delete it
and let the tool re-create it:

```powershell
Remove-Item -Recurse -Force reports
py infostealer_audit.py
```

## How to get more debug output

Set environment variable `PWD_AUDIT_DEBUG=1` (planned, not yet
implemented). For now, edit the script and add `print()` statements
where useful.

## I see different results on different runs

Browser data changes constantly (you log in, you save passwords, you
clear data). That's normal. The version check is cached for 24h so
that part is stable.

## How to report a bug

1. Update to the latest version: `git pull`.
2. Reproduce with `py infostealer_audit.py --no-online --no-tools` to
   eliminate network/installer variables.
3. Open an issue using the bug-report template in
   [.github/ISSUE_TEMPLATE/bug_report.md](../.github/ISSUE_TEMPLATE/bug_report.md).
4. Include OS version, Python version, browser version, exact command
   line, full console output (redact passwords).
