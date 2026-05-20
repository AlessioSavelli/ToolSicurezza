# Adding a Browser

This page is for contributors who want to add support for a new
Chromium-based browser (or a new Gecko-based browser).

## Is it Chromium-based?

If yes, the data layout is essentially the same as Chrome:

```
%LOCALAPPDATA%\<Vendor>\<Browser>\User Data\
├── Local State                  ← contains os_crypt.encrypted_key
├── Default\
│   └── Login Data               ← SQLite with logins table
├── Profile 1\
│   └── Login Data
└── ...
```

To add support, you need to do three things:

### 1. Register the path in `chromium_decrypt.py`

Edit `discover_chromium_browsers()`:

```python
candidates = [
    ("Chrome", local / "Google/Chrome/User Data"),
    ("Edge", local / "Microsoft/Edge/User Data"),
    # ...
    ("YourBrowser", local / "Vendor/YourBrowser/User Data"),  # NEW
]
```

### 2. Register version detection in `browser_versions.py`

Add a `detect_<browser>_version()` function:

```python
def detect_yourbrowser_version() -> str | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "Vendor/YourBrowser/Application/yourbrowser.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Vendor/YourBrowser/Application/yourbrowser.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None
```

And call it from `detect_all_browsers()`.

### 3. Add to the KB

Open `kb/vulnerabilities.json` and add an entry under `browsers`:

```json
"YourBrowser": {
  "vendor": "Vendor Inc.",
  "engine": "Chromium",
  "abe_enabled": true,
  "config_path": "%LOCALAPPDATA%\\Vendor\\YourBrowser\\User Data",
  "version_binary": "%PROGRAMFILES%\\Vendor\\YourBrowser\\Application\\yourbrowser.exe",
  "current_stable": "<known version>",
  "notes": "..."
}
```

### 4. (Optional) Add live version check

If the vendor publishes a JSON/API endpoint with the latest stable
version, add a `fetch_yourbrowser_latest()` function in
`modules/online_versions.py` and call it from `fetch_all_latest()`.

If no API exists, scrape with caution (be polite, cache aggressively).

### 5. (Optional) Crypto wallet extensions

If your browser uses the same extension ID scheme as Chrome, the
existing `infostealer_targets.check_crypto_wallets()` will already
discover wallet extensions in this browser's profiles.

## Is it Gecko-based?

If yes (Firefox, LibreWolf, Waterfox, Pale Moon, ...), the data is
NSS-based:

```
%APPDATA%\<Vendor>\<Browser>\Profiles\<random>.default\
├── key4.db                      ← SQLite, contains NSS keys
└── logins.json                  ← encrypted login blobs
```

Edit `modules/firefox_nss.py`:

```python
def discover_yourbrowser_profiles() -> list[Path]:
    base = Path(os.environ.get("APPDATA", "")) / "Vendor/YourBrowser/Profiles"
    if not base.exists():
        return []
    profiles = []
    for sub in base.iterdir():
        if sub.is_dir() and (sub / "key4.db").exists():
            profiles.append(sub)
    return profiles
```

And in `infostealer_audit.py`, in the Firefox section, add:

```python
yb_profiles = firefox_nss.discover_yourbrowser_profiles()
for prof in yb_profiles:
    creds = firefox_nss.decrypt_firefox_logins(prof)
    # ... add to state["firefox_accounts"][prof.name]
```

## Testing your contribution

```powershell
# 1. Sanity check (don't crash)
py infostealer_audit.py --no-online --no-tools

# 2. Live online check still works
py infostealer_audit.py --no-tools

# 3. Full audit with the new browser installed
py infostealer_audit.py --showpassword

# 4. Verify the HTML report has a section for your browser
```

## Don't forget

- Update `wiki/Installation.md` if your browser has special install
  requirements.
- Update the supported-browsers list in `README.md` and `README_IT.md`.
- Add the browser to the `chromium_abe_timeline` if it diverges from
  Chrome's ABE schedule (Edge generally tracks Chrome but lags ~0-2
  versions; Brave tracks Chromium upstream).
- If your browser implements a custom encryption scheme different from
  v10/v20, document it in `kb/vulnerabilities.json` and implement a
  custom decryption path.

## Submitting

Open a PR with:

- Code changes in `modules/`.
- KB entry under `browsers`.
- Updated docs (README + wiki).
- A screenshot of the audit detecting your browser successfully.
