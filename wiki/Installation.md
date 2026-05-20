# Installation

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Windows 10 (1809+) or Windows 11. The tool uses DPAPI through `crypt32.dll`, so it will not work on Linux, macOS, or under WSL. |
| **Python** | 3.10 or later. 3.12 is the version tested most. |
| **Disk** | < 50 MB |
| **RAM** | Negligible (operates on small SQLite copies in `%TEMP%`) |
| **Network** | Optional. Only needed for live version-check from official vendors. |
| **Privileges** | None for the default audit. Administrator required only for `--aggressive` mode (v20 ABE attempt). |

> **Note on virtualisation:** if you run the tool inside a Hyper-V or
> VirtualBox VM, the DPAPI keychain is the VM's user, not the host's.
> You will get the credentials saved in the VM, not on your laptop/desktop.

## Step-by-step install

### 1. Clone the repository

```powershell
git clone https://github.com/AlessioSavelli/ToolSicurezza.git
cd ToolSicurezza
```

### 2. (Recommended) create a virtual environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If your execution policy blocks the activate script:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 3. Install dependencies

```powershell
py -m pip install -r requirements.txt
```

This installs only `cryptography`. Everything else is either standard
library, or auto-installed by the tool on first run (`pypykatz`,
`browser_cookie3`).

### 4. (Optional) install the extra Python recovery tools manually

```powershell
py -m pip install pypykatz browser-cookie3
```

You don't have to. `infostealer_audit.py` will do it for you on first
run.

### 5. Verify

```powershell
py infostealer_audit.py --help
```

You should see the help message.

## Updating

```powershell
git pull
py -m pip install -U -r requirements.txt
```

The auto-update mechanism for `pypykatz` and `browser_cookie3` checks
for newer versions every 24 hours and upgrades silently. Force it with
`--force-tool-update`.

## Uninstalling

```powershell
cd ..
Remove-Item -Recurse -Force ToolSicurezza
```

If you used a virtualenv, also delete `%LOCALAPPDATA%\pip\Cache` and
the auto-installed pip packages, if you want a fully clean removal:

```powershell
py -m pip uninstall -y cryptography pypykatz browser-cookie3
```

The tool also creates a few cache/state files in `%TEMP%`:

- `pwd_audit_versions_cache.json`
- `pwd_audit_tools_state.json`

These are safe to delete at any time.

## Common installation issues

### "py is not recognized"

Install Python from python.org and make sure the *py launcher* checkbox
is enabled. Alternatively, use `python` instead of `py`.

### "git is not recognized"

Install Git for Windows from https://git-scm.com/.

### `cryptography` install fails on Windows

Make sure you are using a modern Python (3.10+) and pip (>= 21).
`cryptography` ships pre-built wheels for Windows since v3.4.

```powershell
py -m pip install --upgrade pip
py -m pip install cryptography
```

### Defender flags the LaZagne install

This is expected. `LaZagne` is a well-known PUA-flagged binary. By
default `ToolSicurezza` **does not** auto-install it. To opt in:

```powershell
py infostealer_audit.py --install-flagged-tools
```

If you go this route, you may need a Defender exclusion for the install
directory. Do this **only on your own development machine** and never on
production systems.

### Aggressive mode fails to elevate

You need a user account that is a member of the local Administrators
group. The UAC prompt must be accepted. On systems where UAC is
disabled or the account is restricted, aggressive mode will not work.
