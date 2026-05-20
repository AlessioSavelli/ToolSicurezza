# Threat Model

This page describes what this tool defends against, and what it
explicitly does **not** try to address.

## In scope (what we audit)

### Threat actor: user-mode infostealer

The primary threat actor we audit against is a **commodity Windows
infostealer** that has obtained code execution as the current user (no
admin, no SYSTEM). Examples:

- RedLine, Vidar, Lumma C2, StealC, Rhadamanthys, Phemedrone, Glove
  Stealer, Stealka, Shuyal, Torg Grabber, Arkanix, ...

The infostealer typically runs once, harvests credentials, exfiltrates,
and exits. It does not maintain persistence (other variants do, but
this is not our threat model).

### What such a threat actor can and cannot do

✅ Can:

- Read any file the current user can read.
- Call DPAPI in the current user's context → decrypt v10 master keys.
- Read Chromium `Local State` and `Login Data`.
- Read Firefox `key4.db` and `logins.json`.
- Run `cmdkey /list` and read Windows Credential Manager entries.
- Read `~/.ssh/`, `~/.gnupg/`, `%APPDATA%\Telegram Desktop\tdata\`,
  Discord LevelDB, Steam VDF.
- Enumerate browser extensions and their per-extension data folders.

❌ Cannot:

- Call DPAPI in SYSTEM context (would need elevation).
- Decrypt Chrome v20 ABE without bypass (Stratum 3 hardcoded constant
  in chrome.dll, requires DLL injection or signature scanning).
- Touch other users' profiles on the same machine.
- Read TPM-bound keys (DBSC, future Chrome).

### Our coverage

For every credential store the threat actor can read, we read the same
data and report it back to the user. We close the loop by quantifying
exposure.

## In scope (what we audit, extended)

### Threat actor: admin-elevated infostealer

Some infostealers (or post-exploitation tools) gain Administrator. With
admin, additional capabilities open up:

✅ Can additionally:

- Spawn a scheduled task as SYSTEM (this is what `--aggressive` mode
  demonstrates).
- Run `mimikatz`/`pypykatz` to dump LSASS and Credential Manager
  protected secrets.
- Disable Windows Defender (with policy bypass).
- Bypass v20 Stratum 2 (SYSTEM-DPAPI of the inner blob).

❌ Still cannot (typically):

- Decrypt v20 Stratum 3 (chrome.dll constant) without DLL injection
  into chrome.exe itself.
- Read TPM-bound keys without active user session.

### Our coverage of admin scenarios

`--aggressive` mode in `pwd_audit.py` simulates this exactly:

1. UAC elevation.
2. Scheduled task as SYSTEM.
3. SYSTEM DPAPI unwrap of the v20 inner blob.
4. Try to find the AES key inside the unwrapped blob.
5. Report the result.

This lets the user see whether admin-level credential theft would
succeed or not.

## Out of scope (what we don't audit)

### Threat actor: kernel-level / firmware-level attacker

We do **not** address:

- Kernel rootkits.
- UEFI/BIOS implants.
- Hardware-backed memory acquisition (cold boot, DMA, ...).
- Bootkits.

If an attacker has kernel-level access, they have everything. No
user-mode tool can defend against that.

### Threat actor: physical attacker with offline disk

We do **not** address:

- Attacker who removed the disk and is reading it on another machine.

DPAPI is bound to the user account's master key, which itself is
encrypted with the user's NT hash. An offline attacker who knows or
brute-forces the NT hash can decrypt everything.

Defense: BitLocker. Out of scope for this project but explicitly
recommended in the fix recommendations.

### Threat actor: malicious browser extension

A malicious extension can read the credentials in the browser's
**runtime** memory, regardless of how they are stored on disk. We do
not audit installed browser extensions for malicious behaviour
(beyond detecting crypto wallet extensions, which we report as
*targets*, not *threats*).

Defense: only install extensions from trusted sources. Periodic
review. Browser policy management.

### Network-based threats

We do not address:

- Phishing.
- Man-in-the-middle on the network.
- Credential stuffing on remote services.

These threats exist regardless of local storage protection.

## Why audit at all?

If a sophisticated attacker (kernel-level, physical, or network) is
in your model, this tool is not enough. But the **vast majority** of
credential-theft incidents in 2025–2026 are commodity infostealers,
user-mode. Auditing what they would see is exactly what this tool
does, and what 99% of users actually need.

## Updating this model

Threats evolve. When you see news of a new technique:

1. Add it to `kb/vulnerabilities.json` under `bypass_techniques`.
2. Reference it from the relevant timeline entry.
3. If it changes our coverage (we can now audit something we
   couldn't), implement it in a module.
4. If it falls outside our scope (e.g., requires kernel access),
   document it here.
