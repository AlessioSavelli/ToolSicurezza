"""Decifrazione credenziali legacy (formati storici pre-v10).

Coperture:
  - Internet Explorer / Edge Legacy "Vault" (Windows Credential Manager Web)
  - Chrome pre-80 (Login Data senza prefisso 'v10', solo DPAPI)
  - WinINET cookies stash (legacy)
  - cmdkey /list e parse Credential Manager generic

Tutti i metodi richiedono solo user-context DPAPI = lavoro come l'utente.
"""
from __future__ import annotations
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path


# Import dal sibling module
sys.path.insert(0, str(Path(__file__).parent))
try:
    from chromium_decrypt import dpapi_unprotect
except ImportError:
    dpapi_unprotect = None


# ============================================================
# WINDOWS CREDENTIAL MANAGER (via cmdkey + DPAPI)
# ============================================================
def list_credential_manager() -> list[dict]:
    """Lista credenziali in Windows Credential Manager.

    Usa `cmdkey /list` per il parsing iniziale (mostra solo target name).
    Ritorna lista di {target, type, persistence}.
    """
    try:
        r = subprocess.run(
            ["cmdkey", "/list"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return []
        creds = []
        current = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Target:") or line.startswith("Destinazione:"):
                if current:
                    creds.append(current)
                current = {"target": line.split(":", 1)[1].strip()}
            elif line.startswith("Type:") or line.startswith("Tipo:"):
                current["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("User:") or line.startswith("Utente:"):
                current["user"] = line.split(":", 1)[1].strip()
            elif line.startswith("Persistence:") or line.startswith("Persistenza:"):
                current["persistence"] = line.split(":", 1)[1].strip()
        if current:
            creds.append(current)
        return creds
    except Exception:
        return []


# ============================================================
# IE / EDGE LEGACY VAULT (Web Credentials)
# ============================================================
# Le Web Credentials di IE/Edge Legacy sono in C:\Users\<user>\AppData\Local\Microsoft\Vault\
# Decifratura usa CryptUnprotectData con entropy specifica.
def list_ie_vault_files() -> list[Path]:
    """Cerca file .vcrd e .vsch in tutti i Vault paths."""
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    vault_root = local / "Microsoft" / "Vault"
    if not vault_root.exists():
        return []
    return list(vault_root.rglob("*.vcrd")) + list(vault_root.rglob("*.vpol"))


def detect_ie_legacy_vault() -> dict:
    """Detection-only: dice se ci sono Vault credentials senza tentare decrypt."""
    files = list_ie_vault_files()
    if not files:
        return {"present": False, "count": 0}
    return {
        "present": True,
        "count": len(files),
        "paths": [str(f) for f in files[:10]],
        "note": "Decifratura richiede parsing del Vault binary format "
                "+ DPAPI per ciascuna entry. Riferimento: "
                "https://github.com/AlessandroZ/LaZagne (modulo iexplorer)",
    }


# ============================================================
# CHROME PRE-V80 (Login Data senza prefisso v10)
# ============================================================
def is_pre_v10_format(blob: bytes) -> bool:
    """Heuristic: blob inizia con DPAPI header (01 00 00 00 d0 8c 9d df)."""
    if not blob or len(blob) < 8:
        return False
    return (blob[:4] == b"\x01\x00\x00\x00"
            and blob[4:8] == b"\xd0\x8c\x9d\xdf")


def decrypt_pre_v10(blob: bytes) -> str | None:
    """Decifra direttamente DPAPI (Chrome < 80)."""
    if not dpapi_unprotect:
        return None
    try:
        return dpapi_unprotect(blob).decode("utf-8", errors="replace")
    except Exception:
        return None


# ============================================================
# OUTLOOK / OFFICE (registry + DPAPI)
# ============================================================
def detect_outlook_profiles() -> dict:
    """Detection profili Outlook (NON estrae credenziali)."""
    import winreg
    profiles = []
    for hive_name, hive in [("HKCU", winreg.HKEY_CURRENT_USER)]:
        for key_path in [
            r"Software\Microsoft\Office\16.0\Outlook\Profiles",
            r"Software\Microsoft\Office\15.0\Outlook\Profiles",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles",
        ]:
            try:
                with winreg.OpenKey(hive, key_path) as k:
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(k, i)
                            profiles.append({
                                "hive": hive_name,
                                "path": f"{key_path}\\{sub}",
                                "name": sub,
                            })
                            i += 1
                        except OSError:
                            break
            except (FileNotFoundError, OSError):
                continue
    return {"present": len(profiles) > 0, "count": len(profiles),
            "profiles": profiles[:10]}


# ============================================================
# WiFi PROFILES (netsh + DPAPI)
# ============================================================
def list_wifi_profiles() -> list[dict]:
    """Lista profili Wi-Fi salvati e (se possibile) password in chiaro.

    Usa `netsh wlan show profiles` + `netsh wlan show profile <name> key=clear`.
    Richiede admin per la chiave in chiaro.
    """
    try:
        r = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            return []
        names = []
        for line in r.stdout.splitlines():
            if "Profilo Utente Tutti" in line or "All User Profile" in line:
                names.append(line.split(":", 1)[1].strip())
        profiles = []
        for n in names:
            entry = {"name": n, "key_visible": False, "key": None,
                     "auth": None}
            try:
                r2 = subprocess.run(
                    ["netsh", "wlan", "show", "profile",
                     f"name={n}", "key=clear"],
                    capture_output=True, text=True, timeout=10,
                )
                if r2.returncode == 0:
                    for line in r2.stdout.splitlines():
                        line = line.strip()
                        if "Contenuto chiave" in line or "Key Content" in line:
                            entry["key"] = line.split(":", 1)[1].strip()
                            entry["key_visible"] = True
                        elif ("Autenticazione" in line or "Authentication" in line) \
                                and ":" in line:
                            v = line.split(":", 1)[1].strip()
                            if v and v not in ("Aperta",):
                                entry["auth"] = v
            except Exception:
                pass
            profiles.append(entry)
        return profiles
    except Exception:
        return []


# ============================================================
# ORCHESTRATORE
# ============================================================
def audit_legacy_credentials() -> dict:
    """Esegue tutti i check legacy. Ritorna structured dict."""
    return {
        "credential_manager": list_credential_manager(),
        "ie_legacy_vault": detect_ie_legacy_vault(),
        "outlook_profiles": detect_outlook_profiles(),
        "wifi_profiles": list_wifi_profiles(),
    }
