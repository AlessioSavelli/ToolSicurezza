"""Decifrazione credenziali browser Chromium-based.

Modulo condiviso fra pwd_audit.py e infostealer_audit.py.
Implementa decifrazione v10 (Chrome 80-126) e wrapping per v20 (Chrome 127+).

Format v10:
  password_value = "v10" + nonce(12) + ciphertext + tag(16)
  Master key = DPAPI_unprotect(Local_State.os_crypt.encrypted_key[5:])

Format v20 (App-Bound Encryption):
  password_value = "v20" + nonce(12) + ciphertext + tag(16)
  Master key v20 = decrypt(Local_State.os_crypt.app_bound_encrypted_key)
                   via SYSTEM elevation + chrome.dll constant key (Strato 3)

Format pre-v10 (Chrome < 80):
  password_value = blob DPAPI direttamente
"""
from __future__ import annotations
import base64
import ctypes
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path


# ============================================================
# DPAPI
# ============================================================
class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes) -> bytes:
    """CryptUnprotectData per user-context corrente."""
    bin_in = DataBlob(len(blob), ctypes.cast(
        ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    bin_out = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_in), None, None, None, None, 0,
            ctypes.byref(bin_out)):
        err = ctypes.windll.kernel32.GetLastError()
        raise RuntimeError(f"DPAPI fail (err=0x{err & 0xFFFFFFFF:08X})")
    out = ctypes.string_at(bin_out.pbData, bin_out.cbData)
    ctypes.windll.kernel32.LocalFree(bin_out.pbData)
    return out


def get_v10_master_key(local_state_path: Path) -> bytes | None:
    """Estrae master key AES-256 v10 da Local State."""
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        enc_b64 = data.get("os_crypt", {}).get("encrypted_key")
        if not enc_b64:
            return None
        enc = base64.b64decode(enc_b64)
        if enc[:5] != b"DPAPI":
            return None
        return dpapi_unprotect(enc[5:])
    except Exception:
        return None


def aes_gcm_decrypt_blob(key: bytes, blob: bytes) -> str | None:
    """Decifra blob v10 con la master key data."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    if not blob or len(blob) < 31 or blob[:3] != b"v10":
        return None
    nonce = blob[3:15]
    ct_and_tag = blob[15:]
    try:
        plain = AESGCM(key).decrypt(nonce, ct_and_tag, None)
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None


def decrypt_chromium_password(blob: bytes, key_v10: bytes,
                              key_v20: bytes | None = None) -> tuple[str | None, str]:
    """Decifra una singola password Chromium.

    Ritorna (plaintext_or_None, format_tag) dove format_tag in:
        'v10', 'v20', 'v20_protected', 'pre_v10', 'unknown', 'empty'
    """
    if not blob or len(blob) < 1:
        return None, "empty"
    if len(blob) < 31:
        return None, "unknown"

    prefix = blob[:3]
    if prefix == b"v10":
        plain = aes_gcm_decrypt_blob(key_v10, blob)
        return plain, "v10"

    if prefix == b"v20":
        if key_v20 is None:
            return None, "v20_protected"
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = blob[3:15]
            ct_and_tag = blob[15:]
            plain = AESGCM(key_v20).decrypt(nonce, ct_and_tag, None)
            # v20 plaintext puo' contenere 32-byte header opaco
            if len(plain) > 32 and not plain[:1].isalpha():
                return plain[32:].decode("utf-8", errors="replace"), "v20"
            return plain.decode("utf-8", errors="replace"), "v20"
        except Exception:
            return None, "v20"

    # Pre-v10: DPAPI diretto
    try:
        return dpapi_unprotect(blob).decode("utf-8", errors="replace"), "pre_v10"
    except Exception:
        return None, "pre_v10"


# ============================================================
# BROWSER DISCOVERY
# ============================================================
def discover_chromium_browsers() -> list[dict]:
    """Trova installazioni Chromium-based con dati utente."""
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    roaming = Path(os.environ.get("APPDATA", ""))

    candidates = [
        ("Chrome", local / "Google/Chrome/User Data"),
        ("Edge", local / "Microsoft/Edge/User Data"),
        ("Brave", local / "BraveSoftware/Brave-Browser/User Data"),
        ("Vivaldi", local / "Vivaldi/User Data"),
        ("Opera", roaming / "Opera Software/Opera Stable"),
        ("Opera GX", roaming / "Opera Software/Opera GX Stable"),
        ("Chromium", local / "Chromium/User Data"),
        ("Arc", local / "Arc/User Data"),
    ]
    found = []
    for label, root in candidates:
        if not root.exists():
            continue
        local_state = root / "Local State"
        if not local_state.exists():
            continue
        profiles = []
        for sub in root.iterdir():
            if sub.is_dir() and (sub / "Login Data").exists():
                profiles.append(sub)
        if profiles:
            found.append({
                "browser": label,
                "root": root,
                "local_state": local_state,
                "profiles": profiles,
            })
    return found


def read_logins_table(profile_path: Path) -> list[tuple]:
    """Legge la tabella logins via copia temporanea (Chrome la tiene lockata).

    Ritorna list di tuple (origin_url, username_value, password_value_bytes,
    date_created, times_used, action_url, signon_realm, blacklisted_by_user).
    """
    login_db = profile_path / "Login Data"
    if not login_db.exists():
        return []
    tmp = Path(tempfile.gettempdir()) / f"audit_logins_{os.getpid()}_{profile_path.name}.db"
    try:
        shutil.copy(login_db, tmp)
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        cur.execute(
            "SELECT origin_url, username_value, password_value, "
            "date_created, times_used, action_url, signon_realm, "
            "blacklisted_by_user FROM logins"
        )
        rows = cur.fetchall()
        con.close()
        return [(r[0], r[1], bytes(r[2]) if r[2] else b"", r[3], r[4],
                 r[5], r[6], r[7]) for r in rows]
    except Exception:
        return []
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass


def extract_all_chromium_credentials(aggressive_key_lookup_fn=None) -> dict:
    """Estrae tutte le credenziali Chromium per ogni browser+profile.

    Args:
      aggressive_key_lookup_fn: optional callable(local_state_path) → key_v20 bytes
        Se fornita e ritorna chiave valida, tenta anche decifrazione v20.

    Ritorna:
      {
        "Chrome": [
          {
            "profile": "Default",
            "credentials": [
              {url, username, password, format, cipher_strength, blob_len, ...},
              ...
            ]
          },
          ...
        ],
        ...
      }
    """
    result = {}
    found = discover_chromium_browsers()

    for b in found:
        browser_name = b["browser"]
        master_v10 = get_v10_master_key(b["local_state"])
        master_v20 = None
        if aggressive_key_lookup_fn:
            try:
                master_v20 = aggressive_key_lookup_fn(b["local_state"])
            except Exception:
                master_v20 = None

        result[browser_name] = []
        for profile in b["profiles"]:
            creds = []
            rows = read_logins_table(profile)
            for row in rows:
                url, user, blob, dc, tu, action_url, realm, blacklisted = row
                if blacklisted:
                    continue
                if not blob:
                    continue
                if not master_v10:
                    creds.append({
                        "url": url, "username": user,
                        "password": None, "format": "no_key",
                        "blob_len": len(blob), "decryptable": False,
                    })
                    continue
                plain, fmt = decrypt_chromium_password(blob, master_v10, master_v20)

                # Skip blacklist empty (v10 31-byte tag, decrypts to "")
                if plain == "":
                    continue

                creds.append({
                    "url": url,
                    "username": user or "",
                    "password": plain,
                    "format": fmt,
                    "blob_len": len(blob),
                    "date_created": dc,
                    "times_used": tu or 0,
                    "decryptable": plain is not None,
                })
            result[browser_name].append({
                "profile": profile.name,
                "credentials": creds,
                "v10_decrypted": sum(1 for c in creds if c["format"] == "v10" and c["decryptable"]),
                "v20_total": sum(1 for c in creds if c["format"] in ("v20", "v20_protected")),
                "v20_decrypted": sum(1 for c in creds if c["format"] == "v20" and c["decryptable"]),
                "v20_protected": sum(1 for c in creds if c["format"] == "v20_protected"),
            })
    return result
