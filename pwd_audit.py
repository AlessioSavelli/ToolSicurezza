r"""
pwd_audit.py - Audit difensivo delle credenziali salvate nei browser

Scopo: quantificare il rischio reale di un'eventuale infezione da infostealer
analizzando le credenziali che TU hai salvato nel TUO browser sul TUO PC.

Cosa fa:
  1. Trova i profili di Chrome / Edge / Brave per l'utente corrente
  2. Decifra le password salvate usando DPAPI (chiave master) + AES-GCM
     (la stessa procedura che farebbe un infostealer come RedLine/Lumma)
  3. Calcola metriche di robustezza (lunghezza, entropia, classi caratteri,
     pattern comuni come date/sequenze/parole dizionario)
  4. Rileva PASSWORD RIUTILIZZATE su piu' siti (il rischio piu' alto:
     una credenziale rubata = N siti compromessi)
  5. Classifica ogni account per criticita' (banking, email, gaming, ecc.)
  6. Genera un report HTML interattivo + sommario CLI

Sicurezza:
  - Funziona solo nel contesto del TUO utente Windows (DPAPI). Non puo'
    leggere credenziali di altri utenti. Non puo' essere eseguito remoto.
  - Default: password mascherate (****). Devi passare --reveal per vederle.
  - I report locali sono salvati in .\reports\ (non vengono inviati altrove).
  - Nessuna connessione di rete in uscita.

Uso:
  py pwd_audit.py                          # audit completo, pwd mascherate
  py pwd_audit.py --reveal                 # mostra anche pwd in chiaro
  py pwd_audit.py --aggressive             # tenta di rompere anche v20-ABE
                                           # (richiede privilegi Administrator,
                                           #  spawna SYSTEM via Task Scheduler)
  py pwd_audit.py --browsers chrome,edge   # solo specifici browser
  py pwd_audit.py --no-html                # solo CLI, niente HTML
  py pwd_audit.py --out report.html        # nome file output custom

NB: Questo tool fa esattamente quello che farebbe un malware infostealer
sul tuo PC. Lo scopo e' QUANTIFICARE il danno potenziale per decidere
quante password cambiare in caso di infezione.

Autore: tool creato per audit personale post-incidente Trojan:Win32/Kepavll!rfn
"""
from __future__ import annotations
import argparse
import base64
import ctypes
import datetime
import getpass
import hashlib
import html
import json
import math
import os
import re
import secrets
import shutil
import sqlite3
import string
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

# i18n support (must come after Path import, before anything else uses strings)
try:
    from modules.i18n import get_strings, detect_system_language  # noqa: E402
except ImportError:
    # Fallback if run from a different working directory
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent))
    from modules.i18n import get_strings, detect_system_language  # noqa: E402


# ============================================================
# DIPENDENZE — auto-install se mancanti
# ============================================================
def ensure_dependencies():
    """Installa 'cryptography' se non presente."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except ImportError:
        print("[setup] Installo 'cryptography' (necessaria per AES-GCM)...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 "--disable-pip-version-check", "cryptography"]
            )
            print("[setup] OK.")
        except subprocess.CalledProcessError:
            print("[!] Installazione fallita. Esegui manualmente:")
            print("    py -m pip install cryptography")
            sys.exit(1)


# ============================================================
# DPAPI — decifra la master key di Chrome/Edge
# ============================================================
class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob: bytes) -> bytes:
    """Decifra un blob DPAPI usando l'identita' dell'utente Windows corrente.

    Richiama Win32 API CryptUnprotectData (crypt32.dll).
    """
    bin_in = DataBlob(len(blob), ctypes.cast(
        ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    bin_out = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_in), None, None, None, None, 0,
            ctypes.byref(bin_out)):
        err = ctypes.windll.kernel32.GetLastError()
        raise RuntimeError(f"CryptUnprotectData failed (LastError={err})")
    out = ctypes.string_at(bin_out.pbData, bin_out.cbData)
    ctypes.windll.kernel32.LocalFree(bin_out.pbData)
    return out


def get_master_key(local_state_path: Path) -> bytes | None:
    """Estrae e decifra la master key AES-256 da Local State."""
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        enc_key_b64 = data["os_crypt"]["encrypted_key"]
        enc_key = base64.b64decode(enc_key_b64)
        # I primi 5 byte sono il prefisso "DPAPI"
        if enc_key[:5] != b"DPAPI":
            return None
        return dpapi_unprotect(enc_key[5:])
    except Exception as e:
        print(f"[!] Errore lettura master key da {local_state_path}: {e}")
        return None


def find_v20_key_in_blob(candidate_blob: bytes,
                          sample_v20_password_blob: bytes) -> bytes | None:
    """Cerca la chiave AES v20 in un blob sliding window.

    Prende un blob (es. l'output di DPAPI multi-layer) e prova ogni
    finestra di 32 byte contigui come chiave AES per decifrare un
    sample v20 password. La finestra che decifra correttamente e' la chiave.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if (not sample_v20_password_blob or
            len(sample_v20_password_blob) < 31 or
            sample_v20_password_blob[:3] != b"v20"):
        return None

    nonce = sample_v20_password_blob[3:15]
    ct_and_tag = sample_v20_password_blob[15:]

    # Prova ogni finestra di 32 byte
    for i in range(len(candidate_blob) - 32 + 1):
        candidate = candidate_blob[i:i + 32]
        try:
            AESGCM(candidate).decrypt(nonce, ct_and_tag, None)
            print(f"    [+] CHIAVE v20 trovata a offset {i} del blob "
                  f"(blob_len={len(candidate_blob)})")
            return candidate
        except Exception:
            continue
    return None


def aes_gcm_decrypt(key_v10: bytes, key_v20: bytes | None,
                    blob: bytes) -> tuple[str | None, str]:
    """Decifra un blob Chrome.

    Formati supportati:
      - v10: Chrome 80-126 (decifrabile in user-mode con DPAPI user key)
      - v20: Chrome 127+ (App-Bound Encryption, richiede SYSTEM context
             per decifrare la app-bound key)
      - pre-v10: blob DPAPI diretto

    Ritorna (plaintext_or_None, format_tag) dove format_tag e' uno di:
      'v10', 'v20', 'v20_protected', 'pre_v10', 'unknown'
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob or len(blob) < 31:
        return None, "unknown"

    prefix = blob[:3]
    if prefix == b"v10":
        nonce = blob[3:15]
        ct_and_tag = blob[15:]
        try:
            plain = AESGCM(key_v10).decrypt(nonce, ct_and_tag, None)
            return plain.decode("utf-8", errors="replace"), "v10"
        except Exception:
            return None, "v10"

    if prefix == b"v20":
        # Chrome 127+ App-Bound Encryption
        if key_v20 is None:
            return None, "v20_protected"
        nonce = blob[3:15]
        ct_and_tag = blob[15:]
        try:
            plain = AESGCM(key_v20).decrypt(nonce, ct_and_tag, None)
            # In v20, il plaintext puo' contenere padding/header — Chrome
            # appende metadata. Per le password: i primi 32 byte sono un
            # header opaco, il resto e' il plaintext UTF-8.
            if len(plain) > 32 and plain[:1].isalpha() is False:
                # Tipico: 32 byte header + plaintext
                return plain[32:].decode("utf-8", errors="replace"), "v20"
            return plain.decode("utf-8", errors="replace"), "v20"
        except Exception:
            return None, "v20"

    # Pre-Chrome 80: blob DPAPI diretto
    try:
        return dpapi_unprotect(blob).decode("utf-8", errors="replace"), "pre_v10"
    except Exception:
        return None, "pre_v10"


def get_app_bound_key(local_state_path: Path) -> bytes | None:
    """Estrae app_bound_encrypted_key da Local State (Chrome 127+).

    Questa chiave e' protetta da DPAPI con doppia cifratura:
      1) DPAPI user-context (decifrabile da noi)
      2) DPAPI SYSTEM-context (decifrabile solo con privilegi SYSTEM)

    Se il primo strato si apre ma il secondo no, ritorna None.
    """
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        enc_b64 = data.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not enc_b64:
            return None
        enc = base64.b64decode(enc_b64)
        # Prefisso "APPB" (4 byte)
        if enc[:4] != b"APPB":
            return None
        # Primo strato DPAPI user-context
        try:
            inner = dpapi_unprotect(enc[4:])
        except Exception:
            return None
        # Secondo strato: DPAPI SYSTEM-context — proviamo, fallira'
        # se non siamo SYSTEM
        try:
            outer = dpapi_unprotect(inner)
            # outer e' un blob complesso: prima dei 32 byte di chiave c'e'
            # un header con flag + struct. La chiave AES e' negli ultimi
            # 32 byte (formato documentato da reverse engineering di Chrome).
            if len(outer) >= 32:
                return outer[-32:]
            return None
        except Exception:
            return None
    except Exception:
        return None


# ============================================================
# MODALITA' AGGRESSIVA — SYSTEM elevation via Task Scheduler
# ============================================================

# Helper script che gira come SYSTEM e decifra il secondo strato DPAPI
SYSTEM_HELPER_SCRIPT = r'''
"""Helper eseguito come SYSTEM via Task Scheduler.

Argomenti: <input_blob_path> <output_blob_path>
Legge l'input (intermediate DPAPI blob), lo decifra come SYSTEM, scrive il risultato.
"""
import ctypes
import sys
import traceback

class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(blob):
    bin_in = DataBlob(len(blob), ctypes.cast(
        ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
    bin_out = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(bin_in), None, None, None, None, 0,
            ctypes.byref(bin_out)):
        err = ctypes.windll.kernel32.GetLastError()
        raise RuntimeError("DPAPI SYSTEM fail err=" + str(err))
    out = ctypes.string_at(bin_out.pbData, bin_out.cbData)
    ctypes.windll.kernel32.LocalFree(bin_out.pbData)
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: helper <in> <out>")
    in_path = sys.argv[1]
    out_path = sys.argv[2]
    try:
        with open(in_path, "rb") as f:
            blob = f.read()
        result = dpapi_unprotect(blob)
        with open(out_path, "wb") as f:
            f.write(result)
    except Exception as e:
        with open(out_path + ".err", "w", encoding="utf-8") as f:
            f.write(repr(e) + "\n" + traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
'''


def is_admin() -> bool:
    """Ritorna True se il processo corrente e' elevato (admin)."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    """Rilancia lo script con UAC prompt. Termina il processo corrente."""
    print("[*] Richiesta elevazione UAC...")
    args = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable,
        f'"{os.path.abspath(__file__)}" {args}', None, 1
    )
    if ret <= 32:
        print(f"[!] ShellExecute fallito (codice {ret}). "
              f"Esegui manualmente PowerShell come Administrator e "
              f"rilancia: py {os.path.abspath(__file__)} {args}")
        sys.exit(1)
    sys.exit(0)


def dpapi_unprotect_as_system(blob: bytes) -> bytes | None:
    """Decifra un blob DPAPI nel contesto SYSTEM.

    Tecnica: crea una scheduled task transitoria che gira come SYSTEM,
    le passa il blob via file temporaneo, recupera il risultato.

    Richiede privilegi Administrator (per creare task SYSTEM).
    """
    import time
    import secrets

    if not is_admin():
        return None

    # Usiamo path CORTI in C:\Windows\Temp (writable da SYSTEM, breve)
    # per evitare il limite di 261 char su schtasks /TR.
    rnd = secrets.token_hex(4)  # 8 char totali
    # Preferisci C:\Windows\Temp (corto), fallback a tempfile.gettempdir()
    win_temp = Path(r"C:\Windows\Temp")
    if win_temp.exists() and os.access(str(win_temp), os.W_OK):
        tmp_dir = win_temp
    else:
        tmp_dir = Path(tempfile.gettempdir())

    in_path = tmp_dir / f"pa{rnd}i.bin"
    out_path = tmp_dir / f"pa{rnd}o.bin"
    err_path = Path(str(out_path) + ".err")
    helper_path = tmp_dir / f"pa{rnd}h.py"
    wrapper_path = tmp_dir / f"pa{rnd}w.bat"
    task_name = f"PwdAuditV20_{rnd}"

    try:
        # 1. Scrivi blob input, helper script, e wrapper batch
        in_path.write_bytes(blob)
        helper_path.write_text(SYSTEM_HELPER_SCRIPT, encoding="utf-8")
        # Il wrapper batch consente di evitare il limite 261 char di /TR.
        # Il .bat puo' contenere comandi lunghi quanto vuole.
        py_exe = sys.executable
        wrapper_content = (
            "@echo off\r\n"
            f'"{py_exe}" "{helper_path}" "{in_path}" "{out_path}"\r\n'
        )
        wrapper_path.write_text(wrapper_content, encoding="utf-8")

        # 2. Crea scheduled task SYSTEM.
        future = (datetime.datetime.now()
                  + datetime.timedelta(minutes=2)).strftime("%H:%M")
        tr = f'"{wrapper_path}"'
        create = subprocess.run(
            ["schtasks", "/Create", "/TN", task_name, "/SC", "ONCE",
             "/ST", future, "/RU", "SYSTEM", "/RL", "HIGHEST",
             "/F", "/TR", tr],
            capture_output=True, text=True, timeout=15,
        )
        if create.returncode != 0:
            print(f"[!] schtasks /Create fallito (rc={create.returncode}):")
            print(f"    stdout: {create.stdout.strip()}")
            print(f"    stderr: {create.stderr.strip()}")
            return None
        print(f"    [+] Task '{task_name}' creata come SYSTEM "
              f"(wrapper: {wrapper_path.name})")

        # 3. Esegui la task
        run = subprocess.run(
            ["schtasks", "/Run", "/TN", task_name],
            capture_output=True, text=True, timeout=15,
        )
        if run.returncode != 0:
            print(f"[!] schtasks /Run fallito: {run.stderr.strip()}")
            return None
        print(f"    [+] Task avviata, attendo output...")

        # 4. Attendi il risultato (max ~10s)
        for _ in range(40):
            if out_path.exists() or err_path.exists():
                break
            time.sleep(0.25)

        if err_path.exists():
            err_msg = err_path.read_text(encoding="utf-8", errors="replace")
            print(f"[!] Helper SYSTEM fallito:\n{err_msg[:500]}")
            return None

        if not out_path.exists():
            print(f"[!] Timeout: helper SYSTEM non ha prodotto output.")
            return None

        result = out_path.read_bytes()
        return result

    finally:
        # Cleanup: elimina task e file temporanei
        subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            capture_output=True, text=True, timeout=10,
        )
        for p in (in_path, out_path, err_path, helper_path, wrapper_path):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass


def get_app_bound_key_aggressive(local_state_path: Path,
                                 sample_v20_blob: bytes | None = None) -> bytes | None:
    """Versione aggressiva: usa SYSTEM elevation per decifrare la v20 key.

    Formato app_bound_encrypted_key:
      [APPB][4-byte version/flags][DPAPI-SYSTEM-protected blob]

    Il blob DPAPI e' cifrato nel contesto SYSTEM da chrome_elevation_service.
    Serve elevation a SYSTEM (scheduled task) per decifrare.

    Dopo la decifrazione, il blob risultante puo' essere:
      - Direttamente la chiave AES (32 byte)
      - Un blob con header + chiave (32 byte a un offset specifico)
      - Doppia cifratura: DPAPI-SYSTEM(DPAPI-USER(key))

    Proviamo varie strategie.

    Richiede admin. Ritorna i 32 byte della chiave AES v20 o None.
    """
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        enc_b64 = data.get("os_crypt", {}).get("app_bound_encrypted_key")
        if not enc_b64:
            return None
        enc = base64.b64decode(enc_b64)
        if enc[:4] != b"APPB":
            return None

        # Struttura: "APPB" (4B) + version (4B) + DPAPI-SYSTEM blob
        # Il vero blob DPAPI inizia all'offset 4 (versione + GUID DPAPI)
        dpapi_blob = enc[4:]
        print(f"    [+] Blob DPAPI da decifrare: {len(dpapi_blob)} byte")
        print(f"    [+] Inizio (hex): {dpapi_blob[:20].hex()}")

        # Strategia 1: SYSTEM DPAPI diretto su enc[4:]
        print(f"    [+] Strategia 1: SYSTEM-DPAPI su offset 4...")
        outer = dpapi_unprotect_as_system(dpapi_blob)
        if outer is None:
            print(f"    [-] Strategia 1 fallita")
            return None
        print(f"    [+] SYSTEM-DPAPI OK: {len(outer)} byte risultato")
        print(f"    [+] Risultato inizio hex: {outer[:32].hex()}")
        print(f"    [+] Risultato fine hex:   {outer[-32:].hex()}")

        # Il risultato puo' contenere ulteriori layer.
        if len(outer) == 32:
            print(f"    [+] Risultato e' 32 byte = chiave AES diretta!")
            return outer

        # Se il risultato e' piu' grande, potrebbe esserci un altro layer DPAPI
        inner = None
        if outer[:4] == b"\x01\x00\x00\x00" and outer[4:8] == b"\xd0\x8c\x9d\xdf":
            print(f"    [+] Risultato sembra un altro blob DPAPI, "
                  f"tento unprotect user...")
            try:
                inner = dpapi_unprotect(outer)
                print(f"    [+] User-DPAPI OK: {len(inner)} byte")
                if len(inner) == 32:
                    return inner
            except Exception as e:
                print(f"    [-] User-DPAPI sul layer interno: {e}")
                inner = None

        # Se abbiamo un sample blob v20, brute-force su tutte le 32-byte windows
        if sample_v20_blob:
            # Prima cerca nell'inner se disponibile
            search_targets = []
            if inner:
                search_targets.append((inner, "inner-DPAPI"))
            search_targets.append((outer, "outer-SYSTEM-DPAPI"))
            for blob_to_search, label in search_targets:
                print(f"    [+] Brute-force chiave nel blob {label} "
                      f"({len(blob_to_search)} byte, "
                      f"{len(blob_to_search)-31} possibili offset)...")
                key = find_v20_key_in_blob(blob_to_search, sample_v20_blob)
                if key:
                    return key
            print(f"    [-] Brute-force fallito: nessuna 32-byte window "
                  f"contigua decifra il sample v20.")
            print(f"    [-] Significato: Chrome 131+ usa un ulteriore strato "
                  f"di AES con chiave hardcoded in chrome.dll (Application "
                  f"Bound Encryption con 'masterkey wrapping'). "
                  f"Per il bypass finale serve:")
            print(f"        - Estrazione della constant key da chrome.dll "
                  f"via signature scanning (richiede RE del binario)")
            print(f"        - OPPURE chiamata IElevator::DecryptData via COM "
                  f"(richiede path validation bypass)")
            print(f"    [i] La protezione v20 ha RESISTITO a SYSTEM "
                  f"elevation + DPAPI user. Bypass dichiarato fallito.")
            return None

        # Nessun sample disponibile: non possiamo validare la chiave
        # Restituiamo None invece di indovinare
        print(f"    [-] Nessun sample v20 blob disponibile per validazione, "
              f"non possiamo distinguere la chiave dal resto del blob.")
        return None
    except Exception as e:
        print(f"[!] get_app_bound_key_aggressive: {e}")
        import traceback
        traceback.print_exc()
        return None


# ============================================================
# BROWSER DISCOVERY — trova i profili
# ============================================================
def discover_browsers() -> list[dict]:
    """Ritorna lista di profili browser disponibili per l'utente corrente."""
    user = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    local = Path(os.environ.get("LOCALAPPDATA", Path(user) / "AppData/Local"))
    roaming = Path(os.environ.get("APPDATA", Path(user) / "AppData/Roaming"))

    candidates = [
        # (label, user_data_root)
        ("Chrome", local / "Google/Chrome/User Data"),
        ("Edge", local / "Microsoft/Edge/User Data"),
        ("Brave", local / "BraveSoftware/Brave-Browser/User Data"),
        ("Vivaldi", local / "Vivaldi/User Data"),
        ("Opera", roaming / "Opera Software/Opera Stable"),
        ("Chromium", local / "Chromium/User Data"),
    ]

    found = []
    for label, root in candidates:
        if not root.exists():
            continue
        local_state = root / "Local State"
        if not local_state.exists():
            continue
        # Trova tutti i profili (Default, Profile 1, Profile 2, ...)
        profiles = []
        for sub in root.iterdir():
            if not sub.is_dir():
                continue
            if (sub / "Login Data").exists():
                profiles.append(sub)
        if profiles:
            found.append({
                "browser": label,
                "root": root,
                "local_state": local_state,
                "profiles": profiles,
            })
    return found


# ============================================================
# ANALISI ROBUSTEZZA PASSWORD
# ============================================================
COMMON_WEAK = {
    "password", "123456", "12345678", "qwerty", "abc123", "111111",
    "letmein", "admin", "welcome", "monkey", "1234", "iloveyou",
    "password1", "qwertyuiop", "passw0rd", "p@ssw0rd", "p@ssword",
    "azerty", "1q2w3e4r", "qwerty123", "asdf", "asdfgh", "12345",
    "123123", "000000", "qazwsx", "trustno1", "dragon", "master",
    "football", "baseball", "ninja", "michael", "shadow", "superman",
    "batman", "qweasd", "qwertz", "starwars", "hello", "freedom",
    "whatever", "summer", "winter", "spring", "autumn", "ciao",
    "password123", "admin123", "root", "toor", "guest",
}

# Italiani comuni / locali
LOCAL_WEAK = {
    "italia", "roma", "milano", "napoli", "ciaociao", "amore", "tiamo",
    "calcio", "ferrari", "juventus", "milan", "inter", "lazio",
    "alessio", "alex", "alessandro", "marco", "luca", "andrea",
    "savelli", "puri", "natale", "natalia",
}


def entropy(s: str) -> float:
    """Entropia di Shannon in bit/char (NOT bit totali)."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def char_classes(s: str) -> dict:
    return {
        "lower": any(c in string.ascii_lowercase for c in s),
        "upper": any(c in string.ascii_uppercase for c in s),
        "digit": any(c in string.digits for c in s),
        "special": any(not c.isalnum() for c in s),
    }


def is_sequential(s: str) -> bool:
    """True se contiene una sequenza di 4+ char consecutivi (1234, abcd, qwer)."""
    s = s.lower()
    seqs = ["abcdefghijklmnopqrstuvwxyz", "0123456789",
            "qwertyuiopasdfghjklzxcvbnm"]
    for seq in seqs:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in s or seq[i:i+4][::-1] in s:
                return True
    return False


def has_year(s: str) -> bool:
    return bool(re.search(r"(19[5-9]\d|20[0-3]\d)", s))


def analyze_password(pwd: str) -> dict:
    """Ritorna un dizionario con metriche di robustezza."""
    if not pwd:
        return {"strength": "EMPTY", "score": 0, "issues": ["password vuota"]}

    L = len(pwd)
    cc = char_classes(pwd)
    ent_per_char = entropy(pwd)
    total_ent = ent_per_char * L  # entropia totale (rough)

    issues = []
    score = 0

    # Lunghezza
    if L < 8:
        issues.append(f"troppo corta ({L} char)")
    elif L < 12:
        score += 1
        issues.append(f"corta ({L} char)")
    elif L < 16:
        score += 2
    else:
        score += 3

    # Classi
    n_classes = sum(cc.values())
    if n_classes == 1:
        issues.append("solo 1 classe di caratteri")
    elif n_classes == 2:
        score += 1
    elif n_classes >= 3:
        score += 2
    if n_classes == 4:
        score += 1

    # Dizionario debole
    low = pwd.lower()
    if low in COMMON_WEAK or low in LOCAL_WEAK:
        issues.append("password DIZIONARIO (top-weak)")
        score = 0
    else:
        # Check substring match
        for w in list(COMMON_WEAK)[:30] + list(LOCAL_WEAK):
            if len(w) >= 5 and w in low:
                issues.append(f"contiene parola debole '{w}'")
                score = max(0, score - 1)
                break

    # Pattern
    if is_sequential(pwd):
        issues.append("contiene sequenza (1234/abcd/qwerty)")
        score = max(0, score - 1)
    if has_year(pwd):
        issues.append("contiene anno (1950-2039)")
    if re.fullmatch(r"\d+", pwd):
        issues.append("solo numerica")
        score = max(0, score - 1)
    if re.fullmatch(r"[a-zA-Z]+", pwd):
        issues.append("solo alfabetica")

    # Entropia
    if total_ent < 30:
        issues.append(f"entropia bassa ({total_ent:.0f} bit)")
        score = max(0, score - 1)
    elif total_ent >= 60:
        score += 1

    # Classifica finale
    if score <= 1:
        strength = "VERY_WEAK"
    elif score <= 3:
        strength = "WEAK"
    elif score <= 5:
        strength = "MEDIUM"
    elif score <= 7:
        strength = "STRONG"
    else:
        strength = "VERY_STRONG"

    return {
        "length": L,
        "classes": n_classes,
        "entropy_total": round(total_ent, 1),
        "entropy_per_char": round(ent_per_char, 2),
        "strength": strength,
        "score": score,
        "issues": issues,
    }


# ============================================================
# CLASSIFICAZIONE SITO PER CRITICITA'
# ============================================================
CATEGORIES = [
    # (category, severity, keywords)
    ("Banking",    "CRITICAL", ["bnl", "intesasanpaolo", "unicredit", "santander", "findomestic", "fineco", "ing.it", "n26", "revolut", "paypal", "satispay", "postepay", "bancoposta", "sia.eu"]),
    ("Email",      "CRITICAL", ["gmail", "googlemail", "accounts.google", "outlook", "live.com", "microsoftonline", "hotmail", "libero.it", "tim.it", "tiscali", "yahoo", "proton", "fastmail", "icloud", "appleid", "idmsa.apple"]),
    ("Cloud/Dev",  "CRITICAL", ["aws.amazon", "console.aws", "azure", "github", "gitlab", "bitbucket", "digitalocean", "linode", "heroku", "vercel", "netlify", "cloudflare", "openai", "auth0", "hivemq", "hackthebox"]),
    ("Lavoro",     "CRITICAL", ["e-distribuzione", "arca-enel", "enel.com", "sts.enel", "sharepoint", "salesforce", "workday", "slack.com", "teams.microsoft"]),
    ("Crypto",     "CRITICAL", ["binance", "coinbase", "kraken", "metamask", "blockchain", "trezor", "ledger", "exchange"]),
    ("Gaming",     "HIGH",     ["steampowered", "steamcommunity", "riotgames", "epicgames", "battle.net", "blizzard", "signin.ea", "ea.com", "ubisoft", "playstation", "sonyentertainment", "xbox", "samsung", "g2a", "kinguin", "gog.com", "nexusmods", "square-enix", "gearbox", "leagueoflegends"]),
    ("Dev Tools",  "HIGH",     ["digikey", "mouser", "autodesk", "broadcom", "jlcpcb", "snapeda", "grabcad", "fritzing", "nxp", "findchips", "easyeda", "cadence", "wolfram", "element14"]),
    ("Social",     "HIGH",     ["facebook", "instagram", "twitter", "x.com", "linkedin", "tiktok", "discord", "telegram", "whatsapp", "reddit", "snapchat"]),
    ("Shopping",   "MEDIUM",   ["amazon", "ebay", "aliexpress", "wish.com", "shop.ticketmaster", "ticketmaster", "vinted", "subito", "ikea", "zalando", "asos"]),
    ("Streaming",  "MEDIUM",   ["netflix", "spotify", "youtube", "disneyplus", "primevideo", "twitch", "deezer", "tidal", "zoom"]),
    ("Hosting",    "MEDIUM",   ["ionos", "one.com", "aruba", "register.it", "godaddy", "ovh", "siteground", "bluehost"]),
    ("Telco",     "MEDIUM",    ["windtre", "tim.it", "vodafone", "iliad", "tiscali"]),
    ("Router",    "LOW",       ["192.168.", "fritz.box", "tplinkmodem", "10.0.0.", "localhost"]),
    ("Forum/Edu", "LOW",       ["forum.", "ucp.php", "ecampus", "cineca", "elearning", "unicz", "unical", "unina"]),
]


def classify(url: str) -> tuple[str, str]:
    """Ritorna (categoria, severity) basandosi sull'URL."""
    u = url.lower()
    for cat, sev, kws in CATEGORIES:
        for kw in kws:
            if kw in u:
                return cat, sev
    return "Altro", "LOW"


# ============================================================
# RIUTILIZZO PASSWORD (la vera bomba)
# ============================================================
def find_reuse(records: list[dict]) -> dict:
    """Mappa hash_pwd -> [record1, record2, ...] solo se >1 sito.

    Usiamo SHA-256 per non tenere le password in chiaro nella mappa di reuse.
    Ignora i record protetti v20 (non abbiamo la password in chiaro).
    """
    by_hash = defaultdict(list)
    for r in records:
        if r.get("protected"):
            continue
        if not r.get("password"):
            continue
        h = hashlib.sha256(r["password"].encode("utf-8")).hexdigest()
        by_hash[h].append(r)
    return {h: lst for h, lst in by_hash.items() if len(lst) > 1}


# ============================================================
# REPORT HTML
# ============================================================
def mask(pwd: str) -> str:
    if not pwd:
        return ""
    if len(pwd) <= 3:
        return "*" * len(pwd)
    return pwd[0] + "*" * (len(pwd) - 2) + pwd[-1]


def severity_color(sev: str) -> str:
    return {"CRITICAL": "#c00", "HIGH": "#e66100",
            "MEDIUM": "#d4a017", "LOW": "#666"}.get(sev, "#666")


def strength_color(s: str) -> str:
    return {"VERY_WEAK": "#c00", "WEAK": "#e66100",
            "MEDIUM": "#d4a017", "STRONG": "#3a8",
            "VERY_STRONG": "#0a6", "EMPTY": "#888",
            "PROTECTED_v20": "#069"}.get(s, "#888")


def render_html(records: list[dict], reuse_map: dict, out_path: Path,
                reveal: bool, aggressive: bool = False, lang: str = "en"):
    """Genera report HTML (multilingue)."""
    T = get_strings(lang)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(records)
    by_sev = defaultdict(int)
    by_strength = defaultdict(int)
    n_protected = 0
    n_decrypted = 0
    for r in records:
        by_sev[r["severity"]] += 1
        by_strength[r["strength"]] += 1
        if r.get("protected"):
            n_protected += 1
        else:
            n_decrypted += 1
    n_reuse_groups = len(reuse_map)
    n_reused_accounts = sum(len(v) for v in reuse_map.values())

    # Sort: criticita' DESC, poi debolezza DESC
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    str_order = {"VERY_WEAK": 0, "WEAK": 1, "EMPTY": 2,
                 "MEDIUM": 3, "STRONG": 4, "VERY_STRONG": 5}
    records_sorted = sorted(records, key=lambda r: (
        sev_order.get(r["severity"], 99),
        str_order.get(r["strength"], 99),
        r["url"]
    ))

    parts = []
    _aggressive_note = (
        f'<br><br>{T["pwd_aggressive_note"]}' if aggressive else ''
    )
    parts.append(f"""<!doctype html>
<html lang="{T['html_lang']}"><head><meta charset="utf-8">
<title>{T['pwd_report_title']} — {now}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1300px;margin:1.5em auto;padding:0 1em;color:#222;background:#fafafa}}
h1{{border-bottom:3px solid #c00;padding-bottom:.3em;margin-top:0}}
h2{{margin-top:2em;padding:.4em .6em;color:#fff;border-radius:6px;background:#333}}
.stats{{display:flex;flex-wrap:wrap;gap:.6em;margin:1em 0}}
.stat{{padding:.6em .9em;border-radius:8px;background:#fff;border:1px solid #ddd;box-shadow:0 1px 2px rgba(0,0,0,.05)}}
.stat b{{font-size:1.6em;display:block;line-height:1}}
.stat small{{color:#666;font-size:.85em}}
table{{width:100%;border-collapse:collapse;margin:1em 0;background:#fff;font-size:.9em}}
th{{background:#eee;padding:.5em;text-align:left;border-bottom:2px solid #ccc;position:sticky;top:0}}
td{{padding:.4em .5em;border-bottom:1px solid #eee;vertical-align:top}}
tr:hover{{background:#f7f9fb}}
.url{{font-family:Consolas,monospace;font-size:.85em;color:#0066cc;max-width:340px;overflow:hidden;text-overflow:ellipsis}}
.user{{font-family:Consolas,monospace;font-size:.85em;max-width:200px;overflow:hidden;text-overflow:ellipsis}}
.pwd{{font-family:Consolas,monospace;font-size:.85em;background:#f4f4f4;padding:.15em .4em;border-radius:3px}}
.tag{{display:inline-block;padding:.15em .5em;border-radius:3px;color:#fff;font-size:.78em;font-weight:600}}
.issue{{font-size:.78em;color:#a00;display:block}}
.box{{padding:.8em 1em;border-radius:6px;margin:.6em 0}}
.box.warn{{background:#fff3d6;border-left:4px solid #d4a017}}
.box.bad{{background:#fde6e6;border-left:4px solid #c00}}
.box.ok{{background:#e6f7e6;border-left:4px solid #2a8}}
.box.info{{background:#eef3fa;border-left:4px solid #36c}}
.reuse-group{{background:#fff8e1;border-left:4px solid #d4a017;padding:.6em 1em;margin:.5em 0;border-radius:4px}}
.reuse-group ul{{margin:.3em 0;padding-left:1.4em}}
.copy{{cursor:pointer;color:#06c;font-size:.8em;margin-left:.4em}}
details{{margin:.5em 0}}
summary{{cursor:pointer;font-weight:600;padding:.3em 0}}
</style>
</head><body>
<h1>{T['pwd_h1']}</h1>
<div style="color:#666;margin-bottom:1em">{T['generated_at']}: {now} - {T['user_label']}: {html.escape(getpass.getuser())} - {T['machine_label']}: {html.escape(os.environ.get('COMPUTERNAME', '?'))}</div>

<div class="box bad">
<strong>{T['pwd_what_box_title']}</strong> {T['pwd_what_box_text']}{_aggressive_note}
</div>

<div class="stats">
<div class="stat"><b>{total}</b><small>{T['stat_total_creds']}</small></div>
<div class="stat" style="border-left:4px solid #c00"><b>{n_decrypted}</b><small>{T['stat_decrypted_vm']}</small></div>
<div class="stat" style="border-left:4px solid #069"><b>{n_protected}</b><small>{T['stat_protected_v20_abe']}</small></div>
<div class="stat" style="border-left:4px solid #c00"><b>{by_sev['CRITICAL']}</b><small>CRITICAL</small></div>
<div class="stat" style="border-left:4px solid #e66100"><b>{by_sev['HIGH']}</b><small>HIGH</small></div>
<div class="stat" style="border-left:4px solid #d4a017"><b>{by_sev['MEDIUM']}</b><small>MEDIUM</small></div>
<div class="stat" style="border-left:4px solid #c00"><b>{by_strength.get('VERY_WEAK',0) + by_strength.get('WEAK',0)}</b><small>{T['stat_weak_pwd']}</small></div>
<div class="stat" style="border-left:4px solid #d4a017"><b>{n_reused_accounts}</b><small>{T['stat_reused_pwd']}</small></div>
</div>

<div class="box info">
<strong>{T['abe_info_title']}</strong> {T['abe_info_text'].format(n=n_protected)}
</div>
""")

    # Sezione REUSE
    if reuse_map:
        parts.append(f'<h2 style="background:#d4a017">{T["reuse_section_title"]}</h2>')
        # Sort by group size desc
        for h, group in sorted(reuse_map.items(), key=lambda x: -len(x[1])):
            sample = group[0]["password"]
            pwd_show = sample if reveal else mask(sample)
            parts.append(f'<div class="reuse-group">')
            parts.append(f'<strong>{T["reuse_same_pwd"]}</strong> ')
            parts.append(f'<span class="pwd">{html.escape(pwd_show)}</span> ')
            parts.append(f'{T["reuse_used_on"]} <strong>{len(group)} {T["reuse_sites_suffix"]}</strong>:')
            parts.append('<ul>')
            for r in group:
                parts.append(f'<li><span class="tag" style="background:{severity_color(r["severity"])}">{r["severity"]}</span> '
                             f'<span class="url">{html.escape(r["url"][:90])}</span> '
                             f'(<span class="user">{html.escape(r["username"] or "-")}</span>)</li>')
            parts.append('</ul></div>')

    # Tabella completa
    parts.append(f'<h2>{T["all_creds_title"]}</h2>')
    parts.append(f'<table><thead><tr>'
                 f'<th>{T["col_browser"]}</th>'
                 f'<th>{T["col_sev"]}</th>'
                 f'<th>{T["col_category"]}</th>'
                 f'<th>{T["col_url"]}</th>'
                 f'<th>{T["col_username"]}</th>'
                 f'<th>{T["col_password"]}</th>'
                 f'<th>{T["col_len"]}</th>'
                 f'<th>{T["col_strength"]}</th>'
                 f'<th>{T["col_issues"]}</th>'
                 f'</tr></thead><tbody>')
    for r in records_sorted:
        if r.get("protected"):
            pwd_show = T["protected_v20_abe_tag"]
        else:
            pwd_show = (r["password"] or "") if reveal else mask(r["password"] or "")
        issues_html = ""
        if r["analysis"]["issues"]:
            issues_html = "<br>".join(
                f'<span class="issue">- {html.escape(i)}</span>'
                for i in r["analysis"]["issues"])
        parts.append('<tr>')
        parts.append(f'<td>{html.escape(r["browser"])}</td>')
        parts.append(f'<td><span class="tag" style="background:{severity_color(r["severity"])}">{r["severity"]}</span></td>')
        parts.append(f'<td>{html.escape(r["category"])}</td>')
        parts.append(f'<td class="url" title="{html.escape(r["url"])}">{html.escape(r["url"][:90])}</td>')
        parts.append(f'<td class="user">{html.escape(r["username"] or "-")}</td>')
        parts.append(f'<td class="pwd">{html.escape(pwd_show)}</td>')
        parts.append(f'<td>{r["analysis"].get("length", "-")}</td>')
        parts.append(f'<td><span class="tag" style="background:{strength_color(r["strength"])}">{r["strength"]}</span></td>')
        parts.append(f'<td>{issues_html}</td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')

    # Note finali
    parts.append(f"""
<details><summary>{T['strength_guide_title']}</summary>
<ul>
<li><b>VERY_WEAK</b>: {T['strength_very_weak_desc']}</li>
<li><b>WEAK</b>: {T['strength_weak_desc']}</li>
<li><b>MEDIUM</b>: {T['strength_medium_desc']}</li>
<li><b>STRONG</b>: {T['strength_strong_desc']}</li>
<li><b>VERY_STRONG</b>: {T['strength_very_strong_desc']}</li>
</ul>
</details>

<details><summary>{T['tech_notes_title']}</summary>
<ul>
<li>{T['tech_note_1']}</li>
<li>{T['tech_note_2']}</li>
<li>{T['tech_note_3']}</li>
<li>{T['tech_note_4']}</li>
<li>{T['tech_note_5']}</li>
</ul>
</details>

<div class="box info">
<strong>{T['suggestions_title']}</strong>
<ol>
<li>{T['suggestion_1']}</li>
<li>{T['suggestion_2']}</li>
<li>{T['suggestion_3']}</li>
<li>{T['suggestion_4']}</li>
<li>{T['suggestion_5']}</li>
</ol>
</div>
</body></html>""")

    out_path.write_text("".join(parts), encoding="utf-8")


# ============================================================
# MAIN
# ============================================================
def _extract_sample_v20_blob(profiles: list[Path]) -> bytes | None:
    """Estrae un blob password v20 di esempio da uno dei profili.
    Serve come 'noto cifrato' per il brute-force della key offset.
    """
    for profile in profiles:
        login_db = profile / "Login Data"
        if not login_db.exists():
            continue
        tmp = Path(tempfile.gettempdir()) / f"sample_v20_{secrets.token_hex(4)}.db"
        try:
            shutil.copy(login_db, tmp)
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            # Confronto BLOB→testo non affidabile in SQLite, filtro in Python
            cur.execute("SELECT password_value FROM logins "
                        "WHERE LENGTH(password_value) > 31")
            rows = cur.fetchall()
            con.close()
            for (blob,) in rows:
                if blob and len(blob) > 31:
                    b = bytes(blob)
                    if b[:3] == b"v20":
                        return b
        except Exception:
            pass
        finally:
            try:
                tmp.unlink()
            except Exception:
                pass
    return None


def collect_credentials(browsers_filter: list[str] | None,
                        aggressive: bool = False) -> list[dict]:
    """Trova, decifra, classifica tutte le credenziali.

    Se aggressive=True, tenta di rompere anche le chiavi v20 via SYSTEM
    elevation (richiede admin).
    """
    found = discover_browsers()
    if browsers_filter:
        fl = [b.lower() for b in browsers_filter]
        found = [b for b in found if b["browser"].lower() in fl]
    if not found:
        print("[!] Nessun browser supportato trovato.")
        return []

    records = []
    stats_v20_protected = 0
    for b in found:
        print(f"\n[*] Browser: {b['browser']}")
        master_v10 = get_master_key(b["local_state"])
        if not master_v10:
            print(f"    [!] Impossibile estrarre master key v10, salto.")
            continue
        print(f"    Master key v10: OK (len={len(master_v10)} byte)")

        # v20 ABE key
        master_v20 = None
        local_state_text = b["local_state"].read_text(encoding="utf-8",
                                                     errors="ignore")
        has_v20 = "app_bound_encrypted_key" in local_state_text

        if has_v20:
            if aggressive:
                print(f"    [AGGRESSIVE] Tentativo decifrazione v20-ABE "
                      f"via SYSTEM elevation...")
                # Estrai un sample v20 blob per brute-force della key offset
                sample_v20 = _extract_sample_v20_blob(b["profiles"])
                if sample_v20:
                    print(f"    [+] Sample v20 blob estratto "
                          f"({len(sample_v20)} byte) per brute-force key offset")
                master_v20 = get_app_bound_key_aggressive(b["local_state"],
                                                          sample_v20)
                if master_v20:
                    print(f"    Master key v20 (ABE): OK "
                          f"(len={len(master_v20)} byte) — "
                          f"PROTEZIONE ABE BYPASSATA ✓")
                else:
                    print(f"    Master key v20 (ABE): bypass FALLITO. "
                          f"Le password v20 resteranno protette.")
            else:
                # Modalita' standard: prova solo strato user, poi rinuncia
                master_v20 = get_app_bound_key(b["local_state"])
                if master_v20:
                    print(f"    Master key v20 (ABE): OK (len={len(master_v20)} byte) "
                          f"-- inusuale, sei admin/SYSTEM?")
                else:
                    print(f"    Master key v20 (ABE): PROTETTA "
                          f"(serve SYSTEM context, OK per uno user-mode infostealer)")
                    print(f"    Usa --aggressive per tentare il bypass.")

        for profile in b["profiles"]:
            login_db = profile / "Login Data"
            tmp = Path(tempfile.gettempdir()) / f"audit_{b['browser']}_{profile.name}.db"
            try:
                shutil.copy(login_db, tmp)
            except Exception as e:
                print(f"    [!] Impossibile copiare {login_db}: {e}")
                continue
            try:
                con = sqlite3.connect(tmp)
                cur = con.cursor()
                cur.execute(
                    "SELECT origin_url, username_value, password_value, "
                    "date_created, times_used FROM logins"
                )
                rows = cur.fetchall()
                con.close()
            except Exception as e:
                print(f"    [!] Errore SQL su {tmp}: {e}")
                continue
            finally:
                try:
                    tmp.unlink()
                except Exception:
                    pass

            n_ok = 0
            n_empty = 0
            n_v20_prot = 0
            n_fail = 0
            for url, user, pwd_blob, dc, tu in rows:
                if not pwd_blob:
                    continue
                plain, fmt = aes_gcm_decrypt(master_v10, master_v20, pwd_blob)
                if plain is None:
                    if fmt == "v20_protected":
                        n_v20_prot += 1
                        # Comunque registriamo l'entry come "protected"
                        cat, sev = classify(url)
                        records.append({
                            "browser": f"{b['browser']}/{profile.name}",
                            "url": url,
                            "username": user,
                            "password": None,
                            "protected": True,
                            "format": fmt,
                            "blob_len": len(pwd_blob),
                            "date_created": "",
                            "times_used": tu or 0,
                            "category": cat,
                            "severity": sev,
                            "strength": "PROTECTED_v20",
                            "analysis": {
                                "strength": "PROTECTED_v20",
                                "issues": ["Chrome v127+ App-Bound Encryption "
                                          "- richiede privilegi SYSTEM per decifrare"],
                                "length": None,
                            },
                        })
                    else:
                        n_fail += 1
                    continue
                if plain == "":
                    n_empty += 1
                    continue
                cat, sev = classify(url)
                ana = analyze_password(plain)
                try:
                    if dc and dc > 0:
                        date_created = datetime.datetime.fromtimestamp(
                            dc / 1000000 - 11644473600).strftime("%Y-%m-%d")
                    else:
                        date_created = ""
                except Exception:
                    date_created = ""
                records.append({
                    "browser": f"{b['browser']}/{profile.name}",
                    "url": url,
                    "username": user,
                    "password": plain,
                    "protected": False,
                    "format": fmt,
                    "blob_len": len(pwd_blob),
                    "date_created": date_created,
                    "times_used": tu or 0,
                    "category": cat,
                    "severity": sev,
                    "strength": ana["strength"],
                    "analysis": ana,
                })
                n_ok += 1
            stats_v20_protected += n_v20_prot
            print(f"    Profilo '{profile.name}': "
                  f"{n_ok} decifrate, {n_v20_prot} protette v20-ABE, "
                  f"{n_empty} vuote, {n_fail} errori")
    return records


def print_cli_summary(records: list[dict], reuse_map: dict, reveal: bool):
    """Stampa sommario CLI."""
    print("\n" + "=" * 72)
    print(f"SOMMARIO - {len(records)} credenziali totali")
    print("=" * 72)

    by_sev = defaultdict(int)
    by_str = defaultdict(int)
    n_protected = 0
    n_decrypted = 0
    for r in records:
        by_sev[r["severity"]] += 1
        by_str[r["strength"]] += 1
        if r.get("protected"):
            n_protected += 1
        else:
            n_decrypted += 1

    print(f"\nStato decifrazione:")
    print(f"  Decifrate (vulnerabili a infostealer user-mode): {n_decrypted}")
    print(f"  Protette v20-ABE (richiedono SYSTEM privileges):  {n_protected}")

    print(f"\nPer criticita' del sito:")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if by_sev[s]:
            print(f"  {s:10s}: {by_sev[s]:>3d}")

    print(f"\nPer robustezza password (solo quelle decifrate):")
    for s in ["VERY_WEAK", "WEAK", "MEDIUM", "STRONG", "VERY_STRONG"]:
        if by_str[s]:
            print(f"  {s:14s}: {by_str[s]:>3d}")
    if by_str["PROTECTED_v20"]:
        print(f"  PROTECTED_v20 : {by_str['PROTECTED_v20']:>3d}  "
              f"(non analizzabile - serve SYSTEM)")

    if reuse_map:
        print(f"\nPassword RIUTILIZZATE: {len(reuse_map)} gruppi, "
              f"{sum(len(v) for v in reuse_map.values())} account totali")
        for h, group in sorted(reuse_map.items(), key=lambda x: -len(x[1]))[:5]:
            sample = group[0]["password"]
            pwd_show = sample if reveal else mask(sample)
            urls = ", ".join(r["url"].split("/")[2] if "://" in r["url"] else r["url"]
                             for r in group[:3])
            if len(group) > 3:
                urls += f" ... +{len(group)-3}"
            print(f"  pwd '{pwd_show}' su {len(group)} siti: {urls}")

    # Top 10 password piu' deboli su siti critici
    weak_critical = [r for r in records
                     if not r.get("protected")
                     and r["severity"] in ("CRITICAL", "HIGH")
                     and r["strength"] in ("VERY_WEAK", "WEAK")]
    if weak_critical:
        print(f"\n!! TOP 10 password DEBOLI su siti CRITICAL/HIGH:")
        for r in weak_critical[:10]:
            pwd_show = r["password"] if reveal else mask(r["password"])
            print(f"  [{r['severity']:8s}] {r['url'][:55]:<55} "
                  f"({r['username'] or '-'}) -> '{pwd_show}' ({r['strength']})")

    # Top siti CRITICAL/HIGH protetti v20 (per consapevolezza)
    critical_protected = [r for r in records
                          if r.get("protected")
                          and r["severity"] in ("CRITICAL", "HIGH")]
    if critical_protected:
        print(f"\nSiti CRITICAL/HIGH protetti da v20-ABE ({len(critical_protected)}):")
        print(f"  Un infostealer user-mode (es. Kepavll, RedLine basic) NON")
        print(f"  riuscirebbe a esfiltrare queste credenziali senza elevation.")


class TeeOutput:
    """Mirror stdout/stderr a un file di log (utile in finestra elevata UAC
    che si chiude all'uscita)."""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
                st.flush()
            except Exception:
                pass

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


def main():
    ap = argparse.ArgumentParser(
        description="Audit difensivo delle credenziali salvate nei browser.")
    ap.add_argument("--browsers", help="Lista browser (default: tutti). "
                    "Es: chrome,edge,brave")
    ap.add_argument("--reveal", action="store_true",
                    help="Mostra le password in chiaro (default: mascherate).")
    ap.add_argument("--aggressive", action="store_true",
                    help="Tenta di rompere v20 App-Bound Encryption via "
                         "SYSTEM elevation (Task Scheduler). Richiede admin. "
                         "Implica --reveal.")
    ap.add_argument("--no-elevate", action="store_true",
                    help="Non rilanciare con UAC se --aggressive ma non admin. "
                         "Esce con errore.")
    ap.add_argument("--no-html", action="store_true",
                    help="Skip HTML, solo CLI.")
    ap.add_argument("--out", default=None,
                    help="Path output HTML (default: ./reports/audit_<timestamp>.html)")
    ap.add_argument("--no-pause", action="store_true",
                    help="Non fare pause-on-exit nemmeno in aggressive "
                         "(default: pausa se relaunched via UAC)")
    ap.add_argument(
        "--lang",
        choices=["it", "en", "fr", "de", "du", "es"],
        default=None,
        metavar="LANG",
        help="Lingua del report HTML: it/en/fr/de(=du)/es. "
             "Default: auto-detect dalla lingua di sistema Windows.",
    )
    args = ap.parse_args()

    # Lingua report
    raw_lang = args.lang or detect_system_language()
    lang = "de" if raw_lang == "du" else raw_lang  # alias du -> de

    # Mirror stdout/stderr su file di log quando aggressive
    # (la finestra UAC si chiude all'uscita e perderemmo l'output).
    log_file = None
    if args.aggressive:
        reports_dir = Path(__file__).parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = reports_dir / f"audit_aggressive_{ts}.log"
        try:
            log_file = open(log_path, "w", encoding="utf-8")
            sys.stdout = TeeOutput(sys.stdout, log_file)
            sys.stderr = TeeOutput(sys.stderr, log_file)
            print(f"[i] Log completo verra' scritto in: {log_path}")
        except Exception as e:
            print(f"[!] Impossibile creare log: {e}")

    ensure_dependencies()

    # Aggressive implica reveal (altrimenti che senso ha?)
    if args.aggressive:
        args.reveal = True
        if not is_admin():
            if args.no_elevate:
                print("[!] --aggressive richiede privilegi Administrator. "
                      "Lancia da PowerShell admin.")
                sys.exit(1)
            print("=" * 72)
            print("MODALITA' AGGRESSIVA — richiede elevazione UAC")
            print("=" * 72)
            print("Ti verra' chiesto di confermare l'elevazione a Administrator.")
            print("E' NECESSARIO per creare una scheduled task come SYSTEM,")
            print("che e' la tecnica usata per bypassare la v20 App-Bound Encryption.")
            print()
            relaunch_as_admin()
            return  # non raggiunto, relaunch_as_admin exit

    print("=" * 72)
    print("pwd_audit.py - audit credenziali browser")
    print("=" * 72)
    print(f"Utente Windows: {getpass.getuser()}")
    print(f"Admin elevato:  {is_admin()}")
    print(f"Aggressive mode: {args.aggressive}")
    print(f"Reveal mode:    {args.reveal}")
    if args.aggressive:
        print()
        print("!! ATTENZIONE: modalita' AGGRESSIVA attiva.")
        print("   Tentero' di rompere anche la cifratura v20 (App-Bound)")
        print("   creando una scheduled task SYSTEM. Tutte le password decifrate")
        print("   appariranno in chiaro nel report.")
    elif args.reveal:
        print("[!] ATTENZIONE: password in chiaro nel report. Non condividere il file.")

    browsers_filter = args.browsers.split(",") if args.browsers else None

    records = collect_credentials(browsers_filter, aggressive=args.aggressive)
    if not records:
        print("\nNessuna credenziale trovata. Fine.")
        return

    reuse_map = find_reuse(records)

    print_cli_summary(records, reuse_map, args.reveal)

    if not args.no_html:
        if args.out:
            out_path = Path(args.out)
        else:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_aggressive" if args.aggressive else ""
            out_path = Path(__file__).parent / "reports" / f"audit{suffix}_{ts}.html"
            out_path.parent.mkdir(parents=True, exist_ok=True)
        render_html(records, reuse_map, out_path, args.reveal,
                    aggressive=args.aggressive, lang=lang)
        print(f"\n[OK] Report HTML: {out_path}")
        print(f"     Aprilo nel browser per la versione completa.")
        if args.reveal:
            print(f"     [!] CONTIENE PASSWORD IN CHIARO. "
                  f"Elimina dopo l'uso o spostalo in BitLocker.")

    print()

    # In aggressive mode, pausa per non far chiudere la finestra UAC.
    if args.aggressive and not args.no_pause:
        print("=" * 72)
        print("OK. Premi INVIO per uscire (e chiudere questa finestra).")
        print("=" * 72)
        try:
            input()
        except EOFError:
            pass

    if log_file:
        try:
            log_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
