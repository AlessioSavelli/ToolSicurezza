"""Rilevamento target classici di un infostealer (oltre password browser).

Per ogni target rilevato, il tool segnala SOLO LA PRESENZA — non
esfiltra ne' decifra il contenuto. Lo scopo e' quantificare la superficie
d'attacco, non fare il lavoro del malware.

Target audited:
  - Discord token (Local Storage leveldb)
  - Steam loginusers.vdf
  - Crypto wallet extensions (Chrome/Edge/Brave)
  - Telegram Desktop session
  - Windows Credential Manager (count entries)
  - SSH private keys
  - GPG keyring
  - FileZilla sitemanager.xml
  - VPN configs (OpenVPN, WireGuard)
"""
from __future__ import annotations
import json
import os
import re
import subprocess
from pathlib import Path


# Path templates
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
ROAMING = Path(os.environ.get("APPDATA", ""))
HOME = Path(os.environ.get("USERPROFILE", "~"))


# ============================================================
# DISCORD
# ============================================================
def check_discord_token() -> dict:
    """Verifica presenza dati Discord."""
    result = {
        "target": "Discord Token",
        "found": False,
        "paths": [],
        "ldb_files": 0,
        "log_files": 0,
        "encrypted_token_pattern_found": False,
        "details": [],
        "value": "HIGH",
        "description": "Token API Discord — login completo bypassando 2FA. "
                       "Cifrato AES-GCM con master key DPAPI.",
    }
    variants = ["discord", "discordptb", "discordcanary", "discorddevelopment"]
    for v in variants:
        p = ROAMING / v / "Local Storage" / "leveldb"
        if p.exists():
            result["found"] = True
            result["paths"].append(str(p))
            ldb = list(p.glob("*.ldb"))
            log = list(p.glob("*.log"))
            result["ldb_files"] += len(ldb)
            result["log_files"] += len(log)
            # Cerca pattern token v10_ in qualche file
            try:
                for f in (ldb + log)[:5]:  # check primi 5 file
                    raw = f.read_bytes()
                    if b"dQw4w9WgXcQ:" in raw or b'"v10_' in raw or b"v10_" in raw:
                        result["encrypted_token_pattern_found"] = True
                        break
            except Exception:
                pass
    if result["found"]:
        result["details"].append(
            f"Trovati {result['ldb_files']} .ldb + {result['log_files']} .log "
            f"in {len(result['paths'])} install Discord")
        if result["encrypted_token_pattern_found"]:
            result["details"].append(
                "[!] Pattern token cifrato 'v10_' rilevato nei file leveldb")
    return result


# ============================================================
# STEAM
# ============================================================
def check_steam() -> dict:
    """Verifica presenza loginusers.vdf di Steam."""
    result = {
        "target": "Steam autologin",
        "found": False,
        "paths": [],
        "users": [],
        "details": [],
        "value": "HIGH",
        "description": "Token autologin Steam — accesso al client + library + "
                       "skin senza credenziali. NON ruba la password ma il token.",
    }
    candidates = [
        Path("C:/Program Files (x86)/Steam/config/loginusers.vdf"),
        Path("C:/Program Files/Steam/config/loginusers.vdf"),
    ]
    for c in candidates:
        if c.exists():
            result["found"] = True
            result["paths"].append(str(c))
            try:
                content = c.read_text(encoding="utf-8", errors="ignore")
                # Estrai SteamIDs e nomi
                ids = re.findall(r'"(\d{17})"', content)
                names = re.findall(r'"PersonaName"\s+"([^"]+)"', content)
                accounts = re.findall(r'"AccountName"\s+"([^"]+)"', content)
                allow_auto = re.findall(r'"AllowAutoLogin"\s+"(\d)"', content)
                result["users"] = list(set(names + accounts))
                result["details"].append(
                    f"SteamIDs trovati: {len(set(ids))} | "
                    f"AutoLogin attivo per: {sum(int(x) for x in allow_auto)}")
            except Exception:
                pass
    # Steamguard files
    ssfn_dir = Path("C:/Program Files (x86)/Steam")
    if ssfn_dir.exists():
        ssfn = list(ssfn_dir.glob("ssfn*"))
        if ssfn:
            result["details"].append(f"Trovati {len(ssfn)} file ssfn "
                                     "(Steam Guard cookies)")
    return result


# ============================================================
# CRYPTO WALLET EXTENSIONS
# ============================================================
WALLET_EXTENSIONS = {
    # extension_id : display_name
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
    "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask (alt)",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
    "fhilaheimglignddkjgofkcbgekhenbh": "Oxygen / Atomic",
    "fnnegphlobjdpkhecapkijjdkgcjhkib": "Harmony",
    "nphplpgoakhhjchkkhmiggakijnkhfnd": "TON Wallet",
    "ojggmchlghnjlapmfbnjholfjkiidbch": "Venom",
    "aiifbnbfobpmeekipheeijimdpnlpgpp": "Station Wallet (Terra)",
    "amkmjjmmflddogmhpjloimipbofnfjih": "Wombat",
    "nlbmnnijcnlegkjjpcfjclmcfggfefdm": "MEW CX",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby Wallet",
    "opcgpfmipidbgpenhmajoajpbobppdil": "Sui Wallet",
    "fhmfendgdocmcbmfikdcogofphimnkno": "Sollet",
    "klnaejjgbibmhlephnhpmaofohgkpgkd": "ZilPay",
    "lpfcbjknijpeeillifnkikgncikgfhdo": "Nami (Cardano)",
    "kkpllkodjeloidieedojogacfhpaihoh": "Enkrypt",
    "djclckkglechooblngghdinmeemkbgci": "OKX Wallet",
    "blnieiiffboillknjnepogjhkgnoapac": "Petra (Aptos)",
    "ppdadbejkmjnefldpcdjhnkpbjkikoip": "Backpack",
    "cnmamaachppnkjgnildpdmkaakejnhae": "Aurora Wallet",
}

CHROMIUM_BROWSERS_FOR_WALLETS = [
    ("Chrome", LOCAL / "Google/Chrome/User Data"),
    ("Edge", LOCAL / "Microsoft/Edge/User Data"),
    ("Brave", LOCAL / "BraveSoftware/Brave-Browser/User Data"),
    ("Vivaldi", LOCAL / "Vivaldi/User Data"),
    ("Opera", ROAMING / "Opera Software/Opera Stable"),
]


def check_crypto_wallets() -> dict:
    """Scansiona estensioni wallet installate."""
    result = {
        "target": "Crypto wallets (browser extensions)",
        "found": False,
        "installed": [],  # [{browser, profile, ext_id, name, has_data}]
        "details": [],
        "value": "CRITICAL",
        "description": "Estensioni wallet crypto: seed phrase + private keys "
                       "spesso cifrati con password debole.",
    }
    for browser_name, root in CHROMIUM_BROWSERS_FOR_WALLETS:
        if not root.exists():
            continue
        # Profili
        for profile in root.iterdir():
            if not profile.is_dir():
                continue
            ext_dir = profile / "Extensions"
            ldata_dir = profile / "Local Extension Settings"
            if not ext_dir.exists():
                continue
            for ext_id, name in WALLET_EXTENSIONS.items():
                ext_path = ext_dir / ext_id
                if ext_path.exists():
                    has_local_data = (ldata_dir / ext_id).exists()
                    data_size = 0
                    if has_local_data:
                        try:
                            data_size = sum(
                                f.stat().st_size
                                for f in (ldata_dir / ext_id).rglob("*")
                                if f.is_file()
                            )
                        except Exception:
                            pass
                    result["installed"].append({
                        "browser": browser_name,
                        "profile": profile.name,
                        "ext_id": ext_id,
                        "name": name,
                        "has_local_data": has_local_data,
                        "data_size_bytes": data_size,
                    })
                    result["found"] = True
    if result["installed"]:
        result["details"].append(
            f"Trovate {len(result['installed'])} estensioni wallet installate")
        for w in result["installed"]:
            data_kb = w["data_size_bytes"] // 1024
            status = f"con {data_kb}KB di dati locali" if w["has_local_data"] else "senza dati locali"
            result["details"].append(
                f"  - {w['name']:25s} ({w['browser']}/{w['profile']}) — {status}")
    return result


# ============================================================
# TELEGRAM
# ============================================================
def check_telegram() -> dict:
    """Verifica Telegram Desktop session."""
    result = {
        "target": "Telegram Desktop session",
        "found": False,
        "paths": [],
        "details": [],
        "value": "HIGH",
        "description": "Telegram tdata directory contiene session token che "
                       "permette login senza credenziali.",
    }
    p = ROAMING / "Telegram Desktop" / "tdata"
    if p.exists():
        result["found"] = True
        result["paths"].append(str(p))
        try:
            # Conta file key_data*
            keys = list(p.glob("key_data*"))
            d_dir = list(p.glob("D*"))
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
            result["details"].append(
                f"key_data files: {len(keys)} | D dirs: {len(d_dir)} | "
                f"size: {size//1024}KB")
        except Exception:
            pass
    return result


# ============================================================
# SSH KEYS
# ============================================================
def check_ssh_keys() -> dict:
    """Cerca chiavi SSH private."""
    result = {
        "target": "SSH private keys",
        "found": False,
        "paths": [],
        "encrypted": 0,
        "unencrypted": 0,
        "details": [],
        "value": "HIGH",
        "description": "Chiavi SSH private = accesso a server, GitHub, "
                       "deployment. Senza passphrase = accesso istantaneo.",
    }
    ssh_dir = HOME / ".ssh"
    if not ssh_dir.exists():
        return result
    key_names = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]
    for name in key_names:
        kf = ssh_dir / name
        if kf.exists() and not str(kf).endswith(".pub"):
            result["found"] = True
            result["paths"].append(str(kf))
            try:
                first_line = kf.read_text(encoding="utf-8",
                                          errors="ignore").splitlines()[0:5]
                head = "\n".join(first_line)
                if "ENCRYPTED" in head or "DEK-Info" in head:
                    result["encrypted"] += 1
                    result["details"].append(f"  - {name}: ENCRYPTED (con passphrase)")
                else:
                    result["unencrypted"] += 1
                    result["details"].append(
                        f"  - {name}: NON cifrata (no passphrase) [!]")
            except Exception:
                pass
    # Anche eventuali altre chiavi
    for kf in ssh_dir.iterdir():
        if kf.is_file() and kf.name not in key_names \
                and not kf.suffix == ".pub" \
                and kf.name not in ("known_hosts", "config", "authorized_keys"):
            try:
                head = kf.read_text(encoding="utf-8", errors="ignore")[:200]
                if "BEGIN" in head and "PRIVATE KEY" in head:
                    result["found"] = True
                    result["paths"].append(str(kf))
                    if "ENCRYPTED" in head:
                        result["encrypted"] += 1
                    else:
                        result["unencrypted"] += 1
            except Exception:
                pass
    return result


# ============================================================
# GPG KEYRING
# ============================================================
def check_gpg() -> dict:
    result = {
        "target": "GPG keyring",
        "found": False,
        "paths": [],
        "details": [],
        "value": "MEDIUM",
        "description": "Chiavi GPG: firme codice, decifratura email, "
                       "git commit signing.",
    }
    p = ROAMING / "gnupg"
    if p.exists():
        result["found"] = True
        result["paths"].append(str(p))
        priv = list((p / "private-keys-v1.d").glob("*.key")) if (p / "private-keys-v1.d").exists() else []
        result["details"].append(f"Private keys: {len(priv)}")
    return result


# ============================================================
# FILEZILLA
# ============================================================
def check_filezilla() -> dict:
    result = {
        "target": "FileZilla sitemanager",
        "found": False,
        "paths": [],
        "credentials": 0,
        "details": [],
        "value": "HIGH",
        "description": "FileZilla salva FTP credentials in chiaro (storica "
                       "vulnerabilita').",
    }
    candidates = [
        ROAMING / "FileZilla/sitemanager.xml",
        ROAMING / "FileZilla/recentservers.xml",
    ]
    for c in candidates:
        if c.exists():
            result["found"] = True
            result["paths"].append(str(c))
            try:
                text = c.read_text(encoding="utf-8", errors="ignore")
                # Conta <Pass>
                n = len(re.findall(r"<Pass[\s>]", text))
                result["credentials"] += n
            except Exception:
                pass
    if result["credentials"]:
        result["details"].append(f"Credenziali FTP salvate: {result['credentials']}")
    return result


# ============================================================
# WINDOWS CREDENTIAL MANAGER
# ============================================================
def check_credential_manager() -> dict:
    """Conta credenziali in Windows Credential Manager (Generic + Web)."""
    result = {
        "target": "Windows Credential Manager",
        "found": False,
        "count": 0,
        "details": [],
        "value": "MEDIUM",
        "description": "Credenziali Outlook/RDP/network shares/Git in "
                       "Credential Manager. Cifrate DPAPI user-context.",
    }
    try:
        ps_cmd = "cmdkey /list | Select-String '^\\s*Target:' | Measure-Object | Select-Object -ExpandProperty Count"
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            try:
                n = int(out.stdout.strip())
                result["count"] = n
                result["found"] = n > 0
                if n > 0:
                    result["details"].append(f"Entry totali in Credential Manager: {n}")
            except ValueError:
                pass
    except Exception:
        pass
    return result


# ============================================================
# VPN CONFIGS
# ============================================================
def check_vpn_configs() -> dict:
    result = {
        "target": "VPN client configs",
        "found": False,
        "items": [],
        "details": [],
        "value": "MEDIUM",
        "description": "Config OpenVPN/WireGuard con credenziali embedded.",
    }
    # OpenVPN
    ovpn_dirs = [
        Path("C:/Program Files/OpenVPN/config"),
        HOME / "OpenVPN/config",
    ]
    for d in ovpn_dirs:
        if d.exists():
            ovpns = list(d.glob("*.ovpn"))
            if ovpns:
                result["found"] = True
                result["items"].append(
                    {"type": "OpenVPN", "path": str(d), "count": len(ovpns)})
    # WireGuard
    wg = Path("C:/Program Files/WireGuard/Data/Configurations")
    if wg.exists():
        cfgs = list(wg.glob("*.conf"))
        if cfgs:
            result["found"] = True
            result["items"].append(
                {"type": "WireGuard", "path": str(wg), "count": len(cfgs)})
    for it in result["items"]:
        result["details"].append(f"  {it['type']}: {it['count']} config in {it['path']}")
    return result


# ============================================================
# ORCHESTRATORE
# ============================================================
def audit_all_targets() -> list[dict]:
    """Esegue tutti i check, ritorna lista risultati."""
    checks = [
        check_discord_token,
        check_steam,
        check_crypto_wallets,
        check_telegram,
        check_ssh_keys,
        check_gpg,
        check_filezilla,
        check_credential_manager,
        check_vpn_configs,
    ]
    return [c() for c in checks]
