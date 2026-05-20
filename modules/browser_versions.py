"""Detection versione browser + matching contro KB vulnerabilita'.

Determina:
- Quali browser sono installati
- Loro versione esatta (registry / file version info)
- Quali vulnerabilita' note li affettano (basandosi su kb/vulnerabilities.json)
- Quali fix sono necessari (consigli con release date)
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import winreg
from pathlib import Path

# ============================================================
# RILEVAMENTO VERSIONI
# ============================================================
def _get_file_version(file_path: Path) -> str | None:
    """Estrae version info da un .exe via Windows API."""
    if not file_path.exists():
        return None
    try:
        # Usa powershell come fallback portatile (no pywin32 needed)
        ps_cmd = (f"(Get-Item '{file_path}').VersionInfo.ProductVersion")
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def _get_reg_value(hive, sub, name) -> str | None:
    try:
        with winreg.OpenKey(hive, sub) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return val
    except (FileNotFoundError, OSError):
        return None


def detect_chrome_version() -> str | None:
    """Detecta versione Chrome via registry + fallback file."""
    # Registry: HKCU\Software\Google\Chrome\BLBeacon\version
    v = _get_reg_value(winreg.HKEY_CURRENT_USER,
                       r"Software\Google\Chrome\BLBeacon", "version")
    if v:
        return v
    v = _get_reg_value(winreg.HKEY_LOCAL_MACHINE,
                       r"SOFTWARE\Google\Chrome\BLBeacon", "version")
    if v:
        return v
    # File fallback
    candidates = [
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"))
        / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None


def detect_edge_version() -> str | None:
    """Edge version via file."""
    candidates = [
        Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"))
        / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "Microsoft/Edge/Application/msedge.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    # Registry
    return _get_reg_value(winreg.HKEY_LOCAL_MACHINE,
                          r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
                          "pv")


def detect_brave_version() -> str | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "BraveSoftware/Brave-Browser/Application/brave.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "BraveSoftware/Brave-Browser/Application/brave.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None


def detect_vivaldi_version() -> str | None:
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Vivaldi/Application/vivaldi.exe",
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "Vivaldi/Application/vivaldi.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None


def detect_firefox_version() -> str | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files"))
        / "Mozilla Firefox/firefox.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"))
        / "Mozilla Firefox/firefox.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None


def detect_opera_version() -> str | None:
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Opera/opera.exe",
        Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "Opera/opera.exe",
    ]
    for c in candidates:
        if c.exists():
            v = _get_file_version(c)
            if v:
                return v
    return None


def detect_all_browsers() -> dict:
    """Ritorna dict {browser_name: version_string_or_None}."""
    return {
        "Chrome": detect_chrome_version(),
        "Edge": detect_edge_version(),
        "Brave": detect_brave_version(),
        "Vivaldi": detect_vivaldi_version(),
        "Firefox": detect_firefox_version(),
        "Opera": detect_opera_version(),
    }


# ============================================================
# MATCHING CONTRO KB
# ============================================================
def _parse_major(v: str) -> int | None:
    """Estrae il major version da '148.0.7050.30' -> 148."""
    if not v:
        return None
    m = re.match(r"(\d+)", v)
    return int(m.group(1)) if m else None


def _version_in_range(version: str, range_str: str) -> bool:
    """Check se 'version' rientra in range_str come '127.0 - 130.x' o '>= 148' o '< 127'."""
    major = _parse_major(version)
    if major is None:
        return False
    range_str = range_str.strip()

    if range_str.startswith(">= "):
        return major >= int(range_str[3:].split(".")[0])
    if range_str.startswith("<= "):
        return major <= int(range_str[3:].split(".")[0])
    if range_str.startswith("> "):
        return major > int(range_str[2:].split(".")[0])
    if range_str.startswith("< "):
        return major < int(range_str[2:].split(".")[0])
    if " - " in range_str:
        lo, hi = range_str.split(" - ", 1)
        lo_m = _parse_major(lo)
        hi_m = _parse_major(hi)
        if lo_m is not None and hi_m is not None:
            return lo_m <= major <= hi_m
    # Exact match like "127" or "127.x"
    if range_str.endswith(".x"):
        return major == int(range_str[:-2].split(".")[0])
    try:
        return major == int(range_str.split(".")[0])
    except ValueError:
        return False


def load_kb(kb_path: Path | None = None) -> dict:
    """Carica il knowledge base JSON."""
    if kb_path is None:
        # Default: <script_dir>/../kb/vulnerabilities.json
        kb_path = Path(__file__).parent.parent / "kb" / "vulnerabilities.json"
    with open(kb_path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_applicable_vulnerabilities(browser_name: str, version: str,
                                     kb: dict) -> list[dict]:
    """Per un browser + versione, restituisce gli entry KB applicabili.

    Solo per browser Chromium-based (Chrome, Edge, Brave, Vivaldi, Opera).
    Per Firefox abbiamo logica separata.
    """
    if not version or browser_name == "Firefox":
        return []

    timeline = kb.get("chromium_abe_timeline", [])
    applicable = []
    for entry in timeline:
        if _version_in_range(version, entry["version_range"]):
            applicable.append(entry)
    return applicable


def severity_score(entry: dict) -> int:
    """Punteggio 1-10 basato su difficolta'.

    Lower difficulty (TRIVIAL/LOW) → higher score (more vulnerable).
    """
    diff = entry.get("decrypt_difficulty", "MEDIUM")
    return {
        "TRIVIAL": 10,
        "LOW": 9,
        "MEDIUM": 6,
        "HARD": 3,
        "VERY_HARD": 1,
    }.get(diff, 5)


def render_vulnerability_summary(browsers: dict, kb: dict) -> list[dict]:
    """Per ogni browser rilevato, costruisce un summary di vulnerabilita'.

    Ritorna lista di:
    {
      "browser": "Chrome",
      "version": "148.0.7050.30",
      "major": 148,
      "abe_status": "ABE_V3_DBSC",
      "decrypt_difficulty": "VERY_HARD",
      "score": 1-10,
      "applicable_bypasses": [...],
      "applicable_techniques_detail": [{name, complexity, ...}, ...],
      "kb_entries": [...],
      "fix_recommendation": "...",
      "current_stable_version": "148",
      "outdated": False,
    }
    """
    results = []
    for browser_name, version in browsers.items():
        if not version:
            continue

        major = _parse_major(version)
        info = {
            "browser": browser_name,
            "version": version,
            "major": major,
        }

        # Browser info da KB
        br_kb = kb.get("browsers", {}).get(browser_name, {})
        current_stable = br_kb.get("current_stable")
        try:
            current_major = int(str(current_stable).split(".")[0])
        except (ValueError, AttributeError):
            current_major = None
        info["current_stable"] = current_stable
        info["outdated"] = (current_major is not None and major is not None
                            and major < current_major)
        info["abe_enabled"] = br_kb.get("abe_enabled", False)

        # Cerca vulnerabilita' nel timeline ABE (solo Chromium)
        if browser_name != "Firefox":
            applicable = find_applicable_vulnerabilities(browser_name, version, kb)
            if applicable:
                entry = applicable[0]  # primo match
                info["abe_status"] = entry.get("abe_status")
                info["decrypt_difficulty"] = entry.get("decrypt_difficulty")
                info["score"] = severity_score(entry)
                info["description"] = entry.get("description")
                info["applicable_bypasses"] = entry.get("applicable_bypasses", [])
                info["fix_label"] = entry.get("fix", {}).get("milestone")
                info["fix_version"] = entry.get("fix", {}).get("fixed_in")
                info["fix_date"] = entry.get("fix", {}).get("fixed_date")
                info["kb_entries"] = applicable
                # Resolve tecnica dettagli
                tech_kb = kb.get("bypass_techniques", {})
                info["bypass_details"] = []
                for bp in entry.get("applicable_bypasses", []):
                    if bp in tech_kb:
                        info["bypass_details"].append({
                            "key": bp,
                            **tech_kb[bp]
                        })
        else:
            # Firefox: logica specifica
            info["abe_status"] = "NSS"
            info["decrypt_difficulty"] = "MEDIUM"
            info["score"] = 6
            info["description"] = (
                "Firefox usa NSS database (key4.db). Senza master password, "
                "le credenziali sono decifrabili user-mode via PBKDF2 + AES-256-CBC. "
                "Con master password impostata, attacker deve fare brute force su di essa."
            )
            info["fix_label"] = "Imposta una Master Password forte in Firefox"
            info["fix_version"] = "any"
            info["fix_date"] = "user action required"

        results.append(info)
    return results


# ============================================================
# SUGGERIMENTI FIX
# ============================================================
def generate_fix_recommendations(summary: list[dict], kb: dict) -> list[dict]:
    """Lista raccomandazioni concrete con priorita'."""
    recs = []
    for s in summary:
        if s.get("outdated"):
            recs.append({
                "priority": "HIGH",
                "browser": s["browser"],
                "action": f"Aggiorna {s['browser']} alla versione {s['current_stable']} "
                          f"(attualmente: {s['version']}).",
                "reason": "Versione obsoleta espone a CVE note risolte in versioni recenti.",
                "how": f"Apri {s['browser']} → menu → Informazioni → "
                       f"l'aggiornamento si scarica automaticamente. "
                       f"Riavvia il browser per completare.",
            })

        if s.get("score", 0) >= 8:
            recs.append({
                "priority": "CRITICAL",
                "browser": s["browser"],
                "action": "Migra le credenziali a un password manager dedicato "
                          "(Bitwarden / KeePassXC / 1Password).",
                "reason": (f"{s['browser']} v{s['major']} ha protezione "
                           f"'{s.get('decrypt_difficulty', 'MEDIUM')}' contro decryption: "
                           "un infostealer comune le esfiltra in secondi."),
                "how": "Esporta password da browser (Settings > Password > Esporta), "
                       "importale nel PM, poi cancellale dal browser.",
            })

        if s.get("abe_enabled"):
            recs.append({
                "priority": "MEDIUM",
                "browser": s["browser"],
                "action": "Disabilita 'Save passwords' nel browser",
                "reason": "Anche con v20 ABE attivo, eliminare la superficie d'attacco "
                          "e' meglio che proteggerla.",
                "how": f"Settings > Password manager > disattiva 'Offer to save passwords'. "
                       "O via policy registry HKCU\\Software\\Policies\\... "
                       "(vedi /Policies / fai eseguire al tool).",
            })

        if s["browser"] == "Firefox":
            recs.append({
                "priority": "HIGH",
                "browser": "Firefox",
                "action": "Imposta una Master Password (Primary Password) in Firefox",
                "reason": "Senza master password, le credenziali Firefox sono "
                          "decifrabili in pochi secondi da un infostealer.",
                "how": "Firefox > Settings > Privacy & Security > Logins and Passwords > "
                       "Use a Primary Password. Scegli una password robusta (16+ char).",
            })
    return recs
