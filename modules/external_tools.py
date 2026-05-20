"""Detection + auto-install di tool open-source di credential recovery.

Tool gestiti (tutti Python, pip-installable o git+pip):

  - pypykatz         - Mimikatz portato in Python puro (DPAPI, LSASS, ecc.)
  - firepwd          - Firefox NSS password decryptor
  - browser_cookie3  - Browser cookie extractor
  - haystack         - Optional, memory analysis
  - LaZagne          - Multi-source credential dumper (Defender PUA-flagged)

Comportamento:
  - All'avvio, check ogni tool importabile/in PATH
  - Se mancante e auto_install=True: pip install
  - Una volta al giorno: pip install --upgrade (per tenerli aggiornati)
  - Risultati cache su file per evitare pip ogni avvio
  - Defender-flagged tools NON auto-installati di default; usa
    --install-flagged-tools per opt-in esplicito

Etica:
  - Solo tool pubblicamente disponibili (GitHub/PyPI), nessuna sorgente "shady"
  - Eseguiti solo per audit del PC dell'utente
  - LaZagne (e simili PUA-flagged) richiedono conferma esplicita perché
    Microsoft Defender potrebbe metterli in quarantena
"""
from __future__ import annotations
import datetime
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


STATE_FILE = Path(tempfile.gettempdir()) / "pwd_audit_tools_state.json"
UPDATE_INTERVAL_HOURS = 24


# ============================================================
# REGISTRO TOOL
# ============================================================
TOOL_REGISTRY = {
    "pypykatz": {
        "description": "Mimikatz pure-Python (DPAPI, LSASS, SAM, ecc.)",
        "pypi_name": "pypykatz",
        "import_name": "pypykatz",
        "cli_check": ["pypykatz", "--help"],
        "category": "credential_extraction",
        "github": "https://github.com/skelsec/pypykatz",
        "defender_flagged": False,
        "use_cases": [
            "Dump DPAPI master keys",
            "Parsare Credential Manager files",
            "LSASS minidump parsing",
        ],
    },
    # firepwd: replicato internamente da modules/firefox_nss.py (NON auto-install
    # perche' lclevy/firepwd e' uno script standalone senza setup.py)
    "firepwd_internal": {
        "description": "Firefox NSS decrypt (impl. interna, equivalente a firepwd)",
        "pypi_name": None,
        "git_install": None,
        "import_name": "modules.firefox_nss",  # nostro modulo interno
        "cli_check": None,
        "category": "browser_passwords",
        "github": "https://github.com/lclevy/firepwd (algoritmo replicato internamente)",
        "defender_flagged": False,
        "use_cases": [
            "Decifrare profili Firefox con/senza Primary Password "
            "(no dependency esterna)",
        ],
    },
    "browser_cookie3": {
        "description": "Multi-browser cookie extractor",
        "pypi_name": "browser-cookie3",
        "import_name": "browser_cookie3",
        "cli_check": None,
        "category": "browser_cookies",
        "github": "https://github.com/borisbabic/browser_cookie3",
        "defender_flagged": False,
        "use_cases": [
            "Estrarre cookie da Chrome/Firefox/Edge per audit sessioni attive",
        ],
    },
    "lazagne": {
        "description": "LaZagne - multi-source credential dumper",
        "pypi_name": None,  # non su PyPI
        "git_install": "git+https://github.com/AlessandroZ/LaZagne.git",
        "import_name": None,
        "cli_check": ["laZagne.exe", "--help"],
        "alt_cli_checks": [
            ["laZagne", "--help"],
            ["lazagne", "--help"],
            [sys.executable, "-m", "lazagne", "--help"],
        ],
        "category": "all_credentials",
        "github": "https://github.com/AlessandroZ/LaZagne",
        "defender_flagged": True,
        "use_cases": [
            "Browsers, email clients, Wi-Fi, FTP, chat apps, ecc.",
        ],
    },
}


# ============================================================
# CHECK INSTALLAZIONE
# ============================================================
def _is_module_importable(name: str) -> bool:
    if not name:
        return False
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


def _is_command_available(cmd_args: list) -> bool:
    """Verifica se un comando e' eseguibile sul sistema.

    NB: NON usiamo solo subprocess.run perche' su Windows:
      - Un'invocazione di un comando inesistente puo' aprire finestra Store
      - `python -m <module>` ritorna rc=1 con "No module named" anche se
        Python e' valido (falso positivo se non controlliamo stderr)
    """
    if not cmd_args:
        return False
    exe = cmd_args[0]
    # Caso speciale: python -m <module>
    if (exe == sys.executable or exe.lower().endswith("python.exe")
            or exe.lower().endswith("python")) \
            and len(cmd_args) >= 3 and cmd_args[1] == "-m":
        module_name = cmd_args[2]
        if not _is_module_importable(module_name):
            return False
        try:
            r = subprocess.run(cmd_args, capture_output=True, text=True, timeout=5)
            stderr_lower = (r.stderr or "").lower()
            if "no module named" in stderr_lower:
                return False
            return r.returncode in (0, 1, 2)
        except Exception:
            return False
    # Path assoluto
    if "\\" in exe or "/" in exe:
        if not Path(exe).exists():
            return False
    else:
        # Comando su PATH
        if not shutil.which(exe):
            return False
    try:
        r = subprocess.run(cmd_args, capture_output=True, text=True, timeout=5)
        return r.returncode in (0, 1, 2)
    except Exception:
        return False


def check_tool_installed(tool_name: str) -> bool:
    """Ritorna True se il tool e' utilizzabile (importabile o CLI disponibile)."""
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return False
    if info.get("import_name") and _is_module_importable(info["import_name"]):
        return True
    if info.get("cli_check") and _is_command_available(info["cli_check"]):
        return True
    for alt in info.get("alt_cli_checks", []):
        if _is_command_available(alt):
            return True
    return False


# ============================================================
# INSTALL / UPDATE
# ============================================================
def _pip_install(args: list, upgrade: bool = False, verbose: bool = True) -> bool:
    """Wrapper pip install. Ritorna True se rc=0."""
    cmd = [sys.executable, "-m", "pip", "install", "--quiet",
           "--disable-pip-version-check"]
    if upgrade:
        cmd.append("--upgrade")
    cmd.extend(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if verbose and r.returncode != 0:
            print(f"    [!] pip stderr: {r.stderr.strip()[:300]}")
        return r.returncode == 0
    except Exception as e:
        if verbose:
            print(f"    [!] pip exception: {e}")
        return False


def install_tool(tool_name: str, force: bool = False, verbose: bool = True) -> bool:
    """Installa un tool. Ritorna True se ora e' disponibile."""
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return False
    if info.get("defender_flagged") and not force:
        if verbose:
            print(f"    [skip] {tool_name} - flagged come PUA da Defender. "
                  f"Usa --install-flagged-tools per installare.")
        return False

    if verbose:
        print(f"    [pip] Installo {tool_name}...")
    args = []
    if info.get("pypi_name"):
        args.append(info["pypi_name"])
    elif info.get("git_install"):
        args.append(info["git_install"])
    else:
        if verbose:
            print(f"    [!] Nessun metodo di install per {tool_name}")
        return False
    ok = _pip_install(args, upgrade=False, verbose=verbose)
    if ok:
        # Verify
        return check_tool_installed(tool_name)
    return False


def upgrade_tool(tool_name: str, verbose: bool = True) -> bool:
    """Upgrade di un tool gia' installato."""
    info = TOOL_REGISTRY.get(tool_name)
    if not info:
        return False
    if verbose:
        print(f"    [pip] Upgrade {tool_name}...")
    args = []
    if info.get("pypi_name"):
        args.append(info["pypi_name"])
    elif info.get("git_install"):
        args.append(info["git_install"])
    else:
        return False
    return _pip_install(args, upgrade=True, verbose=verbose)


# ============================================================
# STATE / GIORNALIERO
# ============================================================
def _load_state() -> dict:
    if not STATE_FILE.exists():
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: dict):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _should_check_updates() -> bool:
    state = _load_state()
    last = state.get("last_update_check")
    if not last:
        return True
    try:
        last_dt = datetime.datetime.fromisoformat(last)
        age = datetime.datetime.now() - last_dt
        return age.total_seconds() >= UPDATE_INTERVAL_HOURS * 3600
    except Exception:
        return True


def _mark_updates_done():
    state = _load_state()
    state["last_update_check"] = datetime.datetime.now().isoformat()
    _save_state(state)


# ============================================================
# ENSURE-ALL (orchestratore)
# ============================================================
def ensure_external_tools(auto_install: bool = True,
                          install_flagged: bool = False,
                          force_update: bool = False,
                          verbose: bool = True) -> dict:
    """Per ogni tool nel registry:
      1. Check se installato
      2. Se mancante e auto_install=True: pip install
      3. Se installato e (update_check_due or force_update): pip upgrade

    Ritorna dict di stato finale:
      {
        "tool_name": {
          "installed": True/False,
          "newly_installed": True/False,
          "upgraded": True/False,
          "defender_flagged": True/False,
          "github": "...",
          ...
        }
      }
    """
    results = {}
    should_update = force_update or _should_check_updates()

    for name, info in TOOL_REGISTRY.items():
        if verbose:
            print(f"\n  [tool] {name} - {info['description']}")

        was_installed = check_tool_installed(name)
        newly = False
        upgraded = False

        if not was_installed and auto_install:
            if info.get("defender_flagged") and not install_flagged:
                if verbose:
                    print(f"    [skip] PUA-flagged, salto auto-install. "
                          f"Disponibile su {info['github']}")
            else:
                newly = install_tool(name, force=install_flagged, verbose=verbose)
                if verbose:
                    print(f"    {'[+] Installato' if newly else '[!] Install fallito'}")

        elif was_installed and should_update:
            if info.get("defender_flagged") and not install_flagged:
                if verbose:
                    print(f"    [ok] Gia' installato (no upgrade per PUA-flagged)")
            else:
                upgraded = upgrade_tool(name, verbose=verbose)
                if verbose:
                    print(f"    {'[~] Upgraded' if upgraded else '[ok] Up-to-date o stesso'}")

        elif was_installed:
            if verbose:
                print(f"    [ok] Gia' installato")

        final_state = check_tool_installed(name)
        results[name] = {
            "installed": final_state,
            "newly_installed": newly,
            "upgraded": upgraded,
            "description": info["description"],
            "github": info["github"],
            "defender_flagged": info.get("defender_flagged", False),
            "category": info["category"],
            "use_cases": info.get("use_cases", []),
        }

    if should_update:
        _mark_updates_done()
    return results


# ============================================================
# INVOCATION
# ============================================================
def run_pypykatz_dpapi_dump() -> dict:
    """Esegue pypykatz live dpapi blob dump. Ritorna info aggregata."""
    if not check_tool_installed("pypykatz"):
        return {"available": False}
    try:
        # Versione semplificata: dump DPAPI masterkeys + Credential Manager
        r = subprocess.run(
            [sys.executable, "-m", "pypykatz", "live", "dpapi", "credentialfiles"],
            capture_output=True, text=True, timeout=30,
        )
        out = r.stdout
        return {
            "available": True,
            "ok": r.returncode == 0,
            "output_preview": out[:3000],
            "lines": len(out.splitlines()),
        }
    except Exception as e:
        return {"available": True, "ok": False, "error": str(e)}


def run_browser_cookie3_count() -> dict:
    """Usa browser_cookie3 per CONTARE i cookie disponibili per browser."""
    if not check_tool_installed("browser_cookie3"):
        return {"available": False}
    try:
        import browser_cookie3
        counts = {}
        loaders = [
            ("Chrome", browser_cookie3.chrome),
            ("Edge", browser_cookie3.edge),
            ("Firefox", browser_cookie3.firefox),
            ("Brave", browser_cookie3.brave),
            ("Opera", browser_cookie3.opera),
        ]
        for name, loader in loaders:
            try:
                jar = loader()
                counts[name] = len(list(jar))
            except Exception:
                counts[name] = None
        return {"available": True, "ok": True, "counts": counts}
    except Exception as e:
        return {"available": True, "ok": False, "error": str(e)}


def run_firepwd(profile_path: Path) -> dict:
    """Esegue firepwd su un profilo Firefox."""
    if not check_tool_installed("firepwd"):
        return {"available": False}
    try:
        r = subprocess.run(
            [sys.executable, "-m", "firepwd", "-d", str(profile_path)],
            capture_output=True, text=True, timeout=30,
        )
        return {
            "available": True,
            "ok": r.returncode == 0,
            "output_preview": r.stdout[:2000],
        }
    except Exception as e:
        return {"available": True, "ok": False, "error": str(e)}
