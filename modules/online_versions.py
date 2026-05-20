"""Live check delle versioni stable correnti dai siti ufficiali.

Sorgenti:
  Chrome:  https://chromiumdash.appspot.com/fetch_releases (API pubblica Google)
  Firefox: https://product-details.mozilla.org/1.0/firefox_versions.json
  Edge:    Endpoint Microsoft + parsing release page
  Brave:   GitHub releases API
  Opera:   Web scraping (best-effort)

Tutti i fetch hanno timeout breve e fallback gracefully a None.
Risultati cached per 24h in tempfile per non chiamare API ripetutamente.
"""
from __future__ import annotations
import datetime
import json
import os
import re
import tempfile
import urllib.request
from pathlib import Path


CACHE_FILE = Path(tempfile.gettempdir()) / "pwd_audit_versions_cache.json"
CACHE_TTL_HOURS = 24
HTTP_TIMEOUT = 10  # seconds


def _http_get(url: str, timeout: int = HTTP_TIMEOUT) -> str | None:
    """GET semplice con user agent."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (pwd-audit-tool/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        ts = data.get("_timestamp")
        if ts:
            cached_at = datetime.datetime.fromisoformat(ts)
            age = datetime.datetime.now() - cached_at
            if age.total_seconds() < CACHE_TTL_HOURS * 3600:
                return data
    except Exception:
        pass
    return {}


def _save_cache(data: dict):
    # Usa una copia per non mutare l'originale (il chiamante itera sul dict)
    to_save = dict(data)
    to_save["_timestamp"] = datetime.datetime.now().isoformat()
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(to_save, f, indent=2)
    except Exception:
        pass


# ============================================================
# CHROME (Google Chromium Dash)
# ============================================================
def fetch_chrome_latest() -> dict | None:
    """Fetch Chrome stable version + release date dall'API chromiumdash."""
    url = ("https://chromiumdash.appspot.com/fetch_releases"
           "?channel=Stable&platform=Windows&num=1")
    raw = _http_get(url)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if data and isinstance(data, list) and len(data) > 0:
            entry = data[0]
            ts_ms = entry.get("time")
            release_date = None
            if ts_ms:
                release_date = datetime.datetime.fromtimestamp(
                    ts_ms / 1000).strftime("%Y-%m-%d")
            return {
                "browser": "Chrome",
                "version": entry.get("version"),
                "major": int(entry.get("milestone", 0)) or None,
                "release_date": release_date,
                "channel": entry.get("channel", "Stable"),
                "source": "chromiumdash.appspot.com",
            }
    except Exception:
        pass
    return None


# ============================================================
# FIREFOX (Mozilla product-details)
# ============================================================
def fetch_firefox_latest() -> dict | None:
    """Fetch Firefox stable da product-details Mozilla."""
    url = "https://product-details.mozilla.org/1.0/firefox_versions.json"
    raw = _http_get(url)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        version = data.get("LATEST_FIREFOX_VERSION")
        major = int(version.split(".")[0]) if version else None
        # Release date
        url2 = "https://product-details.mozilla.org/1.0/firefox.json"
        raw2 = _http_get(url2)
        release_date = None
        if raw2:
            try:
                d2 = json.loads(raw2)
                v_entry = d2.get("releases", {}).get(f"firefox-{version}", {})
                release_date = v_entry.get("date")
            except Exception:
                pass
        return {
            "browser": "Firefox",
            "version": version,
            "major": major,
            "release_date": release_date,
            "channel": "release",
            "source": "product-details.mozilla.org",
        }
    except Exception:
        pass
    return None


# ============================================================
# EDGE (Microsoft enterprise endpoint)
# ============================================================
def fetch_edge_latest() -> dict | None:
    """Fetch Edge stable. Endpoint Microsoft non e' molto stabile,
    usiamo l'API releases di EdgeUpdate o fallback su user-agent string."""
    url = "https://edgeupdates.microsoft.com/api/products?view=enterprise"
    raw = _http_get(url)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        for product in data:
            if product.get("Product") == "Stable":
                # Per ogni release prendiamo la piu' recente Windows x64
                releases = product.get("Releases", [])
                win_releases = [r for r in releases
                                if r.get("Platform") == "Windows"
                                and r.get("Architecture") == "x64"]
                if win_releases:
                    win_releases.sort(
                        key=lambda r: r.get("PublishedTime", ""),
                        reverse=True)
                    latest = win_releases[0]
                    version = latest.get("ProductVersion")
                    major = int(version.split(".")[0]) if version else None
                    pt = latest.get("PublishedTime", "")
                    release_date = pt[:10] if pt else None
                    return {
                        "browser": "Edge",
                        "version": version,
                        "major": major,
                        "release_date": release_date,
                        "channel": "Stable",
                        "source": "edgeupdates.microsoft.com",
                    }
    except Exception:
        pass
    return None


# ============================================================
# BRAVE (GitHub releases)
# ============================================================
def fetch_brave_latest() -> dict | None:
    url = "https://api.github.com/repos/brave/brave-browser/releases/latest"
    raw = _http_get(url)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        tag = data.get("tag_name", "").lstrip("v")
        major = int(tag.split(".")[0]) if tag else None
        return {
            "browser": "Brave",
            "version": tag,
            "major": major,
            "release_date": (data.get("published_at") or "")[:10],
            "channel": "Release",
            "source": "github.com/brave/brave-browser",
        }
    except Exception:
        pass
    return None


# ============================================================
# ORCHESTRATORE
# ============================================================
def fetch_all_latest(use_cache: bool = True, verbose: bool = False) -> dict:
    """Recupera versioni stable di Chrome/Firefox/Edge/Brave.

    Ritorna dict {browser_name: {version, major, release_date, source} or None}.
    """
    if use_cache:
        cached = _load_cache()
        if cached and any(k != "_timestamp" for k in cached):
            if verbose:
                print(f"    [cache] usando cache versioni (eta' < {CACHE_TTL_HOURS}h)")
            return {k: v for k, v in cached.items() if k != "_timestamp"}

    if verbose:
        print(f"    [online] fetch versioni stable da fonti ufficiali...")
    results = {
        "Chrome": fetch_chrome_latest(),
        "Firefox": fetch_firefox_latest(),
        "Edge": fetch_edge_latest(),
        "Brave": fetch_brave_latest(),
    }
    _save_cache(results)
    return results


def compare_with_installed(installed_versions: dict, latest_versions: dict) -> list[dict]:
    """Confronta versioni installate vs ultime stable.

    Ritorna lista di:
      {
        "browser", "installed", "latest", "latest_date", "is_outdated",
        "major_gap": int (quanti major dietro), "risk_level": str
      }
    """
    out = []
    for browser_name, installed in installed_versions.items():
        if not installed:
            continue
        latest_info = latest_versions.get(browser_name)
        entry = {
            "browser": browser_name,
            "installed": installed,
            "latest": None,
            "latest_date": None,
            "is_outdated": None,
            "major_gap": None,
            "risk_level": "UNKNOWN",
        }
        if not latest_info:
            out.append(entry)
            continue
        latest_ver = latest_info.get("version")
        entry["latest"] = latest_ver
        entry["latest_date"] = latest_info.get("release_date")
        try:
            inst_major = int(re.match(r"(\d+)", installed).group(1))
            lat_major = latest_info.get("major") or int(
                re.match(r"(\d+)", latest_ver).group(1))
            entry["major_gap"] = lat_major - inst_major
            entry["is_outdated"] = inst_major < lat_major
            if entry["major_gap"] <= 0:
                entry["risk_level"] = "OK"
            elif entry["major_gap"] == 1:
                entry["risk_level"] = "LOW"
            elif entry["major_gap"] <= 3:
                entry["risk_level"] = "MEDIUM"
            elif entry["major_gap"] <= 10:
                entry["risk_level"] = "HIGH"
            else:
                entry["risk_level"] = "CRITICAL"
        except Exception:
            pass
        out.append(entry)
    return out
