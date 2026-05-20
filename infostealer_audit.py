r"""
infostealer_audit.py - Audit completo della superficie d'attacco infostealer

V2 features:
  - Per-browser tab con tutti gli account decifrati (URL + user + pwd)
  - Risk level per credential (cipher format + criticita' sito)
  - Online version check (Chrome/Firefox/Edge/Brave da fonti ufficiali)
  - Auto-install di tool Python esterni (pypykatz, firepwd, browser_cookie3)
  - Flag --showpassword: rivela password in chiaro + decifra anche legacy
  - Detection target: Discord, Steam, Crypto wallets, SSH, GPG,
    Telegram, FileZilla, Credential Manager, Wi-Fi, IE Vault, Outlook

Uso:
  py infostealer_audit.py                  # default (passwords masked)
  py infostealer_audit.py --showpassword   # mostra password in chiaro
  py infostealer_audit.py --no-online      # skip live version check
  py infostealer_audit.py --no-tools       # skip auto-install Python tools
  py infostealer_audit.py --install-flagged-tools  # opt-in PUA tools (LaZagne)
  py infostealer_audit.py --json out.json  # export
"""
from __future__ import annotations
import argparse
import datetime
import getpass
import html
import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Path setup
sys.path.insert(0, str(Path(__file__).parent))
from modules import browser_versions as bv
from modules import infostealer_targets as targets
from modules import chromium_decrypt as cd
from modules import online_versions as ov
from modules import external_tools as ext
from modules import legacy_decrypt as legacy
from modules import lazagne_light as lzlite

try:
    from modules import firefox_nss
except Exception:
    firefox_nss = None

from modules.i18n import get_strings, detect_system_language  # noqa: E402


# ============================================================
# DIPENDENZE
# ============================================================
def ensure_dependencies():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa
    except ImportError:
        print("[setup] Installo 'cryptography'...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", "cryptography"]
        )


# ============================================================
# CLASSIFICAZIONE RISCHIO CREDENZIALE
# ============================================================
def cipher_risk(format_tag: str) -> tuple[str, str, int]:
    """Per ogni formato, ritorna (label, color, score 0-10).

    Score: piu' alto = piu' facile da rubare (decifrabile in user-mode).
    """
    table = {
        "v10":           ("v10 (AES-GCM + DPAPI user)",   "#c00", 9),
        "v20":           ("v20 (ABE - DECIFRATA!)",        "#c00", 8),
        "v20_protected": ("v20-ABE protected",            "#3a8", 2),
        "pre_v10":       ("pre-v10 (DPAPI direct)",        "#c00", 10),
        "no_key":        ("no master key",                 "#888", 0),
        "empty":         ("empty",                         "#888", 0),
        "unknown":       ("unknown format",                "#888", 5),
    }
    return table.get(format_tag, ("?", "#666", 5))


def url_criticality(url: str) -> tuple[str, str]:
    """Classifica URL in (category, severity)."""
    cat, sev = bv._parse_major, "LOW"  # placeholder
    # Riuso la stessa logica del precedente classify in pwd_audit_compat
    CATEGORIES = [
        ("Banking",    "CRITICAL", ["bnl", "intesasanpaolo", "unicredit", "santander",
            "findomestic", "fineco", "ing.it", "n26", "revolut", "paypal",
            "satispay", "postepay", "bancoposta", "sia.eu"]),
        ("Email",      "CRITICAL", ["gmail", "googlemail", "accounts.google",
            "outlook", "live.com", "microsoftonline", "hotmail", "libero.it",
            "tim.it", "tiscali", "yahoo", "proton", "fastmail", "icloud",
            "appleid", "idmsa.apple"]),
        ("Cloud/Dev",  "CRITICAL", ["aws.amazon", "console.aws", "azure",
            "github", "gitlab", "bitbucket", "digitalocean", "linode", "heroku",
            "vercel", "netlify", "cloudflare", "openai", "auth0", "hivemq",
            "hackthebox"]),
        ("Lavoro",     "CRITICAL", ["e-distribuzione", "arca-enel", "enel.com",
            "sts.enel", "sharepoint", "salesforce", "workday", "slack.com",
            "teams.microsoft"]),
        ("Crypto",     "CRITICAL", ["binance", "coinbase", "kraken", "metamask",
            "blockchain", "trezor", "ledger", "exchange"]),
        ("Gaming",     "HIGH",     ["steampowered", "steamcommunity", "riotgames",
            "epicgames", "battle.net", "blizzard", "signin.ea", "ea.com",
            "ubisoft", "playstation", "sonyentertainment", "xbox", "samsung",
            "g2a", "kinguin", "gog.com", "nexusmods", "square-enix",
            "gearbox", "leagueoflegends"]),
        ("Dev Tools",  "HIGH",     ["digikey", "mouser", "autodesk", "broadcom",
            "jlcpcb", "snapeda", "grabcad", "fritzing", "nxp", "findchips",
            "easyeda", "cadence", "wolfram", "element14"]),
        ("Social",     "HIGH",     ["facebook", "instagram", "twitter", "x.com",
            "linkedin", "tiktok", "discord", "telegram", "whatsapp", "reddit",
            "snapchat"]),
        ("Shopping",   "MEDIUM",   ["amazon", "ebay", "aliexpress", "wish.com",
            "shop.ticketmaster", "ticketmaster", "vinted", "subito", "ikea",
            "zalando", "asos"]),
        ("Streaming",  "MEDIUM",   ["netflix", "spotify", "youtube",
            "disneyplus", "primevideo", "twitch", "deezer", "tidal", "zoom"]),
        ("Hosting",    "MEDIUM",   ["ionos", "one.com", "aruba", "register.it",
            "godaddy", "ovh", "siteground", "bluehost"]),
        ("Router",    "LOW",       ["192.168.", "fritz.box", "tplinkmodem",
            "10.0.0.", "localhost"]),
        ("Forum/Edu", "LOW",       ["forum.", "ucp.php", "ecampus", "cineca",
            "elearning", "unicz", "unical", "unina"]),
    ]
    u = url.lower()
    for c, s, kws in CATEGORIES:
        for k in kws:
            if k in u:
                return c, s
    return "Altro", "LOW"


# ============================================================
# REPORTER HTML
# ============================================================
def sev_color(sev):
    return {"CRITICAL": "#c00", "HIGH": "#e66100",
            "MEDIUM": "#d4a017", "LOW": "#3a8"}.get(sev, "#666")


def risk_lvl_color(rl):
    return {"OK": "#3a8", "LOW": "#d4a017", "MEDIUM": "#e66100",
            "HIGH": "#c00", "CRITICAL": "#900"}.get(rl, "#666")


def mask_password(pwd):
    if not pwd:
        return ""
    if len(pwd) <= 3:
        return "*" * len(pwd)
    return pwd[0] + "*" * (len(pwd) - 2) + pwd[-1]


def render_html(state: dict, out_path: Path):
    """Genera report HTML multilingua con tab.

    state contiene:
      - browsers_installed: dict {name: version}
      - browser_summary: list di vulnerability summary entries
      - latest_versions: dict da fonti online
      - version_comparison: list confronto installed vs latest
      - chromium_accounts: dict {browser: [{profile, credentials, ...}]}
      - target_results: list di target detected
      - external_tools: dict stato tool installati
      - legacy_data: dict legacy creds (cred manager, vault, wifi, ...)
      - fix_recs: list raccomandazioni
      - kb: knowledge base
      - showpassword: bool
      - lang: str (it/en/fr/de/es)
    """
    T = get_strings(state.get("lang", "en"))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    user = getpass.getuser()
    machine = os.environ.get("COMPUTERNAME", "?")
    sp = state["showpassword"]

    # Calcola statistiche
    chromium = state.get("chromium_accounts", {})
    n_creds_total = sum(len(p["credentials"])
                        for plist in chromium.values()
                        for p in plist)
    n_decrypted = sum(1 for plist in chromium.values()
                       for p in plist for c in p["credentials"]
                       if c.get("decryptable"))
    n_protected = n_creds_total - n_decrypted
    n_targets_found = sum(1 for t in state["target_results"] if t.get("found"))

    # Overall risk
    avg_score = (sum(b.get("score", 0) for b in state["browser_summary"])
                 / max(len(state["browser_summary"]), 1))
    n_outdated = sum(1 for v in state.get("version_comparison", [])
                     if v.get("is_outdated"))
    if n_outdated >= 2 or avg_score >= 8 or n_decrypted > 30:
        overall = (T["risk_CRITICAL"], "#c00")
    elif n_outdated >= 1 or avg_score >= 5 or n_decrypted > 10:
        overall = (T["risk_HIGH"], "#e66100")
    elif n_targets_found >= 3 or avg_score >= 3:
        overall = (T["risk_MEDIUM"], "#d4a017")
    else:
        overall = (T["risk_LOW"], "#3a8")

    parts = []
    parts.append(f"""<!doctype html>
<html lang="{T['html_lang']}"><head><meta charset="utf-8">
<title>{T['report_title']} - {now}</title>
<style>
:root {{--c-pri:#36c;--bg:#fafafa;--border:#ddd}}
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1500px;
     margin:1em auto;padding:0 1em;color:#222;background:var(--bg)}}
h1{{border-bottom:3px solid #c00;padding-bottom:.3em;margin-top:0}}
h2{{margin-top:2em;padding:.5em .7em;color:#fff;border-radius:6px;background:#333}}
h3{{margin-top:1.2em;color:#444}}
.banner{{padding:1em 1.2em;border-radius:8px;color:#fff;margin:1em 0;
        font-size:1.1em}}
.stats{{display:flex;flex-wrap:wrap;gap:.5em;margin:1em 0}}
.stat{{padding:.5em .8em;border-radius:6px;background:#fff;
      border:1px solid var(--border);min-width:110px}}
.stat b{{font-size:1.5em;display:block;line-height:1}}
.stat small{{color:#666;font-size:.8em}}
.tabs{{display:flex;flex-wrap:wrap;gap:.2em;border-bottom:2px solid #ccc;
      margin-top:1em}}
.tab{{padding:.6em 1.1em;background:#eee;border:1px solid #ccc;
     border-bottom:none;border-radius:6px 6px 0 0;cursor:pointer;
     font-weight:600;user-select:none}}
.tab.active{{background:#fff;border-bottom:2px solid #fff;
            margin-bottom:-2px;color:var(--c-pri)}}
.tab-panel{{display:none;background:#fff;border:1px solid #ccc;
           border-top:none;padding:1em;border-radius:0 6px 6px 6px}}
.tab-panel.active{{display:block}}
.tag{{display:inline-block;padding:.13em .5em;border-radius:3px;
     color:#fff;font-size:.78em;font-weight:600}}
table{{width:100%;border-collapse:collapse;margin:1em 0;background:#fff;
      font-size:.88em}}
th{{background:#eee;padding:.45em;text-align:left;border-bottom:2px solid #ccc}}
td{{padding:.4em .45em;border-bottom:1px solid #eee;vertical-align:top}}
.url{{font-family:Consolas,monospace;font-size:.83em;color:#0066cc;
     max-width:340px;overflow:hidden;text-overflow:ellipsis;
     white-space:nowrap;display:inline-block}}
.user{{font-family:Consolas,monospace;font-size:.83em}}
.pwd{{font-family:Consolas,monospace;font-size:.83em;background:#f4f4f4;
     padding:.13em .4em;border-radius:3px;display:inline-block}}
.box{{padding:.7em 1em;border-radius:6px;margin:.6em 0}}
.box.warn{{background:#fff3d6;border-left:4px solid #d4a017}}
.box.bad{{background:#fde6e6;border-left:4px solid #c00}}
.box.ok{{background:#e6f7e6;border-left:4px solid #2a8}}
.box.info{{background:#eef3fa;border-left:4px solid #36c}}
.bypass-card{{background:#fff;border:1px solid #ddd;border-radius:6px;
             padding:.5em .8em;margin:.3em 0}}
.bypass-card .name{{font-weight:600}}
.bypass-card .meta{{color:#666;font-size:.83em;margin-top:.2em}}
.fix-rec{{background:#fff;border-left:4px solid #36c;padding:.5em 1em;
        margin:.4em 0;border-radius:4px}}
.fix-rec.priority-CRITICAL{{border-left-color:#c00}}
.fix-rec.priority-HIGH{{border-left-color:#e66100}}
.fix-rec.priority-MEDIUM{{border-left-color:#d4a017}}
details{{margin:.4em 0}}
summary{{cursor:pointer;font-weight:600}}
.tl-item{{border-left:3px solid #ccc;padding:.4em .7em;margin:.3em 0;
        background:#fff}}
.tl-item.current{{border-left-color:#36c;background:#eef3fa}}
.tl-item.vulnerable{{border-left-color:#c00}}
.target-row.found{{background:#fff3d6}}
.target-row.notfound{{color:#999;background:#fafafa}}
.version-row.outdated{{background:#fde6e6}}
.version-row.uptodate{{background:#e6f7e6}}
.tool-card{{background:#fff;border:1px solid #ddd;border-radius:6px;
           padding:.7em 1em;margin:.4em 0}}
.tool-card.installed{{border-left:4px solid #3a8}}
.tool-card.notinstalled{{border-left:4px solid #d4a017}}
.tool-card.flagged{{border-left:4px solid #c00}}
.code{{font-family:Consolas,monospace;background:#f4f4f4;padding:.1em .3em;
      border-radius:3px;font-size:.85em}}
</style>
<script>
function showTab(name){{
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelector(`.tab[data-tab="${{name}}"]`).classList.add('active');
  document.querySelector(`.tab-panel[data-tab="${{name}}"]`).classList.add('active');
  history.replaceState(null,'',`#${{name}}`);
}}
window.addEventListener('load',()=>{{
  const h = location.hash.slice(1);
  if(h && document.querySelector(`.tab[data-tab="${{h}}"]`)){{showTab(h);}}
}});
</script>
</head><body>
<h1>{T['report_title']}</h1>
<p style="color:#666">{T['generated_at']}: {now} &mdash; {T['user_label']}: {html.escape(user)} &mdash; {T['machine_label']}: {html.escape(machine)} &mdash; {'<strong style="color:#c00">' + T["showpassword_mode"] + '</strong>' if sp else T["passwords_masked"]}</p>

<div class="banner" style="background:{overall[1]}">
<strong>{T['overall_risk_prefix']}: {overall[0]}</strong>
</div>

<div class="stats">
<div class="stat"><b>{len(state['browsers_installed'])}</b><small>{T['stat_browsers']}</small></div>
<div class="stat" style="border-left:4px solid #c00"><b>{n_decrypted}</b><small>{T['stat_decrypted']}</small></div>
<div class="stat" style="border-left:4px solid #3a8"><b>{n_protected}</b><small>{T['stat_protected']}</small></div>
<div class="stat" style="border-left:4px solid #e66100"><b>{n_outdated}</b><small>{T['stat_outdated']}</small></div>
<div class="stat" style="border-left:4px solid #c00"><b>{n_targets_found}</b><small>{T['stat_targets']}</small></div>
<div class="stat"><b>{sum(1 for v in state['external_tools'].values() if v['installed'])}/{len(state['external_tools'])}</b><small>{T['stat_tools']}</small></div>
<div class="stat" style="border-left:4px solid #963"><b>{state.get('lazagne_summary',{}).get('total_credentials_found',0)}</b><small>{T['stat_lazagne']}</small></div>
</div>

<div class="tabs">
<div class="tab active" data-tab="overview" onclick="showTab('overview')">{T['tab_overview']}</div>
<div class="tab" data-tab="accounts" onclick="showTab('accounts')">{T['tab_accounts']}</div>
<div class="tab" data-tab="versions" onclick="showTab('versions')">{T['tab_versions']}</div>
<div class="tab" data-tab="targets" onclick="showTab('targets')">{T['tab_targets']}</div>
<div class="tab" data-tab="lazagne" onclick="showTab('lazagne')">{T['tab_lazagne']}</div>
<div class="tab" data-tab="legacy" onclick="showTab('legacy')">{T['tab_legacy']}</div>
<div class="tab" data-tab="tools" onclick="showTab('tools')">{T['tab_tools']}</div>
<div class="tab" data-tab="fixes" onclick="showTab('fixes')">{T['tab_fixes']}</div>
<div class="tab" data-tab="timeline" onclick="showTab('timeline')">{T['tab_timeline']}</div>
</div>

<!-- ============== TAB: OVERVIEW ============== -->
<div class="tab-panel active" data-tab="overview">
<h2 style="background:#36c">{T['section_overview']}</h2>
<div class="box info">
{T['overview_info_box']}
</div>
<h3>{T['stat_browsers']}</h3>
<table><thead><tr><th>{T['col_browser']}</th><th>{T['col_installed_version']}</th><th>{T['col_current_stable']}</th><th>{T['col_diff']}</th><th>{T['col_risk']}</th></tr></thead><tbody>
""")

    # Versions overview table
    for v in state["version_comparison"]:
        klass = "version-row outdated" if v.get("is_outdated") else "version-row uptodate"
        gap = v.get("major_gap")
        gap_str = f"+{gap} major" if gap and gap > 0 else T["up_to_date"] if gap == 0 else "—"
        rl = v.get("risk_level", "UNKNOWN")
        parts.append(f'<tr class="{klass}">')
        parts.append(f'<td><strong>{html.escape(v["browser"])}</strong></td>')
        parts.append(f'<td>{html.escape(str(v["installed"] or "—"))}</td>')
        parts.append(f'<td>{html.escape(str(v["latest"] or "—"))} '
                     f'<small style="color:#666">({html.escape(str(v.get("latest_date") or "?"))})</small></td>')
        parts.append(f'<td>{gap_str}</td>')
        parts.append(f'<td><span class="tag" style="background:{risk_lvl_color(rl)}">{rl}</span></td>')
        parts.append('</tr>')

    parts.append('</tbody></table>')
    parts.append('</div>')  # /overview

    # ============== TAB: ACCOUNTS ==============
    parts.append('<div class="tab-panel" data-tab="accounts">')
    parts.append(f'<h2 style="background:#c00">{T["section_accounts"]}</h2>')
    if sp:
        parts.append(f'<div class="box bad"><strong>{T["showpassword_warning"]}</strong></div>')
    else:
        parts.append(f'<div class="box info">{T["masked_info"]}</div>')

    for browser_name, profiles_list in chromium.items():
        total = sum(len(p["credentials"]) for p in profiles_list)
        decrypted = sum(1 for p in profiles_list for c in p["credentials"]
                        if c.get("decryptable"))
        protected = sum(1 for p in profiles_list for c in p["credentials"]
                        if c.get("format") == "v20_protected")

        parts.append(f'<h3>{html.escape(browser_name)} '
                     f'<small style="color:#666">— {total} {T["credentials_word"]}, '
                     f'{decrypted} {T["decrypted_word"]}, {protected} {T["protected_word"]}</small></h3>')

        for profile_info in profiles_list:
            pname = profile_info["profile"]
            creds = profile_info["credentials"]
            if not creds:
                continue
            parts.append(f'<details><summary>{T["profile_label"]}: <strong>{html.escape(pname)}</strong> '
                         f'({len(creds)} {T["credentials_word"]})</summary>')
            parts.append(f'<table><thead><tr>'
                         f'<th>{T["col_url"]}</th><th>{T["col_username"]}</th><th>{T["col_password"]}</th>'
                         f'<th>{T["col_cipher"]}</th><th>{T["col_category"]}</th><th>{T["col_risk"]}</th>'
                         f'</tr></thead><tbody>')
            # Sort: decryptable + critical first
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            def _sort_key(c):
                cat, sev = url_criticality(c["url"])
                return (0 if c.get("decryptable") else 1,
                        sev_order.get(sev, 99),
                        c["url"])
            sorted_creds = sorted(creds, key=_sort_key)
            for c in sorted_creds:
                cat, sev = url_criticality(c["url"])
                fmt = c.get("format", "?")
                cipher_label, cipher_col, cipher_score = cipher_risk(fmt)
                pwd_show = "—"
                if c.get("password"):
                    if sp:
                        pwd_show = html.escape(c["password"])
                    else:
                        pwd_show = html.escape(mask_password(c["password"]))
                elif c.get("format") == "v20_protected":
                    pwd_show = T["v20_protected_tag"]
                parts.append('<tr>')
                parts.append(f'<td><a class="url" href="{html.escape(c["url"])}" '
                             f'title="{html.escape(c["url"])}">{html.escape(c["url"][:80])}</a></td>')
                parts.append(f'<td class="user">{html.escape(c.get("username") or "—")}</td>')
                parts.append(f'<td class="pwd">{pwd_show}</td>')
                parts.append(f'<td><span class="tag" style="background:{cipher_col}">{cipher_label}</span></td>')
                parts.append(f'<td>{cat}</td>')
                parts.append(f'<td><span class="tag" style="background:{sev_color(sev)}">{sev}</span></td>')
                parts.append('</tr>')
            parts.append('</tbody></table></details>')

    # Firefox accounts
    if state.get("firefox_accounts"):
        parts.append('<h3>Firefox</h3>')
        for profile, creds in state["firefox_accounts"].items():
            if not creds:
                continue
            parts.append(f'<details><summary>{T["profile_label"]} Firefox: <strong>{html.escape(profile)}</strong> '
                         f'({len(creds)} {T["credentials_word"]})</summary>')
            parts.append(f'<table><thead><tr><th>{T["col_url"]}</th><th>{T["col_username"]}</th><th>{T["col_password"]}</th>'
                         f'<th>{T["col_cipher"]}</th><th>{T["col_category"]}</th><th>{T["col_risk"]}</th></tr></thead><tbody>')
            for c in creds:
                cat, sev = url_criticality(c["url"])
                pwd_show = (html.escape(c["password"]) if sp
                            else html.escape(mask_password(c["password"])))
                parts.append(f'<tr><td><span class="url">{html.escape(c["url"][:80])}</span></td>'
                             f'<td class="user">{html.escape(c.get("username") or "—")}</td>'
                             f'<td class="pwd">{pwd_show}</td>'
                             f'<td><span class="tag" style="background:#c00">NSS PBKDF2+AES-256</span></td>'
                             f'<td>{cat}</td>'
                             f'<td><span class="tag" style="background:{sev_color(sev)}">{sev}</span></td></tr>')
            parts.append('</tbody></table></details>')

    parts.append('</div>')  # /accounts

    # ============== TAB: VERSIONS & CVE ==============
    parts.append('<div class="tab-panel" data-tab="versions">')
    parts.append(f'<h2 style="background:#36c">{T["section_versions"]}</h2>')
    parts.append(f'<table><thead><tr><th>{T["col_browser"]}</th><th>{T["col_installed_version"]}</th><th>{T["col_current_stable"]}</th>'
                 f'<th>{T["col_released"]}</th><th>{T["col_major_gap"]}</th><th>{T["col_risk"]}</th><th>{T["col_source"]}</th>'
                 f'</tr></thead><tbody>')
    for v in state["version_comparison"]:
        klass = "outdated" if v.get("is_outdated") else "uptodate"
        rl = v.get("risk_level", "UNKNOWN")
        latest_info = state["latest_versions"].get(v["browser"], {}) or {}
        src = latest_info.get("source", "—") if latest_info else "—"
        parts.append(f'<tr class="version-row {klass}">')
        parts.append(f'<td><strong>{html.escape(v["browser"])}</strong></td>')
        parts.append(f'<td>{html.escape(str(v["installed"] or "—"))}</td>')
        parts.append(f'<td>{html.escape(str(v["latest"] or "—"))}</td>')
        parts.append(f'<td>{html.escape(str(v.get("latest_date") or "—"))}</td>')
        gap = v.get("major_gap")
        parts.append(f'<td>{"+" + str(gap) if gap and gap > 0 else "—"}</td>')
        parts.append(f'<td><span class="tag" style="background:{risk_lvl_color(rl)}">{rl}</span></td>')
        parts.append(f'<td><small>{html.escape(str(src))}</small></td>')
        parts.append('</tr>')
    parts.append('</tbody></table>')

    parts.append(f'<h3>{T["vuln_known_header"]}</h3>')
    for b in state["browser_summary"]:
        parts.append(f'<h4>{html.escape(b["browser"])} v{html.escape(str(b["version"]))}</h4>')
        parts.append('<div class="stats">')
        diff = b.get("decrypt_difficulty", "?")
        parts.append(f'<div class="stat" style="border-left:4px solid {sev_color("CRITICAL" if diff in ("TRIVIAL","LOW") else "HIGH" if diff=="MEDIUM" else "LOW")}">'
                     f'<b>{diff}</b><small>{T["decrypt_diff_label"]}</small></div>')
        parts.append(f'<div class="stat"><b>{b.get("score", 0)}/10</b><small>{T["risk_score_label"]}</small></div>')
        parts.append('</div>')
        if b.get("description"):
            parts.append(f'<p>{html.escape(b["description"])}</p>')
        if b.get("bypass_details"):
            parts.append(f'<details><summary>{T["bypass_section_label"]}</summary>')
            for tech in b["bypass_details"]:
                used_by = ", ".join(tech.get("used_by", []) or ["—"])
                parts.append(f'<div class="bypass-card">')
                parts.append(f'<div class="name">{html.escape(tech["name"])} '
                             f'<span class="tag" style="background:{sev_color("CRITICAL" if tech.get("complexity")=="TRIVIAL" else "HIGH" if tech.get("complexity")=="LOW" else "MEDIUM")}">'
                             f'{tech.get("complexity","?")}</span></div>')
                parts.append(f'<div class="meta">{html.escape(tech.get("description",""))}</div>')
                parts.append(f'<div class="meta"><strong>{T["used_by_label"]}</strong> {html.escape(used_by)}</div>')
                if tech.get("ref"):
                    parts.append(f'<div class="meta"><a href="{html.escape(tech["ref"])}">{T["ref_label"]}</a></div>')
                parts.append('</div>')
            parts.append('</details>')
        if b.get("fix_label"):
            parts.append(f'<div class="box warn"><strong>{T["fix_prefix"]}</strong> '
                         f'{html.escape(str(b.get("fix_label") or "—"))} '
                         f'(v{html.escape(str(b.get("fix_version") or "?"))} — '
                         f'{T["released_label"]} {html.escape(str(b.get("fix_date") or "?"))})</div>')
    parts.append('</div>')  # /versions

    # ============== TAB: TARGETS ==============
    parts.append('<div class="tab-panel" data-tab="targets">')
    parts.append(f'<h2 style="background:#c00">{T["section_targets"]}</h2>')
    parts.append(f'<p>{T["targets_intro"]}</p>')
    parts.append(f'<table><thead><tr><th>{T["col_target"]}</th><th>{T["col_status"]}</th><th>{T["col_value"]}</th><th>{T["col_details"]}</th></tr></thead><tbody>')
    for t in state["target_results"]:
        klass = "target-row found" if t.get("found") else "target-row notfound"
        status = T["status_present"] if t.get("found") else "—"
        details = "<br>".join(html.escape(d) for d in t.get("details", [])) or "&nbsp;"
        parts.append(f'<tr class="{klass}"><td><strong>{html.escape(t["target"])}</strong>'
                     f'<br><small style="color:#666">{html.escape(t.get("description",""))}</small></td>'
                     f'<td><strong>{status}</strong></td>'
                     f'<td><span class="tag" style="background:{sev_color(t.get("value","LOW"))}">'
                     f'{t.get("value","?")}</span></td>'
                     f'<td>{details}</td></tr>')
    parts.append('</tbody></table></div>')

    # ============== TAB: LAZAGNE LIGHT ==============
    parts.append('<div class="tab-panel" data-tab="lazagne">')
    parts.append(f'<h2 style="background:#963">{T["section_lazagne"]}</h2>')
    parts.append(f'<p>{T["lazagne_intro"]}</p>')

    lz = state.get("lazagne_light", {})
    sp = state["showpassword"]

    # Wi-Fi
    wifi = lz.get("wifi", [])
    # Detect "service not running" sentinel
    if wifi and wifi[0].get("_status") == "wireless_service_not_running":
        parts.append(f'<h3>{T["wifi_header"]} {T["wifi_na"]}</h3>')
        parts.append(f'<div class="box info">{html.escape(wifi[0].get("_note",""))}</div>')
        wifi = []
    else:
        parts.append(f'<h3>{T["wifi_header"]} ({len(wifi)})</h3>')
    if wifi:
        with_key = sum(1 for w in wifi if w.get("key"))
        parts.append(f'<p><strong>{with_key}</strong> {T["wifi_key_msg"]}</p>')
        parts.append(f'<table><thead><tr><th>{T["col_ssid"]}</th><th>{T["col_auth"]}</th><th>{T["col_cipher"]}</th>'
                     f'<th>{T["col_key_cleartext"]}</th></tr></thead><tbody>')
        for w in wifi:
            key_show = "—"
            if w.get("key"):
                k = w["key"]
                key_show = (f'<span class="pwd">{html.escape(k)}</span>' if sp
                            else f'<span class="pwd">{html.escape(mask_password(k))}</span>')
            parts.append(f'<tr><td>{html.escape(w.get("ssid",""))}</td>'
                         f'<td>{html.escape(str(w.get("auth") or "—"))}</td>'
                         f'<td>{html.escape(str(w.get("cipher") or "—"))}</td>'
                         f'<td>{key_show}</td></tr>')
        parts.append('</tbody></table>')

    # PuTTY
    putty = lz.get("putty", [])
    parts.append(f'<h3>{T["putty_header"]} ({len(putty)})</h3>')
    if putty:
        parts.append(f'<div class="box info">{T["putty_note"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_session"]}</th><th>{T["col_host"]}</th>'
                     f'<th>{T["col_port"]}</th><th>{T["col_user"]}</th><th>{T["col_protocol"]}</th></tr></thead><tbody>')
        for p in putty:
            parts.append(f'<tr><td>{html.escape(p.get("session",""))}</td>'
                         f'<td class="user">{html.escape(str(p.get("HostName") or "—"))}</td>'
                         f'<td>{html.escape(str(p.get("PortNumber") or "—"))}</td>'
                         f'<td>{html.escape(str(p.get("UserName") or "—"))}</td>'
                         f'<td>{html.escape(str(p.get("Protocol") or "—"))}</td></tr>')
        parts.append('</tbody></table>')

    # WinSCP
    winscp = lz.get("winscp", [])
    parts.append(f'<h3>{T["winscp_header"]} ({len(winscp)})</h3>')
    if winscp:
        dec = sum(1 for w in winscp if w.get("decrypted_password"))
        parts.append(f'<div class="box bad">{T["winscp_warning"]} '
                     f'<strong>{dec}/{len(winscp)}</strong> {T["winscp_decrypted_msg"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_session"]}</th><th>{T["col_host"]}</th>'
                     f'<th>{T["col_user"]}</th><th>{T["col_password"]}</th><th>{T["col_protocol"]}</th></tr></thead><tbody>')
        for w in winscp:
            pwd = w.get("decrypted_password")
            pwd_show = "—"
            if pwd:
                pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp
                            else f'<span class="pwd">{html.escape(mask_password(pwd))}</span>')
            elif w.get("password_present"):
                pwd_show = '<small>encrypted (no host/user info)</small>'
            parts.append(f'<tr><td>{html.escape(w.get("session",""))}</td>'
                         f'<td class="user">{html.escape(str(w.get("HostName") or "—"))}</td>'
                         f'<td>{html.escape(str(w.get("UserName") or "—"))}</td>'
                         f'<td>{pwd_show}</td>'
                         f'<td>{html.escape(str(w.get("FSProtocol") or "—"))}</td></tr>')
        parts.append('</tbody></table>')

    # Git credentials
    git = lz.get("git_credentials", [])
    parts.append(f'<h3>{T["git_header"]} ({len(git)})</h3>')
    if git:
        parts.append(f'<div class="box bad">{T["git_warning"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_url"]}</th><th>{T["col_user"]}</th><th>{T["col_password"]}</th>'
                     f'</tr></thead><tbody>')
        for g in git:
            pwd_show = (f'<span class="pwd">{html.escape(g.get("password",""))}</span>'
                        if sp else
                        f'<span class="pwd">{html.escape(mask_password(g.get("password","")))}</span>')
            parts.append(f'<tr><td class="url">{html.escape(g.get("url",""))}</td>'
                         f'<td class="user">{html.escape(g.get("username",""))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # OpenVPN
    ovpn = lz.get("openvpn", [])
    parts.append(f'<h3>{T["openvpn_header"]} ({len(ovpn)})</h3>')
    if ovpn:
        parts.append(f'<table><thead><tr><th>{T["col_config"]}</th><th>{T["col_auth_file"]}</th>'
                     f'<th>{T["col_username"]}</th><th>{T["col_password"]}</th></tr></thead><tbody>')
        for o in ovpn:
            pwd = o.get("password")
            pwd_show = "—"
            if pwd:
                pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp
                            else f'<span class="pwd">{html.escape(mask_password(pwd))}</span>')
            parts.append(f'<tr><td class="code">{html.escape(o.get("config",""))}</td>'
                         f'<td class="code">{html.escape(str(o.get("auth_file") or "—"))}</td>'
                         f'<td>{html.escape(str(o.get("username") or "—"))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # FileZilla
    fz = lz.get("filezilla", [])
    parts.append(f'<h3>{T["filezilla_header"]} ({len(fz)})</h3>')
    if fz:
        parts.append(f'<div class="box warn">{T["filezilla_warning"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_host"]}</th><th>{T["col_port"]}</th><th>{T["col_user"]}</th>'
                     f'<th>{T["col_password"]}</th></tr></thead><tbody>')
        for f in fz:
            pwd = f.get("password")
            pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp and pwd
                        else f'<span class="pwd">{html.escape(mask_password(pwd))}</span>' if pwd
                        else "—")
            parts.append(f'<tr><td class="user">{html.escape(str(f.get("host") or "—"))}</td>'
                         f'<td>{html.escape(str(f.get("port") or "—"))}</td>'
                         f'<td>{html.escape(str(f.get("user") or "—"))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # Thunderbird
    tb = lz.get("thunderbird", [])
    parts.append(f'<h3>{T["thunderbird_header"]} ({len(tb)})</h3>')
    if tb:
        parts.append(f'<div class="box warn">{T["thunderbird_warning"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_profile"]}</th><th>{T["col_host"]}</th><th>{T["col_user"]}</th>'
                     f'<th>{T["col_password"]}</th></tr></thead><tbody>')
        for t in tb:
            pwd = t.get("password")
            pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp and pwd
                        else f'<span class="pwd">{html.escape(mask_password(pwd or ""))}</span>')
            parts.append(f'<tr><td>{html.escape(t.get("profile",""))}</td>'
                         f'<td class="user">{html.escape(str(t.get("host") or "—"))}</td>'
                         f'<td>{html.escape(str(t.get("user") or "—"))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # Pidgin
    pidgin = lz.get("pidgin", [])
    parts.append(f'<h3>{T["pidgin_header"]} ({len(pidgin)})</h3>')
    if pidgin:
        parts.append(f'<div class="box bad">{T["pidgin_warning"]}</div>')
        parts.append(f'<table><thead><tr><th>{T["col_protocol"]}</th><th>{T["col_app_name"]}</th><th>{T["col_password"]}</th></tr></thead><tbody>')
        for p in pidgin:
            pwd = p.get("password")
            pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp and pwd
                        else f'<span class="pwd">{html.escape(mask_password(pwd or ""))}</span>')
            parts.append(f'<tr><td>{html.escape(p.get("protocol",""))}</td>'
                         f'<td>{html.escape(p.get("name",""))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # DBVisualizer
    dbv = lz.get("dbvisualizer", [])
    if dbv:
        parts.append(f'<h3>{T["dbviz_header"]} ({len(dbv)})</h3>')
        parts.append(f'<table><thead><tr><th>{T["col_alias"]}</th><th>{T["col_db_url"]}</th><th>{T["col_user"]}</th>'
                     f'<th>{T["col_password"]}</th></tr></thead><tbody>')
        for d in dbv:
            pwd = d.get("password")
            pwd_show = (f'<span class="pwd">{html.escape(pwd)}</span>' if sp and pwd
                        else f'<span class="pwd">{html.escape(mask_password(pwd or ""))}</span>' if pwd else "—")
            parts.append(f'<tr><td>{html.escape(str(d.get("alias") or "—"))}</td>'
                         f'<td class="url">{html.escape(str(d.get("url") or "—"))}</td>'
                         f'<td>{html.escape(str(d.get("userid") or "—"))}</td>'
                         f'<td>{pwd_show}</td></tr>')
        parts.append('</tbody></table>')

    # RDP files
    rdp = lz.get("rdp_files", [])
    if rdp:
        parts.append(f'<h3>{T["rdp_header"]} ({len(rdp)})</h3>')
        parts.append(f'<table><thead><tr><th>{T["col_file"]}</th><th>{T["col_host"]}</th><th>{T["col_user"]}</th>'
                     f'<th>{T["col_pwd_encrypted"]}</th></tr></thead><tbody>')
        for r in rdp:
            parts.append(f'<tr><td class="code">{html.escape(r.get("file",""))}</td>'
                         f'<td class="user">{html.escape(str(r.get("host") or "—"))}</td>'
                         f'<td>{html.escape(str(r.get("username") or "—"))}</td>'
                         f'<td>{T["yes_str"] if r.get("has_encrypted_password") else T["no_str"]}</td></tr>')
        parts.append('</tbody></table>')

    # Cisco AnyConnect
    cisco = lz.get("cisco_anyconnect", [])
    if cisco:
        parts.append(f'<h3>{T["cisco_anyconnect_header"]} ({len(cisco)})</h3>')
        parts.append('<ul>')
        for c in cisco[:20]:
            parts.append(f'<li><strong>{html.escape(c.get("profile",""))}</strong> &rarr; '
                         f'<span class="code">{html.escape(c.get("host",""))}</span></li>')
        parts.append('</ul>')

    # Chat tokens (presenza)
    chat = lz.get("chat_tokens", {})
    if chat:
        parts.append(f'<h3>{T["chat_header"]}</h3>')
        parts.append(f'<table><thead><tr><th>{T["col_app_name"]}</th><th>{T["col_status"]}</th><th>{T["col_path"]}</th></tr></thead><tbody>')
        for name, v in chat.items():
            status = T["status_present"] if v.get("present") else "—"
            klass = "found" if v.get("present") else "notfound"
            parts.append(f'<tr class="target-row {klass}"><td>{html.escape(name)}</td>'
                         f'<td>{status}</td>'
                         f'<td class="code">{html.escape(v.get("path",""))}</td></tr>')
        parts.append('</tbody></table>')

    parts.append('</div>')  # /lazagne

    # ============== TAB: LEGACY ==============
    parts.append('<div class="tab-panel" data-tab="legacy">')
    parts.append(f'<h2 style="background:#666">{T["section_legacy"]}</h2>')
    legacy_data = state.get("legacy_data", {})
    # Credential Manager
    cm = legacy_data.get("credential_manager", [])
    parts.append(f'<h3>{T["credman_header"]} — {len(cm)} {T["entries_word"]}</h3>')
    if cm:
        parts.append(f'<table><thead><tr><th>{T["col_target"]}</th><th>{T["col_type"]}</th><th>{T["col_user"]}</th><th>{T["col_persistence"]}</th></tr></thead><tbody>')
        for c in cm[:200]:
            parts.append(f'<tr><td class="code">{html.escape(c.get("target","—"))}</td>'
                         f'<td>{html.escape(c.get("type","—"))}</td>'
                         f'<td>{html.escape(c.get("user","—"))}</td>'
                         f'<td>{html.escape(c.get("persistence","—"))}</td></tr>')
        parts.append('</tbody></table>')
    # IE Vault
    vault = legacy_data.get("ie_legacy_vault", {})
    if vault.get("present"):
        parts.append(f'<h3>{T["vault_header"]} — {vault["count"]} files</h3>')
        parts.append(f'<div class="box warn">{html.escape(vault.get("note",""))}</div>')
    # Wi-Fi
    wifi = legacy_data.get("wifi_profiles", [])
    parts.append(f'<h3>{T["wifi_saved_header"]} — {len(wifi)}</h3>')
    if wifi:
        parts.append(f'<table><thead><tr><th>{T["col_ssid"]}</th><th>{T["col_auth"]}</th><th>{T["col_key_cleartext"]}</th></tr></thead><tbody>')
        for w in wifi[:50]:
            key_show = "—"
            if w.get("key"):
                if sp:
                    key_show = f'<span class="pwd">{html.escape(w["key"])}</span>'
                else:
                    key_show = f'<span class="pwd">{html.escape(mask_password(w["key"]))}</span>'
            parts.append(f'<tr><td>{html.escape(w.get("name",""))}</td>'
                         f'<td>{html.escape(str(w.get("auth") or "—"))}</td>'
                         f'<td>{key_show}</td></tr>')
        parts.append('</tbody></table>')
    # Outlook
    outlook = legacy_data.get("outlook_profiles", {})
    if outlook.get("present"):
        parts.append(f'<h3>{T["outlook_header"]} — {outlook["count"]}</h3>')
        for p in outlook.get("profiles", [])[:10]:
            parts.append(f'<div class="code">{html.escape(p["hive"])}\\{html.escape(p["path"])}</div>')
    parts.append('</div>')  # /legacy

    # ============== TAB: TOOLS ==============
    parts.append('<div class="tab-panel" data-tab="tools">')
    parts.append(f'<h2 style="background:#3a8">{T["section_tools"]}</h2>')
    parts.append(f'<p>{T["tools_intro"]}</p>')
    for tname, tstate in state["external_tools"].items():
        klass = "tool-card "
        if tstate["installed"]:
            klass += "installed"
        elif tstate["defender_flagged"]:
            klass += "flagged"
        else:
            klass += "notinstalled"
        status = T["status_installed"] if tstate["installed"] else T["status_missing"]
        extra = ""
        if tstate["newly_installed"]:
            extra = f' <span class="tag" style="background:#3a8">{T["tag_new"]}</span>'
        elif tstate["upgraded"]:
            extra = f' <span class="tag" style="background:#36c">{T["tag_upgraded"]}</span>'
        if tstate["defender_flagged"]:
            extra += f' <span class="tag" style="background:#c00">{T["tag_pua"]}</span>'
        parts.append(f'<div class="{klass}">')
        parts.append(f'<strong>{html.escape(tname)}</strong> — {status}{extra}<br>')
        parts.append(f'<small>{html.escape(tstate["description"])}</small><br>')
        parts.append(f'<small><a href="{html.escape(tstate["github"])}">{html.escape(tstate["github"])}</a></small>')
        if tstate.get("use_cases"):
            parts.append('<ul style="margin:.3em 0">')
            for u in tstate["use_cases"]:
                parts.append(f'<li><small>{html.escape(u)}</small></li>')
            parts.append('</ul>')
        parts.append('</div>')
    parts.append('</div>')  # /tools

    # ============== TAB: FIXES ==============
    parts.append('<div class="tab-panel" data-tab="fixes">')
    parts.append(f'<h2 style="background:#3a8">{T["section_fixes"]}</h2>')
    prio_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_recs = sorted(state["fix_recs"],
                          key=lambda r: prio_order.get(r.get("priority", "LOW"), 99))
    for r in sorted_recs:
        parts.append(f'<div class="fix-rec priority-{r["priority"]}">')
        parts.append(f'<strong><span class="tag" style="background:{sev_color(r["priority"])}">'
                     f'{r["priority"]}</span> {html.escape(r["action"])}</strong> '
                     f'<small style="color:#666">({html.escape(r["browser"])})</small><br>')
        parts.append(f'<div style="margin-top:.3em"><strong>{T["why_label"]}</strong> {html.escape(r["reason"])}</div>')
        parts.append(f'<div><strong>{T["how_label"]}</strong> {html.escape(r["how"])}</div>')
        parts.append('</div>')
    parts.append('</div>')  # /fixes

    # ============== TAB: TIMELINE ==============
    parts.append('<div class="tab-panel" data-tab="timeline">')
    parts.append(f'<h2 style="background:#666">{T["section_timeline"]}</h2>')
    kb = state["kb"]
    user_major = None
    for b in state["browser_summary"]:
        if b["browser"] == "Chrome" and b.get("major"):
            user_major = b["major"]
            break
    for entry in kb.get("chromium_abe_timeline", []):
        klass = "tl-item"
        if user_major is not None and bv._version_in_range(
                f"{user_major}.0", entry["version_range"]):
            klass += " current"
        if entry.get("decrypt_difficulty") in ("TRIVIAL", "LOW", "MEDIUM"):
            klass += " vulnerable"
        parts.append(f'<div class="{klass}">')
        parts.append(f'<strong>{html.escape(entry["version_range"])}</strong> — '
                     f'{html.escape(entry["label"])} '
                     f'<span class="tag" style="background:{sev_color("CRITICAL" if entry.get("decrypt_difficulty")=="TRIVIAL" else "HIGH" if entry.get("decrypt_difficulty") in ("LOW","MEDIUM") else "LOW")}">'
                     f'{entry.get("decrypt_difficulty","?")}</span>')
        if entry.get("released_date"):
            parts.append(f' <small style="color:#666">[{html.escape(entry["released_date"])}]</small>')
        parts.append(f'<p style="margin:.3em 0">{html.escape(entry.get("description",""))}</p>')
        fix = entry.get("fix", {})
        if fix.get("fixed_in"):
            parts.append(f'<small><strong>{T["tl_fix_label"]}</strong> Chrome {html.escape(str(fix["fixed_in"]))} '
                         f'({html.escape(str(fix.get("fixed_date","?")))}) — '
                         f'{html.escape(str(fix.get("milestone","")))}</small>')
        parts.append('</div>')
    parts.append('</div>')  # /timeline

    parts.append('</body></html>')
    out_path.write_text("".join(parts), encoding="utf-8")


# ============================================================
# MAIN
# ============================================================
def main():
    ap = argparse.ArgumentParser(
        description="Audit completo superficie infostealer (v2).")
    ap.add_argument("--showpassword", action="store_true",
                    help="Mostra le password in chiaro nel report HTML.")
    ap.add_argument("--no-online", action="store_true",
                    help="Skip live version check (offline mode).")
    ap.add_argument("--no-tools", action="store_true",
                    help="Skip auto-install dei tool Python esterni.")
    ap.add_argument("--install-flagged-tools", action="store_true",
                    help="Opt-in esplicito per tool PUA-flagged "
                         "(LaZagne). Defender potrebbe metterli in quarantena.")
    ap.add_argument("--force-tool-update", action="store_true",
                    help="Forza pip upgrade dei tool installati anche se "
                         "controllato di recente.")
    ap.add_argument("--no-html", action="store_true",
                    help="Skip HTML, solo CLI.")
    ap.add_argument("--out", default=None, help="Path output HTML.")
    ap.add_argument(
        "--lang",
        choices=["it", "en", "fr", "de", "du", "es"],
        default=None,
        metavar="LANG",
        help="Forza la lingua del report HTML: it/en/fr/de(=du)/es. "
             "Default: auto-detect dalla lingua di sistema Windows.",
    )
    ap.add_argument("--json", dest="json_out", default=None,
                    help="Salva risultati grezzi in JSON.")
    args = ap.parse_args()

    ensure_dependencies()

    # Lingua report
    raw_lang = args.lang or detect_system_language()
    lang = "de" if raw_lang == "du" else raw_lang  # alias du -> de

    print("=" * 72)
    print("infostealer_audit.py v2 - audit superficie + accounts + tools")
    print("=" * 72)
    print(f"Utente Windows: {getpass.getuser()}")
    print(f"Showpassword:   {args.showpassword}")
    print(f"Lingua report:  {lang} {'(auto-detect)' if not args.lang else '(--lang)'}")

    state = {"showpassword": args.showpassword, "lang": lang}

    # 1. Carica KB
    kb = bv.load_kb()
    state["kb"] = kb
    print(f"\n[1/9] KB caricato (Chrome stable rif: "
          f"{kb['_meta'].get('current_chrome_stable')})")

    # 2. Detect browser versions installed
    print("\n[2/9] Detect browser installati...")
    installed = bv.detect_all_browsers()
    state["browsers_installed"] = installed
    for n, v in installed.items():
        print(f"    {n:12s} {v or 'NON INSTALLATO'}")

    # 3. Online version check
    if args.no_online:
        print("\n[3/9] Online version check SKIPPED")
        latest = {}
    else:
        print("\n[3/9] Live check ultime versioni stable...")
        latest = ov.fetch_all_latest(use_cache=True, verbose=True)
        for n, info in latest.items():
            if info:
                print(f"    {n:8s} latest: {info.get('version')} "
                      f"({info.get('release_date')}) [{info.get('source')}]")
            else:
                print(f"    {n:8s} latest: <unavailable>")
    state["latest_versions"] = latest
    state["version_comparison"] = ov.compare_with_installed(installed, latest)

    # 4. Auto-install / update external tools
    if args.no_tools:
        print("\n[4/9] Tool auto-install SKIPPED")
        state["external_tools"] = {}
    else:
        print("\n[4/9] Verifica + auto-install tool recovery Python...")
        state["external_tools"] = ext.ensure_external_tools(
            auto_install=True,
            install_flagged=args.install_flagged_tools,
            force_update=args.force_tool_update,
            verbose=True,
        )

    # 5. Vulnerability summary
    print("\n[5/9] Matching versioni vs KB CVE...")
    summary = bv.render_vulnerability_summary(installed, kb)
    state["browser_summary"] = summary
    for s in summary:
        print(f"    {s['browser']} v{s['version']}: "
              f"score {s.get('score',0)}/10, diff {s.get('decrypt_difficulty','?')}")

    # 6. Estrai TUTTE le credenziali Chromium (per il tab account)
    print("\n[6/9] Estrazione + decifrazione credenziali Chromium...")
    chromium_accounts = cd.extract_all_chromium_credentials()
    state["chromium_accounts"] = chromium_accounts
    for browser_name, profiles_list in chromium_accounts.items():
        for p in profiles_list:
            print(f"    {browser_name}/{p['profile']}: "
                  f"{p['v10_decrypted']} v10 decifrate, "
                  f"{p['v20_protected']} v20-protected")

    # Firefox (opzionale)
    firefox_accounts = {}
    if firefox_nss:
        ff_profiles = firefox_nss.discover_firefox_profiles()
        if ff_profiles:
            print(f"    Firefox profili: {len(ff_profiles)}")
            for prof in ff_profiles:
                creds = firefox_nss.decrypt_firefox_logins(prof)
                firefox_accounts[prof.name] = creds
                print(f"      {prof.name}: {len(creds)} credenziali decifrate")
    state["firefox_accounts"] = firefox_accounts

    # 7. Target audit + legacy
    print("\n[7/9] Scansione target infostealer + legacy...")
    state["target_results"] = targets.audit_all_targets()
    for t in state["target_results"]:
        if t.get("found"):
            print(f"    [!] {t['target']}: PRESENTE [{t['value']}]")
    state["legacy_data"] = legacy.audit_legacy_credentials()
    print(f"    Credential Manager entries: {len(state['legacy_data'].get('credential_manager',[]))}")
    print(f"    Wi-Fi profiles: {len(state['legacy_data'].get('wifi_profiles',[]))}")

    # 8. LaZagne Light (replica pura-Python)
    print("\n[8/9] LaZagne Light: Wi-Fi/PuTTY/WinSCP/Git/OpenVPN/...")
    lz = lzlite.run_lazagne_light()
    lz_sum = lzlite.summary(lz)
    state["lazagne_light"] = lz
    state["lazagne_summary"] = lz_sum
    wifi_list = lz.get("wifi", [])
    if wifi_list and wifi_list[0].get("_status") == "wireless_service_not_running":
        print(f"    Wi-Fi:        n/a (servizio wireless non attivo - desktop senza scheda?)")
    else:
        print(f"    Wi-Fi:        {lz_sum['wifi_count']} profili ({lz_sum['wifi_with_key']} con chiave visibile)")
    print(f"    PuTTY:        {lz_sum['putty_sessions']} sessioni")
    print(f"    WinSCP:       {lz_sum['winscp_sessions']} sessioni ({lz_sum['winscp_decrypted']} con pwd decifrata)")
    print(f"    Git creds:    {lz_sum['git_creds']} (.git-credentials plaintext)")
    print(f"    OpenVPN:      {lz_sum['openvpn_configs']} config ({lz_sum['openvpn_with_creds']} con auth file)")
    print(f"    FileZilla:    {lz_sum['filezilla_sites']} sites ({lz_sum['filezilla_with_pwd']} con pwd)")
    print(f"    Thunderbird:  {lz_sum['thunderbird_creds']} credenziali")
    print(f"    Pidgin:       {lz_sum['pidgin_accounts']} account chat")
    print(f"    DBVisualizer: {lz_sum['dbvisualizer_dbs']} database")
    print(f"    RDP files:    {lz_sum['rdp_files']}")
    print(f"    TOTAL credenziali extra trovate: {lz_sum['total_credentials_found']}")

    # 9. Fix recommendations
    state["fix_recs"] = bv.generate_fix_recommendations(summary, kb)
    print(f"\n[9/9] {len(state['fix_recs'])} raccomandazioni fix generate")

    # JSON export
    if args.json_out:
        def _clean(o):
            if isinstance(o, (bytes, bytearray)):
                return f"<bytes:{len(o)}>"
            if isinstance(o, Path):
                return str(o)
            if isinstance(o, dict):
                return {k: _clean(v) for k, v in o.items()}
            if isinstance(o, list):
                return [_clean(x) for x in o]
            return o
        out = {k: _clean(v) for k, v in state.items() if k != "kb"}
        Path(args.json_out).write_text(
            json.dumps(out, indent=2, default=str),
            encoding="utf-8")
        print(f"\n[OK] JSON: {args.json_out}")

    # HTML report
    if not args.no_html:
        if args.out:
            out_path = Path(args.out)
        else:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            suffix = "_showpassword" if args.showpassword else ""
            out_path = Path(__file__).parent / "reports" / f"infostealer{suffix}_{ts}.html"
            out_path.parent.mkdir(parents=True, exist_ok=True)
        render_html(state, out_path)
        T_main = get_strings(lang)
        print(f"\n[OK] Report HTML: {out_path}")
        if args.showpassword:
            print(f"     {T_main['showpassword_file_warning']}")


if __name__ == "__main__":
    main()
