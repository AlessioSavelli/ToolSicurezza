"""
sanitize_demo_reports.py
Sanifica i report HTML generati da ToolSicurezza, rimuovendo tutti i dati personali
e sostituendoli con dati di fantasia coerenti. Aggiunge il prefisso lingua al filename.

Esegui da ToolSicurezza\:
    python sanitize_demo_reports.py
"""
import re
import os
import glob
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# MAPPA: report timestamp → prefisso lingua
# (ordine crescente di LastWriteTime = it, en, fr, de, es)
# ─────────────────────────────────────────────────────────────
REPORTS_DIR = Path(__file__).parent / "reports"
DEMO_DIR = REPORTS_DIR / "demo"

LANG_MAP = {
    "infostealer_20260520_181520.html": "IT",
    "infostealer_20260520_181526.html": "EN",
    "infostealer_20260520_181532.html": "FR",
    "infostealer_20260520_181546.html": "DE",
    "infostealer_20260520_181604.html": "ES",
}

# ─────────────────────────────────────────────────────────────
# SOSTITUZIONI ORDINATE: più specifiche prima, più generiche dopo
# Formato: (pattern_regex, replacement)
# ─────────────────────────────────────────────────────────────
REPLACEMENTS = [

    # ── Sistema / identità macchina ──────────────────────────
    (r"utente:\s*Asus\b",            "utente: demo-user"),
    (r"user:\s*Asus\b",              "user: demo-user"),
    (r"Benutzer:\s*Asus\b",          "Benutzer: demo-user"),
    (r"utilisateur:\s*Asus\b",       "utilisateur: demo-user"),
    (r"usuario:\s*Asus\b",           "usuario: demo-user"),
    (r"macchina:\s*PC-ALESSIO\b",    "macchina: DEMO-PC"),
    (r"machine:\s*PC-ALESSIO\b",     "machine: DEMO-PC"),
    (r"Rechner:\s*PC-ALESSIO\b",     "Rechner: DEMO-PC"),
    (r"\bPC-ALESSIO\b",              "DEMO-PC"),
    # Path AppData con username reale
    (r"C:\\Users\\Asus\\",           r"C:\\Users\\demo-user\\"),

    # ── Email reali → email fittizie ─────────────────────────
    # Email principali
    (r"savelli\.alessio@libero\.it", "mario.rossi@libero.it"),
    (r"alessioneplus@gmail\.com",    "mario.rossi@gmail.com"),
    (r"alessio\.savelli@e-distribuzione\.com", "mario.rossi@example-company.com"),
    (r"alessio\.savelli@hotmail\.it","mario.rossi@hotmail.it"),
    # Email secondarie / familiari
    (r"savelli\.chiara@alice\.it",   "demo.family@alice.it"),
    (r"storymoney@tim\.it",          "demo.game@tim.it"),
    (r"pietro\.puri@alice\.it",      "demo.user3@alice.it"),
    # Email usa-e-getta (temp)
    (r"pbo32964@dcobe\.com",         "temp01@disposable.com"),
    (r"omk68877@tccho\.com",         "temp02@disposable.com"),
    (r"wcmlckgqbbgpxcochh@kvhrr\.com","temp03@disposable.com"),
    (r"cmdzqpybhbbnqnfrjc@cwmxc\.com","temp04@disposable.com"),
    (r"cauwcykdbanaldsdgs@tmmcv\.net","temp05@disposable.com"),
    (r"luz97117@jioso\.com",         "temp06@disposable.com"),
    # Apple Private Relay
    (r"xkwvjcj7jt@privaterelay\.appleid\.com", "xxxx.private@privaterelay.appleid.com"),
    # URL-encoded email in href/title
    (r"alessioneplus%40gmail\.com",  "mario.rossi%40gmail.com"),

    # ── Username reali → username fittizi ────────────────────
    (r"\bAlessioSavelli\b",  "MarioRossi"),
    (r"\bAlessioSav\b",      "MRossi"),
    (r"\bAlessioneplus\b",   "mariorossi"),
    (r"Alessio S\.",         "M. Rossi"),
    (r"\bAlessio\b",         "Mario"),
    (r"\bNatalliaFera\b",    "User2"),
    (r"\bxthevampirex\b",    "gamer_xyz"),
    (r"\bnatashaxfera\b",    "player_abc"),
    (r"\bwbrelettronica\b",  "shop_demo"),
    (r"\bLetsPushAdmin\b",   "SiteAdmin"),
    (r"\bLetsPush\b",        "DemoGym"),
    (r"\bmynameisnotimportant\b", "forum_user"),
    # Codice fiscale / matricola universitaria
    (r"\bsvllss98h09m208z\b","demo_student_id"),
    # Token device Windows Live
    (r"\b02bmkqlntqjemefp\b","device_token_demo"),
    # Token EOS SDK
    (r"83287756497c406f93943dc01dd539f3", "demo0eos0token0000000000000000000"),

    # ── URL personali → URL demo ─────────────────────────────
    # Portale datore di lavoro
    (r"arca-enel\.convenzioniaziendali\.it",  "intranet.example-employer.com"),
    (r"private\.e-distribuzione\.it",         "portal.example-employer.com"),
    # Scuola / università
    (r"ecampus\.istitutovolta\.eu",           "ecampus.example-school.edu"),
    (r"unical\.esse3\.cineca\.it",            "university.esse3.cineca.it"),
    # Poliambulatorio (dati sanitari)
    (r"referti\.poliambulatoriolametino\.it", "referti.example-clinic.it"),
    # Palestra
    (r"letspushhometraining\.com",            "example-gym.com"),
    # Sito adulti
    (r"dirtyroulette\.com",                   "example-socialsite.com"),
    # Biglietteria specifica
    (r"etnalandonline\.tm\.vivaticket\.com/biglietteria/anag/checkAndInsertAnag\.do",
     "events-demo.tm.vivaticket.com/biglietteria/anag/checkAndInsertAnag.do"),
    # Shop specifico
    (r"sbsav\.co\.uk/shop/spare-parts/alto/alto-12-woofer-for-alto-ts312-\.html",
     "example-shop.co.uk/shop/spare-parts/demo-product.html"),
    # HiveMQ cluster ID univoco
    (r"2e22c1dfc37b48349209f62328bec03d", "demo-cluster-id-00000000000000000"),
    # OpenID auth code
    (r"0KXw1bmw0d",  "DemoAuthCode0"),

    # ── Android scheme URLs (base64 lunghe) → demo ───────────
    # Netflix android://
    (r"android://Jzj5T2E45Hb33D[^@]+@com\.netflix\.mediaclient/",
     "android://DEMO_KEY==@com.netflix.mediaclient/"),
    # XM android://
    (r"android://WIyCR4vaiGSnuz[^@]+@com\.xm\.csee/",
     "android://DEMO_KEY==@com.xm.csee/"),
    # Qualsiasi altra android:// rimasta con chiavi lunghe
    (r"android://[A-Za-z0-9+/=_-]{20,}@",
     "android://DEMO_KEY==@"),

    # ── Credential Manager entries ───────────────────────────
    (r"MicrosoftAccount:target=SSO_POP_User:user=mario\.rossi@hotmail\.it",
     "MicrosoftAccount:target=SSO_POP_User:user=mario.rossi@hotmail.it"),
    # Il precedente pattern era già rimpiazzato; questo gestisce il target generico
    (r"LegacyGeneric:target=gh:github\.com:MarioRossi",
     "LegacyGeneric:target=gh:github.com:MarioRossi"),
    (r"GitHub - https://api\.github\.com/MarioRossi",
     "GitHub - https://api.github.com/MarioRossi"),

    # ── Titolo pagina: rimuove il timestamp preciso ───────────
    # Lascia la data ma oscura i minuti esatti
    (r"(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}",  r"\1 [DEMO]"),

    # ── Banner generato: oscura la data/ora esatta nel banner ─
    (r"(Generato|Generated|Généré|Erstellt|Generado):\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}",
     r"\1: 2026-01-01 [DEMO]"),
]

# ─────────────────────────────────────────────────────────────
# DEMO WATERMARK — inserito subito dopo <body>
# ─────────────────────────────────────────────────────────────
WATERMARK = (
    '<div style="background:#e8f4ff;border:2px solid #36c;padding:.6em 1em;'
    'border-radius:6px;margin:.5em 0;font-size:.85em">'
    '⚠️ <strong>DEMO REPORT</strong> — Tutti i dati personali sono stati sostituiti '
    'con dati di fantasia. Questo file è destinato esclusivamente a mostrare '
    'le funzionalità di ToolSicurezza.'
    '</div>\n'
)


def sanitize(html: str) -> str:
    """Applica tutte le sostituzioni e aggiunge il watermark."""
    for pattern, repl in REPLACEMENTS:
        html = re.sub(pattern, repl, html)

    # Inserisci watermark subito dopo </h1>
    html = html.replace('</h1>\n', '</h1>\n' + WATERMARK, 1)
    return html


def main():
    DEMO_DIR.mkdir(parents=True, exist_ok=True)

    processed = 0
    for src_name, lang_prefix in LANG_MAP.items():
        src_path = REPORTS_DIR / src_name
        if not src_path.exists():
            print(f"  [SKIP] Non trovato: {src_path}")
            continue

        print(f"  [{lang_prefix}] {src_name} ...", end=" ")
        raw = src_path.read_text(encoding="utf-8")
        clean = sanitize(raw)

        # Nuovo nome: IT_infostealer_demo.html  ecc.
        dst_name = f"{lang_prefix}_infostealer_demo.html"
        dst_path = DEMO_DIR / dst_name
        dst_path.write_text(clean, encoding="utf-8")

        delta = len(raw) - len(clean)
        print(f"OK -> {dst_name}  ({len(clean)//1024} KB, delta={delta:+d} bytes)")
        processed += 1

    print(f"\n[OK] {processed} report sanificati in: {DEMO_DIR}")

    # Verifica rapida: cerca pattern residui sospetti
    print("\n[Verifica residui dati personali]")
    suspects = [
        "Asus", "PC-ALESSIO", "savelli", "alessioneplus",
        "AlessioSavelli", "Alessioneplus", "natashaxfera",
        "xthevampirex", "NatalliaFera", "letspushhometraining",
        "dirtyroulette", "poliambulatoriolametino", "istitutovolta",
        "svllss98h09m208z", "02bmkqlntqjemefp",
    ]
    found_any = False
    for dst_path in DEMO_DIR.glob("*_infostealer_demo.html"):
        content = dst_path.read_text(encoding="utf-8")
        hits = [s for s in suspects if s.lower() in content.lower()]
        if hits:
            print(f"  [!!] {dst_path.name}: residui trovati -> {hits}")
            found_any = True
        else:
            print(f"  [OK] {dst_path.name}: pulito")
    if not found_any:
        print("  Tutti i file sono puliti. Nessun dato personale residuo.")


if __name__ == "__main__":
    main()
