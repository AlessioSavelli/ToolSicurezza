#!/usr/bin/env python3
"""
build_wiki.py — Generate interconnected HTML wiki for ToolSicurezza.
Reads .md files from the wiki repo, writes HTML to docs/wiki/.
"""

import re
import sys
from pathlib import Path
import markdown as md_lib
from markdown.extensions.tables import TableExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.codehilite import CodeHiliteExtension

WIKI_SRC  = Path(__file__).parent.parent / "ToolSicurezza.wiki"
DOCS_OUT  = Path(__file__).parent / "docs"
REPO_URL  = "https://github.com/AlessioSavelli/ToolSicurezza"

# ── Navigation structure ───────────────────────────────────────────────────
NAV = [
    ("GETTING STARTED", [
        ("Home",           "Home"),
        ("Installation",   "Installation"),
        ("Quick-Start",    "Quick Start"),
    ]),
    ("USING THE TOOL", [
        ("CLI-Reference",  "CLI Reference"),
        ("HTML-Report",    "HTML Report"),
        ("Demo-Reports",   "Demo Reports"),
    ]),
    ("INTERNALS", [
        ("Architecture",    "Architecture"),
        ("Knowledge-Base",  "Knowledge Base"),
        ("Adding-a-Browser","Adding a Browser"),
        ("Contributing-KB", "Contributing to KB"),
    ]),
    ("REFERENCE", [
        ("FAQ",             "FAQ"),
        ("Troubleshooting", "Troubleshooting"),
        ("Threat-Model",    "Threat Model"),
        ("Legal-and-Ethics","Legal & Ethics"),
    ]),
]

ALL_SLUGS = {slug for _, pages in NAV for slug, _ in pages}

# ── CSS ────────────────────────────────────────────────────────────────────
CSS = """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f0f2f5;color:#1a202c;display:flex;min-height:100vh}

/* ── Sidebar ── */
#sidebar{
  width:268px;min-width:268px;background:#1e2535;color:#cbd5e0;
  display:flex;flex-direction:column;position:sticky;top:0;
  height:100vh;overflow-y:auto;z-index:10;
  scrollbar-width:thin;scrollbar-color:#4a5568 transparent}
#sidebar::-webkit-scrollbar{width:4px}
#sidebar::-webkit-scrollbar-thumb{background:#4a5568;border-radius:2px}

.sidebar-logo{
  padding:20px 20px 16px;border-bottom:1px solid #2d3748}
.sidebar-logo a{
  text-decoration:none;color:#e2e8f0;font-size:1.05rem;font-weight:700;
  display:flex;align-items:center;gap:8px}
.sidebar-logo .badge{
  background:#3182ce;color:#fff;font-size:.65rem;padding:2px 6px;
  border-radius:10px;font-weight:600;letter-spacing:.4px}

.nav-section{padding:20px 16px 4px}
.nav-section-title{
  font-size:.65rem;font-weight:700;letter-spacing:1px;
  color:#718096;text-transform:uppercase;padding:0 8px 6px}
.nav-section a{
  display:block;padding:6px 10px;border-radius:6px;
  color:#a0aec0;text-decoration:none;font-size:.875rem;
  transition:background .15s,color .15s;margin-bottom:1px}
.nav-section a:hover{background:#2d3748;color:#e2e8f0}
.nav-section a.active{
  background:#2b6cb0;color:#fff;font-weight:600}

.sidebar-footer{
  margin-top:auto;padding:16px 20px;border-top:1px solid #2d3748;
  font-size:.75rem;color:#718096}
.sidebar-footer a{color:#90cdf4;text-decoration:none}
.sidebar-footer a:hover{text-decoration:underline}

/* ── Main content ── */
#main{flex:1;min-width:0;padding:40px 48px 80px;max-width:980px}

/* breadcrumb */
.breadcrumb{font-size:.8rem;color:#718096;margin-bottom:24px}
.breadcrumb a{color:#3182ce;text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
.breadcrumb span{margin:0 6px}

/* headings */
#content h1{font-size:2rem;font-weight:700;color:#1a202c;
  margin-bottom:8px;padding-bottom:12px;border-bottom:2px solid #e2e8f0}
#content h2{font-size:1.35rem;font-weight:700;color:#2d3748;
  margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid #e8ecf0}
#content h3{font-size:1.1rem;font-weight:600;color:#2d3748;margin:28px 0 10px}
#content h4{font-size:.95rem;font-weight:600;color:#4a5568;margin:20px 0 8px}

/* paragraph, lists */
#content p{line-height:1.75;color:#2d3748;margin:0 0 16px}
#content ul,#content ol{padding-left:1.5em;margin:0 0 16px}
#content li{line-height:1.7;margin-bottom:4px}
#content li p{margin-bottom:4px}

/* inline code */
#content code{
  background:#edf2f7;color:#c7254e;padding:1px 5px;
  border-radius:4px;font-size:.875em;font-family:'SFMono-Regular',Consolas,
  'Liberation Mono',Menlo,monospace}

/* code blocks */
#content pre{
  background:#1e2535;border-radius:8px;padding:20px 22px;margin:0 0 20px;
  overflow-x:auto;border:1px solid #2d3748}
#content pre code{
  background:none;color:#a8b8d8;padding:0;font-size:.84rem;
  font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
  line-height:1.65}

/* tables */
#content table{
  border-collapse:collapse;width:100%;margin:0 0 20px;
  font-size:.875rem;border-radius:8px;overflow:hidden;
  box-shadow:0 1px 3px rgba(0,0,0,.08)}
#content th{
  background:#2d3748;color:#e2e8f0;padding:10px 14px;
  text-align:left;font-weight:600;font-size:.8rem;letter-spacing:.3px}
#content td{
  padding:9px 14px;border-bottom:1px solid #e8ecf0;color:#2d3748}
#content tr:last-child td{border-bottom:none}
#content tr:nth-child(even) td{background:#f7fafc}

/* blockquote */
#content blockquote{
  border-left:4px solid #3182ce;background:#ebf8ff;
  padding:12px 18px;border-radius:0 6px 6px 0;margin:0 0 20px;color:#2c5282}
#content blockquote p{margin:0;color:inherit}

/* horizontal rule */
#content hr{border:none;border-top:1px solid #e2e8f0;margin:32px 0}

/* links */
#content a{color:#3182ce;text-decoration:none}
#content a:hover{text-decoration:underline;color:#2b6cb0}

/* page nav (prev/next) */
.page-nav{
  display:flex;justify-content:space-between;margin-top:48px;
  padding-top:24px;border-top:1px solid #e2e8f0;gap:12px}
.page-nav a{
  display:flex;flex-direction:column;padding:14px 20px;
  border:1px solid #e2e8f0;border-radius:8px;text-decoration:none;
  color:#2d3748;transition:border-color .2s,box-shadow .2s;
  flex:1;max-width:48%}
.page-nav a:hover{border-color:#3182ce;box-shadow:0 2px 8px rgba(49,130,206,.15)}
.page-nav .nav-dir{font-size:.72rem;color:#718096;margin-bottom:4px;font-weight:600}
.page-nav .nav-title{font-size:.9rem;font-weight:600;color:#2d3748}
.page-nav .next{text-align:right;margin-left:auto}

/* responsive */
@media(max-width:900px){
  #sidebar{display:none}
  #main{padding:24px 20px 60px}
}
"""

# ── HTML template ──────────────────────────────────────────────────────────
def html_page(slug, title, body_html, prev_page=None, next_page=None):
    # build nav
    nav_html = ""
    for section_label, pages in NAV:
        links = ""
        for s, label in pages:
            active = ' class="active"' if s == slug else ""
            links += f'<a href="{s}.html"{active}>{label}</a>\n'
        nav_html += (
            f'<div class="nav-section">'
            f'<div class="nav-section-title">{section_label}</div>'
            f'{links}</div>\n'
        )

    # breadcrumb
    section_name = ""
    for section_label, pages in NAV:
        for s, _ in pages:
            if s == slug:
                section_name = section_label.title()
    breadcrumb = (
        f'<div class="breadcrumb">'
        f'<a href="Home.html">Docs</a>'
        f'<span>›</span>{section_name}<span>›</span>{title}'
        f'</div>'
    ) if slug != "Home" else ""

    # prev/next
    flat = [(s, l) for _, pages in NAV for s, l in pages]
    idx  = next((i for i, (s, _) in enumerate(flat) if s == slug), None)
    pn   = ""
    if idx is not None:
        parts = []
        if idx > 0:
            ps, pl = flat[idx - 1]
            parts.append(
                f'<a href="{ps}.html">'
                f'<span class="nav-dir">← Previous</span>'
                f'<span class="nav-title">{pl}</span></a>'
            )
        else:
            parts.append('<span></span>')
        if idx < len(flat) - 1:
            ns, nl = flat[idx + 1]
            parts.append(
                f'<a href="{ns}.html" class="next">'
                f'<span class="nav-dir">Next →</span>'
                f'<span class="nav-title">{nl}</span></a>'
            )
        pn = f'<nav class="page-nav">{"".join(parts)}</nav>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — ToolSicurezza Docs</title>
<style>{CSS}</style>
</head>
<body>
<nav id="sidebar">
  <div class="sidebar-logo">
    <a href="Home.html">🛡 ToolSicurezza <span class="badge">v1.0</span></a>
  </div>
  {nav_html}
  <div class="sidebar-footer">
    <a href="{REPO_URL}" target="_blank">GitHub ↗</a> &nbsp;·&nbsp;
    <a href="{REPO_URL}/blob/main/DISCLAIMER.md" target="_blank">Disclaimer</a>
  </div>
</nav>
<main id="main">
  {breadcrumb}
  <div id="content">
{body_html}
  </div>
  {pn}
</main>
</body>
</html>"""


# ── Markdown → HTML conversion ────────────────────────────────────────────
def slug_to_html_link(m):
    """Replace [[Page-Name]] or (Page-Name.md) style links."""
    return m.group(0)  # passthrough; handled below


def fix_links(html_text):
    """Convert wiki-style links to .html equivalents."""
    # [text](Page-Name.md)  →  [text](Page-Name.html)
    html_text = re.sub(
        r'href="([A-Za-z][A-Za-z0-9_-]*)\.md"',
        lambda m: f'href="{m.group(1)}.html"',
        html_text,
    )
    # bare page names in href that match known slugs
    def replace_slug(m):
        slug = m.group(1)
        if slug in ALL_SLUGS:
            return f'href="{slug}.html"'
        return m.group(0)
    html_text = re.sub(r'href="([A-Za-z][A-Za-z0-9_-]*)"', replace_slug, html_text)
    return html_text


def convert_md(src: Path) -> str:
    text = src.read_text(encoding="utf-8")
    # pre-process: fix internal markdown links  [text](Page.md)
    text = re.sub(r'\]\(([A-Za-z][A-Za-z0-9_-]*)\.md\)', r'](\1.html)', text)
    text = re.sub(r'\]\(([A-Za-z][A-Za-z0-9_-]*)\)', lambda m: (
        f']({m.group(1)}.html)' if m.group(1) in ALL_SLUGS else m.group(0)
    ), text)

    html = md_lib.markdown(
        text,
        extensions=[
            "tables",
            "fenced_code",
            "toc",
            "attr_list",
            "def_list",
            "admonition",
            "nl2br",
        ],
    )
    html = fix_links(html)
    return html


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    if not WIKI_SRC.exists():
        print(f"ERROR: wiki source not found at {WIKI_SRC}", file=sys.stderr)
        sys.exit(1)

    DOCS_OUT.mkdir(parents=True, exist_ok=True)

    flat = [(s, l) for _, pages in NAV for s, l in pages]

    for slug, label in flat:
        src = WIKI_SRC / f"{slug}.md"
        if not src.exists():
            print(f"  [skip] {slug}.md not found")
            continue

        body = convert_md(src)
        page = html_page(slug, label, body)
        out  = DOCS_OUT / f"{slug}.html"
        out.write_text(page, encoding="utf-8")
        print(f"  [ok] {out.name}")

    # index.html → redirect to Home.html
    idx = DOCS_OUT / "index.html"
    idx.write_text(
        '<!DOCTYPE html><html><head><meta charset="UTF-8">'
        '<meta http-equiv="refresh" content="0;url=Home.html">'
        '</head><body><a href="Home.html">→ Home</a></body></html>',
        encoding="utf-8",
    )
    print(f"  [ok] index.html (redirect)")
    print(f"\nDone — {len(flat)+1} files written to {DOCS_OUT}")


if __name__ == "__main__":
    main()
