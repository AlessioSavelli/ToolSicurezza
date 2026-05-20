# Contributing to the Knowledge Base

The KB in `kb/vulnerabilities.json` is what gives the audit tool its
context. Without an up-to-date KB, the version check still works but
the bypass technique mapping becomes stale.

## When to update

- When a new Chrome milestone introduces a security change (typically
  every 4 weeks).
- When a public research paper or blog post documents a new bypass.
- When a new infostealer family is disclosed.
- When you find a factual error or outdated entry.

## Sources we accept

✅ Acceptable:

- Peer-reviewed conference / journal papers (USENIX, IEEE S&P, CCS,
  Black Hat / DEF CON archived presentations).
- Vendor security advisories (Google, Microsoft, Mozilla, Apple).
- Security firms' research blogs with public-facing authorship
  (Mandiant, CrowdStrike, BlackBerry Research, Cybereason, Check Point,
  Group-IB, Sophos, Kaspersky, ESET, Trend Micro, Cisco Talos, etc.).
- Reputable independent researchers' public posts (e.g. on GitHub,
  Medium, personal blogs) with verifiable identity.
- Public CVE advisories with NIST NVD entries.

🛑 Not acceptable:

- "I tested this myself but haven't published" — unless you publish
  the research alongside the PR.
- Private threat-intelligence reports (unless the source has
  explicitly authorised public reproduction).
- Forum posts with anonymous claims and no PoC.
- Marketing materials that lack technical substance.

## Structure of a contribution

A KB contribution PR should touch:

1. `kb/vulnerabilities.json` — the actual data.
2. `_meta.last_updated` — bump the date.
3. `_meta.sources` — append the new URL if not already present.
4. PR description — at least one quote from the source justifying each
   factual claim.

Example PR description for a new infostealer:

```markdown
## New infostealer: FooStealer (2026-Q1)

Adds an entry under `known_infostealers.FooStealer` based on:

- Cybereason blog post, 2026-02-10: "FooStealer technical analysis"
  https://www.cybereason.com/blog/foostealer-2026

Key claims:

- First seen 2026-01. Cite: "First sightings on 27 January 2026" (Cybereason).
- v20 bypass via debugger-attach. Cite: "FooStealer attaches as a debugger
  to chrome.exe and reads the key from the heap" (Cybereason).
- Targets Chrome 127-148. Cite: "Tested working on Chrome 127 through 148"
  (Cybereason).

No new bypass technique to add — debugger-attach is already documented under
`bypass_techniques.debugger-attach-voidstealer`.
```

## Style guidelines

- Use present-tense, descriptive labels: "Inner AES wrapping" not
  "Introduced inner AES wrapping".
- ISO dates: `2024-11-12`, not `Nov 12, 2024`.
- Version-range strings consistent: `131 - 135`, `>= 148`, `< 127`.
- `decrypt_difficulty` and `complexity` use the predefined enums:
  TRIVIAL / LOW / MEDIUM / HIGH / VERY_HIGH (with VERY_HARD for difficulty).
- Field `used_by`: list of strings, infostealer names exactly as in
  `known_infostealers` keys (or "X family", "Y fork").
- Field `ref`: a single URL to the primary source. If you have
  multiple, pick the most authoritative.

## Things to leave out

We are conservative about what we publish:

- ❌ Sample SHA256 hashes (these can be misused).
- ❌ Operational C2 domain lists.
- ❌ Detailed YARA rules unless they are already public.
- ❌ Detonation procedures.
- ❌ Personal information of researchers or victims.

We include:

- ✅ Documented TTPs at the conceptual level.
- ✅ Browser/OS targets.
- ✅ Bypass technique categories.
- ✅ Public research links.

## Schema validation

There is no strict schema yet. Please:

```powershell
py -c "import json; json.load(open('kb/vulnerabilities.json', encoding='utf-8')); print('KB OK')"
```

Plan: introduce JSON Schema in a future release for CI-level
validation.

## When in doubt

Open a draft PR and ping the maintainers in the description. We
prefer over-communication when in ambiguous territory. There's no
penalty for asking before submitting.
