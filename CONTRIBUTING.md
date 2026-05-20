# Contributing to ToolSicurezza

Thanks for considering a contribution. This project is built and maintained
to help users perform **defensive security audits on their own systems**.
Every contribution must keep that goal in mind.

## Before you start

1. Read [`DISCLAIMER.md`](DISCLAIMER.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
2. Skim the project [wiki](wiki/Home.md) so you know how the pieces fit
   together.
3. Check existing [issues](../../issues) and [pull requests](../../pulls)
   to avoid duplicate work.

## What we accept

✅ Welcome:

- New defensive detections (additional infostealer targets, new credential
  stores, new browser profiles).
- Support for additional browsers and operating-system locales.
- Updates and corrections to `kb/vulnerabilities.json` based on public
  research, with citations.
- Pure code quality improvements: type hints, refactoring, tests,
  performance.
- Documentation, translations of the wiki, fixed typos.
- New CI/lint workflows.

🛑 We will reject:

- Anything that targets systems the user does not own or have explicit
  authorisation to audit.
- Inclusion or download of malware samples, exploit kits, or weaponised
  payloads.
- Network exfiltration capability (the suite operates strictly on local
  data).
- Zero-day exploit code, even if defensive in intent.
- Code that intentionally evades endpoint protection (EDR, AV) to hide
  itself.

## Development setup

```powershell
git clone https://github.com/AlessioSavelli/ToolSicurezza.git
cd ToolSicurezza
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m pip install -r requirements-dev.txt   # ruff, pytest, mypy
```

Run the linter:

```powershell
ruff check .
ruff format --check .
```

Run tests:

```powershell
py -m pytest tests/
```

## Pull request checklist

Before opening a PR:

- [ ] Code passes `ruff check` and `ruff format`.
- [ ] If adding a new module, include a docstring at the top describing the
      purpose and listing any external sources/algorithms used.
- [ ] If adding a credential-recovery technique, link the **public**
      research that describes the algorithm. We do not accept original
      offensive research; we *replicate* defensively what has already been
      published.
- [ ] Update `wiki/CLI-Reference.md` if you added or changed a CLI flag.
- [ ] Update `kb/vulnerabilities.json` `_meta.last_updated` if you touched
      the KB.
- [ ] Update `README.md` / `README_IT.md` if you added a user-visible
      feature.
- [ ] Add or update a test where reasonable.

## Commit message convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(browsers): add Arc browser detection
fix(firefox): handle empty key4.db on fresh profiles
docs(wiki): clarify aggressive mode prerequisites
refactor(report): split HTML rendering into Jinja templates
chore(deps): bump cryptography to 43.0.1
```

## Coding style

- Python 3.10+ syntax allowed (`list[int]` style annotations, structural
  pattern matching where it improves clarity).
- `ruff` is the source of truth for style.
- Public functions take a docstring; private helpers (leading `_`) take
  one only if non-trivial.
- No global mutable state, ever.
- All filesystem and registry operations must use a try/except and fail
  gracefully — never crash the whole audit because one source is
  unavailable.

## Knowledge-base contributions

When adding to `kb/vulnerabilities.json`:

1. Cite at least one **public, primary** source (research paper, vendor
   advisory, security-firm blog post) per claim.
2. Prefer factual fields (CVE, date, version) over editorial commentary.
3. Do not include sample hashes or IoCs that could be misused for offensive
   campaigns. Public threat-intel summaries are fine; detailed YARA rules
   or detonation procedures are not.

## Reporting bugs

Use the [issue templates](.github/ISSUE_TEMPLATE/). Always include:

- OS version (`winver`).
- Python version (`py --version`).
- Browser versions involved.
- Exact command line used.
- Console output (redact any plaintext credential).

## Reporting security vulnerabilities

See [SECURITY.md](SECURITY.md). **Do not open public issues** for security
problems in this software.

## Recognition

All contributors are listed in `CONTRIBUTORS.md` (created on first
contribution) and in the GitHub Insights tab. By submitting a PR you agree
to license your contribution under the project [MIT License](LICENSE).
