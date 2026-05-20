# Security Policy

## Supported versions

Only the `main` branch is supported. Tagged releases that are older than
30 days are unsupported; please upgrade.

| Version | Supported |
|---|---|
| `main` (latest commit) | ✅ |
| Tagged release < 30 days | ✅ |
| Older tags | ❌ |

## Reporting a vulnerability in this software

If you find a security issue **in this project itself** (for example a
code-execution flaw in the report generator, a path-traversal in the
file-handling, or an information-disclosure that would let a non-admin
user read another user's reports), please **report it privately**.

### How to report

1. **Preferred:** open a private security advisory on GitHub via the
   *Security → Advisories → New draft security advisory* tab of the repo.
2. **Alternative:** email the maintainers at the address listed in the
   GitHub organisation profile. Use PGP if possible.

### What to include

- A clear description of the issue.
- Steps to reproduce (ideally a small PoC, redacted of any real
  credentials).
- The affected file/function and commit hash.
- The impact you believe it has.
- Your name/handle, if you want to be credited in the fix.

### What happens next

- We aim to acknowledge receipt within **5 business days**.
- We aim to publish a fix or mitigation within **45 days** of confirmed
  receipt for high-severity issues, **90 days** for medium/low.
- Once a fix is released, we will credit you (with your permission) in
  the release notes.

### Coordinated disclosure

Please **do not** publicly disclose the issue (issues, social media,
blog posts) until we have released a fix or 90 days have elapsed,
whichever comes first.

## NOT a vulnerability in this project

The following are **expected behaviour** and not vulnerabilities:

- The tool can decrypt your own Chrome v10 credentials in user-mode. This
  is the *purpose* of the tool. It is not a Chrome vulnerability and not
  a tool vulnerability — it is how Windows DPAPI was designed.
- Aggressive mode requires Administrator and creates a transient
  scheduled task running as `NT AUTHORITY\SYSTEM`. This is documented
  and required by the design.
- The tool may show plaintext credentials in the HTML report when
  `--showpassword` is used. This is the requested behaviour.
- The tool can run on a machine without your knowledge if a malicious
  user has user-level access to your account. So can any other Python
  script. The same threat-model applies to **any** desktop application
  with access to your DPAPI keychain.

## Reporting vulnerabilities in *other* software

If you discover a vulnerability in Chrome, Edge, Firefox, an infostealer
family, or any other third-party software while using this tool, please
report it to the **vendor of that software** through their responsible
disclosure programme. This project's maintainers are not the appropriate
contact for third-party vulnerabilities.

Useful contacts:

- Chrome (Google VRP): https://bughunters.google.com/
- Firefox (Mozilla Security): https://www.mozilla.org/security/bug-bounty/
- Microsoft (MSRC): https://msrc.microsoft.com/
- Brave: https://brave.com/security/

## Hall of fame

Security researchers who have responsibly disclosed issues in this
project will be listed here.

*(empty so far)*
