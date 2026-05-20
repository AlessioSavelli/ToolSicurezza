# Disclaimer & Acceptable Use Policy

> **Read this document in full before downloading, installing, or running any
> component of this project.**

## 1. Purpose of the software

`ToolSicurezza` is a **defensive security audit suite**. Its sole intended
purposes are:

1. **Self-audit** — allowing a user to inspect, on systems they personally
   own or administer, what credentials, browser data, and configuration items
   would be exposed to a hypothetical infostealer running with the same
   privileges as the local user.
2. **Educational & research** — demonstrating how Windows DPAPI, Chromium's
   App-Bound Encryption (v20), and the NSS database used by Firefox-family
   browsers actually work, in order to make informed decisions about
   credential hygiene and password manager adoption.
3. **Threat modelling** — quantifying the "blast radius" of a successful
   infostealer infection on a specific machine, before such an event happens,
   so that hardening can be prioritised.

The software does **not** include, ship, or download:

- Any malware sample, backdoor, or weaponised payload.
- Any exploit code targeting third-party systems.
- Any network exfiltration capability — the suite operates strictly on
  local data and produces local reports.

## 2. Authorised use only

You may use this software **only**:

- On computers you **personally own** and are the primary user/administrator
  of; **or**
- On computers for which you possess **explicit, written authorisation**
  from the legitimate owner to perform security testing (for example a
  signed penetration-test engagement letter, an internal IT-security
  approval, or a bug-bounty programme scope document).

You may **not** use this software to:

- Access, copy, decrypt or process credentials, cookies, session tokens or
  any other authentication material belonging to another natural or legal
  person without their prior, informed, written consent.
- Bypass technical protection measures of systems for which you are not
  authorised, even if you have physical access.
- Provide the decrypted output of this tool to any third party, except in
  the context of a legitimate security engagement or with the data
  subject's explicit consent.

## 3. Compliance with applicable laws

You are solely responsible for ensuring that your use of this software
complies with the laws of your jurisdiction. Notable instruments include
but are not limited to:

| Jurisdiction | Instrument | Relevance |
|---|---|---|
| Council of Europe | Convention on Cybercrime (Budapest, 2001) | Articles 2-6: illegal access, interception, data interference |
| European Union | Directive 2013/40/EU | Attacks against information systems |
| European Union | Regulation 2016/679 (GDPR) | Processing of personal data including credentials |
| European Union | Regulation 2021/821 | Dual-use export controls — cyber-surveillance items |
| European Union | Cyber Resilience Act (2024) | Requirements for products with digital elements |
| 🇮🇹 Italy | Art. 615-ter Codice Penale | Unauthorised access to a computer or telematic system |
| 🇮🇹 Italy | Art. 615-quater Codice Penale | Unlawful holding & diffusion of access codes |
| 🇮🇹 Italy | Art. 617-quater Codice Penale | Interception of telematic communications |
| 🇮🇹 Italy | D.lgs. 196/2003 + GDPR | Privacy code |
| 🇩🇪 Germany | §§ 202a-c StGB | Ausspähen von Daten |
| 🇫🇷 France | Art. 323-1 ss Code Pénal | Atteintes aux STAD |
| 🇬🇧 United Kingdom | Computer Misuse Act 1990 | Unauthorised access offences |
| 🇺🇸 United States | 18 U.S.C. § 1030 (CFAA) | Computer Fraud and Abuse Act |

Several EU member states (including Germany — §202c StGB, the so-called
"Hackerparagraph") criminalise the **possession, production or distribution
of hacking tools** in some circumstances. The defensive nature of this
project (self-audit, no remote exfiltration, no exploit) and its scientific
purpose generally place it outside such prohibitions, but **you remain
responsible for verifying applicability in your own jurisdiction**.

If you are unsure whether your intended use is lawful, **consult a qualified
legal professional in your jurisdiction before proceeding**.

## 4. No warranty

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED. The MIT License terms in `LICENSE` apply in full.

In particular, no warranty is made regarding:

- The accuracy, completeness, or timeliness of the vulnerability knowledge
  base (`kb/vulnerabilities.json`). It is a best-effort compilation of
  publicly available research and may be incomplete or outdated.
- The success of decryption operations. Some browsers and versions
  intentionally implement protections that this tool documents but cannot
  bypass (e.g., Chrome v20 App-Bound Encryption "Stratum 3").
- The behaviour of the project on configurations not tested by the
  contributors.

## 5. No liability

To the maximum extent permitted by applicable law, the authors,
contributors, and copyright holders shall **not be liable** for:

- Any damage, loss of data, account compromise, financial loss, or
  reputational harm resulting from the use, misuse, or inability to use this
  software.
- Any actions taken by users or third parties based on the output of this
  software.
- Any violation of laws, contracts, or terms of service committed by users
  while operating this software.

## 6. Personal data (GDPR Article 6 lawful basis)

When you run this software on your own system, the decryption and analysis
of your own credentials does **not** constitute personal-data processing of
third-party data, because:

- The data subject (you) is identical to the data controller (you), and
- The lawful basis under GDPR Art. 6(1)(a) — consent — is implicitly given
  by the user invoking the tool on their own data.

Reports generated by the software (HTML, JSON, log files) may contain
plaintext credentials, including credentials linked to natural persons
(yourself or others if you share the machine). You are responsible for:

- Storing these reports securely (encrypted volume, BitLocker, etc.).
- Not distributing reports containing third-party credentials.
- Deleting reports promptly after the audit is concluded.

The software itself performs **no automated data transmission** outside the
local machine.

## 7. Responsible disclosure of vulnerabilities

If you discover a vulnerability in this software itself, please follow the
process described in [SECURITY.md](SECURITY.md). Do **not** open public
issues or post details on social media before a coordinated disclosure
window has elapsed.

## 8. Trademark and third-party references

This project references third-party tools (`LaZagne`, `pypykatz`,
`firepwd`, `browser_cookie3`), browsers (`Chrome`, `Edge`, `Firefox`,
`Brave`, etc.), malware families, CVE identifiers, and security
publications. All such references are made for descriptive and educational
purposes and do not imply endorsement, sponsorship, or affiliation. All
trademarks remain the property of their respective owners.

## 9. Acceptance

By cloning, downloading, building, installing or running any component of
this project, **you acknowledge that you have read and agree to the terms of
this disclaimer**, the project `LICENSE`, and the
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

If you do not agree, you must not use the software.

---

**Last updated:** 2026-05-18
**Document version:** 1.0
