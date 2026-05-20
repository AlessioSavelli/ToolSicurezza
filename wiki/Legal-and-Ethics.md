# Legal and Ethics

This page expands on the legal framing of
[`DISCLAIMER.md`](../DISCLAIMER.md) and provides context for users
operating in different jurisdictions.

> ⚠️ This page is **not legal advice**. If you have specific concerns
> about your intended use, consult a qualified lawyer in your
> jurisdiction.

## The European Union dual-use regulation

Regulation (EU) 2021/821 governs the export of dual-use items,
including some "cyber-surveillance items". This project is designed to
fall **outside** the controlled categories because:

- It does not constitute an "intrusion software" within the meaning of
  the Wassenaar Arrangement and the related EU implementation. It does
  not modify the standard execution path of other software (it reads
  files the user already owns).
- It does not generate, deploy, or operate "command and control"
  infrastructure.
- It is offered openly as Free and Open Source Software (FOSS) under
  the [MIT license](../LICENSE) for security-research and
  self-audit purposes.

The applicable General Software Note (Note 3) of the EU Dual-Use
Regulation typically excludes from controls software that is "in the
public domain". This project is published under an OSI-approved
license and freely distributed, satisfying that condition.

> If you intend to use, modify, or redistribute this software in a
> commercial context, or to export it to a country subject to specific
> export controls, **verify independently** that no controls apply to
> your situation.

## The EU Cyber Resilience Act (CRA)

Regulation (EU) 2024/2847 introduces cybersecurity requirements for
products with digital elements. The CRA contains an explicit exemption
for **free and open-source software** "developed or supplied outside
the course of a commercial activity" (Article 2(11)).

This project is community-developed, non-commercial, and FOSS. The CRA
obligations for "manufacturers" of products do not apply. However, as
the project grows, contributors should be aware that:

- If the project is integrated into a commercial product, the
  commercial integrator becomes the responsible "manufacturer".
- The project maintains responsible vulnerability disclosure practices
  (see [SECURITY.md](../SECURITY.md)).

## GDPR (Regulation EU 2016/679)

When you use this software on **your own** machine, the GDPR
implications are minimal:

- The data subject (you) is identical to the data controller (you).
- The processing is performed locally, with no cross-border transfer.
- The lawful basis under Article 6(1)(a) — consent — is implicitly
  given by invoking the tool on your own data.

**However**, if your machine contains credentials of other natural
persons (family members, employees, friends who used your computer),
and you decrypt those credentials, you are processing their personal
data. In that case:

- Have a lawful basis (consent of the data subject, or Article 6(1)(f)
  "legitimate interests" if you are e.g. a system administrator
  performing an incident-response audit).
- Do not retain the data longer than necessary.
- Do not disclose it to third parties without basis.
- Honour data-subject rights (access, erasure).

The tool itself does **not** retain anything. The HTML/JSON reports
do. Delete them after use.

## Italian penal code references

For users in Italy:

### Art. 615-ter c.p. — *Accesso abusivo ad un sistema informatico o telematico*

Punishes unauthorised access to a computer or telematic system. Using
this tool **on your own system** is *not* "abusivo" — you have legitimate
access by virtue of ownership. Using it on someone else's system
without consent **is** punishable.

### Art. 615-quater c.p. — *Detenzione e diffusione abusiva di codici di accesso*

Punishes the unauthorised holding or distribution of access codes
"obtained or used illegally". Holding the credentials this tool
decrypts on your own machine is *not* punishable — they are your own
credentials. Distributing decrypted reports containing third-party
credentials would be.

### Art. 615-quinquies c.p. — *Diffusione di apparecchiature, dispositivi o programmi informatici diretti a danneggiare o interrompere un sistema informatico o telematico*

Punishes the distribution of programs designed to *damage* or *interrupt*
computer systems. This tool does neither. It is a read-only audit tool.

### Art. 617-quater c.p. — *Intercettazione, impedimento o interruzione illecita di comunicazioni informatiche o telematiche*

Punishes illegal interception of telematic communications. This tool
performs no network interception.

## German Hackerparagraph (§202c StGB)

Germany's §202c StGB criminalises the *production, acquisition,
distribution* of computer programs whose primary purpose is the
commission of certain hacking offences (§§202a, 202b, 303a, 303b).

The "primary purpose" test means that dual-use tools designed for
defensive audit and security research are generally outside the scope.
This project is:

- Designed for self-audit (defensive).
- Released as FOSS with explicit disclaimer.
- Includes no exploits or malware samples.
- Documents bypass techniques only at a level necessary for understanding
  the protections, not at a level enabling weaponisation.

Practical guidance for German users: the BSI (Federal Office for
Information Security) has clarified in multiple statements that
legitimate security research tools are protected, and the §202c
"Hackerparagraph" should not be read to criminalise security
professionals. However, **never** use such tools against systems for
which you do not have authorisation.

## United Kingdom Computer Misuse Act 1990

Sections 1-3 criminalise unauthorised access, unauthorised access with
intent, and unauthorised acts impairing the operation of a computer.
Self-audit on your own machine is authorised access by definition.
Third-party use without consent is not.

## United States CFAA (18 U.S.C. § 1030)

Same logic. Authorised use on your own systems is lawful. The
*Van Buren v. United States* (2021) Supreme Court decision narrowed
the scope of "exceeds authorised access", which generally helps
defensive researchers, but the underlying prohibition on **unauthorised
access** remains.

## Responsible disclosure (general principle)

If you discover a vulnerability in third-party software while using
this tool (Chrome, Edge, Firefox, an infostealer family, a Windows
component):

1. Report it privately to the vendor's security team.
2. Allow a reasonable disclosure window (typically 90 days).
3. Coordinate public disclosure with the vendor.
4. Do not exploit the vulnerability in the wild during the disclosure
   window.

See [SECURITY.md](../SECURITY.md) for our own vulnerability disclosure
policy.

## Educational use safeguards

If you are using this project in an educational setting (classroom,
training, CTF preparation):

- Run only on lab/training machines that the student owns or is
  authorised to use.
- Do not use captured credentials for any purpose other than the
  educational exercise.
- Make sure students understand the legal context (this page is a
  good starting point).
- Consider running in an isolated VM with synthetic browser data, to
  avoid even the appearance of unauthorised credential handling.

## Acceptable use in a corporate environment

If your employer wants to deploy this tool for internal use:

- Document the authorisation (an internal IT-security policy
  approval, a signed engagement letter, or equivalent).
- Run only on company-owned machines or with the employee's informed
  consent.
- Store the reports in a controlled location with restricted access.
- Treat the reports as containing personal data and apply your
  company's data-protection policies.
- Ensure any deployment complies with applicable workplace surveillance
  laws (in the EU, see the Italian "Statuto dei lavoratori" Art. 4 and
  similar provisions in other member states; these may require
  union/works-council agreement before the tool is used systematically
  on employee machines).

## Unacceptable use (will get you in legal trouble)

- Running the tool on a colleague's machine "as a prank".
- Decrypting credentials from a found USB stick / borrowed laptop.
- Running the tool as part of an unauthorised access campaign.
- Selling decrypted credentials.
- Boasting about decrypted credentials online.
- Using the tool to facilitate unauthorised access to a service you do
  not have an account for.

If you are tempted to do any of the above, **stop and consult a
lawyer**. The penalties under the laws listed above are non-trivial
(years of imprisonment in several jurisdictions).

## Final note

This project exists because *understanding* threats is the first step
to *defending* against them. Used as intended — on your own systems,
for your own education and protection — it is a powerful tool. Used
otherwise, it can cause real harm to real people, and it can land
the user in real legal trouble.

Be the good guy.
