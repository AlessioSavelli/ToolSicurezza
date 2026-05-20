"""
modules/i18n.py - Internazionalizzazione report HTML
Lingue: it (Italiano), en (English), fr (Francais), de (Deutsch), es (Espanol)
"""
from __future__ import annotations

SUPPORTED = {"it", "en", "fr", "de", "es"}

_S: dict[str, dict[str, str]] = {

    # ─────────────────────────── ITALIANO ────────────────────────────
    "it": {
        "html_lang": "it",
        "report_title": "Infostealer Audit Report",
        "generated_at": "Generato",
        "user_label": "utente",
        "machine_label": "macchina",
        "passwords_masked": "password mascherate",
        "showpassword_mode": "SHOWPASSWORD MODE",
        "overall_risk_prefix": "Rischio complessivo",
        "risk_CRITICAL": "CRITICO",
        "risk_HIGH": "ALTO",
        "risk_MEDIUM": "MEDIO",
        "risk_LOW": "BASSO",
        # stat boxes
        "stat_browsers": "Browser installati",
        "stat_decrypted": "Credenziali decifrate (vulnerabili)",
        "stat_protected": "Credenziali v20-protected",
        "stat_outdated": "Browser obsoleti",
        "stat_targets": "Target infostealer trovati",
        "stat_tools": "Tool recovery installati",
        "stat_lazagne": "Credenziali LaZagne-Light estratte",
        # tabs
        "tab_overview": "Overview",
        "tab_accounts": "Account per browser",
        "tab_versions": "Versioni & CVE",
        "tab_targets": "Target infostealer",
        "tab_lazagne": "LaZagne Light",
        "tab_legacy": "Credenziali legacy",
        "tab_tools": "Tool recovery",
        "tab_fixes": "Raccomandazioni fix",
        "tab_timeline": "ABE Timeline",
        # overview
        "section_overview": "Riassunto esecutivo",
        "overview_info_box": (
            "Cosa significa questo report: elenca tutti i bersagli che un "
            "infostealer (LummaC2, RedLine, Vidar, Glove Stealer, Phemedrone, ecc.) "
            "cercherebbe sul tuo PC. Per ogni elemento riporta stato esposizione, "
            "valore per l’attaccante, tecniche di bypass note, e fix consigliato "
            "con data di release."
        ),
        "col_browser": "Browser",
        "col_installed_version": "Versione installata",
        "col_current_stable": "Versione stable corrente",
        "col_diff": "Differenza",
        "col_risk": "Risk",
        "up_to_date": "aggiornato",
        # accounts
        "section_accounts": "Account decifrati per browser",
        "showpassword_warning": (
            "MODE: SHOWPASSWORD — le password sono in chiaro. "
            "Tratta questo file come dato sensibile."
        ),
        "masked_info": (
            "Le password sono mascherate. Per visualizzarle in chiaro, "
            "esegui di nuovo con <code class=\"code\">--showpassword</code>."
        ),
        "profile_label": "Profilo",
        "credentials_word": "credenziali",
        "decrypted_word": "decifrate",
        "protected_word": "v20-protected",
        "col_url": "URL",
        "col_username": "Username",
        "col_password": "Password",
        "col_cipher": "Cipher",
        "col_category": "Categoria",
        "v20_protected_tag": "[v20-PROTECTED]",
        # versions
        "section_versions": "Versioni installate vs. ultime stable",
        "col_released": "Rilasciata",
        "col_major_gap": "Major gap",
        "col_source": "Sorgente",
        "vuln_known_header": "Vulnerabilità note per browser installato",
        "decrypt_diff_label": "Decrypt difficulty",
        "risk_score_label": "Risk score",
        "bypass_section_label": "Tecniche di bypass applicabili",
        "used_by_label": "Usato da:",
        "ref_label": "Ref",
        "fix_prefix": "Fix:",
        "released_label": "rilasciata",
        # targets
        "section_targets": "Target infostealer rilevati",
        "targets_intro": "Bersagli classici. SOLO PRESENZA, niente esfiltrazione.",
        "col_target": "Target",
        "col_status": "Stato",
        "col_value": "Valore",
        "col_details": "Dettagli",
        "status_present": "✓ PRESENTE",
        # lazagne
        "section_lazagne": "LaZagne Light — replica pura-Python",
        "lazagne_intro": (
            "Implementazione interna delle categorie LaZagne più utili. "
            "Zero dipendenze esterne, zero binari PUA-flagged. "
            "Algoritmi pubblici documentati."
        ),
        "wifi_header": "Wi-Fi profiles",
        "wifi_na": "(n/a)",
        "wifi_key_msg": "profili con chiave visibile (richiede admin per la chiave in chiaro).",
        "putty_header": "PuTTY sessions",
        "putty_note": "PuTTY NON salva password SSH per design. Mostriamo solo host/user/port delle sessioni configurate.",
        "winscp_header": "WinSCP sessions",
        "winscp_warning": "WinSCP usa un algoritmo XOR custom DECIFRABILE in user-mode.",
        "winscp_decrypted_msg": "password decifrate.",
        "git_header": "Git credentials",
        "git_warning": (
            "Il file <code class=\"code\">~/.git-credentials</code> "
            "è in <strong>PLAINTEXT</strong> per design. Qualsiasi processo "
            "user-mode lo legge istantaneamente."
        ),
        "openvpn_header": "OpenVPN configs",
        "filezilla_header": "FileZilla saved sites",
        "filezilla_warning": "FileZilla salva password in <code class=\"code\">sitemanager.xml</code> base64-encoded (NON cifrate).",
        "thunderbird_header": "Thunderbird credentials",
        "thunderbird_warning": "Thunderbird usa lo stesso NSS schema di Firefox. Senza Primary Password = decifrabile in user-mode.",
        "pidgin_header": "Pidgin chat accounts",
        "pidgin_warning": "Pidgin salva password in PLAINTEXT in <code>accounts.xml</code>.",
        "dbviz_header": "DBVisualizer databases",
        "rdp_header": "RDP files",
        "chat_header": "Chat/messaging apps (presenza)",
        "col_ssid": "SSID",
        "col_auth": "Auth",
        "col_key_cleartext": "Key (cleartext)",
        "col_session": "Sessione",
        "col_host": "Host",
        "col_port": "Porta",
        "col_user": "Utente",
        "col_protocol": "Protocollo",
        "col_config": "Config",
        "col_auth_file": "Auth file",
        "col_file": "File",
        "col_pwd_encrypted": "Pwd cifrata",
        "col_alias": "Alias",
        "col_db_url": "URL DB",
        "col_app_name": "App",
        "col_path": "Path",
        "col_profile": "Profilo",
        "col_type": "Tipo",
        "col_persistence": "Persistenza",
        "yes_str": "SÌ",
        "no_str": "NO",
        # legacy
        "section_legacy": "Credenziali Windows legacy",
        "credman_header": "Windows Credential Manager",
        "vault_header": "IE / Edge Legacy Vault",
        "wifi_saved_header": "Profili Wi-Fi salvati",
        "outlook_header": "Profili Outlook",
        "entries_word": "entries",
        # tools
        "section_tools": "Tool recovery installati &amp; pronti",
        "tools_intro": (
            "Tool open-source pubblicamente disponibili. Quelli mancanti vengono "
            "installati automaticamente via pip. PUA-flagged richiedono "
            "opt-in esplicito con <code class=\"code\">--install-flagged-tools</code>."
        ),
        "status_installed": "✓ INSTALLATO",
        "status_missing": "MANCANTE",
        "tag_new": "NEW",
        "tag_upgraded": "UPGRADED",
        "tag_pua": "PUA-flagged",
        # fixes
        "section_fixes": "Raccomandazioni di fix",
        "why_label": "Perché:",
        "how_label": "Come:",
        # timeline
        "section_timeline": "Timeline App-Bound Encryption (Chrome 127+)",
        "tl_fix_label": "Fix:",
        "showpassword_file_warning": "[!] CONTIENE PASSWORD IN CHIARO. Elimina dopo l'audit.",
        # pwd_audit-specific keys
        "pwd_report_title": "Audit credenziali browser",
        "pwd_h1": "Audit credenziali browser",
        "pwd_what_box_title": "Cosa significa questo report:",
        "pwd_what_box_text": (
            "queste sono ESATTAMENTE le credenziali che un infostealer "
            "(RedLine, Lumma, Kepavll, ecc.) riuscirebbe a esfiltrare dal tuo PC "
            "se eseguito nel contesto del tuo utente Windows. Il malware fa la stessa "
            "identica decifrazione che ha fatto questo tool (DPAPI + AES-GCM)."
        ),
        "pwd_aggressive_note": (
            "<strong style=\"color:#c00\">MODALITA AGGRESSIVA attiva:</strong> "
            "oltre alle credenziali user-mode (v10), il tool ha tentato di bypassare "
            "anche la <code>v20 App-Bound Encryption</code> creando una "
            "<strong>scheduled task come SYSTEM</strong>. Questo simula un infostealer "
            "elevato a admin (come quelli che usano UAC bypass o COM elevation)."
        ),
        "stat_total_creds": "credenziali totali",
        "stat_decrypted_vm": "DECIFRATE<br>(vulnerabili user-mode)",
        "stat_protected_v20_abe": "PROTETTE v20-ABE<br>(richiedono SYSTEM)",
        "stat_weak_pwd": "password DEBOLI",
        "stat_reused_pwd": "account con pwd RIUTILIZZATA",
        "abe_info_title": "Chrome 127+ App-Bound Encryption (v20):",
        "abe_info_text": (
            "Le password salvate da Chrome aggiornato (luglio 2024 in poi) sono cifrate "
            "due volte: una con DPAPI dell'utente, una con DPAPI di SYSTEM. Un infostealer "
            "in modalita' utente normale (la stragrande maggioranza) NON riesce a "
            "decifrarle. Le {n} credenziali «PROTETTE» sopra sono in questo stato."
        ),
        "reuse_section_title": (
            "Password riutilizzate (la singola perdita compromette tutti questi siti)"
        ),
        "reuse_same_pwd": "Stessa password",
        "reuse_used_on": "usata su",
        "reuse_sites_suffix": "siti",
        "all_creds_title": "Tutte le credenziali (ordinate per criticità + debolezza)",
        "col_sev": "Sev",
        "col_len": "Len",
        "col_strength": "Robustezza",
        "col_issues": "Problemi",
        "protected_v20_abe_tag": "[PROTETTO v20-ABE]",
        "strength_guide_title": "Come interpretare i livelli di robustezza",
        "strength_very_weak_desc": "password dizionario / sequenze ovvie / molto corta. Rotta in secondi.",
        "strength_weak_desc": "corta o monoclasse. Rotta in minuti/ore con brute force mirato.",
        "strength_medium_desc": "lunghezza decente + 2-3 classi. Rotta in giorni/settimane.",
        "strength_strong_desc": "12+ char, 3-4 classi, entropia 60+ bit. Rotta in mesi/anni.",
        "strength_very_strong_desc": "16+ char, alta entropia, 4 classi. Tecnicamente irrompibile per brute force.",
        "tech_notes_title": "Note tecniche su DPAPI e AES-GCM",
        "tech_note_1": "Chrome/Edge salvano le password come blob <code>v10</code> + nonce(12B) + ciphertext + tag(16B).",
        "tech_note_2": "La chiave AES-256 è in <code>Local State</code>, cifrata via DPAPI usando le credenziali Windows dell'utente.",
        "tech_note_3": "DPAPI (<code>CryptUnprotectData</code>) usa la master key dell'utente Windows + il suo SID + la sua password (o PIN/Hello).",
        "tech_note_4": "Un malware in esecuzione come il tuo utente Windows può fare tutto questo. NON serve essere admin.",
        "tech_note_5": "Per impedire l'esfiltrazione futura: <strong>non salvare password nel browser</strong>, usa un password manager dedicato.",
        "suggestions_title": "Suggerimenti:",
        "suggestion_1": "Migra a un password manager (Bitwarden gratis, KeePassXC, 1Password, Proton Pass).",
        "suggestion_2": "Disabilita &ldquo;salva password&rdquo; nel browser (Settings &gt; Password Manager OPPURE policy HKCU\\Software\\Policies\\Google\\Chrome\\PasswordManagerEnabled = 0).",
        "suggestion_3": "Cancella tutte le password salvate dopo aver migrato: <code>chrome://settings/passwords</code>.",
        "suggestion_4": "Abilita 2FA su tutti gli account CRITICAL.",
        "suggestion_5": "Per gli account riutilizzati, usa password uniche generate dal manager.",
        "cisco_anyconnect_header": "Profili Cisco AnyConnect",
    },

    # ─────────────────────────── ENGLISH ─────────────────────────────
    "en": {
        "html_lang": "en",
        "report_title": "Infostealer Audit Report",
        "generated_at": "Generated",
        "user_label": "user",
        "machine_label": "machine",
        "passwords_masked": "passwords masked",
        "showpassword_mode": "SHOWPASSWORD MODE",
        "overall_risk_prefix": "Overall risk",
        "risk_CRITICAL": "CRITICAL",
        "risk_HIGH": "HIGH",
        "risk_MEDIUM": "MEDIUM",
        "risk_LOW": "LOW",
        "stat_browsers": "Browsers installed",
        "stat_decrypted": "Decrypted credentials (at risk)",
        "stat_protected": "v20-protected credentials",
        "stat_outdated": "Outdated browsers",
        "stat_targets": "Infostealer targets found",
        "stat_tools": "Recovery tools installed",
        "stat_lazagne": "LaZagne-Light credentials found",
        "tab_overview": "Overview",
        "tab_accounts": "Accounts by browser",
        "tab_versions": "Versions & CVE",
        "tab_targets": "Infostealer targets",
        "tab_lazagne": "LaZagne Light",
        "tab_legacy": "Legacy credentials",
        "tab_tools": "Recovery tools",
        "tab_fixes": "Fix recommendations",
        "tab_timeline": "ABE Timeline",
        "section_overview": "Executive summary",
        "overview_info_box": (
            "What this report means: it lists every target that an infostealer "
            "(LummaC2, RedLine, Vidar, Glove Stealer, Phemedrone, etc.) would look "
            "for on your PC. For each item it reports exposure status, attacker value, "
            "known bypass techniques, and recommended fix with release date."
        ),
        "col_browser": "Browser",
        "col_installed_version": "Installed version",
        "col_current_stable": "Current stable",
        "col_diff": "Difference",
        "col_risk": "Risk",
        "up_to_date": "up-to-date",
        "section_accounts": "Decrypted accounts by browser",
        "showpassword_warning": (
            "MODE: SHOWPASSWORD — passwords are in clear text. "
            "Treat this file as sensitive data."
        ),
        "masked_info": (
            "Passwords are masked. To view them in plain text, "
            "run again with <code class=\"code\">--showpassword</code>."
        ),
        "profile_label": "Profile",
        "credentials_word": "credentials",
        "decrypted_word": "decrypted",
        "protected_word": "v20-protected",
        "col_url": "URL",
        "col_username": "Username",
        "col_password": "Password",
        "col_cipher": "Cipher",
        "col_category": "Category",
        "v20_protected_tag": "[v20-PROTECTED]",
        "section_versions": "Installed versions vs. latest stable",
        "col_released": "Released",
        "col_major_gap": "Major gap",
        "col_source": "Source",
        "vuln_known_header": "Known vulnerabilities for installed browsers",
        "decrypt_diff_label": "Decrypt difficulty",
        "risk_score_label": "Risk score",
        "bypass_section_label": "Applicable bypass techniques",
        "used_by_label": "Used by:",
        "ref_label": "Ref",
        "fix_prefix": "Fix:",
        "released_label": "released",
        "section_targets": "Infostealer targets detected",
        "targets_intro": "Classic targets. PRESENCE ONLY — no data exfiltration.",
        "col_target": "Target",
        "col_status": "Status",
        "col_value": "Value",
        "col_details": "Details",
        "status_present": "✓ PRESENT",
        "section_lazagne": "LaZagne Light — pure-Python replica",
        "lazagne_intro": (
            "Built-in implementation of the most useful LaZagne categories. "
            "Zero external dependencies, zero PUA-flagged binaries. "
            "Documented public algorithms."
        ),
        "wifi_header": "Wi-Fi profiles",
        "wifi_na": "(n/a)",
        "wifi_key_msg": "profiles with visible key (requires admin for cleartext key).",
        "putty_header": "PuTTY sessions",
        "putty_note": "PuTTY does NOT save SSH passwords by design. Showing only host/user/port of configured sessions.",
        "winscp_header": "WinSCP sessions",
        "winscp_warning": "WinSCP uses a custom XOR algorithm DECRYPTABLE in user-mode.",
        "winscp_decrypted_msg": "passwords decrypted.",
        "git_header": "Git credentials",
        "git_warning": (
            "The file <code class=\"code\">~/.git-credentials</code> "
            "is in <strong>PLAINTEXT</strong> by design. Any user-mode process "
            "reads it instantly."
        ),
        "openvpn_header": "OpenVPN configs",
        "filezilla_header": "FileZilla saved sites",
        "filezilla_warning": "FileZilla stores passwords in <code class=\"code\">sitemanager.xml</code> base64-encoded (NOT encrypted).",
        "thunderbird_header": "Thunderbird credentials",
        "thunderbird_warning": "Thunderbird uses the same NSS scheme as Firefox. Without Primary Password = decryptable in user-mode.",
        "pidgin_header": "Pidgin chat accounts",
        "pidgin_warning": "Pidgin stores passwords in PLAINTEXT in <code>accounts.xml</code>.",
        "dbviz_header": "DBVisualizer databases",
        "rdp_header": "RDP files",
        "chat_header": "Chat/messaging apps (presence)",
        "col_ssid": "SSID",
        "col_auth": "Auth",
        "col_key_cleartext": "Key (cleartext)",
        "col_session": "Session",
        "col_host": "Host",
        "col_port": "Port",
        "col_user": "User",
        "col_protocol": "Protocol",
        "col_config": "Config",
        "col_auth_file": "Auth file",
        "col_file": "File",
        "col_pwd_encrypted": "Pwd encrypted",
        "col_alias": "Alias",
        "col_db_url": "DB URL",
        "col_app_name": "App",
        "col_path": "Path",
        "col_profile": "Profile",
        "col_type": "Type",
        "col_persistence": "Persistence",
        "yes_str": "YES",
        "no_str": "NO",
        "section_legacy": "Windows legacy credentials",
        "credman_header": "Windows Credential Manager",
        "vault_header": "IE / Edge Legacy Vault",
        "wifi_saved_header": "Saved Wi-Fi profiles",
        "outlook_header": "Outlook profiles",
        "entries_word": "entries",
        "section_tools": "Recovery tools installed &amp; ready",
        "tools_intro": (
            "Publicly available open-source tools. Missing ones are automatically "
            "installed via pip. PUA-flagged tools require explicit opt-in with "
            "<code class=\"code\">--install-flagged-tools</code>."
        ),
        "status_installed": "✓ INSTALLED",
        "status_missing": "MISSING",
        "tag_new": "NEW",
        "tag_upgraded": "UPGRADED",
        "tag_pua": "PUA-flagged",
        "section_fixes": "Fix recommendations",
        "why_label": "Why:",
        "how_label": "How:",
        "section_timeline": "App-Bound Encryption Timeline (Chrome 127+)",
        "tl_fix_label": "Fix:",
        "showpassword_file_warning": "[!] CONTAINS PLAIN TEXT PASSWORDS. Delete after the audit.",
        # pwd_audit-specific keys
        "pwd_report_title": "Browser Credential Audit",
        "pwd_h1": "Browser Credential Audit",
        "pwd_what_box_title": "What this report means:",
        "pwd_what_box_text": (
            "these are EXACTLY the credentials that an infostealer "
            "(RedLine, Lumma, Kepavll, etc.) would exfiltrate from your PC "
            "if executed in your Windows user context. The malware performs the exact "
            "same decryption this tool just did (DPAPI + AES-GCM)."
        ),
        "pwd_aggressive_note": (
            "<strong style=\"color:#c00\">AGGRESSIVE MODE active:</strong> "
            "in addition to user-mode credentials (v10), the tool attempted to bypass "
            "the <code>v20 App-Bound Encryption</code> by creating a "
            "<strong>scheduled task as SYSTEM</strong>. This simulates an infostealer "
            "elevated to admin (such as those using UAC bypass or COM elevation)."
        ),
        "stat_total_creds": "total credentials",
        "stat_decrypted_vm": "DECRYPTED<br>(user-mode vulnerable)",
        "stat_protected_v20_abe": "PROTECTED v20-ABE<br>(require SYSTEM)",
        "stat_weak_pwd": "WEAK passwords",
        "stat_reused_pwd": "accounts with reused password",
        "abe_info_title": "Chrome 127+ App-Bound Encryption (v20):",
        "abe_info_text": (
            "Passwords saved by an up-to-date Chrome (since July 2024) are encrypted twice: "
            "once with user DPAPI, once with SYSTEM DPAPI. A user-mode infostealer "
            "(the vast majority) CANNOT decrypt them. "
            "The {n} 'PROTECTED' credentials above are in this state."
        ),
        "reuse_section_title": (
            "Reused passwords (a single breach compromises all these sites)"
        ),
        "reuse_same_pwd": "Same password",
        "reuse_used_on": "used on",
        "reuse_sites_suffix": "sites",
        "all_creds_title": "All credentials (sorted by severity + weakness)",
        "col_sev": "Sev",
        "col_len": "Len",
        "col_strength": "Strength",
        "col_issues": "Issues",
        "protected_v20_abe_tag": "[PROTECTED v20-ABE]",
        "strength_guide_title": "How to interpret strength levels",
        "strength_very_weak_desc": "dictionary password / obvious sequences / very short. Cracked in seconds.",
        "strength_weak_desc": "short or single-class. Cracked in minutes/hours with targeted brute-force.",
        "strength_medium_desc": "decent length + 2-3 classes. Cracked in days/weeks.",
        "strength_strong_desc": "12+ chars, 3-4 classes, 60+ bits entropy. Cracked in months/years.",
        "strength_very_strong_desc": "16+ chars, high entropy, 4 classes. Technically unbreakable by brute-force.",
        "tech_notes_title": "Technical notes on DPAPI and AES-GCM",
        "tech_note_1": "Chrome/Edge store passwords as <code>v10</code> blobs + nonce(12B) + ciphertext + tag(16B).",
        "tech_note_2": "The AES-256 key is in <code>Local State</code>, encrypted via DPAPI using the Windows user's credentials.",
        "tech_note_3": "DPAPI (<code>CryptUnprotectData</code>) uses the Windows user's master key + SID + password (or PIN/Hello).",
        "tech_note_4": "Malware running as your Windows user can do all of this. Admin is NOT required.",
        "tech_note_5": "To prevent future exfiltration: <strong>stop saving passwords in the browser</strong>, use a dedicated password manager.",
        "suggestions_title": "Recommendations:",
        "suggestion_1": "Migrate to a password manager (Bitwarden free, KeePassXC, 1Password, Proton Pass).",
        "suggestion_2": "Disable 'save passwords' in the browser (Settings &gt; Password Manager OR registry policy HKCU\\Software\\Policies\\Google\\Chrome\\PasswordManagerEnabled = 0).",
        "suggestion_3": "Delete all saved passwords after migrating: <code>chrome://settings/passwords</code>.",
        "suggestion_4": "Enable 2FA on all CRITICAL accounts.",
        "suggestion_5": "For reused accounts, use unique passwords generated by the manager.",
        "cisco_anyconnect_header": "Cisco AnyConnect profiles",
    },

    # ──────────────────────────── FRANÇAIS ───────────────────────────
    "fr": {
        "html_lang": "fr",
        "report_title": "Rapport d’audit Infostealer",
        "generated_at": "Généré",
        "user_label": "utilisateur",
        "machine_label": "machine",
        "passwords_masked": "mots de passe masqués",
        "showpassword_mode": "MODE AFFICHAGE MOTS DE PASSE",
        "overall_risk_prefix": "Risque global",
        "risk_CRITICAL": "CRITIQUE",
        "risk_HIGH": "ÉLEVÉ",
        "risk_MEDIUM": "MOYEN",
        "risk_LOW": "FAIBLE",
        "stat_browsers": "Navigateurs installés",
        "stat_decrypted": "Identifiants déchiffrés (vulnérables)",
        "stat_protected": "Identifiants v20-protégés",
        "stat_outdated": "Navigateurs obsolètes",
        "stat_targets": "Cibles infostealer détectées",
        "stat_tools": "Outils de récupération installés",
        "stat_lazagne": "Identifiants LaZagne-Light trouvés",
        "tab_overview": "Vue d’ensemble",
        "tab_accounts": "Comptes par navigateur",
        "tab_versions": "Versions & CVE",
        "tab_targets": "Cibles infostealer",
        "tab_lazagne": "LaZagne Light",
        "tab_legacy": "Identifiants legacy",
        "tab_tools": "Outils de récupération",
        "tab_fixes": "Recommandations",
        "tab_timeline": "Chronologie ABE",
        "section_overview": "Résumé exécutif",
        "overview_info_box": (
            "Ce que ce rapport signifie : il liste toutes les cibles qu’un "
            "infostealer (LummaC2, RedLine, Vidar, Glove Stealer, Phemedrone, etc.) "
            "rechercherait sur votre PC. Pour chaque élément il indique l’état "
            "d’exposition, la valeur pour l’attaquant, les techniques de "
            "contournement connues et le correctif recommandé avec sa date de publication."
        ),
        "col_browser": "Navigateur",
        "col_installed_version": "Version installée",
        "col_current_stable": "Version stable actuelle",
        "col_diff": "Différence",
        "col_risk": "Risque",
        "up_to_date": "à jour",
        "section_accounts": "Comptes déchiffrés par navigateur",
        "showpassword_warning": (
            "MODE : AFFICHAGE MDP — les mots de passe sont en clair. "
            "Traitez ce fichier comme une donnée sensible."
        ),
        "masked_info": (
            "Les mots de passe sont masqués. Pour les afficher en clair, "
            "relancez avec <code class=\"code\">--showpassword</code>."
        ),
        "profile_label": "Profil",
        "credentials_word": "identifiants",
        "decrypted_word": "déchiffrés",
        "protected_word": "v20-protégés",
        "col_url": "URL",
        "col_username": "Nom d’utilisateur",
        "col_password": "Mot de passe",
        "col_cipher": "Chiffrement",
        "col_category": "Catégorie",
        "v20_protected_tag": "[v20-PROTÉGÉ]",
        "section_versions": "Versions installées vs. dernières versions stables",
        "col_released": "Publiée",
        "col_major_gap": "Écart majeur",
        "col_source": "Source",
        "vuln_known_header": "Vulnérabilités connues pour les navigateurs installés",
        "decrypt_diff_label": "Difficulté de déchiffrement",
        "risk_score_label": "Score de risque",
        "bypass_section_label": "Techniques de contournement applicables",
        "used_by_label": "Utilisé par :",
        "ref_label": "Réf",
        "fix_prefix": "Correctif :",
        "released_label": "publié",
        "section_targets": "Cibles infostealer détectées",
        "targets_intro": "Cibles classiques. PRÉSENCE UNIQUEMENT — aucune exfiltration.",
        "col_target": "Cible",
        "col_status": "Statut",
        "col_value": "Valeur",
        "col_details": "Détails",
        "status_present": "✓ PRÉSENT",
        "section_lazagne": "LaZagne Light — réplique Python",
        "lazagne_intro": (
            "Implémentation interne des catégories LaZagne les plus utiles. "
            "Zéro dépendance externe, zéro binaire marqué PUA. "
            "Algorithmes publics documentés."
        ),
        "wifi_header": "Profils Wi-Fi",
        "wifi_na": "(n/a)",
        "wifi_key_msg": "profils avec clé visible (nécessite admin pour la clé en clair).",
        "putty_header": "Sessions PuTTY",
        "putty_note": "PuTTY NE sauvegarde PAS les mots de passe SSH par conception. Affichage uniquement host/user/port.",
        "winscp_header": "Sessions WinSCP",
        "winscp_warning": "WinSCP utilise un algorithme XOR personnalisé DÉCHIFFRABLE en mode utilisateur.",
        "winscp_decrypted_msg": "mots de passe déchiffrés.",
        "git_header": "Identifiants Git",
        "git_warning": (
            "Le fichier <code class=\"code\">~/.git-credentials</code> "
            "est en <strong>CLAIR</strong> par conception. Tout processus "
            "utilisateur peut le lire instantanément."
        ),
        "openvpn_header": "Configurations OpenVPN",
        "filezilla_header": "Sites sauvegardés FileZilla",
        "filezilla_warning": "FileZilla stocke les mots de passe dans <code class=\"code\">sitemanager.xml</code> en base64 (NON chiffrés).",
        "thunderbird_header": "Identifiants Thunderbird",
        "thunderbird_warning": "Thunderbird utilise le même schéma NSS que Firefox. Sans mot de passe principal = déchiffrable.",
        "pidgin_header": "Comptes Pidgin",
        "pidgin_warning": "Pidgin stocke les mots de passe en CLAIR dans <code>accounts.xml</code>.",
        "dbviz_header": "Bases de données DBVisualizer",
        "rdp_header": "Fichiers RDP",
        "chat_header": "Applications de messagerie (présence)",
        "col_ssid": "SSID",
        "col_auth": "Auth",
        "col_key_cleartext": "Clé (en clair)",
        "col_session": "Session",
        "col_host": "Hôte",
        "col_port": "Port",
        "col_user": "Utilisateur",
        "col_protocol": "Protocole",
        "col_config": "Config",
        "col_auth_file": "Fichier auth",
        "col_file": "Fichier",
        "col_pwd_encrypted": "Mot de passe chiffré",
        "col_alias": "Alias",
        "col_db_url": "URL BD",
        "col_app_name": "Application",
        "col_path": "Chemin",
        "col_profile": "Profil",
        "col_type": "Type",
        "col_persistence": "Persistance",
        "yes_str": "OUI",
        "no_str": "NON",
        "section_legacy": "Identifiants Windows legacy",
        "credman_header": "Gestionnaire d’informations d’identification Windows",
        "vault_header": "Coffre-fort IE / Edge Legacy",
        "wifi_saved_header": "Profils Wi-Fi enregistrés",
        "outlook_header": "Profils Outlook",
        "entries_word": "entrées",
        "section_tools": "Outils de récupération installés &amp; prêts",
        "tools_intro": (
            "Outils open source disponibles publiquement. Les manquants sont "
            "installés automatiquement via pip. Les outils marqués PUA nécessitent "
            "un opt-in explicite avec <code class=\"code\">--install-flagged-tools</code>."
        ),
        "status_installed": "✓ INSTALLÉ",
        "status_missing": "MANQUANT",
        "tag_new": "NOUVEAU",
        "tag_upgraded": "MIS À JOUR",
        "tag_pua": "Marqué PUA",
        "section_fixes": "Recommandations de correction",
        "why_label": "Pourquoi :",
        "how_label": "Comment :",
        "section_timeline": "Chronologie App-Bound Encryption (Chrome 127+)",
        "tl_fix_label": "Correctif :",
        "showpassword_file_warning": "[!] CONTIENT DES MOTS DE PASSE EN CLAIR. Supprimez après l’audit.",
        # pwd_audit-specific keys
        "pwd_report_title": "Audit des identifiants du navigateur",
        "pwd_h1": "Audit des identifiants du navigateur",
        "pwd_what_box_title": "Ce que ce rapport signifie :",
        "pwd_what_box_text": (
            "ce sont EXACTEMENT les identifiants qu’un infostealer "
            "(RedLine, Lumma, Kepavll, etc.) pourrait exfiltrer de votre PC "
            "s’il était exécuté dans le contexte de votre utilisateur Windows. "
            "Le malware effectue exactement le même déchiffrement que cet outil (DPAPI + AES-GCM)."
        ),
        "pwd_aggressive_note": (
            "<strong style=\"color:#c00\">MODE AGRESSIF actif :</strong> "
            "en plus des identifiants en mode utilisateur (v10), l’outil a tenté de contourner "
            "le <code>v20 App-Bound Encryption</code> en créant une "
            "<strong>tâche planifiée en tant que SYSTEM</strong>. Cela simule un infostealer "
            "élevé en admin (comme ceux utilisant le contournement UAC ou l’élévation COM)."
        ),
        "stat_total_creds": "identifiants au total",
        "stat_decrypted_vm": "DÉCHIFFRÉS<br>(vulnérables mode utilisateur)",
        "stat_protected_v20_abe": "PROTÉGÉS v20-ABE<br>(nécessitent SYSTEM)",
        "stat_weak_pwd": "mots de passe FAIBLES",
        "stat_reused_pwd": "comptes avec mot de passe RÉUTILISÉ",
        "abe_info_title": "Chrome 127+ App-Bound Encryption (v20) :",
        "abe_info_text": (
            "Les mots de passe enregistrés par Chrome à jour (depuis juillet 2024) sont "
            "chiffrés deux fois : une fois avec DPAPI de l’utilisateur, une fois avec DPAPI "
            "de SYSTEM. Un infostealer en mode utilisateur normal (la grande majorité) NE peut "
            "PAS les déchiffrer. Les {n} identifiants «PROTÉGÉS» ci-dessus sont dans cet état."
        ),
        "reuse_section_title": (
            "Mots de passe réutilisés (une seule fuite compromet tous ces sites)"
        ),
        "reuse_same_pwd": "Même mot de passe",
        "reuse_used_on": "utilisé sur",
        "reuse_sites_suffix": "sites",
        "all_creds_title": "Tous les identifiants (triés par sévérité + faiblesse)",
        "col_sev": "Sév",
        "col_len": "Long",
        "col_strength": "Robustesse",
        "col_issues": "Problèmes",
        "protected_v20_abe_tag": "[PROTÉGÉ v20-ABE]",
        "strength_guide_title": "Comment interpréter les niveaux de robustesse",
        "strength_very_weak_desc": "mot de passe dictionnaire / séquences évidentes / très court. Cracké en secondes.",
        "strength_weak_desc": "court ou monoclasse. Cracké en minutes/heures avec brute-force ciblé.",
        "strength_medium_desc": "longueur correcte + 2-3 classes. Cracké en jours/semaines.",
        "strength_strong_desc": "12+ caractères, 3-4 classes, entropie 60+ bits. Cracké en mois/années.",
        "strength_very_strong_desc": "16+ caractères, haute entropie, 4 classes. Techniquement incassable par brute-force.",
        "tech_notes_title": "Notes techniques sur DPAPI et AES-GCM",
        "tech_note_1": "Chrome/Edge stockent les mots de passe comme blobs <code>v10</code> + nonce(12B) + texte chiffré + tag(16B).",
        "tech_note_2": "La clé AES-256 est dans <code>Local State</code>, chiffrée via DPAPI avec les identifiants Windows de l’utilisateur.",
        "tech_note_3": "DPAPI (<code>CryptUnprotectData</code>) utilise la clé maître de l’utilisateur Windows + son SID + son mot de passe (ou PIN/Hello).",
        "tech_note_4": "Un malware s’exécutant sous votre utilisateur Windows peut faire tout cela. Aucun droit admin n’est requis.",
        "tech_note_5": "Pour éviter l’exfiltration future : <strong>ne pas enregistrer les mots de passe dans le navigateur</strong>, utiliser un gestionnaire dédié.",
        "suggestions_title": "Recommandations :",
        "suggestion_1": "Migrez vers un gestionnaire de mots de passe (Bitwarden gratuit, KeePassXC, 1Password, Proton Pass).",
        "suggestion_2": "Désactivez «enregistrer les mots de passe» dans le navigateur (Paramètres &gt; Gestionnaire de mots de passe OU stratégie registre HKCU\\Software\\Policies\\Google\\Chrome\\PasswordManagerEnabled = 0).",
        "suggestion_3": "Supprimez tous les mots de passe enregistrés après migration : <code>chrome://settings/passwords</code>.",
        "suggestion_4": "Activez l’authentification à deux facteurs sur tous les comptes CRITICAL.",
        "suggestion_5": "Pour les comptes réutilisés, utilisez des mots de passe uniques générés par le gestionnaire.",
        "cisco_anyconnect_header": "Profils Cisco AnyConnect",
    },

    # ──────────────────────────── DEUTSCH ────────────────────────────
    "de": {
        "html_lang": "de",
        "report_title": "Infostealer-Audit-Bericht",
        "generated_at": "Erstellt",
        "user_label": "Benutzer",
        "machine_label": "Rechner",
        "passwords_masked": "Passwörter maskiert",
        "showpassword_mode": "PASSWORT-ANZEIGE-MODUS",
        "overall_risk_prefix": "Gesamtrisiko",
        "risk_CRITICAL": "KRITISCH",
        "risk_HIGH": "HOCH",
        "risk_MEDIUM": "MITTEL",
        "risk_LOW": "NIEDRIG",
        "stat_browsers": "Installierte Browser",
        "stat_decrypted": "Entschlüsselte Anmeldedaten (gefährdet)",
        "stat_protected": "v20-geschützte Anmeldedaten",
        "stat_outdated": "Veraltete Browser",
        "stat_targets": "Gefundene Infostealer-Ziele",
        "stat_tools": "Installierte Wiederherstellungstools",
        "stat_lazagne": "LaZagne-Light-Anmeldedaten gefunden",
        "tab_overview": "Übersicht",
        "tab_accounts": "Konten nach Browser",
        "tab_versions": "Versionen & CVE",
        "tab_targets": "Infostealer-Ziele",
        "tab_lazagne": "LaZagne Light",
        "tab_legacy": "Legacy-Anmeldedaten",
        "tab_tools": "Wiederherstellungstools",
        "tab_fixes": "Empfehlungen",
        "tab_timeline": "ABE-Zeitstrahl",
        "section_overview": "Zusammenfassung",
        "overview_info_box": (
            "Was dieser Bericht bedeutet: Er listet alle Ziele auf, die ein Infostealer "
            "(LummaC2, RedLine, Vidar, Glove Stealer, Phemedrone usw.) auf Ihrem PC "
            "suchen würde. Für jeden Eintrag werden Expositionsstatus, "
            "Angreiferwert, bekannte Bypass-Techniken und empfohlene Korrekturen "
            "mit Veröffentlichungsdatum angegeben."
        ),
        "col_browser": "Browser",
        "col_installed_version": "Installierte Version",
        "col_current_stable": "Aktuelle Stable-Version",
        "col_diff": "Unterschied",
        "col_risk": "Risiko",
        "up_to_date": "aktuell",
        "section_accounts": "Entschlüsselte Konten nach Browser",
        "showpassword_warning": (
            "MODUS: PASSWÖRTER ANZEIGEN — Passwörter sind im Klartext. "
            "Behandeln Sie diese Datei als vertraulich."
        ),
        "masked_info": (
            "Passwörter sind maskiert. Zur Klartextanzeige erneut mit "
            "<code class=\"code\">--showpassword</code> ausführen."
        ),
        "profile_label": "Profil",
        "credentials_word": "Anmeldedaten",
        "decrypted_word": "entschlüsselt",
        "protected_word": "v20-geschützt",
        "col_url": "URL",
        "col_username": "Benutzername",
        "col_password": "Passwort",
        "col_cipher": "Verschlüsselung",
        "col_category": "Kategorie",
        "v20_protected_tag": "[v20-GESCHÜTZT]",
        "section_versions": "Installierte Versionen vs. aktuelle Stable-Versionen",
        "col_released": "Veröffentlicht",
        "col_major_gap": "Versions-Lücke",
        "col_source": "Quelle",
        "vuln_known_header": "Bekannte Schwachstellen für installierte Browser",
        "decrypt_diff_label": "Entschlüsselungsschwierigkeit",
        "risk_score_label": "Risiko-Score",
        "bypass_section_label": "Anwendbare Bypass-Techniken",
        "used_by_label": "Verwendet von:",
        "ref_label": "Ref",
        "fix_prefix": "Korrektur:",
        "released_label": "veröffentlicht",
        "section_targets": "Erkannte Infostealer-Ziele",
        "targets_intro": "Klassische Ziele. NUR PRÄSENZ — keine Datenexfiltration.",
        "col_target": "Ziel",
        "col_status": "Status",
        "col_value": "Wert",
        "col_details": "Details",
        "status_present": "✓ VORHANDEN",
        "section_lazagne": "LaZagne Light — Python-Replik",
        "lazagne_intro": (
            "Interne Implementierung der nützlichsten LaZagne-Kategorien. "
            "Keine externen Abhängigkeiten, keine PUA-markierten Binärdateien. "
            "Dokumentierte öffentliche Algorithmen."
        ),
        "wifi_header": "WLAN-Profile",
        "wifi_na": "(n/v)",
        "wifi_key_msg": "Profile mit sichtbarem Schlüssel (Admin für Klartext-Schlüssel erforderlich).",
        "putty_header": "PuTTY-Sitzungen",
        "putty_note": "PuTTY speichert SSH-Passwörter konstruktionsbedingt NICHT. Zeige nur Host/Benutzer/Port.",
        "winscp_header": "WinSCP-Sitzungen",
        "winscp_warning": "WinSCP verwendet einen benutzerdefinierten XOR-Algorithmus, der im Benutzermodus ENTSCHLÜSSELBAR ist.",
        "winscp_decrypted_msg": "Passwörter entschlüsselt.",
        "git_header": "Git-Anmeldedaten",
        "git_warning": (
            "Die Datei <code class=\"code\">~/.git-credentials</code> "
            "ist konstruktionsbedingt im <strong>KLARTEXT</strong>. Jeder Prozess "
            "im Benutzermodus kann sie sofort lesen."
        ),
        "openvpn_header": "OpenVPN-Konfigurationen",
        "filezilla_header": "Gespeicherte FileZilla-Sites",
        "filezilla_warning": "FileZilla speichert Passwörter in <code class=\"code\">sitemanager.xml</code> base64-kodiert (NICHT verschlüsselt).",
        "thunderbird_header": "Thunderbird-Anmeldedaten",
        "thunderbird_warning": "Thunderbird verwendet dasselbe NSS-Schema wie Firefox. Ohne Hauptpasswort = im Benutzermodus entschlüsselbar.",
        "pidgin_header": "Pidgin-Chat-Konten",
        "pidgin_warning": "Pidgin speichert Passwörter im KLARTEXT in <code>accounts.xml</code>.",
        "dbviz_header": "DBVisualizer-Datenbanken",
        "rdp_header": "RDP-Dateien",
        "chat_header": "Messaging-Apps (Präsenz)",
        "col_ssid": "SSID",
        "col_auth": "Auth",
        "col_key_cleartext": "Schlüssel (Klartext)",
        "col_session": "Sitzung",
        "col_host": "Host",
        "col_port": "Port",
        "col_user": "Benutzer",
        "col_protocol": "Protokoll",
        "col_config": "Konfiguration",
        "col_auth_file": "Auth-Datei",
        "col_file": "Datei",
        "col_pwd_encrypted": "Verschlüsseltes Passwort",
        "col_alias": "Alias",
        "col_db_url": "DB-URL",
        "col_app_name": "App",
        "col_path": "Pfad",
        "col_profile": "Profil",
        "col_type": "Typ",
        "col_persistence": "Persistenz",
        "yes_str": "JA",
        "no_str": "NEIN",
        "section_legacy": "Windows-Legacy-Anmeldedaten",
        "credman_header": "Windows-Anmeldeinformationsverwaltung",
        "vault_header": "IE / Edge Legacy-Tresor",
        "wifi_saved_header": "Gespeicherte WLAN-Profile",
        "outlook_header": "Outlook-Profile",
        "entries_word": "Einträge",
        "section_tools": "Wiederherstellungstools installiert &amp; bereit",
        "tools_intro": (
            "Öffentlich verfügbare Open-Source-Tools. Fehlende werden automatisch "
            "über pip installiert. PUA-markierte Tools erfordern explizites Opt-in "
            "mit <code class=\"code\">--install-flagged-tools</code>."
        ),
        "status_installed": "✓ INSTALLIERT",
        "status_missing": "FEHLEND",
        "tag_new": "NEU",
        "tag_upgraded": "AKTUALISIERT",
        "tag_pua": "PUA-markiert",
        "section_fixes": "Korrekturen und Empfehlungen",
        "why_label": "Warum:",
        "how_label": "Wie:",
        "section_timeline": "App-Bound Encryption Zeitstrahl (Chrome 127+)",
        "tl_fix_label": "Korrektur:",
        "showpassword_file_warning": "[!] ENTHÄLT KLARTEXT-PASSWÖRTER. Nach dem Audit löschen.",
        # pwd_audit-specific keys
        "pwd_report_title": "Browser-Anmeldedaten-Audit",
        "pwd_h1": "Browser-Anmeldedaten-Audit",
        "pwd_what_box_title": "Was dieser Bericht bedeutet:",
        "pwd_what_box_text": (
            "Das sind GENAU die Anmeldedaten, die ein Infostealer "
            "(RedLine, Lumma, Kepavll usw.) von Ihrem PC exfiltrieren würde, "
            "wenn er im Kontext Ihres Windows-Benutzers ausgeführt wird. "
            "Der Schadcode führt dieselbe Entschlüsselung durch wie dieses Tool (DPAPI + AES-GCM)."
        ),
        "pwd_aggressive_note": (
            "<strong style=\"color:#c00\">AGGRESSIVER MODUS aktiv:</strong> "
            "Zusätzlich zu den Benutzermodus-Anmeldedaten (v10) hat das Tool versucht, "
            "die <code>v20 App-Bound Encryption</code> zu umgehen, indem eine "
            "<strong>geplante Aufgabe als SYSTEM</strong> erstellt wurde. Dies simuliert "
            "einen auf Admin erweiterten Infostealer (wie solche mit UAC-Bypass oder COM-Elevation)."
        ),
        "stat_total_creds": "Anmeldedaten gesamt",
        "stat_decrypted_vm": "ENTSCHLÜSSELT<br>(Benutzermodus gefährdet)",
        "stat_protected_v20_abe": "GESCHÜTZT v20-ABE<br>(erfordern SYSTEM)",
        "stat_weak_pwd": "SCHWACHE Passwörter",
        "stat_reused_pwd": "Konten mit WIEDERVERWENDETEM Passwort",
        "abe_info_title": "Chrome 127+ App-Bound Encryption (v20):",
        "abe_info_text": (
            "Von aktuellem Chrome (ab Juli 2024) gespeicherte Passwörter sind doppelt verschlüsselt: "
            "einmal mit Benutzer-DPAPI, einmal mit SYSTEM-DPAPI. Ein Infostealer im normalen "
            "Benutzermodus (die große Mehrheit) KANN sie nicht entschlüsseln. "
            "Die {n} oben als 'GESCHÜTZT' markierten Anmeldedaten befinden sich in diesem Zustand."
        ),
        "reuse_section_title": (
            "Wiederverwendete Passwörter (ein einziger Diebstahl kompromittiert alle diese Seiten)"
        ),
        "reuse_same_pwd": "Gleiches Passwort",
        "reuse_used_on": "verwendet auf",
        "reuse_sites_suffix": "Seiten",
        "all_creds_title": "Alle Anmeldedaten (sortiert nach Kritikalität + Schwäche)",
        "col_sev": "Krit",
        "col_len": "Len",
        "col_strength": "Stärke",
        "col_issues": "Probleme",
        "protected_v20_abe_tag": "[GESCHÜTZT v20-ABE]",
        "strength_guide_title": "Stärkestufen verstehen",
        "strength_very_weak_desc": "Wörterbuchpasswort / offensichtliche Sequenzen / sehr kurz. In Sekunden geknackt.",
        "strength_weak_desc": "Kurz oder einklassig. In Minuten/Stunden mit gezieltem Brute-Force geknackt.",
        "strength_medium_desc": "Angemessene Länge + 2-3 Klassen. In Tagen/Wochen geknackt.",
        "strength_strong_desc": "12+ Zeichen, 3-4 Klassen, 60+ Bit Entropie. In Monaten/Jahren geknackt.",
        "strength_very_strong_desc": "16+ Zeichen, hohe Entropie, 4 Klassen. Technisch unknackbar per Brute-Force.",
        "tech_notes_title": "Technische Hinweise zu DPAPI und AES-GCM",
        "tech_note_1": "Chrome/Edge speichern Passwörter als <code>v10</code>-Blobs + Nonce(12B) + Geheimtext + Tag(16B).",
        "tech_note_2": "Der AES-256-Schlüssel befindet sich in <code>Local State</code>, via DPAPI mit den Windows-Benutzeranmeldedaten verschlüsselt.",
        "tech_note_3": "DPAPI (<code>CryptUnprotectData</code>) verwendet den Master-Key des Windows-Benutzers + seine SID + sein Passwort (oder PIN/Hello).",
        "tech_note_4": "Schadsoftware, die unter Ihrem Windows-Benutzer läuft, kann all das tun. Admin ist NICHT erforderlich.",
        "tech_note_5": "Um künftige Exfiltration zu verhindern: <strong>Passwörter nicht im Browser speichern</strong>, einen dedizierten Passwort-Manager verwenden.",
        "suggestions_title": "Empfehlungen:",
        "suggestion_1": "Wechseln Sie zu einem Passwort-Manager (Bitwarden kostenlos, KeePassXC, 1Password, Proton Pass).",
        "suggestion_2": "Deaktivieren Sie 'Passwörter speichern' im Browser (Einstellungen &gt; Passwort-Manager ODER Registry-Richtlinie HKCU\\Software\\Policies\\Google\\Chrome\\PasswordManagerEnabled = 0).",
        "suggestion_3": "Löschen Sie alle gespeicherten Passwörter nach der Migration: <code>chrome://settings/passwords</code>.",
        "suggestion_4": "Aktivieren Sie 2FA für alle CRITICAL-Konten.",
        "suggestion_5": "Verwenden Sie für wiederverwendete Konten einzigartige, vom Manager generierte Passwörter.",
        "cisco_anyconnect_header": "Cisco AnyConnect-Profile",
    },

    # ──────────────────────────── ESPAÑOL ────────────────────────────
    "es": {
        "html_lang": "es",
        "report_title": "Informe de Auditoría Infostealer",
        "generated_at": "Generado",
        "user_label": "usuario",
        "machine_label": "máquina",
        "passwords_masked": "contraseñas enmascaradas",
        "showpassword_mode": "MODO MOSTRAR CONTRASEÑAS",
        "overall_risk_prefix": "Riesgo global",
        "risk_CRITICAL": "CRÍTICO",
        "risk_HIGH": "ALTO",
        "risk_MEDIUM": "MEDIO",
        "risk_LOW": "BAJO",
        "stat_browsers": "Navegadores instalados",
        "stat_decrypted": "Credenciales descifradas (vulnerables)",
        "stat_protected": "Credenciales v20-protegidas",
        "stat_outdated": "Navegadores desactualizados",
        "stat_targets": "Objetivos infostealer encontrados",
        "stat_tools": "Herramientas de recuperación instaladas",
        "stat_lazagne": "Credenciales LaZagne-Light encontradas",
        "tab_overview": "Resumen",
        "tab_accounts": "Cuentas por navegador",
        "tab_versions": "Versiones & CVE",
        "tab_targets": "Objetivos infostealer",
        "tab_lazagne": "LaZagne Light",
        "tab_legacy": "Credenciales heredadas",
        "tab_tools": "Herramientas de recuperación",
        "tab_fixes": "Recomendaciones",
        "tab_timeline": "Línea de tiempo ABE",
        "section_overview": "Resumen ejecutivo",
        "overview_info_box": (
            "Qué significa este informe: lista todos los objetivos que un infostealer "
            "(LummaC2, RedLine, Vidar, Glove Stealer, Phemedrone, etc.) buscaría en "
            "tu PC. Para cada elemento indica el estado de exposición, el valor para "
            "el atacante, las técnicas de bypass conocidas y la corrección "
            "recomendada con su fecha de publicación."
        ),
        "col_browser": "Navegador",
        "col_installed_version": "Versión instalada",
        "col_current_stable": "Versión estable actual",
        "col_diff": "Diferencia",
        "col_risk": "Riesgo",
        "up_to_date": "actualizado",
        "section_accounts": "Cuentas descifradas por navegador",
        "showpassword_warning": (
            "MODO: MOSTRAR CONTRASEÑAS — las contraseñas están en texto claro. "
            "Trate este archivo como dato sensible."
        ),
        "masked_info": (
            "Las contraseñas están enmascaradas. Para verlas en texto claro, "
            "ejecute de nuevo con <code class=\"code\">--showpassword</code>."
        ),
        "profile_label": "Perfil",
        "credentials_word": "credenciales",
        "decrypted_word": "descifradas",
        "protected_word": "v20-protegidas",
        "col_url": "URL",
        "col_username": "Nombre de usuario",
        "col_password": "Contraseña",
        "col_cipher": "Cifrado",
        "col_category": "Categoría",
        "v20_protected_tag": "[v20-PROTEGIDO]",
        "section_versions": "Versiones instaladas vs. últimas versiones estables",
        "col_released": "Publicada",
        "col_major_gap": "Diferencia principal",
        "col_source": "Fuente",
        "vuln_known_header": "Vulnerabilidades conocidas para navegadores instalados",
        "decrypt_diff_label": "Dificultad de descifrado",
        "risk_score_label": "Puntuación de riesgo",
        "bypass_section_label": "Técnicas de bypass aplicables",
        "used_by_label": "Usado por:",
        "ref_label": "Ref",
        "fix_prefix": "Corrección:",
        "released_label": "publicada",
        "section_targets": "Objetivos infostealer detectados",
        "targets_intro": "Objetivos clásicos. SOLO PRESENCIA — sin exfiltración de datos.",
        "col_target": "Objetivo",
        "col_status": "Estado",
        "col_value": "Valor",
        "col_details": "Detalles",
        "status_present": "✓ PRESENTE",
        "section_lazagne": "LaZagne Light — réplica Python",
        "lazagne_intro": (
            "Implementación interna de las categorías LaZagne más útiles. "
            "Cero dependencias externas, cero binarios marcados como PUA. "
            "Algoritmos públicos documentados."
        ),
        "wifi_header": "Perfiles Wi-Fi",
        "wifi_na": "(n/d)",
        "wifi_key_msg": "perfiles con clave visible (se requiere admin para clave en claro).",
        "putty_header": "Sesiones PuTTY",
        "putty_note": "PuTTY NO guarda contraseñas SSH por diseño. Solo se muestran host/usuario/puerto.",
        "winscp_header": "Sesiones WinSCP",
        "winscp_warning": "WinSCP usa un algoritmo XOR personalizado DESCIFRABLE en modo usuario.",
        "winscp_decrypted_msg": "contraseñas descifradas.",
        "git_header": "Credenciales Git",
        "git_warning": (
            "El archivo <code class=\"code\">~/.git-credentials</code> "
            "está en <strong>TEXTO CLARO</strong> por diseño. Cualquier proceso "
            "en modo usuario lo lee instantáneamente."
        ),
        "openvpn_header": "Configuraciones OpenVPN",
        "filezilla_header": "Sitios guardados en FileZilla",
        "filezilla_warning": "FileZilla guarda contraseñas en <code class=\"code\">sitemanager.xml</code> en base64 (NO cifradas).",
        "thunderbird_header": "Credenciales Thunderbird",
        "thunderbird_warning": "Thunderbird usa el mismo esquema NSS que Firefox. Sin contraseña maestra = descifrable en modo usuario.",
        "pidgin_header": "Cuentas de chat Pidgin",
        "pidgin_warning": "Pidgin guarda contraseñas en TEXTO CLARO en <code>accounts.xml</code>.",
        "dbviz_header": "Bases de datos DBVisualizer",
        "rdp_header": "Archivos RDP",
        "chat_header": "Aplicaciones de mensajería (presencia)",
        "col_ssid": "SSID",
        "col_auth": "Auth",
        "col_key_cleartext": "Clave (texto claro)",
        "col_session": "Sesión",
        "col_host": "Host",
        "col_port": "Puerto",
        "col_user": "Usuario",
        "col_protocol": "Protocolo",
        "col_config": "Config",
        "col_auth_file": "Archivo auth",
        "col_file": "Archivo",
        "col_pwd_encrypted": "Contraseña cifrada",
        "col_alias": "Alias",
        "col_db_url": "URL BD",
        "col_app_name": "App",
        "col_path": "Ruta",
        "col_profile": "Perfil",
        "col_type": "Tipo",
        "col_persistence": "Persistencia",
        "yes_str": "SÍ",
        "no_str": "NO",
        "section_legacy": "Credenciales Windows heredadas",
        "credman_header": "Administrador de credenciales de Windows",
        "vault_header": "Almacén IE / Edge Legacy",
        "wifi_saved_header": "Perfiles Wi-Fi guardados",
        "outlook_header": "Perfiles de Outlook",
        "entries_word": "entradas",
        "section_tools": "Herramientas de recuperación instaladas &amp; listas",
        "tools_intro": (
            "Herramientas de código abierto disponibles públicamente. Las que faltan "
            "se instalan automáticamente vía pip. Las marcadas como PUA requieren "
            "opt-in explícito con <code class=\"code\">--install-flagged-tools</code>."
        ),
        "status_installed": "✓ INSTALADO",
        "status_missing": "FALTANTE",
        "tag_new": "NUEVO",
        "tag_upgraded": "ACTUALIZADO",
        "tag_pua": "Marcado PUA",
        "section_fixes": "Recomendaciones de corrección",
        "why_label": "Por qué:",
        "how_label": "Cómo:",
        "section_timeline": "Línea de tiempo App-Bound Encryption (Chrome 127+)",
        "tl_fix_label": "Corrección:",
        "showpassword_file_warning": "[!] CONTIENE CONTRASEÑAS EN TEXTO CLARO. Eliminar después de la auditoría.",
        # pwd_audit-specific keys
        "pwd_report_title": "Auditoría de credenciales del navegador",
        "pwd_h1": "Auditoría de credenciales del navegador",
        "pwd_what_box_title": "Qué significa este informe:",
        "pwd_what_box_text": (
            "estas son EXACTAMENTE las credenciales que un infostealer "
            "(RedLine, Lumma, Kepavll, etc.) podría exfiltrar de tu PC "
            "si se ejecutara en el contexto de tu usuario de Windows. "
            "El malware realiza exactamente el mismo descifrado que hizo esta herramienta (DPAPI + AES-GCM)."
        ),
        "pwd_aggressive_note": (
            "<strong style=\"color:#c00\">MODO AGRESIVO activo:</strong> "
            "además de las credenciales en modo usuario (v10), la herramienta intentó eludir "
            "el <code>v20 App-Bound Encryption</code> creando una "
            "<strong>tarea programada como SYSTEM</strong>. Esto simula un infostealer "
            "elevado a admin (como los que usan bypass de UAC o elevación COM)."
        ),
        "stat_total_creds": "credenciales totales",
        "stat_decrypted_vm": "DESCIFRADAS<br>(vulnerables modo usuario)",
        "stat_protected_v20_abe": "PROTEGIDAS v20-ABE<br>(requieren SYSTEM)",
        "stat_weak_pwd": "contraseñas DÉBILES",
        "stat_reused_pwd": "cuentas con contraseña REUTILIZADA",
        "abe_info_title": "Chrome 127+ App-Bound Encryption (v20):",
        "abe_info_text": (
            "Las contraseñas guardadas por Chrome actualizado (desde julio de 2024) están cifradas "
            "dos veces: una con DPAPI del usuario, otra con DPAPI de SYSTEM. Un infostealer "
            "en modo usuario normal (la gran mayoría) NO puede descifrarlas. "
            "Las {n} credenciales «PROTEGIDAS» de arriba están en este estado."
        ),
        "reuse_section_title": (
            "Contraseñas reutilizadas (una sola filtración compromete todos estos sitios)"
        ),
        "reuse_same_pwd": "Misma contraseña",
        "reuse_used_on": "usada en",
        "reuse_sites_suffix": "sitios",
        "all_creds_title": "Todas las credenciales (ordenadas por criticidad + debilidad)",
        "col_sev": "Sev",
        "col_len": "Long",
        "col_strength": "Fortaleza",
        "col_issues": "Problemas",
        "protected_v20_abe_tag": "[PROTEGIDA v20-ABE]",
        "strength_guide_title": "Cómo interpretar los niveles de fortaleza",
        "strength_very_weak_desc": "contraseña diccionario / secuencias obvias / muy corta. Descifrada en segundos.",
        "strength_weak_desc": "corta o monoclase. Descifrada en minutos/horas con fuerza bruta dirigida.",
        "strength_medium_desc": "longitud decente + 2-3 clases. Descifrada en días/semanas.",
        "strength_strong_desc": "12+ caracteres, 3-4 clases, entropía 60+ bits. Descifrada en meses/años.",
        "strength_very_strong_desc": "16+ caracteres, alta entropía, 4 clases. Técnicamente irrompible por fuerza bruta.",
        "tech_notes_title": "Notas técnicas sobre DPAPI y AES-GCM",
        "tech_note_1": "Chrome/Edge guardan contraseñas como blobs <code>v10</code> + nonce(12B) + texto cifrado + tag(16B).",
        "tech_note_2": "La clave AES-256 está en <code>Local State</code>, cifrada mediante DPAPI usando las credenciales de Windows del usuario.",
        "tech_note_3": "DPAPI (<code>CryptUnprotectData</code>) usa la clave maestra del usuario de Windows + su SID + su contraseña (o PIN/Hello).",
        "tech_note_4": "Un malware ejecutándose como tu usuario de Windows puede hacer todo esto. NO se necesita ser admin.",
        "tech_note_5": "Para evitar futura exfiltración: <strong>no guardes contraseñas en el navegador</strong>, usa un gestor de contraseñas dedicado.",
        "suggestions_title": "Sugerencias:",
        "suggestion_1": "Migra a un gestor de contraseñas (Bitwarden gratis, KeePassXC, 1Password, Proton Pass).",
        "suggestion_2": "Desactiva 'guardar contraseñas' en el navegador (Configuración &gt; Gestor de contraseñas O política de registro HKCU\\Software\\Policies\\Google\\Chrome\\PasswordManagerEnabled = 0).",
        "suggestion_3": "Elimina todas las contraseñas guardadas tras migrar: <code>chrome://settings/passwords</code>.",
        "suggestion_4": "Activa 2FA en todas las cuentas CRITICAL.",
        "suggestion_5": "Para las cuentas reutilizadas, usa contraseñas únicas generadas por el gestor.",
        "cisco_anyconnect_header": "Perfiles Cisco AnyConnect",
    },
}


def get_strings(lang: str) -> dict:
    """Return translation dict for *lang*. Falls back to 'en' for unknown codes."""
    return _S.get(lang, _S["en"])


def detect_system_language() -> str:
    """Detect Windows UI language. Returns supported 2-letter code or 'en'."""
    supported = {"it", "en", "fr", "de", "es"}
    # Method 1: Windows registry (most reliable)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Control Panel\International") as k:
            locale_name = winreg.QueryValueEx(k, "LocaleName")[0]  # e.g. "it-IT"
            code = locale_name.split("-")[0].lower()
            if code in supported:
                return code
    except Exception:
        pass
    # Method 2: locale module
    try:
        import locale
        lang_loc = (locale.getdefaultlocale()[0] or "").split("_")[0].lower()
        if lang_loc in supported:
            return lang_loc
    except Exception:
        pass
    return "en"
