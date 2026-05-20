# ToolSicurezza — Audit credenziali + superficie infostealer

Suite di tool per **quantificare il rischio reale** in caso di infezione
da infostealer (RedLine, Lumma, Kepavll, Vidar, Glove Stealer, Phemedrone,
WhiteSnake, VoidStealer, ecc.) sul tuo PC Windows.

> Nato dopo l'incidente del 17/05/2026 dove `Trojan:Win32/Kepavll!rfn`
> è stato bloccato da Windows Defender mentre tentava di rubare le
> credenziali salvate in Chrome.

## 🧰 Tool inclusi

1. **`pwd_audit.py`** — audit profondo delle password salvate nei browser
   Chromium (Chrome, Edge, Brave, Vivaldi, Opera). Decifra v10, prova bypass
   v20 ABE in modalità aggressiva (vedi sotto).

2. **`infostealer_audit.py`** — audit completo della superficie d'attacco:
   - Browser detection + versione + matching CVE/ABE bypass
   - Discord token detection
   - Steam autologin (`loginusers.vdf`)
   - Crypto wallet extensions (25+ wallets noti: MetaMask, Phantom, Trust,
     Coinbase, Binance, Exodus, Keplr, Rabby, OKX, ecc.)
   - Telegram Desktop session
   - SSH private keys (rsa/ed25519/ecdsa/dsa)
   - GPG keyring
   - FileZilla saved sites
   - Windows Credential Manager (count)
   - VPN configs (OpenVPN/WireGuard)

3. **Knowledge Base** (`kb/vulnerabilities.json`) — timeline dettagliato delle
   modifiche ABE in Chrome 127→148, tecniche di bypass note, infostealer che
   le usano, e release date dei fix.

4. **Modulo Firefox NSS** (`modules/firefox_nss.py`) — decifrazione
   credenziali Firefox dalla `key4.db` SQLite e `logins.json` (PBKDF2 +
   AES-256-CBC, senza dipendere dalla libreria NSS).

## ⚡ Quick start

```powershell
cd D:\Desktop\ToolSicurezza

# AUDIT COMPLETO V2 (RACCOMANDATO)
py infostealer_audit.py                    # password mascherate
py infostealer_audit.py --showpassword     # password in chiaro
py infostealer_audit.py --no-online        # skip live version check
py infostealer_audit.py --no-tools         # skip auto-install Python tools
py infostealer_audit.py --install-flagged-tools  # opt-in LaZagne

# Audit deep password (solo Chromium, modalita' legacy)
py pwd_audit.py                 # user-mode, mascherate
py pwd_audit.py --reveal        # user-mode, chiaro
py pwd_audit.py --aggressive    # admin/SYSTEM, prova bypass v20 ABE
```

Help: `py infostealer_audit.py --help` / `py pwd_audit.py --help`

## 🆕 Features v2 (infostealer_audit.py)

Il report HTML è strutturato in **9 tab navigabili**:

1. **Overview** — riassunto esecutivo + matrice versioni
2. **Account per browser** — credenziali decifrate, raggruppate per browser e
   profilo. Ogni riga mostra URL, username, password (mascherata / chiara con
   `--showpassword`), formato cipher (`v10`/`v20`/`v20-protected`/`pre-v10`),
   categoria sito, e risk level
3. **Versioni & CVE** — confronto versioni installate vs ultime stable live
   da fonti ufficiali (chromiumdash, Mozilla product-details, edgeupdates,
   GitHub releases). Lista tecniche bypass applicabili
4. **Target infostealer** — Discord, Steam, 25+ crypto wallet, SSH, GPG,
   Telegram, FileZilla, Credential Manager, VPN configs
5. **LaZagne Light** — modulo built-in che replica WiFi/PuTTY/WinSCP/Git/
   OpenVPN/FileZilla/Thunderbird/Pidgin/DBVisualizer/RDP/Cisco AnyConnect
   (zero dipendenze esterne, zero binari PUA-flagged)
6. **Credenziali legacy** — Windows Credential Manager full dump, IE/Edge
   Legacy Vault, profili Wi-Fi (con chiave se `--showpassword`), Outlook
7. **Tool recovery** — stato installazione di `pypykatz`, `browser_cookie3`,
   `firepwd_internal`, `LaZagne` (opt-in). Auto-installati se mancanti
8. **Raccomandazioni fix** — ordinate per priorità, con motivazione e
   istruzioni pratiche
9. **ABE Timeline** — storia ABE Chrome 127→148 con bypass noti e milestone fix

## 🔥 Modalità aggressiva (--aggressive)

Simula esattamente cosa farebbe un infostealer **elevato a admin** (es. tramite
UAC bypass o COM elevation). Cerca di bypassare la protezione **v20 App-Bound Encryption**
introdotta da Chrome 127+ tramite questa catena:

1. Carica `app_bound_encrypted_key` dal Local State
2. **Strato 1 — SYSTEM DPAPI**: crea una scheduled task SYSTEM, scarica la decifrazione
   DPAPI fatta nel contesto SYSTEM. Ritorna un blob intermedio (~380 byte).
3. **Strato 2 — User DPAPI**: il blob intermedio è un altro DPAPI blob, decifrato nel
   contesto utente corrente. Ritorna un blob più piccolo (~130 byte) che dovrebbe
   contenere la chiave AES-256 per i blob v20.
4. **Strato 3 — chrome.dll AES wrapping** (Chrome 131+): qui Chrome aggiunge un terzo
   strato con una **chiave AES costante hardcoded nel binario chrome.dll**. La chiave AES
   reale è cifrata con questa "master constant" che cambia ad ogni release di Chrome.

Il tool tenta automaticamente un **brute-force su tutte le 32-byte windows** del blob
intermedio per trovare una chiave che decifri un sample password v20. Se nessuna funziona,
significa che siamo davanti allo **Strato 3** (Chrome 131+).

**Per bypassare lo Strato 3** servono tecniche più invasive:
- **Signature scanning** di `chrome.dll` per estrarre la constant key (richiede aggiornamento
  delle signature ad ogni release Chrome)
- **COM IElevator** (`{708860E0-F641-4611-8895-7D867DD3675B}`) con path validation bypass
- **DLL injection** dentro `chrome.exe` per usare la routine di decifrazione interna

Queste tecniche sono usate da infostealer commerciali "v20-aware" (RedLine pro 2024,
Lumma 2025, alcuni Vidar fork) ma sono ancora complesse e fragili.

**Risultato pratico sul tuo PC** (Chrome 131+):
- Strati 1 e 2: ✓ BYPASSATI dal tool
- Strato 3: ✗ resiste — bypass dichiarato fallito, password v20 non decifrate

**Conclusione**: Chrome v20 ABE non è una protezione "uno strato" ma "tre strati", e
solo i primi due sono attaccabili genericamente con admin/SYSTEM. Il terzo richiede
manutenzione costante (signature update per ogni Chrome release) — questo è esattamente
il motivo per cui pochi infostealer riescono ad esfiltrare credenziali Chrome moderne.

**Requisito modalità aggressiva**: privilegi Administrator (UAC prompt).

**Output**: il file HTML/log contiene il dettaglio di ogni strato bypassato. Le password
v10 sono decifrate in chiaro. Le password v20 restano protette se lo Strato 3 resiste.
Tratta il file come dato sensibile e cancellalo dopo l'audit.



## A cosa serve

In un incidente di sicurezza, la domanda fondamentale è:
> "Cosa avrebbe potuto rubare il malware se non l'avessi bloccato?"

Questo tool risponde **esattamente** a quella domanda. Fa la stessa
identica decifrazione che farebbe un infostealer:

1. Trova i profili di Chrome / Edge / Brave / Vivaldi / Opera / Chromium
2. Estrae la **master key AES-256** dal file `Local State` (cifrata via DPAPI)
3. La decifra usando le credenziali Windows dell'utente corrente
4. Apre il database `Login Data` (SQLite) di ogni profilo
5. Decifra ogni password (AES-GCM v10) col master
6. Analizza ogni password per:
   - **Robustezza**: lunghezza, classi caratteri, entropia, pattern (date, sequenze, dizionario)
   - **Criticità del sito**: banking > email > cloud > gaming > shopping > router
   - **Riutilizzo**: la stessa password su più siti = bomba a orologeria
7. Genera report HTML interattivo + sommario CLI

## Perché è utile

- **Quantifica il danno**: sapere che un infostealer prenderebbe N password,
  di cui X CRITICAL e Y deboli, dà una stima concreta del rischio.
- **Trova le password riutilizzate**: il pattern più pericoloso. Una pwd
  rubata = N siti compromessi.
- **Aiuta a fare triage post-incidente**: lista ordinata di cosa cambiare
  per primo.
- **Dimostra il problema**: vedere le proprie password in chiaro è la
  motivazione migliore per passare a un password manager dedicato.

## Chrome v20 App-Bound Encryption (importante!)

Da luglio 2024 Chrome 127+ ha introdotto **App-Bound Encryption (ABE)**
per password e cookie. È un meccanismo di cifratura a doppio livello:

1. La master key v10 (decifrabile in user-mode) — usata per dati legacy
2. La master key v20 (App-Bound) — protetta da DPAPI SYSTEM-context

Le password salvate dopo l'update hanno il prefisso `v20` invece di `v10`
e sono cifrate con la chiave v20. Per decifrarle serve:

- Privilegi **SYSTEM** (es. `psexec -s`), oppure
- DLL injection in chrome.exe, oppure
- Exploit COM elevation (CVE-2024-XXXX)

**Conseguenza pratica:** un infostealer user-mode classico (Kepavll, RedLine
basic, Lumma standard) **NON riesce** a rubare le password v20.

Il tool rileva le entry v20 e le segna come `PROTECTED_v20`. Edge, Brave e
altri Chromium hanno schema simile.

> Sul PC dove è stato sviluppato questo tool, il risultato post-incidente
> è stato: 57 credenziali Chrome v20-protected (intoccabili da user-mode
> infostealer), solo 2 credenziali Edge in v10. La protezione di Chrome
> ha funzionato.

## 🔓 LaZagne Light (modulo built-in)

Replica pura-Python delle categorie LaZagne più utili, **senza dipendere dal
binario LaZagne** (Defender PUA-flagged). Tutti algoritmi pubblici documentati,
zero binari esterni, zero dipendenze pip aggiuntive.

| Categoria | Cosa estrae | Note |
|---|---|---|
| **Wi-Fi** | Profili salvati + chiave in chiaro (netsh) | Richiede admin per key cleartext |
| **PuTTY** | Sessioni SSH salvate (host, port, user) | PuTTY NON salva password per design |
| **WinSCP** | Sessioni FTP/SFTP + **password decifrata** | Algoritmo XOR custom pubblico |
| **Git credentials** | `~/.git-credentials` | **PLAINTEXT** by design! |
| **OpenVPN** | `.ovpn` + auth-user-pass files | Username/password se config remember |
| **FileZilla** | `sitemanager.xml` decoded | Base64-encoded, NON cifrato |
| **Thunderbird** | Credenziali email | Stesso NSS schema Firefox |
| **Pidgin** | Chat accounts | **PLAINTEXT** in accounts.xml |
| **Cisco AnyConnect** | Profili VPN (host, gruppi) | No password (in CredMan) |
| **DBVisualizer** | Connessioni database SQL | Base64-encoded |
| **RDP files** | `.rdp` saved | Pwd encrypted DPAPI |
| **Chat tokens** | Slack/Teams/Telegram/Signal | Detection only |

Output nel tab dedicato **"LaZagne Light"** del report HTML. Con
`--showpassword` le password decifrate sono mostrate in chiaro; senza, sono
mascherate (`M*****a`).

> Se il tuo PC è un desktop senza scheda Wi-Fi (servizio `wlansvc` non
> attivo), il tool lo rileva automaticamente e mostra "n/a" invece di "0".

## 🔧 Auto-install di tool esterni

Al primo lancio (o ogni 24h), `infostealer_audit.py` controlla la presenza di
questi tool Python open-source e li installa via pip se mancanti:

| Tool | Auto-install | Note |
|---|---|---|
| `pypykatz` | ✅ default | Mimikatz pure-Python (DPAPI, LSASS) |
| `browser_cookie3` | ✅ default | Cookie extractor multi-browser |
| `firepwd_internal` | ✅ replicato in `modules/firefox_nss.py` | NSS decrypt without external dep |
| `LaZagne` | ❌ opt-in | PUA-flagged da Microsoft Defender — usa `--install-flagged-tools` |

I tool sono aggiornati automaticamente ogni 24h (cache `pwd_audit_tools_state.json`).
Per forzare l'upgrade: `--force-tool-update`. Per disabilitare l'auto-install:
`--no-tools`.

## 🌐 Live version check (online)

`infostealer_audit.py` controlla ogni 24h (cached) le versioni stable correnti
da fonti ufficiali:

- **Chrome** → `https://chromiumdash.appspot.com/fetch_releases` (Google)
- **Firefox** → `https://product-details.mozilla.org/1.0/firefox_versions.json` (Mozilla)
- **Edge** → `https://edgeupdates.microsoft.com/api/products` (Microsoft)
- **Brave** → `https://api.github.com/repos/brave/brave-browser/releases/latest` (GitHub)

Per skip: `--no-online`. Cache 24h in `%TEMP%\pwd_audit_versions_cache.json`.

## 📚 Knowledge Base estesa (kb/vulnerabilities.json)

Oltre alla **timeline ABE** (Chrome 127→148) e alle **tecniche di bypass note**,
la KB include ora una sezione `known_infostealers` con dettagli su:

RedLine, LummaC2, Vidar, Phemedrone, WhiteSnake, Meduza, StealC, Rhadamanthys,
Meta Stealer, Lumar, Glove Stealer, VoidStealer, Stealka, Shuyal, Torg Grabber,
Arkanix.

Per ognuno: data first-seen, browser target, tecnica ABE bypass, massima
versione Chrome supportata dalla variante "basic" vs "pro". Tutte le info da
**research pubblica** (BlackFog, BleepingComputer, Cybereason, Group-IB,
DarkReading, ecc.) — **nessun binario malware è incluso**.

## Sicurezza ed etica

Questo tool è uno **strumento difensivo**:

- Funziona **solo** nel contesto del **tuo** utente Windows
  (DPAPI lega la decifrazione al SID + password dell'utente).
- **Non** può leggere credenziali di altri utenti del PC.
- **Non** può essere usato da remoto contro qualcun altro.
- **Non** invia nulla in rete: tutto resta sul tuo disco.
- Default: password **mascherate** (es. `M*****a`). Devi passare
  `--reveal` esplicitamente per vederle in chiaro.
- I report sono salvati in `.\reports\` (locale).

**Lo scopo è dimostrarti cosa un malware vedrebbe — non aiutare qualcuno
a rubare credenziali altrui.** L'unica cosa che questo tool fa più di un
infostealer è: **analizzare e mostrare**, invece di esfiltrare verso un C2.

## Requisiti

- Windows 10/11
- Python 3.10+ (testato su 3.12)
- Browser supportati: Chrome, Edge, Brave, Vivaldi, Opera, Chromium
- Package Python: `cryptography` (auto-installato al primo avvio)

## Uso

### Audit base (password mascherate)

```powershell
cd D:\Desktop\ToolSicurezza
py pwd_audit.py
```

Output: sommario a video + report HTML in `.\reports\audit_<timestamp>.html`.

### Audit completo con password in chiaro

```powershell
py pwd_audit.py --reveal
```

> ⚠️ Il file HTML conterrà le password in chiaro. **Non condividerlo.**
> Dopo aver consultato, eliminalo.

### Solo specifici browser

```powershell
py pwd_audit.py --browsers chrome,edge
```

### Solo console (no HTML)

```powershell
py pwd_audit.py --no-html
```

### Path output custom

```powershell
py pwd_audit.py --out C:\path\to\report.html
```

## Output di esempio

```
========================================================================
SOMMARIO — 57 credenziali
========================================================================

Per criticita':
  CRITICAL  :  10
  HIGH      :  18
  MEDIUM    :  19
  LOW       :  10

Per robustezza:
  VERY_WEAK :   2
  WEAK      :  14
  MEDIUM    :  28
  STRONG    :  11
  VERY_STRONG:  2

Password RIUTILIZZATE: 3 gruppi, 9 account totali
  pwd 'M*****a' su 4 siti: github.com, gitlab.com, jlcpcb.com ... +1
  pwd 'A*****1' su 3 siti: amazon.it, ebay.it, aliexpress.com
  pwd 'q*****!' su 2 siti: forum.futurashop.it, snapeda.com

!! TOP 10 password DEBOLI su siti CRITICAL/HIGH:
  [CRITICAL] https://github.com/                            (AlessioSavelli) -> 'M*****a' (WEAK)
  ...
```

Il report HTML ha:
- Statistiche aggregate (grafici testuali)
- Sezione "Password riutilizzate" con tutti i gruppi
- Tabella completa ordinata per criticità DESC + robustezza ASC
- Categorizzazione per Banking / Email / Cloud / Gaming / ecc.
- Spiegazione tecnica DPAPI + AES-GCM in fondo

## Come funziona (dettagli tecnici)

### Schema decifrazione Chrome 80-126 (v10)

```
Local State (JSON)
  └─ os_crypt.encrypted_key (base64)
      └─ DPAPI("DPAPI" + AES_KEY_256)
          └─ CryptUnprotectData() → MASTER_KEY_v10 (32 byte)

Login Data (SQLite)
  └─ logins.password_value (blob)
      └─ "v10" (3B) + nonce (12B) + ciphertext + tag (16B)
          └─ AES-GCM(MASTER_KEY_v10, nonce, ct, tag) → plaintext
```

### Schema Chrome 127+ (v20 — App-Bound Encryption)

```
Local State (JSON)
  └─ os_crypt.app_bound_encrypted_key (base64)
      └─ "APPB" (4B) + DPAPI_user( DPAPI_SYSTEM( wrapped_key ))
          └─ CryptUnprotectData() user → strip → SYSTEM blob
              └─ CryptUnprotectData() SYSTEM → MASTER_KEY_v20 (32 byte)
                 [INACCESSIBILE in user-mode!]

Login Data (SQLite)
  └─ logins.password_value (blob)
      └─ "v20" (3B) + nonce (12B) + ciphertext + tag (16B)
          └─ AES-GCM(MASTER_KEY_v20, ...) → plaintext
```

### Categorie e severity

| Categoria | Severity | Esempi |
|---|---|---|
| Banking | CRITICAL | bnl.it, paypal.com, n26.com, fineco.it |
| Email | CRITICAL | gmail, outlook, libero.it, appleid.apple.com |
| Cloud/Dev | CRITICAL | aws.amazon, github, gitlab, openai, auth0 |
| Lavoro | CRITICAL | e-distribuzione, salesforce, slack |
| Crypto | CRITICAL | binance, coinbase, metamask |
| Gaming | HIGH | steam, riot, epicgames, ea, playstation |
| Dev Tools | HIGH | digikey, mouser, autodesk, jlcpcb |
| Social | HIGH | facebook, instagram, twitter, discord |
| Shopping | MEDIUM | amazon, ebay, aliexpress |
| Streaming | MEDIUM | netflix, spotify, twitch |
| Hosting | MEDIUM | ionos, aruba, ovh |
| Router | LOW | 192.168.x.x, fritz.box, localhost |

### Calcolo robustezza

Score basato su:
- **Lunghezza**: +0 (<8), +1 (8-11), +2 (12-15), +3 (16+)
- **Classi caratteri**: +0 (1), +1 (2), +2 (3), +3 (4)
- **Dizionario weak**: -tutto se in top-weak list (italiani inclusi)
- **Pattern**: -1 per sequenze, anni, monotipo
- **Entropia totale**: -1 se <30 bit, +1 se >60 bit

Classifica finale:
- score ≤1: **VERY_WEAK** (rotta in secondi)
- score ≤3: **WEAK** (minuti/ore)
- score ≤5: **MEDIUM** (giorni)
- score ≤7: **STRONG** (mesi/anni)
- score ≥8: **VERY_STRONG** (irrompibile per brute force)

## Architettura

```
ToolSicurezza/
├── pwd_audit.py                    # tool 1: deep password audit Chromium
├── infostealer_audit.py            # tool 2 (v2): audit completo
├── README.md
├── requirements.txt                # cryptography
├── kb/
│   └── vulnerabilities.json        # KB CVE + ABE timeline + bypass tecniche
│                                   #  + known_infostealers (17 famiglie)
├── modules/
│   ├── __init__.py
│   ├── browser_versions.py         # detection + CVE matcher
│   ├── chromium_decrypt.py         # DPAPI + AES-GCM (v10/v20)
│   ├── firefox_nss.py              # NSS PBKDF2 + AES-CBC
│   ├── infostealer_targets.py      # Discord/Steam/Wallet/SSH/etc
│   ├── lazagne_light.py            # WiFi/PuTTY/WinSCP/Git/Pidgin/...
│   ├── legacy_decrypt.py           # CredMan/IE Vault/Outlook
│   ├── online_versions.py          # live version check fonti ufficiali
│   └── external_tools.py           # pypykatz/browser_cookie3/lazagne mgmt
└── reports/                        # output (creata on demand)
    ├── audit_<ts>.html             # pwd_audit
    ├── infostealer_<ts>.html       # infostealer_audit (default)
    └── infostealer_showpassword_<ts>.html  # con --showpassword
```

## 📊 Knowledge Base CVE / ABE bypass timeline

Il file `kb/vulnerabilities.json` contiene:

- **`chromium_abe_timeline`**: ogni range di versioni Chrome con la sua difficoltà
  di decifrazione, le tecniche di bypass note applicabili, le date di release
  delle versioni che hanno introdotto le mitigation
- **`bypass_techniques`**: dettaglio di ogni tecnica (COM IElevator path bypass,
  DLL injection, reflective hollowing, early bird APC, debugger attach,
  chrome.dll signature scanning, ecc.) con livello di complessità, requisiti
  privilegi, infostealer noti che la usano, link a research
- **`browsers`**: per ogni browser supportato, path config, current stable version,
  schema ABE
- **`infostealer_targets`**: catalogo dei bersagli classici + valore per l'attaccante

### Aggiornare il KB

Quando esce un nuovo Chrome o emerge un nuovo bypass:

1. Modifica `kb/vulnerabilities.json`:
   - aggiorna `_meta.current_chrome_stable` + data
   - aggiungi un nuovo entry in `chromium_abe_timeline` per il nuovo range
   - se serve, aggiungi una nuova `bypass_techniques.<id>` con metadata
2. Salva. Il tool ricaricherà al prossimo lancio.

Le fonti consultate sono elencate in `_meta.sources` — controllale per gli
ultimi aggiornamenti pubblici.

## 🎯 Output infostealer_audit

Il report HTML è organizzato in 5 sezioni:

1. **Banner rischio complessivo** — CRITICO / ALTO / MEDIO / BASSO con
   indicazione operativa
2. **Browser rilevati & vulnerabilità note** — per ogni browser: versione,
   risk score 1-10, ABE status, tecniche bypass applicabili (con link
   alle research di riferimento), fix consigliato + release date
3. **Timeline ABE Chrome 127+** — storia completa dell'evoluzione della
   protezione e dei bypass; la riga della *tua* versione è evidenziata
4. **Target rilevati** — tabella di tutti i bersagli infostealer con stato
   PRESENTE/non trovato e valore
5. **Raccomandazioni fix** — ordinate per priorità CRITICAL → LOW, ognuna
   con motivazione e istruzioni pratiche su come farlo

Esempio di entry timeline (Chrome 131-135):
- `decrypt_difficulty: HARD`
- `description: Aggiunto strato finale di AES con constant key hardcoded in chrome.dll...`
- `applicable_bypasses: [chrome-dll-signature-scanning, dll-injection-chrome-exe, ...]`
- `fix.fixed_in: 136+`
- `fix.fixed_date: 2025-04-29`
- `fix.milestone: Remote debugging port restriction`

## Comportamento atteso vs. malware reale

| Aspetto | Questo tool | Infostealer reale |
|---|---|---|
| Decifrazione DPAPI | ✅ stesso meccanismo | ✅ |
| Decifrazione AES-GCM | ✅ stesso meccanismo | ✅ |
| Cookies di sessione | ❌ non li tocca | ✅ ruba anche quelli |
| Discord token | ❌ non li tocca | ✅ |
| Wallet crypto | ❌ non li tocca | ✅ |
| File `*.txt` con "wallet"/"password" | ❌ no scan | ✅ scan ricorsivo |
| Esfiltrazione rete | ❌ tutto locale | ✅ POST a C2 |
| Output | report HTML | invio cifrato al C2 |

Quindi: **se questo tool ti restituisce N password, un infostealer
prende almeno N+altri secret** (cookie, token, wallet, file sensibili).

## Frequenza d'uso consigliata

- **Una tantum** dopo un incidente (per quantificare il danno).
- **Trimestralmente** per controllare l'igiene credenziali e individuare reuse.
- **Prima** e **dopo** la migrazione a un password manager (per verificare
  di aver pulito tutto dal browser).

## Disclaimer

- Lo strumento è fornito as-is per uso personale sul tuo PC.
- Eseguilo solo su sistemi di tua proprietà o per cui hai autorizzazione
  esplicita.
- L'autore non è responsabile per uso improprio.

## Estensioni future possibili

- Audit di Firefox (formato diverso: NSS database)
- Check su Have I Been Pwned API (con hash k-anonymity)
- Export a CSV / JSON per import in password manager
- Watcher continuo: alerta quando vengono salvate nuove credenziali
- Audit di password salvate in Windows Credential Manager
- Audit di chiavi SSH e GPG presenti

## Riferimenti tecnici

- Microsoft DPAPI: https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptoapi-cryptography-functions
- Chrome password encryption: https://chromium.googlesource.com/chromium/src/+/master/components/os_crypt/
- AES-GCM spec: NIST SP 800-38D
- Trojan:Win32/Kepavll (incidente di partenza): https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FKepavll%21rfn
