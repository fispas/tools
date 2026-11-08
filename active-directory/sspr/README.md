# sspr — Self Service Password Reset (on-prem)

> **Versione 0.5.0** — motore, servizio web (.NET 10 LTS), portale utenti multilingua, pannello di amministrazione completamente personalizzabile con report, avvisi di scadenza, campagne di registrazione, inoltro a SIEM e installer guidato scritti. **Mai compilato né eseguito finora**: la prima verifica reale è la pipeline GitHub Actions, poi un'installazione di prova in laboratorio. Su richiesta, il progetto vive qui in `fispas/tools`, anche se è un'applicazione web.

## Installazione rapida

Fuori dall'installer serve solo questo:
1. **Scaricare il pacchetto**: repo `fispas/tools` → *Actions* → workflow *sspr* → ultima esecuzione verde → artefatto **FispaSSPR-package** (zip). In alternativa l'installer lo scarica da solo con un token GitHub fine-grained (permesso *Actions: Read* sul repo).
2. Estrarlo sul **server membro** che ospiterà il portale (Windows Server 2016+, non un DC) e lanciare, come amministratore con un account Domain Admins:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\Install-FispaSSPR.ps1
   ```
3. Al termine, se si usa un nome dedicato (es. `password.contoso.local`), creare il **record DNS** CNAME verso il server.

Tutto il resto lo fa la procedura, chiedendo passo passo i dati:

| Passo | Cosa chiede | Cosa fa |
|---|---|---|
| Pacchetto e prerequisiti | Cartella/zip o token GitHub | Verifica server membro 2016+ non DC, installa RSAT se manca |
| Schema AD | Conferma (permanente), eventuali credenziali Schema Admins | Import di `schema\FispaSSPR-Schema.ldf` con `ldifde` sullo Schema Master |
| gMSA | Nome del gMSA, nome DNS del portale | KDS root key (con attesa di 10 ore o subito se c'è un solo DC), creazione del gMSA autorizzato solo per questo server, `Install-ADServiceAccount` + test, SPN `HTTP/` |
| Utenti e operatori | OU abilitate (lista con caselle), gruppi esclusi, nomi dei gruppi operatori | Crea *SSPR-Admins* / *SSPR-Helpdesk*, aggiunge l'operatore corrente, deleghe minime sulle OU (reset password, `lockoutTime`, `pwdLastSet`, `tokenGroups`, attributi `fispaSspr*` confidenziali) |
| Certificato | Esistente / CA aziendale (modello) / PFX / autofirmato, porta | Richiesta o import, permesso di lettura della chiave privata al gMSA |
| Portale, email e SMS | Nome azienda, help desk, metodi, SMTP, gateway SMS, password compromesse | Pulsanti **Invia email di prova** e **Invia SMS di prova** |
| Installazione | Password del backup della chiave master | Copia in `%ProgramFiles%\FispaSSPR`, ACL su `%ProgramData%\FispaSSPR`, `config.json`, chiave master DPAPI-NG verso il gMSA + backup cifrato, Registro eventi `SSPR`, diritto *Accedi come servizio*, servizio Windows come gMSA con ripristino automatico, regola firewall Dominio/Privato, avvio e verifica |

Lo stato della procedura (senza segreti) è salvato in `%ProgramData%\FispaSSPR\installer-state.json`: se serve aspettare la KDS root key si chiude e si riprende. Log in `%ProgramData%\FispaSSPR\installer_*.log`.

- **Aggiornamento**: rilanciare l'installer con il nuovo pacchetto; chiave master mantenuta, scelta se mantenere la configurazione modificata dal pannello.
- **Disinstallazione**: `Install-FispaSSPR.ps1 -Uninstall` (servizio, programma, firewall; scelta se tenere dati e chiave). In AD restano gMSA, gruppi, deleghe e schema, elencati a fine operazione.
- **Ripristino della chiave** su un nuovo server: `FispaSSPR.exe restore --sid <SID gMSA> --backup <file>` (chiede la password del backup).
- **Accesso automatico** dai PC di dominio: aggiungere l'indirizzo del portale alla zona Intranet via GPO.

## Personalizzazione (pannello → Configurazione)

Tutto si cambia dal pannello, senza riavvio e senza toccare file. Ogni sezione si può esportare e importare (JSON senza password) per riusarla su altri ambienti.

| Sezione | Cosa si personalizza |
|---|---|
| **Generale** | Nome azienda, titolo e sottotitolo del portale, indirizzo pubblicato, contatto help desk, collegamento alla guida, prefisso telefonico predefinito, **avviso in evidenza** (informazione / attenzione / importante), **lingue del portale** (italiano, inglese; la prima è la predefinita, con più lingue compare il selettore e si usa la lingua del browser) |
| **Aspetto** | **Logo**, **icona della scheda**, **immagine di sfondo** (caricati dal pannello, formato riconosciuto dai byte, SVG con script o riferimenti esterni rifiutati), 10 colori (principale, sfondi, testi, intestazione, esiti), carattere, arrotondamenti, altezza del logo, nome azienda in intestazione sì/no, **CSS personalizzato** (senza @import, URL esterni o script) |
| **Testi** | **Ogni testo** del portale e ogni messaggio di errore, **per ogni lingua** (178 voci in catalogo, con ricerca, filtro per sezione, "solo personalizzati", ripristino del predefinito). Segnaposto `{company}`, `{helpdesk}`, `{portalUrl}` e quelli specifici di ogni testo |
| **Notifiche** | Attivazione per evento (metodo aggiunto/rimosso, password cambiata/reimpostata, sblocco, azioni dell'help desk), canali (email personale, SMS, email aziendale), **oggetto, testo email e testo SMS** di ogni notifica e del codice di verifica |
| **Funzioni** | Reset, sblocco, cambio password, registrazione autonoma, rimozione dei metodi, verifica dal vivo della password, accesso Windows / con password, prima registrazione solo da PC aziendale, conferma con metodo esistente per modificare i metodi, comportamento del reset (sblocca, cambio obbligatorio, invio codici in background), azioni consentite all'help desk, reset con password temporanea |
| **Verifica e password** | Metodi attivi, minimi da registrare, verifiche per reset e sblocco, durata e tentativi dei codici, tolleranza TOTP, nome nell'app, lunghezza minima, parole vietate, password compromesse (online k-anonymity / lista locale / no) |
| **Sicurezza** | Limiti per utente, IP e globali, codici all'ora, durate di sessione utente e pannello, validità della conferma d'identità, tempo minimo di risposta, tentativi del secondo fattore, conservazione dell'audit |
| **Email e SMS** | SMTP e gateway SMS con prova di invio |
| **Scadenze e campagne** | **Avviso di scadenza della password** (soglie in giorni, es. 14/7/3/1, ora di invio, email aziendale e/o metodi registrati; usa `msDS-UserPasswordExpiryTimeComputed`, quindi rispetta dominio e PSO) e **campagna di registrazione** (invito periodico a chi non ha registrato i metodi, intervallo, massimo per esecuzione), con pulsante *Esegui ora* |
| **Integrazioni** | Inoltro di ogni evento dell'audit a **syslog** (RFC 5424, UDP o TCP) per il SIEM e a un **webhook** (Teams, Slack, chat: POST `{"text": ...}`), anche solo per gli eventi rilevanti |
| **Directory** | Domain controller, OU abilitate, gruppi esclusi |
| **Avanzate** | Configurazione completa in JSON, esporta/importa |

Restano fuori dal pannello, per sicurezza, solo porta, certificato, gMSA, gruppi degli operatori e obbligo del secondo fattore per il pannello: si cambiano rieseguendo l'installer.

I testi predefiniti stanno in `src/FispaSspr.Web/Texts/texts.<lingua>.json` (it, en), generati da `tools/gen-texts.py`. Le personalizzazioni si salvano come `chiave` (italiano) o `en:chiave` (altre lingue).

## Struttura della cartella
| Percorso | Contenuto |
|---|---|
| `src/FispaSspr.Core` | Motore indipendente da AD e dal web: cifratura AES-GCM, TOTP, codici monouso, limiti dei tentativi, protezione degli account, policy password e password compromesse, codec degli attributi, interfacce, configurazione |
| `src/FispaSspr.Web` | Servizio Windows `FispaSSPR.exe` (Kestrel, self-contained): directory AD come gMSA, chiave master DPAPI-NG, SMTP/SMS, audit, sessioni, API, riga di comando (`init`, `restore`, `validate`, `version`) |
| `src/FispaSspr.Web/wwwroot` | Portale utenti (`/`) e pannello di amministrazione (`/admin/`), HTML/JS senza dipendenze esterne; tema generato in `/theme.css` |
| `src/FispaSspr.Web/Texts` | Catalogo dei testi predefiniti (portale, errori, notifiche) |
| `tools/gen-texts.py` | Generatore del catalogo dei testi |
| `tests/FispaSspr.Core.Tests` | Test xUnit (vettori RFC 6238/4648, manomissioni, iniezione LDAP, account protetti...) |
| `api/openapi.yaml` | Contratto API tra interfaccia web e motore |
| `installer/Install-FispaSSPR.ps1` | Installazione guidata con GUI, aggiornamento, disinstallazione |
| `installer/schema/FispaSSPR-Schema.ldf` | Estensione dello schema AD |
| `docs/` | `schema.md`, `crypto.md`, `eventi.md` |

**Build, test e pacchetto**: `.github/workflows/sspr.yml` su Windows a ogni push in questa cartella: controllo sintattico dell'installer con il parser di PowerShell 5.1, build, test, `dotnet publish` self-contained e artefatto **FispaSSPR-package** (`app\`, `schema\`, `Install-FispaSSPR.ps1`, `LEGGIMI.md`), conservato 90 giorni.

Portale on-prem per Active Directory che permette agli utenti di:
- **reimpostare** la password dimenticata;
- **cambiare** la password che conoscono;
- **sbloccare** l'account.

Ha un **pannello di amministrazione** per amministratori e help desk. Si installa e si configura da solo con una procedura guidata di pochi clic.

## Decisioni prese (6 novembre 2026)

| Tema | Decisione |
|---|---|
| Ambiente | Solo on-prem (niente Entra ID) |
| Funzioni | Reset, cambio e sblocco, più il pannello amministratori |
| Verifica dell'identità | Tutti e tre i metodi: app TOTP, SMS, email secondaria |
| SMS | Gratuito: [SMS Gateway for Android](https://sms-gate.app) in modalità locale (telefono Android con SIM in LAN), connettore HTTP generico per altri provider |
| Archivio dei metodi registrati | Attributi AD dedicati (estensione dello schema), confidenziali e cifrati |
| Esposizione | Solo LAN / VPN |
| Motore | Il più solido, **ASP.NET Core** (oggi .NET 10 LTS), senza precludere il passaggio a Node.js: contratto API, formato dei dati e cifratura sono documentati e indipendenti dal linguaggio |
| Installazione | Procedura guidata unica, pochi clic, configurato e funzionante al termine |

## Architettura

```
Browser (SPA statica, nessuna CDN esterna)
   |  HTTPS, API REST documentata in api/openapi.yaml
Servizio Windows "FispaSSPR" (ASP.NET Core 10 self-contained, Kestrel)   <- gira come gMSA
   |-- Directory      : LDAP firmato e sigillato (Kerberos) verso i DC (System.DirectoryServices)
   |-- Enrollment     : attributi AD fispaSspr* cifrati AES-256-GCM
   |-- OTP            : TOTP RFC 6238, codici SMS/email monouso
   |-- Notifiche      : SMTP (relay interno), SMS Gateway for Android / HTTP generico
   |-- Password check : policy di dominio + PSO, password compromesse (HIBP k-anonymity o lista offline)
   |-- Audit          : Registro eventi "SSPR" + log locale
```

- **Niente IIS**: servizio Windows self-contained con Kestrel, quindi niente Hosting Bundle e niente .NET da installare. L'installer copia una cartella e registra il servizio.
- **Intercambiabilità del motore**: la SPA parla solo con l'API (`api/openapi.yaml`). Il dominio applicativo sta dietro interfacce (`IDirectory`, `IEnrollmentStore`, `IOtpChannel`, `IAuditLog`). Schema AD, formato cifrato e configurazione sono documentati, così un backend Node.js può sostituire quello .NET senza toccare frontend, dati e installer.
- **Cartella `active-directory/sspr`** di `fispas/tools`: `src/` (motore, servizio e interfaccia in `wwwroot`), `api/` (OpenAPI), `installer/` (procedura guidata PowerShell), `docs/`, test e CI GitHub Actions.

## Dati in Active Directory

Classe ausiliaria `fispaSsprUser` aggiunta alla classe `user`, con gli attributi:

| Attributo | Tipo | Contenuto |
|---|---|---|
| `fispaSsprTotp` | stringa | Segreto TOTP cifrato |
| `fispaSsprMobile` | stringa | Cellulare verificato, cifrato |
| `fispaSsprEmail` | stringa | Email secondaria verificata, cifrata |
| `fispaSsprState` | stringa | JSON cifrato: data di registrazione, metodi verificati, ultimo reset, ultimo timestep TOTP usato (anti-replay) |

- **OID** generati con il metodo Microsoft (radice `1.2.840.113556.1.8000.2554.*` da GUID), documentati in `docs/schema.md`.
- **Confidenziali**: `searchFlags` 0x80, fuori dal Global Catalog. Li legge e li scrive **solo** il gMSA del portale, sulle OU abilitate. Gli utenti non leggono né scrivono i propri: le modifiche passano dal portale dopo la verifica.
- **Cifratura**: AES-256-GCM, formato `v1:base64(nonce|ciphertext|tag)`. La chiave master sta sul server, protetta con DPAPI-NG verso il SID del gMSA. Durante l'installazione si esporta un backup della chiave protetto da password. Se la chiave va persa, gli utenti devono solo registrarsi di nuovo.
- **L'estensione dello schema è permanente** (gli attributi si possono disattivare ma non eliminare). Va eseguita una volta per foresta da un membro di Schema Admins. L'installer mostra esattamente cosa aggiunge e chiede conferma; c'è anche come script separato per chi gestisce lo schema.

## Funzioni utente

**Registrazione dei metodi**
- Da PC di dominio: accesso automatico con autenticazione Windows.
- Da VPN: nome utente e password attuale.
- TOTP: QR code e verifica di un codice. Cellulare ed email: codice di conferma inviato e verificato.
- Numero minimo di metodi configurabile, predefinito 2.
- Ogni modifica dei metodi viene notificata su tutti i metodi già registrati; la **prima registrazione** viene segnalata all'email aziendale (non ci sono altri recapiti da avvisare).
- Prima registrazione solo dal PC aziendale (accesso Windows): attiva come impostazione consigliata dell'installer.

**Cambio password** (password attuale nota)
- Cambio eseguito *come l'utente*, quindi rispetta cronologia ed età minima.
- Conferma con un metodo registrato, configurabile.

**Reset** (password dimenticata)
1. Nome utente. La risposta è sempre la stessa, che l'account esista o no.
2. Scelta del metodo tra quelli registrati, mostrati mascherati (`+39 *** *** 123`, `m***@g***.com`).
3. Verifica di uno o due codici (configurabile; due metodi per il reset come impostazione predefinita consigliata).
4. Nuova password con verifica dal vivo di policy e password compromesse.
5. Reset eseguito dal gMSA **con cronologia ed età minima della password** (controllo LDAP_SERVER_POLICY_HINTS, come il writeback di Entra; disattivabile), sblocco se necessario, chiusura delle altre sessioni dell'utente, notifica su tutti i metodi.

**Sblocco**: stessa verifica del reset, poi `lockoutTime = 0` e notifica.

## Pannello di amministrazione

- **Accesso**: autenticazione Windows, membro del gruppo AD *SSPR-Admins* o *SSPR-Helpdesk* (nomi configurabili), più un secondo fattore obbligatorio con il proprio TOTP.
- **Ruoli**:
  - *Helpdesk*: ricerca utenti, stato della registrazione, sblocco, azzeramento dei metodi (forza una nuova registrazione), invito via email a registrarsi;
  - *Admin*: tutto quello dell'Helpdesk, più reset con password temporanea e cambio obbligatorio al primo accesso (motivo obbligatorio), configurazione, report.
- **Dashboard**: percentuale di utenti registrati, reset, cambi e sblocchi per periodo, blocchi in corso, tentativi sospetti.
- **Utenti**: ricerca solo nelle OU abilitate, dettaglio con metodi mascherati e ultimi eventi.
- **Audit**: registro filtrabile ed esportabile in CSV.
- **Report**: stato della registrazione e scadenza della password di tutti gli utenti delle OU abilitate, con indicatori, filtri, ordinamento ed esportazione CSV.
- **Configurazione**:
  - OU abilitate e gruppi esclusi;
  - metodi richiesti e durata dei codici;
  - limiti dei tentativi;
  - SMTP, gateway SMS, aspetto (logo, nome azienda, testi);
  - password compromesse.
- **Stato**: connessione ai DC, test SMTP e SMS, scadenza del certificato, chiave master, versione.
- Gli **account protetti** non sono mai gestibili né dal portale né dal pannello: adminCount=1, gruppi privilegiati (anche Cert Publishers, Hyper-V Administrators, Storage Replica Administrators, DnsAdmins e i gruppi di Exchange con diritti su AD), Protected Users, gruppi esclusi, account di servizio e gMSA. Come impostazione predefinita sono esclusi anche gli **operatori del portale** (gruppi admin e help desk): di solito hanno deleghe in AD e un loro reset via SMS sarebbe una scorciatoia verso quei permessi.

## Requisiti di sicurezza

- **Hosting**:
  - server membro, **mai un DC**; solo LAN/VPN;
  - HTTPS con TLS 1.2+ e HSTS; certificato dalla CA aziendale (o importato, oppure autofirmato con avviso);
  - header CSP rigorosi senza script inline, protezione CSRF, cookie `Secure`/`HttpOnly`/`SameSite=Strict`, sessione di reset di 10 minuti al massimo.
- **Identità del servizio**:
  - **gMSA**, con delega minima solo sulle OU abilitate: reimposta password, scrittura di `lockoutTime` e `pwdLastSet`, lettura e scrittura degli attributi `fispaSspr*`;
  - le esclusioni degli account protetti sono controllate anche nel codice, non solo dai permessi.
- **Codici**: TOTP a 6 cifre con anti-replay. I codici SMS ed email:
  - sono a 6 cifre e valgono 5 minuti;
  - sono monouso e ammettono 5 tentativi;
  - sono salvati solo come HMAC.
- **Protezione dagli abusi**:
  - limiti per utente, per IP e globali (prima il limite per IP: chi lo supera non consuma il budget di tutti);
  - **blocco giornaliero**: oltre 10 verifiche fallite in 24 ore (configurabile) reset e conferma d'identità dell'utente restano bloccati fino al giorno dopo;
  - al limite delle sessioni si eliminano prima quelle anonime meno recenti: chi apre sessioni a raffica non blocca gli utenti autenticati;
  - tempi di risposta costanti;
  - nessuna informazione sull'esistenza o sullo stato degli account.
- **Password**:
  - policy di dominio e PSO verificate prima dell'invio;
  - controllo delle password compromesse con HIBP in k-anonymity: escono solo i primi 5 caratteri dell'hash, quindi serve l'uscita verso internet solo per quello. In alternativa una lista offline delle password più comuni;
  - parole vietate configurabili (nome azienda, nome utente);
  - mai registrate nei log né inviate.
- **Conferma d'identità (step-up)**: con un utente già registrato, aggiungere, sostituire o rimuovere metodi e cambiare la password richiedono un codice da un metodo esistente: chi conosce solo la password non può sostituire i metodi. Opzionale: prima registrazione solo da PC aziendale (Windows).
- **Verifica delle credenziali**: bind LDAP Kerberos firmato e cifrato più "Who am I": l'identità autenticata deve coincidere con l'utente (niente fallback su Guest).
- **Anti-enumerazione**: flussi finti indistinguibili, tempi minimi di risposta configurabili, codici di reset inviati in background, regole delle password del singolo utente solo dopo la verifica.
- **Sessioni**: identificativo e token CSRF nuovi a ogni login e logout, scadenza per inattività e assoluta, limite al numero di sessioni, chiusura delle altre sessioni dell'utente dopo cambio o reset della password; sessione del pannello limitata nel tempo con ripetizione del secondo fattore e limite ai codici errati per operatore.
- **Aspetto**: file caricati validati dai byte, serviti con CSP `sandbox`; nessun percorso di file arbitrario in configurazione; testi personalizzati sempre come testo semplice; CSS personalizzato filtrato; colori e carattere validati.
- **Export CSV dell'audit** protetto dalla formula injection.
- **Audit**: Registro eventi `SSPR` con ID documentati, utile anche alla futura dashboard di monitoraggio AD; notifiche all'utente per reset, sblocco e modifica dei metodi.

## Fasi di sviluppo

1. Struttura, OpenAPI, schema AD e cifratura, motore con test. **Scritta**.
2. Servizio, registrazione dei metodi, cambio password, reset, sblocco. **Scritta**.
3. Pannello amministratori. **Scritta**.
4. Installer guidato, aggiornamento, disinstallazione, pacchetto da CI. **Scritta**.
5. Collaudo: CI verde, installazione in laboratorio, correzioni.
6. Documentazione utente e amministratore, pagina da distribuire agli utenti.

## Changelog
- **0.5.0** — **.NET 10 LTS** (.NET 8 esce dal supporto il 10 novembre 2026). Sicurezza: reset con cronologia ed età minima della password (LDAP_SERVER_POLICY_HINTS), blocco giornaliero delle verifiche fallite, operatori del portale e altri gruppi privilegiati (Cert Publishers, Hyper-V Administrators, Storage Replica Administrators, DnsAdmins, Exchange) esclusi dal self-service, avviso all'email aziendale alla prima registrazione, chiusura delle altre sessioni dopo cambio o reset, limite per IP prima di quello globale, sessioni anonime sacrificabili al limite, nessuna sessione creata da richieste senza token, email accettate solo in formato stretto, inoltro SIEM/webhook che non si ferma mai su un errore. Installer: proprietario e permessi della cartella dati rafforzati (chiavi in sola lettura per il servizio), prima registrazione solo da PC aziendale come scelta consigliata. Correzioni: requisiti della password nella lingua dell'utente, avvisi di scadenza con recupero dei giorni saltati e senza doppioni anche con *Esegui ora*, campagna ferma se la registrazione è disattivata, errori di directory delle attività nell'audit, report con password scadute o da cambiare, eventi esatti nella scheda utente, tentativi dei codici modificabili senza riavvio, webhook anche in formato Teams (Adaptive Card).
- **0.4.0** — portale multilingua (italiano e inglese, selettore in intestazione, testi personalizzabili per lingua); avvisi di scadenza della password e campagna di registrazione pianificati, con *Esegui ora* (eventi 1700-1702); report registrazioni e scadenze con CSV; inoltro dell'audit a syslog/SIEM e webhook; nuova grafica del portale e del pannello (icone, indicatori, schede, tabelle ordinabili). Validazione delle nuove impostazioni.
- **0.3.0** — personalizzazione completa dal pannello (logo, icona, sfondo, colori, carattere, CSS, avviso, tutti i testi, notifiche per evento e canale, funzioni attivabili, impostazioni granulari, esporta/importa); editor della configurazione a schede al posto del JSON. Sicurezza: conferma d'identità per modifiche ai metodi e cambio password, prima registrazione solo da Windows (opzionale), verifica credenziali con LDAP "Who am I", rotazione della sessione al logout, scadenze di sessione utente e pannello, limite ai codici errati del secondo fattore, invio dei codici di reset in background, regole PSO solo dopo la verifica, solo oggetti utente da SID, file dell'aspetto validati, CSV senza formula injection, pulizia dell'audit, notifiche anche per le azioni dell'help desk (prima dell'azzeramento). `restore` chiede la password da console.
- **0.2.0** — servizio web (`FispaSspr.Web`), portale utenti, pannello di amministrazione con 2FA operatori, installer guidato `Install-FispaSSPR.ps1` (gMSA, schema, deleghe, certificato, servizio), pacchetto pubblicato dalla CI.
- **0.1.0** — motore `FispaSspr.Core`, test, schema AD, documentazione del formato cifrato e degli eventi, contratto API.
