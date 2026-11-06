# sspr — Self Service Password Reset (on-prem)

> **Stato: fase 1 in corso** (motore, schema AD, cifratura, contratto API). Su richiesta, il progetto vive qui in `fispas/tools`, anche se è un'applicazione web.

## Struttura della cartella
| Percorso | Contenuto | Stato |
|---|---|---|
| `src/FispaSspr.Core` | Motore indipendente da AD e dal web: cifratura AES-GCM, TOTP, codici monouso, limiti dei tentativi, protezione degli account, policy password e password compromesse, codec degli attributi, interfacce, configurazione | Fase 1 |
| `tests/FispaSspr.Core.Tests` | Test xUnit (vettori RFC 6238/4648, manomissioni, iniezione LDAP, account protetti...) | Fase 1 |
| `api/openapi.yaml` | Contratto API tra interfaccia web e motore | Fase 1 |
| `installer/schema/FispaSSPR-Schema.ldf` | Estensione dello schema AD | Fase 1 |
| `docs/` | `schema.md`, `crypto.md`, `eventi.md` | Fase 1 |
| `src/FispaSspr.Directory` | Implementazione AD (LDAP/Kerberos come gMSA), DPAPI-NG | Fase 2 |
| `src/FispaSspr.Web` + `web/` | Servizio Windows (Kestrel) e interfaccia utente/amministratore | Fasi 2-3 |
| `installer/` | Procedura guidata `Install-FispaSSPR.ps1` | Fase 4 |

**Build e test**: `.github/workflows/sspr.yml` compila ed esegue i test su Windows a ogni push in questa cartella; i risultati sono nella scheda *Actions* del repo. In locale: `dotnet test tests/FispaSspr.Core.Tests`.

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
| Motore | Il più solido, **ASP.NET Core 8**, senza precludere il passaggio a Node.js: contratto API, formato dei dati e cifratura sono documentati e indipendenti dal linguaggio |
| Installazione | Procedura guidata unica, pochi clic, configurato e funzionante al termine |

## Architettura

```
Browser (SPA statica, nessuna CDN esterna)
   |  HTTPS, API REST documentata in api/openapi.yaml
Servizio Windows "FispaSSPR" (ASP.NET Core 8 self-contained, Kestrel)   <- gira come gMSA
   |-- Directory      : LDAP/Kerberos verso i DC (System.DirectoryServices.Protocols)
   |-- Enrollment     : attributi AD fispaSspr* cifrati AES-256-GCM
   |-- OTP            : TOTP RFC 6238, codici SMS/email monouso
   |-- Notifiche      : SMTP (relay interno), SMS Gateway for Android / HTTP generico
   |-- Password check : policy di dominio + PSO, password compromesse (HIBP k-anonymity o lista offline)
   |-- Audit          : Registro eventi "SSPR" + log locale
```

- **Niente IIS**: servizio Windows self-contained con Kestrel, quindi niente Hosting Bundle e niente .NET da installare. L'installer copia una cartella e registra il servizio.
- **Intercambiabilità del motore**: la SPA parla solo con l'API (`api/openapi.yaml`). Il dominio applicativo sta dietro interfacce (`IDirectory`, `IEnrollmentStore`, `IOtpChannel`, `IAuditLog`). Schema AD, formato cifrato e configurazione sono documentati, così un backend Node.js può sostituire quello .NET senza toccare frontend, dati e installer.
- **Cartella `active-directory/sspr`** di `fispas/tools`: `src/` (backend), `web/` (SPA), `api/` (OpenAPI), `installer/` (procedura guidata PowerShell sullo standard del repo), `docs/`, test e CI GitHub Actions.

## Dati in Active Directory

Classe ausiliaria `fispaSsprUser` aggiunta alla classe `user`, con gli attributi:

| Attributo | Tipo | Contenuto |
|---|---|---|
| `fispaSsprTotp` | ottetti | Segreto TOTP cifrato |
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
- Ogni modifica dei metodi viene notificata su tutti i metodi già registrati.

**Cambio password** (password attuale nota)
- Cambio eseguito *come l'utente*, quindi rispetta cronologia ed età minima.
- Conferma con un metodo registrato, configurabile.

**Reset** (password dimenticata)
1. Nome utente. La risposta è sempre la stessa, che l'account esista o no.
2. Scelta del metodo tra quelli registrati, mostrati mascherati (`+39 *** *** 123`, `m***@g***.com`).
3. Verifica di uno o due codici (configurabile; due metodi per il reset come impostazione predefinita consigliata).
4. Nuova password con verifica dal vivo di policy e password compromesse.
5. Reset eseguito dal gMSA, sblocco se necessario, notifica su tutti i metodi.

**Sblocco**: stessa verifica del reset, poi `lockoutTime = 0` e notifica.

## Pannello di amministrazione

- **Accesso**: autenticazione Windows, membro del gruppo AD *SSPR-Admins* o *SSPR-Helpdesk* (nomi configurabili), più un secondo fattore obbligatorio con il proprio TOTP.
- **Ruoli**:
  - *Helpdesk*: ricerca utenti, stato della registrazione, sblocco, azzeramento dei metodi (forza una nuova registrazione), invito via email a registrarsi;
  - *Admin*: tutto quello dell'Helpdesk, più reset con password temporanea e cambio obbligatorio al primo accesso (motivo obbligatorio), configurazione, report.
- **Dashboard**: percentuale di utenti registrati, reset, cambi e sblocchi per periodo, blocchi in corso, tentativi sospetti.
- **Utenti**: ricerca solo nelle OU abilitate, dettaglio con metodi mascherati e ultimi eventi.
- **Audit**: registro filtrabile ed esportabile in CSV.
- **Configurazione**:
  - OU abilitate e gruppi esclusi;
  - metodi richiesti e durata dei codici;
  - limiti dei tentativi;
  - SMTP, gateway SMS, aspetto (logo, nome azienda, testi);
  - password compromesse.
- **Stato**: connessione ai DC, test SMTP e SMS, scadenza del certificato, chiave master, versione.
- Gli **account protetti** non sono mai gestibili né dal portale né dal pannello: adminCount=1, gruppi privilegiati, Protected Users, gruppi esclusi, account di servizio e gMSA.

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
  - limiti per utente, per IP e globali, blocco progressivo;
  - tempi di risposta costanti;
  - nessuna informazione sull'esistenza o sullo stato degli account.
- **Password**:
  - policy di dominio e PSO verificate prima dell'invio;
  - controllo delle password compromesse con HIBP in k-anonymity: escono solo i primi 5 caratteri dell'hash, quindi serve l'uscita verso internet solo per quello. In alternativa una lista offline delle password più comuni;
  - parole vietate configurabili (nome azienda, nome utente);
  - mai registrate nei log né inviate.
- **Audit**: Registro eventi `SSPR` con ID documentati, utile anche alla futura dashboard di monitoraggio AD; notifiche all'utente per reset, sblocco e modifica dei metodi.

## Installazione guidata (`Install-FispaSSPR.ps1`, GUI)

1. Verifica dei prerequisiti: server membro 2016+, non DC, porta libera, account dell'operatore.
2. **Schema**: verifica e, se manca, estensione con conferma (Schema Admins). In alternativa genera lo script per l'amministratore dello schema.
3. **gMSA**: verifica della KDS root key e creazione del gMSA. Se la chiave è nuova e servono 10 ore, la procedura lo spiega e riprende più tardi.
4. **OU abilitate e gruppi**: selezione delle OU da un albero, creazione di *SSPR-Admins* e *SSPR-Helpdesk*, deleghe e ACL sugli attributi confidenziali.
5. **Certificato**: richiesta alla CA aziendale, import di un PFX o certificato autofirmato.
6. **Servizio**: copia in `%ProgramFiles%\FispaSSPR`, servizio Windows come gMSA con ripristino automatico, regola firewall solo per i profili Dominio/Privato, sorgente del Registro eventi, chiave master con backup.
7. **SMTP, SMS e aspetto**, con pulsanti di test.
8. Avvio, verifica dello stato, apertura del portale; indirizzo da pubblicare (collegamento via GPO, link nella schermata di logon).

Previsti anche aggiornamento (sostituzione dei file, configurazione invariata) e disinstallazione (servizio, deleghe, gruppi; lo schema resta, ma lo si può disattivare).

## Fasi di sviluppo

1. Struttura, OpenAPI, schema AD e cifratura, motore con test. **In corso**: motore Core e test scritti, in attesa della prima esecuzione della CI.
2. Registrazione dei metodi, cambio password, reset, sblocco.
3. Pannello amministratori.
4. Installer guidato, aggiornamento, disinstallazione.
5. Documentazione utente e amministratore, pagina da distribuire agli utenti.
