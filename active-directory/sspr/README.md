# sspr — Self Service Password Reset

> **Stato: progetto in definizione.** Linee guida e decisioni aperte. Essendo un'applicazione web, il codice andrà in un **repo dedicato** (regola di `fispas/tools`); qui restano progetto, script di installazione e configurazione lato AD.

Permette agli utenti di reimpostare (password dimenticata) o cambiare la propria password di dominio e di sbloccare l'account, senza passare dall'help desk, con le massime garanzie di sicurezza.

## Prima scelta: usare Entra ID se c'è
Se il cliente è **ibrido con Microsoft 365** e ha Entra ID P1 (Business Premium, E3/E5):
**Entra SSPR + password writeback** (Entra Connect o Cloud Sync) è più sicuro di qualunque portale fatto in casa: MFA, registrazione dei metodi, protezione dagli attacchi e audit sono gestiti da Microsoft e on-prem non si espone nulla.
In quel caso questo tool si limita a **verificare e configurare**: writeback attivo, permessi dell'account di sincronizzazione, metodi abilitati, registrazione obbligatoria, report di utilizzo.

Il portale custom serve solo per i clienti **solo on-prem**.

## Portale custom: regole di sicurezza (non negoziabili)

**Infrastruttura**
- Su un **server membro** dedicato o condiviso a basso rischio. **Mai su un domain controller.**
- Solo HTTPS (TLS 1.2+, HSTS), certificato valido. Esposto su Internet solo dietro reverse proxy/WAF; preferibile solo rete interna o VPN.
- Header di sicurezza (CSP, X-Frame-Options, X-Content-Type-Options), protezione CSRF, nessun dato sensibile nei log.

**Identità del servizio**
- Gira con un **gMSA**, mai con un account con password.
- Delega AD **minima**: solo "Reimposta password", "Scrivi pwdLastSet" e "Scrivi lockoutTime" sugli oggetti utente delle OU abilitate. Niente diritti sulle OU amministrative.
- **Esclusi sempre**, con un controllo nel codice oltre ai permessi:
  - account con adminCount=1;
  - membri di Protected Users e dei gruppi privilegiati;
  - account Tier 0, account di servizio e gMSA;
  - account disabilitati o scaduti.

**Verifica dell'identità**
- Registrazione dei metodi fatta da utente **già autenticato** (accesso integrato Windows o login con password attuale), con conferma del metodo prima di salvarlo.
- Metodi:
  - codice TOTP da app di autenticazione (consigliato);
  - codice monouso via SMS al cellulare registrato (serve un gateway SMS, da scegliere);
  - codice via email a un indirizzo **secondario**, mai quello aziendale che dipende dalla password.
- Mai le sole domande di sicurezza. Per il reset si possono richiedere due metodi.
- I codici scadono in 5–10 minuti, sono monouso e salvati solo come hash.

**Protezione dagli abusi**
- Limite di tentativi per utente e per IP, blocco progressivo, CAPTCHA dopo i primi errori.
- Risposte e tempi **identici** per utenti esistenti e inesistenti (nessuna enumerazione).
- Il portale non rivela mai se un account esiste, è bloccato o ha metodi registrati.

**Password**
- Rispetto della policy di dominio e delle PSO (lunghezza, complessità, cronologia), validata prima di inviarla ad AD.
- Controllo contro le **password compromesse** (lista HIBP offline in formato k-anonymity, aggiornata periodicamente) e contro parole vietate (nome azienda, nome utente).
- Mai registrata, mai inviata per email.

**Audit e notifiche**
- Registro eventi dedicato (`SSPR`) per registrazione, richieste, reset, sblocchi, errori e blocchi, con ID evento documentati. Serve anche alla futura dashboard di monitoraggio.
- Notifica all'utente (sul metodo registrato) a ogni reset e a ogni cambio dei metodi.
- Report periodico: utenti registrati, reset effettuati, tentativi sospetti.

## Architettura proposta
- **ASP.NET Core** su IIS (Windows Server 2016+), autenticazione Windows per la registrazione, accesso ad AD con `System.DirectoryServices.AccountManagement` sul gMSA.
- Archivio dei metodi registrati: attributi AD dedicati (estensione di schema) **oppure** database locale cifrato. Da decidere: gli attributi AD si replicano e non richiedono un DB, ma vanno protetti in lettura.
- Installazione e configurazione lato AD (gMSA, deleghe sulle OU, esclusioni, registro eventi) con uno script di `fispas/tools` sullo standard del repo, con GUI e simulazione.

## Decisioni aperte
1. Clienti tipici: ibridi M365 (Entra SSPR) e/o solo on-prem (portale custom).
2. Funzioni: reset (password dimenticata), cambio (password nota, anche da fuori rete), sblocco. Una, alcune o tutte.
3. Metodi di verifica: TOTP, SMS (con quale gateway), email secondaria.
4. Dove salvare i metodi registrati: attributi AD o database cifrato.
5. Esposizione: solo LAN/VPN o anche Internet dietro reverse proxy.
6. Nome e repo dedicato dell'applicazione web.
