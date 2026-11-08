# ad-hardening — Fotografia e hardening di Active Directory

> **Stato:** versione 0.3.0 — fotografia (31 controlli, con confronto automatico), hardening (42 azioni) e ripristino dai backup nello stesso tool, da collaudare in laboratorio. Fase 3 (documentazione) da fare. Questo file raccoglie anche linee guida e decisioni.

## Uso della fase 1 — `Invoke-ADAssessment.ps1`

```powershell
.\Invoke-ADAssessment.ps1                       # GUI: Configurazione -> Controlli -> Analizza -> Esegui i controlli
.\Invoke-ADAssessment.ps1 -NoGui                # tutti i controlli con la configurazione salvata
.\Invoke-ADAssessment.ps1 -NoGui -User K-ASREP-01,K-DEL-01
```
- **Sola lettura**: non modifica nulla. Funziona da un utente di dominio standard, senza moduli aggiuntivi (LDAP/ADSI). I controlli che richiedono più privilegi, come i servizi sui DC, risultano *Non verificato*.
- **Output** in `%ProgramData%\FispaTools\ADAssessment\Report`:
  - `ADAssessment_<dominio>_<data>.html`: punteggio, riepilogo per categoria, controlli ordinati per gravità, remediation, evidenze;
  - `.json` completo;
  - `_controlli.csv` e `_evidenze.csv`.
- **Punteggio**: 100 meno i punti di rischio. Un *Critico* vale il peso pieno del controllo, un *Attenzione* metà.

| ID | Controllo |
|---|---|
| H-DC-01 | Domain controller e sistemi operativi |
| H-FL-01 | Livello funzionale di dominio e foresta |
| H-SYSVOL-01 | Replica SYSVOL: DFSR o FRS (stato della migrazione) |
| H-BIN-01 | Cestino AD |
| H-FSMO-01 | Ruoli FSMO |
| P-ADM-01 | Membri dei gruppi privilegiati (ricorsivi), Schema Admins, Operators |
| P-KRB-01 | Età della password di krbtgt |
| P-ADM-02 | Administrator integrato |
| P-ADC-01 | adminCount orfani |
| P-SENS-01 | Admin delegabili e fuori da Protected Users |
| P-PU-01 | Gruppo Protected Users |
| K-SPN-01 | Account utente con SPN (kerberoasting) |
| K-ASREP-01 | Preautenticazione Kerberos disattivata |
| K-DEL-01 | Delega non vincolata |
| K-DES-01 | Cifratura DES |
| W-POL-01 | Policy delle password di dominio |
| W-NREQ-01 | Password non obbligatoria |
| W-REV-01 | Cifratura reversibile |
| W-NEXP-01 | Password che non scadono |
| W-INACT-01 | Utenti inutilizzati |
| W-COMP-01 | Computer obsoleti o inattivi |
| C-MAQ-01 | MachineAccountQuota |
| C-PRE2K-01 | Accesso compatibile pre-Windows 2000 |
| C-LAPS-01 | LAPS (Windows e legacy): schema e copertura |
| C-GMSA-01 | KDS root key e gMSA |
| C-GPP-01 | Password nelle GPP (cpassword) in SYSVOL |
| C-TRUST-01 | Trust e SID filtering |
| C-SPOOL-01 | Print Spooler sui DC |

Prossimi controlli della fase 1:
- replica AD e backlog DFSR;
- DNS;
- ADCS (ESC1–ESC8);
- ACL su dominio e AdminSDHolder (DCSync);
- GPO (permessi, GPO vuote o non collegate);
- NTLM / LDAP signing / SMB signing / SMBv1;
- audit policy effettiva;
- logon degli account Tier 0;
- confronto tra due fotografie.

## Uso della fase 2 — hardening (stesso script)

```powershell
.\Invoke-ADAssessment.ps1        # Configurazione: Modalita' = Hardening -> Controlli e azioni -> Analizza -> spunta -> Esegui
.\Invoke-ADAssessment.ps1 -NoGui -ConfigPath .\hardening.json -User HD-MAQ,HD-PRE2K -Simulate
```
- **Analizza** verifica lo stato attuale di ogni azione: *Conforme* (non selezionabile), *Da applicare* (con il dettaglio), *Non verificabile*.
- **Simulazione attiva di default**: il report dice esattamente cosa verrebbe fatto. Per applicare si toglie la spunta *Simulazione* e si conferma.
- Per ogni azione applicata: **backup JSON dello stato precedente**, applicazione, **nuova verifica** (*OK* oppure *Attenzione* se l'effetto non è ancora visibile, es. replica), istruzioni di annullamento nel report.
- Report in `<cartella report>\Hardening_<dominio>_<data>\` (HTML, CSV, JSON, `*.backup.json`).
- Requisiti: RSAT ActiveDirectory e GroupPolicy, account Domain Admins (cestino AD ed Enterprise/Schema per poche azioni). Tutte le operazioni (LDAP, GPO, SYSVOL) usano lo stesso DC.

| Area | Azioni (ID) | Impatto |
|---|---|---|
| Dominio | `HD-BIN` cestino AD · `HD-MAQ` MachineAccountQuota=0 · `HD-PRE2K` Anonymous/Everyone fuori da Pre-Windows 2000 · `HD-KDS` KDS root key · `HD-PWDPOL` policy password di dominio (lunghezza, complessità, blocco) | basso → alto |
| Account privilegiati | `HD-SCHEMA` svuota Schema Admins · `HD-SENSITIVE` sensibili e non delegabili · `HD-PROTUSERS` Protected Users (elenco o tutti, esclusi SPN, Administrator e break-glass) · `HD-ADMINPSO` PSO dedicata agli admin · `HD-ADMINCOUNT` adminCount orfani + ereditarietà ACL · `HD-KRBTGT` rotazione krbtgt in **due passaggi** con controllo della replica su tutti i DC | basso → alto |
| Account | `HD-ASREP` · `HD-DES` · `HD-REVERSIBLE` · `HD-PWDNOTREQD` · `HD-GUEST` · `HD-INACTIVE-USERS` · `HD-INACTIVE-COMPUTERS` (disattiva, annota, opzionalmente sposta in quarantena; esclusioni e break-glass) | basso / medio |
| Windows LAPS | `HD-LAPS-SCHEMA` · `HD-LAPS-PERM` (SELF sulle OU) · `HD-LAPS-GPO` (lunghezza, rotazione, azioni post-autenticazione, account gestito) | basso |
| GPO DC | `HD-DC-LDAPSIGN` · `HD-DC-LDAPCB` · `HD-DC-SMBSIGN` · `HD-DC-SMB1` · `HD-DC-NTLM` · `HD-DC-SPOOLER` (anche stop immediato) · `HD-DC-LSAPPL` · `HD-DC-WDIGEST` · `HD-DC-LOGS` (registro Security, riga di comando dei processi, script block logging) · `HD-DC-AUDIT` (30 sottocategorie dei criteri avanzati, baseline Microsoft) | basso → alto |
| GPO server e client | `HD-MB-SMB1` · `HD-MB-WDIGEST` · `HD-MB-LSAPPL` · `HD-MB-NTLM` · `HD-MB-SMBSIGN` sulle OU indicate | medio / alto |
| Tier model | `HD-TIER-OU` OU Tier0/1/2 (Accounts, Groups, Devices, ServiceAccounts) protette, gruppi TierN-Admins · `HD-TIER-LOGON` GPO di deny logon (locale, RDP, rete, batch, servizio) Tier0→Tier1/2 e Tier1→Tier2, **non collegate** finché non si sceglie | alto |

Configurazione granulare in GUI: prefisso e modalità di collegamento delle GPO (attiva / disattivata / non collegata), OU per server e client, livello NTLM, channel binding, dimensione dei log, stop immediato dello Spooler, policy password e PSO, Protected Users, account break-glass, gestione degli inattivi, intervallo krbtgt, OU e parametri LAPS, nome del tier model e collegamento delle sue GPO.

**Novità 0.3.0**
- Controlli **ADCS ESC1–ESC4** (modelli pubblicati sfruttabili da utenti comuni), **DCSync** e controllo dell'oggetto dominio concessi a principali non standard (account Entra Connect riconosciuti e segnalati a parte), **AdminSDHolder** con permessi anomali.
- **Confronto** automatico con la fotografia precedente dello stesso dominio (o con un file scelto): variazione del punteggio, rischi nuovi, peggiorati, migliorati, risolti, nuove evidenze.
- Azioni `HD-DC-NTLMAUDIT` / `HD-MB-NTLMAUDIT` (audit NTLM prima di restringerlo), `HD-MB-CREDGUARD` (Credential Guard senza blocco UEFI), `HD-MB-RCG` (Remote Credential Guard per RDP).
- **Modalità Ripristino**: si indica la cartella `Hardening_<dominio>_<data>`; Analizza elenca i backup, ciascuno annullabile (flag degli account, valori delle GPO, account inattivi riattivati e riportati nell'OU d'origine, membri dei gruppi, MachineAccountQuota, policy password, PSO, adminCount, collegamenti delle GPO disattivati). Cestino AD, KDS, schema LAPS, krbtgt e OU del tier model restano manuali e sono segnalati. Simulazione di default.
- Report HTML con lo stile comune (punteggio ad anello, filtri per esito, ricerca nelle evidenze, tema scuro, stampa/PDF).

Le password GPP (cpassword) e la delega non vincolata restano solo segnalate dalla fotografia: si correggono a mano (serve sapere cosa usa quella configurazione).

Sviluppo: sorgenti in `_src/` (controlli in `engine.ps1`, `Get-AdChecks`; azioni in `hardening.ps1`, `Get-HardeningActions`), file generato con `python _lib/build.py`.

Tool per fotografare lo stato di sicurezza e salute di un dominio Active Directory, nello stile di PingCastle e Purple Knight, e applicare le best practice di hardening in modo guidato e reversibile. Alla fine produce anche la documentazione.

## Fasi

| Fase | Contenuto | Modifica il dominio |
|---|---|---|
| 1. Fotografia | Controlli di salute e sicurezza, punteggio, rischio, export HTML/JSON/CSV, confronto tra due fotografie | No |
| 2. Hardening | Moduli di remediation, ognuno con analisi di impatto, anteprima, simulazione, backup e rollback | Sì, solo su conferma |
| 3. Documentazione | Report Word "Analisi Healthcheck Active Directory" dalla fotografia (oggi si fa a mano da PingCastle) | No |

## Fase 1 — Fotografia (sola lettura)

Ambito: dominio corrente. Ogni controllo produce: ID, categoria, titolo, esito (OK / Attenzione / Critico / Non applicabile), punti di rischio, evidenze (oggetti coinvolti), spiegazione, remediation consigliata, riferimenti (MITRE ATT&CK, ANSSI, CIS, Microsoft).

**Salute del dominio ("healthy")**
- DC: sistema operativo, ruoli FSMO, GC, servizi critici (NTDS, DNS, Netlogon, KDC, DFSR, W32Time), sincronizzazione dell'ora
- Replica AD (`repadmin` / API), errori e latenza; siti e subnet senza associazione
- **SYSVOL: DFSR o ancora FRS**, stato della migrazione, backlog, coerenza delle GPO tra DC (elemento distintivo)
- DNS: zone integrate in AD, scavenging, record dei DC, forwarder
- Livello funzionale di foresta e dominio, cestino AD, backup di sistema recente
- ADCS e DHCP se presenti

**Sicurezza ("hardening")**
- Account privilegiati: membri di Domain/Enterprise/Schema Admins, Administrators, Account/Server/Backup/Print Operators, DnsAdmins; annidamenti; adminCount orfani
- krbtgt: età della password; Administrator built-in: uso, password, rinomina
- Kerberos: account con SPN (kerberoasting), senza preautenticazione (AS-REP roasting), delega non vincolata, vincolata e RBCD, cifratura DES/RC4
- Password: policy di dominio, PSO, password che non scadono, password non richiesta, reversibile, account inattivi, computer obsoleti
- **LAPS** (Windows LAPS o legacy): copertura, schema, permessi di lettura
- **gMSA**: KDS root key, servizi e task pianificati che girano con account utente di dominio
- **Protected Users** e "account sensibile, non delegabile" sugli amministrativi
- Audit policy avanzata effettiva sui DC
- NTLM (v1, restrizioni), LDAP signing e channel binding, SMB signing, SMBv1, Print Spooler sui DC, MachineAccountQuota, accesso anonimo (Pre-Windows 2000 Compatible Access)
- GPO: permessi di modifica anomali, GPP con password (cpassword), GPO non collegate o vuote
- ADCS: template vulnerabili (ESC1–ESC8), permessi della CA, web enrollment
- ACL pericolose sull'oggetto dominio e su AdminSDHolder (DCSync, GenericAll, WriteDacl)
- Trust: direzione, SID filtering, selective authentication
- **Tier model**: dove si collegano gli account Tier 0 (eventi di logon), presenza di PAW, separazione degli account

**Output**: report HTML navigabile (stile WinAuditPro), JSON completo, un CSV per ogni casistica, punteggio per categoria e globale. Due fotografie si confrontano: nuovi rischi, rischi risolti, trend.

## Fase 2 — Hardening (moduli)

Regole valide per **ogni** modulo:
1. **Analisi di impatto** prima di tutto: cosa cambia, chi viene colpito (es. servizi che usano NTLM, account con delega, logon degli admin su server Tier 1).
2. **Anteprima e simulazione** attive di default. Nessuna modifica senza conferma esplicita.
3. **Backup** prima di ogni modifica: GPO (`Backup-GPO`), oggetti e ACL modificati, membri dei gruppi.
4. **Rollback** documentato e, dove possibile, automatico.
5. **Rollout a fasi**: prima un'OU o un gruppo pilota, poi l'estensione.
6. Log di ogni azione e report finale.

| Modulo | Cosa fa | Note di sicurezza |
|---|---|---|
| gMSA | KDS root key, creazione gMSA, gruppo dei server autorizzati, sostituzione di servizi e task che usano account utente | La KDS root key diventa effettiva dopo 10 ore; verificare `Test-ADServiceAccount` sul server prima di cambiare il servizio |
| Windows LAPS | Estensione dello schema, permessi alle OU, GPO, cifratura della password, delega di lettura | Lo schema richiede Schema Admins; coesistenza e migrazione da LAPS legacy |
| Protected Users | Aggiunta degli account amministrativi dopo il controllo di compatibilità | Niente NTLM, delega, DES/RC4 né credenziali in cache: **mai** gli account di servizio; sempre un account break-glass fuori dal gruppo |
| Account sensibili | "Account sensibile, non delegabile" sugli amministrativi | |
| Audit policy | GPO di audit avanzato sui DC e sui server secondo le baseline Microsoft, più dimensione dei log | Base anche per la futura dashboard di monitoraggio |
| Tier model | OU Tier 0/1/2, gruppi admin per tier, GPO di deny logon (locale, RDP, rete, batch, servizio) incrociate, PAW, account break-glass | Il più invasivo: analisi dei logon reali, pilota, break-glass **verificato** prima di applicare. Rischio di restare fuori dal dominio |
| Protocolli | NTLMv1 off, audit e poi restrizione di NTLM, LDAP signing e channel binding, SMB signing, SMBv1 off, Spooler off sui DC | Sempre prima in modalità audit, poi enforcement |
| Pulizia | MachineAccountQuota = 0, Pre-Windows 2000 Compatible Access, adminCount orfani, account e computer inattivi (disabilita, poi elimina) | |
| krbtgt | Rotazione doppia controllata, con attesa della replica tra le due | Mai due rotazioni ravvicinate |

## Fase 3 — Documentazione
Report Word sullo schema dell'"Analisi Healthcheck Active Directory" già in uso: sintesi per la direzione, punteggi, rischi principali, piano di remediation per priorità, allegati tecnici. Nome file `Report - Assessment AD - <dominio>.docx`, con i campi autore e approvatore configurabili.

## Architettura
- PowerShell 5.1, sulla libreria `_lib/toolkit`: GUI a schede, configurazione JSON, `-NoGui`, report.
- Controlli definiti in modo dichiarativo (id, categoria, peso, funzione di raccolta, funzione di valutazione), così se ne aggiungono senza toccare il motore.
- Raccolta dati via LDAP/ADSI e API .NET. Il modulo ActiveDirectory e GroupPolicy si usano se presenti, altrimenti il controllo viene segnato come "non verificato" invece di fallire.
- Esecuzione da un server membro o da un DC, con un account Domain Admin solo per la fase 2. La fase 1 deve funzionare il più possibile con un utente di dominio standard, segnalando i controlli che richiedono più privilegi.

## Decisioni
- **Prese** (settembre 2026, aggiornate a novembre 2026):
  - fase 2 (hardening) nello **stesso tool**, come modalità;
  - ambito limitato al dominio corrente;
  - ADCS e DHCP inclusi se presenti;
  - divisione in parte "healthy" e parte hardening;
  - export HTML / JSON / CSV.
- **Da confermare**:
  - lingua del report HTML (italiano; inglese in seguito?);
  - soglie di punteggio e pesi: allineati a PingCastle o propri.

## Changelog
- **0.3.1** — revisione: DC e computer con Windows Server 2012/2012 R2 ora critici (ESU finiti il 13/10/2026), Server 2016 segnalato (supporto fino al 12/01/2027), Windows 10 non LTSC segnalato (solo con ESU); trust: SID filtering verificato sui trust in uscita (prima sulla direzione sbagliata), SID history e delega TGT sui trust di foresta; SYSVOL DFSR riconosciuta anche nei domini nati con DFSR; Key Admins, Enterprise Key Admins e Replicator tra i gruppi privilegiati; AS-REP solo sugli account attivi. Hardening: controllo della replica di krbtgt su tutti i DC prima della rotazione (prima non confrontava davvero i valori), account di trust tra domini mai disattivati come inattivi, SMBv1 client disattivato insieme alla dipendenza del servizio Workstation (come indica Microsoft), diritti utente scritti senza cancellare il resto di GptTmpl.inf. Ripristino: si ripristinano solo i bit di userAccountControl cambiati dall'hardening (un account disattivato dopo resta disattivato), tipo dei valori GPO conservato. Senza interfaccia (`-NoGui`) hardening e ripristino reali richiedono l'elenco esplicito delle azioni (`-User`): niente "applica tutto" da un'operazione pianificata.
- **0.3.0** — controlli ADCS ESC1-ESC4, DCSync, AdminSDHolder; confronto tra fotografie; azioni audit NTLM, Credential Guard, Remote Credential Guard; modalità Ripristino dai backup; report e GUI con la nuova grafica.
- **0.2.0** — fase 2: modalità Hardening con 38 azioni (dominio, account privilegiati, account, Windows LAPS, GPO DC e membri, criteri di audit avanzati, tier model), verifica prima/dopo, simulazione di default, backup JSON, report HTML/CSV/JSON con istruzioni di annullamento; configurazione granulare in GUI.
- **0.1.0** — fase 1: 28 controlli in sola lettura, report HTML / JSON / CSV, punteggio, GUI e `-NoGui`.
