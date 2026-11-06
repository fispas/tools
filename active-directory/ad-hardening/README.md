# ad-hardening — Fotografia e hardening di Active Directory

> **Stato: progetto in definizione.** Questo file raccoglie linee guida e decisioni. Il codice arriva per fasi.

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
- **Prese** (settembre 2026):
  - ambito limitato al dominio corrente;
  - ADCS e DHCP inclusi se presenti;
  - divisione in parte "healthy" e parte hardening;
  - export HTML / JSON / CSV.
- **Da confermare**:
  - la decisione di settembre era "solo analisi, nessuna remediation", ora superata dalla fase 2. Va deciso se la fase 2 resta nello stesso tool o diventa un tool separato (`ad-hardening-apply`);
  - lingua del report HTML (italiano; inglese in seguito?);
  - soglie di punteggio e pesi: allineati a PingCastle o propri.
