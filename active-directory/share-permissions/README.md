# share-permissions — Migrazione dei permessi delle share a gruppi AD e hardening

Porta le share di un file server dal modello "utenti direttamente nelle ACL" al modello a gruppi (AGDLP) e ne applica l'hardening. Nasce dagli script `Share-AnalisiShareNomi`, `Share-CreaGruppiInBaseAlleShare` e `Share-AddUserPermissionShareAtGroup`, resi generici, sicuri e completi.

## Requisiti
- PowerShell 5.1, cmdlet SMB (Windows Server 2012 / Windows 8 e successivi)
- Amministratore sul file server (locale o remoto: WinRM, con ripiego su DCOM)
- Diritti di creazione gruppi nell'OU indicata e di modifica dei membri
- Macchina nel dominio. **Non serve il modulo ActiveDirectory**: tutto via LDAP, sempre sullo stesso DC

## Uso

```powershell
.\Set-SharePermissions.ps1
```

1. **Configurazione**: file server, share da includere ed escludere, OU e nomi dei gruppi, passi da eseguire, backup. Salvabile in `%ProgramData%\FispaTools\SharePermissions\config.json`, con *Salva come* / *Carica* per più file server.
2. **Share** → *Analizza*: fotografia in sola lettura di ogni share:
   - utenti con permessi espliciti (scrittura o lettura) e gruppi presenti nelle ACL;
   - accesso ampio (Everyone, Users, Authenticated Users, Domain Users), SID orfani, regole di deny, ereditarietà disattivata;
   - permessi della share, Access-Based Enumeration;
   - nomi dei gruppi che verranno usati.
3. Spunta le share → **Applica alle share** → conferma con il riepilogo.

La **simulazione è attiva di default**: per ogni share mostra gruppi, membri e passi, senza modificare nulla.

### Senza GUI
```powershell
.\Set-SharePermissions.ps1 -NoGui -ConfigPath D:\Share\fs01.json -User Contabilita,Tecnico
.\Set-SharePermissions.ps1 -NoGui -Simulate
```
`-User` qui indica i **nomi delle share**. Codici di uscita: `0` ok, `1` configurazione non valida, `2` almeno una share fallita.

## Cosa fa per ogni share (nell'ordine, ogni passo si attiva dalla configurazione)
1. **Backup**: `icacls /save` della cartella (o dell'intero albero) e permessi della share in JSON, in `<backup>\<server>\<data>\`. Nel log c'è il comando di ripristino:
   `icacls "<cartella padre>" /restore "<file>.acl"`. Se il backup fallisce, la share non viene toccata.
2. **Gruppi**: `<prefisso><Share>_RW` e `<prefisso><Share>_RO` (oppure un gruppo unico), creati nell'OU se mancano. Ambito consigliato: DomainLocal.
3. **Membri**: gli utenti con permesso di scrittura entrano nel gruppo RW, quelli in sola lettura nel gruppo RO. Opzionalmente si annidano anche i gruppi già presenti nelle ACL. Non vengono mai aggiunti account amministrativi, di sistema, orfani o esclusi.
4. **NTFS**: ACE del gruppo sulla cartella della share (Modifica / Lettura ed esecuzione), ereditata da tutto l'albero.
5. **Pulizia**: rimozione delle ACE esplicite degli utenti migrati, solo sulla radice o nell'intero albero. Viene fatta **solo** per chi è risultato membro del gruppo del proprio livello e solo se il gruppo ha ricevuto l'ACE, quindi nessuno perde l'accesso alla share.
6. **Hardening**:
   - permessi della share standard (Authenticated Users Modifica, Administrators Full, Everyone rimosso), con i nomi risolti sul file server, quindi indipendenti dalla lingua;
   - Access-Based Enumeration;
   - cifratura SMB.

## Attenzione
- **Intero albero**: chi aveva permessi espliciti diversi in una sottocartella li perde e resta con il solo accesso del gruppo. In quel caso fare prima il backup dell'albero e valutare con la simulazione.
- I permessi effettivi cambiano al **prossimo logon** degli utenti, quando il token include i nuovi gruppi. Conviene applicare fuori orario e poi far fare logoff/logon.
- **Cifratura SMB**: i client senza SMB 3 non accedono più.

## Output
- Log e report CSV in `%ProgramData%\FispaTools\SharePermissions\Log` (nel report, la colonna Utente contiene il nome della share)
- Backup in `%ProgramData%\FispaTools\SharePermissions\Backup`

## Sviluppo
Generato da `_src/` con `python _lib/build.py` (libreria comune in `_lib/toolkit`). Non modificare a mano `Set-SharePermissions.ps1`.

## Changelog
- **1.0.0** — prima versione: analisi, gruppi RW/RO via LDAP, popolamento dalle ACL, ACE di gruppo, rimozione sicura delle ACE utente, permessi share standard, ABE, cifratura SMB, backup con comando di ripristino, simulazione, GUI e `-NoGui`.
