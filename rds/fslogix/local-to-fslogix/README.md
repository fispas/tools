# local-to-fslogix — Profili locali → FSLogix

Tool con interfaccia grafica (GUI) scritto in PowerShell per automatizzare, gestire e monitorare la migrazione massiva di profili utente locali (Windows) verso container FSLogix (VHDX).

## 🚀 Funzionalità Principali

* **Interfaccia Grafica (GUI):** Semplifica la selezione dei percorsi e degli utenti da migrare tramite moduli Windows Forms.
* **Esecuzione Asincrona (Runspaces):** L'operazione di copia massiva avviene in un thread separato. L'interfaccia grafica rimane reattiva e si aggiorna in tempo reale senza fastidiosi blocchi (freeze).
* **Validazione Pre-Migrazione (Pre-Checks):**
* Risoluzione automatica dell'identificatore di sicurezza (SID) dell'utente.
* Verifica dell'integrità del profilo nel registro di sistema (`HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`), ignorando profili corrotti o temporanei (`.bak`).
* Controllo di accesso su `ntuser.dat` per assicurarsi che il profilo non sia attualmente in uso (utente loggato).


* **Assegnazione Automatica Permessi (ACL):** Utilizza `icacls` per creare le cartelle di destinazione (`SID_Username`) e assegnare automaticamente la proprietà (Owner) e i permessi corretti all'utente di dominio.
* **Test Post-Migrazione:** Verifica la corretta creazione fisica del file `.vhdx` nel percorso di destinazione e controlla che la sua dimensione sia maggiore di 0 byte per validare il successo dell'operazione.
* **Logging Dettagliato:** Mostra l'output in tempo reale direttamente nella GUI e salva una copia permanente in un file testuale con timestamp (es. `%TEMP%\FSLogixMigration\FSLogix_Migration_Log_...`).

## 🛠️ Prerequisiti

1. **Privilegi:** Lo script *deve* essere eseguito come Amministratore locale.
2. **FSLogix Apps:** FSLogix deve essere fisicamente installato sul server/macchina da cui si lancia lo script. Il tool si appoggia all'eseguibile ufficiale `frx.exe` (percorso letto dal registro `HKLM:\SOFTWARE\FSLogix\Apps`, fallback `%ProgramFiles%\FSLogix\Apps`).
3. **PowerShell:** Versione 5.1 o superiore. Nessun modulo aggiuntivo di terze parti richiesto.

## ⚙️ Come si utilizza

1. Aprire una console PowerShell come Amministratore ed eseguire lo script `Convert-LocalProfileToFSLogix.ps1`.
2. **Cartella Profili Locali:** Selezionare o digitare il percorso di origine contenente i profili locali (di default `C:\Users`).
3. **Destinazione FSLogix:** Selezionare o digitare la directory di rete o il disco locale in cui verranno salvati i dischi VHDX (campo vuoto di default, es. `D:\FSLogix` oppure `\\SRV01\FSLogix$`).
4. **Dimensione VHDX (MB):** Impostare il limite massimo del disco virtuale in megabyte (es. 30000 per ~30GB).
5. Cliccare su **Carica Profili**. La lista si popolerà con i nomi utente trovati nella cartella sorgente, ignorando in automatico cartelle di sistema come `Public`, `Default`, o `Administrator`.
6. Spuntare le caselle accanto agli utenti che si desidera migrare.
7. Cliccare su **AVVIA MIGRAZIONE**.
8. Monitorare l'avanzamento tramite la barra di stato progressiva e il box di log in tempo reale.

## 🔍 Come funziona "sotto il cofano"

Quando si avvia la migrazione per un utente, lo script esegue questa sequenza logica:

1. Ricava il dominio (o hostname) e il SID associato all'utente selezionato.
2. Esegue i controlli di sicurezza (pre-checks) assicurandosi che l'utente esista nel registro e non abbia la sessione aperta sul server.
3. Se la cartella di destinazione per l'utente non esiste, la crea nel formato standard FSLogix (`SID_NomeUtente`).
4. Configura i permessi NTFS usando `icacls`, garantendo l'accesso `(OI)(CI)F` in base alle best practice di Microsoft per i container FSLogix.
5. Invoca il comando ufficiale di copia:
`frx.exe copy-profile -filename "Percorso.vhdx" -sid <SID> -size-mbs <SIZE> -dynamic 1 -verbose`
6. Terminata l'esecuzione del processo figlio, esegue un test logico sul file generato.
7. Scrive l'esito dell'operazione, la dimensione creata o eventuali codici di errore (Exit Code) di `frx.exe` nel file di log globale.

## Changelog
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-local-profile-migrator`; script rinominato secondo convenzione
- **1.1.0** — aggiunto header di help; log in `%TEMP%\FSLogixMigration` invece di `C:\temp`; percorso FSLogix letto dal registro; destinazione senza default fisso, con controllo campo vuoto
