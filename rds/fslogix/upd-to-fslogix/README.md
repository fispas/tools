# Migrazione UPD a FSLogix - Documentazione

Questo script automatizza e mette in sicurezza la transizione dei profili utente dal vecchio formato UPD (User Profile Disk) alla struttura e ai requisiti nativi di FSLogix.

## 📌 Prerequisiti

Prima di eseguire lo script, assicurarsi che la macchina di esecuzione soddisfi i seguenti requisiti:

* **Privilegi Amministrativi**: Lo script eseguirà un test iniziale e si bloccherà se non viene eseguito come Amministratore (necessario per il mount dei dischi e le modifiche NTFS).
* **Modulo ActiveDirectory**: Necessario per risolvere i SID dei file VHDX nei rispettivi `SamAccountName`.
* **PowerShell 5.1+**: Richiesto per l'integrazione con `System.Windows.Forms` (per le finestre di dialogo GUI) e `Out-GridView`.

## 🚀 Come si usa

1. Avviare una console PowerShell come Amministratore.
2. Eseguire lo script: `.\Convert-UPDToFSLogix.ps1`
3. **Selezione Origine**: Si aprirà una finestra di dialogo. Selezionare la cartella che contiene i file UPD originali (i file con prefisso `UVHD-S...`).
4. **Selezione Destinazione**: Si aprirà una seconda finestra di dialogo. Selezionare la cartella di root dove verranno creati i profili FSLogix.
5. **Selezione Utenti**: Apparirà una griglia visiva (GridView) con l'elenco di tutti gli utenti trovati. È possibile usare i filtri in alto, selezionare uno, più o tutti gli utenti e cliccare su **OK** in basso a destra.
6. Lo script inizierà l'elaborazione mostrando a schermo l'avanzamento con i relativi log temporali.

## ⚙️ Come funziona sotto il cofano

Per ogni utente selezionato, lo script esegue un flusso di lavoro rigoroso, protetto da blocchi `try/catch` e validazioni continue:

1. **Test Pre-Esecuzione**: Verifica che il VHDX di origine esista ancora e controlla se esiste già un disco FSLogix in destinazione (chiedendo eventualmente di sovrascriverlo o saltarlo).
2. **Mount del Disco**: Monta il VHDX originale e ne individua la lettera di unità testando le partizioni attive (ignora le partizioni di sistema nascoste).
3. **Ristrutturazione Interna**:
* Crea una cartella `Profile` all'interno del disco montato.
* Sposta tutto il contenuto del profilo nella nuova cartella `Profile`, escludendo tramite un'espressione regolare le cartelle di sistema e il Cestino.


4. **Iniezione File di Registro**: Crea la cartella `AppData\Local\FSLogix` all'interno del disco e inietta il file `ProfileData.reg` necessario al motore FSLogix per il corretto aggancio del profilo su `C:\Users\<NomeUtente>`.
5. **Dismount Sicuro**: Smonta il disco, assicurandosi di rilasciare i lock sul file system.
6. **Copia e Rinomina**: Invece di spostare il file, lo **copia** nella directory di destinazione FSLogix (all'interno della cartella `<SID>_<SAM>`) e lo rinomina in `Profile_<SAM>.vhdx`. Il VHDX UPD originale rimane intatto e preservato.
7. **Applicazione Permessi NTFS**: Esegue il reset e l'impostazione dei permessi tramite `icacls`, garantendo l'accesso completo al proprietario del profilo (utente del dominio), a `SYSTEM` e al gruppo `Administrators`.

## 🛡️ Test di Validazione e Contatori

Lo script è progettato per non bloccarsi o corrompere i dati in caso di imprevisti, garantendo tolleranza agli errori per migrazioni massive:

* **Test di coerenza percorsi**: Impedisce di selezionare la stessa cartella per origine e destinazione.
* **Test sui file system**: Verifica la presenza dei file originari prima del mount, il successo del dismount, l'effettiva creazione dei file .reg e il successo delle operazioni di copia e rinomina.
* **Cleanup garantito**: Un blocco `finally` assicura che, anche in caso di crash fatale su un singolo profilo, venga effettuato un tentativo forzato di smontaggio del VHDX per non lasciare dischi appesi nel sistema.
* **Statistiche Finali**: Al termine dell'esecuzione, lo script stampa un report basato su contatori incrementali costantemente aggiornati:
* Totale utenti selezionati.
* Dischi elaborati con **Successo**.
* Dischi **Saltati** (scelta dell'utente o file esistenti).
* Migrazioni **Fallite** (con errori dettagliati su quale test specifico non è stato superato).

## Changelog
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-UPD-profile-migrator`; script rinominato secondo convenzione
