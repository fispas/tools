Questo strumento è uno script PowerShell basato su interfaccia grafica (GUI) progettato per semplificare e automatizzare la migrazione massiva dei profili utente Windows dal formato Roaming (es. condivisioni di rete con cartelle `.V6`) al formato VHDX nativo di FSLogix.

## 🚀 Caratteristiche Principali

* **Interfaccia Grafica Integrata:** Utilizza `System.Windows.Forms` per la selezione intuitiva delle directory di origine e destinazione.
* **Selezione Utenti Dinamica:** Interfaccia basata su `Out-GridView` per selezionare singolarmente o massivamente gli utenti da migrare.
* **Creazione VHDX Affidabile:** Sfrutta `DiskPart` per garantire la massima compatibilità nella creazione e formattazione (NTFS) dei dischi virtuali espandibili.
* **Copia ad Alte Prestazioni:** Utilizza `Robocopy` in modalità multi-thread (`/MT:8`) per il trasferimento dei dati, gestendo i file bloccati o in uso.
* **Iniezione Registro di Sistema:** Genera automaticamente il file `ProfileData.reg` all'interno del VHDX per indicare a FSLogix il corretto `ProfileImagePath`.
* **Sicurezza e Permessi:** Applica in automatico le ACL (Permessi NTFS) corrette sulla cartella contenitore del profilo tramite `icacls`, assegnando i diritti all'utente, a SYSTEM e agli Amministratori.
* **Safe-Fail & Test:** Contiene test di validazione continui (verifica percorsi, montaggio/smontaggio sicuro, controllo dimensioni file) per prevenire corruzioni dei dati.

## 📋 Prerequisiti

Prima di eseguire lo script, assicurarsi che il sistema soddisfi i seguenti requisiti:

1. **Privilegi di Amministratore:** Lo script deve essere eseguito da una console PowerShell avviata come Amministratore.
2. **Modulo Active Directory:** Necessario per risolvere i nomi utente (SAM) nei rispettivi SID (`Install-WindowsFeature RSAT-AD-PowerShell`).
3. **Permessi di Lettura/Scrittura:** L'account che esegue lo script deve avere privilegi di lettura sulla share Roaming sorgente e di controllo completo sulla share FSLogix di destinazione.

## 🛠️ Istruzioni per l'Uso

1. Scaricare o copiare lo script sul server o sulla workstation di management.
2. Aprire PowerShell come Amministratore.
3. Eseguire lo script:
```powershell
.\Convert-RoamingProfileToFSLogix.ps1

```


4. **Seleziona Sorgente:** Si aprirà una finestra di dialogo. Selezionare la directory radice che contiene i profili Roaming (es. `\\Server\Profili$`).
5. **Seleziona Destinazione:** Selezionare la directory radice dove verranno creati i contenitori FSLogix (es. `\\Server\FSLogix$`).
6. **Dimensione VHDX:** Verrà richiesto di inserire la dimensione massima in MB per i dischi virtuali (il valore predefinito è `30000` MB, ovvero ~30GB).
7. **Selezione Utenti:** Si aprirà una griglia (Grid View). Selezionare le righe corrispondenti agli utenti che si desidera migrare e cliccare su **OK** (in basso a destra).
* *Nota: Se il sistema rileva un disco già esistente nella destinazione, verrà richiesto se si desidera sovrascriverlo o saltare l'utente.*



## 📊 Flusso di Lavoro per Singolo Utente

Per ogni utente selezionato, lo script esegue le seguenti operazioni:

1. Verifica l'accessibilità dei percorsi.
2. Crea la cartella contenitore nel formato `SID_samaccountname`.
3. Crea un file `.vhdx` espandibile e lo formatta tramite `DiskPart`.
4. Monta il VHDX sul sistema.
5. Usa `Robocopy` per clonare il contenuto della cartella Roaming all'interno della cartella `Profile` del VHDX.
6. Crea le chiavi di registro necessarie per FSLogix (`ProfileData.reg`).
7. Smonta il VHDX.
8. Imposta i permessi NTFS sulla cartella contenitore dell'utente.

Al termine, lo script stamperà un report statistico con il numero di migrazioni completate con successo, saltate o fallite.

## ⚠️ Note di Sicurezza e Troubleshooting

* **Utenti Disconnessi:** È caldamente consigliato eseguire la migrazione quando gli utenti target *non* sono connessi, per evitare che `Robocopy` trovi file bloccati (es. `NTUSER.DAT` in uso).
* **Gestione Errori:** In caso di errore critico durante la copia, il blocco `finally` assicura che il disco VHDX venga comunque smontato per non lasciare partizioni "fantasma" appese al server di management.

---

*Autore: Area Tecnica - Ricca IT*

## Changelog
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-RoamingProfile-migrator`; script rinominato secondo convenzione; rimossi i delimitatori markdown (```powershell) a inizio/fine file che impedivano l'esecuzione
