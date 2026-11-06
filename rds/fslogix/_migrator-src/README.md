# _migrator-src — sorgenti dei migratori FSLogix

I tre migratori (`upd-to-fslogix`, `roaming-to-fslogix`, `local-to-fslogix`) sono script **single-file** da copiare e lanciare dove servono, ma condividono la stessa base: avvio/elevazione, motore (log, montaggio dischi, permessi, ProfileData.reg, esecuzione) e GUI generata dallo schema dei campi.

Per non correggere tre volte lo stesso codice, i file finali si generano da qui:

| File | Contenuto |
|---|---|
| `core_pre.ps1` | Elevazione, STA, stato condiviso |
| `core_engine.ps1` | Motore comune |
| `core_main.ps1` | Configurazione JSON, modalità `-NoGui`, GUI |
| `<tool>_head.ps1` | Help, parametri, metadati del tool |
| `<tool>_engine.ps1` | Default, validazione, analisi, migrazione del singolo utente |
| `<tool>_gui.ps1` | Campi della configurazione e colonne della griglia |

```bash
python rds/fslogix/_migrator-src/build.py
```

Non modificare a mano i `Convert-*.ps1`: modificare i sorgenti e rigenerare.
