# _migrator-src — sorgenti dei migratori FSLogix

I tre migratori (`upd-to-fslogix`, `roaming-to-fslogix`, `local-to-fslogix`) sono script **single-file**, generati da:

| File | Contenuto |
|---|---|
| `../../../_lib/toolkit/*` | Libreria comune del repo: avvio/elevazione, motore base, configurazione JSON, `-NoGui`, GUI |
| `fslogix_engine.ps1` | Parte comune ai migratori: naming FSLogix, montaggio dischi, permessi, ProfileData.reg |
| `<tool>_head.ps1` | Help, parametri, metadati ed etichette del tool |
| `<tool>_engine.ps1` | Default, validazione, analisi, migrazione del singolo utente |
| `<tool>_gui.ps1` | Campi della configurazione e colonne della griglia |

```bash
python _lib/build.py
```

Non modificare a mano i `Convert-*.ps1`: modificare i sorgenti e rigenerare.
