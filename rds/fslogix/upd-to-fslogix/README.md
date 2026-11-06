# upd-to-fslogix — User Profile Disk → FSLogix

Migra i dischi UPD di Remote Desktop (`UVHD-<SID>.vhdx` / `.vhd`) in contenitori FSLogix. Lavora su una **copia**: i dischi UPD originali non vengono mai modificati.

## Requisiti
- Windows Server 2012 R2+ / Windows 10+, PowerShell 5.1
- Amministratore (la GUI chiede l'elevazione da sola)
- Cmdlet `Mount-DiskImage` (modulo Storage, presente di serie), `robocopy`
- Macchina nel dominio. **Non serve il modulo ActiveDirectory**: gli utenti si risolvono dal SID

## Uso

```powershell
.\Convert-UPDToFSLogix.ps1
```

1. **Configurazione**: percorsi, formato FSLogix, comportamento. I campi hanno una descrizione sotto. *Salva* scrive in `%ProgramData%\FispaTools\UPDToFSLogix\config.json`; *Salva come* / *Carica* gestiscono più configurazioni (una per ambiente).
2. **Profili** → *Analizza*: elenca i dischi con utente, nome, dimensione, data e stato. Non selezionabili (in grigio): SID non risolto, escluso, disco in uso. In arancione: disco FSLogix già presente.
3. Spunta i profili (filtro e *Seleziona tutti* disponibili) → **Avvia migrazione**. Viene chiesta una conferma con il riepilogo.
4. **Log**: avanzamento in tempo reale. *Annulla* completa il profilo in corso e si ferma.

La **simulazione è attiva di default**: verifica tutto e scrive nel log le operazioni senza toccare nulla. Per la migrazione reale va disattivata.

### Senza GUI

```powershell
.\Convert-UPDToFSLogix.ps1 -NoGui                                   # config salvata, tutti i profili migrabili
.\Convert-UPDToFSLogix.ps1 -NoGui -ConfigPath D:\Mig\upd.json -User mario.rossi,anna.bianchi
.\Convert-UPDToFSLogix.ps1 -NoGui -Simulate                         # forza la simulazione
```
Codici di uscita: `0` ok, `1` configurazione non valida, `2` almeno un profilo fallito.

## Parametri della configurazione

| Campo | Default | Note |
|---|---|---|
| Cartella UPD (origine) | — | Cartella con i file `UVHD-S-*.vhdx/.vhd` |
| Cartella FSLogix (destinazione) | — | Locale o UNC |
| Nome cartella utente | dal registro FSLogix, altrimenti `%sid%_%username%` | Come `SIDDirNamePattern`; `%username%_%sid%` = FlipFlop |
| Nome disco | dal registro FSLogix, altrimenti `Profile_%username%` | Come `VHDNamePattern`; l'estensione resta quella del disco UPD |
| Cartella profili sul session host | `C:\Users` | Per `ProfileImagePath` in `ProfileData.reg` |
| Se il disco FSLogix esiste già | Salta | Salta / Rinomina in `.bak-<data>` / Sovrascrivi |
| Owner e permessi sulla cartella | sì | Per SID: utente, SYSTEM, Administrators |
| Elimina il disco se fallisce | sì | Niente dischi incompleti in produzione |
| Utenti esclusi | — | SamAccountName separati da `;` |
| Cartella log e report | `%ProgramData%\FispaTools\UPDToFSLogix\Log` | Log, report CSV, log robocopy |
| Simulazione | sì | |

## Cosa fa per ogni utente
1. Verifica che il disco UPD esista e non sia in uso, gestisce un eventuale disco FSLogix già presente, controlla lo spazio libero.
2. Copia il disco nella cartella dell'utente con `robocopy /J` e lo rinomina.
3. Monta la copia su una cartella temporanea (nessuna lettera di unità), sposta il contenuto in `\Profile` escludendo `Uvhd-Binding`, cestino e `System Volume Information`. Ogni errore di spostamento blocca la migrazione dell'utente.
4. Crea `\Profile\AppData\Local\FSLogix\ProfileData.reg` (UTF-16, come i file `.reg` di Windows).
5. Smonta (fino a 3 tentativi), imposta owner e permessi, verifica il disco finale.
6. Se qualcosa fallisce: smonta comunque e, se configurato, elimina la copia incompleta.

## Output
- Log: `<cartella log>\UPDToFSLogix_<data>.log`
- Report: `<cartella log>\UPDToFSLogix_Report_<data>.csv` (separatore `;`, si apre direttamente in Excel)

## Changelog
- **2.0.0** — riscritto: GUI a schede con configurazione salvabile e più profili di configurazione, analisi con stato per utente, simulazione di default, esecuzione in background con annullamento pulito, modalità `-NoGui`. Si lavora sulla copia (la 1.x spostava il contenuto dentro il disco UPD originale prima di copiarlo). Nessuna domanda da console: gestione del disco esistente configurabile. Niente modulo ActiveDirectory. Montaggio senza lettera di unità. Permessi per SID con controllo dei codici di uscita. Errori di spostamento non più ignorati. Pulizia dei dischi incompleti. Supporto `.vhd`. Report CSV.
- **1.1.0** — rimossi riferimenti aziendali dall'header, esempi di percorso neutri.
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-UPD-profile-migrator`.
