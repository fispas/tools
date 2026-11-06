# local-to-fslogix — Profili locali → FSLogix

Migra i profili locali di Windows in contenitori FSLogix con `frx.exe copy-profile`. Va eseguito sulla macchina che ospita i profili (session host o PC), con FSLogix installato.

## Requisiti
- PowerShell 5.1, amministratore (la GUI chiede l'elevazione da sola)
- FSLogix Apps installato (`frx.exe`, percorso letto dal registro)

## Uso

```powershell
.\Convert-LocalProfileToFSLogix.ps1
```

1. **Configurazione**: destinazione, formato e dimensione del disco, opzioni. *Salva* scrive in `%ProgramData%\FispaTools\LocalToFSLogix\config.json`; *Salva come* / *Carica* per più ambienti.
2. **Profili** → *Analizza*: i profili vengono letti dal registro (`ProfileList`), non dai nomi delle cartelle, con utente, nome, dominio, cartella, ultimo uso e stato. Non selezionabili: account non risolto, account locale (salvo opzione), escluso, profilo temporaneo/corrotto (`.bak`), cartella assente, profilo caricato, `NTUSER.DAT` in uso.
3. Spunta i profili → **Avvia migrazione** → conferma con riepilogo.
4. **Log** in tempo reale, compreso l'output di `frx.exe`; *Annulla* completa il profilo in corso e si ferma.

La **simulazione è attiva di default**: mostra il comando `frx.exe` che verrebbe eseguito per ogni utente.

### Senza GUI

```powershell
.\Convert-LocalProfileToFSLogix.ps1 -NoGui
.\Convert-LocalProfileToFSLogix.ps1 -NoGui -User mario.rossi,anna.bianchi -Simulate
```
Codici di uscita: `0` ok, `1` configurazione non valida, `2` almeno un profilo fallito.

## Parametri della configurazione

| Campo | Default | Note |
|---|---|---|
| Cartella FSLogix | — | Locale o UNC |
| Percorso frx.exe | da `HKLM\SOFTWARE\FSLogix\Apps`, altrimenti `%ProgramFiles%\FSLogix\Apps` | |
| Formato | dal registro FSLogix, altrimenti VHDX | VHDX / VHD |
| Dimensione massima (MB) | dal registro FSLogix, altrimenti 30000 | `-size-mbs` |
| Tipo disco | dal registro FSLogix, altrimenti Dinamico | `-dynamic 1/0` |
| Nome cartella utente / Nome disco | come FSLogix | `%sid%_%username%`, `Profile_%username%` |
| Includi account locali | no | |
| Utenti esclusi | — | Separati da `;` |
| Se il disco esiste già | Salta | Salta / Rinomina / Sovrascrivi |
| Permessi sulla cartella utente | sì | Per SID: utente, SYSTEM, Administrators |
| Elimina il disco se fallisce | sì | |
| Abilita percorsi lunghi | no | Imposta `LongPathsEnabled=1`: la 1.x lo faceva sempre, ora solo se richiesto |
| Cartella log e report | `%ProgramData%\FispaTools\LocalToFSLogix\Log` | |
| Simulazione | sì | |

## Output
- Log: `<cartella log>\LocalToFSLogix_<data>.log`
- Report: `<cartella log>\LocalToFSLogix_Report_<data>.csv`

## Changelog
- **2.0.0** — riscritto: GUI a schede con configurazione salvabile, simulazione di default, annullamento pulito, modalità `-NoGui`, report CSV. Profili letti da `ProfileList` invece che dai nomi delle cartelle, con controllo di profilo caricato e `NTUSER.DAT` in uso. Lettura asincrona dell'output di `frx.exe` (la 1.x poteva bloccarsi su output lunghi). Formato, tipo disco e nomi FSLogix configurabili. Permessi per SID con controllo dei codici di uscita, applicati anche a cartelle esistenti. Gestione del disco esistente. Pulizia dei dischi incompleti. `LongPathsEnabled` solo su richiesta.
- **1.1.0** — header di help, log in `%TEMP%`, percorso FSLogix dal registro, destinazione senza default fisso.
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-local-profile-migrator`.
