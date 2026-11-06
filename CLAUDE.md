# Regole del repo `tools`

Raccolta di tool e script operativi di Fispa (sistemista). Queste regole valgono per ogni modifica.

## Principio fondamentale
Ogni tool deve essere **generico ed eseguibile ovunque**, mai scritto per un singolo cliente.
- Nessun dominio, server, IP, utente, percorso o nome di cliente scritto nel codice.
- Tutto ciò che dipende dall'ambiente è un **parametro** o viene **auto-rilevato** (es. `Get-ADDomain`, `$env:USERDNSDOMAIN`, `[System.Net.Dns]::GetHostName()`).
- Valori di default sensati, che funzionino senza configurazione quando possibile.
- Esempi nei README con valori fittizi (`contoso.local`, `SRV01`, `utente.test`).
- Se un tool nasce da un caso reale, va generalizzato prima del commit.

## Struttura
Cartelle per **area / progetto**, mai per cliente:
```
<area>/<tool>/            es. active-directory/audit-gmsa/
<area>/<gruppo>/<tool>/   es. active-directory/gpo/winrm-enable/
```
Aree attuali: `active-directory/`, `rds/`, `windows/`, `utility/`. Se un tool non rientra, si crea una nuova area.
Le web app complete restano nei loro repo dedicati. **Eccezione**: `active-directory/sspr` (portale SSPR, C#/.NET) vive in questo repo per scelta di Fispa; build e test con `.github/workflows/sspr.yml`.

## Ogni tool
Copiare `_template/`. Ogni cartella tool contiene:
- lo script (PowerShell: `Verbo-Nome.ps1` con verbi approvati; cartelle in kebab-case)
- `README.md`: scopo, requisiti, parametri, esempi, output, changelog
- opzionale `config.example.json` (il `config.json` reale è in `.gitignore`)

Standard dei tool (modello: `rds/fslogix/compact-vhdx` e i migratori FSLogix):
- **configurabili da GUI**: ogni impostazione è un campo con descrizione, salvabile in JSON (`%ProgramData%\FispaTools\<Tool>\config.json`), con Salva come / Carica per più ambienti; i default mancanti si fondono con quelli del tool
- **anche senza GUI**: `-NoGui -ConfigPath <json>` per console e operazioni pianificate, codici di uscita significativi
- **robusti**: lavoro lungo in background (runspace) con GUI reattiva, annullamento pulito, simulazione attiva di default, conferma prima di agire, codici di uscita di robocopy/icacls/diskpart/exe sempre controllati, cleanup in `finally`, log + report CSV
- **nessuna dipendenza evitabile**: es. SID ↔ utente con .NET invece del modulo ActiveDirectory, permessi per SID (indipendenti dalla lingua), dischi montati su cartella invece che su lettera
- file `.ps1` in **UTF-8 con BOM** (PowerShell 5.1 legge male i file senza BOM)
- codice condiviso: libreria `_lib/toolkit` (avvio/elevazione, motore con log/esecuzione/report, configurazione JSON, `-NoGui`, GUI a schede generata dallo schema dei campi). Un nuovo tool con GUI fornisce solo `_src/head.ps1` (help, parametri, `$Tool`), `_src/engine.ps1` (`Get-ToolDefaultConfig`, `Get-ToolPrereqIssues`, `Test-ToolConfig`, `Get-ToolItems`, `Invoke-ToolItem`) e `_src/gui.ps1` (`$ToolSchema`, `$ToolColumns`), si registra in `_lib/build.py` e si genera con `python _lib/build.py`. I file generati restano single-file e non si modificano a mano
- sorgenti **solo ASCII** (accenti come `e'`): `build.py` blocca i caratteri non ASCII

Script PowerShell:
- header con `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES` (versione)
- `[CmdletBinding()]`, `SupportsShouldProcess` per tutto ciò che modifica qualcosa
- di default sola lettura; le azioni distruttive richiedono uno switch esplicito
- output in una cartella `-OutputPath` (default sotto `$env:TEMP` o accanto allo script)
- compatibilità: PowerShell 5.1 salvo diversa indicazione nel README

## Dopo ogni modifica
1. Aggiornare il `README.md` del tool (changelog + versione nell'header).
2. Aggiornare l'indice nel `README.md` in root.
3. Commit descrittivo: `<area>/<tool>: <cosa>` e push su `main`.
