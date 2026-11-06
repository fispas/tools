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
Le web app complete restano nei loro repo dedicati.

## Ogni tool
Copiare `_template/`. Ogni cartella tool contiene:
- lo script (PowerShell: `Verbo-Nome.ps1` con verbi approvati; cartelle in kebab-case)
- `README.md`: scopo, requisiti, parametri, esempi, output, changelog
- opzionale `config.example.json` (il `config.json` reale è in `.gitignore`)

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
