# Nome tool

Una riga su cosa fa.

## Requisiti
- Windows Server 2016+ / Windows 10+
- PowerShell 5.1
- Moduli: _es. ActiveDirectory (RSAT)_
- Permessi: _es. lettura dominio / admin locale_

## Parametri
| Parametro | Default | Descrizione |
|---|---|---|
| `-OutputPath` | `$env:TEMP\<tool>` | Cartella di output |

## Esempi
```powershell
.\Verbo-Nome.ps1
.\Verbo-Nome.ps1 -OutputPath C:\Temp\report
```

## Output
Cosa produce e dove.

## Changelog
- **1.0.0** — prima versione
