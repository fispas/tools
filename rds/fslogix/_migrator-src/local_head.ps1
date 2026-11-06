<#
.SYNOPSIS
    Migra i profili locali di Windows in contenitori FSLogix con frx.exe, con GUI configurabile.

.DESCRIPTION
    Elenca i profili dal registro (ProfileList), non dai nomi delle cartelle, e per ogni
    profilo selezionato:
      - verifica che non sia caricato, temporaneo/corrotto (.bak) o con NTUSER.DAT in uso
      - crea la cartella FSLogix dell'utente
      - esegue frx.exe copy-profile (formato, dimensione e tipo disco configurabili)
      - imposta owner e permessi (utente, SYSTEM, Administrators) sulla cartella
    Va eseguito sulla macchina che ospita i profili locali, con FSLogix installato.
    Senza parametri apre la GUI: configurazione salvabile, analisi, selezione, simulazione,
    avanzamento, annullamento pulito, log e report CSV. Con -NoGui usa la configurazione salvata.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\LocalToFSLogix\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia (console, operazioni pianificate).

.PARAMETER User
    Con -NoGui: elabora solo questi SamAccountName.

.PARAMETER Simulate
    Con -NoGui: forza la simulazione, nessuna modifica.

.EXAMPLE
    .\Convert-LocalProfileToFSLogix.ps1

.EXAMPLE
    .\Convert-LocalProfileToFSLogix.ps1 -NoGui -User mario.rossi,anna.bianchi

.NOTES
    Versione: 2.0.0
    Repo:     fispas/tools (rds/fslogix/local-to-fslogix)
    Richiede: amministratore, FSLogix Apps installato, PowerShell 5.1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name        = 'LocalToFSLogix'
    Title       = 'Profili locali -> FSLogix'
    Version     = '2.0.0'
    ConfirmKeys = @('DestinationPath', 'VolumeType', 'SizeMB', 'DiskType', 'FolderPattern', 'ExistingDisk')
}
