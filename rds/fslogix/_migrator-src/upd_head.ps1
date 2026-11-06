<#
.SYNOPSIS
    Migra i dischi User Profile Disk (UPD) di RDS in contenitori FSLogix, con GUI configurabile.

.DESCRIPTION
    Per ogni disco UVHD-<SID>.vhdx/.vhd selezionato:
      - risolve l'utente dal SID (senza modulo ActiveDirectory)
      - copia il disco nella cartella FSLogix dell'utente (l'originale UPD non viene toccato)
      - monta la COPIA su una cartella temporanea e ne sposta il contenuto in \Profile
      - crea AppData\Local\FSLogix\ProfileData.reg
      - smonta, imposta owner e permessi (utente, SYSTEM, Administrators) sulla cartella
    Senza parametri apre la GUI: configurazione salvabile, analisi dei dischi, selezione,
    simulazione, avanzamento, annullamento pulito, log e report CSV.
    Con -NoGui usa la configurazione salvata (o -ConfigPath) ed elabora tutti i profili
    migrabili, o solo quelli indicati con -User.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\UPDToFSLogix\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia (console, operazioni pianificate).

.PARAMETER User
    Con -NoGui: elabora solo questi SamAccountName.

.PARAMETER Simulate
    Con -NoGui: forza la simulazione, nessuna modifica.

.EXAMPLE
    .\Convert-UPDToFSLogix.ps1

.EXAMPLE
    .\Convert-UPDToFSLogix.ps1 -NoGui -ConfigPath D:\Migrazione\upd.json -User mario.rossi -Simulate

.NOTES
    Versione: 2.0.0
    Repo:     fispas/tools (rds/fslogix/upd-to-fslogix)
    Richiede: amministratore, Windows Server 2012 R2+ / Windows 10+, PowerShell 5.1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name        = 'UPDToFSLogix'
    Title       = 'UPD -> FSLogix'
    Version     = '2.0.0'
    ItemNoun     = 'profili'
    ItemTab      = 'Profili'
    StartLabel   = 'Avvia migrazione'
    RunningLabel = 'Migrazione in corso'
    CloseWarning = "`n(Non chiudere il processo a forza: un disco potrebbe restare montato.)"
    ConfirmKeys = @('SourcePath', 'DestinationPath', 'FolderPattern', 'DiskNamePattern', 'ExistingDisk')
}
