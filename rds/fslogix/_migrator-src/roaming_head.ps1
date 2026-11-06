<#
.SYNOPSIS
    Migra i profili Roaming (cartelle utente.V6 e simili) in contenitori FSLogix, con GUI configurabile.

.DESCRIPTION
    Per ogni cartella profilo selezionata:
      - ricava l'utente dal nome cartella e ne risolve il SID (senza modulo ActiveDirectory)
      - crea un nuovo disco VHD/VHDX (dinamico o fisso) con diskpart e lo formatta NTFS
      - monta il disco su una cartella temporanea e copia il profilo in \Profile con robocopy
      - imposta owner e permessi dell'utente dentro il disco, crea ProfileData.reg
      - smonta, imposta owner e permessi sulla cartella utente
    La cartella Roaming originale non viene modificata.
    Senza parametri apre la GUI: configurazione salvabile, analisi, selezione, simulazione,
    avanzamento, annullamento pulito, log e report CSV. Con -NoGui usa la configurazione salvata.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\RoamingToFSLogix\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia (console, operazioni pianificate).

.PARAMETER User
    Con -NoGui: elabora solo questi SamAccountName.

.PARAMETER Simulate
    Con -NoGui: forza la simulazione, nessuna modifica.

.EXAMPLE
    .\Convert-RoamingProfileToFSLogix.ps1

.EXAMPLE
    .\Convert-RoamingProfileToFSLogix.ps1 -NoGui -ConfigPath D:\Migrazione\roaming.json -Simulate

.NOTES
    Versione: 2.0.0
    Repo:     fispas/tools (rds/fslogix/roaming-to-fslogix)
    Richiede: amministratore, Windows Server 2012 R2+ / Windows 10+, PowerShell 5.1, macchina nel dominio
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name        = 'RoamingToFSLogix'
    Title       = 'Roaming -> FSLogix'
    Version     = '2.0.0'
    ConfirmKeys = @('SourcePath', 'DestinationPath', 'VolumeType', 'SizeMB', 'DiskType', 'FolderPattern', 'ExistingDisk')
}
