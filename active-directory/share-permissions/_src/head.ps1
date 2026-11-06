<#
.SYNOPSIS
    Migra i permessi delle share da utenti a gruppi AD e applica l'hardening delle condivisioni, con GUI configurabile.

.DESCRIPTION
    Analisi (sola lettura) di ogni share di un file server, locale o remoto:
      - utenti con permessi espliciti (lettura o modifica), gruppi, SID orfani
      - accessi troppo ampi (Everyone, Users, Authenticated Users, Domain Users) su NTFS e share
      - ereditarieta', Access-Based Enumeration, cifratura SMB
    Migrazione e hardening, per ogni share selezionata (ogni passo attivabile dalla configurazione):
      1. backup di ACL NTFS (icacls /save) e permessi della share, con il comando di ripristino nel log
      2. gruppi AD per share (<prefisso><Share>_RW e _RO, oppure un gruppo unico), creati via LDAP
      3. utenti trovati nelle ACL aggiunti al gruppo del livello corrispondente
      4. ACE NTFS del gruppo sulla cartella della share (ereditata da tutto l'albero)
      5. rimozione delle ACE esplicite degli utenti migrati, solo se sono membri del gruppo
      6. permessi share standard, Access-Based Enumeration, cifratura SMB
    Non serve il modulo ActiveDirectory. Simulazione attiva di default.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\SharePermissions\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia con la configurazione salvata.

.PARAMETER User
    Con -NoGui: elabora solo queste share (nome).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione.

.EXAMPLE
    .\Set-SharePermissions.ps1

.EXAMPLE
    .\Set-SharePermissions.ps1 -NoGui -ConfigPath D:\Share\fs01.json -User Contabilita,Tecnico -Simulate

.NOTES
    Versione: 1.0.0
    Repo:     fispas/tools (active-directory/share-permissions)
    Richiede: amministratore sul file server, diritti di creazione gruppi nell'OU indicata, PowerShell 5.1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name         = 'SharePermissions'
    Title        = 'Share: migrazione a gruppi e hardening'
    Version      = '1.0.0'
    ItemNoun     = 'share'
    ItemTab      = 'Share'
    StartLabel   = 'Applica alle share'
    RunningLabel = 'Elaborazione delle share in corso'
    CloseWarning = ''
    ConfirmKeys  = @('FileServer', 'GroupOU', 'GroupMode', 'GroupScope', 'CreateGroups', 'PopulateGroups', 'GrantGroupNtfs', 'RemoveUserAces', 'SharePermissions', 'EnableABE', 'EncryptData', 'BackupDir')
}
