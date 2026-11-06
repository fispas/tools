<#
.SYNOPSIS
    Fotografia della sicurezza e della salute di Active Directory (sola lettura), con GUI configurabile.

.DESCRIPTION
    Fase 1 del progetto ad-hardening: controlli in stile PingCastle / Purple Knight sul dominio corrente,
    eseguiti via LDAP/ADSI senza moduli aggiuntivi. Per ogni controllo: esito (OK, Info, Attenzione,
    Critico, Non verificato), punti di rischio, evidenze, remediation consigliata.
    Categorie: salute del dominio (DC, livelli funzionali, SYSVOL DFSR/FRS, cestino AD, FSMO),
    account privilegiati, Kerberos, password e account, configurazione del dominio (LAPS, gMSA,
    MachineAccountQuota, accesso anonimo, GPP con password, trust).
    Output: report HTML navigabile, JSON completo, CSV dei risultati e delle evidenze.
    Non modifica nulla: puo' essere eseguito con un utente di dominio standard (alcuni controlli
    richiedono privilegi e in quel caso risultano "Non verificato").

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\ADAssessment\config.json

.PARAMETER NoGui
    Esegue tutti i controlli senza interfaccia (per un'operazione pianificata).

.PARAMETER User
    Con -NoGui: esegue solo questi controlli (ID, es. K-ASREP-01).

.PARAMETER Simulate
    Ignorato: lo strumento e' sempre in sola lettura.

.EXAMPLE
    .\Invoke-ADAssessment.ps1

.EXAMPLE
    .\Invoke-ADAssessment.ps1 -NoGui -ConfigPath D:\Assessment\contoso.json

.NOTES
    Versione: 0.1.0 (fase 1 - fotografia)
    Repo:     fispas/tools (active-directory/ad-hardening)
    Richiede: macchina nel dominio, PowerShell 5.1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name         = 'ADAssessment'
    Title        = 'Active Directory: fotografia di sicurezza'
    Version      = '0.1.0'
    ReadOnly     = $true
    RequiresAdmin = $false
    ItemNoun     = 'controlli'
    ItemTab      = 'Controlli'
    StartLabel   = 'Esegui i controlli'
    RunningLabel = 'Controlli in corso'
    CloseWarning = ''
    ConfirmKeys  = @('DomainController', 'InactiveDays', 'OutputDir')
}
