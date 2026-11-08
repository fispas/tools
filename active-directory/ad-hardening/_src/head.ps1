<#
.SYNOPSIS
    Active Directory: fotografia di sicurezza (fase 1) e hardening guidato (fase 2), con GUI configurabile.

.DESCRIPTION
    Modalita' Fotografia (sola lettura): controlli in stile PingCastle / Purple Knight sul dominio corrente,
    via LDAP/ADSI senza moduli aggiuntivi. Per ogni controllo: esito, punti di rischio, evidenze, remediation.
    Output: report HTML navigabile, JSON completo, CSV dei risultati e delle evidenze.

    Modalita' Hardening: azioni correttive selezionabili una per una. Per ciascuna lo strumento verifica lo
    stato attuale (Analizza), mostra il piano, salva lo stato precedente (backup JSON), applica e verifica di
    nuovo. Simulazione attiva di default. Aree: dominio (cestino AD, MachineAccountQuota, pre-Windows 2000,
    KDS root key, policy password), account privilegiati (Schema Admins, sensibili non delegabili, Protected
    Users, PSO admin, adminCount orfani, rotazione krbtgt in due passaggi), account (preautenticazione, DES,
    cifratura reversibile, password non obbligatoria, Guest, inattivi), Windows LAPS (schema, permessi, GPO),
    GPO di hardening per DC e membri (firma LDAP/SMB, channel binding, NTLMv2, SMBv1, Spooler, RunAsPPL,
    WDigest, registri), criteri di controllo avanzati sui DC, tier model (OU, gruppi, GPO di deny logon).
    Modalita' Ripristino: annulla le azioni di un'esecuzione di hardening partendo dai suoi backup JSON.
    La fotografia si confronta in automatico con la precedente dello stesso dominio (rischi nuovi e risolti).
    L'hardening richiede gli strumenti RSAT (ActiveDirectory, GroupPolicy) e un account Domain Admins
    (alcune azioni Enterprise o Schema Admins).

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\ADAssessment\config.json

.PARAMETER NoGui
    Esegue senza interfaccia (operazione pianificata): fotografia completa, oppure le azioni di hardening
    da applicare secondo la configurazione (Mode, DryRun).

.PARAMETER User
    Con -NoGui: esegue solo questi controlli o azioni (ID, es. K-ASREP-01 oppure HD-MAQ).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione (nessuna modifica) anche se la configurazione dice il contrario.

.EXAMPLE
    .\Invoke-ADAssessment.ps1

.EXAMPLE
    .\Invoke-ADAssessment.ps1 -NoGui -ConfigPath D:\Assessment\contoso.json

.EXAMPLE
    .\Invoke-ADAssessment.ps1 -NoGui -ConfigPath D:\Assessment\contoso-hardening.json -User HD-MAQ,HD-PRE2K -Simulate

.NOTES
    Versione: 0.3.0 (fotografia, hardening, ripristino, confronto)
    Repo:     fispas/tools (active-directory/ad-hardening)
    Richiede: macchina nel dominio, PowerShell 5.1; per l'hardening RSAT AD + GPMC
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
    Title        = 'Active Directory: fotografia e hardening'
    Version      = '0.3.0'
    ReadOnly     = $true
    RequiresAdmin = $false
    ItemNoun     = 'controlli o azioni'
    ItemTab      = 'Controlli e azioni'
    StartLabel   = 'Esegui'
    RunningLabel = 'Esecuzione in corso'
    CloseWarning = "`nIn hardening l'azione in corso viene completata prima di chiudere."
    ConfirmKeys  = @('Mode', 'DryRun', 'DomainController', 'GpoLinkMode', 'OutputDir')
}
