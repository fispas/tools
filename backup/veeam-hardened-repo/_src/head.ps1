<#
.SYNOPSIS
    Configura via SSH un server Ubuntu come hardened repository Veeam (iSCSI, multipath, LUN XFS, utente, blindatura), con GUI configurabile.

.DESCRIPTION
    Pannello Windows che guida la configurazione della macchina "vrepo" appena installata.
    Il lavoro sul server lo fa vrepo-setup.sh (incorporato in questo file), eseguito via OpenSSH:
      1. Accesso: chiave SSH dedicata, installazione di vrepo-setup.sh e regola sudo limitata allo script
      2. Pacchetti (open-iscsi, xfsprogs, parted, multipath-tools) e ora di sistema (NTP)
      3. Initiator iSCSI (nome, node.startup automatico)
      4. Target: discovery sui portali indicati, login con avvio automatico, CHAP, record non usati eliminati
      5. Multipath: profilo QNAP o generico, alias multipath con il nome della LUN
      6. LUN: GPT, XFS reflink/crc 4K, fstab per UUID (_netdev,nofail), mount protetto con chattr +i
      7. Utente Veeam: creazione, password generata, sudo temporaneo, permessi 700 sui repository
      8. Blindatura dopo l'aggiunta in VBR: via sudo, password bloccata, chiave e regola del tool rimosse, SSH spento
    Analizza legge lo stato del server e propone i passi e le LUN trovate. Simulazione attiva di default.
    Lo stesso script si usa anche da solo sul server: sudo ./vrepo-setup.sh (wizard a menu).

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\VeeamHardenedRepo\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia con la configurazione salvata. Richiede -User con i passi da eseguire.

.PARAMETER User
    Con -NoGui: passi da eseguire, con il nome mostrato nella colonna Passo
    (Accesso, Pacchetti, NTP, Initiator, Target, Multipath, LUN:<nome>, Utente, Blindatura, Disconnessione).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione.

.EXAMPLE
    .\Initialize-VeeamHardenedRepo.ps1

.EXAMPLE
    .\Initialize-VeeamHardenedRepo.ps1 -NoGui -ConfigPath D:\Profili\vrepo01.json -User Pacchetti,NTP,Initiator,Target,Multipath -Simulate

.NOTES
    Versione: 1.0.0
    Repo:     fispas/tools (backup/veeam-hardened-repo)
    Richiede: client OpenSSH di Windows (ssh.exe, ssh-keygen.exe), PowerShell 5.1; sul server Ubuntu 22.04/24.04 con un utente amministratore (sudo)
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name          = 'VeeamHardenedRepo'
    Title         = 'Veeam Hardened Repository: configurazione vrepo'
    Version       = '1.0.0'
    ItemNoun      = 'passi'
    ItemTab       = 'Passi'
    StartLabel    = 'Esegui i passi'
    RunningLabel  = 'Configurazione del server in corso'
    CloseWarning  = "`nUn comando gia' avviato sul server prosegue fino alla fine."
    RequiresAdmin = $false
    ConfirmKeys   = @('Host', 'SshUser', 'IscsiPortals', 'Multipath', 'MountBase', 'VeeamUser', 'ForceFormat', 'SshDisable')
}
