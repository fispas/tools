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

#region AVVIO (libreria _lib/toolkit)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
# $Tool.RequiresAdmin = $false per i tool in sola lettura che funzionano anche da utente standard
$needAdmin = -not ($Tool.ContainsKey('RequiresAdmin') -and -not $Tool.RequiresAdmin)
if (-not $NoGui -and ((-not $isAdmin -and $needAdmin) -or -not $isSta)) {
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($ConfigPath) { $argList += @('-ConfigPath', "`"$ConfigPath`"") }
    try {
        if ($isAdmin -or -not $needAdmin) { Start-Process -FilePath powershell.exe -ArgumentList $argList }
        else { Start-Process -FilePath powershell.exe -ArgumentList $argList -Verb RunAs }
    } catch {
        Write-Error "Avvio come amministratore annullato o non riuscito: $($_.Exception.Message)"
    }
    return
}
if (-not $isAdmin -and $needAdmin) {
    Write-Error 'Servono i privilegi di amministratore: aprire PowerShell come amministratore.'
    exit 1
}

$State = [hashtable]::Synchronized(@{
    Queue      = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    Cancel     = $false
    Headless   = [bool]$NoGui
    LogDir     = $null
    LogFile    = $null
    ReportFile = $null
})
#endregion

# Motore: definito una volta, usato dalla GUI, dal runspace di esecuzione e dalla modalita' -NoGui
$Engine = {
    #region MOTORE BASE (libreria _lib/toolkit, comune a tutti i tool GUI del repo)

    function Write-ToolLog {
        param(
            [string]$Message,
            [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP')][string]$Level = 'INFO'
        )
        $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.PadRight(5), $Message
        if ($State.LogFile) {
            try { Add-Content -LiteralPath $State.LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
        }
        if ($State.Headless) {
            $color = switch ($Level) { 'OK' { 'Green' } 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'STEP' { 'Cyan' } default { 'Gray' } }
            Write-Host $line -ForegroundColor $color
        } elseif ($State.Queue) {
            $State.Queue.Enqueue(@{ T = 'log'; L = $Level; M = $line })
        }
    }

    function Send-ToolMessage([hashtable]$Message) {
        if (-not $State.Headless -and $State.Queue) { $State.Queue.Enqueue($Message) }
    }

    # SID -> account (DOMINIO\utente) senza modulo ActiveDirectory; nome visualizzato via ADSI se disponibile
    function Resolve-SidAccount([string]$Sid) {
        try {
            $nt = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch { return $null }
        $parts = $nt.Split('\', 2)
        $domain = ''; $sam = $nt
        if ($parts.Count -eq 2) { $domain = $parts[0]; $sam = $parts[1] }
        $display = ''
        if ($domain -and $domain -ne $env:COMPUTERNAME) {
            try {
                $de = [adsi]"LDAP://<SID=$Sid>"
                if ($de.Properties['displayName'].Count -gt 0) { $display = [string]$de.Properties['displayName'][0] }
            } catch { }
        }
        [pscustomobject]@{ Account = $nt; Domain = $domain; Sam = $sam; DisplayName = $display }
    }

    function Resolve-AccountSid([string]$Domain, [string]$Sam) {
        try {
            if ($Domain) { $nt = New-Object System.Security.Principal.NTAccount($Domain, $Sam) }
            else { $nt = New-Object System.Security.Principal.NTAccount($Sam) }
            $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch { $null }
    }

    function Test-ExcludedUser($Config, [string]$Sam) {
        @($Config.ExcludeUsers) -contains $Sam
    }

    function Test-FileExclusive([string]$Path) {
        try {
            $fs = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
            $fs.Close()
            $true
        } catch { $false }
    }

    function Get-FreeBytes([string]$Path) {
        if (-not ('FispaTools.NativeDisk' -as [type])) {
            Add-Type -Namespace FispaTools -Name NativeDisk -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool GetDiskFreeSpaceEx(string lpDirectoryName, out ulong lpFreeBytesAvailable, out ulong lpTotalNumberOfBytes, out ulong lpTotalNumberOfFreeBytes);
'@
        }
        $p = $Path
        while ($p -and -not (Test-Path -LiteralPath $p)) { $p = Split-Path -Parent $p }
        if (-not $p) { return $null }
        if (-not $p.EndsWith('\')) { $p += '\' }
        $free = [uint64]0; $total = [uint64]0; $totalFree = [uint64]0
        if ([FispaTools.NativeDisk]::GetDiskFreeSpaceEx($p, [ref]$free, [ref]$total, [ref]$totalFree)) { return [double]$free }
        $null
    }

    function Assert-FreeSpace([string]$Path, [double]$Bytes) {
        if ($Bytes -le 0) { return }
        $free = Get-FreeBytes $Path
        if ($null -eq $free) { Write-ToolLog "Spazio libero non verificabile su $Path" 'WARN'; return }
        if ($free -lt $Bytes) {
            throw ('Spazio insufficiente su {0}: liberi {1:N1} GB, necessari {2:N1} GB' -f $Path, ($free / 1GB), ($Bytes / 1GB))
        }
    }

    # Avvio processo con lettura asincrona di stdout/stderr (niente deadlock su output lunghi)
    function Invoke-ProcessCapture([string]$FilePath, [string]$Arguments) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $out.Result; StdErr = $err.Result }
    }

    function Invoke-ToolRun($Config, $Items) {
        $list = @($Items)
        $n = $list.Count
        $results = New-Object System.Collections.Generic.List[object]
        $mode = 'ESECUZIONE REALE'
        if ($Config.DryRun) { $mode = 'SIMULAZIONE (nessuna modifica)' }
        if ($Tool.ReadOnly) { $mode = 'SOLA LETTURA' }
        Write-ToolLog ('=== {0} {1} - {2} {3} - {4}' -f $Tool.Title, $Tool.Version, $n, $Tool.ItemNoun, $mode) 'STEP'
        foreach ($k in @($Config.Keys)) { Write-ToolLog ('  {0} = {1}' -f $k, (@($Config[$k]) -join '; ')) }
        for ($i = 0; $i -lt $n; $i++) {
            $item = $list[$i]
            if ($State.Cancel) {
                for ($j = $i; $j -lt $n; $j++) {
                    $results.Add([pscustomobject]@{ Utente = $list[$j].Utente; SID = $list[$j].SID; Origine = $list[$j].Origine; Destinazione = ''; Esito = 'Annullato'; Messaggio = "Annullato dall'operatore"; DurataSec = 0; DimensioneMB = '' })
                    Send-ToolMessage @{ T = 'row'; K = $list[$j].Key; E = 'Annullato' }
                }
                Write-ToolLog "Annullato dall'operatore: $($n - $i) $($Tool.ItemNoun) non elaborati." 'WARN'
                break
            }
            Send-ToolMessage @{ T = 'prog'; C = $i; N = $n; M = ('{0}/{1} {2}' -f ($i + 1), $n, $item.Utente) }
            Write-ToolLog ('--- [{0}/{1}] {2} ({3})' -f ($i + 1), $n, $item.Utente, $item.SID) 'STEP'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
            try {
                $o = Invoke-ToolItem -Config $Config -Item $item
                foreach ($k in @($o.Keys)) { $r[$k] = $o[$k] }
            } catch {
                $r.Esito = 'Fallito'
                $r.Messaggio = $_.Exception.Message
                Write-ToolLog "Errore: $($r.Messaggio)" 'ERROR'
            }
            $sw.Stop()
            $lvl = switch ($r.Esito) { 'OK' { 'OK' } 'Fallito' { 'ERROR' } 'Critico' { 'ERROR' } 'Saltato' { 'WARN' } 'Attenzione' { 'WARN' } default { 'INFO' } }
            $txt = $r.Esito
            if ($r.Messaggio) { $txt += " - $($r.Messaggio)" }
            Write-ToolLog ('{0}: {1} ({2:N0} s)' -f $item.Utente, $txt, $sw.Elapsed.TotalSeconds) $lvl
            Send-ToolMessage @{ T = 'row'; K = $item.Key; E = $r.Esito }
            $results.Add([pscustomobject]@{
                Utente = $item.Utente; SID = $item.SID; Origine = $item.Origine; Destinazione = $r.Destinazione
                Esito = $r.Esito; Messaggio = $r.Messaggio; DurataSec = [math]::Round($sw.Elapsed.TotalSeconds, 0); DimensioneMB = $r.DimensioneMB
                Dati = $r['Dati']
            })
        }
        $State.ReportFile = Join-Path $State.LogDir ('{0}_Report_{1}.csv' -f $Tool.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        try { $results | Select-Object -Property * -ExcludeProperty Dati | Export-Csv -LiteralPath $State.ReportFile -NoTypeInformation -Delimiter ';' -Encoding UTF8 -ErrorAction Stop }
        catch { Write-ToolLog "Report CSV non scritto: $($_.Exception.Message)" 'ERROR'; $State.ReportFile = $null }
        # report aggiuntivo del tool (es. HTML), se il tool definisce Complete-ToolRun
        if (Get-Command Complete-ToolRun -CommandType Function -ErrorAction SilentlyContinue) {
            try {
                $extra = Complete-ToolRun -Config $Config -Results $results.ToArray()
                if ($extra) { $State.ReportFile = [string]@($extra)[-1] }
            } catch { Write-ToolLog "Report finale non generato: $($_.Exception.Message)" 'ERROR' }
        }
        $count = @{}
        foreach ($g in @($results | Group-Object Esito)) { $count[$g.Name] = $g.Count }
        $parts = @("Totale $n")
        foreach ($e in @('OK', 'Simulato', 'Info', 'Attenzione', 'Critico', 'Non verificato', 'Saltato', 'Fallito', 'Annullato')) { if ($count[$e]) { $parts += "$e $($count[$e])" } }
        $summary = $parts -join ' | '
        if (-not $count['Fallito']) { $count['Fallito'] = 0 }
        $lvl = 'OK'
        if ($count['Fallito'] -gt 0 -or $count['Critico'] -gt 0) { $lvl = 'ERROR' } elseif ($count['Saltato'] -or $count['Annullato'] -or $count['Attenzione']) { $lvl = 'WARN' }
        Write-ToolLog "=== Fine. $summary" $lvl
        if ($State.ReportFile) { Write-ToolLog "Report: $($State.ReportFile)" }
        Send-ToolMessage @{ T = 'done'; S = $summary; F = $count['Fallito']; R = $State.ReportFile }
        , $results.ToArray()
    }
    #endregion

    #region SPECIFICO: fotografia di sicurezza di Active Directory (sola lettura)

    $script:Dom = $null

    function Get-ToolDefaultConfig {
        [ordered]@{
            DomainController = ''
            InactiveDays     = 90
            KrbtgtMaxDays    = 180
            PrivilegedMax    = 5
            MaxEvidence      = 200
            CheckDcServices  = $true
            ScanSysvolGpp    = $true
            OutputDir        = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Report'))
            LogDir           = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not $env:USERDNSDOMAIN) { $w += 'Sessione non di dominio: eseguire da una macchina del dominio con un account di dominio.' }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        try { [void](Get-AdContext $Config) } catch { $e += "Dominio non raggiungibile: $($_.Exception.Message)" }
        if (-not $Scan -and -not $Config.OutputDir) { $e += 'Indicare la cartella dei report.' }
        $e
    }

    # ------------------------------------------------------------------ accesso LDAP

    function Get-AdContext($Config) {
        if ($script:Dom) { return $script:Dom }
        $dc = [string]$Config.DomainController
        if (-not $dc) { $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name }
        $root = [adsi]"LDAP://$dc/RootDSE"
        $dn = [string]$root.Properties['defaultNamingContext'][0]
        if (-not $dn) { throw "RootDSE non leggibile su $dc" }
        $domObj = [adsi]"LDAP://$dc/$dn"
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($domObj.Properties['objectSid'][0], 0)).Value
        $script:Dom = [pscustomobject]@{
            Dc        = $dc
            Dn        = $dn
            Dns       = ($dn -replace '^DC=', '' -replace ',DC=', '.')
            ConfigDn  = [string]$root.Properties['configurationNamingContext'][0]
            SchemaDn  = [string]$root.Properties['schemaNamingContext'][0]
            Sid       = $sid
            DomainFL  = [int]$root.Properties['domainFunctionality'][0]
            ForestFL  = [int]$root.Properties['forestFunctionality'][0]
            Now       = [DateTime]::UtcNow
        }
        $script:Dom
    }

    function Search-Ldap($Config, [string]$Filter, [string[]]$Props, [string]$Base, [string]$Scope = 'Subtree') {
        $ctx = Get-AdContext $Config
        if (-not $Base) { $Base = $ctx.Dn }
        $de = [adsi]"LDAP://$($ctx.Dc)/$($Base.Replace('/', '\/'))"
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
        $ds.Filter = $Filter
        $ds.PageSize = 1000
        $ds.SearchScope = $Scope
        [void]$ds.PropertiesToLoad.AddRange($Props)
        $out = New-Object System.Collections.Generic.List[object]
        $res = $ds.FindAll()
        try {
            foreach ($r in $res) {
                $h = @{}
                foreach ($p in $Props) {
                    $v = @($r.Properties[$p.ToLower()])
                    if ($v.Count -eq 1) { $h[$p] = $v[0] } elseif ($v.Count -gt 1) { $h[$p] = $v } else { $h[$p] = $null }
                }
                $out.Add([pscustomobject]$h)
            }
        } finally { $res.Dispose() }
        , $out.ToArray()
    }

    function Get-LdapObject($Config, [string]$Dn, [string[]]$Props) {
        $r = @(Search-Ldap $Config '(objectClass=*)' $Props $Dn 'Base')
        if ($r.Count) { $r[0] } else { $null }
    }

    function ConvertFrom-FileTime($v) {
        if ($null -eq $v) { return $null }
        $n = [int64]$v
        if ($n -le 0 -or $n -ge [DateTime]::MaxValue.ToFileTimeUtc()) { return $null }
        [DateTime]::FromFileTimeUtc($n)
    }

    function Get-AgeDays($v) {
        $d = ConvertFrom-FileTime $v
        if (-not $d) { return $null }
        [math]::Floor(((Get-AdContext $null).Now - $d).TotalDays)
    }

    function Get-SidDn($Config, [string]$Sid) {
        $ctx = Get-AdContext $Config
        try { [string]([adsi]"LDAP://$($ctx.Dc)/<SID=$Sid>").Properties['distinguishedName'][0] } catch { $null }
    }

    # Membri ricorsivi (utenti) di un gruppo, via LDAP_MATCHING_RULE_IN_CHAIN
    function Get-GroupMembersRecursive($Config, [string]$GroupDn) {
        if (-not $GroupDn) { return @() }
        $f = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f $GroupDn.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a')
        @(Search-Ldap $Config $f @('sAMAccountName', 'distinguishedName', 'userAccountControl', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'objectSid'))
    }

    function Get-ObjSid($o) {
        if ($o.objectSid -is [byte[]]) { return (New-Object System.Security.Principal.SecurityIdentifier($o.objectSid, 0)).Value }
        ''
    }

    function Test-Uac($o, [int]$Flag) { ([int]$o.userAccountControl -band $Flag) -ne 0 }

    $script:UserProps = @('sAMAccountName', 'distinguishedName', 'userAccountControl', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'servicePrincipalName', 'objectSid', 'whenCreated')

    function Get-PrivilegedGroups($Config) {
        $ctx = Get-AdContext $Config
        @(
            @{ Name = 'Domain Admins'; Sid = "$($ctx.Sid)-512" }
            @{ Name = 'Enterprise Admins'; Sid = "$($ctx.Sid)-519" }
            @{ Name = 'Schema Admins'; Sid = "$($ctx.Sid)-518" }
            @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' }
            @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548' }
            @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549' }
            @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550' }
            @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551' }
        )
    }

    function Get-PrivilegedUsers($Config) {
        if ($script:PrivUsers) { return $script:PrivUsers }
        $map = @{}
        foreach ($g in (Get-PrivilegedGroups $Config)) {
            $dn = Get-SidDn $Config $g.Sid
            foreach ($u in (Get-GroupMembersRecursive $Config $dn)) {
                $k = [string]$u.distinguishedName
                if (-not $map.ContainsKey($k)) { $map[$k] = [pscustomobject]@{ User = $u; Groups = New-Object System.Collections.Generic.List[string] } }
                $map[$k].Groups.Add($g.Name)
            }
        }
        $script:PrivUsers = @($map.Values)
        $script:PrivUsers
    }
    $script:PrivUsers = $null

    # Risultato standard di un controllo
    function New-CheckResult([string]$Status, [string]$Summary, $Evidence = @(), [string]$Remediation = '') {
        [pscustomobject]@{ Status = $Status; Summary = $Summary; Evidence = @($Evidence); Remediation = $Remediation }
    }

    function Format-Evidence($Objects, [scriptblock]$Text, $Config) {
        $max = [int]$Config.MaxEvidence
        if ($max -le 0) { $max = 200 }
        $all = @($Objects)
        $out = @($all | Select-Object -First $max | ForEach-Object { & $Text $_ })
        if ($all.Count -gt $max) { $out += "... altri $($all.Count - $max) (vedi JSON)" }
        $out
    }

    # ------------------------------------------------------------------ catalogo dei controlli
    # Ogni controllo: Id, Categoria, Titolo, Peso (punti di rischio se Critico; meta' se Attenzione), Richiede, Run (scriptblock che riceve $Config)

    function Get-AdChecks {
        @(
            # ----------------------------------------------------- salute
            @{ Id = 'H-DC-01'; Cat = 'Salute del dominio'; Title = 'Domain controller e sistemi operativi'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $dcs = @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp'))
                $old = @($dcs | Where-Object { "$($_.operatingSystem)" -match '2003|2008|2012' })
                $ev = Format-Evidence $dcs { param($d) '{0} - {1} {2}' -f $d.dNSHostName, $d.operatingSystem, $d.operatingSystemVersion } $Config
                if (@($old | Where-Object { "$($_.operatingSystem)" -match '2003|2008' }).Count) { return New-CheckResult 'Critico' "$($dcs.Count) DC, di cui $($old.Count) con sistema operativo fuori supporto" $ev 'Sostituire i DC con Windows Server 2003/2008: non ricevono aggiornamenti di sicurezza.' }
                if ($old.Count) { return New-CheckResult 'Attenzione' "$($dcs.Count) DC, di cui $($old.Count) con Windows Server 2012/2012 R2 (fuori supporto da ottobre 2023)" $ev 'Pianificare la sostituzione dei DC 2012/2012 R2.' }
                if ($dcs.Count -lt 2) { return New-CheckResult 'Attenzione' 'Un solo domain controller: nessuna ridondanza' $ev 'Aggiungere almeno un secondo DC.' }
                New-CheckResult 'OK' "$($dcs.Count) DC con sistema operativo supportato" $ev
            } }
            @{ Id = 'H-FL-01'; Cat = 'Salute del dominio'; Title = 'Livello funzionale di dominio e foresta'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $names = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }
                $txt = 'Dominio {0}, foresta {1}' -f $names[$ctx.DomainFL], $names[$ctx.ForestFL]
                if ($ctx.DomainFL -lt 6) { return New-CheckResult 'Attenzione' $txt @() 'Alzare il livello funzionale (almeno 2012 R2, meglio 2016) dopo aver sostituito i DC obsoleti: abilita Protected Users completo, Kerberos armoring, gMSA migliori.' }
                if ($ctx.DomainFL -lt 7) { return New-CheckResult 'Info' $txt @() 'Valutare il passaggio al livello 2016.' }
                New-CheckResult 'OK' $txt
            } }
            @{ Id = 'H-SYSVOL-01'; Cat = 'Salute del dominio'; Title = 'Replica SYSVOL: DFSR o FRS'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $g = Get-LdapObject $Config ("CN=DFSR-GlobalSettings,CN=System,$($ctx.Dn)") @('msDFSR-Flags')
                $flags = $null
                if ($g) { $flags = $g.'msDFSR-Flags' }
                $states = @{ 0 = 'Start (FRS)'; 16 = 'Prepared'; 32 = 'Redirected'; 48 = 'Eliminated (solo DFSR)' }
                if ($null -eq $flags) {
                    if ($ctx.DomainFL -ge 3) { return New-CheckResult 'Critico' 'Migrazione da FRS a DFSR mai avviata: SYSVOL replicata con FRS' @() 'Migrare SYSVOL a DFSR con dfsrmig (prepared, redirected, eliminated). FRS non e'' supportato da Windows Server 2019 in poi.' }
                    return New-CheckResult 'Critico' 'SYSVOL replicata con FRS (livello funzionale < 2008)' @() 'Alzare il livello funzionale e migrare a DFSR.' }
                $st = $states[[int]$flags]
                if ([int]$flags -eq 48) { return New-CheckResult 'OK' "SYSVOL replicata con DFSR (stato: $st)" }
                New-CheckResult 'Critico' "Migrazione FRS -> DFSR incompleta (stato: $st)" @() 'Completare la migrazione con dfsrmig /setglobalstate 3 e verificare con dfsrmig /getmigrationstate.'
            } }
            @{ Id = 'H-BIN-01'; Cat = 'Salute del dominio'; Title = 'Cestino di Active Directory'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $f = Get-LdapObject $Config ("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ctx.ConfigDn)") @('msDS-EnabledFeatureBL')
                if ($f -and $f.'msDS-EnabledFeatureBL') { return New-CheckResult 'OK' 'Cestino AD attivo' }
                New-CheckResult 'Attenzione' 'Cestino AD non attivo: gli oggetti eliminati si recuperano solo da backup' @() 'Enable-ADOptionalFeature "Recycle Bin Feature" (richiede livello foresta 2008 R2, operazione irreversibile).'
            } }
            @{ Id = 'H-FSMO-01'; Cat = 'Salute del dominio'; Title = 'Ruoli FSMO'; Weight = 0; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $f = $d.Forest
                $ev = @("PDC: $($d.PdcRoleOwner.Name)", "RID: $($d.RidRoleOwner.Name)", "Infrastructure: $($d.InfrastructureRoleOwner.Name)", "Schema: $($f.SchemaRoleOwner.Name)", "Domain naming: $($f.NamingRoleOwner.Name)")
                New-CheckResult 'Info' "PDC emulator: $($d.PdcRoleOwner.Name)" $ev
            } }

            # ----------------------------------------------------- account privilegiati
            @{ Id = 'P-ADM-01'; Cat = 'Account privilegiati'; Title = 'Membri dei gruppi privilegiati'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $priv = @(Get-PrivilegedUsers $Config)
                $ctx = Get-AdContext $Config
                $da = @(Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-512"))
                $sa = @(Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-518"))
                $ops = @($priv | Where-Object { @($_.Groups | Where-Object { $_ -like '*Operators' }).Count })
                $ev = Format-Evidence $priv { param($p) '{0} - {1}' -f $p.User.sAMAccountName, (($p.Groups | Sort-Object -Unique) -join ', ') } $Config
                $issues = @()
                if ($da.Count -gt [int]$Config.PrivilegedMax) { $issues += "$($da.Count) Domain Admins (soglia $($Config.PrivilegedMax))" }
                if ($sa.Count) { $issues += "$($sa.Count) membri di Schema Admins (va lasciato vuoto)" }
                if ($ops.Count) { $issues += "$($ops.Count) membri dei gruppi Operators (vanno lasciati vuoti)" }
                $sum = "$($priv.Count) account con privilegi amministrativi"
                if ($issues.Count) { return New-CheckResult 'Attenzione' ($sum + ': ' + ($issues -join '; ')) $ev 'Ridurre al minimo i membri, usare account amministrativi dedicati e separati dagli account quotidiani, svuotare Schema Admins e Operators.' }
                New-CheckResult 'OK' $sum $ev
            } }
            @{ Id = 'P-KRB-01'; Cat = 'Account privilegiati'; Title = 'Eta'' della password di krbtgt'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $k = @(Search-Ldap $Config '(&(objectClass=user)(sAMAccountName=krbtgt))' @('pwdLastSet'))
                $age = Get-AgeDays $k[0].pwdLastSet
                $txt = "Password di krbtgt cambiata $age giorni fa"
                if ($age -gt 3 * [int]$Config.KrbtgtMaxDays) { return New-CheckResult 'Critico' $txt @() 'Ruotare la password di krbtgt due volte, attendendo la replica completa tra le due rotazioni (script ufficiale Microsoft New-KrbtgtKeys).' }
                if ($age -gt [int]$Config.KrbtgtMaxDays) { return New-CheckResult 'Attenzione' $txt @() 'Ruotare periodicamente la password di krbtgt (due rotazioni distanziate).' }
                New-CheckResult 'OK' $txt
            } }
            @{ Id = 'P-ADM-02'; Cat = 'Account privilegiati'; Title = 'Account Administrator integrato'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $a = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-500") @('sAMAccountName', 'pwdLastSet', 'lastLogonTimestamp', 'userAccountControl')
                $pw = Get-AgeDays $a.pwdLastSet
                $ll = Get-AgeDays $a.lastLogonTimestamp
                $ev = @("Nome: $($a.sAMAccountName)", "Password cambiata $pw giorni fa", "Ultimo logon (circa): $(if ($null -ne $ll) { "$ll giorni fa" } else { 'mai' })")
                $iss = @()
                if ($null -ne $ll -and $ll -lt 30) { $iss += 'usato di recente' }
                if ($pw -gt 365) { $iss += 'password vecchia di oltre un anno' }
                if (-not (Test-Uac $a 0x100000)) { $iss += 'non marcato come sensibile e non delegabile' }
                if ($iss.Count) { return New-CheckResult 'Attenzione' ('Administrator integrato: ' + ($iss -join ', ')) $ev 'Usare account amministrativi nominativi; tenere l''Administrator integrato come emergenza, con password lunga custodita, sensibile e non delegabile.' }
                New-CheckResult 'OK' 'Administrator integrato non usato e protetto' $ev
            } }
            @{ Id = 'P-ADC-01'; Cat = 'Account privilegiati'; Title = 'adminCount orfani'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $priv = @{}
                foreach ($p in (Get-PrivilegedUsers $Config)) { $priv[[string]$p.User.distinguishedName] = $true }
                $ac = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(adminCount=1))' @('sAMAccountName', 'distinguishedName'))
                $orph = @($ac | Where-Object { -not $priv.ContainsKey([string]$_.distinguishedName) -and $_.sAMAccountName -ne 'krbtgt' })
                if (-not $orph.Count) { return New-CheckResult 'OK' 'Nessun account con adminCount=1 fuori dai gruppi privilegiati' }
                New-CheckResult 'Attenzione' "$($orph.Count) account con adminCount=1 non piu' privilegiati: ereditarieta' delle ACL bloccata" (Format-Evidence $orph { param($u) $u.sAMAccountName } $Config) 'Azzerare adminCount e riattivare l''ereditarieta'' delle autorizzazioni su questi account.'
            } }
            @{ Id = 'P-SENS-01'; Cat = 'Account privilegiati'; Title = 'Admin non protetti dalla delega'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $pu = @{}
                foreach ($u in (Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-525"))) { $pu[[string]$u.distinguishedName] = $true }
                $bad = @(Get-PrivilegedUsers $Config | Where-Object { -not (Test-Uac $_.User 0x100000) -and -not $pu.ContainsKey([string]$_.User.distinguishedName) -and -not (Test-Uac $_.User 2) })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Tutti gli account privilegiati attivi sono sensibili o in Protected Users' }
                New-CheckResult 'Attenzione' "$($bad.Count) account privilegiati delegabili e fuori da Protected Users" (Format-Evidence $bad { param($p) $p.User.sAMAccountName } $Config) 'Impostare "Account sensibile e non delegabile" e valutare Protected Users (mai per gli account di servizio; tenere un account break-glass fuori).'
            } }
            @{ Id = 'P-PU-01'; Cat = 'Account privilegiati'; Title = 'Gruppo Protected Users'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $dn = Get-SidDn $Config "$($ctx.Sid)-525"
                if (-not $dn) { return New-CheckResult 'Attenzione' 'Gruppo Protected Users assente (serve un PDC 2012 R2 o successivo)' }
                $m = @(Get-GroupMembersRecursive $Config $dn)
                if (-not $m.Count) { return New-CheckResult 'Attenzione' 'Protected Users e'' vuoto' @() 'Aggiungere gli account amministrativi dopo aver verificato la compatibilita'' (niente NTLM, delega, DES/RC4, credenziali in cache).' }
                New-CheckResult 'OK' "$($m.Count) account in Protected Users" (Format-Evidence $m { param($u) $u.sAMAccountName } $Config)
            } }

            # ----------------------------------------------------- Kerberos
            @{ Id = 'K-SPN-01'; Cat = 'Kerberos'; Title = 'Account utente con SPN (kerberoasting)'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account utente attivo con SPN' }
                $priv = @{}
                foreach ($p in (Get-PrivilegedUsers $Config)) { $priv[[string]$p.User.distinguishedName] = $true }
                $privSpn = @($u | Where-Object { $priv.ContainsKey([string]$_.distinguishedName) })
                $ev = Format-Evidence $u { param($x) '{0} - password di {1} giorni{2}' -f $x.sAMAccountName, (Get-AgeDays $x.pwdLastSet), $(if ($priv.ContainsKey([string]$x.distinguishedName)) { ' - PRIVILEGIATO' } else { '' }) } $Config
                if ($privSpn.Count) { return New-CheckResult 'Critico' "$($u.Count) account con SPN, di cui $($privSpn.Count) privilegiati: la loro password si puo' attaccare offline" $ev 'Convertire i servizi in gMSA; dove non possibile, password di almeno 25 caratteri e togliere i privilegi.' }
                New-CheckResult 'Attenzione' "$($u.Count) account utente con SPN esposti al kerberoasting" $ev 'Convertire i servizi in gMSA o usare password lunghe (25+ caratteri) e cifratura AES.'
            } }
            @{ Id = 'K-ASREP-01'; Cat = 'Kerberos'; Title = 'Preautenticazione Kerberos disattivata (AS-REP roasting)'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account senza preautenticazione' }
                New-CheckResult 'Critico' "$($u.Count) account senza preautenticazione Kerberos" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere "Non richiedere la preautenticazione Kerberos" dagli account.'
            } }
            @{ Id = 'K-DEL-01'; Cat = 'Kerberos'; Title = 'Delega non vincolata'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $o = @(Search-Ldap $Config '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'objectClass'))
                if (-not $o.Count) { return New-CheckResult 'OK' 'Nessun oggetto (esclusi i DC) con delega non vincolata' }
                New-CheckResult 'Critico' "$($o.Count) oggetti con delega non vincolata: chi li compromette ottiene i ticket di chi vi si autentica" (Format-Evidence $o { param($x) $x.sAMAccountName } $Config) 'Passare alla delega vincolata (o RBCD) solo verso i servizi necessari.'
            } }
            @{ Id = 'K-DES-01'; Cat = 'Kerberos'; Title = 'Account con cifratura DES'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account limitato a DES' }
                New-CheckResult 'Attenzione' "$($u.Count) account con 'Usa solo tipi di crittografia DES'" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere l''opzione DES: e'' disattivato di default da Windows 7 / 2008 R2.'
            } }

            # ----------------------------------------------------- password e account
            @{ Id = 'W-POL-01'; Cat = 'Password e account'; Title = 'Policy delle password di dominio'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $d = Get-LdapObject $Config $ctx.Dn @('minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'lockoutThreshold', 'pwdProperties')
                $maxAge = 0
                if ($d.maxPwdAge -and [int64]$d.maxPwdAge -ne [int64]::MinValue) { $maxAge = [math]::Round([math]::Abs([int64]$d.maxPwdAge) / 864000000000) }
                $complex = ([int]$d.pwdProperties -band 1) -ne 0
                $ev = @("Lunghezza minima: $($d.minPwdLength)", "Cronologia: $($d.pwdHistoryLength)", "Scadenza: $(if ($maxAge) { "$maxAge giorni" } else { 'mai' })", "Blocco dopo: $(if ([int]$d.lockoutThreshold) { "$($d.lockoutThreshold) tentativi" } else { 'mai' })", "Complessita': $(if ($complex) { 'si' } else { 'no' })")
                $iss = @()
                $crit = $false
                if ([int]$d.minPwdLength -lt 8) { $iss += 'lunghezza minima sotto 8'; $crit = $true } elseif ([int]$d.minPwdLength -lt 12) { $iss += 'lunghezza minima sotto 12' }
                if (-not [int]$d.lockoutThreshold) { $iss += 'nessun blocco dopo tentativi errati' }
                if (-not $complex) { $iss += 'complessita'' disattivata' }
                if ([int]$d.pwdHistoryLength -lt 12) { $iss += 'cronologia sotto 12' }
                $rem = 'Lunghezza minima di almeno 12-14 caratteri (meglio passphrase), blocco dopo 5-10 tentativi, cronologia 24; per gli admin una PSO piu'' restrittiva.'
                if ($crit) { return New-CheckResult 'Critico' ('Policy debole: ' + ($iss -join ', ')) $ev $rem }
                if ($iss.Count) { return New-CheckResult 'Attenzione' ('Policy da rafforzare: ' + ($iss -join ', ')) $ev $rem }
                New-CheckResult 'OK' 'Policy delle password adeguata' $ev
            } }
            @{ Id = 'W-NREQ-01'; Cat = 'Password e account'; Title = 'Account con password non obbligatoria'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account attivo con PASSWD_NOTREQD' }
                New-CheckResult 'Critico' "$($u.Count) account attivi possono avere password vuota" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere il flag PASSWD_NOTREQD (userAccountControl 0x20) e impostare una password.'
            } }
            @{ Id = 'W-REV-01'; Cat = 'Password e account'; Title = 'Password con cifratura reversibile'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account con cifratura reversibile' }
                New-CheckResult 'Critico' "$($u.Count) account con password memorizzata in modo reversibile" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere l''opzione e far cambiare la password.'
            } }
            @{ Id = 'W-NEXP-01'; Cat = 'Password e account'; Title = 'Password che non scadono'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account attivo con password senza scadenza' }
                New-CheckResult 'Attenzione' "$($u.Count) account attivi con password che non scade" (Format-Evidence $u { param($x) '{0} - password di {1} giorni' -f $x.sAMAccountName, (Get-AgeDays $x.pwdLastSet) } $Config) 'Per gli account di servizio passare a gMSA; per gli utenti togliere l''opzione o usare password lunghe con controllo delle password compromesse.'
            } }
            @{ Id = 'W-INACT-01'; Cat = 'Password e account'; Title = 'Utenti attivi inutilizzati'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $days = [int]$Config.InactiveDays
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                $old = @($u | Where-Object { $ll = Get-AgeDays $_.lastLogonTimestamp; $cr = $_.whenCreated; ($null -eq $ll -and $cr -and ((Get-Date) - [datetime]$cr).TotalDays -gt $days) -or ($null -ne $ll -and $ll -gt $days) })
                if (-not $old.Count) { return New-CheckResult 'OK' "Nessun utente attivo inutilizzato da oltre $days giorni" }
                New-CheckResult 'Attenzione' "$($old.Count) utenti attivi senza logon da oltre $days giorni (su $($u.Count))" (Format-Evidence $old { param($x) $ll = Get-AgeDays $x.lastLogonTimestamp; '{0} - ultimo logon {1}' -f $x.sAMAccountName, $(if ($null -ne $ll) { "$ll giorni fa" } else { 'mai' }) } $Config) 'Disabilitare gli account non usati e spostarli in un''OU dedicata; eliminarli dopo un periodo di attesa.'
            } }
            @{ Id = 'W-COMP-01'; Cat = 'Password e account'; Title = 'Computer obsoleti o inattivi'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $days = [int]$Config.InactiveDays
                $c = @(Search-Ldap $Config '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'operatingSystem', 'lastLogonTimestamp'))
                $eol = @($c | Where-Object { "$($_.operatingSystem)" -match 'Windows (XP|Vista|7|8 |8\.1)|Server (2003|2008)' })
                $inact = @($c | Where-Object { $ll = Get-AgeDays $_.lastLogonTimestamp; $null -ne $ll -and $ll -gt $days })
                $ev = @(Format-Evidence $eol { param($x) 'Obsoleto: {0} - {1}' -f $x.sAMAccountName, $x.operatingSystem } $Config) + @(Format-Evidence $inact { param($x) 'Inattivo: {0} - {1} giorni' -f $x.sAMAccountName, (Get-AgeDays $x.lastLogonTimestamp) } $Config)
                if ($eol.Count) { return New-CheckResult 'Critico' "$($eol.Count) computer con sistema operativo fuori supporto, $($inact.Count) inattivi da oltre $days giorni (su $($c.Count))" $ev 'Sostituire o isolare i sistemi fuori supporto; disabilitare i computer inattivi.' }
                if ($inact.Count) { return New-CheckResult 'Attenzione' "$($inact.Count) computer inattivi da oltre $days giorni (su $($c.Count))" $ev 'Disabilitare e poi eliminare i computer inattivi.' }
                New-CheckResult 'OK' "$($c.Count) computer attivi, nessuno obsoleto o inattivo"
            } }

            # ----------------------------------------------------- configurazione
            @{ Id = 'C-MAQ-01'; Cat = 'Configurazione del dominio'; Title = 'MachineAccountQuota'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $d = Get-LdapObject $Config $ctx.Dn @('ms-DS-MachineAccountQuota')
                $q = [int]$d.'ms-DS-MachineAccountQuota'
                if ($q -eq 0) { return New-CheckResult 'OK' 'MachineAccountQuota = 0' }
                New-CheckResult 'Attenzione' "MachineAccountQuota = $($q): ogni utente puo' aggiungere $q computer al dominio" @() 'Impostare ms-DS-MachineAccountQuota a 0 e delegare il join a un gruppo dedicato (base di molti attacchi RBCD).'
            } }
            @{ Id = 'C-PRE2K-01'; Cat = 'Configurazione del dominio'; Title = 'Accesso compatibile pre-Windows 2000'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $g = Get-LdapObject $Config (Get-SidDn $Config 'S-1-5-32-554') @('member')
                $members = @($g.member | Where-Object { $_ })
                $bad = @($members | Where-Object { $_ -match 'S-1-1-0|S-1-5-7' })
                $ev = @($members | ForEach-Object { "$_" })
                if ($bad.Count) { return New-CheckResult 'Critico' 'Everyone o ANONYMOUS LOGON nel gruppo "Accesso compatibile precedente a Windows 2000": lettura anonima della directory' $ev 'Rimuovere Everyone e ANONYMOUS LOGON dal gruppo (lasciare Authenticated Users solo se necessario).' }
                New-CheckResult 'OK' 'Nessun accesso anonimo tramite il gruppo pre-Windows 2000' $ev
            } }
            @{ Id = 'C-LAPS-01'; Cat = 'Configurazione del dominio'; Title = 'LAPS: copertura delle password degli admin locali'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $win = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' @('lDAPDisplayName') $ctx.SchemaDn 'OneLevel').Count -gt 0
                $leg = @(Search-Ldap $Config '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' @('lDAPDisplayName') $ctx.SchemaDn 'OneLevel').Count -gt 0
                if (-not $win -and -not $leg) { return New-CheckResult 'Critico' 'LAPS non installato (schema non esteso): password degli admin locali probabilmente uguali ovunque' @() 'Implementare Windows LAPS (Update-LapsADSchema, permessi sulle OU, GPO).' }
                $props = @('sAMAccountName')
                if ($win) { $props += 'msLAPS-PasswordExpirationTime' }
                if ($leg) { $props += 'ms-Mcs-AdmPwdExpirationTime' }
                $c = @(Search-Ldap $Config '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' $props)
                $cov = @($c | Where-Object { ($win -and $_.'msLAPS-PasswordExpirationTime') -or ($leg -and $_.'ms-Mcs-AdmPwdExpirationTime') })
                $miss = @($c | Where-Object { -not (($win -and $_.'msLAPS-PasswordExpirationTime') -or ($leg -and $_.'ms-Mcs-AdmPwdExpirationTime')) })
                $pct = 0
                if ($c.Count) { $pct = [math]::Round($cov.Count * 100 / $c.Count) }
                $kind = @(); if ($win) { $kind += 'Windows LAPS' }; if ($leg) { $kind += 'LAPS legacy' }
                $sum = "$($kind -join ' + '): $($cov.Count) computer su $($c.Count) coperti ($pct%)"
                $ev = Format-Evidence $miss { param($x) "Senza LAPS: $($x.sAMAccountName)" } $Config
                if ($pct -lt 50) { return New-CheckResult 'Critico' $sum $ev 'Estendere la GPO LAPS a tutte le OU dei computer.' }
                if ($pct -lt 95) { return New-CheckResult 'Attenzione' $sum $ev 'Estendere la GPO LAPS ai computer mancanti.' }
                New-CheckResult 'OK' $sum $ev
            } }
            @{ Id = 'C-GMSA-01'; Cat = 'Configurazione del dominio'; Title = 'gMSA e KDS root key'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $keys = @(Search-Ldap $Config '(objectClass=msKds-ProvRootKey)' @('cn') ("CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($ctx.ConfigDn)") 'OneLevel')
                $g = @(Search-Ldap $Config '(objectClass=msDS-GroupManagedServiceAccount)' @('sAMAccountName'))
                $ev = Format-Evidence $g { param($x) $x.sAMAccountName } $Config
                if (-not $keys.Count) { return New-CheckResult 'Attenzione' 'KDS root key assente: i gMSA non si possono usare' $ev 'Add-KdsRootKey -EffectiveImmediately (diventa utilizzabile dopo 10 ore), poi convertire i servizi in gMSA.' }
                if (-not $g.Count) { return New-CheckResult 'Info' 'KDS root key presente, nessun gMSA in uso' $ev 'Convertire in gMSA i servizi che girano con account utente (vedi K-SPN-01 e W-NEXP-01).' }
                New-CheckResult 'OK' "$($g.Count) gMSA in uso" $ev
            } }
            @{ Id = 'C-GPP-01'; Cat = 'Configurazione del dominio'; Title = 'Password nelle Group Policy Preferences (cpassword)'; Weight = 15; Needs = 'Utente di dominio (lettura SYSVOL)'; Run = {
                param($Config)
                if (-not $Config.ScanSysvolGpp) { return New-CheckResult 'Non verificato' 'Controllo disattivato nella configurazione' }
                $ctx = Get-AdContext $Config
                $root = "\\$($ctx.Dns)\SYSVOL\$($ctx.Dns)\Policies"
                if (-not (Test-Path -LiteralPath $root)) { return New-CheckResult 'Non verificato' "SYSVOL non raggiungibile: $root" }
                $hits = @(Get-ChildItem -LiteralPath $root -Recurse -Include *.xml -File -ErrorAction SilentlyContinue | Where-Object { Select-String -LiteralPath $_.FullName -Pattern 'cpassword="[^"]+' -Quiet })
                if (-not $hits.Count) { return New-CheckResult 'OK' 'Nessuna password GPP trovata in SYSVOL' }
                New-CheckResult 'Critico' "$($hits.Count) file GPP con password (decifrabili da chiunque nel dominio)" (Format-Evidence $hits { param($f) $f.FullName.Substring($root.Length) } $Config) 'Eliminare le preferenze con password, cambiare subito le password esposte e usare LAPS o gMSA.'
            } }
            @{ Id = 'C-TRUST-01'; Cat = 'Configurazione del dominio'; Title = 'Trust'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $t = @(Search-Ldap $Config '(objectClass=trustedDomain)' @('name', 'trustDirection', 'trustType', 'trustAttributes'))
                if (-not $t.Count) { return New-CheckResult 'OK' 'Nessun trust' }
                $dir = @{ 1 = 'in ingresso'; 2 = 'in uscita'; 3 = 'bidirezionale' }
                $noFilter = @($t | Where-Object { [int]$_.trustType -eq 2 -and ([int]$_.trustAttributes -band 0x8) -eq 0 -and ([int]$_.trustAttributes -band 0x4) -eq 0 -and [int]$_.trustDirection -band 1 })
                $ev = Format-Evidence $t { param($x) '{0} - {1}, attributi 0x{2:X}' -f $x.name, $dir[[int]$x.trustDirection], [int]$x.trustAttributes } $Config
                if ($noFilter.Count) { return New-CheckResult 'Attenzione' "$($t.Count) trust, di cui $($noFilter.Count) esterni in ingresso senza SID filtering" $ev 'Attivare il SID filtering (quarantine) sui trust esterni e valutare la selective authentication.' }
                New-CheckResult 'Info' "$($t.Count) trust configurati" $ev
            } }
            @{ Id = 'C-SPOOL-01'; Cat = 'Configurazione del dominio'; Title = 'Print Spooler sui domain controller'; Weight = 10; Needs = 'Amministratore sui DC (WMI/WinRM)'; Run = {
                param($Config)
                if (-not $Config.CheckDcServices) { return New-CheckResult 'Non verificato' 'Controllo disattivato nella configurazione' }
                $dcs = @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))
                $on = @(); $ko = @()
                foreach ($d in $dcs) {
                    try {
                        $s = Get-CimInstance -ComputerName $d.dNSHostName -ClassName Win32_Service -Filter "Name='Spooler'" -OperationTimeoutSec 20 -ErrorAction Stop
                        if ($s.State -eq 'Running') { $on += $d.dNSHostName }
                    } catch { $ko += $d.dNSHostName }
                }
                $ev = @($on | ForEach-Object { "Spooler attivo: $_" }) + @($ko | ForEach-Object { "Non verificato (accesso negato o WinRM chiuso): $_" })
                if ($on.Count) { return New-CheckResult 'Critico' "Print Spooler attivo su $($on.Count) DC (PrintNightmare, coercizione dell'autenticazione)" $ev 'Disattivare e fermare il servizio Spooler sui DC via GPO.' }
                if ($ko.Count -eq $dcs.Count) { return New-CheckResult 'Non verificato' 'Nessun DC interrogabile: servono privilegi di amministratore e WinRM' $ev }
                New-CheckResult 'OK' 'Print Spooler fermo sui DC verificati' $ev
            } }
        )
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria

    function Get-ToolItems($Config) {
        $ctx = Get-AdContext $Config
        Write-ToolLog "Dominio $($ctx.Dns) - DC $($ctx.Dc)" 'STEP'
        foreach ($c in (Get-AdChecks)) {
            [pscustomobject]@{
                Key        = $c.Id
                Utente     = $c.Id
                SID        = ''
                Origine    = $c.Cat
                Id         = $c.Id
                Categoria  = $c.Cat
                Controllo  = $c.Title
                Peso       = $c.Weight
                Richiede   = $c.Needs
                Stato      = 'Pronto'
                Selectable = $true
            }
        }
    }

    function Invoke-ToolItem($Config, $Item) {
        $c = @(Get-AdChecks | Where-Object { $_.Id -eq $Item.Id })[0]
        if (-not $c) { throw "Controllo sconosciuto: $($Item.Id)" }
        $r = & $c.Run $Config
        if (-not $r) { throw 'Il controllo non ha restituito un risultato' }
        $points = 0
        if ($r.Status -eq 'Critico') { $points = $c.Weight } elseif ($r.Status -eq 'Attenzione') { $points = [math]::Ceiling($c.Weight / 2) }
        $dati = [pscustomobject]@{
            Id = $c.Id; Categoria = $c.Cat; Titolo = $c.Title; Peso = $c.Weight; Punti = $points; Richiede = $c.Needs
            Esito = $r.Status; Sintesi = $r.Summary; Evidenze = @($r.Evidence); Remediation = $r.Remediation
        }
        foreach ($e in @($r.Evidence | Select-Object -First 5)) { Write-ToolLog "    $e" }
        @{ Esito = $r.Status; Messaggio = $r.Summary; Dati = $dati }
    }

    function ConvertTo-HtmlText($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }

    # Report HTML, JSON e CSV delle evidenze. Restituisce il percorso del report HTML
    function Complete-ToolRun($Config, $Results) {
        $ctx = Get-AdContext $Config
        $dir = [string]$Config.OutputDir
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $base = Join-Path $dir ('ADAssessment_{0}_{1}' -f $ctx.Dns, $stamp)
        $checks = @($Results | Where-Object { $_.Dati } | ForEach-Object { $_.Dati })
        foreach ($f in @($Results | Where-Object { -not $_.Dati -and $_.Esito -eq 'Fallito' })) {
            $checks += [pscustomobject]@{ Id = $f.Utente; Categoria = $f.Origine; Titolo = $f.Utente; Peso = 0; Punti = 0; Richiede = ''; Esito = 'Non verificato'; Sintesi = "Errore: $($f.Messaggio)"; Evidenze = @(); Remediation = '' }
        }
        $risk = [int](($checks | Measure-Object -Property Punti -Sum).Sum)
        $score = [math]::Max(0, 100 - $risk)
        $meta = [pscustomobject]@{ Dominio = $ctx.Dns; DC = $ctx.Dc; Data = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Eseguito = "$env:USERDOMAIN\$env:USERNAME"; Da = $env:COMPUTERNAME; Versione = $Tool.Version; Punteggio = $score; Rischio = $risk }

        # JSON e CSV
        [System.IO.File]::WriteAllText("$base.json", ([pscustomobject]@{ Meta = $meta; Controlli = $checks } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
        $checks | Select-Object Id, Categoria, Titolo, Esito, Punti, Sintesi, Remediation | Export-Csv -LiteralPath "$base`_controlli.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        @(foreach ($c in $checks) { foreach ($e in @($c.Evidenze)) { [pscustomobject]@{ Id = $c.Id; Esito = $c.Esito; Evidenza = $e } } }) |
            Export-Csv -LiteralPath "$base`_evidenze.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8

        # HTML
        $colors = @{ 'OK' = '#2f855a'; 'Info' = '#3182ce'; 'Attenzione' = '#dd6b20'; 'Critico' = '#c53030'; 'Non verificato' = '#718096' }
        $order = @{ 'Critico' = 0; 'Attenzione' = 1; 'Non verificato' = 2; 'Info' = 3; 'OK' = 4 }
        $cnt = @{}
        foreach ($k in $colors.Keys) { $cnt[$k] = @($checks | Where-Object { $_.Esito -eq $k }).Count }
        $scoreColor = '#2f855a'
        if ($score -lt 50) { $scoreColor = '#c53030' } elseif ($score -lt 75) { $scoreColor = '#dd6b20' }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<!DOCTYPE html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
        [void]$sb.Append("<title>Fotografia AD - $(ConvertTo-HtmlText $ctx.Dns)</title><style>")
        [void]$sb.Append('body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1a202c}.wrap{max-width:1100px;margin:0 auto;padding:24px}')
        [void]$sb.Append('h1{margin:0 0 4px}h2{margin:28px 0 10px;border-bottom:2px solid #cbd5e0;padding-bottom:4px}.muted{color:#718096;font-size:13px}')
        [void]$sb.Append('.tiles{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}.tile{background:#fff;border-radius:8px;padding:14px 18px;min-width:120px;box-shadow:0 1px 2px rgba(0,0,0,.08)}.tile b{display:block;font-size:26px}')
        [void]$sb.Append('.chk{background:#fff;border-radius:8px;margin:10px 0;padding:12px 16px;border-left:6px solid #cbd5e0;box-shadow:0 1px 2px rgba(0,0,0,.06)}')
        [void]$sb.Append('.badge{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;margin-right:8px}.id{font-family:Consolas,monospace;color:#4a5568;font-size:12px;margin-right:8px}')
        [void]$sb.Append('.rem{margin-top:6px;font-size:14px}.rem b{color:#2d3748}details{margin-top:6px}summary{cursor:pointer;color:#3182ce;font-size:13px}pre{background:#f7fafc;padding:8px;white-space:pre-wrap;font-size:12px;max-height:320px;overflow:auto}')
        [void]$sb.Append('table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:6px 10px;border-bottom:1px solid #e2e8f0;text-align:left;font-size:14px}</style></head><body><div class="wrap">')
        [void]$sb.Append("<h1>Fotografia di sicurezza Active Directory</h1><div class=`"muted`">Dominio <b>$(ConvertTo-HtmlText $ctx.Dns)</b> - DC $(ConvertTo-HtmlText $ctx.Dc) - $($meta.Data) - eseguito da $(ConvertTo-HtmlText $meta.Eseguito) su $(ConvertTo-HtmlText $env:COMPUTERNAME) - $($Tool.Title) $($Tool.Version)</div>")
        [void]$sb.Append("<div class=`"tiles`"><div class=`"tile`"><b style=`"color:$scoreColor`">$score/100</b>Punteggio</div>")
        foreach ($k in @('Critico', 'Attenzione', 'Non verificato', 'Info', 'OK')) { [void]$sb.Append("<div class=`"tile`"><b style=`"color:$($colors[$k])`">$($cnt[$k])</b>$k</div>") }
        [void]$sb.Append('</div>')
        # riepilogo per categoria
        [void]$sb.Append('<table><tr><th>Categoria</th><th>Critico</th><th>Attenzione</th><th>Punti di rischio</th></tr>')
        foreach ($g in @($checks | Group-Object Categoria)) {
            $gc = @($g.Group | Where-Object { $_.Esito -eq 'Critico' }).Count
            $ga = @($g.Group | Where-Object { $_.Esito -eq 'Attenzione' }).Count
            $gp = [int](($g.Group | Measure-Object -Property Punti -Sum).Sum)
            [void]$sb.Append("<tr><td>$(ConvertTo-HtmlText $g.Name)</td><td>$gc</td><td>$ga</td><td>$gp</td></tr>")
        }
        [void]$sb.Append('</table>')
        foreach ($g in @($checks | Group-Object Categoria)) {
            [void]$sb.Append("<h2>$(ConvertTo-HtmlText $g.Name)</h2>")
            foreach ($c in @($g.Group | Sort-Object { $order[$_.Esito] }, Id)) {
                $col = $colors[$c.Esito]
                if (-not $col) { $col = '#718096' }
                [void]$sb.Append("<div class=`"chk`" style=`"border-left-color:$col`"><span class=`"badge`" style=`"background:$col`">$(ConvertTo-HtmlText $c.Esito)</span><span class=`"id`">$(ConvertTo-HtmlText $c.Id)</span><b>$(ConvertTo-HtmlText $c.Titolo)</b>")
                if ($c.Punti) { [void]$sb.Append(" <span class=`"muted`">($($c.Punti) punti)</span>") }
                [void]$sb.Append("<div>$(ConvertTo-HtmlText $c.Sintesi)</div>")
                if ($c.Remediation -and $c.Esito -ne 'OK') { [void]$sb.Append("<div class=`"rem`"><b>Cosa fare:</b> $(ConvertTo-HtmlText $c.Remediation)</div>") }
                $ev = @($c.Evidenze)
                if ($ev.Count) { [void]$sb.Append("<details><summary>Evidenze ($($ev.Count))</summary><pre>$(ConvertTo-HtmlText ($ev -join "`n"))</pre></details>") }
                [void]$sb.Append('</div>')
            }
        }
        [void]$sb.Append("<p class=`"muted`">Strumento in sola lettura: nessuna modifica e' stata fatta al dominio. File: $(ConvertTo-HtmlText $base).json / _controlli.csv / _evidenze.csv</p></div></body></html>")
        [System.IO.File]::WriteAllText("$base.html", $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
        Write-ToolLog ('Punteggio {0}/100 (rischio {1} punti) - Critici {2}, Attenzione {3}' -f $score, $risk, $cnt['Critico'], $cnt['Attenzione']) 'STEP'
        Write-ToolLog "Report HTML: $base.html" 'OK'
        "$base.html"
    }
    #endregion
}

#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Dominio' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente nel dominio della macchina. Tutte le letture LDAP usano questo DC.' }
    @{ Type = 'Section'; Label = 'Soglie' }
    @{ Key = 'InactiveDays'; Label = 'Giorni di inattivita'''; Type = 'Int'; Min = 30; Max = 730; Help = 'Oltre questa soglia utenti e computer senza logon sono segnalati come inattivi.' }
    @{ Key = 'KrbtgtMaxDays'; Label = 'Eta'' massima password krbtgt (giorni)'; Type = 'Int'; Min = 30; Max = 3650; Help = 'Oltre: Attenzione; oltre il triplo: Critico.' }
    @{ Key = 'PrivilegedMax'; Label = 'Numero massimo di Domain Admins'; Type = 'Int'; Min = 1; Max = 100 }
    @{ Key = 'MaxEvidence'; Label = 'Evidenze massime per controllo'; Type = 'Int'; Min = 10; Max = 100000; Help = 'Righe mostrate nel report HTML; il JSON e il CSV delle evidenze contengono lo stesso limite.' }
    @{ Type = 'Section'; Label = 'Controlli opzionali' }
    @{ Key = 'CheckDcServices'; Label = 'Interroga i servizi dei DC (Print Spooler)'; Type = 'Bool'; Help = 'Richiede privilegi di amministratore sui DC e WinRM/WMI raggiungibile; altrimenti il controllo risulta Non verificato.' }
    @{ Key = 'ScanSysvolGpp'; Label = 'Cerca password GPP in SYSVOL (cpassword)'; Type = 'Bool'; Help = 'Legge tutti i file XML delle GPO in SYSVOL.' }
    @{ Type = 'Section'; Label = 'Output' }
    @{ Key = 'OutputDir'; Label = 'Cartella dei report'; Type = 'Folder'; Help = 'Report HTML, JSON completo, CSV dei controlli e delle evidenze.' }
    @{ Key = 'LogDir'; Label = 'Cartella log'; Type = 'Folder' }
)

$ToolColumns = @(
    @{ Name = 'Id'; Header = 'ID'; Weight = 8 }
    @{ Name = 'Categoria'; Header = 'Categoria'; Weight = 14 }
    @{ Name = 'Controllo'; Header = 'Controllo'; Weight = 30 }
    @{ Name = 'Peso'; Header = 'Peso'; Weight = 5 }
    @{ Name = 'Richiede'; Header = 'Richiede'; Weight = 16 }
)
#endregion

#region CONFIGURAZIONE E INTERFACCIA (libreria _lib/toolkit)
. $Engine

# etichette dell'interfaccia: ogni tool puo' personalizzarle in $Tool
foreach ($kv in @{ ItemNoun = 'elementi'; ItemTab = 'Elementi'; StartLabel = 'Avvia'; RunningLabel = 'Operazione in corso'; CloseWarning = '' }.GetEnumerator()) {
    if (-not $Tool.ContainsKey($kv.Key)) { $Tool[$kv.Key] = $kv.Value }
}

$ToolDataDir = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name)
$DefaultConfigPath = Join-Path $ToolDataDir 'config.json'

function ConvertTo-ConfigValue($Field, $Value) {
    switch ($Field.Type) {
        'Int' { try { return [int]$Value } catch { return $null } }
        'Bool' { return [bool]$Value }
        'List' {
            if ($null -eq $Value) { return , @() }
            $arr = @(@($Value) | ForEach-Object { "$_" -split '[;\r\n]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return , $arr
        }
        'Choice' {
            if (@($Field.Choices) -contains [string]$Value) { return [string]$Value }
            return $null
        }
        default {
            if ($null -eq $Value) { return '' }
            return [string]$Value
        }
    }
}

function Read-ToolConfig([string]$Path) {
    $cfg = Get-ToolDefaultConfig
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $loaded = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($f in $ToolSchema) {
            if (-not $f.Key) { continue }
            $p = $loaded.PSObject.Properties[$f.Key]
            if ($p) {
                $v = ConvertTo-ConfigValue $f $p.Value
                if ($null -ne $v) { $cfg[$f.Key] = $v }
            }
        }
    }
    $cfg
}

function Save-ToolConfig($Config, [string]$Path) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = [pscustomobject]$Config | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($true)))
}

function Initialize-ToolLog($Config) {
    $dir = [string]$Config.LogDir
    if (-not $dir) { $dir = Join-Path $ToolDataDir 'Log' }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $State.LogDir = $dir
    $State.LogFile = Join-Path $dir ('{0}_{1}.log' -f $Tool.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# ------------------------------------------------------------------ modalita' senza GUI
if ($NoGui) {
    $cfgPath = $DefaultConfigPath
    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { Write-Error "File di configurazione non trovato: $ConfigPath"; exit 1 }
        $cfgPath = $ConfigPath
    }
    $Config = Read-ToolConfig $cfgPath
    if ($Simulate) { $Config.DryRun = $true }
    Initialize-ToolLog $Config
    Write-ToolLog "Configurazione: $cfgPath"
    foreach ($w in @(Get-ToolPrereqIssues $Config)) { Write-ToolLog $w 'WARN' }
    $errs = @(Test-ToolConfig $Config)
    if ($errs.Count) { foreach ($e in $errs) { Write-ToolLog $e 'ERROR' }; exit 1 }
    $items = @(Get-ToolItems -Config $Config | Where-Object { $_.Selectable })
    if ($User) { $items = @($items | Where-Object { $User -contains $_.Utente }) }
    if (-not $items.Count) { Write-ToolLog "Nessun elemento da elaborare ($($Tool.ItemNoun))." 'WARN'; exit 0 }
    $res = @(Invoke-ToolRun -Config $Config -Items $items)
    if (@($res | Where-Object { $_.Esito -eq 'Fallito' }).Count) { exit 2 }
    exit 0
}

# ------------------------------------------------------------------ GUI
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

function Show-Err([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'OK', 'Error') }
function Show-Info([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'OK', 'Information') }
function Confirm-UI([string]$m) { [System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'YesNo', 'Question') -eq 'Yes' }

$script:CurrentConfigPath = $DefaultConfigPath
if ($ConfigPath) { $script:CurrentConfigPath = $ConfigPath }
try { $Config = Read-ToolConfig $script:CurrentConfigPath }
catch { Show-Err "Configurazione non leggibile, uso i valori predefiniti.`n$($_.Exception.Message)"; $Config = Get-ToolDefaultConfig }
Initialize-ToolLog $Config

$script:Running = $false
$script:CloseWhenDone = $false
$script:Handle = $null
$script:PS = $null
$script:Runspace = $null
$script:LastDone = $null

$form = New-Object System.Windows.Forms.Form
$form.Text = '{0} {1}' -f $Tool.Title, $Tool.Version
$form.Size = New-Object System.Drawing.Size(1150, 780)
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabCfg = New-Object System.Windows.Forms.TabPage('Configurazione')
$tabPro = New-Object System.Windows.Forms.TabPage($Tool.ItemTab)
$tabLog = New-Object System.Windows.Forms.TabPage('Log')
$tabs.TabPages.AddRange(@($tabCfg, $tabPro, $tabLog))

# ---------------------------------------------------------- scheda Configurazione
$tlp = New-Object System.Windows.Forms.TableLayoutPanel
$tlp.Dock = 'Fill'
$tlp.AutoScroll = $true
$tlp.ColumnCount = 3
$tlp.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 8)
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$tip = New-Object System.Windows.Forms.ToolTip
$Ctl = @{}
$row = 0
foreach ($f in $ToolSchema) {
    if ($f.Type -eq 'Section') {
        $sec = New-Object System.Windows.Forms.Label
        $sec.Text = $f.Label
        $sec.AutoSize = $true
        $sec.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
        $sec.Margin = New-Object System.Windows.Forms.Padding(0, 14, 0, 4)
        $tlp.Controls.Add($sec, 0, $row)
        $tlp.SetColumnSpan($sec, 3)
        $row++
        continue
    }
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $f.Label
    $lbl.AutoSize = $true
    $lbl.Anchor = 'Left'
    $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 6, 12, 3)
    switch ($f.Type) {
        'Int' {
            $c = New-Object System.Windows.Forms.NumericUpDown
            $c.Minimum = [decimal]$f.Min
            $c.Maximum = [decimal]$f.Max
            $c.Width = 140
            $c.Anchor = 'Left'
        }
        'Choice' {
            $c = New-Object System.Windows.Forms.ComboBox
            $c.DropDownStyle = 'DropDownList'
            [void]$c.Items.AddRange([object[]]@($f.Choices))
            $c.Width = 240
            $c.Anchor = 'Left'
        }
        'Bool' {
            $c = New-Object System.Windows.Forms.CheckBox
            $c.AutoSize = $true
            $c.Anchor = 'Left'
        }
        default {
            $c = New-Object System.Windows.Forms.TextBox
            $c.Anchor = 'Left, Right'
        }
    }
    $tlp.Controls.Add($lbl, 0, $row)
    $tlp.Controls.Add($c, 1, $row)
    if ($f.Type -in @('Folder', 'File')) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = 'Sfoglia...'
        $btn.AutoSize = $true
        $btn.Tag = @{ Box = $c; Type = $f.Type; Filter = $f.Filter }
        $btn.Add_Click({
            param($s, $e)
            $t = $s.Tag
            if ($t.Type -eq 'Folder') {
                $d = New-Object System.Windows.Forms.FolderBrowserDialog
                $d.ShowNewFolderButton = $true
                if ($t.Box.Text -and (Test-Path -LiteralPath $t.Box.Text)) { $d.SelectedPath = $t.Box.Text }
                if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.SelectedPath }
            } else {
                $d = New-Object System.Windows.Forms.OpenFileDialog
                if ($t.Filter) { $d.Filter = $t.Filter }
                if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.FileName }
            }
        })
        $tlp.Controls.Add($btn, 2, $row)
    }
    if ($f.Help) { $tip.SetToolTip($lbl, $f.Help); $tip.SetToolTip($c, $f.Help) }
    $row++
    if ($f.Help) {
        $h = New-Object System.Windows.Forms.Label
        $h.Text = $f.Help
        $h.AutoSize = $true
        $h.MaximumSize = New-Object System.Drawing.Size(760, 0)
        $h.ForeColor = [System.Drawing.Color]::DimGray
        $h.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 6)
        $tlp.Controls.Add($h, 1, $row)
        $tlp.SetColumnSpan($h, 2)
        $row++
    }
    $Ctl[$f.Key] = $c
}
$tlp.RowCount = $row + 1

function Set-FormFromConfig($Cfg) {
    foreach ($f in $ToolSchema) {
        if (-not $f.Key) { continue }
        $c = $Ctl[$f.Key]
        $v = $Cfg[$f.Key]
        switch ($f.Type) {
            'Int' { $c.Value = [decimal][math]::Min([math]::Max([double]$v, [double]$f.Min), [double]$f.Max) }
            'Choice' { $c.SelectedItem = [string]$v; if ($c.SelectedIndex -lt 0 -and $c.Items.Count) { $c.SelectedIndex = 0 } }
            'Bool' { $c.Checked = [bool]$v }
            'List' { $c.Text = (@($v) -join '; ') }
            default { $c.Text = [string]$v }
        }
    }
}

function Get-ConfigFromForm {
    $cfg = Get-ToolDefaultConfig
    foreach ($f in $ToolSchema) {
        if (-not $f.Key) { continue }
        $c = $Ctl[$f.Key]
        switch ($f.Type) {
            'Int' { $cfg[$f.Key] = [int]$c.Value }
            'Choice' { $cfg[$f.Key] = [string]$c.SelectedItem }
            'Bool' { $cfg[$f.Key] = [bool]$c.Checked }
            'List' { $cfg[$f.Key] = ConvertTo-ConfigValue $f $c.Text }
            default { $cfg[$f.Key] = $c.Text.Trim() }
        }
    }
    $cfg
}

$cfgBar = New-Object System.Windows.Forms.FlowLayoutPanel
$cfgBar.Dock = 'Bottom'
$cfgBar.AutoSize = $true
$cfgBar.Padding = New-Object System.Windows.Forms.Padding(8)
$btnSave = New-Object System.Windows.Forms.Button; $btnSave.Text = 'Salva'; $btnSave.AutoSize = $true
$btnSaveAs = New-Object System.Windows.Forms.Button; $btnSaveAs.Text = 'Salva come...'; $btnSaveAs.AutoSize = $true
$btnLoad = New-Object System.Windows.Forms.Button; $btnLoad.Text = 'Carica...'; $btnLoad.AutoSize = $true
$btnDefaults = New-Object System.Windows.Forms.Button; $btnDefaults.Text = 'Valori predefiniti'; $btnDefaults.AutoSize = $true
$lblCfg = New-Object System.Windows.Forms.Label; $lblCfg.AutoSize = $true; $lblCfg.Margin = New-Object System.Windows.Forms.Padding(12, 8, 3, 3)
$cfgBar.Controls.AddRange(@($btnSave, $btnSaveAs, $btnLoad, $btnDefaults, $lblCfg))
$tabCfg.Controls.Add($tlp)
$tabCfg.Controls.Add($cfgBar)
$tlp.BringToFront()

function Update-CfgLabel { $lblCfg.Text = "File: $script:CurrentConfigPath" }

$btnSave.Add_Click({
    try { Save-ToolConfig (Get-ConfigFromForm) $script:CurrentConfigPath; Update-CfgLabel; Show-Info "Configurazione salvata in`n$script:CurrentConfigPath" }
    catch { Show-Err "Salvataggio non riuscito: $($_.Exception.Message)" }
})
$btnSaveAs.Add_Click({
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Filter = 'Configurazione (*.json)|*.json'
    $d.InitialDirectory = $ToolDataDir
    $d.FileName = 'config.json'
    if ($d.ShowDialog() -eq 'OK') {
        try { Save-ToolConfig (Get-ConfigFromForm) $d.FileName; $script:CurrentConfigPath = $d.FileName; Update-CfgLabel }
        catch { Show-Err "Salvataggio non riuscito: $($_.Exception.Message)" }
    }
})
$btnLoad.Add_Click({
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Filter = 'Configurazione (*.json)|*.json'
    if (Test-Path -LiteralPath $ToolDataDir) { $d.InitialDirectory = $ToolDataDir }
    if ($d.ShowDialog() -eq 'OK') {
        try { Set-FormFromConfig (Read-ToolConfig $d.FileName); $script:CurrentConfigPath = $d.FileName; Update-CfgLabel }
        catch { Show-Err "Configurazione non valida: $($_.Exception.Message)" }
    }
})
$btnDefaults.Add_Click({ if (Confirm-UI 'Ripristinare i valori predefiniti? Le modifiche non salvate vanno perse.') { Set-FormFromConfig (Get-ToolDefaultConfig) } })

# ---------------------------------------------------------- scheda elementi (analisi e selezione)
$proBar = New-Object System.Windows.Forms.FlowLayoutPanel
$proBar.Dock = 'Top'
$proBar.AutoSize = $true
$proBar.Padding = New-Object System.Windows.Forms.Padding(6)
$btnScan = New-Object System.Windows.Forms.Button; $btnScan.Text = 'Analizza'; $btnScan.AutoSize = $true
$btnAll = New-Object System.Windows.Forms.Button; $btnAll.Text = 'Seleziona tutti'; $btnAll.AutoSize = $true
$btnNone = New-Object System.Windows.Forms.Button; $btnNone.Text = 'Nessuno'; $btnNone.AutoSize = $true
$lblFilter = New-Object System.Windows.Forms.Label; $lblFilter.Text = 'Filtro:'; $lblFilter.AutoSize = $true; $lblFilter.Margin = New-Object System.Windows.Forms.Padding(16, 8, 3, 3)
$txtFilter = New-Object System.Windows.Forms.TextBox; $txtFilter.Width = 220
$lblCount = New-Object System.Windows.Forms.Label; $lblCount.AutoSize = $true; $lblCount.Margin = New-Object System.Windows.Forms.Padding(16, 8, 3, 3)
$proBar.Controls.AddRange(@($btnScan, $btnAll, $btnNone, $lblFilter, $txtFilter, $lblCount))

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'Fill'
$grid.BackgroundColor = [System.Drawing.Color]::White
$colSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colSel.Name = 'Sel'; $colSel.HeaderText = ''; $colSel.Width = 32; $colSel.AutoSizeMode = 'None'
[void]$grid.Columns.Add($colSel)
foreach ($col in $ToolColumns) {
    $gc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $gc.Name = $col.Name; $gc.HeaderText = $col.Header; $gc.ReadOnly = $true; $gc.FillWeight = $col.Weight
    [void]$grid.Columns.Add($gc)
}
$colEsito = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colEsito.Name = 'Esito'; $colEsito.HeaderText = 'Esito'; $colEsito.ReadOnly = $true; $colEsito.FillWeight = 8
[void]$grid.Columns.Add($colEsito)
$tabPro.Controls.Add($grid)
$tabPro.Controls.Add($proBar)
$grid.BringToFront()

function Update-Count {
    $sel = 0; $ok = 0
    foreach ($r in $grid.Rows) { if ($r.Tag.Selectable) { $ok++ }; if ($r.Cells['Sel'].Value -eq $true) { $sel++ } }
    $lblCount.Text = 'Selezionati {0} / {1} migrabili ({2} trovati)' -f $sel, $ok, $grid.Rows.Count
}

function Show-Items($Items) {
    $grid.Rows.Clear()
    foreach ($it in @($Items)) {
        $vals = New-Object System.Collections.Generic.List[object]
        $vals.Add($false)
        foreach ($col in $ToolColumns) { $vals.Add([string]$it.($col.Name)) }
        $vals.Add('')
        $idx = $grid.Rows.Add($vals.ToArray())
        $r = $grid.Rows[$idx]
        $r.Tag = $it
        if (-not $it.Selectable) {
            $r.Cells['Sel'].ReadOnly = $true
            $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Gray
        } elseif ($it.Stato -ne 'Pronto') {
            $r.DefaultCellStyle.ForeColor = [System.Drawing.Color]::DarkOrange
        }
    }
    Update-Count
}

$grid.Add_CurrentCellDirtyStateChanged({ if ($grid.IsCurrentCellDirty) { [void]$grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })
$grid.Add_CellValueChanged({ Update-Count })
$btnAll.Add_Click({
    $grid.EndEdit() | Out-Null
    foreach ($r in $grid.Rows) { if ($r.Visible -and $r.Tag.Selectable) { $r.Cells['Sel'].Value = $true } }
    Update-Count
})
$btnNone.Add_Click({
    $grid.EndEdit() | Out-Null
    foreach ($r in $grid.Rows) { $r.Cells['Sel'].Value = $false }
    Update-Count
})
$txtFilter.Add_TextChanged({
    $q = $txtFilter.Text.Trim()
    $grid.CurrentCell = $null
    foreach ($r in $grid.Rows) {
        if (-not $q) { $r.Visible = $true; continue }
        $hit = $false
        foreach ($cell in $r.Cells) { if ([string]$cell.Value -like "*$q*") { $hit = $true; break } }
        $r.Visible = $hit
    }
})
$btnScan.Add_Click({
    $cfg = Get-ConfigFromForm
    $errs = @(Test-ToolConfig $cfg -Scan)
    if ($errs.Count) { Show-Err ($errs -join "`n"); return }
    $form.UseWaitCursor = $true
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $items = @(Get-ToolItems -Config $cfg)
        Show-Items $items
        Write-ToolLog ('Analisi completata: {0} {1} trovati, {2} elaborabili.' -f $items.Count, $Tool.ItemNoun, @($items | Where-Object { $_.Selectable }).Count) 'OK'
    } catch {
        Write-ToolLog "Analisi non riuscita: $($_.Exception.Message)" 'ERROR'
        Show-Err "Analisi non riuscita:`n$($_.Exception.Message)"
    } finally { $form.UseWaitCursor = $false }
})

# ---------------------------------------------------------- scheda Log
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock = 'Fill'
$logBox.ReadOnly = $true
$logBox.WordWrap = $false
$logBox.BackColor = [System.Drawing.Color]::White
$logBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$tabLog.Controls.Add($logBox)

function Add-LogLine([string]$Text, [string]$Level) {
    $color = switch ($Level) {
        'OK' { [System.Drawing.Color]::DarkGreen }
        'WARN' { [System.Drawing.Color]::DarkOrange }
        'ERROR' { [System.Drawing.Color]::Firebrick }
        'STEP' { [System.Drawing.Color]::RoyalBlue }
        default { [System.Drawing.Color]::Black }
    }
    $logBox.SelectionStart = $logBox.TextLength
    $logBox.SelectionLength = 0
    $logBox.SelectionColor = $color
    $logBox.AppendText($Text + "`r`n")
    $logBox.SelectionColor = $logBox.ForeColor
    $logBox.ScrollToCaret()
}

# ---------------------------------------------------------- barra inferiore
$bottom = New-Object System.Windows.Forms.Panel
$bottom.Dock = 'Bottom'
$bottom.Height = 74
$prog = New-Object System.Windows.Forms.ProgressBar
$prog.Dock = 'Top'
$prog.Height = 16
$runBar = New-Object System.Windows.Forms.FlowLayoutPanel
$runBar.Dock = 'Fill'
$runBar.Padding = New-Object System.Windows.Forms.Padding(6, 6, 6, 0)
$btnStart = New-Object System.Windows.Forms.Button; $btnStart.Text = $Tool.StartLabel; $btnStart.Width = 160; $btnStart.Height = 30
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnCancel = New-Object System.Windows.Forms.Button; $btnCancel.Text = 'Annulla'; $btnCancel.Width = 100; $btnCancel.Height = 30; $btnCancel.Enabled = $false
$btnOpenLog = New-Object System.Windows.Forms.Button; $btnOpenLog.Text = 'Cartella log e report'; $btnOpenLog.AutoSize = $true; $btnOpenLog.Height = 30
$lblStatus = New-Object System.Windows.Forms.Label; $lblStatus.AutoSize = $true; $lblStatus.Margin = New-Object System.Windows.Forms.Padding(12, 9, 3, 3); $lblStatus.Text = 'Pronto.'
$runBar.Controls.AddRange(@($btnStart, $btnCancel, $btnOpenLog, $lblStatus))
$bottom.Controls.Add($runBar)
$bottom.Controls.Add($prog)
$runBar.BringToFront()

$form.Controls.Add($tabs)
$form.Controls.Add($bottom)
$tabs.BringToFront()

function Set-Running([bool]$On) {
    $script:Running = $On
    $btnStart.Enabled = -not $On
    $btnScan.Enabled = -not $On
    $btnCancel.Enabled = $On
    $tlp.Enabled = -not $On
    $cfgBar.Enabled = -not $On
}

function Receive-ToolMessage($Msg) {
    switch ($Msg.T) {
        'log' { Add-LogLine $Msg.M $Msg.L }
        'prog' {
            $prog.Maximum = [math]::Max(1, [int]$Msg.N)
            $prog.Value = [math]::Min([int]$Msg.C, $prog.Maximum)
            $lblStatus.Text = "In corso: $($Msg.M)"
        }
        'row' {
            foreach ($r in $grid.Rows) {
                if ($r.Tag.Key -eq $Msg.K) {
                    $r.Cells['Esito'].Value = $Msg.E
                    $r.Cells['Esito'].Style.ForeColor = switch ($Msg.E) {
                        'OK' { [System.Drawing.Color]::DarkGreen }
                        'Fallito' { [System.Drawing.Color]::Firebrick }
                        'Critico' { [System.Drawing.Color]::Firebrick }
                        'Saltato' { [System.Drawing.Color]::DarkOrange }
                        'Attenzione' { [System.Drawing.Color]::DarkOrange }
                        'Simulato' { [System.Drawing.Color]::RoyalBlue }
                        default { [System.Drawing.Color]::Gray }
                    }
                    break
                }
            }
        }
        'done' { $script:LastDone = $Msg }
    }
}

function Receive-AllMessages {
    $msg = $null
    while ($State.Queue.TryDequeue([ref]$msg)) { Receive-ToolMessage $msg }
}

function Complete-Run {
    $h = $script:Handle
    $script:Handle = $null
    try { [void]$script:PS.EndInvoke($h) } catch { Write-ToolLog "Errore interno: $($_.Exception.Message)" 'ERROR' }
    foreach ($e in @($script:PS.Streams.Error)) { Write-ToolLog "Errore interno: $e" 'ERROR' }
    try { $script:PS.Dispose(); $script:Runspace.Close(); $script:Runspace.Dispose() } catch { }
    Receive-AllMessages
    Set-Running $false
    $prog.Value = $prog.Maximum
    if ($script:LastDone) {
        $lblStatus.Text = $script:LastDone.S
        if (-not $script:CloseWhenDone) {
            $txt = "Operazione terminata.`n`n$($script:LastDone.S)"
            if ($script:LastDone.R) { $txt += "`n`nReport: $($script:LastDone.R)" }
            if ($script:LastDone.F -gt 0) { Show-Err $txt } else { Show-Info $txt }
        }
    } else {
        $lblStatus.Text = 'Terminato con errori: vedere il log.'
    }
    if ($script:CloseWhenDone) { $form.Close() }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    Receive-AllMessages
    if ($script:Handle -and $script:Handle.IsCompleted) { Complete-Run }
})

$btnStart.Add_Click({
    $cfg = Get-ConfigFromForm
    $errs = @(Test-ToolConfig $cfg)
    if ($errs.Count) { Show-Err ($errs -join "`n"); return }
    $grid.EndEdit() | Out-Null
    $items = @(foreach ($r in $grid.Rows) { if ($r.Cells['Sel'].Value -eq $true -and $r.Tag.Selectable) { $r.Tag } })
    if (-not $items.Count) { Show-Info "Nessun elemento selezionato.`nScheda $($Tool.ItemTab): premere Analizza e spuntare $($Tool.ItemNoun) da elaborare."; $tabs.SelectedTab = $tabPro; return }
    $mode = 'ESECUZIONE REALE'
    if ($cfg.DryRun) { $mode = 'SIMULAZIONE (nessuna modifica)' }
    if ($Tool.ReadOnly) { $mode = 'SOLA LETTURA (nessuna modifica)' }
    $msg = "$($Tool.ItemTab) da elaborare: $($items.Count)`n"
    foreach ($k in $Tool.ConfirmKeys) { $msg += "$k : $(@($cfg[$k]) -join '; ')`n" }
    $msg += "`nModalita': $mode`n`nProcedere?"
    if (-not (Confirm-UI $msg)) { return }
    Initialize-ToolLog $cfg
    $State.Cancel = $false
    $script:LastDone = $null
    foreach ($r in $grid.Rows) { $r.Cells['Esito'].Value = '' }
    Set-Running $true
    $tabs.SelectedTab = $tabLog
    $script:Runspace = [runspacefactory]::CreateRunspace()
    $script:Runspace.Open()
    $script:Runspace.SessionStateProxy.SetVariable('Config', $cfg)
    $script:Runspace.SessionStateProxy.SetVariable('Items', $items)
    $script:Runspace.SessionStateProxy.SetVariable('State', $State)
    $script:Runspace.SessionStateProxy.SetVariable('Tool', $Tool)
    $script:PS = [powershell]::Create()
    $script:PS.Runspace = $script:Runspace
    [void]$script:PS.AddScript($Engine.ToString() + "`r`nInvoke-ToolRun -Config `$Config -Items `$Items | Out-Null")
    $script:Handle = $script:PS.BeginInvoke()
})

$btnCancel.Add_Click({
    $State.Cancel = $true
    $btnCancel.Enabled = $false
    Write-ToolLog "Annullamento richiesto: termino l'elemento in corso e mi fermo." 'WARN'
})

$btnOpenLog.Add_Click({ if ($State.LogDir -and (Test-Path -LiteralPath $State.LogDir)) { Start-Process explorer.exe $State.LogDir } })

$form.Add_FormClosing({
    param($s, $e)
    if ($script:Running) {
        $e.Cancel = $true
        if ($script:CloseWhenDone) { return }
        if (Confirm-UI "$($Tool.RunningLabel).`nInterrompere dopo l'elemento in corso e chiudere?$($Tool.CloseWarning)") {
            $State.Cancel = $true
            $script:CloseWhenDone = $true
            $btnCancel.Enabled = $false
            Write-ToolLog "Chiusura richiesta: attendo la fine dell'elemento in corso." 'WARN'
        }
    }
})

$form.Add_Shown({
    Set-FormFromConfig $Config
    Update-CfgLabel
    Update-Count
    Write-ToolLog ('{0} {1} su {2} - log: {3}' -f $Tool.Title, $Tool.Version, $env:COMPUTERNAME, $State.LogFile) 'STEP'
    foreach ($w in @(Get-ToolPrereqIssues $Config)) { Write-ToolLog $w 'WARN' }
    $timer.Start()
})

[void]$form.ShowDialog()
$timer.Stop()
$form.Dispose()
#endregion
