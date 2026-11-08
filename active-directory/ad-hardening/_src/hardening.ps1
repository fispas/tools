    #region SPECIFICO: fase 2 - hardening (azioni con simulazione, backup, verifica)

    $script:RunDir = $null
    $script:HardReady = $false

    # Moduli RSAT e server unico per tutte le operazioni (coerenza tra LDAP, GPO e SYSVOL)
    function Initialize-Hardening($Config) {
        if ($script:HardReady) { return }
        foreach ($m in @('ActiveDirectory', 'GroupPolicy')) {
            if (-not (Get-Module -ListAvailable -Name $m)) { throw "Modulo $m mancante: installare gli strumenti RSAT (Install-WindowsFeature RSAT-AD-PowerShell, GPMC oppure Add-WindowsCapability Rsat.*)." }
        }
        Import-Module ActiveDirectory, GroupPolicy -ErrorAction Stop -Verbose:$false
        $ctx = Get-AdContext $Config
        $global:PSDefaultParameterValues['*-AD*:Server'] = $ctx.Dc
        $global:PSDefaultParameterValues['*-GP*:Server'] = $ctx.Dc
        $global:PSDefaultParameterValues['*-GP*:Domain'] = $ctx.Dns
        $script:HardReady = $true
    }

    function Get-RunDir($Config) {
        if (-not $script:RunDir) {
            $prefix = 'Hardening'
            if ([string]$Config.Mode -eq 'Ripristino') { $prefix = 'Ripristino' }
            $script:RunDir = Join-Path ([string]$Config.OutputDir) ('{0}_{1}_{2}' -f $prefix, (Get-AdContext $Config).Dns, (Get-Date -Format 'yyyyMMdd_HHmmss'))
            New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
        }
        $script:RunDir
    }

    # Stato precedente di ogni modifica, per l'annullamento
    function Save-Backup($Config, [string]$Id, $Data) {
        $f = Join-Path (Get-RunDir $Config) "$Id.backup.json"
        $o = [pscustomobject]@{ Id = $Id; Data = $Data; Date = (Get-Date).ToString('s'); By = "$env:USERDOMAIN\$env:USERNAME"; Dc = (Get-AdContext $Config).Dc }
        [System.IO.File]::WriteAllText($f, ($o | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($true)))
        Write-ToolLog "    backup: $f"
        $f
    }

    function New-Plan([bool]$Ok, [string]$Detail, $Targets = @(), [string]$Plan = '') {
        [pscustomobject]@{ Ok = $Ok; Detail = $Detail; Targets = @($Targets); Plan = $Plan }
    }

    function ConvertTo-LdapValue([string]$s) { $s.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a').Replace([string][char]0, '\00') }

    function Get-DcOu($Config) { (Get-ADDomain).DomainControllersContainer }

    function Test-InList([string]$Name, $List) { @($List | Where-Object { $_ -and $_.Trim() -ieq $Name }).Count -gt 0 }

    # ------------------------------------------------------------------ GPO

    function Get-HardGpoName($Config, [string]$Suffix) { '{0} - {1}' -f [string]$Config.GpoPrefix, $Suffix }

    function Get-HardGpo($Config, [string]$Suffix, [switch]$Create, [string]$Comment) {
        $name = Get-HardGpoName $Config $Suffix
        $g = $null
        try { $g = Get-GPO -Name $name -ErrorAction Stop } catch { $g = $null }
        if (-not $g -and $Create) {
            $g = New-GPO -Name $name -Comment $Comment
            Write-ToolLog "    creata la GPO '$name' ($($g.Id))" 'OK'
            Start-Sleep -Seconds 2
        }
        $g
    }

    function Test-GpoLink($Config, $Gpo, $Targets) {
        if ([string]$Config.GpoLinkMode -eq 'Non collegata') { return $true }
        foreach ($t in @($Targets)) {
            if (-not $t) { continue }
            $l = @((Get-GPInheritance -Target $t).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
            if (-not $l.Count) { return $false }
            if ([string]$Config.GpoLinkMode -eq 'Collegata e attiva' -and -not $l[0].Enabled) { return $false }
        }
        $true
    }

    function Set-GpoLinks($Config, $Gpo, $Targets) {
        $mode = [string]$Config.GpoLinkMode
        if ($mode -eq 'Non collegata') { return 'GPO non collegata (da collegare a mano)' }
        $en = 'No'
        if ($mode -eq 'Collegata e attiva') { $en = 'Yes' }
        $done = @()
        foreach ($t in @($Targets)) {
            if (-not $t) { continue }
            $l = @((Get-GPInheritance -Target $t).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
            if ($l.Count) { Set-GPLink -Guid $Gpo.Id -Target $t -LinkEnabled $en | Out-Null } else { New-GPLink -Guid $Gpo.Id -Target $t -LinkEnabled $en | Out-Null }
            $done += $t
        }
        if (-not $done.Count) { return 'GPO creata senza collegamenti (nessuna OU indicata)' }
        "collegata a: $($done -join '; ') ($mode)"
    }

    function Test-GpoRegistryValue($Gpo, [string]$Key, [string]$Name, $Value) {
        if (-not $Gpo) { return $false }
        try {
            $v = Get-GPRegistryValue -Guid $Gpo.Id -Key $Key -ValueName $Name -ErrorAction Stop
            return ([string]$v.Value -eq [string]$Value)
        } catch { return $false }
    }

    function Get-GpoSysvolPath($Config, $Gpo) {
        $ctx = Get-AdContext $Config
        "\\$($ctx.Dc)\SYSVOL\$($ctx.Dns)\Policies\{$($Gpo.Id)}"
    }

    # Aggiunge un'estensione lato client alla GPO (computer) e incrementa la versione in AD e in GPT.INI
    function Add-GpoMachineExtension($Config, $Gpo, [string]$Cse) {
        $ctx = Get-AdContext $Config
        $de = [adsi]"LDAP://$($ctx.Dc)/CN={$($Gpo.Id)},CN=Policies,CN=System,$($ctx.Dn)"
        $cur = [string]$de.Properties['gPCMachineExtensionNames'].Value
        $parts = @([regex]::Matches($cur, '\[[^\]]+\]') | ForEach-Object { $_.Value })
        if ($parts -notcontains $Cse) { $parts += $Cse }
        $parts = @($parts | Sort-Object { $_.ToUpperInvariant() })
        $de.Properties['gPCMachineExtensionNames'].Value = ($parts -join '')
        $ver = [int]$de.Properties['versionNumber'].Value
        $user = $ver -band 0xFFFF0000
        $machine = (($ver -band 0xFFFF) + 1) -band 0xFFFF
        $new = $user -bor $machine
        $de.Properties['versionNumber'].Value = $new
        $de.CommitChanges()
        $ini = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'GPT.INI'
        $txt = if (Test-Path -LiteralPath $ini) { [System.IO.File]::ReadAllText($ini) } else { "[General]`r`n" }
        if ($txt -match 'Version=\d+') { $txt = $txt -replace 'Version=\d+', "Version=$new" } else { $txt = $txt.TrimEnd() + "`r`nVersion=$new`r`n" }
        [System.IO.File]::WriteAllText($ini, $txt, [System.Text.Encoding]::ASCII)
    }

    $script:CseSecurity = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $script:CseAudit = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

    # Diritti utente (Privilege Rights) in GptTmpl.inf: sostituisce le sezioni gestite, mantiene il resto
    function Set-GpoPrivilegeRights($Config, $Gpo, [hashtable]$Rights) {
        $dir = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $file = Join-Path $dir 'GptTmpl.inf'
        $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
        foreach ($k in ($Rights.Keys | Sort-Object)) { $lines += ('{0} = {1}' -f $k, ((@($Rights[$k]) | ForEach-Object { "*$_" }) -join ',')) }
        [System.IO.File]::WriteAllLines($file, $lines, [System.Text.Encoding]::Unicode)
        Add-GpoMachineExtension $Config $Gpo $script:CseSecurity
    }

    function Get-GpoPrivilegeRights($Config, $Gpo) {
        $h = @{}
        if (-not $Gpo) { return $h }
        $file = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        if (-not (Test-Path -LiteralPath $file)) { return $h }
        $in = $false
        foreach ($l in [System.IO.File]::ReadAllLines($file)) {
            if ($l -match '^\s*\[(.+)\]') { $in = $Matches[1] -eq 'Privilege Rights'; continue }
            if ($in -and $l -match '^\s*(\w+)\s*=\s*(.*)$') { $h[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }) }
        }
        $h
    }

    # Criteri di controllo avanzati (audit.csv)
    $script:AuditBaseline = @(
        , @('Account Logon', 'Audit Credential Validation', '{0cce923f-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Logon', 'Audit Kerberos Authentication Service', '{0cce9242-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Logon', 'Audit Kerberos Service Ticket Operations', '{0cce9240-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Computer Account Management', '{0cce9236-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Other Account Management Events', '{0cce923a-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Security Group Management', '{0cce9237-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit User Account Management', '{0cce9235-69ae-11d9-bed3-505054503030}', 3)
        , @('Detailed Tracking', 'Audit PNP Activity', '{0cce9248-69ae-11d9-bed3-505054503030}', 1)
        , @('Detailed Tracking', 'Audit Process Creation', '{0cce922b-69ae-11d9-bed3-505054503030}', 1)
        , @('DS Access', 'Audit Directory Service Access', '{0cce923b-69ae-11d9-bed3-505054503030}', 3)
        , @('DS Access', 'Audit Directory Service Changes', '{0cce923c-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Account Lockout', '{0cce9217-69ae-11d9-bed3-505054503030}', 2)
        , @('Logon/Logoff', 'Audit Group Membership', '{0cce9249-69ae-11d9-bed3-505054503030}', 1)
        , @('Logon/Logoff', 'Audit Logoff', '{0cce9216-69ae-11d9-bed3-505054503030}', 1)
        , @('Logon/Logoff', 'Audit Logon', '{0cce9215-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Other Logon/Logoff Events', '{0cce921c-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Special Logon', '{0cce921b-69ae-11d9-bed3-505054503030}', 1)
        , @('Object Access', 'Audit Detailed File Share', '{0cce9244-69ae-11d9-bed3-505054503030}', 2)
        , @('Object Access', 'Audit File Share', '{0cce9224-69ae-11d9-bed3-505054503030}', 3)
        , @('Object Access', 'Audit Other Object Access Events', '{0cce9227-69ae-11d9-bed3-505054503030}', 3)
        , @('Object Access', 'Audit Removable Storage', '{0cce9245-69ae-11d9-bed3-505054503030}', 3)
        , @('Policy Change', 'Audit Audit Policy Change', '{0cce922f-69ae-11d9-bed3-505054503030}', 3)
        , @('Policy Change', 'Audit Authentication Policy Change', '{0cce9230-69ae-11d9-bed3-505054503030}', 1)
        , @('Policy Change', 'Audit Authorization Policy Change', '{0cce9231-69ae-11d9-bed3-505054503030}', 1)
        , @('Policy Change', 'Audit MPSSVC Rule-Level Policy Change', '{0cce9232-69ae-11d9-bed3-505054503030}', 3)
        , @('Privilege Use', 'Audit Sensitive Privilege Use', '{0cce9228-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit Other System Events', '{0cce9214-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit Security State Change', '{0cce9210-69ae-11d9-bed3-505054503030}', 1)
        , @('System', 'Audit Security System Extension', '{0cce9211-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit System Integrity', '{0cce9212-69ae-11d9-bed3-505054503030}', 3)
    )

    function Get-AuditCsvPath($Config, $Gpo) { Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\Audit\audit.csv' }

    function Set-GpoAuditBaseline($Config, $Gpo) {
        $file = Get-AuditCsvPath $Config $Gpo
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        $txt = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
        $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
        foreach ($a in $script:AuditBaseline) { $lines += (',System,{0},{1},{2},,{3}' -f $a[1], $a[2], $txt[$a[3]], $a[3]) }
        [System.IO.File]::WriteAllLines($file, $lines, (New-Object System.Text.UTF8Encoding($false)))
        Add-GpoMachineExtension $Config $Gpo $script:CseAudit
    }

    function Test-GpoAuditBaseline($Config, $Gpo) {
        if (-not $Gpo) { return $false }
        $file = Get-AuditCsvPath $Config $Gpo
        if (-not (Test-Path -LiteralPath $file)) { return $false }
        $rows = @(Import-Csv -LiteralPath $file)
        foreach ($a in $script:AuditBaseline) {
            $r = @($rows | Where-Object { $_.'Subcategory GUID' -eq $a[2] })
            if (-not $r.Count -or [int]$r[0].'Setting Value' -ne $a[3]) { return $false }
        }
        $true
    }

    # ------------------------------------------------------------------ account

    function Search-Accounts($Config, [string]$Filter, [string[]]$Props) {
        @(Search-Ldap $Config $Filter (@('sAMAccountName', 'distinguishedName', 'userAccountControl', 'objectSid', 'objectClass') + $Props))
    }

    function Get-EnabledUsersWithFlag($Config, [int]$Flag) {
        Search-Accounts $Config ('(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -f $Flag) @()
    }

    # Imposta o toglie un bit di userAccountControl con backup del valore precedente
    function Set-UacFlag($Config, [string]$Id, $Accounts, [int]$Flag, [bool]$On) {
        $bk = @()
        $n = 0
        foreach ($a in @($Accounts)) {
            $de = [adsi]"LDAP://$((Get-AdContext $Config).Dc)/$(([string]$a.distinguishedName).Replace('/', '\/'))"
            $old = [int]$de.Properties['userAccountControl'].Value
            $new = if ($On) { $old -bor $Flag } else { $old -band (-bnot $Flag) }
            if ($new -eq $old) { continue }
            $bk += [pscustomobject]@{ Account = [string]$a.sAMAccountName; Dn = [string]$a.distinguishedName; OldUac = $old; NewUac = $new }
            $de.Properties['userAccountControl'].Value = $new
            $de.CommitChanges()
            $n++
            Write-ToolLog "    $($a.sAMAccountName): userAccountControl 0x$('{0:X}' -f $old) -> 0x$('{0:X}' -f $new)"
        }
        if ($bk.Count) { [void](Save-Backup $Config $Id $bk) }
        $n
    }

    function Get-PrivilegedEnabled($Config) {
        @(Get-PrivilegedUsers $Config | Where-Object { -not (Test-Uac $_.User 2) } | ForEach-Object { $_.User })
    }

    function Get-RandomPassword([int]$Length = 64) {
        $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%+-=?@_'
        $bytes = New-Object byte[] $Length
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    }

    # ------------------------------------------------------------------ catalogo delle azioni
    # Ogni azione: Id, Cat, Title, Impact (Basso/Medio/Alto), Needs, Undo, Test { param($Config) -> New-Plan }, Apply { param($Config, $Plan) -> messaggio }

    function Get-RegistryActions($Config) {
        $lm = [int]$Config.LmCompatibilityLevel
        $cb = 1
        if ([string]$Config.LdapChannelBinding -eq 'Sempre') { $cb = 2 }
        $logKb = [int]$Config.SecurityLogMaxMB * 1024
        @(
            @{ Id = 'HD-DC-LDAPSIGN'; Title = 'Firma LDAP obbligatoria sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity', 'DWord', 2))
               Undo = 'Rimuovere il valore LDAPServerIntegrity dalla GPO. Prima: verificare negli eventi 2889 del Directory Service i client che usano bind non firmati.' }
            @{ Id = 'HD-DC-LDAPCB'; Title = 'Channel binding LDAPS sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LdapEnforceChannelBinding', 'DWord', $cb))
               Undo = 'Rimuovere LdapEnforceChannelBinding dalla GPO (eventi 3039/3040 per i client non compatibili).' }
            @{ Id = 'HD-DC-SMBSIGN'; Title = 'Firma SMB obbligatoria sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'EnableSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature', 'DWord', 1))
               Undo = 'Rimuovere i valori RequireSecuritySignature/EnableSecuritySignature dalla GPO.' }
            @{ Id = 'HD-DC-SMB1'; Title = 'SMBv1 disattivato sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'SMB1', 'DWord', 0))
               Undo = 'Rimuovere il valore SMB1 dalla GPO.' }
            @{ Id = 'HD-DC-NTLM'; Title = "Solo NTLMv2 sui DC (LmCompatibilityLevel $lm)"; Impact = 'Alto'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 'DWord', $lm))
               Undo = 'Rimuovere LmCompatibilityLevel dalla GPO. Prima: verificare con l''audit NTLM (evento 4624, Package Name NTLM V1) che nessun client usi LM/NTLMv1.' }
            @{ Id = 'HD-DC-SPOOLER'; Title = 'Print Spooler disattivato sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\Spooler', 'Start', 'DWord', 4))
               Undo = 'Rimuovere il valore Start del servizio Spooler dalla GPO e riavviare il servizio sui DC.' }
            @{ Id = 'HD-DC-LSAPPL'; Title = 'Protezione LSA (RunAsPPL) sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 'DWord', 1))
               Undo = 'Rimuovere RunAsPPL dalla GPO e riavviare (verificare prima i plugin LSA di terze parti, eventi 3065/3066).' }
            @{ Id = 'HD-DC-WDIGEST'; Title = 'WDigest senza password in memoria sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 'DWord', 0))
               Undo = 'Rimuovere UseLogonCredential dalla GPO.' }
            @{ Id = 'HD-DC-LOGS'; Title = "Registri di sicurezza e PowerShell sui DC (Security $($Config.SecurityLogMaxMB) MB)"; Impact = 'Basso'; Gpo = 'DC Audit'; Scope = 'DC'
               Values = @(@('HKLM\Software\Policies\Microsoft\Windows\EventLog\Security', 'MaxSize', 'DWord', $logKb), @('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled', 'DWord', 1), @('HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO DC Audit.' }
            @{ Id = 'HD-DC-NTLMAUDIT'; Title = 'Audit dell''uso di NTLM sui DC (prima di restringerlo)'; Impact = 'Basso'; Gpo = 'DC Audit'; Scope = 'DC'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'AuditNTLMInDomain', 'DWord', 7), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 'DWord', 2))
               Undo = 'Rimuovere i valori dalla GPO DC Audit. Eventi in Applicazioni e servizi > Microsoft > Windows > NTLM > Operational (8001-8004).' }
            @{ Id = 'HD-MB-NTLMAUDIT'; Title = 'Audit dell''uso di NTLM su server e client'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 'DWord', 2), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictSendingNTLMTraffic', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO Member Hardening.' }
            @{ Id = 'HD-MB-CREDGUARD'; Title = 'Credential Guard su server e client (senza blocco UEFI)'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'EnableVirtualizationBasedSecurity', 'DWord', 1), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'RequirePlatformSecurityFeatures', 'DWord', 1), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'LsaCfgFlags', 'DWord', 2))
               Undo = 'Rimuovere i valori dalla GPO e riavviare. Richiede UEFI, Secure Boot e virtualizzazione; non usare sui DC. Incompatibile con delega non vincolata, NTLMv1, DES.' }
            @{ Id = 'HD-MB-RCG'; Title = 'Remote Credential Guard / Restricted Admin per RDP'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowProtectedCreds', 'DWord', 1))
               Undo = 'Rimuovere AllowProtectedCreds dalla GPO. Uso: mstsc /remoteGuard dai PC amministrativi.' }
            @{ Id = 'HD-MB-SMB1'; Title = 'SMBv1 disattivato su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'SMB1', 'DWord', 0), @('HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start', 'DWord', 4))
               Undo = 'Rimuovere i valori dalla GPO Member Hardening (verificare prima stampanti/NAS che usano SMBv1).' }
            @{ Id = 'HD-MB-WDIGEST'; Title = 'WDigest senza password in memoria su server e client'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 'DWord', 0))
               Undo = 'Rimuovere UseLogonCredential dalla GPO.' }
            @{ Id = 'HD-MB-LSAPPL'; Title = 'Protezione LSA (RunAsPPL) su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 'DWord', 1))
               Undo = 'Rimuovere RunAsPPL dalla GPO e riavviare.' }
            @{ Id = 'HD-MB-NTLM'; Title = "Solo NTLMv2 su server e client (LmCompatibilityLevel $lm)"; Impact = 'Alto'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 'DWord', $lm))
               Undo = 'Rimuovere LmCompatibilityLevel dalla GPO.' }
            @{ Id = 'HD-MB-SMBSIGN'; Title = 'Firma SMB obbligatoria su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO (verificare prima NAS e dispositivi senza firma SMB).' }
        )
    }

    function Get-RegistryActionTargets($Config, $A) {
        if ($A.Scope -eq 'DC') { return @(Get-DcOu $Config) }
        @($Config.MemberHardeningOus | Where-Object { $_ })
    }

    function New-RegistryAction($A) {
        $act = @{ Id = $A.Id; Cat = 'GPO di hardening'; Title = $A.Title; Impact = $A.Impact; Needs = 'Domain Admins'; Undo = $A.Undo; Def = $A }
        $act.Test = {
            param($Config, $Act)
            $a = $Act.Def
            $g = Get-HardGpo $Config $a.Gpo
            $missing = @($a.Values | Where-Object { -not (Test-GpoRegistryValue $g $_[0] $_[1] $_[3]) })
            $targets = @(Get-RegistryActionTargets $Config $a)
            if ($a.Scope -eq 'Member' -and -not $targets.Count) { return New-Plan $true 'Non applicabile: nessuna OU indicata in "OU per server e client"' }
            $linked = $g -and (Test-GpoLink $Config $g $targets)
            $plan = "GPO '$(Get-HardGpoName $Config $a.Gpo)': " + ((@($a.Values) | ForEach-Object { "$($_[0])\$($_[1]) = $($_[3])" }) -join '; ')
            if (-not $missing.Count -and $linked) { return New-Plan $true 'Impostazioni presenti nella GPO e collegamento attivo' }
            New-Plan $false ("Da impostare: $($missing.Count) valori" + $(if (-not $linked) { ', collegamento mancante o disattivato' } else { '' })) $targets $plan
        }
        $act.Apply = {
            param($Config, $Act, $Plan)
            $a = $Act.Def
            $g = Get-HardGpo $Config $a.Gpo -Create -Comment 'FispaTools ad-hardening: impostazioni di sicurezza (vedi report)'
            $bk = @()
            foreach ($v in $a.Values) {
                $old = $null
                try { $old = (Get-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -ErrorAction Stop).Value } catch { }
                $bk += [pscustomobject]@{ Gpo = $g.DisplayName; Key = $v[0]; Name = $v[1]; Old = $old; New = $v[3] }
                Set-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -Type $v[2] -Value $v[3] | Out-Null
            }
            [void](Save-Backup $Config $a.Id $bk)
            $link = Set-GpoLinks $Config $g (Get-RegistryActionTargets $Config $a)
            $msg = "Impostati $($a.Values.Count) valori; $link"
            if ($a.Id -eq 'HD-DC-SPOOLER' -and $Config.StopSpoolerNow) {
                foreach ($d in @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))) {
                    try {
                        $s = Get-CimInstance -ComputerName $d.dNSHostName -ClassName Win32_Service -Filter "Name='Spooler'" -OperationTimeoutSec 30 -ErrorAction Stop
                        [void](Invoke-CimMethod -InputObject $s -MethodName ChangeStartMode -Arguments @{ StartMode = 'Disabled' })
                        [void](Invoke-CimMethod -InputObject $s -MethodName StopService)
                        Write-ToolLog "    Spooler fermato su $($d.dNSHostName)" 'OK'
                    } catch { Write-ToolLog "    Spooler non fermato su $($d.dNSHostName): $($_.Exception.Message)" 'WARN' }
                }
            }
            $msg
        }
        $act
    }

    function Get-HardeningActions($Config) {
        $list = New-Object System.Collections.Generic.List[object]

        # ---------------------------------------------------------- dominio e foresta
        $list.Add(@{ Id = 'HD-BIN'; Cat = 'Dominio'; Title = 'Attiva il cestino di Active Directory'; Impact = 'Basso'; Needs = 'Enterprise Admins'
            Undo = 'Irreversibile (e'' un''opzione della foresta senza effetti negativi).'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $f = Get-LdapObject $Config "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ctx.ConfigDn)" @('msDS-EnabledFeatureBL')
                if ($f -and $f.'msDS-EnabledFeatureBL') { return New-Plan $true 'Cestino gia'' attivo' }
                if ($ctx.ForestFL -lt 4) { return New-Plan $true 'Non applicabile: livello funzionale della foresta inferiore a 2008 R2' }
                New-Plan $false 'Cestino non attivo' @() 'Enable-ADOptionalFeature "Recycle Bin Feature" sulla foresta'
            }
            Apply = { param($Config, $Act, $Plan)
                Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false
                'Cestino AD attivato'
            } })

        $list.Add(@{ Id = 'HD-MAQ'; Cat = 'Dominio'; Title = 'MachineAccountQuota a 0 (gli utenti non aggiungono computer al dominio)'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Ripristinare ms-DS-MachineAccountQuota al valore nel backup. Per i join usare un gruppo delegato sull''OU dei computer.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $v = [int](Get-LdapObject $Config $ctx.Dn @('ms-DS-MachineAccountQuota')).'ms-DS-MachineAccountQuota'
                if ($v -eq 0) { return New-Plan $true 'Gia'' a 0' }
                New-Plan $false "Valore attuale $v" @($v) 'ms-DS-MachineAccountQuota = 0 sull''oggetto dominio'
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$($ctx.Dn)"
                [void](Save-Backup $Config $Act.Id @{ Old = [int]$de.Properties['ms-DS-MachineAccountQuota'].Value })
                $de.Properties['ms-DS-MachineAccountQuota'].Value = 0
                $de.CommitChanges()
                'MachineAccountQuota impostato a 0'
            } })

        $list.Add(@{ Id = 'HD-PRE2K'; Cat = 'Dominio'; Title = 'Togli Anonymous ed Everyone da "Accesso compatibile pre-Windows 2000"'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riaggiungere i membri elencati nel backup al gruppo S-1-5-32-554.'
            Test = { param($Config, $Act)
                $g = Get-LdapObject $Config (Get-SidDn $Config 'S-1-5-32-554') @('member', 'distinguishedName')
                $bad = @(@($g.member) | Where-Object { $_ -match '^CN=(S-1-5-7|S-1-1-0),' })
                if (-not $bad.Count) { return New-Plan $true 'Ne'' Anonymous Logon ne'' Everyone sono membri' }
                New-Plan $false "$($bad.Count) membri da togliere" $bad ('Rimuovere: ' + ($bad -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config 'S-1-5-32-554').Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Group = 'S-1-5-32-554'; Removed = @($Plan.Targets) })
                foreach ($m in $Plan.Targets) { [void]$de.Properties['member'].Remove([string]$m) }
                $de.CommitChanges()
                "Rimossi $($Plan.Targets.Count) membri"
            } })

        $list.Add(@{ Id = 'HD-KDS'; Cat = 'Dominio'; Title = 'Crea la KDS root key (necessaria ai gMSA)'; Impact = 'Basso'; Needs = 'Domain Admins (dominio radice)'
            Undo = 'Nessuno necessario.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $k = @(Search-Ldap $Config '(objectClass=msKds-ProvRootKey)' @('cn') "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($ctx.ConfigDn)" 'OneLevel')
                if ($k.Count) { return New-Plan $true "$($k.Count) KDS root key presenti" }
                New-Plan $false 'Nessuna KDS root key' @() 'Add-KdsRootKey -EffectiveImmediately (utilizzabile dopo 10 ore)'
            }
            Apply = { param($Config, $Act, $Plan)
                [void](Add-KdsRootKey -EffectiveImmediately)
                'KDS root key creata: i gMSA si possono creare tra 10 ore (replica tra i DC)'
            } })

        $list.Add(@{ Id = 'HD-PWDPOL'; Cat = 'Dominio'; Title = "Policy password di dominio (minimo $($Config.DomainMinPasswordLength) caratteri, blocco dopo $($Config.DomainLockoutThreshold) errori)"; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Set-ADDefaultDomainPasswordPolicy con i valori del backup. I nuovi requisiti valgono al prossimo cambio password di ogni utente.'
            Test = { param($Config, $Act)
                $p = Get-ADDefaultDomainPasswordPolicy
                $iss = @()
                if ($p.MinPasswordLength -lt [int]$Config.DomainMinPasswordLength) { $iss += "lunghezza minima $($p.MinPasswordLength)" }
                if (-not $p.ComplexityEnabled) { $iss += 'complessita'' disattivata' }
                if ($p.ReversibleEncryptionEnabled) { $iss += 'cifratura reversibile' }
                if ($p.LockoutThreshold -eq 0 -or $p.LockoutThreshold -gt [int]$Config.DomainLockoutThreshold) { $iss += "soglia di blocco $($p.LockoutThreshold)" }
                if (-not $iss.Count) { return New-Plan $true 'Policy conforme' }
                New-Plan $false ($iss -join ', ') @() ("Minimo $($Config.DomainMinPasswordLength) caratteri, complessita'', niente cifratura reversibile, blocco dopo $($Config.DomainLockoutThreshold) errori per $($Config.DomainLockoutMinutes) minuti")
            }
            Apply = { param($Config, $Act, $Plan)
                $p = Get-ADDefaultDomainPasswordPolicy
                [void](Save-Backup $Config $Act.Id ($p | Select-Object MinPasswordLength, ComplexityEnabled, ReversibleEncryptionEnabled, LockoutThreshold, @{ n = 'LockoutDuration'; e = { $_.LockoutDuration.ToString() } }, @{ n = 'LockoutObservationWindow'; e = { $_.LockoutObservationWindow.ToString() } }, @{ n = 'MaxPasswordAge'; e = { $_.MaxPasswordAge.ToString() } }, PasswordHistoryCount))
                $min = [TimeSpan]::FromMinutes([int]$Config.DomainLockoutMinutes)
                $len = [math]::Max([int]$p.MinPasswordLength, [int]$Config.DomainMinPasswordLength)
                Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength $len -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -LockoutThreshold ([int]$Config.DomainLockoutThreshold) -LockoutDuration $min -LockoutObservationWindow $min -PasswordHistoryCount ([math]::Max([int]$p.PasswordHistoryCount, 24))
                'Policy password di dominio aggiornata'
            } })

        # ---------------------------------------------------------- account privilegiati
        $list.Add(@{ Id = 'HD-SCHEMA'; Cat = 'Account privilegiati'; Title = 'Svuota Schema Admins (da riempire solo per le modifiche allo schema)'; Impact = 'Medio'; Needs = 'Enterprise Admins'
            Undo = 'Riaggiungere i membri elencati nel backup.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $g = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-518") @('member')
                $m = @($g.member | Where-Object { $_ })
                if (-not $m.Count) { return New-Plan $true 'Schema Admins vuoto' }
                New-Plan $false "$($m.Count) membri" $m ('Rimuovere: ' + ($m -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-518").Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Group = 'Schema Admins'; Removed = @($Plan.Targets) })
                foreach ($m in $Plan.Targets) { [void]$de.Properties['member'].Remove([string]$m) }
                $de.CommitChanges()
                "Rimossi $($Plan.Targets.Count) membri da Schema Admins"
            } })

        $list.Add(@{ Id = 'HD-SENSITIVE'; Cat = 'Account privilegiati'; Title = 'Account privilegiati "sensibili e non delegabili"'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Togliere il flag NOT_DELEGATED (0x100000) dagli account del backup.'
            Test = { param($Config, $Act)
                $t = @(Get-PrivilegedEnabled $Config | Where-Object { -not (Test-Uac $_ 0x100000) -and -not $_.servicePrincipalName })
                if (-not $t.Count) { return New-Plan $true 'Tutti gli account privilegiati attivi sono gia'' non delegabili' }
                New-Plan $false "$($t.Count) account delegabili" $t ('Impostare NOT_DELEGATED su: ' + (($t | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan) "Aggiornati $(Set-UacFlag $Config $Act.Id $Plan.Targets 0x100000 $true) account" } })

        $list.Add(@{ Id = 'HD-PROTUSERS'; Cat = 'Account privilegiati'; Title = 'Account amministrativi in Protected Users'; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Togliere dal gruppo Protected Users gli account del backup. Effetti: niente NTLM, delega, DES/RC4, credenziali in cache, ticket di 4 ore.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $pu = Get-SidDn $Config "$($ctx.Sid)-525"
                if (-not $pu) { return New-Plan $true 'Non applicabile: gruppo Protected Users assente (serve un PDC 2012 R2+)' }
                $in = @(Get-GroupMembersRecursive $Config $pu | ForEach-Object { [string]$_.distinguishedName })
                $cand = if ([string]$Config.ProtectedUsersMode -eq 'Tutti gli account privilegiati') {
                    @(Get-PrivilegedEnabled $Config | Where-Object { -not $_.servicePrincipalName })
                } else {
                    @(foreach ($n in @($Config.ProtectedUsersList | Where-Object { $_ })) { Search-Accounts $Config ('(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))' -f (ConvertTo-LdapValue $n.Trim())) @('servicePrincipalName') })
                }
                $t = @($cand | Where-Object { $in -notcontains [string]$_.distinguishedName -and -not (Test-InList ([string]$_.sAMAccountName) $Config.BreakGlassAccounts) -and -not ((Get-ObjSid $_) -like '*-500') })
                if (-not $t.Count) { return New-Plan $true 'Nessun account da aggiungere (elenco vuoto o gia'' presenti)' }
                New-Plan $false "$($t.Count) account da aggiungere" $t ('Aggiungere: ' + (($t | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-525").Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Added = @($Plan.Targets | ForEach-Object { [string]$_.distinguishedName }) })
                foreach ($u in $Plan.Targets) { [void]$de.Properties['member'].Add([string]$u.distinguishedName) }
                $de.CommitChanges()
                "Aggiunti $($Plan.Targets.Count) account a Protected Users (vale dal prossimo logon)"
            } })

        $list.Add(@{ Id = 'HD-ADMINPSO'; Cat = 'Account privilegiati'; Title = "Policy password dedicata agli admin (PSO, minimo $($Config.AdminPsoMinLength) caratteri)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Remove-ADFineGrainedPasswordPolicy con il nome indicato nel backup.'
            Test = { param($Config, $Act)
                $name = "$($Config.GpoPrefix)-Admins"
                $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
                $ctx = Get-AdContext $Config
                $groups = @(@("$($ctx.Sid)-512", "$($ctx.Sid)-519", "$($ctx.Sid)-518") | ForEach-Object { Get-SidDn $Config $_ } | Where-Object { $_ })
                $missing = $groups
                if ($pso) {
                    $subj = @(Get-ADFineGrainedPasswordPolicySubject -Identity $pso | ForEach-Object { $_.DistinguishedName })
                    $missing = @($groups | Where-Object { $subj -notcontains $_ })
                    if (-not $missing.Count -and $pso.MinPasswordLength -ge [int]$Config.AdminPsoMinLength) { return New-Plan $true "PSO $name presente e applicata" }
                }
                New-Plan $false "PSO $name assente o incompleta" $missing "PSO $name (precedenza 10, minimo $($Config.AdminPsoMinLength) caratteri, blocco dopo 5 errori) su Domain Admins, Enterprise Admins, Schema Admins"
            }
            Apply = { param($Config, $Act, $Plan)
                $name = "$($Config.GpoPrefix)-Admins"
                $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
                $min = [TimeSpan]::FromMinutes([int]$Config.DomainLockoutMinutes)
                if (-not $pso) {
                    New-ADFineGrainedPasswordPolicy -Name $name -Precedence 10 -MinPasswordLength ([int]$Config.AdminPsoMinLength) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -PasswordHistoryCount 24 -LockoutThreshold 5 -LockoutDuration $min -LockoutObservationWindow $min -MaxPasswordAge ([TimeSpan]::FromDays([int]$Config.AdminPsoMaxAgeDays)) -MinPasswordAge ([TimeSpan]::FromDays(1)) -Description 'FispaTools ad-hardening: password degli amministratori'
                    $pso = Get-ADFineGrainedPasswordPolicy -Identity $name
                } else { Set-ADFineGrainedPasswordPolicy -Identity $pso -MinPasswordLength ([int]$Config.AdminPsoMinLength) }
                [void](Save-Backup $Config $Act.Id @{ Pso = $name })
                if ($Plan.Targets.Count) { Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects @($Plan.Targets) }
                "PSO $name aggiornata, applicata a $($Plan.Targets.Count) nuovi gruppi"
            } })

        $list.Add(@{ Id = 'HD-ADMINCOUNT'; Cat = 'Account privilegiati'; Title = 'Azzera adminCount orfani e ripristina l''ereditarieta'' delle ACL'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Reimpostare adminCount=1 sugli account del backup (le ACL ereditate restano).'
            Test = { param($Config, $Act)
                $priv = @(Get-PrivilegedUsers $Config | ForEach-Object { [string]$_.User.distinguishedName })
                $o = @(Search-Accounts $Config '(&(objectCategory=person)(objectClass=user)(adminCount=1))' @() | Where-Object { $priv -notcontains [string]$_.distinguishedName -and (Get-ObjSid $_) -notlike '*-502' })
                if (-not $o.Count) { return New-Plan $true 'Nessun adminCount orfano' }
                New-Plan $false "$($o.Count) account" $o ('Azzerare adminCount e riattivare l''ereditarieta'' su: ' + (($o | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                [void](Save-Backup $Config $Act.Id @(@($Plan.Targets) | ForEach-Object { [string]$_.distinguishedName }))
                foreach ($u in $Plan.Targets) {
                    $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$u.distinguishedName).Replace('/', '\/'))"
                    $de.Properties['adminCount'].Clear()
                    $sec = $de.psbase.ObjectSecurity
                    $sec.SetAccessRuleProtection($false, $true)
                    $de.psbase.ObjectSecurity = $sec
                    $de.CommitChanges()
                }
                "Sistemati $($Plan.Targets.Count) account"
            } })

        $list.Add(@{ Id = 'HD-KRBTGT'; Cat = 'Account privilegiati'; Title = 'Rotazione della password di krbtgt (due passaggi distanziati)'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Nessuno: e'' una rotazione. Il secondo passaggio va eseguito dopo l''intervallo configurato e la replica completa.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $k = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-502") @('pwdLastSet')
                $last = ConvertFrom-FileTime $k.pwdLastSet
                $age = [math]::Floor(($ctx.Now - $last).TotalDays)
                $state = Get-KrbtgtState
                $hours = ($ctx.Now - $last).TotalHours
                if ($state.Pending -and $hours -ge [int]$Config.KrbtgtMinHours) { return New-Plan $false "Primo passaggio eseguito $([math]::Floor($hours)) ore fa: manca il secondo" @() 'Secondo reset della password di krbtgt' }
                if ($state.Pending) { return New-Plan $true "Primo passaggio eseguito $([math]::Floor($hours)) ore fa: secondo passaggio dopo $($Config.KrbtgtMinHours) ore" }
                if ($age -le [int]$Config.KrbtgtMaxDays) { return New-Plan $true "Password cambiata $age giorni fa" }
                New-Plan $false "Password cambiata $age giorni fa" @() 'Primo reset della password di krbtgt (rigenerata dal sistema), poi secondo reset dopo l''intervallo configurato'
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $dn = Get-SidDn $Config "$($ctx.Sid)-502"
                # tutti i DC devono avere la stessa versione della password prima di ruotare di nuovo
                $vals = @()
                foreach ($d in @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))) {
                    try { $vals += [string]([adsi]"LDAP://$($d.dNSHostName)/$dn").Properties['pwdLastSet'].Value } catch { throw "DC $($d.dNSHostName) non raggiungibile: rotazione annullata (serve la replica su tutti i DC)." }
                }
                if (@($vals | Select-Object -Unique).Count -gt 1) { throw 'La password di krbtgt non e'' ancora replicata su tutti i DC: attendere e riprovare.' }
                $state = Get-KrbtgtState
                Set-ADAccountPassword -Identity $dn -Reset -NewPassword (ConvertTo-SecureString (Get-RandomPassword 64) -AsPlainText -Force)
                $pending = -not $state.Pending
                Save-KrbtgtState $pending
                if ($pending) { return "Primo passaggio eseguito: ripetere questa azione dopo almeno $($Config.KrbtgtMinHours) ore" }
                'Secondo passaggio eseguito: rotazione di krbtgt completata'
            } })

        # ---------------------------------------------------------- account
        $flags = @(
            @{ Id = 'HD-ASREP'; Flag = 0x400000; Title = 'Richiedi la preautenticazione Kerberos (AS-REP roasting)'; Impact = 'Basso'; Undo = 'Riattivare DONT_REQ_PREAUTH (0x400000) sugli account del backup.' }
            @{ Id = 'HD-DES'; Flag = 0x200000; Title = 'Togli "Usa solo crittografia DES"'; Impact = 'Basso'; Undo = 'Riattivare USE_DES_KEY_ONLY (0x200000) sugli account del backup.' }
            @{ Id = 'HD-REVERSIBLE'; Flag = 0x80; Title = 'Togli la cifratura reversibile delle password'; Impact = 'Basso'; Undo = 'Riattivare ENCRYPTED_TEXT_PWD_ALLOWED (0x80). La copia reversibile sparisce al prossimo cambio password.' }
            @{ Id = 'HD-PWDNOTREQD'; Flag = 0x20; Title = 'Togli "password non obbligatoria"'; Impact = 'Basso'; Undo = 'Riattivare PASSWD_NOTREQD (0x20) sugli account del backup.' }
        )
        foreach ($f in $flags) {
            $list.Add(@{ Id = $f.Id; Cat = 'Account'; Title = $f.Title; Impact = $f.Impact; Needs = 'Domain Admins'; Undo = $f.Undo; Flag = $f.Flag
                Test = { param($Config, $Act)
                    $t = @(Get-EnabledUsersWithFlag $Config $Act.Flag)
                    if (-not $t.Count) { return New-Plan $true 'Nessun account attivo con questa impostazione' }
                    New-Plan $false "$($t.Count) account" $t ('Account: ' + (($t | Select-Object -First 50 | ForEach-Object { $_.sAMAccountName }) -join ', '))
                }
                Apply = { param($Config, $Act, $Plan) "Aggiornati $(Set-UacFlag $Config $Act.Id $Plan.Targets $Act.Flag $false) account" } })
        }

        $list.Add(@{ Id = 'HD-GUEST'; Cat = 'Account'; Title = 'Disattiva l''account Guest'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Riattivare l''account Guest.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $g = @(Search-Accounts $Config ('(objectSid={0}-501)' -f $ctx.Sid) @())
                if (-not $g.Count -or (Test-Uac $g[0] 2)) { return New-Plan $true 'Guest disattivato' }
                New-Plan $false 'Guest attivo' $g 'Disattivare Guest'
            }
            Apply = { param($Config, $Act, $Plan) "Disattivato ($(Set-UacFlag $Config $Act.Id $Plan.Targets 2 $true) account)" } })

        $list.Add(@{ Id = 'HD-INACTIVE-USERS'; Cat = 'Account'; Title = "Disattiva gli utenti inattivi da oltre $($Config.InactiveDays) giorni"; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riattivare (e riportare nell''OU d''origine) gli account del backup: Enable-ADAccount.'
            Test = { param($Config, $Act) Get-InactivePlan $Config $false }
            Apply = { param($Config, $Act, $Plan) Disable-Inactive $Config $Act.Id $Plan.Targets } })

        $list.Add(@{ Id = 'HD-INACTIVE-COMPUTERS'; Cat = 'Account'; Title = "Disattiva i computer inattivi da oltre $($Config.InactiveDays) giorni"; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riattivare (e riportare nell''OU d''origine) i computer del backup.'
            Test = { param($Config, $Act) Get-InactivePlan $Config $true }
            Apply = { param($Config, $Act, $Plan) Disable-Inactive $Config $Act.Id $Plan.Targets } })

        # ---------------------------------------------------------- LAPS
        $list.Add(@{ Id = 'HD-LAPS-SCHEMA'; Cat = 'LAPS'; Title = 'Windows LAPS: estensione dello schema'; Impact = 'Basso'; Needs = 'Schema Admins'
            Undo = 'Irreversibile (estensione dello schema).'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $a = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-Password)' @('cn') $ctx.SchemaDn 'OneLevel')
                if ($a.Count) { return New-Plan $true 'Schema gia'' esteso per Windows LAPS' }
                if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) { return New-Plan $true 'Non applicabile qui: modulo LAPS assente (Windows Server 2019+ aggiornato, o RSAT recenti)' }
                New-Plan $false 'Attributi msLAPS-* assenti' @() 'Update-LapsADSchema'
            }
            Apply = { param($Config, $Act, $Plan) Update-LapsADSchema -Confirm:$false; 'Schema esteso per Windows LAPS' } })

        $list.Add(@{ Id = 'HD-LAPS-PERM'; Cat = 'LAPS'; Title = 'Windows LAPS: permesso dei computer di scrivere la propria password'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Rimuovere dall''OU l''ACE di SELF sugli attributi msLAPS-*.'
            Test = { param($Config, $Act)
                $ous = @($Config.LapsOus | Where-Object { $_ })
                if (-not $ous.Count) { return New-Plan $true 'Nessuna OU indicata in LapsOus' }
                if (-not (Get-Command Set-LapsADComputerSelfPermission -ErrorAction SilentlyContinue)) { return New-Plan $true 'Non applicabile qui: modulo LAPS assente' }
                $missing = @($ous | Where-Object { -not (Test-LapsSelfPermission $Config $_) })
                if (-not $missing.Count) { return New-Plan $true 'Permessi presenti su tutte le OU' }
                New-Plan $false "$($missing.Count) OU senza permesso" $missing ('Set-LapsADComputerSelfPermission su: ' + ($missing -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                foreach ($ou in $Plan.Targets) { [void](Set-LapsADComputerSelfPermission -Identity $ou) }
                [void](Save-Backup $Config $Act.Id @{ Ous = @($Plan.Targets) })
                "Permessi impostati su $($Plan.Targets.Count) OU"
            } })

        $list.Add(@{ Id = 'HD-LAPS-GPO'; Cat = 'LAPS'; Title = "Windows LAPS: GPO (password $($Config.LapsPasswordLength) caratteri, rotazione $($Config.LapsPasswordAgeDays) giorni)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Scollegare o eliminare la GPO Windows LAPS (le password restano quelle correnti).'
            Test = { param($Config, $Act)
                $ous = @($Config.LapsOus | Where-Object { $_ })
                if (-not $ous.Count) { return New-Plan $true 'Nessuna OU indicata in LapsOus' }
                $g = Get-HardGpo $Config 'Windows LAPS'
                $vals = Get-LapsValues $Config
                $missing = @($vals | Where-Object { -not (Test-GpoRegistryValue $g $_[0] $_[1] $_[3]) })
                if (-not $missing.Count -and (Test-GpoLink $Config $g $ous)) { return New-Plan $true 'GPO Windows LAPS presente e collegata' }
                New-Plan $false 'GPO assente, incompleta o non collegata' $ous ("GPO '$(Get-HardGpoName $Config 'Windows LAPS')' su: " + ($ous -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $g = Get-HardGpo $Config 'Windows LAPS' -Create -Comment 'FispaTools ad-hardening: Windows LAPS'
                foreach ($v in (Get-LapsValues $Config)) { Set-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -Type $v[2] -Value $v[3] | Out-Null }
                [void](Save-Backup $Config $Act.Id @{ Gpo = $g.DisplayName })
                Set-GpoLinks $Config $g $Plan.Targets
            } })

        # ---------------------------------------------------------- GPO di hardening (registro) e audit
        foreach ($a in (Get-RegistryActions $Config)) { $list.Add((New-RegistryAction $a)) }

        $list.Add(@{ Id = 'HD-DC-AUDIT'; Cat = 'GPO di hardening'; Title = 'Criteri di controllo avanzati sui DC (baseline Microsoft)'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Eliminare audit.csv dalla GPO DC Audit o scollegarla.'
            Test = { param($Config, $Act)
                $g = Get-HardGpo $Config 'DC Audit'
                if ((Test-GpoAuditBaseline $Config $g) -and (Test-GpoLink $Config $g @(Get-DcOu $Config))) { return New-Plan $true 'Baseline di audit presente e collegata ai DC' }
                New-Plan $false 'Baseline di audit assente o non collegata' @(Get-DcOu $Config) "GPO '$(Get-HardGpoName $Config 'DC Audit')' con $($script:AuditBaseline.Count) sottocategorie (account, Kerberos, gruppi, processi, DS, logon, policy, privilegi, sistema)"
            }
            Apply = { param($Config, $Act, $Plan)
                $g = Get-HardGpo $Config 'DC Audit' -Create -Comment 'FispaTools ad-hardening: criteri di controllo avanzati'
                Set-GpoAuditBaseline $Config $g
                Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 | Out-Null
                [void](Save-Backup $Config $Act.Id @{ Gpo = $g.DisplayName; Subcategories = $script:AuditBaseline.Count })
                'Baseline di audit scritta; ' + (Set-GpoLinks $Config $g $Plan.Targets)
            } })

        # ---------------------------------------------------------- tier model
        $list.Add(@{ Id = 'HD-TIER-OU'; Cat = 'Tier model'; Title = "Struttura del tier model (OU '$($Config.TierRootName)', gruppi Tier0/1/2)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Le OU sono protette dall''eliminazione accidentale: togliere la protezione ed eliminarle (vuote).'
            Test = { param($Config, $Act)
                $miss = @(Get-TierModel $Config | Where-Object { -not (Get-LdapObject $Config $_.Dn @('distinguishedName')) })
                if (-not $miss.Count) { return New-Plan $true 'Struttura presente' }
                New-Plan $false "$($miss.Count) oggetti da creare" $miss ('Creare: ' + (($miss | ForEach-Object { $_.Name }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan) New-TierModel $Config $Act.Id } })

        $list.Add(@{ Id = 'HD-TIER-LOGON'; Cat = 'Tier model'; Title = 'GPO di restrizione dei logon tra tier (deny logon)'; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Scollegare le GPO Tier0/Tier1 Restrizioni logon.'
            Test = { param($Config, $Act)
                $plan = Get-TierLogonPlan $Config
                $bad = @($plan | Where-Object { -not $_.Ok })
                if (-not $bad.Count) { return New-Plan $true 'GPO di restrizione presenti' }
                New-Plan $false "$($bad.Count) GPO da creare o aggiornare" $plan (($plan | ForEach-Object { "$($_.Gpo): nega logon a $($_.Names -join ', ')" + $(if ($Config.TierLinkGpos) { " (collegata a $($_.Targets -join '; '))" } else { ' (non collegata)' }) }) -join ' | ')
            }
            Apply = { param($Config, $Act, $Plan)
                [void](New-TierModel $Config 'HD-TIER-OU')
                $out = @()
                foreach ($p in (Get-TierLogonPlan $Config)) {
                    $g = Get-HardGpo $Config $p.Suffix -Create -Comment 'FispaTools ad-hardening: restrizioni di logon del tier model'
                    $rights = @{}
                    foreach ($r in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyNetworkLogonRight')) { $rights[$r] = $p.Sids }
                    Set-GpoPrivilegeRights $Config $g $rights
                    if ($Config.TierLinkGpos) { $out += "$($g.DisplayName): " + (Set-GpoLinks $Config $g $p.Targets) } else { $out += "$($g.DisplayName): creata non collegata" }
                }
                [void](Save-Backup $Config $Act.Id @{ Gpo = @($out) })
                $out -join ' | '
            } })

        $list.ToArray()
    }

    # ------------------------------------------------------------------ supporto delle azioni

    function Get-KrbtgtState {
        $f = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\krbtgt-rotation.json')
        if (Test-Path -LiteralPath $f) { try { return (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json) } catch { } }
        [pscustomobject]@{ Pending = $false; Date = $null }
    }

    function Save-KrbtgtState([bool]$Pending) {
        $f = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\krbtgt-rotation.json')
        New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
        [System.IO.File]::WriteAllText($f, ([pscustomobject]@{ Pending = $Pending; Date = (Get-Date).ToString('s') } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    }

    function Get-InactivePlan($Config, [bool]$Computers) {
        $ctx = Get-AdContext $Config
        $limit = $ctx.Now.AddDays(-[int]$Config.InactiveDays).ToFileTimeUtc()
        $cls = if ($Computers) { '(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))' } else { '(objectCategory=person)(objectClass=user)' }
        $f = "(&$cls(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(lastLogonTimestamp<=$limit)(!(lastLogonTimestamp=*)))(pwdLastSet<=$limit))"
        $all = @(Search-Accounts $Config $f @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'servicePrincipalName', 'isCriticalSystemObject'))
        $created = (Get-Date).AddDays(-[int]$Config.InactiveDays)
        $t = @($all | Where-Object {
            $sid = Get-ObjSid $_
            -not ($sid -match '-(500|501|502)$') -and -not $_.isCriticalSystemObject -and
            -not (Test-InList ([string]$_.sAMAccountName) $Config.BreakGlassAccounts) -and -not (Test-InList ([string]$_.sAMAccountName) $Config.InactiveExclude) -and
            -not (@($_.servicePrincipalName) -match 'MSClusterVirtualServer|MSServerClusterMgmtAPI') -and
            -not ($Config.InactiveSkipWithSpn -and -not $Computers -and $_.servicePrincipalName) -and
            ($null -eq $_.whenCreated -or [datetime]$_.whenCreated -lt $created)
        })
        $what = if ($Computers) { 'computer' } else { 'utenti' }
        if (-not $t.Count) { return New-Plan $true "Nessun $what inattivo da disattivare" }
        $dest = ''
        if ([string]$Config.InactiveAction -eq 'Disattiva e sposta' -and $Config.QuarantineOu) { $dest = " e spostare in $($Config.QuarantineOu)" }
        New-Plan $false "$($t.Count) $what inattivi" $t ("Disattivare$dest`: " + (($t | Select-Object -First 50 | ForEach-Object { $_.sAMAccountName }) -join ', ') + $(if ($t.Count -gt 50) { " ... (+$($t.Count - 50))" } else { '' }))
    }

    function Disable-Inactive($Config, [string]$Id, $Targets) {
        $ctx = Get-AdContext $Config
        $move = [string]$Config.InactiveAction -eq 'Disattiva e sposta' -and $Config.QuarantineOu
        $bk = @()
        $stamp = "Disattivato da FispaTools ad-hardening il $((Get-Date).ToString('yyyy-MM-dd')) per inattivita'"
        foreach ($a in @($Targets)) {
            $dn = [string]$a.distinguishedName
            $de = [adsi]"LDAP://$($ctx.Dc)/$($dn.Replace('/', '\/'))"
            $old = [int]$de.Properties['userAccountControl'].Value
            $bk += [pscustomobject]@{ Account = [string]$a.sAMAccountName; Dn = $dn; OldUac = $old; Description = [string]$de.Properties['description'].Value }
            $de.Properties['userAccountControl'].Value = $old -bor 2
            $desc = $stamp
            $oldDesc = [string]$de.Properties['description'].Value
            if ($oldDesc) { $desc = "$stamp - $oldDesc" }
            if ($desc.Length -gt 1024) { $desc = $desc.Substring(0, 1024) }
            $de.Properties['description'].Value = $desc
            $de.CommitChanges()
            if ($move) {
                try { Move-ADObject -Identity $dn -TargetPath ([string]$Config.QuarantineOu) }
                catch { Write-ToolLog "    $($a.sAMAccountName) disattivato ma non spostato: $($_.Exception.Message)" 'WARN' }
            }
        }
        [void](Save-Backup $Config $Id $bk)
        "Disattivati $($bk.Count) account" + $(if ($move) { " e spostati in $($Config.QuarantineOu)" } else { '' })
    }

    function Get-LapsValues($Config) {
        $k = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $v = @(
            , @($k, 'BackupDirectory', 'DWord', 2)
            , @($k, 'PasswordComplexity', 'DWord', 4)
            , @($k, 'PasswordLength', 'DWord', [int]$Config.LapsPasswordLength)
            , @($k, 'PasswordAgeDays', 'DWord', [int]$Config.LapsPasswordAgeDays)
            , @($k, 'PostAuthenticationResetDelay', 'DWord', 24)
            , @($k, 'PostAuthenticationActions', 'DWord', 3)
        )
        if ($Config.LapsAdminAccount) { $v += , @($k, 'AdministratorAccountName', 'String', [string]$Config.LapsAdminAccount) }
        $v
    }

    function Test-LapsSelfPermission($Config, [string]$Ou) {
        $ctx = Get-AdContext $Config
        $attr = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-Password)' @('schemaIDGUID') $ctx.SchemaDn 'OneLevel')
        if (-not $attr.Count) { return $false }
        $guid = New-Object Guid (, [byte[]]$attr[0].schemaIDGUID)
        try {
            $acl = ([adsi]"LDAP://$($ctx.Dc)/$($Ou.Replace('/', '\/'))").psbase.ObjectSecurity
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            return @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-10' -and $_.ObjectType -eq $guid -and ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) }).Count -gt 0
        } catch { return $false }
    }

    # Struttura: OU radice, Tier0/1/2 con Accounts, Groups, Devices, ServiceAccounts; gruppi TierN-Admins
    function Get-TierModel($Config) {
        $ctx = Get-AdContext $Config
        $root = "OU=$($Config.TierRootName),$($ctx.Dn)"
        $o = @([pscustomobject]@{ Name = "OU $($Config.TierRootName)"; Dn = $root; Kind = 'OU'; Parent = $ctx.Dn; Cn = [string]$Config.TierRootName })
        foreach ($t in 0..2) {
            $tdn = "OU=Tier$t,$root"
            $o += [pscustomobject]@{ Name = "OU Tier$t"; Dn = $tdn; Kind = 'OU'; Parent = $root; Cn = "Tier$t" }
            foreach ($s in @('Accounts', 'Groups', 'Devices', 'ServiceAccounts')) { $o += [pscustomobject]@{ Name = "OU Tier$t\$s"; Dn = "OU=$s,$tdn"; Kind = 'OU'; Parent = $tdn; Cn = $s } }
            $o += [pscustomobject]@{ Name = "gruppo Tier$t-Admins"; Dn = "CN=Tier$t-Admins,OU=Groups,$tdn"; Kind = 'Group'; Parent = "OU=Groups,$tdn"; Cn = "Tier$t-Admins" }
        }
        $o
    }

    function New-TierModel($Config, [string]$Id) {
        $created = @()
        foreach ($x in (Get-TierModel $Config)) {
            if (Get-LdapObject $Config $x.Dn @('distinguishedName')) { continue }
            if ($x.Kind -eq 'OU') { New-ADOrganizationalUnit -Name $x.Cn -Path $x.Parent -ProtectedFromAccidentalDeletion $true -Description 'FispaTools ad-hardening: tier model' }
            else { New-ADGroup -Name $x.Cn -SamAccountName $x.Cn -GroupScope Global -GroupCategory Security -Path $x.Parent -Description "Amministratori del $($x.Cn.Replace('-Admins', '')) (tier model)" }
            $created += $x.Dn
            Write-ToolLog "    creato: $($x.Name)" 'OK'
        }
        if ($created.Count) { [void](Save-Backup $Config $Id @{ Created = $created }) }
        "Creati $($created.Count) oggetti"
    }

    # Tier0 non accede ai dispositivi Tier1/Tier2; Tier1 non accede ai dispositivi Tier2
    function Get-TierLogonPlan($Config) {
        $ctx = Get-AdContext $Config
        $root = "OU=$($Config.TierRootName),$($ctx.Dn)"
        $sid = { param($dn) $o = Get-LdapObject $Config $dn @('objectSid'); if ($o) { Get-ObjSid $o } else { $null } }
        $t0 = & $sid "CN=Tier0-Admins,OU=Groups,OU=Tier0,$root"
        $t1 = & $sid "CN=Tier1-Admins,OU=Groups,OU=Tier1,$root"
        $t0Sids = @(@("$($ctx.Sid)-512", "$($ctx.Sid)-519", "$($ctx.Sid)-518", $t0) | Where-Object { $_ })
        $plans = @(
            @{ Suffix = 'Tier0 Restrizioni logon'; Sids = $t0Sids; Names = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Tier0-Admins'); Targets = @("OU=Devices,OU=Tier1,$root", "OU=Devices,OU=Tier2,$root") }
            @{ Suffix = 'Tier1 Restrizioni logon'; Sids = @(@($t1) | Where-Object { $_ }); Names = @('Tier1-Admins'); Targets = @("OU=Devices,OU=Tier2,$root") }
        )
        foreach ($p in $plans) {
            $g = Get-HardGpo $Config $p.Suffix
            $cur = Get-GpoPrivilegeRights $Config $g
            $ok = [bool]$g -and $p.Sids.Count -gt 0
            if ($ok) { foreach ($s in $p.Sids) { if (@($cur['SeDenyInteractiveLogonRight']) -notcontains $s) { $ok = $false } } }
            if ($ok -and $Config.TierLinkGpos) { $ok = Test-GpoLink $Config $g $p.Targets }
            [pscustomobject]@{ Suffix = $p.Suffix; Gpo = (Get-HardGpoName $Config $p.Suffix); Sids = $p.Sids; Names = $p.Names; Targets = $p.Targets; Ok = $ok }
        }
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria (modalita' Hardening)

    function Get-HardItems($Config) {
        Initialize-Hardening $Config
        $ctx = Get-AdContext $Config
        Write-ToolLog "Hardening - dominio $($ctx.Dns) - DC $($ctx.Dc) - verifica dello stato attuale" 'STEP'
        foreach ($a in (Get-HardeningActions $Config)) {
            $p = $null; $state = ''; $sel = $false
            try {
                $p = & $a.Test $Config $a
                if ($p.Ok) { $state = 'Conforme: ' + $p.Detail } else { $state = 'Da applicare: ' + $p.Detail; $sel = $true }
            } catch { $state = 'Non verificabile: ' + $_.Exception.Message }
            [pscustomobject]@{
                Key = $a.Id; Utente = $a.Id; SID = ''; Origine = $a.Cat
                Id = $a.Id; Categoria = $a.Cat; Controllo = $a.Title; Peso = $a.Impact; Richiede = $a.Needs; Stato = $state
                Selectable = $sel
            }
        }
    }

    function Invoke-HardItem($Config, $Item) {
        Initialize-Hardening $Config
        $a = @(Get-HardeningActions $Config | Where-Object { $_.Id -eq $Item.Id })[0]
        if (-not $a) { throw "Azione sconosciuta: $($Item.Id)" }
        $p = & $a.Test $Config $a
        $dati = [pscustomobject]@{ Id = $a.Id; Categoria = $a.Cat; Titolo = $a.Title; Impatto = $a.Impact; Richiede = $a.Needs; Prima = $p.Detail; Piano = $p.Plan; Esito = ''; Messaggio = ''; Dopo = ''; Annullamento = $a.Undo }
        if ($p.Ok) { $dati.Esito = 'OK'; $dati.Messaggio = 'Gia'' conforme: ' + $p.Detail; return @{ Esito = 'OK'; Messaggio = $dati.Messaggio; Dati = $dati } }
        Write-ToolLog "    piano: $($p.Plan)"
        if ($Config.DryRun) {
            $dati.Esito = 'Simulato'; $dati.Messaggio = 'Verrebbe applicato: ' + $p.Plan
            return @{ Esito = 'Simulato'; Messaggio = $dati.Messaggio; Dati = $dati }
        }
        $msg = [string](@(& $a.Apply $Config $a $p) -join ' ')
        $after = $null
        try { $after = & $a.Test $Config $a } catch { }
        $dati.Messaggio = $msg
        if ($after) { $dati.Dopo = $after.Detail }
        if ($after -and -not $after.Ok) { $dati.Esito = 'Attenzione'; $dati.Messaggio = "$msg (verifica successiva: $($after.Detail); replica o applicazione GPO in corso)" }
        else { $dati.Esito = 'OK' }
        @{ Esito = $dati.Esito; Messaggio = $dati.Messaggio; Dati = $dati }
    }

    function Complete-HardRun($Config, $Results) {
        $ctx = Get-AdContext $Config
        $acts = @($Results | Where-Object { $_.Dati } | ForEach-Object { $_.Dati })
        foreach ($f in @($Results | Where-Object { -not $_.Dati })) {
            $acts += [pscustomobject]@{ Id = $f.Utente; Categoria = $f.Origine; Titolo = $f.Utente; Impatto = ''; Richiede = ''; Prima = ''; Piano = ''; Esito = $f.Esito; Messaggio = $f.Messaggio; Dopo = ''; Annullamento = '' }
        }
        $restore = [string]$Config.Mode -eq 'Ripristino'
        $dir = if ($script:RunDir) { $script:RunDir } else { Get-RunDir $Config }
        $mode = if ($Config.DryRun) { 'SIMULAZIONE - nessuna modifica eseguita' } else { 'ESECUZIONE REALE' }
        $name = if ($restore) { 'ripristino' } else { 'hardening' }
        $base = Join-Path $dir $name
        $acts | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        [System.IO.File]::WriteAllText("$base.json", ([pscustomobject]@{ Dominio = $ctx.Dns; DC = $ctx.Dc; Data = (Get-Date).ToString('s'); Modalita = $mode; Eseguito = "$env:USERDOMAIN\$env:USERNAME"; Azioni = $acts } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
        $hero = New-Object System.Collections.Generic.List[string]
        $hero.Add((New-RptKpi $acts.Count 'Azioni elaborate'))
        foreach ($e in @('OK', 'Simulato', 'Attenzione', 'Fallito', 'Annullato')) {
            $n = @($acts | Where-Object { $_.Esito -eq $e }).Count
            if ($n) { $hero.Add((New-RptKpi $n $e (Get-RptTone $e))) }
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<section class=`"card`" data-filter><h2>Azioni <span class=`"n`"></span></h2><div class=`"toolbar`"><input type=`"search`" placeholder=`"Cerca...`">")
        foreach ($g in @($acts | Group-Object Esito)) { [void]$sb.Append("<span class=`"chip`" data-v=`"$(ConvertTo-RptHtml $g.Name)`">$(ConvertTo-RptHtml $g.Name)<span class=`"c`">$($g.Count)</span></span>") }
        [void]$sb.Append('</div>')
        foreach ($x in $acts) {
            $imp = ''
            if ($x.Impatto) { $imp = "<span class=`"muted`">impatto $(ConvertTo-RptHtml $x.Impatto)</span>" }
            [void]$sb.Append("<details class=`"item`" data-row data-s=`"$(ConvertTo-RptHtml $x.Esito)`"><summary>$(New-RptBadge ([string]$x.Esito))<span class=`"mono muted`">$(ConvertTo-RptHtml $x.Id)</span><span class=`"t`">$(ConvertTo-RptHtml $x.Titolo)</span>$imp</summary><div class=`"det`"><div class=`"kv`">")
            foreach ($r in @(@('Categoria', $x.Categoria), @('Prima', $x.Prima), @('Piano', $x.Piano), @('Risultato', $x.Messaggio), @('Dopo', $x.Dopo), @('Come annullare', $x.Annullamento), @('Richiede', $x.Richiede))) {
                if ($r[1]) { [void]$sb.Append("<b>$($r[0])</b><span>$(ConvertTo-RptHtml $r[1])</span>") }
            }
            [void]$sb.Append('</div></div></details>')
        }
        [void]$sb.Append("</section><p class=`"muted`">Backup dello stato precedente: file *.backup.json in $(ConvertTo-RptHtml $dir). Per annullare: modalita' Ripristino su questa cartella.</p>")
        $title = if ($restore) { 'Ripristino hardening Active Directory' } else { 'Hardening Active Directory' }
        $html = New-RptDocument -Title "$title - $($ctx.Dns)" -Subtitle "DC $($ctx.Dc) - $((Get-Date).ToString('dd/MM/yyyy HH:mm')) - $env:USERDOMAIN\$env:USERNAME - $mode" -Badge 'AD' -HeroHtml ($hero -join '') -BodyHtml $sb.ToString()
        [System.IO.File]::WriteAllText("$base.html", $html, (New-Object System.Text.UTF8Encoding($true)))
        Write-ToolLog "Report: $base.html" 'OK'
        "$base.html"
    }
    #endregion
