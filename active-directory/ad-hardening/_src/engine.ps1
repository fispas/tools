
    #region SPECIFICO: fotografia di sicurezza di Active Directory (sola lettura)

    $script:Dom = $null

    function Get-ToolDefaultConfig {
        [ordered]@{
            Mode             = 'Fotografia'
            DryRun           = $true
            DomainController = ''
            InactiveDays     = 90
            KrbtgtMaxDays    = 180
            PrivilegedMax    = 5
            MaxEvidence      = 200
            CheckDcServices  = $true
            ScanSysvolGpp    = $true
            OutputDir        = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Report'))
            LogDir           = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            # fase 2 - hardening
            GpoPrefix              = 'FispaTools'
            GpoLinkMode            = 'Collegata e attiva'
            MemberHardeningOus     = @()
            LmCompatibilityLevel   = 5
            LdapChannelBinding     = 'Se supportato'
            SecurityLogMaxMB       = 4096
            StopSpoolerNow         = $true
            DomainMinPasswordLength = 12
            DomainLockoutThreshold = 10
            DomainLockoutMinutes   = 15
            AdminPsoMinLength      = 16
            AdminPsoMaxAgeDays     = 365
            ProtectedUsersMode     = 'Elenco'
            ProtectedUsersList     = @()
            BreakGlassAccounts     = @()
            InactiveAction         = 'Disattiva'
            QuarantineOu           = ''
            InactiveExclude        = @()
            InactiveSkipWithSpn    = $true
            KrbtgtMinHours         = 24
            LapsOus                = @()
            LapsPasswordLength     = 20
            LapsPasswordAgeDays    = 30
            LapsAdminAccount       = ''
            TierRootName           = 'Admin'
            TierLinkGpos           = $false
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not $env:USERDNSDOMAIN) { $w += 'Sessione non di dominio: eseguire da una macchina del dominio con un account di dominio.' }
        if ([string]$Config.Mode -eq 'Hardening') {
            foreach ($m in @('ActiveDirectory', 'GroupPolicy')) { if (-not (Get-Module -ListAvailable -Name $m)) { $w += "Hardening: modulo $m mancante (strumenti RSAT)." } }
            $groups = @([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value })
            if (-not @($groups | Where-Object { $_ -match '-(512|519)$' }).Count) { $w += 'Hardening: l''account corrente non e'' Domain Admins ne'' Enterprise Admins: molte azioni non avranno i permessi.' }
            if (-not $Config.DryRun) { $w += 'Hardening in ESECUZIONE REALE: le azioni selezionate modificano il dominio (backup dello stato precedente nella cartella dei report).' }
        }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        $hard = [string]$Config.Mode -eq 'Hardening'
        # in fotografia lo strumento e' in sola lettura; in hardening vale la simulazione
        $Tool.ReadOnly = -not $hard
        try { [void](Get-AdContext $Config) } catch { $e += "Dominio non raggiungibile: $($_.Exception.Message)" }
        if (-not $Scan -and -not $Config.OutputDir) { $e += 'Indicare la cartella dei report.' }
        if ($hard) {
            if ([string]$Config.GpoPrefix -notmatch '^[A-Za-z0-9 _.-]{2,40}$') { $e += 'Prefisso delle GPO non valido (2-40 caratteri: lettere, numeri, spazio, _ . -).' }
            if ([string]$Config.TierRootName -notmatch '^[A-Za-z0-9 _-]{1,40}$') { $e += 'Nome dell''OU radice del tier model non valido.' }
            if ([string]$Config.InactiveAction -eq 'Disattiva e sposta' -and -not $Config.QuarantineOu) { $e += 'Indicare l''OU di quarantena per gli account inattivi.' }
            foreach ($ou in @(@($Config.MemberHardeningOus) + @($Config.LapsOus) + @($Config.QuarantineOu) | Where-Object { $_ })) {
                if ($ou -notmatch '^(OU|CN)=.+,DC=') { $e += "OU non valida (serve il distinguished name): $ou" }
            }
            if ([int]$Config.LmCompatibilityLevel -lt 3 -or [int]$Config.LmCompatibilityLevel -gt 5) { $e += 'LmCompatibilityLevel: da 3 a 5.' }
        }
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
        @(Search-Ldap $Config $f @('sAMAccountName', 'distinguishedName', 'userAccountControl', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'objectSid', 'servicePrincipalName'))
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
        if ([string]$Config.Mode -eq 'Hardening') { return Get-HardItems $Config }
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
        if ([string]$Config.Mode -eq 'Hardening') { return Invoke-HardItem $Config $Item }
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
        if ([string]$Config.Mode -eq 'Hardening') { return Complete-HardRun $Config $Results }
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
