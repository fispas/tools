
    #region SPECIFICO: share -> gruppi AD e hardening

    $script:DcName = $null
    $script:SidCache = @{}

    function Get-ToolDefaultConfig {
        [ordered]@{
            FileServer       = [string]$env:COMPUTERNAME
            IncludeShares    = @()
            ExcludeShares    = @('NETLOGON', 'SYSVOL', 'print$')
            IncludeHidden    = $false
            DomainController = ''
            GroupOU          = ''
            GroupPrefix      = 'GR-'
            GroupMode        = 'Separati (RW/RO)'
            GroupSuffixRW    = '_RW'
            GroupSuffixRO    = '_RO'
            GroupScope       = 'DomainLocal'
            CreateGroups     = $true
            PopulateGroups   = $true
            IncludeAclGroups = $false
            GrantGroupNtfs   = $true
            RemoveUserAces   = 'No'
            SharePermissions = 'Non modificare'
            EnableABE        = $false
            EncryptData      = $false
            BackupDir        = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Backup'))
            BackupTree       = $false
            ExcludeUsers     = @()
            LogDir           = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun           = $true
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { $w += 'Cmdlet SMB (Get-SmbShare) non disponibili: serve Windows Server 2012 / Windows 8 o successivi.' }
        if (-not $env:USERDNSDOMAIN) { $w += "Sessione non di dominio: gruppi e utenti AD non saranno risolti." }
        $w
    }

    # ------------------------------------------------------------------ AD via LDAP (niente modulo ActiveDirectory)

    function Get-DcPrefix($Config) {
        if (-not $script:DcName) {
            if ($Config.DomainController) { $script:DcName = [string]$Config.DomainController }
            else {
                try { $script:DcName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name }
                catch { throw "Nessun domain controller raggiungibile: $($_.Exception.Message)" }
            }
            Write-ToolLog "Domain controller usato per tutte le operazioni LDAP: $script:DcName"
        }
        'LDAP://' + $script:DcName + '/'
    }

    function ConvertTo-LdapFilterValue([string]$Value) {
        $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
    }

    function ConvertTo-AdsPath([string]$Dn) { $Dn.Replace('/', '\/') }

    # SID -> oggetto AD (classe, DN, sAMAccountName). $null se non e' un oggetto del dominio
    function Get-AdObjectBySid($Config, [string]$Sid) {
        if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
        $o = $null
        try {
            $de = [adsi]((Get-DcPrefix $Config) + "<SID=$Sid>")
            $classes = @($de.Properties['objectClass'])
            if ($classes.Count) {
                $cls = 'altro'
                if ($classes -contains 'computer') { $cls = 'computer' }
                elseif ($classes -contains 'user') { $cls = 'user' }
                elseif ($classes -contains 'group') { $cls = 'group' }
                $o = [pscustomobject]@{
                    Sid  = $Sid
                    Dn   = [string]$de.Properties['distinguishedName'][0]
                    Sam  = [string]$de.Properties['sAMAccountName'][0]
                    Name = [string]$de.Properties['name'][0]
                    Class = $cls
                    GroupType = $(if ($cls -eq 'group') { [int]$de.Properties['groupType'][0] } else { 0 })
                }
            }
        } catch { $o = $null }
        $script:SidCache[$Sid] = $o
        $o
    }

    function Find-AdGroup($Config, [string]$Sam) {
        $root = [adsi]((Get-DcPrefix $Config) + 'RootDSE')
        $base = [adsi]((Get-DcPrefix $Config) + [string]$root.Properties['defaultNamingContext'][0])
        $ds = New-Object System.DirectoryServices.DirectorySearcher($base)
        $ds.Filter = '(&(objectCategory=group)(sAMAccountName={0}))' -f (ConvertTo-LdapFilterValue $Sam)
        [void]$ds.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid'))
        $r = $ds.FindOne()
        if (-not $r) { return $null }
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($r.Properties['objectsid'][0], 0)).Value
        [pscustomobject]@{ Sam = $Sam; Dn = [string]$r.Properties['distinguishedname'][0]; Sid = $sid; Created = $false }
    }

    function New-AdGroupLdap($Config, [string]$Sam, [string]$Description) {
        $types = @{ 'Global' = -2147483646; 'DomainLocal' = -2147483644; 'Universal' = -2147483640 }
        $ou = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Config.GroupOU))
        $g = $ou.Create('group', "CN=$Sam")
        $g.Put('sAMAccountName', $Sam)
        $g.Put('groupType', [int]$types[$Config.GroupScope])
        $g.Put('description', $Description)
        $g.SetInfo()
        $g.RefreshCache(@('objectSid', 'distinguishedName'))
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($g.Properties['objectSid'][0], 0)).Value
        [pscustomobject]@{ Sam = $Sam; Dn = [string]$g.Properties['distinguishedName'][0]; Sid = $sid; Created = $true }
    }

    # Aggiunge un membro. Restituisce 'aggiunto', 'presente' o lancia un errore
    function Add-AdGroupMemberLdap($Config, $Group, [string]$MemberDn) {
        $g = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Group.Dn))
        $mPath = (Get-DcPrefix $Config) + (ConvertTo-AdsPath $MemberDn)
        if ($g.IsMember($mPath)) { return 'presente' }
        $g.Add($mPath)
        'aggiunto'
    }

    # ------------------------------------------------------------------ file server

    function Test-IsLocalServer([string]$Server) {
        $s = ([string]$Server).Trim().ToLower()
        if (-not $s -or $s -in @('.', 'localhost', '127.0.0.1')) { return $true }
        $names = @($env:COMPUTERNAME.ToLower())
        try { $names += [System.Net.Dns]::GetHostEntry('localhost').HostName.ToLower() } catch { }
        if ($env:USERDNSDOMAIN) { $names += ($env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN).ToLower() }
        $names -contains $s
    }

    function New-ToolCim($Config) {
        if (Test-IsLocalServer $Config.FileServer) { return $null }
        try { return New-CimSession -ComputerName $Config.FileServer -ErrorAction Stop }
        catch {
            Write-ToolLog "WinRM non disponibile verso $($Config.FileServer), provo DCOM: $($_.Exception.Message)" 'WARN'
            $opt = New-CimSessionOption -Protocol Dcom
            return New-CimSession -ComputerName $Config.FileServer -SessionOption $opt -ErrorAction Stop
        }
    }

    function Get-CimParams($Cim) {
        $p = @{ ErrorAction = 'Stop' }
        if ($Cim) { $p.CimSession = $Cim }
        $p
    }

    function Get-AdminPath($Config, [string]$LocalPath) {
        if (Test-IsLocalServer $Config.FileServer) { return $LocalPath }
        if ($LocalPath -match '^[A-Za-z]:') { return '\\' + $Config.FileServer + '\' + $LocalPath.Replace(':', '$') }
        $LocalPath
    }

    # Nome locale (sul file server) di un SID ben noto: i nomi cambiano con la lingua di Windows
    function Get-WellKnownName($Cim, [string]$Sid) {
        $p = Get-CimParams $Cim
        $a = Get-CimInstance @p -ClassName Win32_SystemAccount -Filter "SID='$Sid'" | Select-Object -First 1
        if (-not $a) { $a = Get-CimInstance @p -ClassName Win32_Group -Filter "LocalAccount=TRUE AND SID='$Sid'" | Select-Object -First 1 }
        if (-not $a) { $a = Get-CimInstance @p -ClassName Win32_Group -Filter "SID='$Sid'" | Select-Object -First 1 }   # domain controller: niente account locali
        if (-not $a) { throw "Account $Sid non trovato sul file server" }
        [string]$a.Name
    }

    function Get-SidName([string]$Sid) {
        try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid }
    }

    # Categoria di un SID trovato in una ACL
    function Get-SidCategory($Config, [string]$Sid) {
        if ($Sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-2') -or $Sid -match '^S-1-5-21-.+-(513|515)$') { return 'ampio' }
        if ($Sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-551', 'S-1-3-0', 'S-1-3-1', 'S-1-3-4', 'S-1-5-9') -or
            $Sid -match '^S-1-5-21-.+-(500|512|518|519|520)$') { return 'amministrativo' }
        if ($Sid -notmatch '^S-1-5-21-') { return 'sistema' }
        $o = Get-AdObjectBySid $Config $Sid
        if (-not $o) { return 'orfano' }
        switch ($o.Class) { 'user' { 'utente' } 'group' { 'gruppo' } default { 'sistema' } }
    }

    # Fotografia di una share: ACL NTFS della cartella, permessi share, impostazioni
    function Get-ShareAnalysis($Config, $Share, $Cim) {
        $adminPath = Get-AdminPath $Config $Share.Path
        $acl = Get-Acl -LiteralPath $adminPath -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $writeMask = 0xD0006 -bor 0x50000000
        $usersRW = @{}; $usersRO = @{}; $groupsRW = @{}; $groupsRO = @{}
        $broad = @{}; $orphans = @{}; $deny = 0; $explicitUsers = 0
        foreach ($r in $rules) {
            $sid = $r.IdentityReference.Value
            if ($r.AccessControlType -ne 'Allow') { $deny++; continue }
            $isRW = ([int64]$r.FileSystemRights -band $writeMask) -ne 0
            $cat = Get-SidCategory $Config $sid
            switch ($cat) {
                'ampio' { $broad[$sid] = (Get-SidName $sid) }
                'orfano' { $orphans[$sid] = $true }
                'utente' {
                    if (-not $r.IsInherited) { $explicitUsers++ }
                    if ($isRW) { $usersRW[$sid] = $true; $usersRO.Remove($sid) } elseif (-not $usersRW.ContainsKey($sid)) { $usersRO[$sid] = $true }
                }
                'gruppo' {
                    if ($isRW) { $groupsRW[$sid] = $true; $groupsRO.Remove($sid) } elseif (-not $groupsRW.ContainsKey($sid)) { $groupsRO[$sid] = $true }
                }
            }
        }
        $p = Get-CimParams $Cim
        $access = @(Get-SmbShareAccess @p -Name $Share.Name)
        $shareText = (@($access | ForEach-Object { '{0}:{1}{2}' -f $_.AccountName, $_.AccessRight, $(if ($_.AccessControlType -ne 'Allow') { '(deny)' } else { '' }) }) -join ', ')
        [pscustomobject]@{
            AdminPath       = $adminPath
            UsersRW         = @($usersRW.Keys)
            UsersRO         = @($usersRO.Keys)
            GroupsRW        = @($groupsRW.Keys)
            GroupsRO        = @($groupsRO.Keys)
            Broad           = @($broad.Values)
            Orphans         = @($orphans.Keys)
            Deny            = $deny
            ExplicitUsers   = $explicitUsers
            Protected       = $acl.AreAccessRulesProtected
            ShareAccess     = $access
            ShareText       = $shareText
            EveryoneFull    = [bool](@($access | Where-Object { $_.AccessRight -eq 'Full' -and $_.AccessControlType -eq 'Allow' -and $_.AccountName -match '^(Everyone|Tutti|Jeder|Tout le monde|Todos)$' }).Count)
            ABE             = [string]$Share.FolderEnumerationMode
            Encrypt         = [bool]$Share.EncryptData
        }
    }

    function Get-GroupBaseName($Config, [string]$ShareName) {
        $ti = (Get-Culture).TextInfo
        $clean = $ti.ToTitleCase($ShareName.TrimEnd('$').ToLower()) -replace '[^A-Za-z0-9_.-]', ''
        $base = [string]$Config.GroupPrefix + $clean
        if ($base.Length -gt 60) { $base = $base.Substring(0, 60) }
        $base
    }

    function Get-PlannedGroups($Config, [string]$ShareName) {
        $base = Get-GroupBaseName $Config $ShareName
        if ($Config.GroupMode -like 'Unico*') {
            return @([pscustomobject]@{ Sam = $base; Level = 'RW'; Rights = 'M'; Label = 'Modifica' })
        }
        @(
            [pscustomobject]@{ Sam = $base + $Config.GroupSuffixRW; Level = 'RW'; Rights = 'M'; Label = 'Modifica' }
            [pscustomobject]@{ Sam = $base + $Config.GroupSuffixRO; Level = 'RO'; Rights = 'RX'; Label = 'Lettura' }
        )
    }

    function Get-ShareList($Config, $Cim) {
        $p = Get-CimParams $Cim
        $all = @(Get-SmbShare @p | Where-Object { -not $_.Special -and "$($_.ShareType)" -match 'FileSystemDirectory' -and $_.Path })
        $all = @($all | Where-Object { @($Config.ExcludeShares) -notcontains $_.Name })
        if (-not $Config.IncludeHidden) { $all = @($all | Where-Object { -not $_.Name.EndsWith('$') }) }
        if (@($Config.IncludeShares).Count) {
            $all = @($all | Where-Object { $n = $_.Name; @(@($Config.IncludeShares) | Where-Object { $n -like $_ }).Count -gt 0 })
        }
        @($all | Sort-Object Name)
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if (-not $Config.FileServer) { $e += 'Indicare il file server.' }
        if ($Scan) { return $e }
        if ($Config.CreateGroups -or $Config.PopulateGroups -or $Config.GrantGroupNtfs) {
            if ([string]$Config.GroupPrefix -notmatch '^[A-Za-z0-9_.-]*$') { $e += 'Il prefisso dei gruppi puo'' contenere solo lettere, numeri, punto, trattino e trattino basso.' }
        }
        if ($Config.CreateGroups) {
            if (-not $Config.GroupOU) { $e += "Indicare l'OU in cui creare i gruppi (distinguishedName, es. OU=Gruppi,DC=contoso,DC=local)." }
            else {
                try {
                    $ou = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Config.GroupOU))
                    if (-not $ou.Properties['distinguishedName'].Count) { $e += "OU non trovata: $($Config.GroupOU)" }
                } catch { $e += "OU non raggiungibile ($($Config.GroupOU)): $($_.Exception.Message)" }
            }
        }
        if ($Config.RemoveUserAces -ne 'No' -and -not ($Config.PopulateGroups -and $Config.GrantGroupNtfs)) {
            $e += "La rimozione delle ACE degli utenti richiede anche 'Popola i gruppi' e 'Permesso NTFS ai gruppi': senza, gli utenti perderebbero l'accesso."
        }
        if (-not $Config.BackupDir) { $e += 'Indicare la cartella dei backup.' }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        $e
    }

    function Get-ToolItems($Config) {
        Write-ToolLog "Analisi delle share di $($Config.FileServer)" 'STEP'
        $cim = New-ToolCim $Config
        try {
            $shares = Get-ShareList $Config $cim
            Write-ToolLog "Share trovate: $($shares.Count)"
            foreach ($sh in $shares) {
                $groups = @(Get-PlannedGroups $Config $sh.Name | ForEach-Object { $_.Sam }) -join ', '
                try {
                    $a = Get-ShareAnalysis $Config $sh $cim
                    $flags = @()
                    if ($a.Broad.Count) { $flags += 'accesso ampio' }
                    if ($a.EveryoneFull) { $flags += 'Everyone Full sulla share' }
                    if ($a.ExplicitUsers) { $flags += "$($a.ExplicitUsers) ACE utente" }
                    if ($a.Orphans.Count) { $flags += "$($a.Orphans.Count) SID orfani" }
                    if ($a.Deny) { $flags += "$($a.Deny) deny" }
                    if ($a.Protected) { $flags += 'ereditarieta disattivata' }
                    $stato = 'Da migliorare: ' + ($flags -join ', ')
                    if (-not $flags.Count) { $stato = 'Pronto' }
                    [pscustomobject]@{
                        Key          = $sh.Name
                        Utente       = $sh.Name
                        SID          = ''
                        Origine      = $a.AdminPath
                        Share        = $sh.Name
                        Percorso     = $sh.Path
                        Utenti       = ('RW {0} / RO {1}' -f $a.UsersRW.Count, $a.UsersRO.Count)
                        GruppiAcl    = ($a.GroupsRW.Count + $a.GroupsRO.Count)
                        Ampio        = ($a.Broad -join ', ')
                        PermShare    = $a.ShareText
                        ABE          = $(if ($a.ABE -eq 'AccessBased') { 'si' } else { 'no' })
                        Gruppi       = $groups
                        Stato        = $stato
                        Selectable   = $true
                        Analysis     = $a
                        ShareObj     = $sh
                    }
                } catch {
                    Write-ToolLog "Share $($sh.Name): analisi non riuscita - $($_.Exception.Message)" 'ERROR'
                    [pscustomobject]@{
                        Key = $sh.Name; Utente = $sh.Name; SID = ''; Origine = $sh.Path; Share = $sh.Name; Percorso = $sh.Path
                        Utenti = ''; GruppiAcl = ''; Ampio = ''; PermShare = ''; ABE = ''; Gruppi = $groups
                        Stato = "Errore: $($_.Exception.Message)"; Selectable = $false; Analysis = $null; ShareObj = $sh
                    }
                }
            }
        } finally { if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue } }
    }

    function Invoke-Icacls([string[]]$IcaclsArgs, [string]$What) {
        $out = & icacls.exe @IcaclsArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "$What non riuscito (icacls exit $LASTEXITCODE): $(@($out) -join ' ')" }
    }

    function Invoke-ToolItem($Config, $Item) {
        $res = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
        $cim = New-ToolCim $Config
        try {
            $p = Get-CimParams $Cim
            $share = Get-SmbShare @p -Name $Item.Share
            $a = Get-ShareAnalysis $Config $share $cim          # rilettura: lo stato puo' essere cambiato dall'analisi
            $path = $a.AdminPath
            $planned = @(Get-PlannedGroups $Config $share.Name)
            $exclude = @($Config.ExcludeUsers)
            $members = @{}
            foreach ($g in $planned) { $members[$g.Sam] = New-Object System.Collections.Generic.List[string] }
            $rw = $planned[0].Sam
            $ro = $planned[-1].Sam
            foreach ($sid in $a.UsersRW) { $members[$rw].Add($sid) }
            foreach ($sid in $a.UsersRO) { $members[$ro].Add($sid) }
            if ($Config.IncludeAclGroups) {
                foreach ($sid in $a.GroupsRW) { $members[$rw].Add($sid) }
                foreach ($sid in $a.GroupsRO) { $members[$ro].Add($sid) }
            }
            foreach ($k in @($members.Keys)) {
                $keep = New-Object System.Collections.Generic.List[string]
                foreach ($sid in $members[$k]) {
                    $o = Get-AdObjectBySid $Config $sid
                    if ($o -and $exclude -contains $o.Sam) { Write-ToolLog "Escluso da configurazione: $($o.Sam)"; continue }
                    $keep.Add($sid)
                }
                $members[$k] = $keep
            }

            Write-ToolLog "Percorso: $path"
            Write-ToolLog ('Utenti in ACL: RW {0}, RO {1}; gruppi in ACL: {2}; accesso ampio: {3}' -f $a.UsersRW.Count, $a.UsersRO.Count, ($a.GroupsRW.Count + $a.GroupsRO.Count), ($(if ($a.Broad.Count) { $a.Broad -join ', ' } else { 'nessuno' })))
            foreach ($g in $planned) {
                $names = @($members[$g.Sam] | ForEach-Object { $o = Get-AdObjectBySid $Config $_; if ($o) { $o.Sam } else { $_ } })
                Write-ToolLog ('Gruppo {0} ({1}): {2} membri da ACL{3}' -f $g.Sam, $g.Label, $names.Count, $(if ($names.Count) { ' - ' + ($names -join ', ') } else { '' }))
            }

            if ($Config.DryRun) {
                $steps = @()
                if ($Config.CreateGroups) { $steps += 'creazione gruppi mancanti' }
                if ($Config.PopulateGroups) { $steps += 'popolamento gruppi' }
                if ($Config.GrantGroupNtfs) { $steps += 'ACE NTFS dei gruppi' }
                if ($Config.RemoveUserAces -ne 'No') { $steps += "rimozione ACE utente ($($Config.RemoveUserAces))" }
                if ($Config.SharePermissions -ne 'Non modificare') { $steps += 'permessi share standard' }
                if ($Config.EnableABE) { $steps += 'Access-Based Enumeration' }
                if ($Config.EncryptData) { $steps += 'cifratura SMB' }
                Write-ToolLog ('[Simulazione] passi: backup, ' + ($steps -join ', '))
                $res.Esito = 'Simulato'
                $res.Messaggio = ($steps -join ', ')
                return $res
            }

            # 1. backup
            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $bdir = Join-Path $Config.BackupDir ('{0}\{1}' -f $Config.FileServer, $stamp)
            New-Item -ItemType Directory -Path $bdir -Force | Out-Null
            $safe = $share.Name -replace '[^A-Za-z0-9_.-]', '_'
            $aclFile = Join-Path $bdir "$safe.acl"
            $icArgs = @($path, '/save', $aclFile, '/C', '/Q')
            if ($Config.BackupTree) { $icArgs += '/T' }
            Invoke-Icacls $icArgs 'Backup ACL'
            $shareInfo = [pscustomobject]@{
                Name = $share.Name; Path = $share.Path; FolderEnumerationMode = [string]$share.FolderEnumerationMode; EncryptData = [bool]$share.EncryptData
                Access = @($a.ShareAccess | ForEach-Object { [pscustomobject]@{ AccountName = $_.AccountName; AccessControlType = [string]$_.AccessControlType; AccessRight = [string]$_.AccessRight } })
            }
            [System.IO.File]::WriteAllText((Join-Path $bdir "$safe.share.json"), ($shareInfo | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($true)))
            $parent = Split-Path -Parent $path
            Write-ToolLog "Backup in $bdir. Ripristino ACL: icacls `"$parent`" /restore `"$aclFile`"" 'OK'
            $res.Destinazione = $bdir

            $done = @()
            # 2. gruppi
            $groupObj = @{}
            foreach ($g in $planned) {
                $obj = Find-AdGroup $Config $g.Sam
                if (-not $obj) {
                    if (-not $Config.CreateGroups) { throw "Il gruppo $($g.Sam) non esiste e la creazione e' disattivata." }
                    $obj = New-AdGroupLdap $Config $g.Sam ("Accesso {0} alla share {1} su {2}" -f $g.Label, $share.Name, $Config.FileServer)
                    Write-ToolLog "Gruppo creato: $($obj.Dn)" 'OK'
                    $done += "creato $($g.Sam)"
                } else { Write-ToolLog "Gruppo esistente: $($obj.Dn)" }
                $groupObj[$g.Sam] = $obj
            }

            # 3. membri
            $migrated = @{}
            if ($Config.PopulateGroups) {
                $added = 0
                foreach ($g in $planned) {
                    foreach ($sid in $members[$g.Sam]) {
                        $o = Get-AdObjectBySid $Config $sid
                        if (-not $o) { continue }
                        try {
                            $r = Add-AdGroupMemberLdap $Config $groupObj[$g.Sam] $o.Dn
                            if ($r -eq 'aggiunto') { $added++; Write-ToolLog "  + $($o.Sam) in $($g.Sam)" }
                            $migrated[$sid] = $g.Level
                        } catch { Write-ToolLog "  Impossibile aggiungere $($o.Sam) a $($g.Sam): $($_.Exception.Message)" 'WARN' }
                    }
                }
                $done += "$added membri aggiunti"
            }

            # 4. ACE NTFS dei gruppi (sulla radice, ereditata da file e sottocartelle)
            $granted = @{}
            if ($Config.GrantGroupNtfs) {
                foreach ($g in $planned) {
                    $gs = $groupObj[$g.Sam].Sid
                    Invoke-Icacls @($path, '/grant', ('*{0}:(OI)(CI){1}' -f $gs, $g.Rights), '/C', '/Q') "Permesso NTFS a $($g.Sam)"
                    $granted[$g.Level] = $true
                    Write-ToolLog "ACE NTFS: $($g.Sam) = $($g.Label)" 'OK'
                }
                $done += 'ACE gruppi'
            }

            # 5. rimozione ACE esplicite degli utenti migrati (solo se membri del gruppo del loro livello, e il gruppo ha l'ACE)
            if ($Config.RemoveUserAces -ne 'No') {
                $removed = 0
                foreach ($sid in @($migrated.Keys)) {
                    if (-not $granted.ContainsKey($migrated[$sid])) { continue }
                    $o = Get-AdObjectBySid $Config $sid
                    if (-not $o -or $o.Class -ne 'user') { continue }
                    $rmArgs = @($path, '/remove:g', "*$sid", '/C', '/Q')
                    if ($Config.RemoveUserAces -like 'Intero*') { $rmArgs += '/T' }
                    try { Invoke-Icacls $rmArgs "Rimozione ACE di $($o.Sam)"; $removed++; Write-ToolLog "  - ACE esplicita rimossa: $($o.Sam)" }
                    catch { Write-ToolLog $_.Exception.Message 'WARN' }
                }
                $done += "$removed ACE utente rimosse"
            }

            # 6. permessi share, ABE, cifratura
            if ($Config.SharePermissions -ne 'Non modificare') {
                $auth = Get-WellKnownName $cim 'S-1-5-11'
                $adm = Get-WellKnownName $cim 'S-1-5-32-544'
                $every = Get-WellKnownName $cim 'S-1-1-0'
                Grant-SmbShareAccess @p -Name $share.Name -AccountName $auth -AccessRight Change -Force | Out-Null
                Grant-SmbShareAccess @p -Name $share.Name -AccountName $adm -AccessRight Full -Force | Out-Null
                if (@($a.ShareAccess | Where-Object { $_.AccountName -match ('(^|\\)' + [regex]::Escape($every) + '$') }).Count) {
                    Revoke-SmbShareAccess @p -Name $share.Name -AccountName $every -Force | Out-Null
                    Write-ToolLog "Permesso share rimosso: $every"
                }
                Write-ToolLog "Permessi share: $auth = Modifica, $adm = Controllo completo (i permessi effettivi li decide NTFS)" 'OK'
                $done += 'permessi share'
            }
            if ($Config.EnableABE -and $share.FolderEnumerationMode -ne 'AccessBased') {
                Set-SmbShare @p -Name $share.Name -FolderEnumerationMode AccessBased -Force
                Write-ToolLog 'Access-Based Enumeration attivata' 'OK'
                $done += 'ABE'
            }
            if ($Config.EncryptData -and -not $share.EncryptData) {
                Set-SmbShare @p -Name $share.Name -EncryptData $true -Force
                Write-ToolLog 'Cifratura SMB attivata (i client senza SMB 3 non accedono piu)' 'WARN'
                $done += 'cifratura SMB'
            }

            $res.Esito = 'OK'
            $res.Messaggio = ($done -join ', ')
            $res
        } finally {
            if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
        }
    }
    #endregion
