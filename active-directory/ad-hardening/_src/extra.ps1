    #region SPECIFICO: controlli ADCS e ACL, confronto tra fotografie, report, ripristino dai backup

    # ACL (DACL) di un oggetto, letta con DirectorySearcher (SecurityMasks Dacl: basta un utente di dominio)
    function Get-ObjectAcl($Config, [string]$Dn) {
        $ctx = Get-AdContext $Config
        $de = [adsi]"LDAP://$($ctx.Dc)/$($Dn.Replace('/', '\/'))"
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de, '(objectClass=*)', [string[]]@('nTSecurityDescriptor'), [System.DirectoryServices.SearchScope]::Base)
        $ds.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $r = $ds.FindOne()
        if (-not $r -or -not $r.Properties['ntsecuritydescriptor'].Count) { return @() }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])
        @($sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    }

    # Diritto completo presente (i diritti generici sono combinazioni di bit)
    function Test-Right($Rule, [string]$Name) {
        $v = [int][System.DirectoryServices.ActiveDirectoryRights]$Name
        ([int]$Rule.ActiveDirectoryRights -band $v) -eq $v
    }

    function Get-SidLabel([string]$Sid) {
        $n = $null
        try { $n = Resolve-SidAccount $Sid } catch { }
        if ($n) { "$n ($Sid)" } else { $Sid }
    }

    # Principali che per impostazione predefinita hanno diritti estesi sul dominio
    $script:DefaultAdminSidRx = '^S-1-5-(18|9)$|^S-1-5-32-544$|-(498|512|516|518|519)$'
    $script:LowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545')

    function Get-AdChecksExtra {
        @(
            @{ Id = 'A-ESC-01'; Cat = 'Servizi certificati (ADCS)'; Title = 'Modelli di certificato sfruttabili (ESC1-ESC4)'; Weight = 20; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $pks = "CN=Public Key Services,CN=Services,$($ctx.ConfigDn)"
                $cas = @(Search-Ldap $Config '(objectClass=pKIEnrollmentService)' @('cn', 'dNSHostName', 'certificateTemplates') "CN=Enrollment Services,$pks" 'OneLevel')
                if (-not $cas.Count) { return New-CheckResult 'OK' 'Nessuna CA aziendale registrata in Active Directory' }
                $published = @($cas | ForEach-Object { @($_.certificateTemplates) } | Where-Object { $_ } | Select-Object -Unique)
                $tpls = @(Search-Ldap $Config '(objectClass=pKICertificateTemplate)' @('cn', 'distinguishedName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy') "CN=Certificate Templates,$pks" 'OneLevel')
                $low = @($script:LowPrivSids) + @("$($ctx.Sid)-513", "$($ctx.Sid)-514", "$($ctx.Sid)-515")
                $enrollG = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
                $autoG = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                $authEku = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '2.5.29.37.0')
                $ev = @(); $bad = 0
                foreach ($t in $tpls) {
                    if ($published -notcontains $t.cn) { continue }
                    $rules = @(Get-ObjectAcl $Config ([string]$t.distinguishedName) | Where-Object { $_.AccessControlType -eq 'Allow' -and $low -contains $_.IdentityReference.Value })
                    $canEnroll = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or ((Test-Right $_ 'ExtendedRight') -and ($_.ObjectType -eq $enrollG -or $_.ObjectType -eq $autoG -or $_.ObjectType -eq [guid]::Empty)) }).Count -gt 0
                    $canWrite = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or ((Test-Right $_ 'WriteProperty') -and $_.ObjectType -eq [guid]::Empty) }).Count -gt 0
                    $eku = @(@($t.pKIExtendedKeyUsage) + @($t.'msPKI-Certificate-Application-Policy') | Where-Object { $_ } | Select-Object -Unique)
                    $approval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -ne 0
                    $ra = [int]$t.'msPKI-RA-Signature' -gt 0
                    $supplies = ([int]$t.'msPKI-Certificate-Name-Flag' -band 1) -ne 0
                    $iss = @()
                    if ($canEnroll -and -not $approval -and -not $ra) {
                        if ($supplies -and ($eku.Count -eq 0 -or @($eku | Where-Object { $authEku -contains $_ }).Count)) { $iss += 'ESC1: soggetto scelto dal richiedente e uso per autenticazione' }
                        if ($eku.Count -eq 0 -or $eku -contains '2.5.29.37.0') { $iss += 'ESC2: uso qualsiasi o nessun EKU' }
                        if ($eku -contains '1.3.6.1.4.1.311.20.2.1') { $iss += 'ESC3: agente di richiesta certificati' }
                    }
                    if ($canWrite) { $iss += 'ESC4: utenti non privilegiati possono modificare il modello' }
                    if ($iss.Count) { $bad++; $ev += "$($t.cn): $($iss -join '; ')" }
                }
                $ev += @($cas | ForEach-Object { "CA: $($_.cn) ($($_.dNSHostName))" })
                if ($bad) { return New-CheckResult 'Critico' "$bad modelli pubblicati permettono a utenti comuni di ottenere certificati validi per altri utenti, anche amministratori" $ev 'Per ogni modello segnalato: soggetto costruito da AD (non "fornito nella richiesta"), approvazione del responsabile o firma autorizzata, registrazione solo per gruppi dedicati, nessun permesso di scrittura agli utenti comuni; non pubblicare i modelli inutilizzati.' }
                New-CheckResult 'OK' "$(@($tpls | Where-Object { $published -contains $_.cn }).Count) modelli pubblicati su $($cas.Count) CA: nessuna configurazione ESC1-ESC4" $ev
            } }

            @{ Id = 'C-DCSYNC-01'; Cat = 'Configurazione del dominio'; Title = 'Diritti di replica (DCSync) e controllo del dominio'; Weight = 20; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $repl = @([guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', [guid]'89e95b76-444d-4c62-991a-0facbeda640c')
                $rules = @(Get-ObjectAcl $Config $ctx.Dn | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notmatch $script:DefaultAdminSidRx })
                $bad = @($rules | Where-Object {
                    (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or
                    ((Test-Right $_ 'ExtendedRight') -and ($repl -contains $_.ObjectType -or $_.ObjectType -eq [guid]::Empty))
                })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Replica e controllo completo del dominio solo ai gruppi predefiniti' }
                $ev = @($bad | Group-Object { $_.IdentityReference.Value } | ForEach-Object { "$(Get-SidLabel $_.Name): $(($_.Group | ForEach-Object { [string]$_.ActiveDirectoryRights }) -join ', ')" })
                $sync = @($ev | Where-Object { $_ -match 'MSOL_|AAD_|Sync_' })
                if ($sync.Count -eq $ev.Count) { return New-CheckResult 'Attenzione' "Diritti di replica a $($ev.Count) account di sincronizzazione (Entra Connect): leciti ma da proteggere come Tier 0" $ev 'Trattare l''account e il server di sincronizzazione come Tier 0: password lunga, nessun accesso interattivo, server protetto come un DC.' }
                New-CheckResult 'Critico' "$($ev.Count) principali non standard possono replicare i segreti (DCSync) o controllare l'oggetto dominio" $ev 'Rimuovere i diritti "Replicating Directory Changes All" e i permessi di controllo completo concessi a utenti o gruppi non amministrativi; se servono a un prodotto, isolarne l''account come Tier 0.'
            } }

            @{ Id = 'C-ADMSD-01'; Cat = 'Configurazione del dominio'; Title = 'Permessi su AdminSDHolder'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $rules = @(Get-ObjectAcl $Config "CN=AdminSDHolder,CN=System,$($ctx.Dn)" | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notmatch $script:DefaultAdminSidRx })
                $bad = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or ((Test-Right $_ 'WriteProperty') -and $_.ObjectType -eq [guid]::Empty) })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Nessun permesso di modifica anomalo su AdminSDHolder' }
                $ev = @($bad | Group-Object { $_.IdentityReference.Value } | ForEach-Object { "$(Get-SidLabel $_.Name): $(($_.Group | ForEach-Object { [string]$_.ActiveDirectoryRights }) -join ', ')" })
                New-CheckResult 'Critico' "$($ev.Count) principali non standard possono modificare AdminSDHolder: i loro permessi vengono copiati su tutti gli account privilegiati ogni ora" $ev 'Rimuovere le voci anomale da CN=AdminSDHolder,CN=System (tipica persistenza dopo una compromissione): verificare chi le ha aggiunte.'
            } }
        )
    }

    # ------------------------------------------------------------------ confronto con una fotografia precedente

    function Get-PreviousSnapshot($Config, [string]$CurrentJson) {
        $ctx = Get-AdContext $Config
        $file = [string]$Config.CompareWith
        if (-not $file) {
            $file = @(Get-ChildItem -LiteralPath ([string]$Config.OutputDir) -Filter ('ADAssessment_{0}_*.json' -f $ctx.Dns) -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $CurrentJson } | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName })[0]
        }
        if (-not $file -or -not (Test-Path -LiteralPath $file)) { return $null }
        try {
            $j = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
            [pscustomobject]@{ File = $file; Meta = $j.Meta; Checks = @($j.Controlli) }
        } catch { Write-ToolLog "Fotografia precedente non leggibile ($file): $($_.Exception.Message)" 'WARN'; $null }
    }

    function Get-SnapshotDiff($Prev, $Checks) {
        $sev = @{ 'OK' = 0; 'Info' = 0; 'Attenzione' = 1; 'Critico' = 2 }
        $rows = @()
        foreach ($c in $Checks) {
            $p = @($Prev.Checks | Where-Object { $_.Id -eq $c.Id })[0]
            $before = if ($p) { [string]$p.Esito } else { '(nuovo controllo)' }
            $var = 'Invariato'
            if ($p -and $sev.ContainsKey($before) -and $sev.ContainsKey([string]$c.Esito)) {
                $a = $sev[$before]; $b = $sev[[string]$c.Esito]
                if ($b -gt $a -and $a -eq 0) { $var = 'Nuovo rischio' } elseif ($b -gt $a) { $var = 'Peggiorato' } elseif ($b -lt $a -and $b -eq 0) { $var = 'Risolto' } elseif ($b -lt $a) { $var = 'Migliorato' }
            } elseif (-not $p) { $var = 'Nuovo controllo' }
            $newEv = 0
            if ($p) { $old = @($p.Evidenze); $newEv = @(@($c.Evidenze) | Where-Object { $old -notcontains $_ }).Count }
            if ($var -eq 'Invariato' -and $newEv -gt 0 -and $sev[[string]$c.Esito] -gt 0) { $var = 'Nuove evidenze' }
            $rows += [pscustomobject]@{ Id = $c.Id; Titolo = $c.Titolo; Prima = $before; Ora = $c.Esito; Variazione = $var; NuoveEvidenze = $newEv }
        }
        , $rows
    }

    # ------------------------------------------------------------------ report HTML della fotografia (stile _lib/report)

    function New-FotoHtml($Config, $Meta, $Checks, [string]$Base, $Prev) {
        $tone = @{ 'OK' = 'ok'; 'Info' = 'info'; 'Attenzione' = 'warn'; 'Critico' = 'err'; 'Non verificato' = 'neutral' }
        $order = @{ 'Critico' = 0; 'Attenzione' = 1; 'Non verificato' = 2; 'Info' = 3; 'OK' = 4 }
        $st = 'ok'
        if ($Meta.Punteggio -lt 50) { $st = 'err' } elseif ($Meta.Punteggio -lt 75) { $st = 'warn' }
        $hero = New-Object System.Collections.Generic.List[string]
        $hero.Add((New-RptScore ([int]$Meta.Punteggio) 'Punteggio' $st))
        foreach ($k in @('Critico', 'Attenzione', 'Non verificato', 'Info', 'OK')) {
            $hero.Add((New-RptKpi (@($Checks | Where-Object { $_.Esito -eq $k }).Count) $k $tone[$k]))
        }
        $diffRows = $null
        if ($Prev) {
            $delta = [int]$Meta.Punteggio - [int]$Prev.Meta.Punteggio
            $sign = ''
            if ($delta -gt 0) { $sign = '+' }
            $dt = 'neutral'
            if ($delta -gt 0) { $dt = 'ok' } elseif ($delta -lt 0) { $dt = 'err' }
            $hero.Add((New-RptKpi "$sign$delta" "rispetto al $($Prev.Meta.Data)" $dt))
            $diffRows = Get-SnapshotDiff $Prev $Checks
        }
        $body = New-Object System.Text.StringBuilder
        # riepilogo per categoria
        $cat = @(foreach ($g in @($Checks | Group-Object Categoria)) {
            [pscustomobject]@{
                Categoria = $g.Name; Controlli = $g.Count
                Critici = @($g.Group | Where-Object { $_.Esito -eq 'Critico' }).Count
                Attenzione = @($g.Group | Where-Object { $_.Esito -eq 'Attenzione' }).Count
                Punti = [int](($g.Group | Measure-Object -Property Punti -Sum).Sum)
            }
        })
        [void]$body.Append((New-RptTable -Title 'Rischio per categoria' -Rows $cat -StatusColumn '' -Columns @(
            @{ Name = 'Categoria'; Header = 'Categoria' }, @{ Name = 'Controlli'; Header = 'Controlli'; Num = $true }, @{ Name = 'Critici'; Header = 'Critici'; Num = $true },
            @{ Name = 'Attenzione'; Header = 'Attenzione'; Num = $true }, @{ Name = 'Punti'; Header = 'Punti di rischio'; Num = $true })))
        if ($diffRows) {
            $changed = @($diffRows | Where-Object { $_.Variazione -ne 'Invariato' })
            $note = "Confronto con $([System.IO.Path]::GetFileName($Prev.File)): $($changed.Count) variazioni"
            [void]$body.Append((New-RptTable -Title $note -Rows $changed -StatusColumn 'Variazione' -Columns @(
                @{ Name = 'Variazione'; Header = 'Variazione'; Badge = $true }, @{ Name = 'Id'; Header = 'ID'; Mono = $true }, @{ Name = 'Titolo'; Header = 'Controllo' },
                @{ Name = 'Prima'; Header = 'Prima'; Badge = $true }, @{ Name = 'Ora'; Header = 'Ora'; Badge = $true }, @{ Name = 'NuoveEvidenze'; Header = 'Nuove evidenze'; Num = $true })))
        }
        foreach ($g in @($Checks | Group-Object Categoria)) {
            $items = New-Object System.Text.StringBuilder
            foreach ($c in @($g.Group | Sort-Object { $order[$_.Esito] }, Id)) {
                $t = $tone[[string]$c.Esito]
                if (-not $t) { $t = 'neutral' }
                $pts = ''
                if ($c.Punti) { $pts = "<span class=`"muted`">$($c.Punti) punti</span>" }
                [void]$items.Append("<details class=`"item`" data-row data-s=`"$(ConvertTo-RptHtml $c.Esito)`"><summary>$(New-RptBadge ([string]$c.Esito) $t)<span class=`"mono muted`">$(ConvertTo-RptHtml $c.Id)</span><span class=`"t`">$(ConvertTo-RptHtml $c.Titolo)</span>$pts</summary><div class=`"det`"><div class=`"kv`">")
                [void]$items.Append("<b>Esito</b><span>$(ConvertTo-RptHtml $c.Sintesi)</span>")
                if ($c.Remediation -and $c.Esito -ne 'OK') { [void]$items.Append("<b>Cosa fare</b><span>$(ConvertTo-RptHtml $c.Remediation)</span>") }
                [void]$items.Append("<b>Richiede</b><span>$(ConvertTo-RptHtml $c.Richiede)</span></div>")
                $ev = @($c.Evidenze)
                if ($ev.Count) { [void]$items.Append("<div style=`"margin-top:10px`" class=`"mono`">$((@($ev) | ForEach-Object { ConvertTo-RptHtml $_ }) -join '<br>')</div>") }
                [void]$items.Append('</div></details>')
            }
            [void]$body.Append("<section class=`"card`" data-filter><h2>$(ConvertTo-RptHtml $g.Name) <span class=`"n`"></span></h2><div class=`"toolbar`"><input type=`"search`" placeholder=`"Cerca nei controlli e nelle evidenze...`">")
            foreach ($k in @('Critico', 'Attenzione', 'Non verificato', 'Info', 'OK')) {
                $n = @($g.Group | Where-Object { $_.Esito -eq $k }).Count
                if ($n) { [void]$body.Append("<span class=`"chip`" data-v=`"$k`">$k<span class=`"c`">$n</span></span>") }
            }
            [void]$body.Append("</div>$($items.ToString())</section>")
        }
        [void]$body.Append("<p class=`"muted`">Fotografia in sola lettura: nessuna modifica al dominio. File: $(ConvertTo-RptHtml $Base).json, _controlli.csv, _evidenze.csv</p>")
        $sub = "Dominio $($Meta.Dominio) - DC $($Meta.DC) - $($Meta.Data) - $($Meta.Eseguito) su $($Meta.Da) - $($Tool.Title) $($Tool.Version)"
        $html = New-RptDocument -Title "Fotografia di sicurezza Active Directory - $($Meta.Dominio)" -Subtitle $sub -Badge 'AD' -HeroHtml ($hero -join '') -BodyHtml $body.ToString()
        [System.IO.File]::WriteAllText("$Base.html", $html, (New-Object System.Text.UTF8Encoding($true)))
        "$Base.html"
    }

    # ------------------------------------------------------------------ ripristino dai backup dell'hardening

    # Come si annulla ogni azione (Kind) e cosa non e' annullabile in automatico
    function Get-RestoreKind([string]$Id) {
        switch -Regex ($Id) {
            '^HD-(SENSITIVE|ASREP|DES|REVERSIBLE|PWDNOTREQD|GUEST)$' { return 'Uac' }
            '^HD-(DC|MB)-' { return 'GpoRegistry' }
            '^HD-INACTIVE-' { return 'Inactive' }
            '^HD-(PRE2K|SCHEMA)$' { return 'GroupReadd' }
            '^HD-PROTUSERS$' { return 'GroupRemove' }
            '^HD-MAQ$' { return 'Maq' }
            '^HD-PWDPOL$' { return 'PwdPol' }
            '^HD-ADMINPSO$' { return 'Pso' }
            '^HD-ADMINCOUNT$' { return 'AdminCount' }
            '^HD-(DC-AUDIT|LAPS-GPO|TIER-LOGON)$' { return 'GpoUnlink' }
            default { return '' }
        }
    }

    function Get-RestoreItems($Config) {
        Initialize-Hardening $Config
        $dir = [string]$Config.RestoreFolder
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { throw 'Indicare la cartella di un''esecuzione di hardening (Hardening_<dominio>_<data>) nel campo "Cartella da ripristinare".' }
        Write-ToolLog "Ripristino - backup in $dir" 'STEP'
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.backup.json' -File | Sort-Object LastWriteTime -Descending)) {
            $b = $null
            try { $b = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
            $id = if ($b) { [string]$b.Id } else { $f.Name }
            $kind = Get-RestoreKind $id
            $state = 'Annullabile'
            if (-not $b) { $state = 'Backup non leggibile' } elseif (-not $kind) { $state = 'Non annullabile in automatico (vedi report di hardening)' }
            [pscustomobject]@{
                Key = $f.FullName; Utente = $id; SID = ''; Origine = $f.Name
                Id = $id; Categoria = 'Ripristino'; Controllo = "Annulla $id (backup del $(if ($b) { $b.Date } else { '?' }) di $(if ($b) { $b.By } else { '?' }))"
                Peso = ''; Richiede = 'Domain Admins'; Stato = $state; Selectable = [bool]($b -and $kind); File = $f.FullName
            }
        }
    }

    function Invoke-RestoreItem($Config, $Item) {
        Initialize-Hardening $Config
        $ctx = Get-AdContext $Config
        $b = Get-Content -LiteralPath $Item.Key -Raw -Encoding UTF8 | ConvertFrom-Json
        $kind = Get-RestoreKind ([string]$b.Id)
        $data = $b.Data
        $plan = @()
        $do = -not $Config.DryRun
        switch ($kind) {
            'Uac' {
                foreach ($a in @($data)) {
                    # solo i bit modificati dall'hardening: le altre modifiche successive (es. account disattivato) restano
                    $mask = [int]$a.OldUac -bxor [int]$a.NewUac
                    $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$a.Dn).Replace('/', '\/'))"
                    $now = [int]$de.Properties['userAccountControl'].Value
                    $target = ($now -band (-bnot $mask)) -bor ([int]$a.OldUac -band $mask)
                    if ($target -eq $now) { $plan += "$($a.Account): gia' come prima"; continue }
                    $plan += "$($a.Account): userAccountControl 0x$('{0:X}' -f $now) -> 0x$('{0:X}' -f $target)"
                    if ($do) { $de.Properties['userAccountControl'].Value = $target; $de.CommitChanges() }
                }
            }
            'GpoRegistry' {
                foreach ($v in @($data)) {
                    $g = Get-GPO -Name ([string]$v.Gpo) -ErrorAction Stop
                    if ($null -eq $v.Old) {
                        $plan += "$($v.Gpo): rimuovi $($v.Key)\$($v.Name)"
                        if ($do) { Remove-GPRegistryValue -Guid $g.Id -Key $v.Key -ValueName $v.Name -ErrorAction SilentlyContinue | Out-Null }
                    } else {
                        $plan += "$($v.Gpo): $($v.Key)\$($v.Name) = $(@($v.Old) -join ', ')"
                        # tipo del valore precedente (backup recenti), altrimenti quello impostato dall'hardening; DWord per i backup vecchi
                        $type = if ($v.OldType) { [string]$v.OldType } elseif ($v.Type) { [string]$v.Type } else { 'DWord' }
                        $val = switch ($type) { 'DWord' { [int]$v.Old } 'QWord' { [int64]$v.Old } 'MultiString' { [string[]]@($v.Old) } default { [string]$v.Old } }
                        if ($do) { Set-GPRegistryValue -Guid $g.Id -Key $v.Key -ValueName $v.Name -Type $type -Value $val | Out-Null }
                    }
                }
            }
            'Inactive' {
                foreach ($a in @($data)) {
                    $cur = @(Search-Ldap $Config ('(sAMAccountName={0})' -f (ConvertTo-LdapValue ([string]$a.Account))) @('distinguishedName'))[0]
                    if (-not $cur) { $plan += "$($a.Account): non trovato"; continue }
                    $origParent = ([string]$a.Dn) -replace '^(?:[^,\\]|\\.)+,', ''
                    $plan += "$($a.Account): riattiva, ripristina la descrizione" + $(if ([string]$cur.distinguishedName -ne [string]$a.Dn) { " e riporta in $origParent" } else { '' })
                    if ($do) {
                        $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$cur.distinguishedName).Replace('/', '\/'))"
                        # si toglie solo la disattivazione fatta dall'hardening (bit 2), il resto di userAccountControl resta com'e'
                        $now = [int]$de.Properties['userAccountControl'].Value
                        if (-not ([int]$a.OldUac -band 2)) { $now = $now -band (-bnot 2) }
                        $de.Properties['userAccountControl'].Value = $now
                        if ($a.Description) { $de.Properties['description'].Value = [string]$a.Description } else { $de.Properties['description'].Clear() }
                        $de.CommitChanges()
                        if ([string]$cur.distinguishedName -ne [string]$a.Dn) { Move-ADObject -Identity ([string]$cur.distinguishedName) -TargetPath $origParent }
                    }
                }
            }
            'GroupReadd' {
                $gdn = if ([string]$b.Id -eq 'HD-SCHEMA') { Get-SidDn $Config "$($ctx.Sid)-518" } else { Get-SidDn $Config 'S-1-5-32-554' }
                $de = [adsi]"LDAP://$($ctx.Dc)/$($gdn.Replace('/', '\/'))"
                foreach ($m in @($data.Removed)) {
                    $plan += "Riaggiungi $m"
                    if ($do -and -not ($de.Properties['member'] -contains [string]$m)) { [void]$de.Properties['member'].Add([string]$m) }
                }
                if ($do) { $de.CommitChanges() }
            }
            'GroupRemove' {
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-525").Replace('/', '\/'))"
                foreach ($m in @($data.Added)) {
                    $plan += "Togli da Protected Users: $m"
                    if ($do -and ($de.Properties['member'] -contains [string]$m)) { [void]$de.Properties['member'].Remove([string]$m) }
                }
                if ($do) { $de.CommitChanges() }
            }
            'Maq' {
                $plan += "ms-DS-MachineAccountQuota = $($data.Old)"
                if ($do) { $de = [adsi]"LDAP://$($ctx.Dc)/$($ctx.Dn)"; $de.Properties['ms-DS-MachineAccountQuota'].Value = [int]$data.Old; $de.CommitChanges() }
            }
            'PwdPol' {
                $plan += "Policy di dominio: minimo $($data.MinPasswordLength), complessita' $($data.ComplexityEnabled), blocco $($data.LockoutThreshold), cronologia $($data.PasswordHistoryCount)"
                if ($do) {
                    Set-ADDefaultDomainPasswordPolicy -Identity $ctx.Dn -MinPasswordLength ([int]$data.MinPasswordLength) -ComplexityEnabled ([bool]$data.ComplexityEnabled) -ReversibleEncryptionEnabled ([bool]$data.ReversibleEncryptionEnabled) `
                        -LockoutThreshold ([int]$data.LockoutThreshold) -LockoutDuration ([TimeSpan]::Parse([string]$data.LockoutDuration)) -LockoutObservationWindow ([TimeSpan]::Parse([string]$data.LockoutObservationWindow)) -PasswordHistoryCount ([int]$data.PasswordHistoryCount)
                }
            }
            'Pso' {
                $name = [string]$data.Pso
                if ($name -notlike "$($Config.GpoPrefix)-*") { throw "La PSO $name non e' stata creata da questo strumento: non la elimino." }
                $plan += "Elimina la PSO $name"
                if ($do) { Remove-ADFineGrainedPasswordPolicy -Identity $name -Confirm:$false }
            }
            'AdminCount' {
                foreach ($dn in @($data)) {
                    $plan += "adminCount = 1 su $dn"
                    if ($do) { $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$dn).Replace('/', '\/'))"; $de.Properties['adminCount'].Value = 1; $de.CommitChanges() }
                }
            }
            'GpoUnlink' {
                $names = @(@($data.Gpo) | ForEach-Object { ([string]$_ -split ':')[0].Trim() } | Where-Object { $_ })
                foreach ($n in $names) {
                    $g = $null
                    try { $g = Get-GPO -Name $n -ErrorAction Stop } catch { $plan += "$n non trovata"; continue }
                    $links = @(Get-GpoLinkTargets $Config $g)
                    $plan += "Disattiva i collegamenti di '$n' ($($links.Count))"
                    if ($do) { foreach ($t in $links) { Set-GPLink -Guid $g.Id -Target $t -LinkEnabled No | Out-Null } }
                }
            }
            default { throw 'Azione non annullabile in automatico.' }
        }
        foreach ($p in $plan) { Write-ToolLog "    $p" }
        $esito = 'OK'
        $msg = ($plan -join '; ')
        if (-not $do) { $esito = 'Simulato'; $msg = 'Verrebbe eseguito: ' + $msg }
        $dati = [pscustomobject]@{ Id = [string]$b.Id; Categoria = 'Ripristino'; Titolo = "Annulla $($b.Id)"; Impatto = ''; Richiede = 'Domain Admins'; Prima = "Backup del $($b.Date) di $($b.By)"; Piano = ($plan -join '; '); Esito = $esito; Messaggio = $msg; Dopo = ''; Annullamento = '' }
        @{ Esito = $esito; Messaggio = $msg; Dati = $dati }
    }

    # OU e dominio a cui e' collegata una GPO (dal report XML della GPO)
    function Get-GpoLinkTargets($Config, $Gpo) {
        $ctx = Get-AdContext $Config
        $guid = "{$($Gpo.Id)}"
        @(Search-Ldap $Config ('(gPLink=*{0}*)' -f $guid) @('distinguishedName') | ForEach-Object { [string]$_.distinguishedName })
    }
    #endregion
