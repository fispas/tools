
    #region SPECIFICO: profili locali -> FSLogix (frx.exe)

    function Get-ToolDefaultConfig {
        $n = Get-DefaultNaming
        [ordered]@{
            DestinationPath      = ''
            VolumeType           = $n.VolumeType
            SizeMB               = $n.SizeMB
            DiskType             = $n.DiskType
            FolderPattern        = $n.FolderPattern
            DiskNamePattern      = $n.DiskNamePattern
            ExistingDisk         = 'Salta'
            IncludeLocalAccounts = $false
            SetFolderAcl         = $true
            CleanupOnError       = $true
            EnableLongPaths      = $false
            FrxPath              = (Get-DefaultFrxPath)
            ExcludeUsers         = @()
            LogDir               = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun               = $true
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not (Test-Path -LiteralPath $Config.FrxPath)) { $w += "frx.exe non trovato in $($Config.FrxPath): FSLogix deve essere installato su questa macchina." }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if ($Scan) { return $e }
        if (-not $Config.DestinationPath) { $e += 'Indicare la cartella FSLogix di destinazione.' }
        if (-not (Test-Path -LiteralPath $Config.FrxPath)) { $e += "frx.exe non trovato: $($Config.FrxPath)" }
        if ($Config.FolderPattern -notmatch '%(sid|username)%') { $e += 'Il nome cartella deve contenere %sid% e/o %username%.' }
        if ($Config.DiskNamePattern -notmatch '%(sid|username)%') { $e += 'Il nome disco deve contenere %username% e/o %sid%.' }
        if ($Config.SizeMB -lt 1024) { $e += 'Dimensione del disco troppo piccola (minimo 1024 MB).' }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        $e
    }

    function Test-ProfileLoaded([string]$Sid) {
        $k = [Microsoft.Win32.Registry]::Users.OpenSubKey($Sid)
        if ($k) { $k.Close(); return $true }
        $false
    }

    function Get-ToolItems($Config) {
        $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        Write-ToolLog 'Analisi dei profili registrati in ProfileList' 'STEP'
        $keys = @(Get-ChildItem -LiteralPath $base -ErrorAction Stop)
        $bak = @($keys | Where-Object { $_.PSChildName -like '*.bak' } | ForEach-Object { $_.PSChildName -replace '\.bak$', '' })
        $ext = '.' + ([string]$Config.VolumeType).ToLower()
        foreach ($k in @($keys | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
            $sid = $k.PSChildName
            $path = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).ProfileImagePath)
            $acc = Resolve-SidAccount $sid
            $isLocal = $acc -and ($acc.Domain -eq $env:COMPUTERNAME)
            $ntuser = $null
            $hasNtuser = $false
            if ($path) { $ntuser = Join-Path $path 'NTUSER.DAT'; $hasNtuser = Test-Path -LiteralPath $ntuser }
            $last = ''
            if ($hasNtuser) { $last = (Get-Item -LiteralPath $ntuser -Force).LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            $stato = 'Pronto'; $sel = $true
            if (-not $acc) { $stato = 'Account non risolto'; $sel = $false }
            elseif ($isLocal -and -not $Config.IncludeLocalAccounts) { $stato = 'Account locale'; $sel = $false }
            elseif (Test-ExcludedUser $Config $acc.Sam) { $stato = 'Escluso'; $sel = $false }
            elseif ($bak -contains $sid) { $stato = 'Profilo temporaneo/corrotto (.bak)'; $sel = $false }
            elseif (-not $path -or -not (Test-Path -LiteralPath $path)) { $stato = 'Cartella profilo assente'; $sel = $false }
            elseif (Test-ProfileLoaded $sid) { $stato = 'Profilo caricato (utente connesso)'; $sel = $false }
            elseif ($hasNtuser -and -not (Test-FileExclusive $ntuser)) { $stato = 'NTUSER.DAT in uso'; $sel = $false }
            elseif ($Config.DestinationPath) {
                $t = Get-ProfileTarget -Config $Config -Sid $sid -Sam $acc.Sam -Domain $acc.Domain -Extension $ext
                if (Test-Path -LiteralPath $t.Disk) { $stato = "Esiste gia' ($($Config.ExistingDisk))" }
            }
            [pscustomobject]@{
                Key        = $sid
                Utente     = $(if ($acc) { $acc.Sam } else { '' })
                Nome       = $(if ($acc) { $acc.DisplayName } else { '' })
                Dominio    = $(if ($acc) { $acc.Domain } else { '' })
                SID        = $sid
                Cartella   = $path
                UltimoUso  = $last
                Stato      = $stato
                Selectable = $sel
                Origine    = $path
            }
        }
    }

    function Invoke-ToolItem($Config, $Item) {
        $res = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
        if (Test-ProfileLoaded $Item.SID) {
            $res.Esito = 'Saltato'; $res.Messaggio = 'Profilo caricato: utente connesso'
            return $res
        }
        $ntuser = Join-Path $Item.Origine 'NTUSER.DAT'
        if ((Test-Path -LiteralPath $ntuser) -and -not (Test-FileExclusive $ntuser)) {
            $res.Esito = 'Saltato'; $res.Messaggio = 'NTUSER.DAT in uso'
            return $res
        }
        $ext = '.' + ([string]$Config.VolumeType).ToLower()
        $t = Get-ProfileTarget -Config $Config -Sid $Item.SID -Sam $Item.Utente -Domain $Item.Dominio -Extension $ext
        $res.Destinazione = $t.Disk
        Write-ToolLog "Origine:      $($Item.Origine)"
        Write-ToolLog "Destinazione: $($t.Disk)"
        if (-not (Resolve-ExistingDisk -Config $Config -DiskPath $t.Disk)) {
            $res.Esito = 'Saltato'; $res.Messaggio = "Disco FSLogix gia' presente"
            return $res
        }
        if ($Config.DiskType -eq 'Fisso') { Assert-FreeSpace -Path $Config.DestinationPath -Bytes ([double]$Config.SizeMB * 1MB) }
        $dynamic = 1
        if ($Config.DiskType -eq 'Fisso') { $dynamic = 0 }
        $frxArgs = 'copy-profile -filename "{0}" -sid {1} -size-mbs {2} -dynamic {3} -verbose' -f $t.Disk, $Item.SID, $Config.SizeMB, $dynamic
        if ($Config.DryRun) {
            Write-ToolLog "[Simulazione] frx.exe $frxArgs"
            $res.Esito = 'Simulato'
            return $res
        }

        if ($Config.EnableLongPaths) {
            $fs = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
            if ((Get-ItemProperty -LiteralPath $fs -Name LongPathsEnabled -ErrorAction SilentlyContinue).LongPathsEnabled -ne 1) {
                New-ItemProperty -LiteralPath $fs -Name LongPathsEnabled -Value 1 -PropertyType DWord -Force | Out-Null
                Write-ToolLog 'LongPathsEnabled impostato a 1.' 'WARN'
            }
        }
        New-Item -ItemType Directory -Path $t.Folder -Force | Out-Null
        $ok = $false
        try {
            Write-ToolLog 'Copia del profilo con frx.exe in corso...'
            $p = Invoke-ProcessCapture -FilePath $Config.FrxPath -Arguments $frxArgs
            foreach ($l in @(($p.StdOut + "`n" + $p.StdErr) -split "`r?`n" | Where-Object { $_.Trim() })) { Write-ToolLog "  frx: $l" }
            if ($p.ExitCode -ne 0) { throw "frx.exe terminato con codice $($p.ExitCode)" }
            $res.DimensioneMB = Test-DiskValid $t.Disk
            $ok = $true
        } finally {
            if (-not $ok) { Remove-PartialDisk -Config $Config -Path $t.Disk }
        }
        if ($Config.SetFolderAcl) { Set-ProfileFolderAcl -Path $t.Folder -Sid $Item.SID }
        $res.Esito = 'OK'
        $res
    }
    #endregion
