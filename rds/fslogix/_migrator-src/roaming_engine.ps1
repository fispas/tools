
    #region SPECIFICO: Roaming -> FSLogix

    function Get-ToolDefaultConfig {
        $n = Get-DefaultNaming
        [ordered]@{
            SourcePath      = ''
            DestinationPath = ''
            Domain          = [string]$env:USERDOMAIN
            SuffixRegex     = '\.V\d+$'
            VolumeType      = $n.VolumeType
            SizeMB          = $n.SizeMB
            DiskType        = $n.DiskType
            FolderPattern   = $n.FolderPattern
            DiskNamePattern = $n.DiskNamePattern
            ProfileRoot     = 'C:\Users'
            ExistingDisk    = 'Salta'
            SetProfileAcl   = $true
            SetFolderAcl    = $true
            RobocopyThreads = 8
            RobocopyRetries = 2
            ExcludeDirs     = @()
            CleanupOnError  = $true
            ExcludeUsers    = @()
            LogDir          = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun          = $true
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue)) { $w += 'Cmdlet Mount-DiskImage non disponibile (modulo Storage): il montaggio dei dischi non funzionera.' }
        if (-not (Get-Command diskpart.exe -ErrorAction SilentlyContinue)) { $w += 'diskpart.exe non trovato.' }
        if (-not (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) { $w += 'robocopy.exe non trovato.' }
        if (-not $env:USERDNSDOMAIN) { $w += 'Sessione non di dominio: la risoluzione degli utenti potrebbe non funzionare.' }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if (-not $Config.SourcePath) { $e += 'Indicare la cartella dei profili Roaming.' }
        elseif (-not (Test-Path -LiteralPath $Config.SourcePath -PathType Container)) { $e += "Cartella di origine non trovata: $($Config.SourcePath)" }
        try { [void][regex]::new([string]$Config.SuffixRegex) } catch { $e += "Espressione del suffisso non valida: $($Config.SuffixRegex)" }
        if ($Scan) { return $e }
        if (-not $Config.DestinationPath) { $e += 'Indicare la cartella FSLogix di destinazione.' }
        elseif ($Config.SourcePath -and $Config.SourcePath.TrimEnd('\') -eq $Config.DestinationPath.TrimEnd('\')) { $e += 'Origine e destinazione coincidono.' }
        if ($Config.FolderPattern -notmatch '%(sid|username)%') { $e += 'Il nome cartella deve contenere %sid% e/o %username%.' }
        if ($Config.DiskNamePattern -notmatch '%(sid|username)%') { $e += 'Il nome disco deve contenere %username% e/o %sid%.' }
        if ($Config.SizeMB -lt 1024) { $e += 'Dimensione del disco troppo piccola (minimo 1024 MB).' }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        $e
    }

    function Get-ToolItems($Config) {
        Write-ToolLog "Analisi di $($Config.SourcePath)" 'STEP'
        $dirs = @(Get-ChildItem -LiteralPath $Config.SourcePath -Directory -Force -ErrorAction Stop | Sort-Object Name)
        Write-ToolLog "Cartelle trovate: $($dirs.Count)"
        $ext = '.' + ([string]$Config.VolumeType).ToLower()
        foreach ($d in $dirs) {
            $sam = $d.Name -replace $Config.SuffixRegex, ''
            $sid = $null
            if ($sam) { $sid = Resolve-AccountSid -Domain $Config.Domain -Sam $sam }
            $acc = $null
            if ($sid) { $acc = Resolve-SidAccount $sid }
            $stato = 'Pronto'; $sel = $true
            if (-not $sid) { $stato = 'Utente non trovato'; $sel = $false }
            elseif (Test-ExcludedUser $Config $sam) { $stato = 'Escluso'; $sel = $false }
            elseif (-not (Test-Path -LiteralPath (Join-Path $d.FullName 'NTUSER.DAT'))) { $stato = 'NTUSER.DAT assente' }
            if ($sel -and $Config.DestinationPath) {
                $t = Get-ProfileTarget -Config $Config -Sid $sid -Sam $sam -Domain $Config.Domain -Extension $ext
                if (Test-Path -LiteralPath $t.Disk) { $stato = "Esiste gia' ($($Config.ExistingDisk))" }
            }
            [pscustomobject]@{
                Key        = $d.FullName
                Utente     = $sam
                Nome       = $(if ($acc) { $acc.DisplayName } else { '' })
                SID        = [string]$sid
                Cartella   = $d.Name
                Modificato = $d.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                Stato      = $stato
                Selectable = $sel
                Origine    = $d.FullName
            }
        }
    }

    function New-ProfileVDisk([string]$Path, [int]$SizeMB, [bool]$Fixed) {
        $type = 'expandable'
        if ($Fixed) { $type = 'fixed' }
        $dp = Join-Path $env:TEMP ('FispaTools_dp_{0}.txt' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
        @(
            "create vdisk file=`"$Path`" maximum=$SizeMB type=$type"
            "select vdisk file=`"$Path`""
            'attach vdisk'
            'create partition primary'
            'format fs=ntfs quick label="Profile"'
            'detach vdisk'
        ) | Set-Content -LiteralPath $dp -Encoding ASCII
        try {
            $out = & diskpart.exe /s $dp 2>&1
            $rc = $LASTEXITCODE
        } finally { Remove-Item -LiteralPath $dp -Force -ErrorAction SilentlyContinue }
        if ($rc -ne 0 -or -not (Test-Path -LiteralPath $Path)) {
            Dismount-IfAttached $Path
            throw ('Creazione del disco con diskpart non riuscita (exit {0}): {1}' -f $rc, ((@($out) | Where-Object { "$_".Trim() } | Select-Object -Last 6) -join ' | '))
        }
        Write-ToolLog ('Disco creato: {0} ({1} MB, {2})' -f $Path, $SizeMB, $type)
    }

    function Invoke-ToolItem($Config, $Item) {
        $res = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
        $src = $Item.Origine
        if (-not (Test-Path -LiteralPath $src)) { throw "Cartella profilo non piu' raggiungibile: $src" }
        $ext = '.' + ([string]$Config.VolumeType).ToLower()
        $t = Get-ProfileTarget -Config $Config -Sid $Item.SID -Sam $Item.Utente -Domain $Config.Domain -Extension $ext
        $res.Destinazione = $t.Disk
        Write-ToolLog "Origine:      $src"
        Write-ToolLog "Destinazione: $($t.Disk)"
        if (-not (Resolve-ExistingDisk -Config $Config -DiskPath $t.Disk)) {
            $res.Esito = 'Saltato'; $res.Messaggio = "Disco FSLogix gia' presente"
            return $res
        }
        $fixed = $Config.DiskType -eq 'Fisso'
        if ($fixed) { Assert-FreeSpace -Path $Config.DestinationPath -Bytes ([double]$Config.SizeMB * 1MB) }
        if ($Config.DryRun) {
            Write-ToolLog ('[Simulazione] nuovo disco {0} MB {1}, copia robocopy in \Profile, permessi, ProfileData.reg' -f $Config.SizeMB, $Config.DiskType)
            $res.Esito = 'Simulato'
            return $res
        }

        $created = $false; $mount = $null; $ok = $false
        try {
            New-Item -ItemType Directory -Path $t.Folder -Force | Out-Null
            $created = $true
            New-ProfileVDisk -Path $t.Disk -SizeMB $Config.SizeMB -Fixed $fixed
            $mount = Mount-VDisk $t.Disk
            $profileDir = Join-Path $mount.Root 'Profile'
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
            $rlog = Join-Path $State.LogDir ('robocopy_{0}.log' -f $Item.Utente)
            $rArgs = @($src, $profileDir, '/E', '/ZB', '/COPY:DAT', '/DCOPY:DAT', '/XJ',
                "/R:$($Config.RobocopyRetries)", '/W:2', "/MT:$($Config.RobocopyThreads)", '/NP', '/NFL', '/NDL', "/UNILOG+:$rlog")
            if (@($Config.ExcludeDirs).Count) { $rArgs += '/XD'; $rArgs += @($Config.ExcludeDirs) }
            Write-ToolLog 'Copia del profilo con robocopy in corso...'
            & robocopy.exe @rArgs | Out-Null
            $rc = $LASTEXITCODE
            if ($rc -ge 8) { throw "Copia del profilo non riuscita (robocopy exit $rc, log: $rlog)" }
            Write-ToolLog "Copia completata (robocopy exit $rc)."
            if ($Config.SetProfileAcl) { Set-ProfileFolderAcl -Path $profileDir -Sid $Item.SID }
            New-ProfileDataReg -ProfileDir $profileDir -Sid $Item.SID -Sam $Item.Utente -Config $Config
            $ok = $true
        } finally {
            if ($mount -and -not (Dismount-VDisk $mount)) { $ok = $false }
            if (-not $ok -and $created) { Remove-PartialDisk -Config $Config -Path $t.Disk }
        }
        if (-not $ok) { throw 'Il disco non e'' stato smontato correttamente.' }
        if ($Config.SetFolderAcl) { Set-ProfileFolderAcl -Path $t.Folder -Sid $Item.SID }
        $res.DimensioneMB = Test-DiskValid $t.Disk
        $res.Esito = 'OK'
        $res
    }
    #endregion
