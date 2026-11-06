
    #region SPECIFICO: UPD -> FSLogix

    function Get-ToolDefaultConfig {
        $n = Get-DefaultNaming
        [ordered]@{
            SourcePath      = ''
            DestinationPath = ''
            FolderPattern   = $n.FolderPattern
            DiskNamePattern = $n.DiskNamePattern
            ProfileRoot     = 'C:\Users'
            ExistingDisk    = 'Salta'
            SetFolderAcl    = $true
            CleanupOnError  = $true
            ExcludeUsers    = @()
            LogDir          = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun          = $true
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue)) { $w += 'Cmdlet Mount-DiskImage non disponibile (modulo Storage): il montaggio dei dischi non funzionera.' }
        if (-not (Get-Command robocopy.exe -ErrorAction SilentlyContinue)) { $w += 'robocopy.exe non trovato.' }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if (-not $Config.SourcePath) { $e += 'Indicare la cartella UPD di origine.' }
        elseif (-not (Test-Path -LiteralPath $Config.SourcePath -PathType Container)) { $e += "Cartella di origine non trovata: $($Config.SourcePath)" }
        if ($Scan) { return $e }
        if (-not $Config.DestinationPath) { $e += 'Indicare la cartella FSLogix di destinazione.' }
        elseif ($Config.SourcePath -and $Config.SourcePath.TrimEnd('\') -eq $Config.DestinationPath.TrimEnd('\')) { $e += 'Origine e destinazione coincidono.' }
        if ($Config.FolderPattern -notmatch '%(sid|username)%') { $e += 'Il nome cartella deve contenere %sid% e/o %username%.' }
        if ($Config.DiskNamePattern -notmatch '%(sid|username)%') { $e += 'Il nome disco deve contenere %username% e/o %sid%.' }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        $e
    }

    function Get-ToolItems($Config) {
        Write-ToolLog "Analisi di $($Config.SourcePath)" 'STEP'
        $files = @(Get-ChildItem -LiteralPath $Config.SourcePath -File -Force -ErrorAction Stop |
            Where-Object { $_.Name -match '^UVHD-S-1-5-21-[\d-]+\.vhdx?$' } | Sort-Object Name)
        Write-ToolLog "Dischi UPD trovati: $($files.Count)"
        foreach ($f in $files) {
            $sid = $f.BaseName.Substring(5)
            $acc = Resolve-SidAccount $sid
            $stato = 'Pronto'; $sel = $true
            if (-not $acc) { $stato = 'SID non risolto'; $sel = $false }
            elseif (Test-ExcludedUser $Config $acc.Sam) { $stato = 'Escluso'; $sel = $false }
            elseif (-not (Test-FileExclusive $f.FullName)) { $stato = 'In uso'; $sel = $false }
            elseif ($Config.DestinationPath) {
                $t = Get-ProfileTarget -Config $Config -Sid $sid -Sam $acc.Sam -Domain $acc.Domain -Extension $f.Extension
                if (Test-Path -LiteralPath $t.Disk) { $stato = "Esiste gia' ($($Config.ExistingDisk))" }
            }
            [pscustomobject]@{
                Key          = $sid
                Utente       = $(if ($acc) { $acc.Sam } else { '' })
                Nome         = $(if ($acc) { $acc.DisplayName } else { '' })
                Domain       = $(if ($acc) { $acc.Domain } else { '' })
                SID          = $sid
                File         = $f.Name
                DimensioneMB = [math]::Round($f.Length / 1MB, 0)
                Modificato   = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                Stato        = $stato
                Selectable   = $sel
                Origine      = $f.FullName
                Extension    = $f.Extension
            }
        }
    }

    # Copia un file con robocopy (/J, adatto a file grandi) e lo rinomina nel nome finale
    function Copy-DiskFile([string]$Source, [string]$Destination) {
        $srcDir = Split-Path -Parent $Source
        $name = Split-Path -Leaf $Source
        $dstDir = Split-Path -Parent $Destination
        $log = Join-Path $State.LogDir ('robocopy_{0}.log' -f [System.IO.Path]::GetFileNameWithoutExtension($name))
        & robocopy.exe $srcDir $dstDir $name /J /R:2 /W:5 /NP /NJH /NJS "/UNILOG+:$log" | Out-Null
        $rc = $LASTEXITCODE
        $copied = Join-Path $dstDir $name
        if ($rc -ge 8) {
            if ($copied -ne $Source -and (Test-Path -LiteralPath $copied)) { Remove-Item -LiteralPath $copied -Force -ErrorAction SilentlyContinue }
            throw "Copia del disco non riuscita (robocopy exit $rc, log: $log)"
        }
        if ($copied -ne $Destination) { Rename-Item -LiteralPath $copied -NewName (Split-Path -Leaf $Destination) -ErrorAction Stop }
    }

    function Invoke-ToolItem($Config, $Item) {
        $res = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
        $src = $Item.Origine
        if (-not (Test-Path -LiteralPath $src)) { throw "Disco UPD non piu' raggiungibile: $src" }
        if (-not (Test-FileExclusive $src)) {
            $res.Esito = 'Saltato'; $res.Messaggio = 'Disco UPD in uso (utente connesso?)'
            return $res
        }
        $t = Get-ProfileTarget -Config $Config -Sid $Item.SID -Sam $Item.Utente -Domain $Item.Domain -Extension $Item.Extension
        $res.Destinazione = $t.Disk
        Write-ToolLog "Origine:      $src"
        Write-ToolLog "Destinazione: $($t.Disk)"
        if (-not (Resolve-ExistingDisk -Config $Config -DiskPath $t.Disk)) {
            $res.Esito = 'Saltato'; $res.Messaggio = "Disco FSLogix gia' presente"
            return $res
        }
        Assert-FreeSpace -Path $Config.DestinationPath -Bytes ((Get-Item -LiteralPath $src).Length * 1.05)
        if ($Config.DryRun) {
            Write-ToolLog "[Simulazione] copia del disco, spostamento del contenuto in \Profile, ProfileData.reg, permessi su $($t.Folder)"
            $res.Esito = 'Simulato'
            return $res
        }

        $created = $false; $mount = $null; $ok = $false
        try {
            New-Item -ItemType Directory -Path $t.Folder -Force | Out-Null
            Write-ToolLog 'Copia del disco UPD in corso...'
            $created = $true
            Copy-DiskFile -Source $src -Destination $t.Disk
            Write-ToolLog 'Copia completata. Montaggio della copia...'
            $mount = Mount-VDisk $t.Disk
            $profileDir = Join-Path $mount.Root 'Profile'
            if (-not (Test-Path -LiteralPath $profileDir)) { New-Item -ItemType Directory -Path $profileDir | Out-Null }
            $exclude = '^(Profile|Uvhd-Binding|\$RECYCLE\.BIN|System Volume Information)$'
            $moved = 0; $moveErr = @()
            foreach ($it in @(Get-ChildItem -LiteralPath $mount.Root -Force | Where-Object { $_.Name -notmatch $exclude })) {
                try { Move-Item -LiteralPath $it.FullName -Destination $profileDir -Force -ErrorAction Stop; $moved++ }
                catch { $moveErr += "$($it.Name): $($_.Exception.Message)" }
            }
            if ($moveErr.Count) { throw ('Spostamento in \Profile non riuscito per: ' + ($moveErr -join ' | ')) }
            Write-ToolLog "Elementi spostati in \Profile: $moved"
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
