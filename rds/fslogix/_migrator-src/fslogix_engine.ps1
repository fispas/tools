
    #region COMUNE AI MIGRATORI FSLOGIX (naming, dischi, permessi, ProfileData.reg)

    function Get-FSLogixValue([string]$Name) {
        try { (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\FSLogix\Profiles' -Name $Name -ErrorAction Stop).$Name } catch { $null }
    }

    # Valori di default letti dalla configurazione FSLogix della macchina, se presente
    function Get-DefaultNaming {
        $folder = Get-FSLogixValue 'SIDDirNamePattern'
        if (-not $folder) {
            if ((Get-FSLogixValue 'FlipFlopProfileDirectoryName') -eq 1) { $folder = '%username%_%sid%' } else { $folder = '%sid%_%username%' }
        }
        $disk = Get-FSLogixValue 'VHDNamePattern'
        if (-not $disk) { $disk = 'Profile_%username%' }
        $disk = $disk -replace '\.vhdx?$', ''
        $size = Get-FSLogixValue 'SizeInMBs'
        if (-not $size) { $size = 30000 }
        $vt = [string](Get-FSLogixValue 'VolumeType')
        if ($vt -notin @('VHD', 'VHDX')) { $vt = 'VHDX' }
        $dyn = Get-FSLogixValue 'IsDynamic'
        $diskType = 'Dinamico'
        if ($null -ne $dyn -and [int]$dyn -eq 0) { $diskType = 'Fisso' }
        @{ FolderPattern = $folder; DiskNamePattern = $disk; SizeMB = [int]$size; VolumeType = $vt.ToUpper(); DiskType = $diskType }
    }

    function Get-DefaultFrxPath {
        $dir = $null
        try { $dir = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\FSLogix\Apps' -Name InstallPath -ErrorAction Stop).InstallPath } catch { }
        if (-not $dir) { $dir = Join-Path $env:ProgramFiles 'FSLogix\Apps' }
        Join-Path $dir 'frx.exe'
    }

    # Cartella e disco di destinazione secondo i pattern FSLogix (%sid%, %username%, %userdomain%)
    function Get-ProfileTarget($Config, [string]$Sid, [string]$Sam, [string]$Domain, [string]$Extension) {
        $expand = {
            param([string]$Pattern)
            $r = $Pattern -replace '%sid%', $Sid.Replace('$', '$$')
            $r = $r -replace '%username%', $Sam.Replace('$', '$$')
            $r = $r -replace '%userdomain%', ([string]$Domain).Replace('$', '$$')
            foreach ($c in [System.IO.Path]::GetInvalidFileNameChars()) { $r = $r.Replace([string]$c, '_') }
            $r
        }
        $folderName = & $expand $Config.FolderPattern
        $diskName = (& $expand ($Config.DiskNamePattern -replace '\.vhdx?$', '')) + $Extension.ToLower()
        $folder = Join-Path $Config.DestinationPath $folderName
        [pscustomobject]@{ Folder = $folder; Disk = (Join-Path $folder $diskName) }
    }

    # Gestione di un disco FSLogix gia' presente. $true = procedere, $false = saltare
    function Resolve-ExistingDisk($Config, [string]$DiskPath) {
        if (-not (Test-Path -LiteralPath $DiskPath)) { return $true }
        switch ($Config.ExistingDisk) {
            'Salta' {
                Write-ToolLog "Disco FSLogix gia' presente, utente saltato: $DiskPath" 'WARN'
                return $false
            }
            default {
                if (-not (Test-FileExclusive $DiskPath)) { throw "Il disco FSLogix esistente e' in uso: $DiskPath" }
                if ($Config.DryRun) {
                    Write-ToolLog "[Simulazione] disco esistente da gestire con '$($Config.ExistingDisk)': $DiskPath"
                    return $true
                }
                if ($Config.ExistingDisk -eq 'Sovrascrivi') {
                    Remove-Item -LiteralPath $DiskPath -Force -ErrorAction Stop
                    Write-ToolLog "Disco esistente eliminato: $DiskPath" 'WARN'
                } else {
                    $bak = '{0}.bak-{1}' -f (Split-Path -Leaf $DiskPath), (Get-Date -Format 'yyyyMMdd-HHmmss')
                    Rename-Item -LiteralPath $DiskPath -NewName $bak -ErrorAction Stop
                    Write-ToolLog "Disco esistente rinominato in $bak" 'WARN'
                }
                return $true
            }
        }
    }

    # Owner e permessi: utente (per SID, indipendente da nome dominio e lingua), SYSTEM, Administrators
    function Set-ProfileFolderAcl([string]$Path, [string]$Sid) {
        $out = & icacls.exe $Path /setowner "*$Sid" /T /C /Q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls /setowner su $Path non riuscito (exit $LASTEXITCODE): $(@($out) -join ' ')" }
        $out = & icacls.exe $Path /grant "*${Sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /C /Q 2>&1
        if ($LASTEXITCODE -ne 0) { throw "icacls /grant su $Path non riuscito (exit $LASTEXITCODE): $(@($out) -join ' ')" }
        Write-ToolLog "Permessi impostati su $Path"
    }

    function New-ProfileDataReg([string]$ProfileDir, [string]$Sid, [string]$Sam, $Config) {
        $regDir = Join-Path $ProfileDir 'AppData\Local\FSLogix'
        New-Item -ItemType Directory -Path $regDir -Force | Out-Null
        $regFile = Join-Path $regDir 'ProfileData.reg'
        if (Test-Path -LiteralPath $regFile) { Write-ToolLog "ProfileData.reg gia' presente, non modificato."; return }
        $root = ([string]$Config.ProfileRoot).TrimEnd('\')
        if (-not $root) { $root = 'C:\Users' }
        $image = ($root + '\' + $Sam).Replace('\', '\\')
        $lines = @(
            'Windows Registry Editor Version 5.00'
            ''
            "[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid]"
            "`"ProfileImagePath`"=`"$image`""
            '"Flags"=dword:00000000'
            '"State"=dword:00000000'
            '"ProfileLoadTimeLow"=dword:00000000'
            '"ProfileLoadTimeHigh"=dword:00000000'
            '"RefCount"=dword:00000000'
            '"RunLogonScriptSync"=dword:00000001'
            ''
        )
        [System.IO.File]::WriteAllText($regFile, ($lines -join "`r`n"), [System.Text.Encoding]::Unicode)
        Write-ToolLog "Creato ProfileData.reg (ProfileImagePath: $root\$Sam)"
    }

    # Monta un VHD/VHDX su una cartella temporanea: non dipende dalle lettere di unita' ne' dall'automount
    function Mount-VDisk([string]$Path) {
        $img = Get-DiskImage -ImagePath $Path -ErrorAction Stop
        if ($img.Attached) { throw "Il disco e' gia' montato (sessione utente o esecuzione precedente): $Path" }
        Mount-DiskImage -ImagePath $Path -NoDriveLetter -ErrorAction Stop | Out-Null
        $disk = $null
        for ($i = 0; $i -lt 30 -and -not $disk; $i++) {
            $disk = Get-DiskImage -ImagePath $Path | Get-Disk -ErrorAction SilentlyContinue
            if (-not $disk) { Start-Sleep -Seconds 1 }
        }
        if (-not $disk) {
            Dismount-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue | Out-Null
            throw "Disco montato ma non visibile al sistema: $Path"
        }
        if ($disk.IsOffline) { Set-Disk -Number $disk.Number -IsOffline $false }
        if ($disk.IsReadOnly) { Set-Disk -Number $disk.Number -IsReadOnly $false }
        $part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.Type -notin @('Reserved', 'System', 'Recovery', 'Unknown') } |
            Sort-Object Size -Descending | Select-Object -First 1
        if (-not $part) {
            Dismount-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue | Out-Null
            throw "Nessuna partizione dati trovata nel disco: $Path"
        }
        $folder = Join-Path $env:TEMP ('FispaTools_mnt_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        try {
            Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber -AccessPath ($folder + '\') -ErrorAction Stop
        } catch {
            Dismount-DiskImage -ImagePath $Path -ErrorAction SilentlyContinue | Out-Null
            try { [System.IO.Directory]::Delete($folder, $false) } catch { }
            throw "Impossibile collegare la partizione a $folder : $($_.Exception.Message)"
        }
        Write-ToolLog "Disco montato in $folder"
        [pscustomobject]@{ ImagePath = $Path; DiskNumber = $disk.Number; PartitionNumber = $part.PartitionNumber; Folder = $folder; Root = ($folder + '\') }
    }

    # Smonta e rimuove la cartella di montaggio. Restituisce $true se il disco non e' piu' montato
    function Dismount-VDisk($Mount) {
        if (-not $Mount) { return $true }
        try {
            Remove-PartitionAccessPath -DiskNumber $Mount.DiskNumber -PartitionNumber $Mount.PartitionNumber -AccessPath $Mount.Root -ErrorAction Stop
        } catch { Write-ToolLog "Rimozione del punto di montaggio non riuscita: $($_.Exception.Message)" 'WARN' }
        for ($i = 1; $i -le 3; $i++) {
            try { Dismount-DiskImage -ImagePath $Mount.ImagePath -ErrorAction Stop | Out-Null; break }
            catch { Write-ToolLog "Smontaggio tentativo $i non riuscito: $($_.Exception.Message)" 'WARN'; Start-Sleep -Seconds 3 }
        }
        $img = Get-DiskImage -ImagePath $Mount.ImagePath -ErrorAction SilentlyContinue
        if ($img -and $img.Attached) {
            Write-ToolLog "ATTENZIONE: il disco resta montato, smontarlo a mano: $($Mount.ImagePath)" 'ERROR'
            return $false
        }
        try { [System.IO.Directory]::Delete($Mount.Folder, $false) } catch { }
        Write-ToolLog 'Disco smontato.'
        $true
    }

    function Dismount-IfAttached([string]$Path) {
        try {
            $img = Get-DiskImage -ImagePath $Path -ErrorAction Stop
            if ($img.Attached) { Dismount-DiskImage -ImagePath $Path -ErrorAction Stop | Out-Null; Write-ToolLog "Disco smontato: $Path" 'WARN' }
        } catch { }
    }

    function Remove-PartialDisk($Config, [string]$Path) {
        if (-not $Config.CleanupOnError -or -not (Test-Path -LiteralPath $Path)) { return }
        Dismount-IfAttached $Path
        try { Remove-Item -LiteralPath $Path -Force -ErrorAction Stop; Write-ToolLog "Disco incompleto eliminato: $Path" 'WARN' }
        catch { Write-ToolLog "Impossibile eliminare il disco incompleto $Path : $($_.Exception.Message)" 'ERROR' }
    }

    function Test-DiskValid([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Disco non trovato a fine migrazione: $Path" }
        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -lt 1MB) { throw "Il disco risulta vuoto o danneggiato ($len byte): $Path" }
        [math]::Round($len / 1MB, 0)
    }
    #endregion
