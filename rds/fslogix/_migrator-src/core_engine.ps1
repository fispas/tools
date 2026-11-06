    #region MOTORE COMUNE (identico nei migratori FSLogix: una correzione qui va replicata negli altri)

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

    function Test-DiskValid([string]$Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Disco non trovato a fine migrazione: $Path" }
        $len = (Get-Item -LiteralPath $Path).Length
        if ($len -lt 1MB) { throw "Il disco risulta vuoto o danneggiato ($len byte): $Path" }
        [math]::Round($len / 1MB, 0)
    }

    function Invoke-ToolRun($Config, $Items) {
        $list = @($Items)
        $n = $list.Count
        $results = New-Object System.Collections.Generic.List[object]
        $mode = 'ESECUZIONE REALE'
        if ($Config.DryRun) { $mode = 'SIMULAZIONE (nessuna modifica)' }
        Write-ToolLog ('=== {0} {1} - {2} profili - {3}' -f $Tool.Title, $Tool.Version, $n, $mode) 'STEP'
        foreach ($k in @($Config.Keys)) { Write-ToolLog ('  {0} = {1}' -f $k, (@($Config[$k]) -join '; ')) }
        for ($i = 0; $i -lt $n; $i++) {
            $item = $list[$i]
            if ($State.Cancel) {
                for ($j = $i; $j -lt $n; $j++) {
                    $results.Add([pscustomobject]@{ Utente = $list[$j].Utente; SID = $list[$j].SID; Origine = $list[$j].Origine; Destinazione = ''; Esito = 'Annullato'; Messaggio = "Annullato dall'operatore"; DurataSec = 0; DimensioneMB = '' })
                    Send-ToolMessage @{ T = 'row'; K = $list[$j].Key; E = 'Annullato' }
                }
                Write-ToolLog "Annullato dall'operatore: $($n - $i) profili non elaborati." 'WARN'
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
            $lvl = switch ($r.Esito) { 'OK' { 'OK' } 'Fallito' { 'ERROR' } 'Saltato' { 'WARN' } default { 'INFO' } }
            $txt = $r.Esito
            if ($r.Messaggio) { $txt += " - $($r.Messaggio)" }
            Write-ToolLog ('{0}: {1} ({2:N0} s)' -f $item.Utente, $txt, $sw.Elapsed.TotalSeconds) $lvl
            Send-ToolMessage @{ T = 'row'; K = $item.Key; E = $r.Esito }
            $results.Add([pscustomobject]@{
                Utente = $item.Utente; SID = $item.SID; Origine = $item.Origine; Destinazione = $r.Destinazione
                Esito = $r.Esito; Messaggio = $r.Messaggio; DurataSec = [math]::Round($sw.Elapsed.TotalSeconds, 0); DimensioneMB = $r.DimensioneMB
            })
        }
        $State.ReportFile = Join-Path $State.LogDir ('{0}_Report_{1}.csv' -f $Tool.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
        try { $results | Export-Csv -LiteralPath $State.ReportFile -NoTypeInformation -Delimiter ';' -Encoding UTF8 -ErrorAction Stop }
        catch { Write-ToolLog "Report CSV non scritto: $($_.Exception.Message)" 'ERROR'; $State.ReportFile = $null }
        $count = @{}
        foreach ($e in @('OK', 'Simulato', 'Saltato', 'Fallito', 'Annullato')) { $count[$e] = @($results | Where-Object { $_.Esito -eq $e }).Count }
        $summary = 'Totale {0} | OK {1} | Simulati {2} | Saltati {3} | Falliti {4} | Annullati {5}' -f $n, $count.OK, $count.Simulato, $count.Saltato, $count.Fallito, $count.Annullato
        $lvl = 'OK'
        if ($count.Fallito -gt 0) { $lvl = 'ERROR' } elseif ($count.Saltato -gt 0 -or $count.Annullato -gt 0) { $lvl = 'WARN' }
        Write-ToolLog "=== Fine. $summary" $lvl
        if ($State.ReportFile) { Write-ToolLog "Report: $($State.ReportFile)" }
        Send-ToolMessage @{ T = 'done'; S = $summary; F = $count.Fallito; R = $State.ReportFile }
        , $results.ToArray()
    }
    #endregion
