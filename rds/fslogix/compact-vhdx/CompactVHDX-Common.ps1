<#
.SYNOPSIS
    Libreria comune di CompactVHDX (compattazione offline dei VHDX FSLogix).

.DESCRIPTION
    Usata da Compact-ProfileDisks.ps1, Stop-CompactVHDX.ps1 e CompactVHDX-Manager.ps1.
    Contiene: configurazione, inventario dei VHDX, report (situazione, singola run, storico),
    grafici SVG, pianificazione dei task (XML), eventi nel Registro applicazioni, email,
    pulizia di log/report vecchi, stop pulito e sgancio dei dischi rimasti agganciati.

    Va caricata con dot-sourcing:  . "$PSScriptRoot\CompactVHDX-Common.ps1"
#>

# ============================================================================
#  Costanti e percorsi
# ============================================================================
$script:CVVersion   = '2.0.0'
# la cartella di installazione e' quella che contiene questa libreria: lo strumento funziona ovunque venga installato
$script:CVBase      = if ($PSScriptRoot) { $PSScriptRoot } else { 'C:\Scripts\CompactVHDX' }
$script:CVDefaultBase = 'C:\Scripts\CompactVHDX'
$script:CVRegKey    = 'HKLM:\SOFTWARE\CompactVHDX'
$script:CVShortcutName = 'CompactVHDX Manager.lnk'
$script:CVLogDir    = "$script:CVBase\Log"
$script:CVDataDir   = "$script:CVBase\Data"
$script:CVConfig    = "$script:CVBase\config.json"
$script:CVStatus    = "$script:CVBase\status.json"
$script:CVStopFile  = "$script:CVBase\STOP"
$script:CVHistory   = "$script:CVDataDir\history.csv"
$script:CVIssuesLog = "$script:CVLogDir\Errori_e_avvisi.log"
$script:CVTaskJob     = 'FSLogix-CompactVHDX'
$script:CVTaskMonitor = 'FSLogix-CompactVHDX-Monitor'
$script:CVTaskManual  = 'FSLogix-CompactVHDX-Manual'
$script:CVEventSource = 'CompactVHDX'

$script:CVDaysIt   = @{ Monday = 'Lunedi'; Tuesday = 'Martedi'; Wednesday = 'Mercoledi'; Thursday = 'Giovedi'; Friday = 'Venerdi'; Saturday = 'Sabato'; Sunday = 'Domenica' }
$script:CVDayOrder = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
$script:CVMonths   = @('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')
$script:CVMonthsIt = @('Gen', 'Feb', 'Mar', 'Apr', 'Mag', 'Giu', 'Lug', 'Ago', 'Set', 'Ott', 'Nov', 'Dic')
$script:CVWeeksIt  = [ordered]@{ '1' = 'Primo'; '2' = 'Secondo'; '3' = 'Terzo'; '4' = 'Quarto'; 'Last' = 'Ultimo' }

# ============================================================================
#  Configurazione
# ============================================================================
function Get-CVDefaultConfig {
    [ordered]@{
        ConfigVersion  = 2
        SetupDone      = $false
        ProfilePaths   = @()          # una o piu' cartelle locali con i VHDX FSLogix (configurazione guidata)
        ReportDir      = "$script:CVBase\Report"
        ExcludeUsers   = @()
        RetentionDays  = 365
        FreeAlertPct   = 15
        FslogixSizeMB  = 30000
        StaleDays      = 90
        Mail = [ordered]@{
            Enabled      = $false
            Method       = 'Smtp'        # Smtp (relay anonimo) | Graph (Microsoft 365)
            TenantId     = ''
            ClientId     = ''
            SecretEnc    = ''            # segreto client cifrato con DPAPI (ambito macchina)
            SmtpServer   = ''
            Port         = 25
            UseSsl       = $false
            From         = ''
            To           = ''
            OnlyOnIssues = $false
        }
        Schedule = [ordered]@{
            Type             = 'Weekly'      # Daily | Weekly | MonthlyDays | MonthlyDow
            Interval         = 1             # ogni N giorni / settimane
            DaysOfWeek       = @('Sunday')
            DaysOfMonth      = @('1')        # 1..31 o 'Last'
            WeeksOfMonth     = @('1')        # 1..4 o 'Last'
            Months           = $script:CVMonths
            Start            = '21:00'
            StopEnabled      = $true
            StopAt           = '07:00'
            MaxDisks         = 0
            MonitorForAdmins = $true
        }
    }
}

function Merge-CVObject($Default, $Loaded) {
    # Completa la configurazione letta da file con le chiavi mancanti (aggiornamenti di versione)
    $out = [ordered]@{}
    foreach ($k in $Default.Keys) {
        $hasLoaded = $Loaded -and ($Loaded.PSObject.Properties.Name -contains $k)
        if ($Default[$k] -is [System.Collections.IDictionary]) {
            $out[$k] = Merge-CVObject $Default[$k] $(if ($hasLoaded) { $Loaded.$k } else { $null })
        } elseif ($hasLoaded) {
            $v = $Loaded.$k
            if ($Default[$k] -is [array]) { $out[$k] = @($v | Where-Object { $null -ne $_ -and "$_" -ne '' }) } else { $out[$k] = $v }
        } else {
            $out[$k] = $Default[$k]
        }
    }
    $out
}

function Get-CVConfig {
    $def = Get-CVDefaultConfig
    if (Test-Path -LiteralPath $script:CVConfig) {
        try {
            $loaded = Get-Content -LiteralPath $script:CVConfig -Raw -Encoding UTF8 | ConvertFrom-Json
            $cfg = Merge-CVObject $def $loaded
            # migrazione dalla versione 1.x: un solo percorso in ProfilePath
            if (-not @($cfg.ProfilePaths).Count -and $loaded.PSObject.Properties.Name -contains 'ProfilePath' -and $loaded.ProfilePath) {
                $cfg.ProfilePaths = @($loaded.ProfilePath)
                $cfg.SetupDone = $true
            }
            return $cfg
        } catch { }
    }
    $def
}

function Save-CVConfig($Config) {
    New-Item -ItemType Directory -Path $script:CVBase -Force | Out-Null
    $Config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:CVConfig -Encoding UTF8
}

# ============================================================================
#  Utility
# ============================================================================
function ConvertTo-CVHtml($s) { [System.Net.WebUtility]::HtmlEncode("$s") }

function Get-CVUserFromFolder([string]$FolderName) {
    # cartelle FSLogix: SID_utente (predefinito) oppure utente_SID (FlipFlopProfileDirectoryName)
    $FolderName -replace '^S-1-\d+(-\d+)+_', '' -replace '_S-1-\d+(-\d+)+$', ''
}

function Get-CVDiskKind([string]$FileName) {
    if ($FileName -match '^Profile_') { 'Profilo' }
    elseif ($FileName -match '^ODFC_') { 'Office (ODFC)' }
    else { 'Altro' }
}

function Get-CVProfilePaths($Config) {
    @($Config.ProfilePaths | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
}

function Test-CVHasCommand([string]$Name) { [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

function Get-CVVolumeInfo([string[]]$Paths) {
    # una o piu' cartelle: somma dei volumi distinti su cui si trovano
    $roots = @($Paths | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetPathRoot($_) } | Sort-Object -Unique)
    if (-not $roots.Count) { return $null }
    $size = 0.0; $free = 0.0
    try {
        foreach ($r in $roots) {
            $d = New-Object IO.DriveInfo $r
            $size += $d.TotalSize; $free += $d.AvailableFreeSpace
        }
        [pscustomobject]@{
            Drive   = ($roots -join ', ')
            SizeGB  = [math]::Round($size / 1GB, 1)
            FreeGB  = [math]::Round($free / 1GB, 1)
            FreePct = $(if ($size) { [math]::Round($free * 100 / $size, 1) } else { 0 })
        }
    } catch { $null }
}

function Test-CVAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Format-CVDuration([double]$Seconds) {
    $ts = [TimeSpan]::FromSeconds([math]::Max(0, $Seconds))
    '{0:00}:{1:00}:{2:00}' -f [math]::Floor($ts.TotalHours), $ts.Minutes, $ts.Seconds
}

# ============================================================================
#  Eventi nel Registro applicazioni
# ============================================================================
#  1000 avvio | 1001 completato | 1002 completato con errori | 1003 interrotto
#  1004 spazio libero sotto soglia | 1005 errore imprevisto
function Write-CVEvent([int]$Id, [string]$Message, [string]$Type = 'Information') {
    try {
        if (-not [Diagnostics.EventLog]::SourceExists($script:CVEventSource)) {
            New-EventLog -LogName Application -Source $script:CVEventSource -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source $script:CVEventSource -EventId $Id -EntryType $Type -Message $Message -ErrorAction Stop
    } catch { }
}

# ============================================================================
#  Stato del job, stop, dischi rimasti agganciati
# ============================================================================
function Read-CVStatus {
    if (-not (Test-Path -LiteralPath $script:CVStatus)) { return $null }
    for ($i = 0; $i -lt 3; $i++) {
        try { return (Get-Content -LiteralPath $script:CVStatus -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { Start-Sleep -Milliseconds 150 }
    }
    $null
}

function Get-CVJobProcess {
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
      Where-Object { $_.CommandLine -match 'Compact-ProfileDisks\.ps1' -and $_.ProcessId -ne $PID })
}

function Test-CVJobRunning { (Get-CVJobProcess).Count -gt 0 }

function Request-CVStop {
    New-Item -ItemType File -Path $script:CVStopFile -Force | Out-Null
}

function Get-CVAttachedLeftovers([string[]]$Roots) {
    if (-not (Test-CVHasCommand 'Get-Disk')) { return @() }
    $full = @(foreach ($r in $Roots) { try { (Resolve-Path -LiteralPath $r -ErrorAction Stop).ProviderPath.TrimEnd('\') } catch { } })
    if (-not $full.Count) { return @() }
    @(Get-Disk -ErrorAction SilentlyContinue | Where-Object {
        $loc = $_.Location
        $loc -and $loc -match '\.vhdx?$' -and @($full | Where-Object { $loc -like "$_\*" }).Count
    })
}

function Dismount-CVLeftovers([string[]]$Roots) {
    # Restituisce l'elenco dei messaggi: dischi sganciati o errori
    $msgs = @()
    foreach ($d in (Get-CVAttachedLeftovers $Roots)) {
        try {
            Dismount-DiskImage -ImagePath $d.Location -ErrorAction Stop | Out-Null
            $msgs += "Sganciato: $($d.Location)"
        } catch {
            $msgs += "ERRORE nello sganciare $($d.Location): $($_.Exception.Message)"
        }
    }
    $msgs
}

function Stop-CVForce([string[]]$Roots) {
    # Ultima risorsa: termina job e diskpart, poi sgancia i dischi rimasti
    Get-CVJobProcess | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Get-Process diskpart -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($t in $script:CVTaskJob, $script:CVTaskManual) {
        $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq 'Running') { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Seconds 3
    $msgs = Dismount-CVLeftovers $Roots
    if (Test-Path -LiteralPath $script:CVStopFile) { Remove-Item -LiteralPath $script:CVStopFile -Force -ErrorAction SilentlyContinue }
    $st = Read-CVStatus
    if ($st -and $st.State -in 'running', 'stopping') {
        $st.State = 'killed'
        $st.Updated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        try { $st | ConvertTo-Json | Set-Content -LiteralPath $script:CVStatus -Encoding UTF8 } catch { }
    }
    Write-CVEvent 1003 "Compattazione terminata con stop forzato. $($msgs -join ' ')" 'Warning'
    $msgs
}

# ============================================================================
#  Inventario dei VHDX (situazione attuale)
# ============================================================================
function Get-CVInventory($Config) {
    $paths = Get-CVProfilePaths $Config
    if (-not $paths.Count) { throw 'Nessuna cartella dei profili configurata: esegui la configurazione guidata.' }
    foreach ($p in $paths) { if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "Cartella profili non trovata: $p" } }

    $open = @{}
    if (Test-CVHasCommand 'Get-SmbOpenFile') {
        Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object { $_.Path -match '\.vhdx?$' } | ForEach-Object {
            $open[$_.Path.ToLower()] = $_.ClientComputerName
        }
    }
    $all = @(foreach ($p in $paths) { Get-ChildItem -LiteralPath $p -Recurse -File -Force -ErrorAction SilentlyContinue })
    $now = Get-Date
    $maxMB = [double]$Config.FslogixSizeMB

    $vhd = foreach ($f in $all) {
        if ($f.Extension -notmatch '^\.vhdx?$') { continue }
        $key = $f.FullName.ToLower()
        [pscustomobject]@{
            Utente   = Get-CVUserFromFolder $f.Directory.Name
            Tipo     = Get-CVDiskKind $f.Name
            File     = $f.FullName
            SizeMB   = [math]::Round($f.Length / 1MB)
            LastWrite = $f.LastWriteTime
            Created  = $f.CreationTime
            DaysIdle = [math]::Floor(($now - $f.LastWriteTime).TotalDays)
            InUse    = $open.ContainsKey($key)
            InUseBy  = $(if ($open.ContainsKey($key)) { $open[$key] } else { '' })
            PctOfMax = $(if ($maxMB -gt 0) { [math]::Round($f.Length / 1MB * 100 / $maxMB, 1) } else { 0 })
        }
    }
    $vhd = @($vhd)

    $openDirs = @($vhd | Where-Object { $_.InUse } | ForEach-Object { Split-Path $_.File -Parent })
    $locks = @($all | Where-Object { $_.Name -match '\.(lock|metadata)$' } | ForEach-Object {
        [pscustomobject]@{
            File      = $_.FullName
            LastWrite = $_.LastWriteTime
            Orphan    = -not ($openDirs -contains $_.DirectoryName)
        }
    })

    $m = $vhd | Measure-Object -Property SizeMB -Sum -Average -Maximum
    [pscustomobject]@{
        Collected   = $now
        Path        = ($paths -join '; ')
        Paths       = $paths
        Volume      = Get-CVVolumeInfo $paths
        Disks       = $vhd
        Count       = $vhd.Count
        TotalMB     = [double]$m.Sum
        AvgMB       = [math]::Round([double]$m.Average)
        MaxMB       = [double]$m.Maximum
        InUse       = @($vhd | Where-Object { $_.InUse }).Count
        Stale       = @($vhd | Where-Object { $_.DaysIdle -ge $Config.StaleDays } | Sort-Object DaysIdle -Descending)
        NearMax     = @($vhd | Where-Object { $_.PctOfMax -ge 80 } | Sort-Object PctOfMax -Descending)
        OrphanLocks = @($locks | Where-Object { $_.Orphan })
        Leftovers   = @(Get-CVAttachedLeftovers $paths)
    }
}

# ============================================================================
#  Installazione, rilevamento e prerequisiti
# ============================================================================
function Find-CVProfileFolders {
    # Cerca nelle condivisioni locali le cartelle che contengono profili FSLogix
    # (VHD/VHDX in sottocartelle per utente) e restituisce le cartelle "radice" dei profili.
    $roots = @()
    if (Test-CVHasCommand 'Get-SmbShare') {
        $roots = @(Get-SmbShare -ErrorAction SilentlyContinue |
                   Where-Object { -not $_.Special -and $_.Path -and $_.Name -notin 'SYSVOL', 'NETLOGON', 'print$' } |
                   ForEach-Object { $_.Path } | Sort-Object -Unique)
    }
    $found = @{}
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r -PathType Container)) { continue }
        $files = @(Get-ChildItem -LiteralPath $r -Recurse -Depth 2 -File -Force -Filter '*.vhd*' -ErrorAction SilentlyContinue |
                   Where-Object { $_.Extension -match '^\.vhdx?$' })
        foreach ($f in $files) {
            # radice = cartella che contiene le cartelle per utente
            $root = if ($f.Directory.Parent) { $f.Directory.Parent.FullName } else { $f.DirectoryName }
            if ($f.DirectoryName -eq $r.TrimEnd('\')) { $root = $f.DirectoryName }
            if (-not $found.ContainsKey($root)) { $found[$root] = [pscustomobject]@{ Path = $root; Count = 0; Bytes = [double]0; Profile = 0; Odfc = 0 } }
            $e = $found[$root]
            $e.Count++; $e.Bytes += $f.Length
            if ($f.Name -match '^Profile_') { $e.Profile++ } elseif ($f.Name -match '^ODFC_') { $e.Odfc++ }
        }
    }
    @($found.Values | ForEach-Object {
        [pscustomobject]@{
            Path   = $_.Path
            Count  = $_.Count
            SizeGB = [math]::Round($_.Bytes / 1GB, 1)
            Detail = "$($_.Profile) profili, $($_.Odfc) Office (ODFC)"
        }
    } | Sort-Object Count -Descending)
}

function Get-CVFslogixSizeMB {
    # SizeInMBs di FSLogix se il server ha l'agente installato, altrimenti il predefinito FSLogix (30000)
    foreach ($k in 'HKLM:\SOFTWARE\FSLogix\Profiles', 'HKLM:\SOFTWARE\Policies\FSLogix\Profiles') {
        try {
            $v = (Get-ItemProperty -Path $k -Name SizeInMBs -ErrorAction Stop).SizeInMBs
            if ([int]$v -gt 0) { return [int]$v }
        } catch { }
    }
    30000
}

function Test-CVPrerequisites {
    $os = [Environment]::OSVersion.Version
    $r = @(
        [pscustomobject]@{ Verifica = 'Esecuzione come amministratore'; Esito = $(if (Test-CVAdmin) { 'OK' } else { 'ERRORE' }); Nota = 'Necessario per diskpart, task pianificati e registro eventi' }
        [pscustomobject]@{ Verifica = 'Windows PowerShell 5.1 o superiore'; Esito = $(if ($PSVersionTable.PSVersion -ge [version]'5.1') { 'OK' } else { 'ERRORE' }); Nota = "Versione rilevata: $($PSVersionTable.PSVersion)" }
        [pscustomobject]@{ Verifica = 'Windows Server 2012 R2 / Windows 8.1 o successivi'; Esito = $(if ($os -ge [version]'6.3') { 'OK' } else { 'ERRORE' }); Nota = "Versione rilevata: $os" }
        [pscustomobject]@{ Verifica = 'diskpart disponibile'; Esito = $(if (Test-Path "$env:WINDIR\System32\diskpart.exe") { 'OK' } else { 'ERRORE' }); Nota = 'Usato per compattare i VHDX' }
        [pscustomobject]@{ Verifica = 'Cmdlet Storage (Get-Disk, Get-DiskImage)'; Esito = $(if ((Test-CVHasCommand 'Get-Disk') -and (Test-CVHasCommand 'Get-DiskImage')) { 'OK' } else { 'AVVISO' }); Nota = 'Per riconoscere e sganciare i dischi rimasti agganciati' }
        [pscustomobject]@{ Verifica = 'Cmdlet SMB (Get-SmbOpenFile)'; Esito = $(if (Test-CVHasCommand 'Get-SmbOpenFile') { 'OK' } else { 'AVVISO' }); Nota = 'Per sapere quali profili sono in uso: senza, si usa solo il test di apertura esclusiva' }
        [pscustomobject]@{ Verifica = 'Condivisioni presenti su questo server'; Esito = $(if ((Test-CVHasCommand 'Get-SmbShare') -and @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special }).Count) { 'OK' } else { 'AVVISO' }); Nota = 'Lo strumento va installato sul file server che ospita i profili FSLogix' }
    )
    $r
}

function Get-CVInstallInfo {
    try { Get-ItemProperty -Path $script:CVRegKey -ErrorAction Stop } catch { $null }
}

function Set-CVInstallInfo {
    try {
        New-Item -Path $script:CVRegKey -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path $script:CVRegKey -Name InstallDir -Value $script:CVBase
        Set-ItemProperty -Path $script:CVRegKey -Name Version -Value $script:CVVersion
    } catch { }
}

function Get-CVShortcutPaths {
    @(
        (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) $script:CVShortcutName),
        (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) $script:CVShortcutName)
    )
}

function New-CVShortcuts {
    $ws = New-Object -ComObject WScript.Shell
    foreach ($lnk in (Get-CVShortcutPaths)) {
        $sc = $ws.CreateShortcut($lnk)
        $sc.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$script:CVBase\CompactVHDX-Manager.ps1`""
        $sc.WorkingDirectory = $script:CVBase
        $sc.IconLocation = "$env:WINDIR\System32\shell32.dll,8"
        $sc.Description = 'CompactVHDX - compattazione offline dei VHDX FSLogix'
        $sc.Save()
    }
}

function Remove-CVShortcuts {
    foreach ($lnk in (Get-CVShortcutPaths)) { Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue }
}

# ============================================================================
#  Storico delle run
# ============================================================================
$script:CVHistoryFields = 'RunId', 'Start', 'End', 'DurationSec', 'Trigger', 'Simulation', 'Filter',
    'DisksTotal', 'Ok', 'Skipped', 'Excluded', 'Errors', 'NotDone', 'SavedMB',
    'VhdxTotalBeforeMB', 'VhdxTotalAfterMB', 'VolumeSizeGB', 'VolumeFreeBeforeGB', 'VolumeFreeAfterGB',
    'AvgSecPerDisk', 'StopReason', 'Report', 'Csv'

function Add-CVHistory($Row) {
    New-Item -ItemType Directory -Path $script:CVDataDir -Force | Out-Null
    # numeri sempre in formato invariante (punto decimale), indipendente dalla lingua del server
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $obj = [ordered]@{}
    foreach ($f in $script:CVHistoryFields) {
        $v = $Row[$f]
        if ($v -is [double] -or $v -is [single] -or $v -is [decimal]) { $v = $v.ToString($inv) }
        $obj[$f] = $v
    }
    [pscustomobject]$obj | Export-Csv -LiteralPath $script:CVHistory -NoTypeInformation -Delimiter ';' -Encoding UTF8 -Append
}

function Get-CVHistory {
    if (-not (Test-Path -LiteralPath $script:CVHistory)) { return @() }
    @(Import-Csv -LiteralPath $script:CVHistory -Delimiter ';' -Encoding UTF8 | Sort-Object RunId)
}

function Get-CVUserGrowth($History, [int]$Top = 10) {
    # Crescita per utente tra le ultime due run reali: dimensione prima della run corrente
    # meno dimensione dopo la run precedente (o prima, se in quella run era saltato)
    $real = @($History | Where-Object { $_.Simulation -ne 'True' -and $_.Csv -and (Test-Path -LiteralPath $_.Csv) })
    if ($real.Count -lt 2) { return @() }
    $cur  = @(Import-Csv -LiteralPath $real[-1].Csv -Delimiter ';' -Encoding UTF8)
    $prev = @{}
    foreach ($r in (Import-Csv -LiteralPath $real[-2].Csv -Delimiter ';' -Encoding UTF8)) {
        $v = if ("$($r.AfterMB)" -ne '') { [double]$r.AfterMB } else { [double]$r.BeforeMB }
        $prev[(Split-Path $r.File -Leaf).ToLower()] = $v
    }
    $g = foreach ($r in $cur) {
        $k = (Split-Path $r.File -Leaf).ToLower()
        if (-not $prev.ContainsKey($k)) { continue }
        [pscustomobject]@{
            Utente   = $r.Utente
            Tipo     = Get-CVDiskKind (Split-Path $r.File -Leaf)
            PrimaMB  = $prev[$k]
            OraMB    = [double]$r.BeforeMB
            DeltaMB  = [double]$r.BeforeMB - $prev[$k]
        }
    }
    @($g | Sort-Object DeltaMB -Descending | Select-Object -First $Top)
}

# ============================================================================
#  Grafici SVG (nessuna dipendenza esterna: funzionano anche senza internet)
# ============================================================================
function New-CVSvgChart {
    param(
        [string]$Title,
        [string[]]$Labels,
        [object[]]$Series,          # @{ Name; Values; Color; Type = 'line'|'bar' }
        [string]$Unit = '',
        [double]$Threshold = [double]::NaN,
        [string]$ThresholdLabel = ''
    )
    $W = 900; $H = 280; $L = 70; $R = 20; $T = 40; $B = 60
    $pw = $W - $L - $R; $ph = $H - $T - $B
    $n = $Labels.Count
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<svg viewBox=`"0 0 $W $H`" class=`"chart`" role=`"img`" aria-label=`"$(ConvertTo-CVHtml $Title)`">")
    [void]$sb.Append("<text x=`"$L`" y=`"22`" class=`"ct`">$(ConvertTo-CVHtml $Title)</text>")

    if ($n -eq 0) {
        [void]$sb.Append("<text x=`"$($W/2)`" y=`"$($H/2)`" text-anchor=`"middle`" class=`"cm`">Nessun dato</text></svg>")
        return $sb.ToString()
    }

    $vals = @()
    foreach ($s in $Series) { $vals += @($s.Values | ForEach-Object { [double]$_ }) }
    if (-not [double]::IsNaN($Threshold)) { $vals += $Threshold }
    $max = ($vals | Measure-Object -Maximum).Maximum
    $min = [math]::Min(0, ($vals | Measure-Object -Minimum).Minimum)
    if ($max -le $min) { $max = $min + 1 }
    # scala "tonda"
    $raw = ($max - $min) / 4
    $mag = [math]::Pow(10, [math]::Floor([math]::Log10([math]::Max($raw, 1e-9))))
    $step = @(1, 2, 2.5, 5, 10 | ForEach-Object { $_ * $mag } | Where-Object { $_ -ge $raw })[0]
    $top = [math]::Ceiling($max / $step) * $step
    $bot = [math]::Floor($min / $step) * $step
    if ($top -le $bot) { $top = $bot + $step }

    $yOf = { param($v) $T + $ph - (($v - $bot) / ($top - $bot)) * $ph }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $f = { param($v) ([double]$v).ToString('0.##', $inv) }

    # griglia e asse Y
    for ($v = $bot; $v -le $top + $step / 2; $v += $step) {
        $y = & $yOf $v
        [void]$sb.Append("<line x1=`"$L`" x2=`"$($L+$pw)`" y1=`"$(& $f $y)`" y2=`"$(& $f $y)`" class=`"gl`"/>")
        [void]$sb.Append("<text x=`"$($L-8)`" y=`"$(& $f ($y+4))`" text-anchor=`"end`" class=`"ax`">$(([double]$v).ToString('N0'))</text>")
    }
    if ($Unit) { [void]$sb.Append("<text x=`"14`" y=`"$($T + $ph/2)`" transform=`"rotate(-90 14 $($T + $ph/2))`" text-anchor=`"middle`" class=`"ax`">$(ConvertTo-CVHtml $Unit)</text>") }

    # asse X
    $slot = $pw / $n
    $every = [math]::Max(1, [math]::Ceiling($n / 12))
    for ($i = 0; $i -lt $n; $i++) {
        if ($i % $every -ne 0 -and $i -ne $n - 1) { continue }
        $x = $L + $slot * ($i + 0.5)
        [void]$sb.Append("<text x=`"$(& $f $x)`" y=`"$($T+$ph+18)`" text-anchor=`"middle`" class=`"ax`">$(ConvertTo-CVHtml $Labels[$i])</text>")
    }

    # serie a barre (affiancate)
    $bars = @($Series | Where-Object { $_.Type -eq 'bar' })
    $bw = [math]::Max(2, ($slot * 0.7) / [math]::Max(1, $bars.Count))
    $bi = 0
    foreach ($s in $bars) {
        $vs = @($s.Values)
        for ($i = 0; $i -lt $n; $i++) {
            $v = [double]$vs[$i]
            $x = $L + $slot * $i + $slot * 0.15 + $bw * $bi
            $y0 = & $yOf 0; $y1 = & $yOf $v
            $y = [math]::Min($y0, $y1); $barH = [math]::Abs($y0 - $y1)   # nota: $h coinciderebbe con $H (PowerShell non distingue maiuscole)
            [void]$sb.Append("<rect x=`"$(& $f $x)`" y=`"$(& $f $y)`" width=`"$(& $f $bw)`" height=`"$(& $f ([math]::Max($barH,0.5)))`" fill=`"$($s.Color)`"><title>$(ConvertTo-CVHtml $Labels[$i]) - $(ConvertTo-CVHtml $s.Name): $($v.ToString('N0')) $Unit</title></rect>")
        }
        $bi++
    }

    # soglia
    if (-not [double]::IsNaN($Threshold)) {
        $y = & $yOf $Threshold
        [void]$sb.Append("<line x1=`"$L`" x2=`"$($L+$pw)`" y1=`"$(& $f $y)`" y2=`"$(& $f $y)`" class=`"th`"/>")
        [void]$sb.Append("<text x=`"$($L+$pw-4)`" y=`"$(& $f ($y-5))`" text-anchor=`"end`" class=`"tl`">$(ConvertTo-CVHtml $ThresholdLabel)</text>")
    }

    # serie a linee
    foreach ($s in @($Series | Where-Object { $_.Type -ne 'bar' })) {
        $vs = @($s.Values)
        $pts = for ($i = 0; $i -lt $n; $i++) { "$(& $f ($L + $slot * ($i + 0.5))),$(& $f (& $yOf ([double]$vs[$i])))" }
        if ($n -gt 1) { [void]$sb.Append("<polyline points=`"$($pts -join ' ')`" fill=`"none`" stroke=`"$($s.Color)`" stroke-width=`"2.5`"/>") }
        for ($i = 0; $i -lt $n; $i++) {
            $x = $L + $slot * ($i + 0.5); $y = & $yOf ([double]$vs[$i])
            [void]$sb.Append("<circle cx=`"$(& $f $x)`" cy=`"$(& $f $y)`" r=`"3.5`" fill=`"$($s.Color)`"><title>$(ConvertTo-CVHtml $Labels[$i]) - $(ConvertTo-CVHtml $s.Name): $(([double]$vs[$i]).ToString('N1')) $Unit</title></circle>")
        }
    }

    # legenda
    $lx = $L
    foreach ($s in $Series) {
        [void]$sb.Append("<rect x=`"$lx`" y=`"$($H-18)`" width=`"12`" height=`"12`" rx=`"2`" fill=`"$($s.Color)`"/>")
        [void]$sb.Append("<text x=`"$($lx+17)`" y=`"$($H-8)`" class=`"lg`">$(ConvertTo-CVHtml $s.Name)</text>")
        $lx += 30 + 7 * "$($s.Name)".Length
    }
    [void]$sb.Append('</svg>')
    $sb.ToString()
}

# ============================================================================
#  HTML: stile comune
# ============================================================================
$script:CVCss = @'
:root{--fg:#1f2933;--mut:#616e7c;--bd:#d9e2ec;--bg:#f5f7fa;--card:#fff;--ok:#1e7b4a;--warn:#b7791f;--err:#c53030;--acc:#2b6cb0}
*{box-sizing:border-box}
body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px;color:var(--fg);background:var(--bg)}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:26px 0 10px}
.sub{color:var(--mut);font-size:13px;margin-bottom:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:12px}
.tile{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 14px}
.tile .v{font-size:22px;font-weight:600}
.tile .l{font-size:12px;color:var(--mut)}
.ok .v{color:var(--ok)}.warn .v{color:var(--warn)}.err .v{color:var(--err)}.acc .v{color:var(--acc)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px;margin-bottom:14px}
table{border-collapse:collapse;width:100%;background:var(--card);font-size:13px}
th,td{border:1px solid var(--bd);padding:5px 8px;text-align:left;vertical-align:top}
th{background:#e4e7eb;position:sticky;top:0}
td.n,th.n{text-align:right;white-space:nowrap}
.info td{border:none;padding:2px 14px 2px 0}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;white-space:nowrap}
.b-ok{background:#def7ec;color:var(--ok)}.b-skip{background:#fefcbf;color:#975a16}.b-err{background:#fed7d7;color:var(--err)}.b-sim{background:#e2e8f0;color:#334e68}.b-exc{background:#e9d8fd;color:#553c9a}
.alert{border-left:4px solid var(--err);background:#fff5f5;padding:10px 14px;margin:0 0 14px;border-radius:4px}
.note{border-left:4px solid var(--warn);background:#fffbeb;padding:10px 14px;margin:0 0 14px;border-radius:4px}
.chart{width:100%;height:auto;background:var(--card);border:1px solid var(--bd);border-radius:8px;margin-bottom:14px}
.chart .ct{font-size:14px;font-weight:600;fill:var(--fg)}
.chart .ax{font-size:11px;fill:var(--mut)}
.chart .lg{font-size:12px;fill:var(--fg)}
.chart .cm{font-size:13px;fill:var(--mut)}
.chart .gl{stroke:#e4e7eb;stroke-width:1}
.chart .th{stroke:var(--err);stroke-width:1.5;stroke-dasharray:6 4}
.chart .tl{font-size:11px;fill:var(--err)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:900px){.grid2{grid-template-columns:1fr}}
.scroll{max-height:520px;overflow:auto;border:1px solid var(--bd);border-radius:8px}
a{color:var(--acc)}
footer{color:var(--mut);font-size:12px;margin-top:24px}
'@

function New-CVHtmlPage([string]$Title, [string]$Body) {
    "<!DOCTYPE html><html lang=`"it`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width,initial-scale=1`"><title>$(ConvertTo-CVHtml $Title)</title><style>$script:CVCss</style></head><body><div class=`"wrap`">$Body<footer>CompactVHDX $script:CVVersion - generato il $((Get-Date).ToString('dd/MM/yyyy HH:mm')) su $env:COMPUTERNAME</footer></div></body></html>"
}

function New-CVTile($Value, [string]$Label, [string]$Class = '') {
    "<div class=`"tile $Class`"><div class=`"v`">$(ConvertTo-CVHtml $Value)</div><div class=`"l`">$(ConvertTo-CVHtml $Label)</div></div>"
}

function Get-CVEsitoClass([string]$Esito) {
    if ($Esito -eq 'OK') { 'b-ok' }
    elseif ($Esito -like 'ERRORE*') { 'b-err' }
    elseif ($Esito -eq 'DA COMPATTARE') { 'b-sim' }
    elseif ($Esito -like 'ESCLUSO*') { 'b-exc' }
    else { 'b-skip' }
}

# ============================================================================
#  Report della singola run
# ============================================================================
function New-CVRunReport {
    param($Results, $Summary, [string]$File, [string]$HistoryFile, $Issues = @())

    $s = $Summary
    $b = New-Object System.Text.StringBuilder
    [void]$b.Append("<h1>Compattazione offline VHDX FSLogix$(ConvertTo-CVHtml $s.Mode)</h1>")
    [void]$b.Append("<div class=`"sub`">$(ConvertTo-CVHtml $s.Server) - $(ConvertTo-CVHtml $s.Path) - run $(ConvertTo-CVHtml $s.RunId)")
    if ($HistoryFile) { [void]$b.Append(" - <a href=`"$(ConvertTo-CVHtml (Split-Path $HistoryFile -Leaf))`">Andamento storico</a>") }
    [void]$b.Append('</div>')
    if ($s.Alert) { [void]$b.Append("<div class=`"alert`">$(ConvertTo-CVHtml $s.Alert)</div>") }

    [void]$b.Append('<div class="tiles">')
    [void]$b.Append((New-CVTile $s.Total 'Dischi trovati'))
    [void]$b.Append((New-CVTile $s.Ok 'Compattati' 'ok'))
    [void]$b.Append((New-CVTile ('{0:N0} MB' -f [double]$s.SavedMB) 'Spazio recuperato' 'ok'))
    [void]$b.Append((New-CVTile $s.Skipped 'Saltati (in uso)' 'warn'))
    [void]$b.Append((New-CVTile $s.Excluded 'Esclusi' ''))
    [void]$b.Append((New-CVTile $s.Errors 'Errori' $(if ($s.Errors) { 'err' } else { '' })))
    [void]$b.Append((New-CVTile $s.NotDone 'Non elaborati (stop)' $(if ($s.NotDone) { 'warn' } else { '' })))
    [void]$b.Append((New-CVTile $s.Duration 'Durata' 'acc'))
    [void]$b.Append('</div>')

    [void]$b.Append('<div class="card"><table class="info">')
    foreach ($kv in $s.Info.GetEnumerator()) { [void]$b.Append("<tr><td><b>$(ConvertTo-CVHtml $kv.Key)</b></td><td>$(ConvertTo-CVHtml $kv.Value)</td></tr>") }
    [void]$b.Append('</table></div>')

    $iss = @($Issues)
    [void]$b.Append("<h2>Errori e avvisi ($(@($iss | Where-Object { $_.Livello -eq 'ERRORE' }).Count) errori, $(@($iss | Where-Object { $_.Livello -eq 'AVVISO' }).Count) avvisi)</h2>")
    if ($iss.Count) {
        [void]$b.Append('<div class="scroll"><table><tr><th>Ora</th><th>Livello</th><th>Messaggio</th><th>Dettaglio</th></tr>')
        foreach ($i in $iss) {
            $cls = if ($i.Livello -eq 'ERRORE') { 'b-err' } else { 'b-skip' }
            [void]$b.Append("<tr><td>$(ConvertTo-CVHtml $i.Ora)</td><td><span class=`"b $cls`">$(ConvertTo-CVHtml $i.Livello)</span></td><td>$(ConvertTo-CVHtml $i.Messaggio)</td><td>$(ConvertTo-CVHtml $i.Dettaglio)</td></tr>")
        }
        [void]$b.Append('</table></div>')
    } else {
        [void]$b.Append('<div class="card">Nessun errore o avviso. I dischi saltati perché in uso sono nel dettaglio per utente.</div>')
    }

    [void]$b.Append('<h2>Dettaglio per utente</h2><div class="scroll"><table><tr><th>Utente</th><th>Disco</th><th class="n">Prima (MB)</th><th class="n">Dopo (MB)</th><th class="n">Recuperati (MB)</th><th class="n">Durata (s)</th><th>Esito</th><th>File</th></tr>')
    $ordered = @($Results | Sort-Object @{ e = { if ($_.Esito -like 'ERRORE*') { 0 } elseif ($_.Esito -eq 'OK') { 1 } elseif ($_.Esito -eq 'DA COMPATTARE') { 2 } elseif ($_.Esito -like 'ESCLUSO*') { 4 } else { 3 } } },
                                        @{ e = { [double]$_.SavedMB }; Descending = $true },
                                        @{ e = { [double]$_.BeforeMB }; Descending = $true })
    foreach ($r in $ordered) {
        [void]$b.Append("<tr><td>$(ConvertTo-CVHtml $r.Utente)</td><td>$(ConvertTo-CVHtml $(if ($r.Tipo) { $r.Tipo } else { Get-CVDiskKind (Split-Path $r.File -Leaf) }))</td><td class=`"n`">$(ConvertTo-CVHtml $r.BeforeMB)</td><td class=`"n`">$(ConvertTo-CVHtml $r.AfterMB)</td><td class=`"n`">$(ConvertTo-CVHtml $r.SavedMB)</td><td class=`"n`">$(ConvertTo-CVHtml $r.DurataSec)</td><td><span class=`"b $(Get-CVEsitoClass $r.Esito)`">$(ConvertTo-CVHtml $r.Esito)</span></td><td>$(ConvertTo-CVHtml $r.File)</td></tr>")
    }
    if (-not $ordered.Count) { [void]$b.Append('<tr><td colspan="8">Nessun disco elaborato</td></tr>') }
    [void]$b.Append('</table></div>')

    New-CVHtmlPage "Compattazione VHDX $($s.RunId)" $b.ToString() | Out-File -LiteralPath $File -Encoding UTF8
}

# ============================================================================
#  Report storico (andamento run per run)
# ============================================================================
function New-CVHistoryReport {
    param($Config, [string]$File)

    $hist = @(Get-CVHistory)
    $real = @($hist | Where-Object { $_.Simulation -ne 'True' })
    $b = New-Object System.Text.StringBuilder
    [void]$b.Append('<h1>Andamento compattazione VHDX FSLogix</h1>')
    [void]$b.Append("<div class=`"sub`">$env:COMPUTERNAME - $(ConvertTo-CVHtml ((Get-CVProfilePaths $Config) -join '; ')) - $($real.Count) run reali, $($hist.Count - $real.Count) simulazioni</div>")

    if (-not $real.Count) {
        [void]$b.Append('<div class="note">Nessuna run reale registrata: i grafici compariranno dopo la prima compattazione.</div>')
    } else {
        $last = $real[-1]
        $first = $real[0]
        $totSaved = ($real | Measure-Object -Property SavedMB -Sum).Sum
        $growth = [double]$last.VhdxTotalBeforeMB - [double]$first.VhdxTotalBeforeMB
        $volPct = if ([double]$last.VolumeSizeGB -gt 0) { [math]::Round([double]$last.VolumeFreeAfterGB * 100 / [double]$last.VolumeSizeGB, 1) } else { 0 }
        if ($volPct -lt $Config.FreeAlertPct) {
            [void]$b.Append("<div class=`"alert`">Spazio libero sul volume dei profili al $volPct% ($($last.VolumeFreeAfterGB) GB): sotto la soglia del $($Config.FreeAlertPct)%.</div>")
        }
        [void]$b.Append('<div class="tiles">')
        [void]$b.Append((New-CVTile $real.Count 'Run reali'))
        [void]$b.Append((New-CVTile ('{0:N1} GB' -f ([double]$totSaved / 1024)) 'Recuperati in totale' 'ok'))
        [void]$b.Append((New-CVTile ('{0:N0} MB' -f [double]$last.SavedMB) 'Recuperati ultima run' 'ok'))
        [void]$b.Append((New-CVTile ('{0:N1} GB' -f ([double]$last.VhdxTotalAfterMB / 1024)) 'Peso VHDX attuale' 'acc'))
        [void]$b.Append((New-CVTile ('{0}{1:N1} GB' -f $(if ($growth -ge 0) { '+' } else { '' }), ($growth / 1024)) 'Crescita dalla prima run' $(if ($growth -gt 0) { 'warn' } else { 'ok' })))
        [void]$b.Append((New-CVTile "$($last.VolumeFreeAfterGB) GB" "Libero su volume ($volPct%)" $(if ($volPct -lt $Config.FreeAlertPct) { 'err' } else { 'ok' })))
        [void]$b.Append((New-CVTile (Format-CVDuration ([double]$last.DurationSec)) 'Durata ultima run' 'acc'))
        [void]$b.Append('</div>')

        $labels = @($real | ForEach-Object { ([datetime]::ParseExact($_.Start, 'yyyy-MM-dd HH:mm:ss', $null)).ToString('dd/MM') })
        $c1 = New-CVSvgChart -Title 'Peso totale dei VHDX (GB)' -Labels $labels -Unit 'GB' -Series @(
            @{ Name = 'Prima della run'; Values = @($real | ForEach-Object { [double]$_.VhdxTotalBeforeMB / 1024 }); Color = '#b7791f'; Type = 'line' },
            @{ Name = 'Dopo la run'; Values = @($real | ForEach-Object { [double]$_.VhdxTotalAfterMB / 1024 }); Color = '#2b6cb0'; Type = 'line' })
        $thr = ([double]$last.VolumeSizeGB) * $Config.FreeAlertPct / 100
        $c2 = New-CVSvgChart -Title 'Spazio libero sul volume dei profili (GB)' -Labels $labels -Unit 'GB' -Threshold $thr -ThresholdLabel "soglia $($Config.FreeAlertPct)%" -Series @(
            @{ Name = 'Prima'; Values = @($real | ForEach-Object { [double]$_.VolumeFreeBeforeGB }); Color = '#b7791f'; Type = 'line' },
            @{ Name = 'Dopo'; Values = @($real | ForEach-Object { [double]$_.VolumeFreeAfterGB }); Color = '#1e7b4a'; Type = 'line' })
        $c3 = New-CVSvgChart -Title 'Spazio recuperato per run (MB)' -Labels $labels -Unit 'MB' -Series @(
            @{ Name = 'MB recuperati'; Values = @($real | ForEach-Object { [double]$_.SavedMB }); Color = '#1e7b4a'; Type = 'bar' })
        $c4 = New-CVSvgChart -Title 'Durata della run (minuti)' -Labels $labels -Unit 'min' -Series @(
            @{ Name = 'Durata'; Values = @($real | ForEach-Object { [math]::Round([double]$_.DurationSec / 60, 1) }); Color = '#2b6cb0'; Type = 'bar' })
        $c5 = New-CVSvgChart -Title 'Durata media per disco compattato (secondi)' -Labels $labels -Unit 's' -Series @(
            @{ Name = 'Secondi per disco'; Values = @($real | ForEach-Object { [double]$_.AvgSecPerDisk }); Color = '#805ad5'; Type = 'line' })
        $c6 = New-CVSvgChart -Title 'Esito dei dischi per run' -Labels $labels -Series @(
            @{ Name = 'Compattati'; Values = @($real | ForEach-Object { [double]$_.Ok }); Color = '#1e7b4a'; Type = 'line' },
            @{ Name = 'Saltati'; Values = @($real | ForEach-Object { [double]$_.Skipped }); Color = '#b7791f'; Type = 'line' },
            @{ Name = 'Errori'; Values = @($real | ForEach-Object { [double]$_.Errors }); Color = '#c53030'; Type = 'line' },
            @{ Name = 'Non elaborati'; Values = @($real | ForEach-Object { [double]$_.NotDone }); Color = '#718096'; Type = 'line' })
        [void]$b.Append("<h2>Andamento</h2>$c1<div class=`"grid2`"><div>$c2</div><div>$c3</div><div>$c4</div><div>$c5</div></div>$c6")

        $growthRows = @(Get-CVUserGrowth $hist 10)
        [void]$b.Append('<h2>Profili cresciuti di più tra le ultime due run</h2>')
        if ($growthRows.Count) {
            [void]$b.Append('<table><tr><th>Utente</th><th>Disco</th><th class="n">Run precedente (MB)</th><th class="n">Ora (MB)</th><th class="n">Crescita (MB)</th></tr>')
            foreach ($g in $growthRows) { [void]$b.Append("<tr><td>$(ConvertTo-CVHtml $g.Utente)</td><td>$(ConvertTo-CVHtml $g.Tipo)</td><td class=`"n`">$($g.PrimaMB.ToString('N0'))</td><td class=`"n`">$($g.OraMB.ToString('N0'))</td><td class=`"n`">$($g.DeltaMB.ToString('N0'))</td></tr>") }
            [void]$b.Append('</table>')
        } else {
            [void]$b.Append('<div class="note">Servono almeno due run reali con il dettaglio per utente.</div>')
        }
    }

    [void]$b.Append('<h2>Tutte le run</h2><div class="scroll"><table><tr><th>Run</th><th>Avvio</th><th class="n">Durata</th><th>Tipo</th><th class="n">Dischi</th><th class="n">Compattati</th><th class="n">Saltati</th><th class="n">Esclusi</th><th class="n">Errori</th><th class="n">Non elab.</th><th class="n">Recuperati MB</th><th class="n">Libero dopo GB</th><th>Interruzione</th><th>Report</th></tr>')
    foreach ($h in ($hist | Sort-Object RunId -Descending)) {
        $tipo = "$($h.Trigger)$(if ($h.Simulation -eq 'True') { ' (simulazione)' } else { '' })"
        $link = if ($h.Report) { "<a href=`"$(ConvertTo-CVHtml (Split-Path $h.Report -Leaf))`">apri</a>" } else { '' }
        [void]$b.Append("<tr><td>$(ConvertTo-CVHtml $h.RunId)</td><td>$(ConvertTo-CVHtml $h.Start)</td><td class=`"n`">$(Format-CVDuration ([double]$h.DurationSec))</td><td>$(ConvertTo-CVHtml $tipo)</td><td class=`"n`">$($h.DisksTotal)</td><td class=`"n`">$($h.Ok)</td><td class=`"n`">$($h.Skipped)</td><td class=`"n`">$($h.Excluded)</td><td class=`"n`">$($h.Errors)</td><td class=`"n`">$($h.NotDone)</td><td class=`"n`">$(([double]$h.SavedMB).ToString('N0'))</td><td class=`"n`">$($h.VolumeFreeAfterGB)</td><td>$(ConvertTo-CVHtml $h.StopReason)</td><td>$link</td></tr>")
    }
    if (-not $hist.Count) { [void]$b.Append('<tr><td colspan="14">Nessuna run registrata</td></tr>') }
    [void]$b.Append('</table></div>')

    New-Item -ItemType Directory -Path (Split-Path $File -Parent) -Force | Out-Null
    New-CVHtmlPage 'Andamento compattazione VHDX' $b.ToString() | Out-File -LiteralPath $File -Encoding UTF8
}

function Get-CVHistoryReportPath($Config) { Join-Path $Config.ReportDir 'Andamento_CompactVHDX.html' }

# ============================================================================
#  Report della situazione attuale
# ============================================================================
function New-CVStatusReport {
    param($Config, $Inventory, [string]$File)

    $inv = $Inventory
    $v = $inv.Volume
    $b = New-Object System.Text.StringBuilder
    [void]$b.Append('<h1>Situazione attuale dei profili FSLogix</h1>')
    [void]$b.Append("<div class=`"sub`">$env:COMPUTERNAME - $(ConvertTo-CVHtml $inv.Path) - rilevata il $($inv.Collected.ToString('dd/MM/yyyy HH:mm'))</div>")
    if ($v -and $v.FreePct -lt $Config.FreeAlertPct) {
        [void]$b.Append("<div class=`"alert`">Spazio libero sul volume $($v.Drive) al $($v.FreePct)% ($($v.FreeGB) GB su $($v.SizeGB) GB): sotto la soglia del $($Config.FreeAlertPct)%.</div>")
    }
    if ($inv.Leftovers.Count) {
        [void]$b.Append("<div class=`"alert`">$($inv.Leftovers.Count) VHDX risultano agganciati a questo server (esecuzione interrotta?): usa 'Sgancia dischi rimasti' nella scheda Esecuzione.</div>")
    }

    [void]$b.Append('<div class="tiles">')
    if ($v) {
        [void]$b.Append((New-CVTile "$($v.SizeGB) GB" "Volume $($v.Drive)"))
        [void]$b.Append((New-CVTile "$($v.FreeGB) GB" "Libero ($($v.FreePct)%)" $(if ($v.FreePct -lt $Config.FreeAlertPct) { 'err' } else { 'ok' })))
    }
    [void]$b.Append((New-CVTile $inv.Count 'VHDX'))
    [void]$b.Append((New-CVTile ('{0:N1} GB' -f ($inv.TotalMB / 1024)) 'Peso totale' 'acc'))
    [void]$b.Append((New-CVTile ('{0:N0} MB' -f $inv.AvgMB) 'Media per profilo'))
    [void]$b.Append((New-CVTile ('{0:N0} MB' -f $inv.MaxMB) 'Profilo più grande'))
    [void]$b.Append((New-CVTile $inv.InUse 'In uso adesso' 'acc'))
    [void]$b.Append((New-CVTile $inv.Stale.Count "Inattivi da $($Config.StaleDays)+ gg" $(if ($inv.Stale.Count) { 'warn' } else { '' })))
    [void]$b.Append((New-CVTile $inv.NearMax.Count 'Oltre 80% del limite' $(if ($inv.NearMax.Count) { 'warn' } else { '' })))
    [void]$b.Append((New-CVTile $inv.OrphanLocks.Count 'Lock orfani' $(if ($inv.OrphanLocks.Count) { 'warn' } else { '' })))
    [void]$b.Append('</div>')

    # ultima run e pianificazione
    $hist = @(Get-CVHistory)
    $job = Get-ScheduledTask -TaskName $script:CVTaskJob -ErrorAction SilentlyContinue
    [void]$b.Append('<div class="card"><table class="info">')
    if ($hist.Count) {
        $l = $hist[-1]
        [void]$b.Append("<tr><td><b>Ultima run</b></td><td>$(ConvertTo-CVHtml $l.Start) - $(ConvertTo-CVHtml $l.Trigger)$(if ($l.Simulation -eq 'True') { ' (simulazione)' }) - compattati $($l.Ok), recuperati $(([double]$l.SavedMB).ToString('N0')) MB, interruzione: $(ConvertTo-CVHtml $l.StopReason)</td></tr>")
    } else {
        [void]$b.Append('<tr><td><b>Ultima run</b></td><td>nessuna</td></tr>')
    }
    if ($job) {
        $ji = $job | Get-ScheduledTaskInfo
        [void]$b.Append("<tr><td><b>Pianificazione</b></td><td>$(ConvertTo-CVHtml (Get-CVScheduleText $Config.Schedule)) - stato $($job.State) - prossima esecuzione $(if ($ji.NextRunTime) { $ji.NextRunTime.ToString('dd/MM/yyyy HH:mm') } else { 'n/d' })</td></tr>")
    } else {
        [void]$b.Append('<tr><td><b>Pianificazione</b></td><td>nessun task pianificato</td></tr>')
    }
    [void]$b.Append("<tr><td><b>Esclusi</b></td><td>$(if ($Config.ExcludeUsers.Count) { ConvertTo-CVHtml ($Config.ExcludeUsers -join ', ') } else { 'nessuno' })</td></tr>")
    [void]$b.Append('</table></div>')

    function Add-Table($Title, $Rows, $Cols, [string]$Empty) {
        [void]$b.Append("<h2>$(ConvertTo-CVHtml $Title)</h2>")
        if (-not @($Rows).Count) { [void]$b.Append("<div class=`"card`">$(ConvertTo-CVHtml $Empty)</div>"); return }
        [void]$b.Append('<div class="scroll"><table><tr>')
        foreach ($c in $Cols) { [void]$b.Append("<th$(if ($c.N) { ' class="n"' })>$(ConvertTo-CVHtml $c.H)</th>") }
        [void]$b.Append('</tr>')
        foreach ($r in $Rows) {
            [void]$b.Append('<tr>')
            foreach ($c in $Cols) { [void]$b.Append("<td$(if ($c.N) { ' class="n"' })>$(ConvertTo-CVHtml (& $c.V $r))</td>") }
            [void]$b.Append('</tr>')
        }
        [void]$b.Append('</table></div>')
    }

    $colsDisk = @(
        @{ H = 'Utente'; V = { param($r) $r.Utente } },
        @{ H = 'Disco'; V = { param($r) $r.Tipo } },
        @{ H = 'Dimensione (MB)'; N = $true; V = { param($r) $r.SizeMB.ToString('N0') } },
        @{ H = '% del limite'; N = $true; V = { param($r) $r.PctOfMax } },
        @{ H = 'Ultima scrittura'; V = { param($r) $r.LastWrite.ToString('dd/MM/yyyy HH:mm') } },
        @{ H = 'In uso da'; V = { param($r) $r.InUseBy } }
    )
    Add-Table 'I 20 profili più grandi' @($inv.Disks | Sort-Object SizeMB -Descending | Select-Object -First 20) $colsDisk 'Nessun VHDX trovato.'
    Add-Table "Profili inattivi da almeno $($Config.StaleDays) giorni (candidati alla pulizia)" $inv.Stale @(
        @{ H = 'Utente'; V = { param($r) $r.Utente } },
        @{ H = 'Dimensione (MB)'; N = $true; V = { param($r) $r.SizeMB.ToString('N0') } },
        @{ H = 'Giorni di inattività'; N = $true; V = { param($r) $r.DaysIdle } },
        @{ H = 'Ultima scrittura'; V = { param($r) $r.LastWrite.ToString('dd/MM/yyyy') } }
    ) 'Nessun profilo inattivo.'
    Add-Table "Profili oltre l'80% del limite FSLogix ($($Config.FslogixSizeMB) MB)" $inv.NearMax $colsDisk 'Nessun profilo vicino al limite.'
    Add-Table 'Lock e metadata orfani (senza disco in uso)' $inv.OrphanLocks @(
        @{ H = 'File'; V = { param($r) $r.File } },
        @{ H = 'Ultima scrittura'; V = { param($r) $r.LastWrite.ToString('dd/MM/yyyy HH:mm') } }
    ) 'Nessun lock orfano.'

    New-Item -ItemType Directory -Path (Split-Path $File -Parent) -Force | Out-Null
    New-CVHtmlPage 'Situazione profili FSLogix' $b.ToString() | Out-File -LiteralPath $File -Encoding UTF8
}

# ============================================================================
#  Pianificazione (Task Scheduler via XML)
# ============================================================================
function Get-CVScheduleText($S) {
    $days = @($S.DaysOfWeek | Sort-Object { $script:CVDayOrder.IndexOf("$_") } | ForEach-Object { $script:CVDaysIt["$_"] }) -join ', '
    $months = if (@($S.Months).Count -ge 12) { 'tutti i mesi' } else { (@($S.Months) | ForEach-Object { $script:CVMonthsIt[$script:CVMonths.IndexOf("$_")] }) -join ', ' }
    $when = switch ($S.Type) {
        'Daily'       { if ([int]$S.Interval -le 1) { 'Ogni giorno' } else { "Ogni $($S.Interval) giorni" } }
        'Weekly'      { "$(if ([int]$S.Interval -le 1) { 'Ogni settimana' } else { "Ogni $($S.Interval) settimane" }): $days" }
        'MonthlyDays' { "Mensile, giorno $((@($S.DaysOfMonth) | ForEach-Object { if ($_ -eq 'Last') { 'ultimo' } else { $_ } }) -join ', ') ($months)" }
        'MonthlyDow'  { "Mensile, $((@($S.WeeksOfMonth) | ForEach-Object { $script:CVWeeksIt["$_"].ToLower() }) -join '/') $days del mese ($months)" }
        default       { $S.Type }
    }
    $stop = if ($S.StopEnabled) { ", stop nuovi dischi alle $($S.StopAt)" } else { '' }
    $max = if ([int]$S.MaxDisks -gt 0) { ", max $($S.MaxDisks) dischi" } else { '' }
    "$when alle $($S.Start)$stop$max"
}

function Get-CVExecLimit($S) {
    # Limite di sicurezza: durata fino allo stop + 1 ora (default 12 ore senza stop)
    if (-not $S.StopEnabled) { return 'PT12H' }
    $a = [datetime]::ParseExact($S.Start, 'HH:mm', $null)
    $z = [datetime]::ParseExact($S.StopAt, 'HH:mm', $null)
    $h = ($z - $a).TotalHours
    if ($h -le 0) { $h += 24 }
    "PT$([math]::Ceiling($h) + 1)H"
}

function ConvertTo-CVXml([string]$s) { [Security.SecurityElement]::Escape($s) }

function New-CVTaskXml {
    param(
        [ValidateSet('Job', 'Monitor', 'Manual')][string]$Kind,
        $Schedule,
        [string]$Arguments,
        [string]$Description
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<?xml version="1.0" encoding="UTF-16"?>')
    [void]$sb.Append('<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">')
    [void]$sb.Append("<RegistrationInfo><Author>CompactVHDX</Author><Description>$(ConvertTo-CVXml $Description)</Description></RegistrationInfo>")

    if ($Kind -eq 'Manual') {
        [void]$sb.Append('<Triggers />')
    } else {
        $S = $Schedule
        $start = (Get-Date).Date.ToString('yyyy-MM-dd') + 'T' + $S.Start + ':00'   # senza fuso: segue l'ora locale
        $days  = (@($S.DaysOfWeek) | ForEach-Object { "<$_ />" }) -join ''
        $months = (@($S.Months) | ForEach-Object { "<$_ />" }) -join ''
        $inner = switch ($S.Type) {
            'Daily'       { "<ScheduleByDay><DaysInterval>$([math]::Max(1, [int]$S.Interval))</DaysInterval></ScheduleByDay>" }
            'Weekly'      { "<ScheduleByWeek><WeeksInterval>$([math]::Max(1, [int]$S.Interval))</WeeksInterval><DaysOfWeek>$days</DaysOfWeek></ScheduleByWeek>" }
            'MonthlyDays' { "<ScheduleByMonth><DaysOfMonth>$((@($S.DaysOfMonth) | ForEach-Object { "<Day>$_</Day>" }) -join '')</DaysOfMonth><Months>$months</Months></ScheduleByMonth>" }
            'MonthlyDow'  { "<ScheduleByMonthDayOfWeek><Weeks>$((@($S.WeeksOfMonth) | ForEach-Object { "<Week>$_</Week>" }) -join '')</Weeks><DaysOfWeek>$days</DaysOfWeek><Months>$months</Months></ScheduleByMonthDayOfWeek>" }
            default       { throw "Tipo di pianificazione non valido: $($S.Type)" }
        }
        [void]$sb.Append("<Triggers><CalendarTrigger><StartBoundary>$start</StartBoundary><Enabled>true</Enabled>$inner</CalendarTrigger></Triggers>")
    }

    if ($Kind -eq 'Monitor') {
        [void]$sb.Append('<Principals><Principal id="Author"><GroupId>S-1-5-32-544</GroupId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>')
        $limit = 'PT0S'
    } else {
        [void]$sb.Append('<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>')
        $limit = if ($Kind -eq 'Job') { Get-CVExecLimit $Schedule } else { 'PT24H' }
    }

    [void]$sb.Append('<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>')
    [void]$sb.Append("<ExecutionTimeLimit>$limit</ExecutionTimeLimit><Priority>7</Priority></Settings>")
    [void]$sb.Append("<Actions Context=`"Author`"><Exec><Command>powershell.exe</Command><Arguments>$(ConvertTo-CVXml $Arguments)</Arguments><WorkingDirectory>$(ConvertTo-CVXml $script:CVBase)</WorkingDirectory></Exec></Actions>")
    [void]$sb.Append('</Task>')
    $sb.ToString()
}

function Get-CVJobArguments([hashtable]$Options) {
    $a = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script:CVBase\Compact-ProfileDisks.ps1`""
    foreach ($k in $Options.Keys) {
        $v = $Options[$k]
        if ($v -is [bool]) { if ($v) { $a += " -$k" } }
        elseif ("$v" -ne '') { $a += " -$k `"$v`"" }
    }
    $a
}

function Register-CVSchedule($Config) {
    $S = $Config.Schedule
    $opt = @{ Trigger = 'Pianificata' }
    if ($S.StopEnabled) { $opt.StopAt = $S.StopAt }
    if ([int]$S.MaxDisks -gt 0) { $opt.MaxDisks = [int]$S.MaxDisks }
    $desc = "Compattazione offline dei VHDX FSLogix non in uso. $(Get-CVScheduleText $S). Per fermarla usare CompactVHDX Manager o Stop-CompactVHDX.ps1: NON terminare il task."
    $xml = New-CVTaskXml -Kind Job -Schedule $S -Arguments (Get-CVJobArguments $opt) -Description $desc
    Register-ScheduledTask -TaskName $script:CVTaskJob -Xml $xml -Force | Out-Null

    if ($S.MonitorForAdmins) {
        $margs = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$script:CVBase\CompactVHDX-Manager.ps1`" -StartTab Esecuzione -Auto"
        $xmlm = New-CVTaskXml -Kind Monitor -Schedule $S -Arguments $margs -Description 'Apre CompactVHDX Manager sulla scheda Esecuzione per gli amministratori collegati, all''avvio della compattazione pianificata.'
        Register-ScheduledTask -TaskName $script:CVTaskMonitor -Xml $xmlm -Force | Out-Null
    } else {
        Unregister-ScheduledTask -TaskName $script:CVTaskMonitor -Confirm:$false -ErrorAction SilentlyContinue
    }
}

function Start-CVManualRun([hashtable]$Options) {
    if (Test-CVJobRunning) { throw 'Una compattazione è già in esecuzione.' }
    $Options.Trigger = 'Manuale'
    $xml = New-CVTaskXml -Kind Manual -Arguments (Get-CVJobArguments $Options) -Description 'Esecuzione manuale da CompactVHDX Manager.'
    Register-ScheduledTask -TaskName $script:CVTaskManual -Xml $xml -Force | Out-Null
    if (Test-Path -LiteralPath $script:CVStatus) { Remove-Item -LiteralPath $script:CVStatus -Force -ErrorAction SilentlyContinue }
    Start-ScheduledTask -TaskName $script:CVTaskManual
}

# ============================================================================
#  Email
# ============================================================================
function Send-CVMail {
    param($Config, [string]$Subject, [string]$HtmlBody, [string[]]$Attachments = @())
    $m = $Config.Mail
    if (-not $m.From -or -not $m.To) { throw 'Configurazione email incompleta: mittente e destinatari sono obbligatori.' }
    $to = @("$($m.To)" -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $att = @($Attachments | Where-Object { $_ -and (Test-Path -LiteralPath $_) })

    if ("$($m.Method)" -eq 'Graph') {
        Send-CVGraphMail -Config $Config -Subject $Subject -HtmlBody $HtmlBody -Attachments $att -To $to
        return
    }

    if (-not $m.SmtpServer) { throw 'Configurazione email incompleta: server SMTP mancante.' }
    $p = @{
        SmtpServer = $m.SmtpServer
        Port       = [int]$m.Port
        From       = $m.From
        To         = $to
        Subject    = $Subject
        Body       = $HtmlBody
        BodyAsHtml = $true
        Encoding   = [Text.Encoding]::UTF8
    }
    if ($m.UseSsl) { $p.UseSsl = $true }
    if ($att.Count) { $p.Attachments = $att }
    Send-MailMessage @p -ErrorAction Stop -WarningAction SilentlyContinue
}

# ----------------------------------------------------------------- Microsoft 365 (Graph API)
$script:CVEntropy = [Text.Encoding]::UTF8.GetBytes('CompactVHDX-Mail')

function Protect-CVSecret([string]$Plain) {
    # DPAPI ambito macchina: decifrabile solo su questo server (dal pannello e dal job SYSTEM)
    if (-not $Plain) { return '' }
    Add-Type -AssemblyName System.Security
    $enc = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($Plain), $script:CVEntropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($enc)
}

function Unprotect-CVSecret([string]$Enc) {
    if (-not $Enc) { return '' }
    Add-Type -AssemblyName System.Security
    try {
        $dec = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($Enc), $script:CVEntropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        [Text.Encoding]::UTF8.GetString($dec)
    } catch {
        throw 'Impossibile decifrare il segreto client: va reinserito nelle Impostazioni (era stato salvato su un altro server?).'
    }
}

function Get-CVApiError($ErrorRecord) {
    $msg = $ErrorRecord.Exception.Message
    try {
        $j = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
        if ($j.error.message) { $msg = "$($j.error.code): $($j.error.message)" }
        elseif ($j.error_description) { $msg = ($j.error_description -split "`r?`n")[0] }
    } catch { }
    $msg
}

function Send-CVGraphMail {
    param($Config, [string]$Subject, [string]$HtmlBody, [string[]]$Attachments = @(), [string[]]$To)
    $m = $Config.Mail
    if (-not $m.TenantId -or -not $m.ClientId -or -not $m.SecretEnc) { throw 'Configurazione Microsoft 365 incompleta: Tenant ID, Client ID e segreto client sono obbligatori.' }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $secret = Unprotect-CVSecret $m.SecretEnc

    try {
        $tok = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($m.TenantId)/oauth2/v2.0/token" -ErrorAction Stop -Body @{
            client_id     = $m.ClientId
            client_secret = $secret
            scope         = 'https://graph.microsoft.com/.default'
            grant_type    = 'client_credentials'
        }
    } catch {
        throw "Autenticazione Microsoft 365 non riuscita: $(Get-CVApiError $_)"
    }

    $message = @{
        subject      = $Subject
        body         = @{ contentType = 'HTML'; content = $HtmlBody }
        toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
    }
    $att = @(foreach ($a in $Attachments) {
        @{
            '@odata.type' = '#microsoft.graph.fileAttachment'
            name          = (Split-Path $a -Leaf)
            contentType   = 'text/html'
            contentBytes  = [Convert]::ToBase64String([IO.File]::ReadAllBytes($a))
        }
    })
    if ($att.Count) { $message.attachments = $att }
    $json = @{ message = $message; saveToSentItems = $false } | ConvertTo-Json -Depth 8

    try {
        Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($m.From))/sendMail" `
            -Headers @{ Authorization = "Bearer $($tok.access_token)" } -ContentType 'application/json; charset=utf-8' `
            -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop | Out-Null
    } catch {
        throw "Invio tramite Microsoft 365 non riuscito: $(Get-CVApiError $_)"
    }
}

function Set-CVSecureFolder([string]$Path) {
    # Cartella degli script (contiene config.json con il segreto cifrato): accesso solo a SYSTEM e Administrators
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# ============================================================================
#  Pulizia di log e report vecchi
# ============================================================================
function Invoke-CVRetention($Config) {
    $days = [int]$Config.RetentionDays
    if ($days -le 0) { return 0 }
    $limit = (Get-Date).AddDays(-$days)
    $n = 0
    foreach ($spec in @(
            @{ Dir = $script:CVLogDir; Filter = 'Compact_*' },
            @{ Dir = $script:CVLogDir; Filter = 'Errori_2*' },
            @{ Dir = $script:CVLogDir; Filter = 'Transcript_*' },
            @{ Dir = $Config.ReportDir; Filter = 'Report_CompactVHDX_*.html' },
            @{ Dir = $Config.ReportDir; Filter = 'Situazione_*.html' })) {
        if (-not (Test-Path -LiteralPath $spec.Dir)) { continue }
        Get-ChildItem -LiteralPath $spec.Dir -Filter $spec.Filter -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $limit } |
            ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue; $n++ }
    }
    # il log cumulativo di errori e avvisi non viene cancellato: si accorcia alle ultime 10000 righe
    try {
        if ((Test-Path -LiteralPath $script:CVIssuesLog) -and (Get-Item -LiteralPath $script:CVIssuesLog).Length -gt 5MB) {
            $keep = @(Get-Content -LiteralPath $script:CVIssuesLog -Tail 10000 -Encoding UTF8)
            Set-Content -LiteralPath $script:CVIssuesLog -Value $keep -Encoding UTF8
        }
    } catch { }
    $n
}
