# NB: niente "#Requires -RunAsAdministrator": bloccherebbe lo script prima dell'auto-elevazione UAC qui sotto
#Requires -Version 5.1
<#
.SYNOPSIS
    WinAuditPro - audit e ottimizzazione di Windows Server / Terminal Server (RDS).

.DESCRIPTION
    Audit completo con report HTML (grafici, trend, export CSV), ottimizzazioni RDS con
    apply/revert e stato persistente, confronto baseline con severity.
    Unico file, nessuna dipendenza esterna.

    Senza parametri apre il pannello grafico: impostazioni salvabili, elenco degli audit
    salvati, azioni eseguite in background con log in tempo reale.
    -Console apre il menu testuale classico. -NoGui / -Action per esecuzioni non interattive.

.PARAMETER Action
    Esecuzione non interattiva: Audit (JSON + HTML), AuditJson, Report (HTML da JSON),
    DryRun (ottimizzazioni senza applicare), Optimize (finestra apply/revert), Compare.

.PARAMETER OutputPath
    Cartella di audit, report e stato delle ottimizzazioni. Default da configurazione
    (C:\PerformanceAudit).

.PARAMETER JsonPath
    Con -Action Report/DryRun/Optimize: audit da usare (default: l'ultimo).

.PARAMETER BaselinePath
    Con -Action Compare: audit di riferimento.

.PARAMETER CurrentPath
    Con -Action Compare: audit da confrontare.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\WinAuditPro\config.json

.PARAMETER NoGui
    Senza -Action esegue un audit completo senza interfaccia.

.PARAMETER Console
    Menu testuale (comportamento della versione 2.0).

.PARAMETER Quick
    Audit completo senza menu e senza aprire il report (compatibilita' 2.0).

.PARAMETER CmdletTimeoutSec
    Timeout dei cmdlet lenti. Default da configurazione (30).

.EXAMPLE
    .\Invoke-WinAuditPro.ps1

.EXAMPLE
    .\Invoke-WinAuditPro.ps1 -NoGui -OutputPath D:\Audit

.EXAMPLE
    .\Invoke-WinAuditPro.ps1 -Action Compare -BaselinePath .\a.json -CurrentPath .\b.json

.NOTES
    Versione : 2.1.1 TS-Edition
    Repo     : fispas/tools (rds/winauditpro)
    Richiede : amministratore, PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Quick,
    [int]$CmdletTimeoutSec = 0,
    [ValidateSet('Audit', 'AuditJson', 'Report', 'DryRun', 'Optimize', 'Compare')][string]$Action,
    [string]$JsonPath,
    [string]$BaselinePath,
    [string]$CurrentPath,
    [string]$ConfigPath,
    [switch]$NoGui,
    [switch]$Console
)


# Auto-elevazione: se non admin, rilancia con UAC
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Action -or $NoGui) { Write-Error 'Servono i privilegi di amministratore.'; exit 1 }
    $argList = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$PSCommandPath`""
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += " -$($kv.Key)" } }
        else { $argList += " -$($kv.Key) `"$($kv.Value)`"" }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

# ==============================================================================
# CONFIGURAZIONE (salvabile dal pannello)
# ==============================================================================
$script:WapVersion       = '2.1.1'
$script:WapScriptPath    = $PSCommandPath
$script:WapDataDir       = Join-Path $env:ProgramData 'FispaTools\WinAuditPro'
$script:WapDefaultConfig = Join-Path $script:WapDataDir 'config.json'

function Get-WapDefaultConfig {
    [ordered]@{
        OutputPath       = 'C:\PerformanceAudit'
        CmdletTimeoutSec = 30
        DaysToScan       = 7
        MaxEvents        = 200
        OpenReport       = $true
    }
}

function Read-WapConfig([string]$Path) {
    $cfg = Get-WapDefaultConfig
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        try {
            $o = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($k in @($cfg.Keys)) {
                $pp = $o.PSObject.Properties[$k]
                if ($pp -and $null -ne $pp.Value -and "$($pp.Value)" -ne '') {
                    if ($cfg[$k] -is [int]) { $cfg[$k] = [int]$pp.Value }
                    elseif ($cfg[$k] -is [bool]) { $cfg[$k] = [bool]$pp.Value }
                    else { $cfg[$k] = [string]$pp.Value }
                }
            }
        } catch { Write-Warning "Configurazione non leggibile ($Path): uso i valori predefiniti. $_" }
    }
    $cfg
}

function Save-WapConfig($Cfg, [string]$Path) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = [pscustomobject]$Cfg | ConvertTo-Json
    $tmp = "$Path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($true)))
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, "$Path.bak", $true) }
    else { [System.IO.File]::Move($tmp, $Path) }
}

$script:WapCfgPath = $script:WapDefaultConfig
if ($ConfigPath) { $script:WapCfgPath = $ConfigPath }
$script:WapCfg = Read-WapConfig $script:WapCfgPath
if ($OutputPath) { $script:WapCfg.OutputPath = $OutputPath } else { $OutputPath = $script:WapCfg.OutputPath }
if ($CmdletTimeoutSec -gt 0) { $script:WapCfg.CmdletTimeoutSec = $CmdletTimeoutSec } else { $CmdletTimeoutSec = [int]$script:WapCfg.CmdletTimeoutSec }

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
Set-StrictMode -Version 1.0
$ErrorActionPreference = 'SilentlyContinue'

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$SEP  = '  ' + ('-' * 60)
$SEP2 = '  ' + ('=' * 60)
$script:AuditLogFile = ''

# ==============================================================================
# UTILITY GLOBALI
# ==============================================================================

function Write-AuditLog {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts    = (Get-Date).ToString('HH:mm:ss')
    $entry = "[$ts][$Level] $Msg"
    if ($script:AuditLogFile) { Add-Content -Path $script:AuditLogFile -Value $entry -EA SilentlyContinue }
    $color = switch ($Level) {
        'OK'      { 'Green'  } 'WARN'    { 'Yellow' }
        'ERROR'   { 'Red'    } 'SECTION' { 'Cyan'   }
        default   { 'Gray'   }
    }
    Write-Host $entry -ForegroundColor $color
}

function Write-AuditSection { param([string]$Name) Write-AuditLog "===[ $Name ]===" 'SECTION' }

# Esegue uno scriptblock con timeout; restituisce $null se scade o lancia eccezione
function Invoke-WithTimeout {
    param([scriptblock]$ScriptBlock, [int]$TimeoutSec = $CmdletTimeoutSec, [string]$Label = '')
    $job = Start-Job -ScriptBlock $ScriptBlock
    $done = Wait-Job $job -Timeout $TimeoutSec
    if ($done) {
        try { $result = Receive-Job $job -ErrorAction Stop; Remove-Job $job -Force; return $result }
        catch { Remove-Job $job -Force; if ($Label) { Write-AuditLog "Timeout/errore: $Label" 'WARN' }; return $null }
    } else {
        Stop-Job $job; Remove-Job $job -Force
        if ($Label) { Write-AuditLog "TIMEOUT ($TimeoutSec s): $Label" 'WARN' }
        return $null
    }
}

function Get-RegVal {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -EA Stop).$Name } catch { return $null }
}

# Traduce un path contatore inglese nella lingua del sistema (Get-Counter accetta solo nomi localizzati:
# su Windows in italiano '\Processor(_Total)\% Processor Time' fallisce).
$script:PerfNameMap = $null
function ConvertTo-LocalCounter {
    param([string]$Path)
    try {
        if ($null -eq $script:PerfNameMap) {
            $script:PerfNameMap = @{}
            $en  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009' -Name Counter -EA Stop).Counter
            $loc = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage' -Name Counter -EA Stop).Counter
            $idxToLoc = @{}
            for ($i = 0; $i -lt $loc.Count - 1; $i += 2) { if (-not $idxToLoc.ContainsKey($loc[$i])) { $idxToLoc[$loc[$i]] = $loc[$i+1] } }
            for ($i = 0; $i -lt $en.Count - 1; $i += 2) {
                $name = $en[$i+1]
                if (-not $script:PerfNameMap.ContainsKey($name) -and $idxToLoc.ContainsKey($en[$i])) { $script:PerfNameMap[$name] = $idxToLoc[$en[$i]] }
            }
        }
        if ($script:PerfNameMap.Count -eq 0) { return $Path }
        if ($Path -match '^\\(?<obj>[^\\(]+)(?<inst>\([^)]*\))?\\(?<ctr>.+)$') {
            $obj = $Matches.obj; $inst = $Matches.inst; $ctr = $Matches.ctr
            if ($script:PerfNameMap.ContainsKey($obj)) { $obj = $script:PerfNameMap[$obj] }
            if ($script:PerfNameMap.ContainsKey($ctr)) { $ctr = $script:PerfNameMap[$ctr] }
            return "\$obj$inst\$ctr"
        }
    } catch { }
    return $Path
}

# Get-Counter con fallback automatico: prova il path inglese, poi quello localizzato
function Get-CounterRaw {
    param([string]$Counter, [int]$Interval = 1, [int]$Samples = 1)
    try { return Get-Counter $Counter -SampleInterval $Interval -MaxSamples $Samples -EA Stop }
    catch {
        $locPath = ConvertTo-LocalCounter $Counter
        if ($locPath -eq $Counter) { throw }
        return Get-Counter $locPath -SampleInterval $Interval -MaxSamples $Samples -EA Stop
    }
}

# Dimensione cartella (include file nascosti, non segue junction/symlink: evita doppi conteggi e loop)
function Get-FolderSizeBytes {
    param([string]$Path)
    [long]$total = 0
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    try { $stack.Push([System.IO.DirectoryInfo]::new($Path)) } catch { return 0 }
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($fi in $dir.EnumerateFiles()) { try { $total += $fi.Length } catch { } }
            foreach ($sub in $dir.EnumerateDirectories()) {
                if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($sub) }
            }
        } catch { }
    }
    return $total
}

function Get-CounterSafe {
    param([string]$Counter, [int]$Samples = 3, [int]$Interval = 2)
    try {
        $r = (Get-CounterRaw $Counter -Interval $Interval -Samples $Samples).CounterSamples |
             Measure-Object -Property CookedValue -Average
        return [math]::Round($r.Average, 2)
    } catch { return $null }
}

# Legge l'indice AC di CPMINCORES del piano attivo (indipendente dalla lingua: usa i valori esadecimali)
function Get-CpuMinCoresAC {
    try {
        $out = (powercfg /query SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 2>$null) -join "`n"
        $hex = [regex]::Matches($out, '0x([0-9a-fA-F]{8})')
        # Ordine output: min, max, incremento, AC, DC
        if ($hex.Count -ge 4) { return [Convert]::ToInt32($hex[3].Groups[1].Value, 16) }
    } catch { }
    return $null
}

function Round2 { param($v); if ($null -eq $v) { return $null }; return [math]::Round($v, 2) }
function Round0 { param($v); if ($null -eq $v) { return $null }; return [math]::Round($v, 0) }
function S      { param($v); if ($null -eq $v) { return '' } else { return "$v" } }

function Get-LastJson {
    $files = @(Get-ChildItem -Path $OutputPath -Filter '*AuditData*.json' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($files.Count -gt 0) { return $files[0].FullName }
    return $null
}

function Get-AllJsons {
    return @(Get-ChildItem -Path $OutputPath -Filter '*AuditData*.json' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
}

# ==============================================================================
# MENU HELPERS
# ==============================================================================

function Write-Header {
    Clear-Host
    Write-Host ''
    Write-Host $SEP2 -ForegroundColor Cyan
    Write-Host "  WinAuditPro $script:WapVersion  [TS-Edition]" -ForegroundColor Cyan
    Write-Host '  Windows Terminal Server Audit & Optimization Tool' -ForegroundColor Cyan
    Write-Host $SEP2 -ForegroundColor Cyan
    Write-Host "  Server : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  Data   : $(Get-Date -Format 'dd/MM/yyyy HH:mm')" -ForegroundColor White
    Write-Host "  Output : $OutputPath" -ForegroundColor White
    Write-Host $SEP -ForegroundColor DarkGray
    Write-Host ''
}

function Write-MenuItem {
    param([string]$Key, [string]$Label, [string]$Desc, [ConsoleColor]$Color = 'White')
    Write-Host "    [$Key] " -ForegroundColor Cyan -NoNewline
    Write-Host "$Label" -ForegroundColor $Color -NoNewline
    if ($Desc) { Write-Host "  -  $Desc" -ForegroundColor DarkGray } else { Write-Host '' }
}

function Show-LastAuditStatus {
    $j = Get-LastJson
    if (-not $j) { Write-Host '  Nessun audit precedente trovato' -ForegroundColor DarkGray; return }
    try {
        $d       = (Get-Content $j -Raw -Encoding UTF8) | ConvertFrom-Json
        $critCol = if ($d.scores.critCount -gt 0) { 'Red' } else { 'Green' }
        $warnCol = if ($d.scores.warnCount -gt 0) { 'Yellow' } else { 'Green' }
        Write-Host '  Ultimo audit : ' -ForegroundColor DarkGray -NoNewline
        Write-Host "$($d.meta.auditDate)" -ForegroundColor White -NoNewline
        Write-Host '   Critici: ' -ForegroundColor DarkGray -NoNewline
        Write-Host "$($d.scores.critCount)" -ForegroundColor $critCol -NoNewline
        Write-Host '   Warning: ' -ForegroundColor DarkGray -NoNewline
        Write-Host "$($d.scores.warnCount)" -ForegroundColor $warnCol
    } catch { }
}

function Pause-Menu {
    Write-Host ''; Write-Host '  Premi INVIO per tornare al menu...' -ForegroundColor DarkGray
    Read-Host | Out-Null
}


# ==============================================================================
# INVOKE-FULLAUDIT
# ==============================================================================

function Invoke-FullAudit {
    param(
        [string]$AuditOutputPath = $OutputPath,
        [int]$DaysToScan  = [int]$script:WapCfg.DaysToScan,
        [int]$MaxEvents   = [int]$script:WapCfg.MaxEvents,
        [switch]$OpenReport,
        [switch]$JsonOnly
    )

    $ScriptVersion = $script:WapVersion
    $StartTime     = Get-Date
    $Timestamp     = $StartTime.ToString('yyyyMMdd_HHmmss')
    $CN            = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'SRV' }

    if (-not (Test-Path $AuditOutputPath)) { New-Item -ItemType Directory -Path $AuditOutputPath -Force | Out-Null }
    $script:AuditLogFile = Join-Path $AuditOutputPath "audit_${CN}_${Timestamp}.log"

    # --------------------------------------------------------------------------
    # RUOLO SERVER
    # --------------------------------------------------------------------------
    Write-AuditSection 'Rilevamento ruolo'

    $isTS = $false; $isDB = $false
    try { $rdsF = Get-WindowsFeature -Name 'RDS-RD-Server' -EA Stop; if ($rdsF.Installed) { $isTS = $true } } catch { }
    $sqlSvcs = @(Get-Service | Where-Object { $_.Name -match 'SQLANYs_|^MSSQL' })
    if ($sqlSvcs.Count -gt 0) { $isDB = $true }

    $ServerRole = if ($isDB -and -not $isTS) { 'DB Server' } elseif ($isTS) { 'Terminal Server' } else { 'Server' }
    $RoleCode   = if ($isDB -and -not $isTS) { 'DB' } elseif ($isTS) { 'TS' } else { 'SRV' }
    Write-AuditLog "Ruolo: $ServerRole ($RoleCode)" 'OK'

    # --------------------------------------------------------------------------
    # QUSER - sessioni RDP
    # --------------------------------------------------------------------------
    $activeUsers = 0; $disconnectedCount = 0; $quserLines = @()
    try {
        $qr = quser 2>$null
        if ($qr) {
            $quserLines        = @($qr | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
            $activeUsers       = ($quserLines | Where-Object { $_ -notmatch 'Disc' }).Count
            $disconnectedCount = ($quserLines | Where-Object { $_ -match  'Disc' }).Count
        }
    } catch { }

    # --------------------------------------------------------------------------
    # 1. SISTEMA
    # --------------------------------------------------------------------------
    Write-AuditSection 'Sistema'

    $os   = $null; $cs = $null; $bios = $null
    try { $os   = Get-CimInstance Win32_OperatingSystem  -EA Stop } catch { $os   = [PSCustomObject]@{Caption='N/A';Version='0';BuildNumber='0';OSArchitecture='N/A';InstallDate=(Get-Date);LastBootUpTime=(Get-Date);TotalVisibleMemorySize=0;FreePhysicalMemory=0} }
    try { $cs   = Get-CimInstance Win32_ComputerSystem   -EA Stop } catch { $cs   = [PSCustomObject]@{Domain='N/A';Manufacturer='N/A';Model='N/A';NumberOfProcessors=1;NumberOfLogicalProcessors=1} }
    try { $bios = Get-CimInstance Win32_BIOS             -EA Stop } catch { $bios = [PSCustomObject]@{SMBIOSBIOSVersion='N/A'} }
    $tz   = try { Get-TimeZone } catch { [PSCustomObject]@{DisplayName='N/A'} }
    $up   = (Get-Date) - $os.LastBootUpTime
    $isVirtual  = ($cs.Model -match 'Virtual|VMware|KVM|Xen|HVM|Hyper-V')
    $hypervisor = if ($cs.Manufacturer -match 'Microsoft') { 'Hyper-V' } elseif ($cs.Manufacturer -match 'VMware') { 'VMware' } elseif ($cs.Model -match 'KVM') { 'KVM' } else { 'Physical/Unknown' }
    $installDateStr = try { $os.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') } catch { '' }
    $lastBootStr    = try { $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { '' }

    $sysData = [ordered]@{
        os                   = S $os.Caption
        version              = S $os.Version
        build                = S $os.BuildNumber
        arch                 = S $os.OSArchitecture
        installDate          = $installDateStr
        lastBoot             = $lastBootStr
        uptimeDays           = [int]$up.Days
        uptimeHours          = [int]$up.Hours
        uptimeMinutes        = [int]$up.Minutes
        domain               = S $cs.Domain
        manufacturer         = S $cs.Manufacturer
        model                = S $cs.Model
        biosVersion          = S $bios.SMBIOSBIOSVersion
        timeZone             = S $tz.DisplayName
        isVirtual            = [bool]$isVirtual
        hypervisor           = S $hypervisor
        activeUsers          = [int]$activeUsers
        disconnectedSessions = [int]$disconnectedCount
    }
    Write-AuditLog "OS: $($sysData.os) build $($sysData.build)" 'OK'

    # --------------------------------------------------------------------------
    # 2. CPU
    # --------------------------------------------------------------------------
    Write-AuditSection 'CPU'

    $cpuObj   = @(Get-CimInstance Win32_Processor -EA SilentlyContinue)
    $cpuFirst = if ($cpuObj.Count -gt 0) { $cpuObj[0] } else { $null }
    $lp       = [int]$cs.NumberOfLogicalProcessors
    $cores    = if ($cpuFirst) { [int]$cpuFirst.NumberOfCores } else { 0 }

    $avgCpu  = Get-CounterSafe '\Processor(_Total)\% Processor Time'
    $avgQ    = Get-CounterSafe '\System\Processor Queue Length'       -Interval 1
    $avgCtx  = Get-CounterSafe '\System\Context Switches/sec'         -Interval 1
    $actThrd = Get-CounterSafe '\System\Threads'                      -Interval 1

    # Fallback WMI se Get-Counter restituisce null o 0
    if ($null -eq $avgCpu -or $avgCpu -eq 0) {
        try {
            $cpuWmi = Get-CimInstance Win32_Processor -EA Stop
            $avgCpu = [math]::Round(($cpuWmi | Measure-Object -Property LoadPercentage -Average).Average, 2)
        } catch { }
    }
    if ($null -eq $actThrd -or $actThrd -eq 0) {
        try { $actThrd = (Get-Process -EA SilentlyContinue | ForEach-Object { $_.Threads.Count } | Measure-Object -Sum).Sum } catch { }
    }

    $perCore = @()
    try {
        $cSamples = (Get-CounterRaw '\Processor(*)\% Processor Time' -Interval 1 -Samples 1).CounterSamples
        $perCore  = @($cSamples | Where-Object { $_.InstanceName -ne '_total' } | Sort-Object {
            try { [int]$_.InstanceName } catch { 0 }
        } | ForEach-Object { [int][math]::Round($_.CookedValue, 0) })
    } catch {
        # Fallback: usa WMI per utilizzo per processore logico
        try {
            $procWmi = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -EA Stop |
                       Where-Object { $_.Name -ne '_Total' } |
                       Sort-Object { try { [int]$_.Name } catch { 0 } }
            $perCore = @($procWmi | ForEach-Object { [int]$_.PercentProcessorTime })
        } catch { }
    }

    # Core parking: CPMINCORES (% minimo core non parcheggiati) del piano attivo; 100 = parking disattivato
    $parkMinCores = Get-CpuMinCoresAC
    if ($null -ne $parkMinCores) {
        $parkingEnabled = ($parkMinCores -lt 100)
    } else {
        $parkVal        = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583' 'ValueMax'
        $parkingEnabled = ($null -eq $parkVal -or $parkVal -ne 0)
    }

    $cpuName        = if ($cpuFirst) { S $cpuFirst.Name.Trim() } else { 'Sconosciuto' }
    $cpuMaxClock    = if ($cpuFirst) { [int]$cpuFirst.MaxClockSpeed }    else { 0 }
    $cpuCurClock    = if ($cpuFirst) { [int]$cpuFirst.CurrentClockSpeed } else { 0 }
    $cpuL2          = if ($cpuFirst) { [int]$cpuFirst.L2CacheSize }      else { 0 }
    $cpuL3          = if ($cpuFirst) { [int]$cpuFirst.L3CacheSize }      else { 0 }
    $cpuAvgPct      = if ($null -ne $avgCpu)  { Round2 $avgCpu  } else { 0.0 }
    $cpuQueue       = if ($null -ne $avgQ)    { Round2 $avgQ    } else { 0.0 }
    $cpuCtxSw       = if ($null -ne $avgCtx)  { Round0 $avgCtx  } else { 0   }
    $cpuActThrd     = if ($null -ne $actThrd) { Round0 $actThrd } else { 0   }
    $cpuPerUserVal  = if ($activeUsers -gt 0) { Round2 ($lp / $activeUsers) } else { $null }

    $cpuData = [ordered]@{
        name                  = $cpuName
        physicalSockets       = [int]$cs.NumberOfProcessors
        coresTotal            = $cores
        logicalProcessors     = $lp
        maxClockMhz           = $cpuMaxClock
        currentClockMhz       = $cpuCurClock
        l2CacheKB             = $cpuL2
        l3CacheKB             = $cpuL3
        hyperThreading        = ($lp -gt $cores)
        avgUsagePct           = $cpuAvgPct
        processorQueue        = $cpuQueue
        contextSwitchesPerSec = $cpuCtxSw
        activeThreads         = $cpuActThrd
        parkingEnabled        = [bool]$parkingEnabled
        coresPerUser          = $cpuPerUserVal
        perCoreUsage          = $perCore
    }
    Write-AuditLog "CPU: $($cpuData.name) - uso: $($cpuData.avgUsagePct)%" 'OK'

    # --------------------------------------------------------------------------
    # 3. RAM
    # --------------------------------------------------------------------------
    Write-AuditSection 'Memoria RAM'

    $totalRAM = Round2 ($os.TotalVisibleMemorySize / 1MB)
    $freeRAM  = Round2 ($os.FreePhysicalMemory      / 1MB)
    $usedRAM  = Round2 ($totalRAM - $freeRAM)
    $ramPct   = if ($totalRAM -gt 0) { Round2 (($usedRAM / $totalRAM) * 100) } else { 0 }

    $pagesSec   = Get-CounterSafe '\Memory\Pages/sec'           -Interval 1 -Samples 2
    $pageFaults = Get-CounterSafe '\Memory\Page Faults/sec'     -Interval 1 -Samples 2
    $poolNP     = Get-CounterSafe '\Memory\Pool Nonpaged Bytes' -Interval 1 -Samples 2
    $committed  = Get-CounterSafe '\Memory\Committed Bytes'     -Interval 1 -Samples 2
    $commitLim  = Get-CounterSafe '\Memory\Commit Limit'        -Interval 1 -Samples 2
    $availMB    = Get-CounterSafe '\Memory\Available MBytes'    -Interval 1 -Samples 2

    $pf   = @(Get-CimInstance Win32_PageFileUsage -EA SilentlyContinue)   # possono esserci piu pagefile
    $pfs  = Get-CimInstance Win32_PageFileSetting -EA SilentlyContinue
    $dpex = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'DisablePagingExecutive'

    $perUserRam = @()
    if ($isTS) {
        try {
            $procsByUser = Get-Process -IncludeUserName -EA Stop |
                Where-Object { $_.UserName -and $_.UserName -notmatch 'SYSTEM|DWM-|UMFD-|LOCAL SERVICE|NETWORK SERVICE' } |
                Group-Object UserName
            $perUserRam = @($procsByUser | ForEach-Object {
                [ordered]@{ user = S $_.Name; ramGB = Round2(($_.Group | Measure-Object WorkingSet64 -Sum).Sum / 1GB); processes = [int]$_.Count }
            } | Sort-Object { $_.ramGB } -Descending)
        } catch { }
    }

    $ramAvailMB     = if ($null -ne $availMB)   { Round0 $availMB            } else { 0   }
    $ramPagesSec2   = if ($null -ne $pagesSec)  { Round2 $pagesSec           } else { 0.0 }
    $ramPageFaults  = if ($null -ne $pageFaults){ Round0 $pageFaults         } else { 0   }
    $ramPoolNP      = if ($null -ne $poolNP)    { Round2 ($poolNP / 1MB)     } else { 0.0 }
    $ramCommitted   = if ($null -ne $committed) { Round2 ($committed / 1GB)  } else { 0.0 }
    $ramCommitLim   = if ($null -ne $commitLim) { Round2 ($commitLim / 1GB)  } else { 0.0 }
    $ramPFLocation  = if ($pf.Count -gt 0) { (@($pf | ForEach-Object { S $_.Name }) -join ', ') } else { '' }
    $ramPFAllocMB   = if ($pf.Count -gt 0) { [int](($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum) } else { 0 }
    $ramPFUsedMB    = if ($pf.Count -gt 0) { [int](($pf | Measure-Object -Property CurrentUsage -Sum).Sum) } else { 0 }
    $ramPFManaged   = if ($cs.PSObject.Properties['AutomaticManagedPagefile'] -and $cs.AutomaticManagedPagefile) { 'Automatico' } elseif (-not $pfs) { 'Automatico' } else { 'Manuale' }
    $ramPerUser     = if ($activeUsers -gt 0) { Round2 ($totalRAM / $activeUsers) } else { $null }

    $ramData = [ordered]@{
        totalGB               = $totalRAM
        usedGB                = $usedRAM
        freeGB                = $freeRAM
        usagePct              = $ramPct
        availableMB           = $ramAvailMB
        pagesSec              = $ramPagesSec2
        pageFaultsSec         = $ramPageFaults
        poolNonPagedMB        = $ramPoolNP
        committedGB           = $ramCommitted
        commitLimitGB         = $ramCommitLim
        disablePagingExecutive= ($dpex -eq 1)
        pagefileLocation      = $ramPFLocation
        pagefileAllocatedMB   = $ramPFAllocMB
        pagefileUsedMB        = $ramPFUsedMB
        pagefileManaged       = $ramPFManaged
        ramPerUserGB          = $ramPerUser
        perUserRam            = $perUserRam
    }
    Write-AuditLog "RAM: $usedRAM / $totalRAM GB ($ramPct%)" 'OK'

    # --------------------------------------------------------------------------
    # 4. DISCO
    # --------------------------------------------------------------------------
    Write-AuditSection 'Disco'

    $rLat  = Get-CounterSafe '\PhysicalDisk(_Total)\Avg. Disk sec/Read'
    $wLat  = Get-CounterSafe '\PhysicalDisk(_Total)\Avg. Disk sec/Write'
    $dQ    = Get-CounterSafe '\PhysicalDisk(_Total)\Current Disk Queue Length'
    $iops  = Get-CounterSafe '\PhysicalDisk(_Total)\Disk Transfers/sec'

    # Fallback per NVMe: se _Total restituisce 0 prova con indice disco fisico
    if (($null -eq $rLat -or $rLat -eq 0) -and ($null -eq $wLat -or $wLat -eq 0)) {
        try {
            $diskSamples = (Get-CounterRaw '\PhysicalDisk(*)\Avg. Disk sec/Read' -Interval 2 -Samples 2).CounterSamples |
                           Where-Object { $_.InstanceName -ne '_total' -and $_.CookedValue -gt 0 } |
                           Measure-Object -Property CookedValue -Average
            if ($diskSamples.Average -gt 0) { $rLat = [math]::Round($diskSamples.Average, 6) }

            $diskSamplesW = (Get-CounterRaw '\PhysicalDisk(*)\Avg. Disk sec/Write' -Interval 2 -Samples 2).CounterSamples |
                            Where-Object { $_.InstanceName -ne '_total' -and $_.CookedValue -gt 0 } |
                            Measure-Object -Property CookedValue -Average
            if ($diskSamplesW.Average -gt 0) { $wLat = [math]::Round($diskSamplesW.Average, 6) }

            # Fallback IOPS
            if ($null -eq $iops -or $iops -eq 0) {
                $iopsSamples = (Get-CounterRaw '\PhysicalDisk(*)\Disk Transfers/sec' -Interval 2 -Samples 2).CounterSamples |
                               Where-Object { $_.InstanceName -ne '_total' } |
                               Measure-Object -Property CookedValue -Sum
                if ($iopsSamples.Sum -gt 0) { $iops = [math]::Round($iopsSamples.Sum, 0) }
            }
        } catch { }

        # Fallback StorPort per NVMe se ancora 0
        if (($null -eq $rLat -or $rLat -eq 0) -and ($null -eq $wLat -or $wLat -eq 0)) {
            try {
                $nvmeR = Get-CounterRaw '\StorPort(*)\Avg. Latency per IO (ms)' -Interval 2 -Samples 2
                $nvmeAvg = ($nvmeR.CounterSamples | Where-Object { $_.CookedValue -gt 0 } | Measure-Object -Property CookedValue -Average).Average
                if ($nvmeAvg -gt 0) {
                    # StorPort in ms, converti in secondi per compatibilita
                    $rLat = $nvmeAvg / 1000
                    $wLat = $nvmeAvg / 1000
                }
            } catch { }
        }
    }
    $nla   = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' 'NtfsDisableLastAccessUpdate'
    # NtfsDisableLastAccessUpdate: bit 0 = 1 -> aggiornamento DISABILITATO (valori 1, 0x80000001, 0x80000003).
    # I valori "system managed" 0x8000000x vengono letti come Int32 negativi: il vecchio test "-ge 1" li sbagliava.
    # Il campo JSON ntfsDisableLastAccess mantiene la semantica storica (true = aggiornamento last-access ATTIVO)
    # per compatibilita con i JSON/baseline gia salvati.
    $nlaUpdatesOn = -not ($null -ne $nla -and ((([int64]$nla) -band 1) -eq 1))
    $n8dot = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' 'NtfsDisable8dot3NameCreation'

    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -EA SilentlyContinue | ForEach-Object {
        $tG = Round2($_.Size / 1GB); $fG = Round2($_.FreeSpace / 1GB); $uG = Round2($tG - $fG)
        $p  = if ($tG -gt 0) { Round2(($uG / $tG) * 100) } else { 0 }
        [ordered]@{ letter = S $_.DeviceID; label = S $_.VolumeName; fsType = S $_.FileSystem; totalGB = $tG; usedGB = $uG; freeGB = $fG; usagePct = $p; health = 'Healthy' }
    })

    $physDisks = @()
    try {
        $physDisks = @(Get-PhysicalDisk -EA Stop | ForEach-Object {
            [ordered]@{ name = S $_.FriendlyName; type = S $_.MediaType; bus = S $_.BusType; sizeGB = Round2($_.Size / 1GB); health = S $_.HealthStatus }
        })
    } catch { }

    $diskReadLat  = if ($null -ne $rLat) { Round2($rLat * 1000) } else { 0.0 }
    $diskWriteLat = if ($null -ne $wLat) { Round2($wLat * 1000) } else { 0.0 }
    $diskIOPS     = if ($null -ne $iops) { Round0 $iops          } else { 0   }
    $diskQueue    = if ($null -ne $dQ)   { Round2 $dQ             } else { 0.0 }

    $diskData = [ordered]@{
        readLatencyMs         = $diskReadLat
        writeLatencyMs        = $diskWriteLat
        iops                  = $diskIOPS
        queueLength           = $diskQueue
        ntfsDisableLastAccess = [bool]$nlaUpdatesOn
        ntfsDisable8dot3      = ($n8dot -ge 1)
        volumes               = $volumes
        physicalDisks         = $physDisks
    }
    Write-AuditLog "Volumi: $($volumes.Count)  Dischi fisici: $($physDisks.Count)" 'OK'

    # --------------------------------------------------------------------------
    # 5. RETE
    # --------------------------------------------------------------------------
    Write-AuditSection 'Rete'

    $tcpAll   = @(Get-NetTCPConnection -EA SilentlyContinue)
    $tcpStates = @($tcpAll | Group-Object State | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ state = S $_.Name; count = [int]$_.Count } })
    $twCount  = ($tcpAll | Where-Object { $_.State -eq 'TimeWait'    } | Measure-Object).Count
    $cwCount  = ($tcpAll | Where-Object { $_.State -eq 'CloseWait'  } | Measure-Object).Count
    $estCount = ($tcpAll | Where-Object { $_.State -eq 'Established'} | Measure-Object).Count

    # Range porte dinamiche (Win2008+: MaxUserPort e ignorato, conta il range dinamico)
    $ephStart = 49152; $ephMax = 16384
    try {
        $tcpSet = Get-NetTCPSetting -SettingName Internet -EA Stop
        if ($tcpSet.DynamicPortRangeStartPort)  { $ephStart = [int]$tcpSet.DynamicPortRangeStartPort }
        if ($tcpSet.DynamicPortRangeNumberOfPorts) { $ephMax = [int]$tcpSet.DynamicPortRangeNumberOfPorts }
    } catch {
        try {
            # Output netsh: "Porta iniziale/Start Port : 49152" e "Numero di porte/Number of Ports : 16384"
            $dynNums = @(netsh int ipv4 show dynamicport tcp 2>$null | ForEach-Object { if ($_ -match ':\s*(\d+)\s*$') { [int]$Matches[1] } })
            if ($dynNums.Count -ge 2) { $ephStart = $dynNums[0]; $ephMax = $dynNums[1] }
        } catch { }
    }
    $ephEnd   = $ephStart + $ephMax - 1
    $ephInUse = ($tcpAll | Where-Object { $_.LocalPort -ge $ephStart -and $_.LocalPort -le $ephEnd } | Measure-Object).Count
    $doMode   = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'

    # Stato "Consenti al computer di spegnere il dispositivo" (una sola query per tutti gli adapter)
    $msPowerEnable = @()
    try { $msPowerEnable = @(Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -EA Stop) } catch { }

    $adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        $ad    = $_
        $ipCfg = Get-NetIPConfiguration -InterfaceIndex $ad.ifIndex -EA SilentlyContinue
        $bind  = Get-NetAdapterBinding   -Name $ad.Name              -EA SilentlyContinue
        $ipv6on= ($bind | Where-Object { $_.ComponentID -eq 'ms_tcpip6' }).Enabled
        $mtu   = ($ad | Get-NetIPInterface -EA SilentlyContinue | Select-Object -First 1).NlMtu
        $adMtu = if ($mtu) { [int]$mtu } else { 1500 }
        $dnsArr = @(); if ($ipCfg.DNSServer) { $dnsArr = @($ipCfg.DNSServer.ServerAddresses) }
        $driverDateStr = ''; if ($ad.DriverDate) { try { $driverDateStr = ([datetime]$ad.DriverDate).ToString('yyyy-MM-dd') } catch { $driverDateStr = "$($ad.DriverDate)" } }

        # --- Advanced Properties ---
        $advProps       = @{}
        $advPropsRaw    = @()
        $jf             = $false
        $rss            = $false
        $rssQueues      = 0
        $intrCoalescing = 'N/A'
        $intrModeration = 'N/A'
        $lsoV2IPv4      = 'N/A'
        $lsoV2IPv6      = 'N/A'
        $tcpChecksumV4  = 'N/A'
        $udpChecksumV4  = 'N/A'
        $ipChecksumV4   = 'N/A'
        $flowControl    = 'N/A'
        $speedDuplex    = 'N/A'
        $txBufSize      = 'N/A'
        $rxBufSize      = 'N/A'
        $intrRate       = 'N/A'

        try {
            $advPropList = Get-NetAdapterAdvancedProperty -Name $ad.Name -EA Stop

            # Raccogli tutte le proprieta avanzate
            $advPropsRaw = @($advPropList | ForEach-Object {
                [ordered]@{
                    keyword      = S $_.RegistryKeyword
                    displayName  = S $_.DisplayName
                    value        = S $_.RegistryValue
                    displayValue = S $_.DisplayValue
                }
            })

            # Helper: cerca per keyword strippando asterisco iniziale
            # Supporta: *FlowControl, FlowControl, *LsoV2IPv4 ecc.
            $getAdv = {
                param([string[]]$keywords)
                foreach ($kw in $keywords) {
                    $found = $advPropList | Where-Object {
                        $clean = $_.RegistryKeyword -replace '^\*', ''
                        $clean -eq $kw -or $_.RegistryKeyword -eq $kw -or $_.RegistryKeyword -eq "*$kw"
                    } | Select-Object -First 1
                    if ($found) { return $found }
                }
                return $null
            }

            # Jumbo frames
            $jfProp = & $getAdv @('JumboPacket','JumboFrame')
            $jf     = ($jfProp -and [int]($jfProp.RegistryValue) -gt 1514)

            # Interrupt Coalescing
            $icProp         = & $getAdv @('InterruptCoalescing','InterruptCoalesc','InterruptCoalescence')
            $intrCoalescing = if ($icProp) { S $icProp.DisplayValue } else { 'N/A' }

            # Interrupt Moderation
            $imProp         = & $getAdv @('InterruptModeration')
            $intrModeration = if ($imProp) { S $imProp.DisplayValue } else { 'N/A' }

            # LSO
            $lso4Prop  = & $getAdv @('LsoV2IPv4','LsoV2Ipv4','LSOv2IPv4')
            $lsoV2IPv4 = if ($lso4Prop) { S $lso4Prop.DisplayValue } else { 'N/A' }

            $lso6Prop  = & $getAdv @('LsoV2IPv6','LsoV2Ipv6','LSOv2IPv6')
            $lsoV2IPv6 = if ($lso6Prop) { S $lso6Prop.DisplayValue } else { 'N/A' }

            # Checksum Offload
            $tcp4Prop      = & $getAdv @('TCPChecksumOffloadIPv4','TCPChecksumOffloadIpv4','TCPChksumOffldIPv4')
            $tcpChecksumV4 = if ($tcp4Prop) { S $tcp4Prop.DisplayValue } else { 'N/A' }

            $udp4Prop      = & $getAdv @('UDPChecksumOffloadIPv4','UDPChecksumOffloadIpv4','UDPChksumOffldIPv4')
            $udpChecksumV4 = if ($udp4Prop) { S $udp4Prop.DisplayValue } else { 'N/A' }

            $ip4Prop       = & $getAdv @('IPChecksumOffloadIPv4','IPChecksumOffloadIpv4','IPChksumOffldIPv4')
            $ipChecksumV4  = if ($ip4Prop) { S $ip4Prop.DisplayValue } else { 'N/A' }

            # Flow Control
            $fcProp      = & $getAdv @('FlowControl')
            $flowControl = if ($fcProp) { S $fcProp.DisplayValue } else { 'N/A' }

            # Speed/Duplex
            $sdProp      = & $getAdv @('SpeedDuplex','Speed','SpeedAndDuplex')
            $speedDuplex = if ($sdProp) { S $sdProp.DisplayValue } else { 'N/A' }

            # TX/RX Buffers
            $txProp    = & $getAdv @('TransmitBuffers','NumTxBuffers','TxBuffers','TransmitDescriptors')
            $txBufSize = if ($txProp) { S $txProp.DisplayValue } else { 'N/A' }

            $rxProp    = & $getAdv @('ReceiveBuffers','NumRxBuffers','RxBuffers','ReceiveDescriptors')
            $rxBufSize = if ($rxProp) { S $rxProp.DisplayValue } else { 'N/A' }

            # Interrupt Rate
            $irProp   = & $getAdv @('InterruptRate','ITR','InterruptThrottleRate','InterruptModeration')
            $intrRate = if ($irProp) { S $irProp.DisplayValue } else { 'N/A' }

        } catch { }

        # RSS
        try {
            $rssObj    = Get-NetAdapterRss -Name $ad.Name -EA Stop
            $rss       = [bool]$rssObj.Enabled
            $rssQueues = [int]$rssObj.NumberOfReceiveQueues
        } catch { }

        # --- Power Management ---
        $pnpCaps         = $null
        $pmWakeOnMagic   = $false
        $pmWakeOnPattern = $false
        $pmWolEnabled    = $false
        try {
            $pmKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
            foreach ($sk in @(Get-ChildItem $pmKey -EA Stop)) {
                $skProps = Get-ItemProperty $sk.PSPath -EA SilentlyContinue
                if ($skProps -and $skProps.NetCfgInstanceId -eq $ad.DeviceID) {
                    if ($skProps.PSObject.Properties['PnPCapabilities']) { $pnpCaps = [int]$skProps.PnPCapabilities }
                    break
                }
            }
        } catch { }
        try {
            $powerMgmt = Get-NetAdapterPowerManagement -Name $ad.Name -EA Stop
            $pmWakeOnMagic   = ("$($powerMgmt.WakeOnMagicPacket)" -eq 'Enabled')
            $pmWakeOnPattern = ("$($powerMgmt.WakeOnPattern)"     -eq 'Enabled')
            $pmWolEnabled    = ($pmWakeOnMagic -or $pmWakeOnPattern)
        } catch { }

        # "Consenti al computer di spegnere il dispositivo": MSPower_DeviceEnable (InstanceName = PnPDeviceID_0)
        # Fallback: PnPCapabilities con bit 0x18 impostati = spegnimento NON consentito
        # (prima il fallback restituiva sempre $true perche controllava solo l'esistenza di una chiave)
        $pmCanTurnOff = $false
        $pmDevice = $null
        if ($ad.PnPDeviceID) { $pmDevice = $msPowerEnable | Where-Object { $_.InstanceName -like "$($ad.PnPDeviceID)*" } | Select-Object -First 1 }
        if ($pmDevice) {
            $pmCanTurnOff = [bool]$pmDevice.Enable
        } elseif ($null -ne $pnpCaps) {
            $pmCanTurnOff = (($pnpCaps -band 0x18) -ne 0x18)
        }

        # Rileva adapter virtuale (VMware, Hyper-V, VirtualBox)
        $isVirtualAdapter = ($ad.InterfaceDescription -match 'VMware|Hyper-V|VirtualBox|vEthernet|Microsoft.*Virtual|Loopback')
        $advPropsCount    = $advPropsRaw.Count

        [ordered]@{
            name             = S $ad.Name
            description      = S $ad.InterfaceDescription
            mac              = S $ad.MacAddress
            linkSpeed        = S $ad.LinkSpeed
            driverVersion    = S $ad.DriverVersion
            driverDate       = $driverDateStr
            mtu              = $adMtu
            ipAddress        = S ($ipCfg.IPv4Address.IPAddress -join ', ')
            gateway          = S ($ipCfg.IPv4DefaultGateway.NextHop -join ', ')
            dns              = $dnsArr
            ipv6Enabled      = [bool]$ipv6on
            jumboFrames      = [bool]$jf
            rssEnabled       = [bool]$rss
            rssQueues        = $rssQueues
            isVirtual        = [bool]$isVirtualAdapter
            advPropsCount    = [int]$advPropsCount
            # Advanced
            intrCoalescing   = $intrCoalescing
            intrModeration   = $intrModeration
            lsoV2IPv4        = $lsoV2IPv4
            lsoV2IPv6        = $lsoV2IPv6
            tcpChecksumV4    = $tcpChecksumV4
            udpChecksumV4    = $udpChecksumV4
            ipChecksumV4     = $ipChecksumV4
            flowControl      = $flowControl
            speedDuplex      = $speedDuplex
            txBuffers        = $txBufSize
            rxBuffers        = $rxBufSize
            intrRate         = $intrRate
            advPropsAll      = $advPropsRaw
            # Power Management
            pmWolEnabled     = [bool]$pmWolEnabled
            pmWakeOnMagic    = [bool]$pmWakeOnMagic
            pmWakeOnPattern  = [bool]$pmWakeOnPattern
            pmAllowTurnOff   = [bool]$pmCanTurnOff
        }
    })

    function Ping-Target { param($IP, $Count = 2)
        # PS 5.1 (Win32_PingStatus) espone ResponseTime; PS 7 espone Latency
        try {
            $r = @(Test-Connection $IP -Count $Count -EA Stop)
            $vals = @($r | ForEach-Object { if ($_.PSObject.Properties['ResponseTime']) { $_.ResponseTime } elseif ($_.PSObject.Properties['Latency']) { $_.Latency } } | Where-Object { $null -ne $_ })
            if ($vals.Count -eq 0) { return $null }
            return Round2(($vals | Measure-Object -Average).Average)
        } catch { return $null }
    }
    $gwAdapter = $adapters | Where-Object { $_.gateway } | Select-Object -First 1
    $gw        = if ($gwAdapter) { ($gwAdapter.gateway -split ',\s*')[0] } else { $null }
    $dnsAdapter= $adapters | Where-Object { $_.dns -and @($_.dns).Count -gt 0 } | Select-Object -First 1
    $dnsServer = if ($dnsAdapter) { @($dnsAdapter.dns)[0] } else { $null }
    $latGW     = if ($gw)        { Ping-Target $gw        } else { $null }
    $latDNS    = if ($dnsServer) { Ping-Target $dnsServer } else { $null }
    $netDOModeVal = if ($null -ne $doMode) { [int]$doMode } else { $null }

    $netData = [ordered]@{
        timeWaitCount          = [int]$twCount
        closeWaitCount         = [int]$cwCount
        totalTcpConnections    = [int]$tcpAll.Count
        establishedConnections = [int]$estCount
        tcpTimedWaitDelay      = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'TcpTimedWaitDelay'
        maxUserPort            = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'MaxUserPort'
        ephemeralPortsInUse    = [int]$ephInUse
        ephemeralPortsMax      = [int]$ephMax
        ephemeralPortsStart    = [int]$ephStart
        deliveryOptMode        = $netDOModeVal
        latencyGatewayMs       = $latGW
        latencyDnsMs           = $latDNS
        tcpStates              = $tcpStates
        adapters               = $adapters
    }
    Write-AuditLog "TCP: $($tcpAll.Count) conn, TW=$twCount, CW=$cwCount" 'OK'

    # --------------------------------------------------------------------------
    # 6. PROCESSI
    # --------------------------------------------------------------------------
    Write-AuditSection 'Processi'

    $allProcs = @(Get-Process -EA SilentlyContinue)
    $topByCpu = @($allProcs | Sort-Object CPU -Descending | Select-Object -First 20 | ForEach-Object {
        [ordered]@{ name = S $_.Name; pid = [int]$_.Id; cpuSec = Round2 $_.CPU; ramMB = Round2($_.WorkingSet64/1MB); threads = [int]$_.Threads.Count; handles = [int]$_.HandleCount }
    })
    $topByRam = @($allProcs | Sort-Object WorkingSet64 -Descending | Select-Object -First 15 | ForEach-Object {
        [ordered]@{ name = S $_.Name; pid = [int]$_.Id; ramMB = Round2($_.WorkingSet64/1MB); privateMemMB = Round2($_.PrivateMemorySize64/1MB) }
    })
    $topByHandles = @($allProcs | Sort-Object HandleCount -Descending | Select-Object -First 15 | ForEach-Object {
        [ordered]@{ name = S $_.Name; pid = [int]$_.Id; handles = [int]$_.HandleCount; ramMB = Round2($_.WorkingSet64/1MB) }
    })
    $procsData = [ordered]@{ topByCpu = $topByCpu; topByRam = $topByRam; topByHandles = $topByHandles; totalCount = [int]$allProcs.Count }
    Write-AuditLog "Processi: $($allProcs.Count) totali" 'OK'

    # --------------------------------------------------------------------------
    # 7. EVENT LOG
    # --------------------------------------------------------------------------
    Write-AuditSection 'Event Log'

    $since = (Get-Date).AddDays(-$DaysToScan)
    $periodHours = $DaysToScan * 24
    $excludeIds  = @(10016, 4624, 4634, 1102, 4648)
    $allEvents   = @()

    foreach ($logName in @('System', 'Application')) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = 1,2,3; StartTime = $since } -MaxEvents $MaxEvents -EA Stop |
                   Where-Object { $_.Id -notin $excludeIds }
            $allEvents += $evs
        } catch { }
    }

    $critCount = ($allEvents | Where-Object { $_.Level -eq 1 } | Measure-Object).Count
    $errCount  = ($allEvents | Where-Object { $_.Level -eq 2 } | Measure-Object).Count
    $warnCount = ($allEvents | Where-Object { $_.Level -eq 3 } | Measure-Object).Count

    $topProviders = @($allEvents | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        [ordered]@{ provider = S $_.Group[0].ProviderName; eventId = [int]$_.Group[0].Id; count = [int]$_.Count }
    })
    $recentEvents = @($allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 20 | ForEach-Object {
        $lvlName = switch ($_.Level) { 1{'Critical'} 2{'Error'} 3{'Warning'} default{'Info'} }
        $msg = try { ($_.Message -replace "`r`n|`n",' ').Substring(0,[Math]::Min(2000,$_.Message.Length)) } catch { 'N/A' }
        [ordered]@{ time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); log = S $_.LogName; level = $lvlName; provider = S $_.ProviderName; id = [int]$_.Id; message = $msg }
    })

    # Analisi aggregata per EventID
    $topEventIDs = @($allEvents | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
        $sample = $_.Group[0]
        $lvlName = switch ($sample.Level) { 1{'Critical'} 2{'Error'} 3{'Warning'} default{'Info'} }
        [ordered]@{
            eventId   = [int]$sample.Id
            provider  = S $sample.ProviderName
            level     = $lvlName
            count     = [int]$_.Count
            lastSeen  = ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            message   = try { ($sample.Message -replace "`r`n|`n",' ').Substring(0,[Math]::Min(200,$sample.Message.Length)) } catch { 'N/A' }
        }
    })

    # Timeline oraria (ultime 48 ore)
    $hourlyTimeline = @()
    $hoursBack = [math]::Min($periodHours, 48)
    for ($h = $hoursBack; $h -ge 0; $h--) {
        $hStart = (Get-Date).AddHours(-$h - 1)
        $hEnd   = (Get-Date).AddHours(-$h)
        $hEvts  = @($allEvents | Where-Object { $_.TimeCreated -ge $hStart -and $_.TimeCreated -lt $hEnd })
        $hourlyTimeline += [ordered]@{
            hour     = $hStart.ToString('yyyy-MM-dd HH:00')
            critical = [int]($hEvts | Where-Object { $_.Level -eq 1 } | Measure-Object).Count
            error    = [int]($hEvts | Where-Object { $_.Level -eq 2 } | Measure-Object).Count
            warning  = [int]($hEvts | Where-Object { $_.Level -eq 3 } | Measure-Object).Count
        }
    }

    # Pattern critici rilevati
    $criticalPatterns = @()

    # Disk errors
    $diskErrors = @($allEvents | Where-Object { $_.Id -in @(7,9,11,15,51,52,153) -and $_.ProviderName -match 'disk|storport|atapi' })
    if ($diskErrors.Count -gt 0) { $criticalPatterns += [ordered]@{ pattern='Disk Errors'; count=[int]$diskErrors.Count; severity='crit'; description="EventID: $(($diskErrors | Group-Object Id | ForEach-Object { $_.Name }) -join ', ')" } }

    # Service crashes
    $svcCrashes = @($allEvents | Where-Object { $_.Id -in @(7022,7023,7024,7031,7034) })
    if ($svcCrashes.Count -gt 0) { $criticalPatterns += [ordered]@{ pattern='Service Crashes'; count=[int]$svcCrashes.Count; severity='crit'; description="Servizi terminati inaspettatamente" } }

    # BSOD / bugcheck
    $bsod = @($allEvents | Where-Object { $_.Id -eq 41 -and $_.ProviderName -match 'Kernel-Power' })
    if ($bsod.Count -gt 0) { $criticalPatterns += [ordered]@{ pattern='Kernel Power / BSOD'; count=[int]$bsod.Count; severity='crit'; description="Riavvii inaspettati o crash kernel" } }

    # Login failures
    $loginFail = @()
    try {
        $secEvts = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$since } -MaxEvents 200 -EA Stop
        $loginFail = @($secEvts)
        $loginFailByUser = @($secEvts | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $user = try { $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text' } catch { 'N/A' }
            $ip   = try { $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress'       } | Select-Object -ExpandProperty '#text' } catch { 'N/A' }
            [ordered]@{ user=$user; ip=$ip; time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') }
        } | Select-Object -First 20)
        if ($loginFail.Count -gt 0) { $criticalPatterns += [ordered]@{ pattern='Login Failures (4625)'; count=[int]$loginFail.Count; severity='warn'; description="Accessi falliti nelle ultime ${periodHours}h" } }
    } catch { $loginFailByUser = @() }

    # Account lockout
    $lockouts = @()
    try {
        $lockouts = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4740; StartTime=$since } -MaxEvents 50 -EA Stop)
        if ($lockouts.Count -gt 0) { $criticalPatterns += [ordered]@{ pattern='Account Lockout (4740)'; count=[int]$lockouts.Count; severity='crit'; description="Account bloccati per tentativi eccessivi" } }
    } catch { }

    # RDP Brute Force (4625 da TerminalServices)
    $rdpBrute = @($loginFail | Where-Object { try { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName' -and $_.'#text' -match 'svchost' } } catch { $false } })
    if ($rdpBrute.Count -gt 10) { $criticalPatterns += [ordered]@{ pattern='RDP Brute Force (stima)'; count=[int]$rdpBrute.Count; severity='crit'; description="Elevato numero di login falliti via RDP" } }

    # Analisi per Source
    $bySource = @($allEvents | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $lvls = $_.Group | Group-Object Level
        [ordered]@{
            source   = S $_.Name
            total    = [int]$_.Count
            critical = [int](($lvls | Where-Object { $_.Name -eq '1' }).Count)
            error    = [int](($lvls | Where-Object { $_.Name -eq '2' }).Count)
            warning  = [int](($lvls | Where-Object { $_.Name -eq '3' }).Count)
        }
    })

    $evtData = [ordered]@{
        periodHours      = $periodHours
        criticalCount    = [int]$critCount
        errorCount       = [int]$errCount
        warningCount     = [int]$warnCount
        topProviders     = $topProviders
        recentEvents     = $recentEvents
        topEventIDs      = $topEventIDs
        hourlyTimeline   = $hourlyTimeline
        criticalPatterns = $criticalPatterns
        bySource         = $bySource
        loginFailures    = if ($loginFailByUser) { $loginFailByUser } else { @() }
        lockoutCount     = [int]$lockouts.Count
    }
    Write-AuditLog "Events: $critCount critici, $errCount errori, $warnCount warning - Pattern: $($criticalPatterns.Count)" 'OK'

    # --------------------------------------------------------------------------
    # 8. SERVIZI
    # --------------------------------------------------------------------------
    Write-AuditSection 'Servizi'

    $unnecessaryNames = @(
        @{N='WSearch';D='Windows Search'}, @{N='SysMain';D='Superfetch'}, @{N='Spooler';D='Print Spooler'},
        @{N='bthserv';D='Bluetooth'}, @{N='AudioSrv';D='Windows Audio'}, @{N='AudioEndpointBuilder';D='Audio Endpoint'},
        @{N='WpnService';D='Push Notifications'}, @{N='iphlpsvc';D='IP Helper (IPv6)'}, @{N='WbioSrvc';D='Biometric'},
        @{N='TabletInputService';D='Tablet Input'}, @{N='lltdsvc';D='Link-Layer Topology'}, @{N='TrkWks';D='Distributed Link Tracking'},
        @{N='CDPSvc';D='Connected Devices Platform'}, @{N='stisvc';D='Image Acquisition'},
        @{N='XblGameSave';D='Xbox Game Save'}, @{N='XboxNetApiSvc';D='Xbox Network'}, @{N='RetailDemo';D='Retail Demo'},
        @{N='WMPNetworkSvc';D='Windows Media Player Network'}, @{N='Fax';D='Fax'}
    )
    $unnecessarySvcs = @($unnecessaryNames | ForEach-Object {
        $sv = Get-Service -Name $_.N -EA SilentlyContinue
        if ($sv) { [ordered]@{ name = $_.N; display = $_.D; status = S $sv.Status; startType = S $sv.StartType; optimized = ($sv.StartType -eq 'Disabled') } }
    } | Where-Object { $_ })

    $telemetryNames = @(
        @{N='DiagTrack';D='Diagnostics Tracking'}, @{N='dmwappushservice';D='WAP Push'},
        @{N='diagnosticshub.standardcollector.service';D='Diagnostics Hub'}, @{N='WerSvc';D='Windows Error Reporting'},
        @{N='PcaSvc';D='Program Compatibility Assistant'}, @{N='wisvc';D='Windows Insider Service'},
        @{N='MapsBroker';D='Downloaded Maps Manager'}, @{N='WdiServiceHost';D='Diagnostic Service Host'},
        @{N='WdiSystemHost';D='Diagnostic System Host'}
    )
    $telemetrySvcs = @($telemetryNames | ForEach-Object {
        $sv = Get-Service -Name $_.N -EA SilentlyContinue
        if ($sv) { [ordered]@{ name = $_.N; display = $_.D; status = S $sv.Status; startType = S $sv.StartType; optimized = ($sv.StartType -eq 'Disabled') } }
    } | Where-Object { $_ })

    $telLevel  = Get-RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry'
    $ceipVal   = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' 'CEIPEnable'
    $runCount  = (Get-Service | Where-Object { $_.Status -eq 'Running' } | Measure-Object).Count

    $svcTelLevelStr = if ($null -ne $telLevel) { "Level $telLevel" } else { 'Non configurato' }

    $svcData = [ordered]@{
        unnecessary    = $unnecessarySvcs
        telemetry      = $telemetrySvcs
        telemetryLevel = $svcTelLevelStr
        ceipEnabled    = -not ($ceipVal -eq 0)
        runningCount   = [int]$runCount
    }
    Write-AuditLog "Servizi in esecuzione: $runCount" 'OK'

    # --------------------------------------------------------------------------
    # 9. RDP / RDS
    # --------------------------------------------------------------------------
    Write-AuditSection 'RDP/RDS'

    $tsPolPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $tsWsPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $tsSrvPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'

    # Valore effettivo: la policy (GPO) prevale sulla configurazione WinStation
    function Get-TsEffective { param([string]$Name)
        $v = Get-RegVal $tsPolPath $Name
        if ($null -ne $v) { return $v }
        return (Get-RegVal $tsWsPath $Name)
    }

    # Pre-calcola tutti i valori condizionali per rdpData
    # NB: "[int](if ...)" non e valido in PowerShell (l'if non e un'espressione): serve $( ).
    #     Prima questi valori restavano sempre vuoti e i controlli RDP lavoravano su dati nulli.
    $rdpSecLayer     = Get-TsEffective 'SecurityLayer'
    $rdpSecLayerInt  = [int]$(if ($null -ne $rdpSecLayer) { $rdpSecLayer } else { 1 })
    $rdpSecLayerName = switch ($rdpSecLayerInt) { 0{'RDP Security'} 2{'SSL/TLS'} default{'Negotiate'} }
    $rdpEncLevel     = Get-TsEffective 'MinEncryptionLevel'
    $rdpEncLevelInt  = [int]$(if ($null -ne $rdpEncLevel) { $rdpEncLevel } else { 2 })
    $rdpEncLevelName = switch ($rdpEncLevel) { 1{'Low'} 2{'Client Compatible'} 3{'High'} 4{'FIPS'} default{'Non configurato'} }
    $rdpSslCert      = if (Get-RegVal $tsWsPath 'SSLCertificateSHA1Hash') { 'Certificato personalizzato' } else { 'self-signed' }
    $rdpLicModeRaw   = Get-RegVal $tsPolPath 'LicensingMode'
    if ($null -eq $rdpLicModeRaw) { $rdpLicModeRaw = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core' 'LicensingMode' }
    $rdpLicMode      = switch ($rdpLicModeRaw) { 2{'Per Device'} 4{'Per User'} default{'Non configurato'} }
    $rdpLicSrvRaw    = Get-RegVal $tsPolPath 'LicenseServers'
    $rdpLicSrv       = if ($rdpLicSrvRaw) { S $rdpLicSrvRaw } else { 'Non configurato' }
    $rdpTransport    = switch (Get-RegVal $tsPolPath 'SelectTransport') { 1{'UDP+TCP'} 2{'Solo TCP'} default{'UDP+TCP (default)'} }
    # ColorDepth (policy "Limita profondita colore massima") e un codice, non il numero di bit:
    # 2=15 bit, 3=16 bit, 4=24 bit, 5=32 bit, 999=compatibile client (32)
    $rdpColorDepthRaw= Get-RegVal $tsPolPath 'ColorDepth'
    $rdpColorDepth   = switch ($rdpColorDepthRaw) { 2{15} 3{16} 4{24} 5{32} default{32} }
    $rdpMaxIdleRaw   = Get-TsEffective 'MaxIdleTime'
    $rdpMaxIdle      = if ($rdpMaxIdleRaw -gt 0) { [int]($rdpMaxIdleRaw / 60000) } else { $null }
    $rdpMaxDiscRaw   = Get-TsEffective 'MaxDisconnectionTime'
    $rdpMaxDisc      = if ($rdpMaxDiscRaw -gt 0) { [int]($rdpMaxDiscRaw / 60000) } else { $null }
    $rdpShadowRaw    = Get-RegVal $tsPolPath 'Shadow'
    $rdpShadow       = [int]$(if ($null -ne $rdpShadowRaw) { $rdpShadowRaw } else { 0 })

    $rdpData = [ordered]@{
        nlaEnabled              = ((Get-TsEffective 'UserAuthentication') -eq 1)
        securityLayer           = $rdpSecLayerInt
        securityLayerName       = $rdpSecLayerName
        encryptionLevel         = $rdpEncLevelInt
        encryptionLevelName     = $rdpEncLevelName
        sslCertificate          = $rdpSslCert
        licenseMode             = $rdpLicMode
        licenseServer           = $rdpLicSrv
        wallpaperEnabled        = -not ((Get-RegVal $tsPolPath 'fNoRemoteDesktopWallpaper') -eq 1)
        menuAnimations          = -not ((Get-RegVal $tsPolPath 'fDisableMenuAnims')          -eq 1)
        fullWindowDrag          = -not ((Get-RegVal $tsPolPath 'fDisableFullWindowDrag')     -eq 1)
        fontSmoothing           = ((Get-RegVal $tsPolPath 'bEnableFontSmoothing')  -eq 1)
        cursorShadow            = -not ((Get-RegVal $tsPolPath 'fDisableCursorShadow')       -eq 1)
        avc444Enabled           = ((Get-RegVal $tsPolPath 'AVC444ModePreferred')   -eq 1)
        h264HWEnabled           = ((Get-RegVal $tsPolPath 'HardwareGraphicsAdapter') -eq 1)
        transportMode           = $rdpTransport
        colorDepthBit           = $rdpColorDepth
        maxIdleMinutes          = $rdpMaxIdle
        maxDisconnectionMinutes = $rdpMaxDisc
        singleSessionPerUser    = ($(if ($null -ne (Get-RegVal $tsPolPath 'fSingleSessionPerUser')) { Get-RegVal $tsPolPath 'fSingleSessionPerUser' } else { Get-RegVal $tsSrvPath 'fSingleSessionPerUser' }) -eq 1)
        deleteTempOnExit        = ((Get-RegVal $tsPolPath 'DeleteTempDirsOnExit')  -eq 1)
        perSessionTempDir       = ((Get-RegVal $tsPolPath 'PerSessionTempDir')     -eq 1)
        shadowMode              = $rdpShadow
        clipboardRedirect       = -not ((Get-TsEffective 'fDisableClip') -eq 1)
        printerRedirect         = -not ((Get-TsEffective 'fDisableCpm')  -eq 1)
        driveRedirect           = -not ((Get-TsEffective 'fDisableCdm')  -eq 1)
        lptRedirect             = -not ((Get-TsEffective 'fDisableLPT')  -eq 1)
        comRedirect             = -not ((Get-TsEffective 'fDisableCcm')  -eq 1)
        activeSessions          = [int]$activeUsers
        disconnectedSessions    = [int]$disconnectedCount
        loadBalancing           = ((Get-RegVal $tsSrvPath 'fIsSessionManagerMode') -eq 1)
        drainMode               = ((Get-RegVal $tsSrvPath 'fDrainMode') -eq 1)
    }
    Write-AuditLog "RDP: NLA=$($rdpData.nlaEnabled), Sessioni=$activeUsers" 'OK'

    # --------------------------------------------------------------------------
    # 10. ANTIVIRUS
    # --------------------------------------------------------------------------
    Write-AuditSection 'Antivirus'

    $kaspSvcs     = @(Get-Service | Where-Object { $_.Name -match '^AVP\.|^avpsus\.' })
    $kaspDetected = ($kaspSvcs.Count -gt 0)

    $avData = [ordered]@{
        product='Windows Defender'; realtimeEnabled=$false; definitionVersion=''; definitionAgeDays=0
        cpuLoadFactor=50; scanOnlyIfIdle=$false; asrRulesCount=0
        exclusionPaths=@(); exclusionProcesses=@(); exclusionExtensions=@()
        requiredExclusionsOk=$false; kasperskyDetected=[bool]$kaspDetected
    }

    if ($kaspDetected) {
        $avData.product = "Kaspersky ($($kaspSvcs[0].Name))"
        Write-AuditLog "Antivirus: Kaspersky rilevato" 'OK'
    } else {
        try {
            $def  = Get-MpComputerStatus -EA Stop
            $defP = Get-MpPreference     -EA Stop
            $reqProc = @('infinity.exe')
            if ($isTS) { $reqProc += @('frxsvc.exe','frxccds.exe','frxccd.exe') }
            if ($isDB) { $reqProc += @('dbsrv17.exe','dbeng17.exe','dbsrv12.exe') }
            $excPaths = @($defP.ExclusionPath      | Where-Object { $_ })
            $excProcs = @($defP.ExclusionProcess   | Where-Object { $_ })
            $excExts  = @($defP.ExclusionExtension | Where-Object { $_ })
            $reqOk    = ($reqProc | Where-Object { $_ -notin $excProcs }).Count -eq 0
            $asrCount = if ($defP.AttackSurfaceReductionRules_Ids) { $defP.AttackSurfaceReductionRules_Ids.Count } else { 0 }
            $avData.realtimeEnabled     = [bool]$def.RealTimeProtectionEnabled
            $avData.definitionVersion   = S $def.AntivirusSignatureVersion
            $avData.definitionAgeDays   = [int]$def.AntivirusSignatureAge
            $avData.cpuLoadFactor       = [int]$defP.ScanAvgCPULoadFactor
            $avData.scanOnlyIfIdle      = [bool]$defP.ScanOnlyIfIdleEnabled
            $avData.asrRulesCount       = $asrCount
            $avData.exclusionPaths      = $excPaths
            $avData.exclusionProcesses  = $excProcs
            $avData.exclusionExtensions = $excExts
            $avData.requiredExclusionsOk= [bool]$reqOk
            Write-AuditLog "Defender: RT=$($def.RealTimeProtectionEnabled), Defs=$($def.AntivirusSignatureAge)gg" 'OK'
        } catch { Write-AuditLog 'Defender non disponibile' 'WARN' }
    }

    # --------------------------------------------------------------------------
    # 11. FIREWALL + SMB
    # --------------------------------------------------------------------------
    Write-AuditSection 'Firewall/SMB'

    $fwProfiles  = Get-NetFirewallProfile -EA SilentlyContinue
    $fwRulesCount= (Get-NetFirewallRule -Enabled True -EA SilentlyContinue | Measure-Object).Count
    $fwData = [ordered]@{
        domainEnabled  = [bool]($fwProfiles | Where-Object { $_.Name -eq 'Domain'  }).Enabled
        privateEnabled = [bool]($fwProfiles | Where-Object { $_.Name -eq 'Private' }).Enabled
        publicEnabled  = [bool]($fwProfiles | Where-Object { $_.Name -eq 'Public'  }).Enabled
        enabledRulesCount = [int]$fwRulesCount
    }
    $smbCfg = Get-SmbServerConfiguration -EA SilentlyContinue
    $smbSMB1 = if ($smbCfg) { [bool]$smbCfg.EnableSMB1Protocol      } else { $true  }
    $smbSMB2 = if ($smbCfg) { [bool]$smbCfg.EnableSMB2Protocol      } else { $true  }
    $smbEnc  = if ($smbCfg) { [bool]$smbCfg.EncryptData             } else { $false }
    $smbSign = if ($smbCfg) { [bool]$smbCfg.RequireSecuritySignature } else { $false }
    $smbData = [ordered]@{
        smb1Enabled      = $smbSMB1
        smb2Enabled      = $smbSMB2
        encryptData      = $smbEnc
        requireSignature = $smbSign
    }
    Write-AuditLog "SMB1=$($smbData.smb1Enabled), FW-Domain=$($fwData.domainEnabled)" 'OK'

    # --------------------------------------------------------------------------
    # 12. REGISTRY
    # --------------------------------------------------------------------------
    Write-AuditSection 'Registry'

    $tcpBase   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    $mmBase    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $mmProfile = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    $mmGames   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
    $fsBase    = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'

    # TcpAckFrequency per ogni interfaccia attiva
    $tcpAckFreqPerIface = @()
    try {
        $ifaceKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -EA Stop
        foreach ($ik in $ifaceKeys) {
            $ackVal = Get-RegVal $ik.PSPath 'TcpAckFrequency'
            $tcpAckFreqPerIface += [ordered]@{
                iface = S $ik.PSChildName
                value = if ($null -ne $ackVal) { [int]$ackVal } else { $null }
            }
        }
    } catch { }
    $tcpAckFreqGlobal = Get-RegVal $tcpBase 'TcpAckFrequency'

    # Disk temp folders size
    $tempFolders = @()
    foreach ($tmpPath in @("$env:SystemRoot\Temp", "$env:TEMP", "$env:SystemRoot\SoftwareDistribution\Download")) {
        try {
            if (Test-Path $tmpPath) {
                $sz = Get-FolderSizeBytes $tmpPath
                $tempFolders += [ordered]@{ path = $tmpPath; sizeGB = [math]::Round($sz / 1GB, 2) }
            }
        } catch { }
    }
    # Measure-Object -Property non legge le chiavi dei dizionari [ordered]: si estrae il valore esplicitamente
    $totalTempGB = [math]::Round([double](($tempFolders | ForEach-Object { $_.sizeGB } | Measure-Object -Sum).Sum), 2)

    $regData = [ordered]@{
        tcpTimedWaitDelay       = Get-RegVal $tcpBase  'TcpTimedWaitDelay'
        maxUserPort             = Get-RegVal $tcpBase  'MaxUserPort'
        keepAliveTime           = Get-RegVal $tcpBase  'KeepAliveTime'
        tcpAckFrequency         = $tcpAckFreqGlobal
        tcpAckFreqPerIface      = $tcpAckFreqPerIface
        systemResponsiveness    = Get-RegVal $mmProfile 'SystemResponsiveness'
        largeSystemCache        = Get-RegVal $mmBase   'LargeSystemCache'
        disablePagingExecutive  = ((Get-RegVal $mmBase 'DisablePagingExecutive') -eq 1)
        ntfsDisableLastAccess   = [bool]$nlaUpdatesOn   # true = last-access ATTIVO (vedi sezione Disco)
        ntfsDisable8dot3        = ((Get-RegVal $fsBase 'NtfsDisable8dot3NameCreation') -ge 1)
        mmcssGpuPriority        = Get-RegVal $mmGames 'GPU Priority'
        mmcssPriority           = Get-RegVal $mmGames 'Priority'
        mmcssSchedulingCategory = Get-RegVal $mmGames 'Scheduling Category'
        win32PrioritySeparation = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation'
        # Auto-login / cached credentials
        cachedLogonsCount       = Get-RegVal 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount'
        # Spectre/Meltdown mitigations
        specreMitigations       = Get-RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride'
        # Temp folders
        tempFolders             = $tempFolders
        totalTempGB             = $totalTempGB
    }
    Write-AuditLog 'Registry raccolto' 'OK'

    # --------------------------------------------------------------------------
    # 13. POWER PLAN
    # --------------------------------------------------------------------------
    Write-AuditSection 'Power Plan'

    $activePlan = $null
    try { $activePlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan | Where-Object { $_.IsActive } | Select-Object -First 1 } catch { }
    $ppName   = if ($activePlan) { S $activePlan.ElementName } else { 'Non rilevato' }
    # Riconosce High/Ultimate Performance per GUID (indipendente dalla lingua) oltre che per nome
    $ppIsHP   = if ($activePlan) {
        [bool]("$($activePlan.InstanceID)" -match '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c|e9a42b02-d5df-448d-aa00-03f14749eb61' -or
               $activePlan.ElementName -match 'High Performance|Ultimate Performance|Prestazioni elevate|Prestazioni ottimali')
    } else { $false }
    $ppData = [ordered]@{
        activePlan        = $ppName
        isHighPerformance = $ppIsHP
    }
    Write-AuditLog "Power Plan: $($ppData.activePlan)" 'OK'

    # --------------------------------------------------------------------------
    # 14. CERTIFICATI (NUOVO)
    # --------------------------------------------------------------------------
    Write-AuditSection 'Certificati'

    $certData = @()
    try {
        $stores = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting')
        foreach ($store in $stores) {
            $certs = Get-ChildItem -Path $store -EA SilentlyContinue
            foreach ($cert in $certs) {
                $daysLeft = [int]($cert.NotAfter - (Get-Date)).TotalDays
                $status   = if ($daysLeft -lt 0) { 'expired' } elseif ($daysLeft -lt 30) { 'expiring' } else { 'ok' }
                $certData += [ordered]@{
                    subject   = S $cert.Subject
                    issuer    = S $cert.Issuer
                    thumbprint= S $cert.Thumbprint
                    notBefore = $cert.NotBefore.ToString('yyyy-MM-dd')
                    notAfter  = $cert.NotAfter.ToString('yyyy-MM-dd')
                    daysLeft  = $daysLeft
                    selfSigned= ($cert.Subject -eq $cert.Issuer)
                    store     = ($store -replace 'Cert:\\LocalMachine\\','')
                    status    = $status
                }
            }
        }
    } catch { Write-AuditLog 'Errore lettura certificati' 'WARN' }

    $certsExpired  = ($certData | Where-Object { $_.status -eq 'expired'  } | Measure-Object).Count
    $certsExpiring = ($certData | Where-Object { $_.status -eq 'expiring' } | Measure-Object).Count
    Write-AuditLog "Certificati: $($certData.Count) totali, $certsExpired scaduti, $certsExpiring in scadenza" 'OK'

    # --------------------------------------------------------------------------
    # 15. WINDOWS UPDATE (NUOVO)
    # --------------------------------------------------------------------------
    Write-AuditSection 'Windows Update'

    $wuData = [ordered]@{
        lastInstallDate     = ''
        lastSearchDate      = ''
        pendingUpdates      = 0
        pendingList         = @()
        wsusServer          = ''
        wsusEnabled         = $false
        autoUpdateEnabled   = $false
        deferralFeatureDays = 0
        deferralQualityDays = 0
        searchCompleted     = $false    # false = ricerca non riuscita: "0 pending" NON significa aggiornato
        searchMode          = 'none'    # online | cache | none
    }

    try {
        $wu = New-Object -ComObject Microsoft.Update.Session -EA Stop
        $searcher = $wu.CreateUpdateSearcher()
        $histCount= $searcher.GetTotalHistoryCount()
        if ($histCount -gt 0) {
            # Ultimo aggiornamento installato con successo (esclude definizioni Defender, che cambiano ogni giorno)
            $hist = @($searcher.QueryHistory(0, [math]::Min($histCount, 100)))
            $lastInst = $hist | Where-Object {
                $_.Operation -eq 1 -and $_.ResultCode -eq 2 -and
                $_.Title -notmatch 'Defender|Security Intelligence|Antimalware|intelligence di sicurezza|definizion'
            } | Sort-Object Date -Descending | Select-Object -First 1
            if (-not $lastInst) { $lastInst = $hist | Sort-Object Date -Descending | Select-Object -First 1 }
            if ($lastInst) { $wuData.lastInstallDate = $lastInst.Date.ToString('yyyy-MM-dd HH:mm:ss') }
        }
        # Cerca aggiornamenti pending (non installati, non nascosti): online con timeout, poi fallback su cache locale
        $searchResult = $null
        try {
            $job2 = $searcher.BeginSearch("IsInstalled=0 and IsHidden=0", $null, $null)
            $waited = 0
            while (-not $job2.IsCompleted -and $waited -lt 60) { Start-Sleep -Seconds 1; $waited++ }
            if ($job2.IsCompleted) { $searchResult = $searcher.EndSearch($job2); $wuData.searchMode = 'online' }
            else { try { $job2.RequestAbort() } catch { } }
        } catch { }
        if (-not $searchResult) {
            try {
                $searcher.Online = $false   # usa i dati dell'ultima scansione, risposta immediata
                $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")
                $wuData.searchMode = 'cache'
            } catch { $searchResult = $null }
        }

        if ($searchResult) {
            $wuData.searchCompleted = $true
            $wuData.pendingUpdates = $searchResult.Updates.Count
            $wuData.pendingList = @($searchResult.Updates | Select-Object -First 10 | ForEach-Object {
                [ordered]@{ title = S $_.Title; severity = S $_.MsrcSeverity; kbIds = @($_.KBArticleIDs) }
            })
        }
    } catch { Write-AuditLog 'Windows Update COM non disponibile' 'WARN' }

    # WSUS via registry
    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wuAU  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $wsusUrl = Get-RegVal $wuPol 'WUServer'
    $wuData.wsusServer          = if ($wsusUrl) { S $wsusUrl } else { '' }
    $wuData.wsusEnabled         = [bool]((Get-RegVal $wuAU 'UseWUServer') -eq 1)
    $wuData.autoUpdateEnabled   = [bool]((Get-RegVal $wuAU 'NoAutoUpdate') -ne 1)
    $wuData.deferralFeatureDays = [int]($(if ($null -ne (Get-RegVal $wuPol 'DeferFeatureUpdatesPeriodInDays')) { Get-RegVal $wuPol 'DeferFeatureUpdatesPeriodInDays' } else { 0 }))
    $wuData.deferralQualityDays = [int]($(if ($null -ne (Get-RegVal $wuPol 'DeferQualityUpdatesPeriodInDays')) { Get-RegVal $wuPol 'DeferQualityUpdatesPeriodInDays' } else { 0 }))
    if ($wuData.searchCompleted) { Write-AuditLog "WU: $($wuData.pendingUpdates) pending ($($wuData.searchMode)), WSUS=$($wuData.wsusEnabled)" 'OK' }
    else { Write-AuditLog "WU: ricerca aggiornamenti NON riuscita - stato pending sconosciuto, WSUS=$($wuData.wsusEnabled)" 'WARN' }

    # --------------------------------------------------------------------------
    # 16. SCHEDULED TASKS (NUOVO)
    # --------------------------------------------------------------------------
    Write-AuditSection 'Scheduled Tasks'

    $taskData = [ordered]@{ failed = @(); suspicious = @(); totalCount = 0 }
    try {
        $tasks = Get-ScheduledTask -EA Stop
        $taskData.totalCount = $tasks.Count
        $since30 = (Get-Date).AddDays(-30)

        # Task falliti recentemente
        $failedTasks = @()
        foreach ($t in ($tasks | Where-Object { $_.State -ne 'Disabled' } | Select-Object -First 200)) {
            try {
                $info = $t | Get-ScheduledTaskInfo -EA Stop
                if ($info.LastTaskResult -notin @(0, 267009, 267011) -and $null -ne $info.LastRunTime -and $info.LastRunTime -gt $since30) {
                    $failedTasks += [ordered]@{
                        name       = S $t.TaskName
                        path       = S $t.TaskPath
                        lastRun    = $info.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss')
                        lastResult = '0x{0:X8}' -f $info.LastTaskResult
                        state      = S $t.State
                    }
                }
            } catch { }
        }
        $taskData.failed = @($failedTasks | Select-Object -First 20)

        # Task sospetti (path non-Microsoft, azioni esterne)
        $suspiciousTasks = @($tasks | Where-Object {
            $_.TaskPath -notmatch '^\\Microsoft\\' -and
            $_.State    -ne 'Disabled' -and
            ($_.Actions | Where-Object { $_.Execute -match '\.(exe|bat|ps1|vbs|cmd)' -and $_.Execute -notmatch 'system32|syswow64' })
        } | Select-Object -First 20 | ForEach-Object {
            $act = ($_.Actions | Select-Object -First 1)
            [ordered]@{ name = S $_.TaskName; path = S $_.TaskPath; execute = S $act.Execute; arguments = S $act.Arguments; state = S $_.State }
        })
        $taskData.suspicious = $suspiciousTasks
    } catch { Write-AuditLog 'Scheduled Tasks non disponibili' 'WARN' }
    Write-AuditLog "Tasks: $($taskData.totalCount) totali, $($taskData.failed.Count) falliti, $($taskData.suspicious.Count) sospetti" 'OK'

    # --------------------------------------------------------------------------
    # 17. PROFILI UTENTE RDS (NUOVO)
    # --------------------------------------------------------------------------
    Write-AuditSection 'Profili Utente RDS'

    $profileData = [ordered]@{ profiles = @(); orphaned = @(); totalSizeGB = 0 }
    try {
        $profPath = "$env:SystemDrive\Users"
        $profDirs = @(Get-ChildItem -Path $profPath -Directory -EA SilentlyContinue |
                      Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' })

        $wmiProfiles = @(Get-CimInstance Win32_UserProfile -EA SilentlyContinue)

        $profs = @()
        foreach ($dir in $profDirs) {
            $sizeBytes = 0
            # Get-FolderSizeBytes include i file nascosti (AppData): prima Get-ChildItem senza -Force li escludeva
            try { $sizeBytes = Get-FolderSizeBytes $dir.FullName } catch { }
            $sizeGB = Round2($sizeBytes / 1GB)
            $wmiProf= $wmiProfiles | Where-Object { $_.LocalPath -eq $dir.FullName } | Select-Object -First 1
            $sid    = if ($wmiProf) { S $wmiProf.SID } else { 'N/A' }
            $loaded = if ($wmiProf) { [bool]$wmiProf.Loaded } else { $false }
            $profs += [ordered]@{ name = S $dir.Name; path = S $dir.FullName; sizeGB = $sizeGB; sid = $sid; loaded = $loaded; lastWrite = $dir.LastWriteTime.ToString('yyyy-MM-dd') }
        }
        $profileData.profiles    = @($profs | Sort-Object { $_.sizeGB } -Descending)
        $rawSum = ($profs | ForEach-Object { $_.sizeGB } | Measure-Object -Sum).Sum
        $profileData.totalSizeGB = if ($null -ne $rawSum) { Round2 $rawSum } else { 0.0 }

        # Profili orfani (SID registrato in registry ma cartella mancante o WMI non trovato)
        $regProfPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $regProfs    = @(Get-ChildItem $regProfPath -EA SilentlyContinue)
        $orphaned    = @()
        foreach ($rp in $regProfs) {
            $localPath = (Get-ItemProperty $rp.PSPath -EA SilentlyContinue).ProfileImagePath
            if ($localPath -and -not (Test-Path $localPath)) {
                $orphaned += [ordered]@{ sid = S ($rp.PSChildName); path = S $localPath }
            }
        }
        $profileData.orphaned = $orphaned
    } catch { Write-AuditLog 'Errore lettura profili' 'WARN' }
    Write-AuditLog "Profili: $($profileData.profiles.Count), orfani: $($profileData.orphaned.Count), totale: $($profileData.totalSizeGB) GB" 'OK'

    # --------------------------------------------------------------------------
    # 17b. LOGIN / ACCESSI UTENTE RDS
    # --------------------------------------------------------------------------
    Write-AuditSection 'Login Utente RDS'

    $loginEvents = [ordered]@{ sessions = @(); summary = @(); totalCount = 0 }
    try {
        # Solo accessi "umani": 4624/4634 con LogonType 2/7/10/11 (i logon di rete tipo 3 riempivano
        # il limite di eventi e nascondevano gli accessi RDS), piu 4647/4778/4779/4800/4801.
        $loginMs  = [int64]$DaysToScan * 86400000
        $tcFilter = "TimeCreated[timediff(@SystemTime) &lt;= $loginMs]"
        $loginQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4634) and $tcFilter]] and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='7' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']]</Select>
    <Select Path="Security">*[System[(EventID=4647 or EventID=4778 or EventID=4779 or EventID=4800 or EventID=4801) and $tcFilter]]</Select>
  </Query>
</QueryList>
"@
        $rawLoginEvts = @()
        try { $rawLoginEvts = @(Get-WinEvent -FilterXml ([xml]$loginQuery) -MaxEvents 1000 -EA Stop) } catch { }

        $sessions = [System.Collections.Generic.List[object]]::new()
        foreach ($ev in $rawLoginEvts) {
            try {
                $xml     = [xml]$ev.ToXml()
                $data    = $xml.Event.EventData.Data
                # Restituisce il primo campo valorizzato tra quelli indicati
                # (4778/4779 usano AccountName/ClientAddress/ClientName invece di TargetUserName/IpAddress/WorkstationName)
                $getD    = { param([string[]]$names)
                    foreach ($n in $names) {
                        $v = ($data | Where-Object { $_.Name -eq $n } | Select-Object -First 1).'#text'
                        if ($v -and $v -ne '-') { return $v }
                    }
                    return $null
                }
                $evtType = switch ($ev.Id) {
                    4624 { 'Login' }
                    4634 { 'Logoff' }
                    4647 { 'Logoff (utente)' }
                    4778 { 'Riconnessione' }
                    4779 { 'Disconnessione' }
                    4800 { 'Blocco workstation' }
                    4801 { 'Sblocco workstation' }
                    default { 'Altro' }
                }
                $user     = & $getD @('TargetUserName','AccountName')
                $domain   = & $getD @('TargetDomainName','AccountDomain')
                $logonType= & $getD @('LogonType')
                $srcIp    = & $getD @('IpAddress','ClientAddress')
                $srcHost  = & $getD @('WorkstationName','ClientName')
                $logonTypeName = switch ($logonType) {
                    '2'  { 'Interattivo' }
                    '3'  { 'Rete' }
                    '7'  { 'Sblocco' }
                    '10' { 'RemoteInterattivo (RDP)' }
                    '11' { 'CachedInterattivo' }
                    default { if ($logonType) { "Tipo $logonType" } elseif ($ev.Id -in 4778,4779) { 'RDP' } else { 'N/A' } }
                }
                # Filtra account di sistema e account computer (terminano con $)
                if ([string]::IsNullOrWhiteSpace($user)) { continue }
                if ($user -match '\$$|^SYSTEM$|^DWM-|^UMFD-|^LOCAL SERVICE$|^NETWORK SERVICE$|^ANONYMOUS') { continue }

                $sessions.Add([ordered]@{
                    time        = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    eventId     = [int]$ev.Id
                    eventType   = $evtType
                    user        = S $user
                    domain      = S $domain
                    logonType   = S $logonTypeName
                    sourceIp    = if ($srcIp)   { S $srcIp   } else { 'N/A' }
                    sourceHost  = if ($srcHost) { S $srcHost } else { 'N/A' }
                    log         = 'Security'
                })
            } catch { }
        }

        # Sommario per utente (@() obbligatorio: con un solo elemento .Count restituirebbe il numero di chiavi del dizionario)
        $summaryByUser = @($sessions | Group-Object { $_.user } | Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
            $logins  = @($_.Group | Where-Object { $_.eventType -eq 'Login' }).Count
            $logoffs = @($_.Group | Where-Object { $_.eventType -match 'Logoff' }).Count
            $discos  = @($_.Group | Where-Object { $_.eventType -match 'Disconnessione' }).Count
            $recons  = @($_.Group | Where-Object { $_.eventType -match 'Riconnessione' }).Count
            $ips     = @($_.Group | Where-Object { $_.sourceIp -ne 'N/A' } | ForEach-Object { $_.sourceIp } | Select-Object -Unique)
            $hosts   = @($_.Group | Where-Object { $_.sourceHost -ne 'N/A' } | ForEach-Object { $_.sourceHost } | Select-Object -Unique)
            $lastSeen= ($_.Group | Sort-Object { $_.time } -Descending | Select-Object -First 1).time
            [ordered]@{
                user         = S $_.Name
                total        = [int]$_.Count
                logins       = [int]$logins
                logoffs      = [int]$logoffs
                disconnections = [int]$discos
                reconnections  = [int]$recons
                sourceIps    = $ips -join ', '
                sourceHosts  = $hosts -join ', '
                lastSeen     = $lastSeen
            }
        })

        $loginEvents.sessions   = @($sessions | Sort-Object { $_.time } -Descending | Select-Object -First 200)
        $loginEvents.summary    = $summaryByUser
        $loginEvents.totalCount = [int]$sessions.Count
        Write-AuditLog "Login events: $($loginEvents.totalCount) eventi, $($summaryByUser.Count) utenti distinti" 'OK'
    } catch { Write-AuditLog 'Errore raccolta login events' 'WARN' }

    # --------------------------------------------------------------------------
    # 18. SOFTWARE
    # --------------------------------------------------------------------------
    Write-AuditSection 'Software'

    $swItems = [System.Collections.Generic.List[object]]::new()
    $swRegPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($rp in $swRegPaths) {
        try {
            if (-not (Test-Path $rp -EA SilentlyContinue)) { continue }
            $keys = Get-ChildItem -Path $rp -EA SilentlyContinue
            foreach ($key in $keys) {
                try {
                    $it = Get-ItemProperty -Path $key.PSPath -EA SilentlyContinue
                    if (-not $it) { continue }
                    $dn = $null
                    try { $dn = $it.DisplayName } catch { }
                    if ([string]::IsNullOrWhiteSpace($dn)) { continue }
                    $ver = ''; try { $ver = "$($it.DisplayVersion)" } catch { }
                    $pub = ''; try { $pub = "$($it.Publisher)"      } catch { }
                    $swItems.Add([ordered]@{
                        name      = $dn.Trim()
                        version   = $ver
                        publisher = $pub
                    })
                } catch { }
            }
        } catch { }
    }
    # Deduplicazione per nome
    $swDedup = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($it2 in $swItems) { if (-not $swDedup.ContainsKey($it2.name)) { $swDedup[$it2.name] = $it2 } }
    $swFinal = @($swDedup.Values | Sort-Object { $_.name })
    $swData  = [ordered]@{ totalCount = [int]$swFinal.Count; items = $swFinal }
    Write-AuditLog "Software: $($swData.totalCount) programmi trovati" 'OK'

    # --------------------------------------------------------------------------
    # 19. SCORING & RACCOMANDAZIONI
    # --------------------------------------------------------------------------
    Write-AuditSection 'Scoring & Raccomandazioni'

    $recs = [System.Collections.Generic.List[hashtable]]::new()
    function Add-Rec { param([string]$p,[string]$cat,[string]$txt,[string]$det)
        $recs.Add([ordered]@{ priority=$p; category=$cat; text=$txt; detail=$det }) }

    # RAM
    if     ($ramPct -ge 85) { Add-Rec 'crit' 'MEMORIA' "RAM al $ramPct% - aggiungere RAM o ridurre sessioni" "Soglia critica >85%" }
    elseif ($ramPct -ge 75) { Add-Rec 'warn' 'MEMORIA' "RAM al $ramPct% - monitorare trend" "Soglia warning >75%" }
    # CPU
    if     ($cpuData.avgUsagePct -ge 85) { Add-Rec 'crit' 'CPU' "CPU al $($cpuData.avgUsagePct)% - carico critico" "Verificare processi" }
    elseif ($cpuData.avgUsagePct -ge 70) { Add-Rec 'warn' 'CPU' "CPU al $($cpuData.avgUsagePct)% - carico elevato" "Monitorare" }
    if ($cpuData.processorQueue -gt 4)   { Add-Rec 'crit' 'CPU' "Processor Queue $($cpuData.processorQueue) - CPU satura" "Ottimizzare carico" }
    elseif ($cpuData.processorQueue -gt 2) { Add-Rec 'warn' 'CPU' "Processor Queue $($cpuData.processorQueue) - attenzione" "Monitorare trend" }
    # DISCO
    foreach ($vol in $diskData.volumes) {
        if     ($vol.usagePct -ge 90) { Add-Rec 'crit' 'DISCO' "Volume $($vol.letter) al $($vol.usagePct)% - critico" "Liberare spazio" }
        elseif ($vol.usagePct -ge 75) { Add-Rec 'warn' 'DISCO' "Volume $($vol.letter) al $($vol.usagePct)% - ridotto" "Pianificare pulizia" }
    }
    if     ($diskData.writeLatencyMs -gt 20) { Add-Rec 'crit' 'DISCO' "Write latency $($diskData.writeLatencyMs)ms - critica" "I/O saturo" }
    elseif ($diskData.writeLatencyMs -gt 10) { Add-Rec 'warn' 'DISCO' "Write latency $($diskData.writeLatencyMs)ms - elevata" "Warning >10ms" }
    # EVENTI
    if ($evtData.criticalCount -gt 0) {
        $topEvt = $evtData.topProviders | Select-Object -First 1
        Add-Rec 'crit' 'STABILITA' "$($evtData.criticalCount) eventi critici - $($topEvt.provider)" "Verificare root cause"
    } elseif ($evtData.errorCount -gt 20) { Add-Rec 'warn' 'STABILITA' "$($evtData.errorCount) errori in $($evtData.periodHours)h" "Numero elevato" }
    # SICUREZZA RDP
    if (-not $rdpData.nlaEnabled)         { Add-Rec 'crit' 'SICUREZZA' 'NLA disabilitato su RDP' 'Abilitare NLA' }
    if ($rdpData.securityLayer -ne 2)     { Add-Rec 'warn' 'SICUREZZA' 'RDP Security Layer non SSL/TLS' 'Impostare Layer=2' }
    if ($rdpData.encryptionLevel -lt 3)   { Add-Rec 'warn' 'SICUREZZA' 'RDP Encryption Level non High' 'Impostare Level=3' }
    # SMB1 segnalato piu avanti nella sezione SMB con descrizione completa (evita doppio conteggio)
    # RETE
    if (-not $netData.tcpTimedWaitDelay)  { Add-Rec 'warn' 'RETE' 'TcpTimedWaitDelay non configurato' 'Impostare a 30s' }
    # MaxUserPort e ignorato da Windows 2008 in poi: si valuta l'utilizzo reale del range dinamico
    $ephPct = if ($netData.ephemeralPortsMax -gt 0) { [math]::Round($netData.ephemeralPortsInUse / $netData.ephemeralPortsMax * 100, 0) } else { 0 }
    if     ($ephPct -ge 80) { Add-Rec 'crit' 'RETE' "Porte effimere al $ephPct% ($($netData.ephemeralPortsInUse)/$($netData.ephemeralPortsMax))" 'Rischio esaurimento porte: ampliare il range dinamico (netsh int ipv4 set dynamicport)' }
    elseif ($ephPct -ge 50) { Add-Rec 'warn' 'RETE' "Porte effimere al $ephPct% ($($netData.ephemeralPortsInUse)/$($netData.ephemeralPortsMax))" 'Monitorare / valutare ampliamento range dinamico' }
    if ($netData.timeWaitCount -ge 500)   { Add-Rec 'crit' 'RETE' "TIME_WAIT $($netData.timeWaitCount) - saturazione porte" "Verificare TcpTimedWaitDelay" }
    elseif ($netData.timeWaitCount -ge 100) { Add-Rec 'warn' 'RETE' "TIME_WAIT $($netData.timeWaitCount) - monitorare" "" }
    if ($netData.closeWaitCount -gt 0)    { Add-Rec 'crit' 'RETE' "CLOSE_WAIT $($netData.closeWaitCount) - leak applicativo" "Verificare applicazione" }
    # NIC Advanced - skip adapter virtuali (VMware/Hyper-V), raggruppa problemi per adapter
    foreach ($adRec in $netData.adapters) {
        $adName = $adRec.name
        # Gli adapter virtuali non espongono queste proprieta: skip per evitare falsi warning
        if ($adRec.isVirtual) { continue }
        # Raccoglie tutti i problemi di questo adapter in un unico warn (evita warning multipli per NIC)
        $nicProblems = @()
        if ($adRec.pmWolEnabled)                      { $nicProblems += 'WoL abilitato' }
        if ($adRec.pmAllowTurnOff)                    { $nicProblems += 'power-off NIC consentito' }
        if (-not $adRec.rssEnabled)                   { $nicProblems += 'RSS disabilitato' }
        if ($adRec.lsoV2IPv4 -eq 'Disabled')        { $nicProblems += 'LSO v2 IPv4 disabilitato' }
        if ($adRec.lsoV2IPv6 -eq 'Disabled')        { $nicProblems += 'LSO v2 IPv6 disabilitato' }
        if ($adRec.flowControl -match 'Disabled')   { $nicProblems += 'Flow Control disabilitato' }
        if ($nicProblems.Count -gt 0) {
            Add-Rec 'warn' 'NIC' "[$adName] $($nicProblems.Count) ottimizzazioni NIC mancanti" ($nicProblems -join ', ')
        }
    }
    # MEMORIA reg
    if (-not $regData.disablePagingExecutive) { Add-Rec 'warn' 'MEMORIA' 'DisablePagingExecutive non attivo' 'Impostare a 1' }
    if ($null -eq $regData.largeSystemCache -or $regData.largeSystemCache -ne 0) { Add-Rec 'warn' 'MEMORIA' 'LargeSystemCache non configurato per TS' 'Impostare a 0 (server mode)' }
    # POWER
    if (-not $ppData.isHighPerformance)   { Add-Rec 'warn' 'PERFORMANCE' 'Power Plan non High Performance' 'Ottimizzare profilo energetico' }
    # RDP performance
    if ($rdpData.wallpaperEnabled)        { Add-Rec 'warn' 'RDP-PERF' 'Wallpaper RDP abilitato' 'Disabilitare' }
    if ($rdpData.menuAnimations)          { Add-Rec 'warn' 'RDP-PERF' 'Animazioni menu RDP attive' 'Disabilitare' }
    if (-not $rdpData.deleteTempOnExit)   { Add-Rec 'warn' 'RDP-MAINT' 'DeleteTempDirsOnExit non configurato' 'Abilitare' }
    if ($rdpData.lptRedirect)             { Add-Rec 'warn' 'RDP' 'Redirect LPT abilitato' 'Disabilitare' }
    if ($rdpData.comRedirect)             { Add-Rec 'warn' 'RDP' 'Redirect COM abilitato' 'Disabilitare' }
    if (-not $rdpData.avc444Enabled)      { Add-Rec 'warn' 'RDP-PERF' 'AVC444 H.264 non abilitato' 'Abilitare per migliore compressione video' }
    if ($rdpData.disconnectedSessions -gt 5) { Add-Rec 'warn' 'RDP-MAINT' "Sessioni disconnesse: $($rdpData.disconnectedSessions)" "Configurare MaxDisconnectionTime" }
    # DELIVERY OPT
    if ($netData.deliveryOptMode -ne 0 -and $null -ne $netData.deliveryOptMode) { Add-Rec 'warn' 'RETE' 'Delivery Optimization non in HTTP only' 'Impostare a 0' }
    # CERTIFICATI
    foreach ($c in ($certData | Where-Object { $_.status -eq 'expired'  })) { Add-Rec 'crit' 'CERTIFICATI' "Certificato SCADUTO: $($c.subject.Substring(0,[Math]::Min(60,$c.subject.Length)))" "Scaduto $($c.daysLeft * -1) giorni fa" }
    foreach ($c in ($certData | Where-Object { $_.status -eq 'expiring' })) { Add-Rec 'warn' 'CERTIFICATI' "Certificato in scadenza: $($c.subject.Substring(0,[Math]::Min(60,$c.subject.Length)))" "Scade tra $($c.daysLeft) giorni" }
    # WINDOWS UPDATE
    if (-not $wuData.searchCompleted)     { Add-Rec 'warn' 'AGGIORNAMENTI' 'Ricerca aggiornamenti Windows non riuscita' 'Stato patch sconosciuto: verificare manualmente Windows Update / WSUS' }
    elseif ($wuData.pendingUpdates -gt 10) { Add-Rec 'crit' 'AGGIORNAMENTI' "$($wuData.pendingUpdates) aggiornamenti pending" "Sistema non aggiornato" }
    elseif ($wuData.pendingUpdates -gt 0) { Add-Rec 'warn' 'AGGIORNAMENTI' "$($wuData.pendingUpdates) aggiornamenti pending" "Pianificare manutenzione" }
    if ($wuData.deferralQualityDays -eq 0 -and -not $wuData.wsusEnabled) { Add-Rec 'warn' 'AGGIORNAMENTI' 'Nessun deferral Quality Updates configurato' 'Configurare almeno 7 giorni per testing' }
    if ($wuData.deferralFeatureDays -eq 0 -and -not $wuData.wsusEnabled) { Add-Rec 'warn' 'AGGIORNAMENTI' 'Nessun deferral Feature Updates configurato' 'Configurare almeno 180 giorni su server' }
    # TASKS
    if ($taskData.failed.Count -gt 5)     { Add-Rec 'warn' 'TASKS' "$($taskData.failed.Count) scheduled task falliti" "Verificare log" }
    if ($taskData.suspicious.Count -gt 0) { Add-Rec 'warn' 'SICUREZZA' "$($taskData.suspicious.Count) task sospetti (non-Microsoft)" "Verificare manualmente" }
    # PROFILI
    foreach ($p in ($profileData.profiles | Where-Object { $_.sizeGB -gt 10 })) { Add-Rec 'warn' 'PROFILI' "Profilo $($p.name): $($p.sizeGB) GB" "Considerare pulizia/reindirizzamento" }
    if ($profileData.orphaned.Count -gt 0) { Add-Rec 'warn' 'PROFILI' "$($profileData.orphaned.Count) profili orfani" "Pulizia registry consigliata" }
    # UPTIME
    if ($sysData.uptimeDays -gt 90) { Add-Rec 'crit' 'STABILITA' "Uptime $($sysData.uptimeDays) giorni - riavvio critico" "Patch e fix potrebbero non essere attivi" }
    elseif ($sysData.uptimeDays -gt 30) { Add-Rec 'warn' 'STABILITA' "Uptime $($sysData.uptimeDays) giorni - pianificare riavvio" "Aggiornamenti potrebbero essere pending" }
    # TCP ACK FREQUENCY
    $ifsWithoutAck = @($regData.tcpAckFreqPerIface | Where-Object { $null -eq $_.value -or $_.value -ne 1 })
    if ($ifsWithoutAck.Count -gt 0) { Add-Rec 'warn' 'RETE' "TcpAckFrequency non ottimizzato su $($ifsWithoutAck.Count) interfacce" "Impostare a 1 per ridurre latenza RDS" }
    # TEMP FOLDERS
    if ($regData.totalTempGB -gt 20)    { Add-Rec 'crit' 'DISCO' "Cartelle temp occupano $($regData.totalTempGB) GB - critico" "Pulizia urgente richiesta" }
    elseif ($regData.totalTempGB -gt 5) { Add-Rec 'warn' 'DISCO' "Cartelle temp occupano $($regData.totalTempGB) GB" "Eseguire pulizia disco" }
    # RDP TIMEOUT mancanti
    if (-not $rdpData.maxIdleMinutes)          { Add-Rec 'warn' 'RDP' 'MaxIdleTime non configurato' 'Impostare a 60 minuti per sessioni abbandonate' }
    if (-not $rdpData.maxDisconnectionMinutes) { Add-Rec 'warn' 'RDP' 'MaxDisconnectionTime non configurato' 'Impostare a 120 minuti' }
    if ($rdpData.colorDepthBit -gt 16 -and $isTS -and -not $rdpData.avc444Enabled) { Add-Rec 'warn' 'RDP-PERF' "Color depth RDP a $($rdpData.colorDepthBit) bit" "Ridurre a 16 bit per migliorare performance" }
    # HANDLE LEAK
    $highHandleProcs = @($allProcs | Where-Object { $_.HandleCount -gt 10000 })
    if ($highHandleProcs.Count -gt 0) { Add-Rec 'warn' 'STABILITA' "Processi con handle elevati: $($highHandleProcs[0].Name) ($($highHandleProcs[0].HandleCount))" "Possibile handle leak" }
    # POOL NONPAGED
    $npPoolMB = [math]::Round($ramData.poolNonPagedMB, 0)
    $totalRamMB = [math]::Round($os.TotalVisibleMemorySize / 1MB * 1024, 0)
    if ($npPoolMB -gt 0 -and $totalRamMB -gt 0) {
        $npPct = [math]::Round($npPoolMB / $totalRamMB * 100, 1)
        if ($npPct -gt 10) { Add-Rec 'warn' 'MEMORIA' "Pool NonPaged al $npPct% della RAM totale ($npPoolMB MB)" "Possibile memory leak kernel" }
    }
    # CACHED LOGONS
    $cachedLogons = [int]($regData.cachedLogonsCount)
    if ($cachedLogons -gt 5) { Add-Rec 'warn' 'SICUREZZA' "Cached logons: $cachedLogons credenziali in cache" "Ridurre a 2-3 su server" }
    # SMB - solo segnalazione, nessun fix automatico
    if ($smbData.smb1Enabled)            { Add-Rec 'crit' 'SICUREZZA' 'SMB1 abilitato - INTERVENTO MANUALE RICHIESTO' 'Disabilitare manualmente: Set-SmbServerConfiguration -EnableSMB1Protocol $false' }
    if (-not $smbData.encryptData)       { Add-Rec 'warn' 'SICUREZZA' 'SMB Encrypt Data disabilitato' 'Valutare abilitazione se dati sensibili in transito' }
    if (-not $smbData.requireSignature)  { Add-Rec 'warn' 'SICUREZZA' 'SMB Require Signature disabilitato' 'Abilitare per prevenire attacchi MITM' }
    # FIREWALL
    if (-not $fwData.domainEnabled)  { Add-Rec 'crit' 'SICUREZZA' 'Firewall Domain Profile DISABILITATO' 'Abilitare immediatamente' }
    if (-not $fwData.privateEnabled) { Add-Rec 'warn' 'SICUREZZA' 'Firewall Private Profile disabilitato' 'Abilitare' }
    if (-not $fwData.publicEnabled)  { Add-Rec 'crit' 'SICUREZZA' 'Firewall Public Profile DISABILITATO' 'Abilitare immediatamente' }

    $critCount_s = ($recs | Where-Object { $_.priority -eq 'crit' } | Measure-Object).Count
    $warnCount_s = ($recs | Where-Object { $_.priority -eq 'warn' } | Measure-Object).Count

    function Get-SectionStatus { param($pct,$warn,$crit)
        if ($pct -ge $crit) { return 'crit' } ; if ($pct -ge $warn) { return 'warn' } ; return 'ok' }

    $scoresData = [ordered]@{
        cpu      = [ordered]@{ value=[int]$cpuData.avgUsagePct; status=(Get-SectionStatus $cpuData.avgUsagePct 70 85) }
        ram      = [ordered]@{ value=[int]$ramPct;              status=(Get-SectionStatus $ramPct              75 85) }
        disk     = [ordered]@{ value=[int]($diskData.volumes[0].usagePct); status=(Get-SectionStatus $diskData.volumes[0].usagePct 70 85) }
        net      = [ordered]@{ value=[int]($twCount + $cwCount); status=if($twCount -ge 500 -or $cwCount -gt 0){'crit'}elseif($twCount -ge 100){'warn'}else{'ok'} }
        rdp      = [ordered]@{ value=0; status=if(-not $rdpData.nlaEnabled){'crit'}elseif($rdpData.wallpaperEnabled -or $rdpData.menuAnimations -or -not $rdpData.deleteTempOnExit -or -not $rdpData.maxIdleMinutes -or $rdpData.lptRedirect -or $rdpData.comRedirect){'warn'}else{'ok'} }
        security = [ordered]@{ value=0; status=if($smbData.smb1Enabled -or -not $rdpData.nlaEnabled){'crit'}else{'ok'} }
        certs    = [ordered]@{ value=$certsExpired+$certsExpiring; status=if($certsExpired-gt 0){'crit'}elseif($certsExpiring-gt 0){'warn'}else{'ok'} }
        updates  = [ordered]@{ value=$wuData.pendingUpdates; status=if(-not $wuData.searchCompleted){'warn'}elseif($wuData.pendingUpdates-gt 10){'crit'}elseif($wuData.pendingUpdates-gt 0){'warn'}else{'ok'} }
        critCount= [int]$critCount_s
        warnCount= [int]$warnCount_s
        okCount  = [int][math]::Max(0, 20 - $critCount_s - $warnCount_s)
        # Score globale 0-100
        globalScore = [int][math]::Max(0, 100 - ($critCount_s * 5) - ($warnCount_s * 2))
    }
    Write-AuditLog "Score globale: $($scoresData.globalScore)/100  Critici: $critCount_s  Warning: $warnCount_s" 'OK'

    # --------------------------------------------------------------------------
    # 20. ASSEMBLA JSON
    # --------------------------------------------------------------------------
    Write-AuditSection 'Assemblaggio JSON'

    $auditData = [ordered]@{
        meta            = [ordered]@{
            hostname        = S $CN
            fqdn            = S "$CN.$($sysData.domain)"
            auditDate       = $StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            auditPeriodDays = [int]$DaysToScan
            serverRole      = S $ServerRole
            roleCode        = S $RoleCode
            readOnly        = $true
            scriptVersion   = S $ScriptVersion
        }
        scores          = $scoresData
        system          = $sysData
        cpu             = $cpuData
        ram             = $ramData
        disk            = $diskData
        network         = $netData
        processes       = $procsData
        eventLog        = $evtData
        services        = $svcData
        rdp             = $rdpData
        antivirus       = $avData
        firewall        = $fwData
        smb             = $smbData
        registry        = $regData
        powerPlan       = $ppData
        certificates    = [ordered]@{ items = $certData; expiredCount = $certsExpired; expiringCount = $certsExpiring }
        windowsUpdate   = $wuData
        scheduledTasks  = $taskData
        userProfiles    = $profileData
        software        = $swData
        loginEvents     = $loginEvents
        recommendations = @($recs)
    }

    $JsonFile = Join-Path $AuditOutputPath "${RoleCode}_AuditData_${CN}_${Timestamp}.json"
    $auditData | ConvertTo-Json -Depth 12 | Out-File -FilePath $JsonFile -Encoding UTF8 -Force
    $jsonSize = [math]::Round((Get-Item $JsonFile).Length / 1KB, 1)
    Write-AuditLog "JSON scritto: $JsonFile ($jsonSize KB)" 'OK'

    $HtmlFile = $null
    if (-not $JsonOnly) {
        Write-AuditSection 'Generazione Report HTML'
        try {
            $HtmlFile = Invoke-NewAuditReport -JsonPath $JsonFile -ReportOutPath $AuditOutputPath
            if ($OpenReport -and $HtmlFile -and (Test-Path $HtmlFile)) { Start-Process $HtmlFile }
        } catch { Write-AuditLog "Errore HTML: $_" 'ERROR' }
    }

    $elapsed = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 1)
    Write-Host ''
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host "  AUDIT COMPLETATO - $CN ($ServerRole)" -ForegroundColor Green
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host "  Durata     : ${elapsed}s"                 -ForegroundColor Cyan
    Write-Host "  Score      : $($scoresData.globalScore)/100" -ForegroundColor $(if($scoresData.globalScore -ge 70){'Green'}elseif($scoresData.globalScore -ge 40){'Yellow'}else{'Red'})
    Write-Host "  Critici    : $critCount_s"                -ForegroundColor $(if($critCount_s -gt 0){'Red'}else{'Green'})
    Write-Host "  Warning    : $warnCount_s"                -ForegroundColor $(if($warnCount_s -gt 0){'Yellow'}else{'Green'})
    Write-Host "  JSON       : $JsonFile"                   -ForegroundColor Cyan
    if ($HtmlFile) { Write-Host "  HTML       : $HtmlFile" -ForegroundColor Cyan }
    Write-Host ('=' * 62) -ForegroundColor Green
    Write-Host ''

    return $JsonFile
}


# ==============================================================================
# INVOKE-NEWAUDITREPORT  (HTML con grafici, trend, export CSV)
# ==============================================================================

function Invoke-NewAuditReport {
    param(
        [Parameter(Mandatory=$true)][string]$JsonPath,
        [string]$ReportOutPath = (Split-Path $JsonPath -Parent),
        [switch]$OpenBrowser
    )

    Write-Host "  [*] Caricamento: $JsonPath" -ForegroundColor Cyan
    $raw = Get-Content -Path $JsonPath -Raw -Encoding UTF8
    $d   = $raw | ConvertFrom-Json
    if (-not $d.meta) { throw "JSON non valido: $JsonPath" }

    $meta = $d.meta; $scores = $d.scores; $sys = $d.system; $cpu = $d.cpu
    $ram  = $d.ram;  $disk   = $d.disk;   $net = $d.network; $procs = $d.processes
    $evts = $d.eventLog; $svcs = $d.services; $rdp = $d.rdp; $av = $d.antivirus
    $fw   = $d.firewall; $smb  = $d.smb; $reg = $d.registry; $pp = $d.powerPlan
    $certs= $d.certificates; $wu = $d.windowsUpdate; $tasks = $d.scheduledTasks
    $profD= $d.userProfiles; $sw = $d.software; $recs = $d.recommendations
    $loginEvts = $d.loginEvents



    # Trend storico: carica tutti i JSON nella stessa cartella per lo stesso host
    $trendCpu = @(); $trendRam = @(); $trendDates = @(); $trendScores = @(); $trendDiskReadLat = @(); $trendDiskWriteLat = @()
    try {
        $allJsons = @(Get-ChildItem -Path $ReportOutPath -Filter "*AuditData_$($meta.hostname)*.json" -EA SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 10)
        foreach ($jf in $allJsons) {
            try {
                $jd = (Get-Content $jf.FullName -Raw -Encoding UTF8) | ConvertFrom-Json
                $trendDates  += $jd.meta.auditDate.Substring(0,10)
                $trendCpu    += [int]$jd.cpu.avgUsagePct
                $trendRam    += [int]$jd.ram.usagePct
                $trendScores += [int]$jd.scores.globalScore
                $trendDiskReadLat  += [int]$jd.disk.readLatencyMs
                $trendDiskWriteLat += [int]$jd.disk.writeLatencyMs
            } catch { }
        }
    } catch { }

    # ---- UTILITY FUNCTIONS ----
    function hs  { param([string]$t); return $t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;' }
    function kvr { param([string]$l,[string]$v); return "<tr><td>$(hs $l)</td><td>$v</td></tr>" }
    function boolBadge {
        param($v,$goodIsTrue=$true,$lt='Si',$lf='No')
        # Normalizza goodIsTrue in caso arrivi come stringa
        if ($goodIsTrue -is [string]) {
            $goodIsTrue = ($goodIsTrue -notin @('false','0','no',''))
        }
        $goodIsTrueBool = [bool]$goodIsTrue
        $vBool   = [bool]$v
        $isGood  = if ($goodIsTrueBool) { $vBool } else { -not $vBool }
        $lbl     = if ($vBool) { $lt } else { $lf }
        $cls     = if ($isGood) { 'bg' } else { 'br' }
        return "<span class='b $cls'>$lbl</span>"
    }
    function nullBadge {
        param($v,$ifNull,$ifSet=$null,$cls='by')
        if ($null -eq $v -or $v -eq '') { return "<span class='b $cls'>$(hs $ifNull)</span>" }
        $txt = if ($ifSet) { $ifSet } else { "$v" }
        return "<span class='b bg'>$txt</span>"
    }
    function pctFill {
        param($p,[int]$w=70,[int]$c=85)
        if ($p -ge $c) { return 'fr' }; if ($p -ge $w) { return 'fy' }; return 'fg'
    }
    function pctColor {
        param($p,[int]$w=70,[int]$c=85)
        if ($p -ge $c) { return 'var(--red)' }; if ($p -ge $w) { return 'var(--yellow)' }; return 'var(--green)'
    }
    function statusBadge {
        param($s,$ok,$warn,$crit)
        switch ($s) { 'crit'{return "<span class='b br'>$(hs $crit)</span>"} 'warn'{return "<span class='b by'>$(hs $warn)</span>"} default{return "<span class='b bg'>$(hs $ok)</span>"} }
    }
    function cardClass { param($s); switch($s){'crit'{'card-crit'}'warn'{'card-warn'}default{'card-ok'}} }

    # ---- CSS ----
    $css = @'
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --border:#30363d;--border2:#444c56;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --green:#3fb950;--gbg:#0d4429;--gt:#56d364;
  --yellow:#d29922;--ybg:#3d2e0e;--yt:#e3b341;
  --red:#f85149;--rbg:#3d0e0e;--rt:#ff7b72;
  --blue:#388bfd;--bbg:#0c2d6b;--bt:#79c0ff;
  --accent:#58a6ff;
  --score-r:120px;
}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:'Cascadia Code','Consolas','SF Mono',monospace;font-size:13px;line-height:1.5}
/* HEADER */
.hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 20px;display:flex;align-items:center;justify-content:space-between;position:fixed;top:0;left:0;right:0;z-index:200;height:48px}
.hdr-l{display:flex;align-items:center;gap:10px}
.srv-badge{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:2px 8px;font-size:10px;color:var(--text2);letter-spacing:.5px;text-transform:uppercase}
.hostname{font-size:15px;font-weight:700;color:var(--text)}
.hdr-r{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text3)}
.dot-live{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block}
/* SCOREBAR */
.sbar{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 20px;display:flex;gap:6px;align-items:center;position:fixed;top:48px;left:0;right:0;z-index:199;height:44px;overflow-x:auto}
.chip{display:flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);cursor:pointer;white-space:nowrap;font-size:11px;background:transparent;transition:border-color .15s,background .15s}
.chip:hover{border-color:var(--border2);background:var(--bg3)}
.chip.active{border-color:var(--accent);background:rgba(88,166,255,.1)}
.cdot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.cdot.g{background:var(--green)}.cdot.y{background:var(--yellow)}.cdot.r{background:var(--red)}
/* LAYOUT */
.layout{display:flex;position:fixed;top:92px;bottom:0;left:0;right:0}
.sidebar{width:200px;min-width:200px;background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;padding:6px 0}
.nav-item{padding:6px 14px;cursor:pointer;display:flex;align-items:center;gap:8px;color:var(--text2);font-size:11.5px;border-left:2px solid transparent;user-select:none;transition:all .1s}
.nav-item:hover{background:var(--bg3);color:var(--text)}
.nav-item.active{background:rgba(88,166,255,.08);color:var(--accent);border-left-color:var(--accent)}
.nav-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.nav-grp{padding:8px 14px 3px;font-size:9.5px;color:var(--text3);letter-spacing:1px;text-transform:uppercase;margin-top:4px}
.nav-sep{height:1px;background:var(--border);margin:4px 0}
.main{flex:1;overflow-y:auto;padding:20px;background:var(--bg)}
.section{display:none}
.section.active{display:block;animation:fadeIn .15s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
/* TITLES */
.sec-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.sec-title .ac{color:var(--accent)}
/* GRIDS */
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
.g2{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px}
.g1{margin-bottom:14px}
@media(max-width:1200px){.g4{grid-template-columns:repeat(2,1fr)}}
/* CARDS */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:13px 14px}
.card-ok  {border-left:3px solid var(--green)}
.card-warn{border-left:3px solid var(--yellow)}
.card-crit{border-left:3px solid var(--red)}
.c-title{font-size:9.5px;color:var(--text3);text-transform:uppercase;letter-spacing:.9px;margin-bottom:7px}
.c-val{font-size:22px;font-weight:700;color:var(--text);line-height:1}
.c-sub{font-size:11px;color:var(--text2);margin-top:4px}
/* BADGES */
.b{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10.5px;font-weight:700;line-height:1.4}
.bg{background:var(--gbg);color:var(--gt)}.by{background:var(--ybg);color:var(--yt)}.br{background:var(--rbg);color:var(--rt)}.bb{background:var(--bbg);color:var(--bt)}
/* TABLES */
.kv{width:100%;border-collapse:collapse}
.kv tr{border-bottom:1px solid var(--border)}.kv tr:last-child{border-bottom:none}
.kv td{padding:6px 8px;vertical-align:middle;font-size:11.5px}.kv td:first-child{color:var(--text2);width:48%}.kv td:last-child{color:var(--text);font-weight:500}
.dt{width:100%;border-collapse:collapse;font-size:11.5px}
.dt th{background:var(--bg3);color:var(--text2);padding:7px 10px;text-align:left;font-weight:600;font-size:10.5px;letter-spacing:.3px;position:sticky;top:0;border-bottom:1px solid var(--border)}
.dt td{padding:5px 10px;border-bottom:1px solid var(--border);color:var(--text)}
.dt tr:hover td{background:rgba(88,166,255,.04)}.dt tr:last-child td{border-bottom:none}
/* PROGRESS */
.pb{background:var(--bg4);border-radius:3px;height:5px;overflow:hidden;margin-top:6px}
.pf{height:100%;border-radius:3px}
.fg{background:var(--green)}.fy{background:var(--yellow)}.fr{background:var(--red)}
/* REC ITEMS */
.rec{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 13px;margin-bottom:8px;display:flex;align-items:flex-start;gap:10px}
.rec:hover{border-color:var(--border2)}
.rec-p{font-size:9.5px;font-weight:700;padding:2px 7px;border-radius:3px;white-space:nowrap;flex-shrink:0;margin-top:1px}
.rec-body{flex:1}.rec-txt{font-size:12px;color:var(--text);line-height:1.4}
.rec-det{font-size:11px;color:var(--text3);margin-top:3px;font-style:italic}
.rec-cat{display:inline-block;font-size:10px;color:var(--text3);background:var(--bg3);padding:1px 6px;border-radius:3px;margin-top:4px}
/* EVENT ITEMS */
.ev-item{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:8px}
.ev-item.lc{border-left:3px solid var(--red)}.ev-item.le{border-left:3px solid var(--red)}.ev-item.lw{border-left:3px solid var(--yellow)}
.ev-hdr{display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-wrap:wrap}
.ev-msg{font-size:11px;color:var(--text2);line-height:1.5;word-break:break-word}
/* SCROLL BOX */
.sb{max-height:360px;overflow-y:auto}
.sb::-webkit-scrollbar{width:4px}.sb::-webkit-scrollbar-track{background:var(--bg3)}.sb::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
/* DISK */
.disk-row{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.disk-letter{background:var(--bg3);border:1px solid var(--border);border-radius:5px;width:34px;height:34px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0}
.disk-info{flex:1}.disk-szs{display:flex;justify-content:space-between;font-size:11px;margin-top:2px}
/* CORE GRID */
.core-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(32px,1fr));gap:4px;margin-top:6px}
.core-cell{text-align:center}.core-bar{border-radius:2px 2px 0 0;width:100%;min-height:4px}
.core-lbl{font-size:8.5px;color:var(--text3);margin-top:2px}
/* USER ROWS */
.user-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.user-name{font-size:11px;color:var(--text2);width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex-shrink:0}
.user-stats{font-size:11px;color:var(--text3);width:100px;text-align:right;flex-shrink:0}
/* SCORE RING */
.score-ring-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:10px}
.score-ring-val{font-size:42px;font-weight:700;line-height:1}
.score-ring-lbl{font-size:11px;color:var(--text2);margin-top:4px}
/* ALERTS */
.alert{border-radius:5px;padding:9px 12px;font-size:11.5px;margin-top:10px;line-height:1.5}
.a-r{background:var(--rbg);color:var(--rt);border-left:3px solid var(--red)}
.a-y{background:var(--ybg);color:var(--yt);border-left:3px solid var(--yellow)}
.a-g{background:var(--gbg);color:var(--gt);border-left:3px solid var(--green)}
/* MINI CHART (CSS sparkline) */
.chart-wrap{display:flex;align-items:flex-end;gap:3px;height:50px;margin-top:8px}
.chart-bar{flex:1;border-radius:2px 2px 0 0;min-height:2px;position:relative;cursor:default}
.chart-bar:hover::after{content:attr(data-v);position:absolute;top:-20px;left:50%;transform:translateX(-50%);background:var(--bg4);color:var(--text);font-size:10px;padding:2px 5px;border-radius:3px;white-space:nowrap;pointer-events:none}
.chart-labels{display:flex;gap:3px;margin-top:4px}
.chart-lbl{flex:1;text-align:center;font-size:9px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* EXPORT BTN */
.export-btn{background:var(--bg3);border:1px solid var(--border);color:var(--text2);padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer;font-family:inherit}
.export-btn:hover{border-color:var(--accent);color:var(--accent)}
/* SCROLLBARS */
.main::-webkit-scrollbar{width:5px}.main::-webkit-scrollbar-track{background:var(--bg)}.main::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
.sidebar::-webkit-scrollbar{width:3px}.sidebar::-webkit-scrollbar-track{background:var(--bg2)}.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}
/* OPTIMIZATION STATE */
.opt-applied  {background:var(--gbg);color:var(--gt)}
.opt-reverted {background:var(--bbg);color:var(--bt)}
.opt-failed   {background:var(--rbg);color:var(--rt)}
.opt-pending  {background:var(--ybg);color:var(--yt)}
/* GAUGE */
.gauge-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:6px 0}
.gauge-val{font-size:20px;font-weight:700;text-anchor:middle;dominant-baseline:middle}
/* TOOLTIP */
[data-tip]{position:relative;cursor:help}
[data-tip]::after{content:attr(data-tip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--bg4);color:var(--text);font-size:10px;padding:5px 9px;border-radius:4px;white-space:pre-wrap;max-width:220px;border:1px solid var(--border2);z-index:999;pointer-events:none;opacity:0;transition:opacity .15s;line-height:1.5}
[data-tip]:hover::after{opacity:1}
/* BACK TO TOP */
#back-top{position:fixed;bottom:18px;right:18px;background:var(--bg3);border:1px solid var(--border2);color:var(--text2);width:34px;height:34px;border-radius:6px;display:none;align-items:center;justify-content:center;cursor:pointer;font-size:16px;z-index:500;transition:all .15s}
#back-top:hover{border-color:var(--accent);color:var(--accent)}
#back-top.visible{display:flex}
/* NAV BADGE */
.nav-badge{margin-left:auto;font-size:9px;font-weight:700;padding:1px 5px;border-radius:10px;line-height:1.4}
.nb-r{background:var(--rbg);color:var(--rt)}
.nb-y{background:var(--ybg);color:var(--yt)}
/* SEARCH BOX */
.search-box{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;font-size:12px;font-family:inherit;width:100%;margin-bottom:10px}
.search-box:focus{outline:none;border-color:var(--accent)}
/* EXECUTIVE SUMMARY */
.exec-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px 18px;margin-bottom:14px}
.exec-status{font-size:28px;font-weight:700;margin-bottom:4px}
.exec-text{font-size:12px;color:var(--text2);line-height:1.8}
.exec-text b{color:var(--text)}
/* STABLE INDICATOR */
.stable-badge{display:inline-flex;align-items:center;gap:6px;background:var(--gbg);color:var(--gt);padding:4px 10px;border-radius:4px;font-size:11px;font-weight:600}
.stable-badge.warn{background:var(--ybg);color:var(--yt)}
.stable-badge.crit{background:var(--rbg);color:var(--rt)}
/* CERT STATUS */
.cert-ok{color:var(--green)}.cert-exp{color:var(--red)}.cert-soon{color:var(--yellow)}
/* FILTER BAR */
.filter-row{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.filter-btn{background:var(--bg3);border:1px solid var(--border);color:var(--text2);padding:3px 10px;border-radius:3px;font-size:11px;cursor:pointer;font-family:inherit}
.filter-btn.on{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.08)}
/* EVENT MODAL */
.ev-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;display:none;align-items:center;justify-content:center}
.ev-modal-overlay.open{display:flex}
.ev-modal{background:var(--bg2);border:1px solid var(--border2);border-radius:10px;width:700px;max-width:95vw;max-height:80vh;display:flex;flex-direction:column;overflow:hidden}
.ev-modal-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.ev-modal-title{font-size:13px;font-weight:700;color:var(--text)}
.ev-modal-close{background:none;border:none;color:var(--text3);font-size:18px;cursor:pointer;padding:0 4px;line-height:1}
.ev-modal-close:hover{color:var(--text)}
.ev-modal-body{padding:16px 18px;overflow-y:auto;flex:1}
.ev-modal-row{display:flex;gap:12px;margin-bottom:8px;font-size:12px}
.ev-modal-lbl{color:var(--text3);min-width:90px;flex-shrink:0}
.ev-modal-val{color:var(--text);word-break:break-word}
.ev-modal-msg{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:11.5px;color:var(--text2);line-height:1.7;white-space:pre-wrap;word-break:break-word;margin-top:8px;max-height:300px;overflow-y:auto}
/* EVENT SEARCH */
.ev-search{background:var(--bg3);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:4px;font-size:12px;font-family:inherit;width:300px}
.ev-search:focus{outline:none;border-color:var(--accent)}
.ev-item{cursor:pointer;transition:border-color .1s}
.ev-item:hover{border-color:var(--accent)}
'@

    # ---- JAVASCRIPT ----
    $js = @'

function filterChip(el, type) {
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    el.classList.add('active');
    // Rimuovi highlight precedenti
    document.querySelectorAll('.rec').forEach(r => r.style.outline = '');
    document.querySelectorAll('.nav-item').forEach(n => n.style.background = '');
    if (type === 'crit') {
        showSection('recs');
        setTimeout(function() {
            filterRecs(document.querySelector('.filter-btn[data-prio="crit"]') || document.querySelectorAll('.filter-btn')[1], 'crit');
            var first = document.querySelector('.rec[data-prio="crit"]');
            if (first) { first.scrollIntoView({behavior:'smooth', block:'center'}); first.style.outline = '2px solid var(--red)'; setTimeout(function(){ first.style.outline=''; }, 2000); }
        }, 100);
    } else if (type === 'warn') {
        showSection('recs');
        setTimeout(function() {
            filterRecs(document.querySelector('.filter-btn[data-prio="warn"]') || document.querySelectorAll('.filter-btn')[2], 'warn');
            var first = document.querySelector('.rec[data-prio="warn"]');
            if (first) { first.scrollIntoView({behavior:'smooth', block:'center'}); first.style.outline = '2px solid var(--yellow)'; setTimeout(function(){ first.style.outline=''; }, 2000); }
        }, 100);
    } else if (type === 'ok') {
        showSection('dashboard');
    } else {
        showSection('dashboard');
    }
}
function exportTableCSV(tableId, filename) {
    var tbl = document.getElementById(tableId);
    if (!tbl) return;
    var rows = Array.from(tbl.querySelectorAll('tr'));
    var csv  = rows.map(function(r){
        return Array.from(r.querySelectorAll('th,td'))
            .map(function(c){ return '"' + c.innerText.replace(/"/g,'""') + '"'; })
            .join(',');
    }).join('\n');
    var blob = new Blob(['\uFEFF'+csv], {type:'text/csv;charset=utf-8;'});
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = filename; a.click();
}
function filterRecs(btn, prio) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('on'));
    btn.classList.add('on');
    document.querySelectorAll('.rec').forEach(function(r){
        if (prio === 'all') { r.style.display=''; }
        else { r.style.display = r.getAttribute('data-prio') === prio ? '' : 'none'; }
    });
}
function showSection(id) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    var s = document.getElementById('s-' + id);
    if (s) s.classList.add('active');
    document.querySelectorAll('.nav-item[data-sec]').forEach(function(it) {
        if (it.getAttribute('data-sec') === id) it.classList.add('active');
    });
    var main = document.querySelector('.main');
    if (main) main.scrollTo({top:0, behavior:'instant'});
    var labels = {logins:'Accessi Utente RDS',dashboard:'Dashboard',recs:'Raccomandazioni',cpu:'CPU',ram:'Memoria RAM',disk:'Disco',net:'Rete',procs:'Processi',events:'Analisi Eventi',services:'Servizi',tasks:'Scheduled Tasks',profiles:'Profili Utente',rdp:'RDP / RDS',av:'Antivirus',fw:'Firewall / SMB',certs:'Certificati',wu:'Windows Update',reg:'Registry',sw:'Software',exec:'Riepilogo Esecutivo',optstate:'Stato Ottimizzazioni'};
    var bc = document.getElementById('breadcrumb-cur');
    if (bc) bc.textContent = labels[id] || id;
}
function filterLoginEvents(val) {
    var rows = document.querySelectorAll('#tbl-login-detail tbody tr');
    var q = val.toLowerCase();
    rows.forEach(function(r) { r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
}


function filterSoftware(val) {
    var rows = document.querySelectorAll('#tbl-sw tbody tr');
    var q = val.toLowerCase();
    rows.forEach(function(r) { r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
}
function updateBreadcrumb(label) { var bc=document.getElementById('breadcrumb-cur'); if(bc) bc.textContent=label; }

// ---- EVENT LOG MODAL ----
function openEventModal(el) {
    var modal = document.getElementById('ev-modal-overlay');
    if (!modal) return;
    var data = {
        time:     el.getAttribute('data-time')     || '',
        level:    el.getAttribute('data-level')    || '',
        log:      el.getAttribute('data-log')      || '',
        provider: el.getAttribute('data-provider') || '',
        id:       el.getAttribute('data-id')       || '',
        message:  el.getAttribute('data-message')  || ''
    };
    document.getElementById('em-time').textContent     = data.time;
    document.getElementById('em-level').textContent    = data.level;
    document.getElementById('em-log').textContent      = data.log;
    document.getElementById('em-provider').textContent = data.provider;
    document.getElementById('em-id').textContent       = data.id;
    document.getElementById('em-msg').textContent      = data.message;
    var lvlCls = data.level === 'CRITICAL' || data.level === 'ERROR' ? 'br' : 'by';
    document.getElementById('em-level').className = 'b ' + lvlCls;
    modal.classList.add('open');
}
function closeEventModal() {
    var modal = document.getElementById('ev-modal-overlay');
    if (modal) modal.classList.remove('open');
}
document.addEventListener('keydown', function(e) { if(e.key==='Escape') closeEventModal(); });

// ---- EVENT SEARCH / FILTER ----
function filterEvents(val) {
    var q = val.toLowerCase().trim();
    var items = document.querySelectorAll('.ev-item[data-searchable]');
    var shown = 0;
    items.forEach(function(el) {
        var text = el.getAttribute('data-searchable').toLowerCase();
        var match = !q || text.includes(q);
        el.style.display = match ? '' : 'none';
        if (match) shown++;
    });
    var counter = document.getElementById('ev-count');
    if (counter) counter.textContent = shown + ' eventi';
}
function filterEventLevel(btn, level) {
    document.querySelectorAll('.ev-level-btn').forEach(function(b){ b.classList.remove('on'); });
    btn.classList.add('on');
    var items = document.querySelectorAll('.ev-item[data-searchable]');
    var shown = 0;
    items.forEach(function(el) {
        var elLevel = el.getAttribute('data-level') || '';
        var match = level === 'ALL' || elLevel === level;
        el.style.display = match ? '' : 'none';
        if (match) shown++;
    });
    var counter = document.getElementById('ev-count');
    if (counter) counter.textContent = shown + ' eventi';
    // reset search
    var searchBox = document.getElementById('ev-search-box');
    if (searchBox) searchBox.value = '';
}
document.addEventListener('DOMContentLoaded', function() {
    showSection('dashboard');
    var main = document.querySelector('.main');
    var btn  = document.getElementById('back-top');
    if (main && btn) {
        main.addEventListener('scroll', function() { btn.classList.toggle('visible', main.scrollTop > 200); });
        btn.addEventListener('click', function() { main.scrollTo({top:0, behavior:'smooth'}); });
    }
});
'@

    # ---- TREND CHART HTML ----
    function Build-TrendChart {
        # -Warn/-Crit: soglie colore; -HigherIsBetter per lo score (prima uno score 90 veniva colorato di rosso)
        param([array]$values, [array]$labels, [string]$colorVar, [string]$Unit = '%', [double]$Warn = 70, [double]$Crit = 85, [switch]$HigherIsBetter)
        if ($values.Count -lt 2) { return '<div style="color:var(--text3);font-size:11px;margin-top:8px">Dati insufficienti per il trend (&lt;2 audit)</div>' }
        $max = ($values | Measure-Object -Maximum).Maximum
        if ($max -le 0) { $max = 1 }
        $bars   = ''
        $lblsHtml = ''
        for ($i = 0; $i -lt $values.Count; $i++) {
            $v    = $values[$i]
            $h    = [int]([math]::Max(2, ($v / $max) * 46))
            $col  = if ($HigherIsBetter) {
                        if ($v -lt $Crit) { 'var(--red)' } elseif ($v -lt $Warn) { 'var(--yellow)' } else { $colorVar }
                    } else {
                        if ($v -ge $Crit) { 'var(--red)' } elseif ($v -ge $Warn) { 'var(--yellow)' } else { $colorVar }
                    }
            $bars += "<div class='chart-bar' style='height:${h}px;background:$col' data-v='$v$Unit'></div>"
            $lblsHtml += "<div class='chart-lbl'>$($labels[$i])</div>"
        }
        return "<div class='chart-wrap'>$bars</div><div class='chart-labels'>$lblsHtml</div>"
    }

    # ---- SECTIONS ----

    # --- DASHBOARD ---
    $cpuColor  = pctColor $cpu.avgUsagePct
    $ramColor  = pctColor $ram.usagePct  -w 75 -c 85
    $diskColor = pctColor ($disk.volumes[0].usagePct)
    $cpuFill   = pctFill  $cpu.avgUsagePct
    $ramFill   = pctFill  $ram.usagePct  -w 75 -c 85
    $diskFill  = pctFill  ($disk.volumes[0].usagePct)
    $cpuStatus = if($cpu.avgUsagePct -ge 85){'crit'}elseif($cpu.avgUsagePct -ge 70){'warn'}else{'ok'}
    $ramStatus = if($ram.usagePct -ge 85){'crit'}elseif($ram.usagePct -ge 75){'warn'}else{'ok'}

    $scoreColor = if($scores.globalScore -ge 70){'var(--green)'}elseif($scores.globalScore -ge 40){'var(--yellow)'}else{'var(--red)'}

    $certAlert = if ($certs.expiredCount -gt 0) {
        "<div class='alert a-r'>$($certs.expiredCount) certificati SCADUTI - intervenire immediatamente</div>"
    } elseif ($certs.expiringCount -gt 0) {
        "<div class='alert a-y'>$($certs.expiringCount) certificati in scadenza entro 30 giorni</div>"
    } else { '' }

    # searchCompleted assente = JSON della versione precedente (si assume ricerca riuscita)
    $wuUnknown = ($null -ne $wu.searchCompleted -and -not $wu.searchCompleted)
    $wuPendingTxt = if ($wuUnknown) { 'N/D' } else { "$($wu.pendingUpdates)" }
    $wuAlert = if ($wuUnknown) {
        "<div class='alert a-y'>Ricerca aggiornamenti Windows non riuscita: stato patch sconosciuto</div>"
    } elseif ($wu.pendingUpdates -gt 10) {
        "<div class='alert a-r'>$($wu.pendingUpdates) aggiornamenti Windows in attesa</div>"
    } elseif ($wu.pendingUpdates -gt 0) {
        "<div class='alert a-y'>$($wu.pendingUpdates) aggiornamenti Windows pending</div>"
    } else { "<div class='alert a-g'>Sistema aggiornato</div>" }

    $trendCpuChart  = Build-TrendChart -values $trendCpu    -labels $trendDates -colorVar 'var(--blue)'
    $trendRamChart  = Build-TrendChart -values $trendRam    -labels $trendDates -colorVar 'var(--accent)'
    $trendScoChart  = Build-TrendChart -values $trendScores -labels $trendDates -colorVar 'var(--green)' -Unit '' -Warn 70 -Crit 40 -HigherIsBetter
    $trendDiskReadChart  = Build-TrendChart -values $trendDiskReadLat  -labels $trendDates -colorVar 'var(--blue)'   -Unit ' ms' -Warn 10 -Crit 20
    $trendDiskWriteChart = Build-TrendChart -values $trendDiskWriteLat -labels $trendDates -colorVar 'var(--accent)' -Unit ' ms' -Warn 10 -Crit 20

    $topProvRows = ($evts.topProviders | ForEach-Object {
        $col = if($_.count -ge 20){'var(--red)'}elseif($_.count -ge 10){'var(--yellow)'}else{'var(--text3)'}
        "<tr><td style='color:$col;font-weight:700'>$($_.count)x</td><td>$(hs $_.provider) &nbsp;<span style='color:var(--text3)'>ID $($_.eventId)</span></td></tr>"
    }) -join ''

    # Pre-calcola tutte le variabili condizionali per Dashboard
    $dashUptimeClass   = if ($sys.uptimeDays -gt 90) { 'card-warn' } else { 'card-ok' }
    $dashBootStr       = try { ([datetime]$sys.lastBoot).ToString('dd/MM HH:mm') } catch { "$($sys.lastBoot)" }
    $dashEvtClass      = if (($evts.criticalCount + $evts.errorCount) -gt 0) { 'card-crit' } else { 'card-ok' }
    $dashEvtTotal      = [int]($evts.criticalCount + $evts.errorCount)
    $dashWuClass       = if ($wuUnknown) { 'card-warn' } elseif ($wu.pendingUpdates -gt 10) { 'card-crit' } elseif ($wu.pendingUpdates -gt 0) { 'card-warn' } else { 'card-ok' }
    $dashWuDate        = if ($wu.lastInstallDate) { $wu.lastInstallDate.Substring(0,10) } else { 'N/A' }
    $dashCpuCardClass  = cardClass $cpuStatus
    $dashRamCardClass  = cardClass $ramStatus
    $dashCpuPct        = [math]::Round($cpu.avgUsagePct, 1)
    $dashCpuPct0       = [math]::Round($cpu.avgUsagePct, 0)
    $dashRamPct        = [math]::Round($ram.usagePct, 1)
    $dashRamPct0       = [math]::Round($ram.usagePct, 0)
    $dashRamUsed       = [math]::Round($ram.usedGB, 1)
    $dashRamTotal      = [math]::Round($ram.totalGB, 1)

    $sectionDashboard = @"
<div id="s-dashboard" class="section">
  <div class="sec-title"><span class="ac">#</span> Dashboard</div>
  <div class="g3">
    <div class="card $dashCpuCardClass" style="cursor:pointer" onclick="showSection('cpu')">
      <div class="c-title">CPU Utilizzo</div>
      <div class="c-val" style="color:$cpuColor">${dashCpuPct}%</div>
      <div class="pb"><div class="pf $cpuFill" style="width:${dashCpuPct0}%"></div></div>
      <div class="c-sub">Queue: $($cpu.processorQueue) &nbsp;|&nbsp; $($cpu.logicalProcessors) LP</div>
    </div>
    <div class="card $dashRamCardClass" style="cursor:pointer" onclick="showSection('ram')">
      <div class="c-title">RAM Utilizzo</div>
      <div class="c-val" style="color:$ramColor">${dashRamPct}%</div>
      <div class="pb"><div class="pf $ramFill" style="width:${dashRamPct0}%"></div></div>
      <div class="c-sub">${dashRamUsed} / ${dashRamTotal} GB</div>
    </div>
    <div class="score-ring-wrap card card-ok" style="cursor:pointer" onclick="showSection('recs')">
      <div class="c-title" style="text-align:center">Score Globale</div>
      <div class="score-ring-val" style="color:$scoreColor">$($scores.globalScore)</div>
      <div class="score-ring-lbl">/ 100 &nbsp;|&nbsp; <span style="color:var(--red)">$($scores.critCount) crit</span> &nbsp;<span style="color:var(--yellow)">$($scores.warnCount) warn</span></div>
    </div>
  </div>
  <div class="g4">
    <div class="card $dashUptimeClass">
      <div class="c-title">Uptime</div>
      <div class="c-val" style="font-size:22px;color:var(--accent)">$($sys.uptimeDays) <span style="font-size:12px;color:var(--text2);font-weight:400">giorni</span></div>
      <div class="c-sub">Boot: $dashBootStr</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Sessioni RDP</div>
      <div class="c-val">$($sys.activeUsers)</div>
      <div class="c-sub"><span style="color:var(--yellow)">$($sys.disconnectedSessions)</span> disconnesse</div>
    </div>
    <div class="card $dashEvtClass">
      <div class="c-title">Event Log ($($evts.periodHours)h)</div>
      <div class="c-val" style="color:var(--red)">$dashEvtTotal</div>
      <div class="c-sub">$($evts.criticalCount) critici / $($evts.errorCount) errori</div>
    </div>
    <div class="card $dashWuClass">
      <div class="c-title">Windows Update</div>
      <div class="c-val" style="font-size:18px">$wuPendingTxt pending</div>
      <div class="c-sub">Ultimo: $dashWuDate</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Informazioni sistema</div>
      <table class="kv">
        $(kvr 'OS' (hs $sys.os))
        $(kvr 'Build' $sys.build)
        $(kvr 'Ruolo' "<span class='b bb'>$($meta.serverRole)</span>")
        $(kvr 'Dominio' (hs $sys.domain))
        $(kvr 'Hypervisor' (hs $sys.hypervisor))
        $(kvr 'TimeZone' (hs $sys.timeZone))
        $(kvr 'BIOS' (hs $sys.biosVersion))
        $(kvr 'RAM totale' "$([math]::Round($ram.totalGB,1)) GB")
        $(kvr 'CPU' (hs $cpu.name))
      </table>
      $certAlert
      $wuAlert
    </div>
    <div class="card">
      <div class="c-title">Top provider eventi</div>
      <table class="kv">$topProvRows</table>
    </div>
  </div>
  <div class="g3">
    <div class="card">
      <div class="c-title">Trend CPU % (ultimi $($trendDates.Count) audit)</div>
      $trendCpuChart
    </div>
    <div class="card">
      <div class="c-title">Trend RAM % (ultimi $($trendDates.Count) audit)</div>
      $trendRamChart
    </div>
    <div class="card">
      <div class="c-title">Trend Score /100 (ultimi $($trendScores.Count) audit)</div>
      $trendScoChart
    </div>
  </div>
</div>
"@

    # --- RACCOMANDAZIONI ---
    $recRows = ($recs | ForEach-Object {
        $priCls = if($_.priority -eq 'crit'){'br'}else{'by'}
        $priLbl = if($_.priority -eq 'crit'){'CRITICO'}else{'WARN'}
        "<div class='rec' data-prio='$($_.priority)'><span class='rec-p b $priCls'>$priLbl</span><div class='rec-body'><div class='rec-txt'>$(hs $_.text)</div><div class='rec-det'>$(hs $_.detail)</div><span class='rec-cat'>$(hs $_.category)</span></div></div>"
    }) -join ''

    $sectionRecs = @"
<div id="s-recs" class="section">
  <div class="sec-title"><span class="ac">!</span> Raccomandazioni &nbsp;<span style="font-size:11px;font-weight:400;color:var(--text3)">$($recs.Count) azioni</span></div>
  <div class="filter-row">
    <span style="font-size:11px;color:var(--text3)">Filtra:</span>
    <button class="filter-btn on"  data-prio="all"  onclick="filterRecs(this,'all')">Tutte ($($recs.Count))</button>
    <button class="filter-btn"     data-prio="crit" onclick="filterRecs(this,'crit')">Critici ($($scores.critCount))</button>
    <button class="filter-btn"     data-prio="warn" onclick="filterRecs(this,'warn')">Warning ($($scores.warnCount))</button>
  </div>
  $recRows
</div>
"@

    # --- CPU ---
    $queueStatus     = if($cpu.processorQueue -gt 4){'crit'}elseif($cpu.processorQueue -gt 2){'warn'}else{'ok'}
    $cpuQueueBadge   = statusBadge $queueStatus 'OK <4' 'WARN >2' 'CRITICO >4'
    $cpuQueueClass   = cardClass $queueStatus
    $cpuQueueVal     = [math]::Round($cpu.processorQueue, 1)
    $cpuCtxFmt       = [string]::Format('{0:N0}', $cpu.contextSwitchesPerSec)
    $cpuParkBadge    = boolBadge (-not $cpu.parkingEnabled) -goodIsTrue $true -lt 'Disabilitato (OK)' -lf 'Abilitato - ottimizzare'
    $cpuCoresPerUser = if ($cpu.coresPerUser) { "$($cpu.coresPerUser)" } else { 'N/A (no sessioni)' }
    $cpuHTBadge      = boolBadge $cpu.hyperThreading -lt 'Attivo' -lf 'Non attivo'
    $coreHtml = ''
    if ($cpu.perCoreUsage -and $cpu.perCoreUsage.Count -gt 0) {
        $coreHtml = ($cpu.perCoreUsage | ForEach-Object {
            $v = $_; $h = [math]::Max(4,[math]::Round($v * 0.44))
            $col = if($v -ge 85){'var(--red)'}elseif($v -ge 65){'var(--yellow)'}else{'var(--green)'}
            "<div class='core-cell'><div class='core-bar' style='height:${h}px;background:$col'></div><div class='core-lbl'>$v</div></div>"
        }) -join ''
    } else {
        $coreHtml = "<div style='color:var(--text3);font-size:11px'>Dati per core non disponibili (contatori non accessibili)</div>"
    }
    $coreSectionTitle = if ($cpu.perCoreUsage -and $cpu.perCoreUsage.Count -gt 0) { "Utilizzo per core ($($cpu.perCoreUsage.Count) core)" } else { "Utilizzo per core ($($cpu.logicalProcessors) LP)" }

    $sectionCpu = @"
<div id="s-cpu" class="section">
  <div class="sec-title"><span class="ac">%</span> CPU</div>
  <div class="g4">
    <div class="card $(cardClass $cpuStatus)">
      <div class="c-title">Utilizzo medio</div>
      <div class="c-val" style="color:$cpuColor">${dashCpuPct}%</div>
      <div class="pb"><div class="pf $cpuFill" style="width:${dashCpuPct0}%"></div></div>
    </div>
    <div class="card $cpuQueueClass">
      <div class="c-title">Processor Queue</div>
      <div class="c-val">$cpuQueueVal</div>
      <div class="c-sub">$cpuQueueBadge</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Context Switch/s</div>
      <div class="c-val" style="font-size:16px">$cpuCtxFmt</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Thread attivi</div>
      <div class="c-val" style="font-size:16px">$($cpu.activeThreads)</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Dettaglio processore</div>
      <table class="kv">
        $(kvr 'Modello' (hs $cpu.name))
        $(kvr 'Socket fisici' $cpu.physicalSockets)
        $(kvr 'Core totali' $cpu.coresTotal)
        $(kvr 'Processori logici' $cpu.logicalProcessors)
        $(kvr 'HyperThreading' $cpuHTBadge)
        $(kvr 'Clock max' "$($cpu.maxClockMhz) MHz")
        $(kvr 'L3 Cache' "$($cpu.l3CacheKB) KB")
        $(kvr 'CPU Parking' $cpuParkBadge)
        $(kvr 'Core per utente' $cpuCoresPerUser)
      </table>
    </div>
    <div class="card">
      <div class="c-title">$coreSectionTitle</div>
      <div class="core-grid">$coreHtml</div>
      <div style="margin-top:10px">
        $trendCpuChart
      </div>
    </div>
  </div>
</div>
"@

    # --- RAM ---
    $pagesStatus     = if($ram.pagesSec -gt 20){'crit'}elseif($ram.pagesSec -gt 5){'warn'}else{'ok'}
    $pagesColor      = if($ram.pagesSec -gt 20){'var(--red)'}elseif($ram.pagesSec -gt 5){'var(--yellow)'}else{'var(--green)'}
    $ramFreeRnd      = [math]::Round($ram.freeGB, 1)
    $ramAlert        = if ($ram.usagePct -ge 85) { "<div class='alert a-r'>RAM critica - $ramFreeRnd GB liberi</div>" } elseif ($ram.usagePct -ge 75) { "<div class='alert a-y'>RAM elevata - monitorare trend</div>" } else { '' }
    $ramPagesStatusBadge = statusBadge $pagesStatus 'OK <5' 'WARN >5' 'CRITICO >20'
    $ramPagesStatusClass = cardClass $pagesStatus
    $ramUsagePctRnd  = [math]::Round($ram.usagePct, 1)
    $ramUsagePct0    = [math]::Round($ram.usagePct, 0)
    $ramPagesRnd     = [math]::Round($ram.pagesSec, 1)
    $ramPFUsedGB     = [math]::Round($ram.pagefileUsedMB / 1024, 1)
    $ramPFAllocGB    = [math]::Round($ram.pagefileAllocatedMB / 1024, 1)
    $ramDPEBadge     = boolBadge $ram.disablePagingExecutive -lt 'Kernel in RAM (OK)' -lf 'Non configurato'
    $ramPerUserStr   = if ($null -ne $ram.ramPerUserGB) { "$([math]::Round($ram.ramPerUserGB, 1)) GB (min 2 GB)" } else { 'N/A (nessuna sessione attiva)' }
    $ramPoolRnd      = [math]::Round($ram.poolNonPagedMB, 0)
    $ramCommitGB     = [math]::Round($ram.committedGB, 1)
    $ramCommitLimGB  = [math]::Round($ram.commitLimitGB, 1)
    $ramStatusClass  = cardClass $ramStatus


    $userRamRows = ($ram.perUserRam | ForEach-Object {
        $pct  = [math]::Round(($_.ramGB / $ram.totalGB) * 100, 0)
        $fill = pctFill ($_.ramGB / $ram.totalGB * 100) -w 12 -c 18
        $uName= ($_.user -split '\\')[-1]
        "<div class='user-row'><div class='user-name'>$uName</div><div style='flex:1'><div class='pb' style='height:6px'><div class='pf $fill' style='width:${pct}%'></div></div></div><div class='user-stats'>$([math]::Round($_.ramGB,1)) GB / $($_.processes) proc</div></div>"
    }) -join ''

    $noUserRamMsg = if (-not $userRamRows) { "<div style='color:var(--text3);font-size:11px'>Nessuna sessione attiva</div>" } else { '' }

    $sectionRam = @"
<div id="s-ram" class="section">
  <div class="sec-title"><span class="ac">M</span> Memoria RAM</div>
  <div class="g4">
    <div class="card $ramStatusClass">
      <div class="c-title">Utilizzo %</div>
      <div class="c-val" style="color:$ramColor">${ramUsagePctRnd}%</div>
      <div class="pb"><div class="pf $ramFill" style="width:${ramUsagePct0}%"></div></div>
    </div>
    <div class="card $ramStatusClass">
      <div class="c-title">RAM libera</div>
      <div class="c-val" style="color:$ramColor">$ramFreeRnd GB</div>
      <div class="c-sub">soglia critica &lt;4 GB</div>
    </div>
    <div class="card $ramPagesStatusClass">
      <div class="c-title">Pages/sec</div>
      <div class="c-val" style="color:$pagesColor">$ramPagesRnd</div>
      <div class="c-sub">$ramPagesStatusBadge</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">PageFile in uso</div>
      <div class="c-val">$ramPFUsedGB GB</div>
      <div class="c-sub">alloc: $ramPFAllocGB GB</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Dettaglio memoria</div>
      <table class="kv">
        $(kvr 'RAM totale' "$dashRamTotal GB")
        $(kvr 'RAM usata' "<span style='color:$ramColor'>$dashRamUsed GB</span>")
        $(kvr 'Pool NonPaged' "$ramPoolRnd MB")
        $(kvr 'Committed' "$ramCommitGB / $ramCommitLimGB GB")
        $(kvr 'Page Faults/s' $ram.pageFaultsSec)
        $(kvr 'DisablePagingExec' $ramDPEBadge)
        $(kvr 'PageFile' "$($ram.pagefileManaged) - $(hs $ram.pagefileLocation)")
        $(kvr 'RAM/utente' $ramPerUserStr)
      </table>
      $ramAlert
    </div>
    <div class="card">
      <div class="c-title">RAM per utente RDS</div>
      $userRamRows
      $noUserRamMsg
    </div>
  </div>
</div>
"@

    # --- DISCO ---
    $readLatStatus  = if($disk.readLatencyMs  -gt 20){'crit'}elseif($disk.readLatencyMs  -gt 10){'warn'}else{'ok'}
    $writeLatStatus = if($disk.writeLatencyMs -gt 20){'crit'}elseif($disk.writeLatencyMs -gt 10){'warn'}else{'ok'}
    $writeLatColor  = pctColor $disk.writeLatencyMs -w 10 -c 20
    $qDiskStatus    = if($disk.queueLength -gt 2){'crit'}elseif($disk.queueLength -gt 1){'warn'}else{'ok'}

    $volumeRows = ($disk.volumes | ForEach-Object {
        $fill  = pctFill $_.usagePct; $color = pctColor $_.usagePct
        "<div class='disk-row'><div class='disk-letter' style='color:$color'>$($_.letter)</div><div class='disk-info'><div style='font-size:11px;color:var(--text2)'>$(hs $_.label) - $($_.fsType)</div><div class='pb'><div class='pf $fill' style='width:$($_.usagePct)%'></div></div><div class='disk-szs'><span style='color:var(--text2)'>$($_.usedGB) / $($_.totalGB) GB</span><span style='color:$color'>$($_.usagePct)%</span></div></div></div>"
    }) -join ''

    $physDiskRows = ($disk.physicalDisks | ForEach-Object {
        $typeCol = if($_.type -eq 'SSD'){'var(--green)'}elseif($_.type -eq 'NVMe'){'var(--accent)'}else{'var(--text2)'}
        "<tr><td>$(hs $_.name)</td><td style='color:$typeCol'>$($_.type)</td><td>$($_.bus)</td><td>$($_.sizeGB) GB</td><td><span class='b bg'>$(hs $_.health)</span></td></tr>"
    }) -join ''

    $diskRLatClass   = cardClass $readLatStatus
    $diskRLatBadge   = statusBadge $readLatStatus 'OK <10ms' 'WARN >10ms' 'CRITICO >20ms'
    $diskWLatClass   = cardClass $writeLatStatus
    $diskWLatBadge   = statusBadge $writeLatStatus 'OK <10ms' 'WARN >10ms' 'CRITICO >20ms'
    $diskQClass      = cardClass $qDiskStatus
    $diskQBadge      = statusBadge $qDiskStatus 'OK <1' 'WARN >1' 'CRITICO >2'
    $diskNtfsBadge1  = boolBadge (-not $disk.ntfsDisableLastAccess) -lt 'Disabilitato (OK)' -lf 'Abilitato - ottimizzare'
    $diskNtfsBadge2  = boolBadge $disk.ntfsDisable8dot3 -lt 'Disabilitato (OK)' -lf 'Abilitato'

    $sectionDisk = @"
<div id="s-disk" class="section">
  <div class="sec-title"><span class="ac">D</span> Disco</div>
  <div class="g4">
    <div class="card $diskRLatClass">
      <div class="c-title">Read Latency</div>
      <div class="c-val">$($disk.readLatencyMs) ms</div>
      <div class="c-sub">$diskRLatBadge</div>
    </div>
    <div class="card $diskWLatClass">
      <div class="c-title">Write Latency</div>
      <div class="c-val" style="color:$writeLatColor">$($disk.writeLatencyMs) ms</div>
      <div class="c-sub">$diskWLatBadge</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">IOPS</div>
      <div class="c-val">$($disk.iops)</div>
    </div>
    <div class="card $diskQClass">
      <div class="c-title">Disk Queue</div>
      <div class="c-val">$($disk.queueLength)</div>
      <div class="c-sub">$diskQBadge</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Volumi logici</div>
      $volumeRows
    </div>
    <div class="card">
      <div class="c-title">Dischi fisici</div>
      <table class="dt"><thead><tr><th>Nome</th><th>Tipo</th><th>Bus</th><th>Size</th><th>Health</th></tr></thead><tbody>$physDiskRows</tbody></table>
      <div style="margin-top:12px">
        <div class="c-title">NTFS Ottimizzazioni</div>
        <table class="kv">
          $(kvr 'NtfsDisableLastAccess' $diskNtfsBadge1)
          $(kvr 'NtfsDisable8dot3' $diskNtfsBadge2)
        </table>
      </div>
    </div>
  </div>
  <div class="g2" style="margin-top:10px">
    <div class="card"><div class="c-title">Trend Read Latency ms</div>$trendDiskReadChart</div>
    <div class="card"><div class="c-title">Trend Write Latency ms</div>$trendDiskWriteChart</div>
  </div>
</div>
"@

    # --- RETE ---
    $twStatus   = if($net.timeWaitCount -ge 500){'crit'}elseif($net.timeWaitCount -ge 100){'warn'}else{'ok'}
    $cwStatus   = if($net.closeWaitCount -gt 0){'crit'}else{'ok'}
    $portsPct   = if($net.ephemeralPortsMax -gt 0){ [math]::Round($net.ephemeralPortsInUse / $net.ephemeralPortsMax * 100, 0) }else{0}
    $portStatus = if($portsPct -ge 80){'crit'}elseif($portsPct -ge 60){'warn'}else{'ok'}
    $portColor  = pctColor $portsPct

    $netTwClass     = cardClass $twStatus
    $netTwBadge     = statusBadge $twStatus 'OK <100' 'WARN >100' 'CRITICO >500'
    $netCwClass     = cardClass $cwStatus
    $netCwBadge     = statusBadge $cwStatus 'OK' 'WARN' 'Problema applicativo'
    $netPortClass   = cardClass $portStatus
    $netPortFill    = pctFill $portsPct
    $netTWDelay     = nullBadge $net.tcpTimedWaitDelay 'Default 240s - ottimizzare' "$($net.tcpTimedWaitDelay)s (OK)"
    $netPortStart   = if ($net.ephemeralPortsStart) { [int]$net.ephemeralPortsStart } else { $null }
    $netMaxPort     = if ($netPortStart) { "<span class='b bb'>$netPortStart-$($netPortStart + [int]$net.ephemeralPortsMax - 1) ($($net.ephemeralPortsMax) porte)</span>" } else { nullBadge $net.maxUserPort 'Non configurato' "$($net.maxUserPort)" }
    $netDOBadge     = if ($net.deliveryOptMode -eq 0) { "<span class='b bg'>HTTP only (OK)</span>" } else { "<span class='b by'>Valore: $($net.deliveryOptMode) - ottimizzare</span>" }

    $adapterRows = ($net.adapters | ForEach-Object {
        $ad      = $_
        $dnsStr  = ($ad.dns -join ', ')
        $ipv6B   = boolBadge $ad.ipv6Enabled -goodIsTrue $false -lt 'Abilitato - verificare' -lf 'Disabilitato (OK)'
        $rssB    = boolBadge $ad.rssEnabled -lt 'Abilitato (OK)' -lf 'Disabilitato'
        $rows    = "<tr><td style='color:var(--text2)'>IP</td><td>$($ad.ipAddress)</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>Gateway</td><td>$($ad.gateway)</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>DNS</td><td>$dnsStr</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>Link Speed</td><td>$($ad.linkSpeed)</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>MTU</td><td>$($ad.mtu)</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>IPv6</td><td>$ipv6B</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>RSS</td><td>$rssB</td></tr>"
        $rows   += "<tr><td style='color:var(--text2)'>Driver</td><td>$($ad.driverVersion) ($($ad.driverDate))</td></tr>"
        "<div style='margin-bottom:12px'><div style='font-size:11px;color:var(--accent);margin-bottom:6px;font-weight:700'>$(hs $ad.name)</div><table class='kv'>$rows</table></div>"
    }) -join ''

    $tcpStateRows = ($net.tcpStates | ForEach-Object { "<tr><td>$(hs $_.state)</td><td>$($_.count)</td></tr>" }) -join ''

    # Costruisce HTML advanced props per ogni adapter
    $adapterAdvHtml = ($net.adapters | ForEach-Object {
        $adv = $_
        $adName = hs $adv.name

        # Badge helper
        $bv = { param($v,$good,$bad)
            if ($v -eq 'N/A' -or $null -eq $v -or $v -eq '') { return "<span style='color:var(--text3)'>N/A</span>" }
            $isGood = ($v -match $good)
            $cls    = if ($isGood) { 'bg' } else { 'by' }
            return "<span class='b $cls'>$(hs $v)</span>"
        }
        $boolB = { param($v,$goodIsTrue=$true)
            $cls = if (($goodIsTrue -and $v) -or (-not $goodIsTrue -and -not $v)) { 'bg' } else { 'by' }
            $lbl = if ($v) { 'Si' } else { 'No' }
            return "<span class='b $cls'>$lbl</span>"
        }

        $rssQueueStr = if ($adv.rssQueues -gt 0) { " ($($adv.rssQueues) code)" } else { '' }
        $pmWolCls    = if ($adv.pmWolEnabled)   { 'by' } else { 'bg' }
        $pmPwrCls    = if ($adv.pmAllowTurnOff) { 'by' } else { 'bg' }
        $rssCls      = if ($adv.rssEnabled)     { 'bg' } else { 'by' }

        # Rileva se adapter virtuale con poche proprieta
        $isVirtAdap   = [bool]$adv.isVirtual
        $advPropsCnt  = [int]$adv.advPropsCount

        # Tabella tutte le proprieta avanzate
        $allAdvRows = ''
        if ($adv.advPropsAll -and $adv.advPropsAll.Count -gt 0) {
            $allAdvRows = ($adv.advPropsAll | ForEach-Object {
                "<tr><td style='color:var(--text3)'>$(hs $_.displayName)</td><td>$(hs $_.value)</td><td style='color:var(--text3);font-size:10px'>$(hs $_.keyword)</td></tr>"
            }) -join ''
        } else {
            $allAdvRows = "<tr><td colspan='3' style='color:var(--text3)'>Nessuna proprieta avanzata disponibile</td></tr>"
        }

        # Nota per adapter virtuale
        $virtualNote = if ($isVirtAdap) {
            "<div class='alert a-y' style='margin-bottom:8px;font-size:11px'>&#9432; Adapter virtuale ($(hs $adv.description)) - alcune proprieta avanzate non sono applicabili o non esposte dal driver.</div>"
        } else { '' }

        @"
<div style="margin-bottom:16px">
  <div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)">$adName &nbsp;<span style="font-size:10px;color:var(--text3);font-weight:400">$(hs $adv.description)</span></div>
  $virtualNote
  <div class="g2" style="margin-bottom:8px">
    <div>
      <div class="c-title" style="margin-bottom:6px">Ottimizzazioni chiave</div>
      <table class="kv">
        <tr><td>RSS</td><td><span class='b $rssCls'>$(if($adv.rssEnabled){"Abilitato$rssQueueStr"}else{"Disabilitato"})</span></td></tr>
        <tr><td>Interrupt Moderation</td><td>$(if($adv.intrModeration -eq "N/A"){"<span style='color:var(--text3)' title='Non esposto dal driver'>N/A</span>"}else{"<span class='b $(if($adv.intrModeration -match 'Enabled|Adaptive'){'bg'}else{'by'})'>$($adv.intrModeration)</span>"})</td></tr>
        <tr><td>Interrupt Coalescing</td><td><span style='color:var(--text2)'>$($adv.intrCoalescing)</span></td></tr>
        <tr><td>LSO v2 IPv4</td><td>$(if($adv.lsoV2IPv4 -eq "N/A"){"<span style='color:var(--text3)'>N/A</span>"}else{"<span class='b $(if($adv.lsoV2IPv4 -match 'Enabl|Attiv'){'bg'}else{'by'})'>$($adv.lsoV2IPv4)</span>"})</td></tr>
        <tr><td>LSO v2 IPv6</td><td>$(if($adv.lsoV2IPv6 -eq "N/A"){"<span style='color:var(--text3)'>N/A</span>"}else{"<span class='b $(if($adv.lsoV2IPv6 -match 'Enabl|Attiv'){'bg'}else{'by'})'>$($adv.lsoV2IPv6)</span>"})</td></tr>
        <tr><td>TCP Checksum Offload v4</td><td><span style='color:var(--text2)'>$($adv.tcpChecksumV4)</span></td></tr>
        <tr><td>UDP Checksum Offload v4</td><td><span style='color:var(--text2)'>$($adv.udpChecksumV4)</span></td></tr>
        <tr><td>IP Checksum Offload v4</td><td><span style='color:var(--text2)'>$($adv.ipChecksumV4)</span></td></tr>
        <tr><td>Flow Control</td><td><span style='color:var(--text2)'>$($adv.flowControl)</span></td></tr>
        <tr><td>Speed/Duplex</td><td><span style='color:var(--text2)'>$($adv.speedDuplex)</span></td></tr>
        <tr><td>TX Buffers</td><td><span style='color:var(--text2)'>$($adv.txBuffers)</span></td></tr>
        <tr><td>RX Buffers</td><td><span style='color:var(--text2)'>$($adv.rxBuffers)</span></td></tr>
        <tr><td>Interrupt Rate</td><td><span style='color:var(--text2)'>$($adv.intrRate)</span></td></tr>
      </table>
    </div>
    <div>
      <div class="c-title" style="margin-bottom:6px">Risparmio energia</div>
      <table class="kv">
        <tr><td>Wake on Magic Packet</td><td><span class='b $pmWolCls'>$(if($adv.pmWakeOnMagic){"Abilitato - disabilitare"}else{"Disabilitato (OK)"})</span></td></tr>
        <tr><td>Wake on Pattern</td><td><span class='b $(if($adv.pmWakeOnPattern){"by"}else{"bg"})'>$(if($adv.pmWakeOnPattern){"Abilitato - disabilitare"}else{"Disabilitato (OK)"})</span></td></tr>
        <tr><td>Consenti spegnimento NIC</td><td><span class='b $pmPwrCls'>$(if($adv.pmAllowTurnOff){"Abilitato - disabilitare"}else{"Disabilitato (OK)"})</span></td></tr>
      </table>
      <div class="c-title" style="margin-bottom:6px;margin-top:12px">Tutte le proprieta avanzate</div>
      <div class="sb" style="max-height:200px">
        <table class="dt">
          <thead><tr><th>Proprieta</th><th>Valore</th><th>Keyword</th></tr></thead>
          <tbody>$allAdvRows</tbody>
        </table>
      </div>
    </div>
  </div>
</div>
"@
    }) -join ''

    $sectionNet = @"
<div id="s-net" class="section">
  <div class="sec-title"><span class="ac">N</span> Rete</div>
  <div class="g4">
    <div class="card $netTwClass">
      <div class="c-title">TIME_WAIT</div>
      <div class="c-val">$($net.timeWaitCount)</div>
      <div class="c-sub">$netTwBadge</div>
    </div>
    <div class="card $netCwClass">
      <div class="c-title">CLOSE_WAIT</div>
      <div class="c-val">$($net.closeWaitCount)</div>
      <div class="c-sub">$netCwBadge</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">TCP Established</div>
      <div class="c-val">$($net.establishedConnections)</div>
      <div class="c-sub">totali: $($net.totalTcpConnections)</div>
    </div>
    <div class="card $netPortClass">
      <div class="c-title">Porte effimere</div>
      <div class="c-val" style="font-size:14px;color:$portColor">$($net.ephemeralPortsInUse) / $($net.ephemeralPortsMax)</div>
      <div class="pb"><div class="pf $netPortFill" style="width:${portsPct}%"></div></div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Adapter di rete</div>
      $adapterRows
    </div>
    <div class="card">
      <div class="c-title">Stato TCP</div>
      <table class="kv">$tcpStateRows</table>
      <div style="margin-top:12px">
        <div class="c-title">Ottimizzazioni TCP</div>
        <table class="kv">
          $(kvr 'TcpTimedWaitDelay' $netTWDelay)
          $(kvr 'Range porte dinamiche' $netMaxPort)
          $(kvr 'Latenza Gateway' $(if ($null -ne $net.latencyGatewayMs) { "$($net.latencyGatewayMs) ms" } else { 'N/A' }))
          $(kvr 'Latenza DNS/DC' $(if ($null -ne $net.latencyDnsMs) { "$($net.latencyDnsMs) ms" } else { 'N/A' }))
          $(kvr 'Delivery Opt.' $netDOBadge)
        </table>
      </div>
    </div>
  </div>
<div class="card" style="margin-top:10px">
  <div class="c-title">Advanced Features NIC - Proprieta e Risparmio Energia</div>
  $adapterAdvHtml
</div>
</div>
"@

    # --- PROCESSI ---
    $procCpuRows = ($procs.topByCpu | ForEach-Object {
        $col = if($_.cpuSec -gt 5000){'var(--red)'}elseif($_.cpuSec -gt 2000){'var(--yellow)'}else{'var(--text)'}
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$($_.pid)</td><td style='color:$col'>$([math]::Round($_.cpuSec,1))</td><td>$([math]::Round($_.ramMB,0))</td><td style='color:var(--text3)'>$($_.threads)</td></tr>"
    }) -join ''
    $procRamRows = ($procs.topByRam | ForEach-Object {
        $col = if($_.ramMB -gt 3000){'var(--red)'}elseif($_.ramMB -gt 1500){'var(--yellow)'}else{'var(--text)'}
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$($_.pid)</td><td style='color:$col'>$([math]::Round($_.ramMB,0))</td><td style='color:var(--text3)'>$([math]::Round($_.privateMemMB,0))</td></tr>"
    }) -join ''

    # topByHandles (nuovo); fallback su topByCpu per i JSON generati con la versione precedente
    $handleSrc = if ($procs.topByHandles) { $procs.topByHandles } else { $procs.topByCpu }
    $highHandleRows = ($handleSrc | Where-Object { $_.handles -gt 5000 } | Sort-Object { $_.handles } -Descending | Select-Object -First 10 | ForEach-Object {
        $hcol = if ($_.handles -gt 10000) { 'var(--red)' } else { 'var(--yellow)' }
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$($_.pid)</td><td style='color:$hcol;font-weight:700'>$($_.handles)</td><td style='color:var(--text3)'>$([math]::Round($_.ramMB,0)) MB</td></tr>"
    }) -join ''
    $highHandleBlock = if ($highHandleRows) {
        "<div class='card' style='margin-bottom:10px'><div class='c-title'>Processi con handle elevati (&gt;5000) - possibile leak</div><table class='dt'><thead><tr><th>Nome</th><th>PID</th><th>Handle</th><th>RAM</th></tr></thead><tbody>$highHandleRows</tbody></table></div>"
    } else { '' }

    $sectionProcs = @"
<div id="s-procs" class="section">
  <div class="sec-title"><span class="ac">P</span> Processi</div>
  $highHandleBlock
  <div class="g2">
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="c-title" style="margin:0">Top CPU</div>
        <button class="export-btn" onclick="exportTableCSV('tbl-cpu-proc','processi_cpu.csv')">Esporta CSV</button>
      </div>
      <div class="sb"><table class="dt" id="tbl-cpu-proc"><thead><tr><th>Nome</th><th>PID</th><th>CPU sec</th><th>RAM MB</th><th>Thread</th></tr></thead><tbody>$procCpuRows</tbody></table></div>
    </div>
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="c-title" style="margin:0">Top RAM</div>
        <button class="export-btn" onclick="exportTableCSV('tbl-ram-proc','processi_ram.csv')">Esporta CSV</button>
      </div>
      <table class="dt" id="tbl-ram-proc"><thead><tr><th>Nome</th><th>PID</th><th>Working MB</th><th>Private MB</th></tr></thead><tbody>$procRamRows</tbody></table>
    </div>
  </div>
</div>
"@

    # --- EVENTI (ANALISI COMPLETA) ---
    $eventRows = ($evts.recentEvents | ForEach-Object {
        $lvl    = $_.level.ToLower()
        $cls    = switch ($lvl) { 'critical'{'lc'} 'error'{'le'} default{'lw'} }
        $bcls   = switch ($lvl) { 'critical'{'br'} 'error'{'br'} default{'by'} }
        "<div class='ev-item $cls'><div class='ev-hdr'><span class='b $bcls'>$($_.level.ToUpper())</span><span style='color:var(--text2);font-size:11px'>$(hs $_.time)</span><span style='color:var(--text3);font-size:11px'>$(hs $_.provider) ID $($_.id)</span></div><div class='ev-msg'>$(hs $_.message)</div></div>"
    }) -join ''

    # Top EventID table
    $topEvtIDRows = ($evts.topEventIDs | ForEach-Object {
        $lvlCls = switch ($_.level) { 'Critical'{'br'} 'Error'{'br'} 'Warning'{'by'} default{'bb'} }
        $maxCount = if ($evts.topEventIDs.Count -gt 0) { [int]($evts.topEventIDs[0].count) } else { 1 }
        $barPct   = [int]([math]::Round($_.count / [math]::Max($maxCount,1) * 100))
        "<tr><td style='font-weight:700;color:var(--accent)'>$($_.eventId)</td><td>$(hs $_.provider)</td><td><span class='b $lvlCls'>$($_.level)</span></td><td><div style='display:flex;align-items:center;gap:8px'><div style='flex:1;background:var(--bg4);border-radius:2px;height:5px'><div style='width:${barPct}%;height:100%;background:var(--accent);border-radius:2px'></div></div><span style='font-weight:700;min-width:30px;text-align:right'>$($_.count)</span></div></td><td style='color:var(--text3);font-size:10px'>$($_.lastSeen)</td></tr>"
    }) -join ''

    # By Source table
    $bySourceRows = ($evts.bySource | ForEach-Object {
        "<tr><td>$(hs $_.source)</td><td style='text-align:center;color:var(--red)'>$($_.critical)</td><td style='text-align:center;color:var(--red)'>$($_.error)</td><td style='text-align:center;color:var(--yellow)'>$($_.warning)</td><td style='font-weight:700'>$($_.total)</td></tr>"
    }) -join ''

    # Pattern critici cards
    $patternCards = ($evts.criticalPatterns | ForEach-Object {
        $cls = if ($_.severity -eq 'crit') { 'card-crit' } else { 'card-warn' }
        $col = if ($_.severity -eq 'crit') { 'var(--red)' } else { 'var(--yellow)' }
        "<div class='card $cls'><div class='c-title'>$($_.pattern)</div><div class='c-val' style='color:$col;font-size:20px'>$($_.count)</div><div class='c-sub' style='margin-top:5px'>$(hs $_.description)</div></div>"
    }) -join ''
    if (-not $patternCards) { $patternCards = "<div style='color:var(--green);font-size:12px'>Nessun pattern critico rilevato</div>" }

    # Login failures table
    $loginRows = ($evts.loginFailures | ForEach-Object {
        "<tr><td style='color:var(--yellow)'>$(hs $_.user)</td><td style='color:var(--text3)'>$(hs $_.ip)</td><td style='color:var(--text3);font-size:10px'>$($_.time)</td></tr>"
    }) -join ''
    $loginBlock = if ($loginRows) {
        "<div class='card' style='margin-top:10px'><div class='c-title'>Login falliti recenti (EventID 4625) - campione 20</div><table class='dt'><thead><tr><th>Utente</th><th>IP Sorgente</th><th>Ora</th></tr></thead><tbody>$loginRows</tbody></table></div>"
    } else { '' }

    # Heatmap oraria (CSS bars)
    $timelineHtml = ''
    if ($evts.hourlyTimeline -and $evts.hourlyTimeline.Count -gt 0) {
        $maxH = ($evts.hourlyTimeline | ForEach-Object { $_.critical + $_.error + $_.warning } | Measure-Object -Maximum).Maximum
        if ($maxH -le 0) { $maxH = 1 }
        $bars = ($evts.hourlyTimeline | ForEach-Object {
            $tot = $_.critical + $_.error + $_.warning
            $h   = [int]([math]::Max(2, ($tot / $maxH) * 50))
            $col = if ($_.critical -gt 0) { 'var(--red)' } elseif ($_.error -gt 0) { 'var(--red)' } elseif ($_.warning -gt 0) { 'var(--yellow)' } else { 'var(--bg4)' }
            $lbl = try { ([datetime]$_.hour).ToString('HH') } catch { '' }
            "<div style='display:flex;flex-direction:column;align-items:center;flex:1'><div style='height:${h}px;width:100%;background:$col;border-radius:2px 2px 0 0;min-height:2px' title='$($_.hour): C=$($_.critical) E=$($_.error) W=$($_.warning)'></div><div style='font-size:8px;color:var(--text3);margin-top:2px'>$lbl</div></div>"
        }) -join ''
        $timelineHtml = "<div class='card' style='margin-bottom:10px'><div class='c-title'>Timeline oraria eventi (ultime $($evts.hourlyTimeline.Count)h) - hover per dettaglio</div><div style='display:flex;align-items:flex-end;gap:2px;height:60px;margin-top:8px'>$bars</div></div>"
    }

    $evtTotalAllClass = if (($evts.criticalCount + $evts.errorCount) -gt 0) { 'card-crit' } else { 'card-ok' }
    $evtTotalAllColor = if ($evts.criticalCount -gt 0) { 'var(--red)' } elseif ($evts.errorCount -gt 0) { 'var(--red)' } else { 'var(--yellow)' }

    # Genera event rows con data-attributes per modal e ricerca
    $eventRowsClickable = ($evts.recentEvents | ForEach-Object {
        $ev     = $_
        $lvl    = $ev.level.ToLower()
        $cls    = switch ($lvl) { 'critical'{'lc'} 'error'{'le'} default{'lw'} }
        $bcls   = switch ($lvl) { 'critical'{'br'} 'error'{'br'} default{'by'} }
        $lvlUp  = $ev.level.ToUpper()
        # Escape per data-attribute (sostituisce " con &quot; e newline)
        # Tutti i valori negli attributi vanno escapati (gli apostrofi nei messaggi italiani rompevano l'HTML)
        $msgEsc = (hs ($ev.message -replace "`r`n|`n",' '))
        $prvEsc = (hs $ev.provider)
        $searchable = hs ("$($ev.time) $($ev.provider) $($ev.id) $($ev.message)".ToLower())
        "<div class='ev-item $cls' onclick='openEventModal(this)' data-time='$($ev.time)' data-level='$lvlUp' data-log='$(hs $ev.log)' data-provider='$prvEsc' data-id='$($ev.id)' data-message=`"$msgEsc`" data-searchable='$searchable'><div class='ev-hdr'><span class='b $bcls'>$lvlUp</span><span style='color:var(--text2);font-size:11px'>$($ev.time)</span><span style='color:var(--text3);font-size:11px'>$(hs $ev.provider) &nbsp;ID $($ev.id)</span><span style='color:var(--text3);font-size:10px;margin-left:auto'>&#128269; clicca per dettaglio</span></div><div class='ev-msg'>$(hs ($ev.message.Substring(0,[math]::Min(200,$ev.message.Length))))</div></div>"
    }) -join ''

    $evtPeriodDays = [math]::Round($evts.periodHours / 24, 0)
    $lockoutClass  = if ($evts.lockoutCount -gt 0) { 'card-crit' } else { 'card-ok' }
    $lockoutColor  = if ($evts.lockoutCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $patternBlock  = if ($patternCards -ne "<div style='color:var(--green);font-size:12px'>Nessun pattern critico rilevato</div>") {
        "<div class='card'><div class='c-title'>Pattern critici rilevati</div><div class='g2' style='margin-bottom:0'>$patternCards</div></div>"
    } else {
        "<div class='card card-ok'><div class='c-title'>Pattern critici</div><div style='color:var(--green);font-size:12px;margin-top:6px'>Nessun pattern critico rilevato</div></div>"
    }

    $sectionEvents = @"
<div id="s-events" class="section">
  <div class="sec-title"><span class="ac">E</span> Analisi Event Log (ultimi $evtPeriodDays giorni)</div>

  <div class="g4">
    <div class="card card-crit" style="cursor:pointer" onclick="document.querySelector('.ev-level-btn[data-lv=CRITICAL]').click()">
      <div class="c-title">Critici</div>
      <div class="c-val" style="color:var(--red)">$($evts.criticalCount)</div>
    </div>
    <div class="card card-crit">
      <div class="c-title">Errori</div>
      <div class="c-val" style="color:var(--red)">$($evts.errorCount)</div>
    </div>
    <div class="card card-warn">
      <div class="c-title">Warning</div>
      <div class="c-val" style="color:var(--yellow)">$($evts.warningCount)</div>
    </div>
    <div class="card $lockoutClass">
      <div class="c-title">Lockout account</div>
      <div class="c-val" style="color:$lockoutColor">$($evts.lockoutCount)</div>
    </div>
  </div>

  <div class="g2" style="margin-bottom:10px">
    $patternBlock
    <div></div>
  </div>

  $timelineHtml

  <div class="g2">
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="c-title" style="margin:0">Top EventID per frequenza</div>
        <button class="export-btn" onclick="exportTableCSV('tbl-evtid','top_eventid.csv')">Esporta CSV</button>
      </div>
      <div class="sb"><table class="dt" id="tbl-evtid">
        <thead><tr><th>EventID</th><th>Provider</th><th>Level</th><th>Frequenza</th><th>Ultimo</th></tr></thead>
        <tbody>$topEvtIDRows</tbody>
      </table></div>
    </div>
    <div class="card">
      <div class="c-title">Riepilogo per Source</div>
      <div class="sb"><table class="dt" id="tbl-bySource">
        <thead><tr><th>Source</th><th style="text-align:center">Crit</th><th style="text-align:center">Err</th><th style="text-align:center">Warn</th><th>Tot</th></tr></thead>
        <tbody>$bySourceRows</tbody>
      </table></div>
    </div>
  </div>

  $loginBlock

  <div class="card" style="margin-top:10px">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
      <div class="c-title" style="margin:0">Ultimi $($evts.recentEvents.Count) eventi</div>
      <span id="ev-count" style="font-size:11px;color:var(--text3)">$($evts.recentEvents.Count) eventi</span>
      <input id="ev-search-box" class="ev-search" type="text" placeholder="&#128269; Cerca per provider, ID, messaggio..." oninput="filterEvents(this.value)">
      <div style="display:flex;gap:4px;margin-left:auto">
        <button class="filter-btn ev-level-btn on" data-lv="ALL"      onclick="filterEventLevel(this,'ALL')">Tutti</button>
        <button class="filter-btn ev-level-btn"    data-lv="CRITICAL" onclick="filterEventLevel(this,'CRITICAL')">Critici</button>
        <button class="filter-btn ev-level-btn"    data-lv="ERROR"    onclick="filterEventLevel(this,'ERROR')">Errori</button>
        <button class="filter-btn ev-level-btn"    data-lv="WARNING"  onclick="filterEventLevel(this,'WARNING')">Warning</button>
      </div>
    </div>
    <div class="sb" style="max-height:500px">
      $eventRowsClickable
    </div>
  </div>
</div>
"@

    # --- SERVIZI ---
    $svcRows = ($svcs.unnecessary | ForEach-Object {
        $cls = if($_.optimized){'bg'}else{'by'}; $lbl = if($_.optimized){'OK'}else{'Running - verificare'}
        "<tr><td>$(hs $_.name)</td><td>$(hs $_.display)</td><td><span class='b $cls'>$lbl</span></td><td style='color:var(--text3)'>$($_.startType)</td></tr>"
    }) -join ''
    $telRows = ($svcs.telemetry | ForEach-Object {
        $cls = if($_.optimized){'bg'}else{'by'}; $lbl = if($_.optimized){'Disabled (OK)'}else{'Running'}
        "<tr><td>$(hs $_.name)</td><td>$(hs $_.display)</td><td><span class='b $cls'>$lbl</span></td></tr>"
    }) -join ''

    $svcCEIPBadge   = boolBadge $svcs.ceipEnabled -goodIsTrue $false -lt 'Abilitato' -lf 'Disabilitato (OK)'

    $sectionServices = @"
<div id="s-services" class="section">
  <div class="sec-title"><span class="ac">S</span> Servizi</div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Servizi non necessari</div>
      <table class="dt"><thead><tr><th>Nome</th><th>Descrizione</th><th>Stato</th><th>Avvio</th></tr></thead><tbody>$svcRows</tbody></table>
    </div>
    <div class="card">
      <div class="c-title">Telemetria e diagnostica</div>
      <table class="dt"><thead><tr><th>Servizio</th><th>Descrizione</th><th>Stato</th></tr></thead><tbody>$telRows</tbody></table>
      <div style="margin-top:12px">
        <table class="kv">
          $(kvr 'Telemetry Level' (hs $svcs.telemetryLevel))
          $(kvr 'CEIP' $svcCEIPBadge)
          $(kvr 'Servizi attivi' $svcs.runningCount)
        </table>
      </div>
    </div>
  </div>
</div>
"@

    # --- RDP ---
    $nlaBadge    = boolBadge $rdp.nlaEnabled -lt 'Abilitato (OK)' -lf 'DISABILITATO'
    $secLayCls   = if ($rdp.securityLayer -eq 2) { 'bg' } else { 'by' }
    $encLvlCls   = if ($rdp.encryptionLevel -ge 3) { 'bg' } else { 'by' }
    $secLayLbl   = switch ($rdp.securityLayer) { 0{'RDP Security'} 1{'Negotiate'} 2{'SSL/TLS (OK)'} default{"$($rdp.securityLayer)"} }
    $encLvlLbl   = switch ($rdp.encryptionLevel) { 1{'Low'} 2{'Client Compatible'} 3{'High (OK)'} 4{'FIPS'} default{"$($rdp.encryptionLevel)"} }
    $rdpWallBadge= boolBadge $rdp.wallpaperEnabled -goodIsTrue $false -lt 'Abilitato - ottimizzare' -lf 'Disabilitato (OK)'
    $rdpAnimBadge= boolBadge $rdp.menuAnimations -goodIsTrue $false -lt 'Attive - ottimizzare' -lf 'Disabilitate (OK)'
    $rdpDragBadge= boolBadge $rdp.fullWindowDrag -goodIsTrue $false -lt 'Abilitato' -lf 'Disabilitato (OK)'
    $rdpFontBadge= boolBadge $rdp.fontSmoothing -lt 'Abilitato (OK)' -lf 'Disabilitato'
    $rdpAVCBadge = boolBadge $rdp.avc444Enabled -lt 'Abilitato (OK)' -lf 'Non configurato'
    $rdpHWBadge  = boolBadge $rdp.h264HWEnabled -lt 'Abilitato (OK)' -lf 'Non configurato'
    $rdpLBBadge  = boolBadge $rdp.loadBalancing -lt 'Attivo' -lf 'Non attivo'
    $rdpDrainBadge = boolBadge $rdp.drainMode -goodIsTrue $false -lt 'ATTIVO' -lf 'Off (OK)'
    $rdpSingleBadge = boolBadge $rdp.singleSessionPerUser -lt 'Abilitato (OK)' -lf 'Disabilitato'
    $rdpDelTmpBadge = boolBadge $rdp.deleteTempOnExit -lt 'Abilitato (OK)' -lf 'Non configurato'
    $rdpPerssBadge  = boolBadge $rdp.perSessionTempDir -lt 'Abilitato (OK)' -lf 'Non configurato'
    $rdpClipBadge   = boolBadge $rdp.clipboardRedirect -lt 'Abilitato' -lf 'Disabilitato'
    $rdpPrntBadge   = boolBadge $rdp.printerRedirect -lt 'Abilitato' -lf 'Disabilitato'
    $rdpDriveBadge  = boolBadge $rdp.driveRedirect -goodIsTrue $false -lt 'Abilitato - verificare' -lf 'Disabilitato (OK)'
    $rdpLPTBadge    = boolBadge $rdp.lptRedirect -goodIsTrue $false -lt 'Abilitato - ottimizzare' -lf 'Disabilitato (OK)'
    $rdpCOMBadge    = boolBadge $rdp.comRedirect -goodIsTrue $false -lt 'Abilitato - ottimizzare' -lf 'Disabilitato (OK)'
    $rdpDiscClass   = if ($rdp.disconnectedSessions -eq 0) { 'bg' } else { 'by' }
    $rdpIdleStr     = if ($rdp.maxIdleMinutes)           { "$($rdp.maxIdleMinutes)" } else { 'Non config' }
    $rdpDiscStr     = if ($rdp.maxDisconnectionMinutes)  { "$($rdp.maxDisconnectionMinutes)" } else { 'Non config' }

    $sectionRdp = @"
<div id="s-rdp" class="section">
  <div class="sec-title"><span class="ac">R</span> RDP / RDS</div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Sicurezza</div>
      <table class="kv">
        $(kvr 'NLA' $nlaBadge)
        $(kvr 'Security Layer' "<span class='b $secLayCls'>$secLayLbl</span>")
        $(kvr 'Encryption Level' "<span class='b $encLvlCls'>$encLvlLbl</span>")
        $(kvr 'SSL Certificate' (hs $rdp.sslCertificate))
        $(kvr 'Licenze RDS' (hs $rdp.licenseMode))
        $(kvr 'License Server' (hs $rdp.licenseServer))
        $(kvr 'Load Balancing' (boolBadge $rdp.loadBalancing -lt 'Attivo' -lf 'Non attivo'))
        $(kvr 'Drain Mode' (boolBadge $rdp.drainMode -goodIsTrue $false -lt 'ATTIVO' -lf 'Off (OK)'))
      </table>
    </div>
    <div class="card">
      <div class="c-title">Performance grafica</div>
      <table class="kv">
        $(kvr 'Wallpaper' (boolBadge $rdp.wallpaperEnabled -goodIsTrue $false -lt 'Abilitato - ottimizzare' -lf 'Disabilitato (OK)'))
        $(kvr 'Animazioni menu' (boolBadge $rdp.menuAnimations -goodIsTrue $false -lt 'Attive - ottimizzare' -lf 'Disabilitate (OK)'))
        $(kvr 'Full Window Drag' (boolBadge $rdp.fullWindowDrag -goodIsTrue $false -lt 'Abilitato' -lf 'Disabilitato (OK)'))
        $(kvr 'Font Smoothing' (boolBadge $rdp.fontSmoothing -lt 'Abilitato (OK)' -lf 'Disabilitato'))
        $(kvr 'AVC444 H.264' (boolBadge $rdp.avc444Enabled -lt 'Abilitato (OK)' -lf 'Non configurato'))
        $(kvr 'HW Encoding' (boolBadge $rdp.h264HWEnabled -lt 'Abilitato (OK)' -lf 'Non configurato'))
        $(kvr 'Transport' (hs $rdp.transportMode))
        $(kvr 'Color Depth' "$($rdp.colorDepthBit) bit")
      </table>
    </div>
    <div class="card">
      <div class="c-title">Sessioni e timeout</div>
      <table class="kv">
        $(kvr 'Sessioni attive' $rdp.activeSessions)
        $(kvr 'Sessioni disconnesse' "<span class='b $rdpDiscClass'>$($rdp.disconnectedSessions)</span>")
        $(kvr 'Max Idle' "$rdpIdleStr min")
        $(kvr 'Max Disconnection' "$rdpDiscStr min")
        $(kvr 'Single Session/User' $rdpSingleBadge)
        $(kvr 'DeleteTempOnExit' $rdpDelTmpBadge)
        $(kvr 'PerSessionTempDir' $rdpPerssBadge)
      </table>
    </div>
    <div class="card">
      <div class="c-title">Redirect periferiche</div>
      <table class="kv">
        $(kvr 'Clipboard' $rdpClipBadge)
        $(kvr 'Stampanti' $rdpPrntBadge)
        $(kvr 'Drive' $rdpDriveBadge)
        $(kvr 'LPT Port' $rdpLPTBadge)
        $(kvr 'COM Port' $rdpCOMBadge)
      </table>
    </div>
  </div>
</div>
"@

    # --- CERTIFICATI (NUOVO) ---
    $certRows = ($certs.items | Sort-Object daysLeft | ForEach-Object {
        $cls  = switch ($_.status) { 'expired'{'cert-exp'} 'expiring'{'cert-soon'} default{'cert-ok'} }
        $bcls = switch ($_.status) { 'expired'{'br'} 'expiring'{'by'} default{'bg'} }
        $lbl  = switch ($_.status) { 'expired'{"SCADUTO $([math]::Abs($_.daysLeft))gg fa"} 'expiring'{"$($_.daysLeft) gg"} default{'OK'} }
        $ss   = if ($_.selfSigned) { "<span class='b by' style='font-size:9px'>self-signed</span>" } else { '' }
        "<tr><td class='$cls'>$(hs ($_.subject -replace 'CN=','').Split(',')[0])</td><td style='color:var(--text3)'>$($_.store)</td><td>$($_.notAfter)</td><td><span class='b $bcls'>$lbl</span> $ss</td></tr>"
    }) -join ''

    $certExpClass  = if ($certs.expiredCount -gt 0) { 'card-crit' } else { 'card-ok' }
    $certExpColor  = if ($certs.expiredCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $certSoonClass = if ($certs.expiringCount -gt 0) { 'card-warn' } else { 'card-ok' }
    $certSoonColor = if ($certs.expiringCount -gt 0) { 'var(--yellow)' } else { 'var(--green)' }

    $sectionCerts = @"
<div id="s-certs" class="section">
  <div class="sec-title"><span class="ac">C</span> Certificati SSL/TLS</div>
  <div class="g3">
    <div class="card $certExpClass">
      <div class="c-title">Scaduti</div>
      <div class="c-val" style="color:$certExpColor">$($certs.expiredCount)</div>
    </div>
    <div class="card $certSoonClass">
      <div class="c-title">In scadenza (&lt;30gg)</div>
      <div class="c-val" style="color:$certSoonColor">$($certs.expiringCount)</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Totali</div>
      <div class="c-val">$($certs.items.Count)</div>
    </div>
  </div>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div class="c-title" style="margin:0">Certificati (LocalMachine\My + WebHosting)</div>
      <button class="export-btn" onclick="exportTableCSV('tbl-certs','certificati.csv')">Esporta CSV</button>
    </div>
    <div class="sb">
      <table class="dt" id="tbl-certs">
        <thead><tr><th>Soggetto</th><th>Store</th><th>Scadenza</th><th>Stato</th></tr></thead>
        <tbody>$certRows</tbody>
      </table>
    </div>
  </div>
</div>
"@

    # --- WINDOWS UPDATE (NUOVO) ---
    $pendingRows = ($wu.pendingList | ForEach-Object {
        $sevCls = switch ($_.severity) { 'Critical'{'br'} 'Important'{'by'} default{'bg'} }
        $kbs    = ($_.kbIds | ForEach-Object { "KB$_" }) -join ' '
        "<tr><td>$(hs $_.title)</td><td><span class='b $sevCls'>$(hs $_.severity)</span></td><td style='color:var(--text3)'>$kbs</td></tr>"
    }) -join ''

    $wuPendClass   = if ($wuUnknown) { 'card-warn' } elseif ($wu.pendingUpdates -gt 10) { 'card-crit' } elseif ($wu.pendingUpdates -gt 0) { 'card-warn' } else { 'card-ok' }
    $wuPendColor   = if ($wuUnknown) { 'var(--yellow)' } elseif ($wu.pendingUpdates -gt 10) { 'var(--red)' } elseif ($wu.pendingUpdates -gt 0) { 'var(--yellow)' } else { 'var(--green)' }
    $wuDateStr     = if ($wu.lastInstallDate) { $wu.lastInstallDate.Substring(0,10) } else { 'N/A' }
    $wuWsusClass   = if ($wu.wsusEnabled) { 'card-ok' } else { 'card-warn' }
    $wuWsusBadge   = boolBadge $wu.wsusEnabled -lt 'Configurato (OK)' -lf 'Non configurato'
    $wuPendingBlock= if ($pendingRows) { "<div class='card'><div class='c-title'>Aggiornamenti pending (prime 10)</div><table class='dt'><thead><tr><th>Titolo</th><th>Severity</th><th>KB</th></tr></thead><tbody>$pendingRows</tbody></table></div>" } else { '' }

    $wuDeferralCardClass    = if ($wu.deferralFeatureDays -eq 0 -or $wu.deferralQualityDays -eq 0) { 'card-warn' } else { 'card-ok' }
    $wuDeferralFeatureColor = if ([int]$wu.deferralFeatureDays -eq 0) { 'var(--yellow)' } else { 'var(--green)' }
    $wuDeferralFeatureText  = if ([int]$wu.deferralFeatureDays -eq 0) { 'Non config - consigliato 180gg' } else { "$($wu.deferralFeatureDays) giorni" }
    $wuDeferralQualityColor = if ([int]$wu.deferralQualityDays -eq 0) { 'var(--yellow)' } else { 'var(--green)' }
    $wuDeferralQualityText  = if ([int]$wu.deferralQualityDays -eq 0) { 'Non config - consigliato 7gg'   } else { "$($wu.deferralQualityDays) giorni" }

    $sectionWU = @"
<div id="s-wu" class="section">
  <div class="sec-title"><span class="ac">U</span> Windows Update</div>
  <div class="g4">
    <div class="card $wuPendClass">
      <div class="c-title">Aggiornamenti pending</div>
      <div class="c-val" style="color:$wuPendColor">$wuPendingTxt</div>
      <div class="c-sub">$(if ($wuUnknown) { 'ricerca non riuscita' } elseif ($wu.searchMode -eq 'cache') { 'da cache ultima scansione' } else { '' })</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Ultimo installato</div>
      <div class="c-val" style="font-size:13px;margin-top:4px">$wuDateStr</div>
    </div>
    <div class="card $wuWsusClass">
      <div class="c-title">WSUS</div>
      <div class="c-sub" style="margin-top:6px">$wuWsusBadge</div>
      <div class="c-sub" style="margin-top:4px;font-size:10px;color:var(--text3)">$(hs $wu.wsusServer)</div>
    </div>
    <div class="card $wuDeferralCardClass">
      <div class="c-title">Deferral</div>
      <div class="c-sub" style="margin-top:6px;font-size:11px">Feature: <span style="color:$wuDeferralFeatureColor">$wuDeferralFeatureText</span></div>
      <div class="c-sub" style="font-size:11px">Quality: <span style="color:$wuDeferralQualityColor">$wuDeferralQualityText</span></div>
    </div>
  </div>
  $wuPendingBlock
</div>
"@

    # --- SCHEDULED TASKS (NUOVO) ---
    $failedTaskRows = ($tasks.failed | ForEach-Object {
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$(hs $_.path)</td><td>$($_.lastRun)</td><td style='color:var(--red)'>$($_.lastResult)</td></tr>"
    }) -join ''
    $suspTaskRows = ($tasks.suspicious | ForEach-Object {
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$(hs $_.path)</td><td style='color:var(--yellow)'>$(hs $_.execute)</td><td style='color:var(--text3)'>$(hs $_.arguments)</td></tr>"
    }) -join ''

    $taskFailedClass   = if ($tasks.failed.Count -gt 0) { 'card-warn' } else { 'card-ok' }
    $taskFailedColor   = if ($tasks.failed.Count -gt 0) { 'var(--yellow)' } else { 'var(--green)' }
    $taskSuspClass     = if ($tasks.suspicious.Count -gt 0) { 'card-warn' } else { 'card-ok' }
    $taskSuspColor     = if ($tasks.suspicious.Count -gt 0) { 'var(--yellow)' } else { 'var(--green)' }
    $taskFailedBlock   = if ($failedTaskRows) { "<div class='card' style='margin-bottom:10px'><div class='c-title'>Task falliti recentemente</div><table class='dt'><thead><tr><th>Nome</th><th>Path</th><th>Ultima esecuzione</th><th>Risultato</th></tr></thead><tbody>$failedTaskRows</tbody></table></div>" } else { '' }
    $taskSuspBlock     = if ($suspTaskRows) { "<div class='card'><div class='c-title'>Task sospetti (verificare)</div><table class='dt'><thead><tr><th>Nome</th><th>Path</th><th>Eseguibile</th><th>Argomenti</th></tr></thead><tbody>$suspTaskRows</tbody></table></div>" } else { '' }

    $sectionTasks = @"
<div id="s-tasks" class="section">
  <div class="sec-title"><span class="ac">T</span> Scheduled Tasks</div>
  <div class="g3">
    <div class="card card-ok">
      <div class="c-title">Task totali</div>
      <div class="c-val">$($tasks.totalCount)</div>
    </div>
    <div class="card $taskFailedClass">
      <div class="c-title">Falliti (30gg)</div>
      <div class="c-val" style="color:$taskFailedColor">$($tasks.failed.Count)</div>
    </div>
    <div class="card $taskSuspClass">
      <div class="c-title">Sospetti (non-MS)</div>
      <div class="c-val" style="color:$taskSuspColor">$($tasks.suspicious.Count)</div>
    </div>
  </div>
  $taskFailedBlock
  $taskSuspBlock
</div>
"@

    # --- PROFILI UTENTE (NUOVO) ---
    $profRows = ($profD.profiles | ForEach-Object {
        $col   = if($_.sizeGB -gt 20){'var(--red)'}elseif($_.sizeGB -gt 10){'var(--yellow)'}else{'var(--text)'}
        $load  = if($_.loaded){"<span class='b bg'>Caricato</span>"}else{"<span class='b' style='background:var(--bg3);color:var(--text3)'>Offline</span>"}
        "<tr><td>$(hs $_.name)</td><td style='color:$col'>$($_.sizeGB) GB</td><td>$load</td><td style='color:var(--text3)'>$($_.lastWrite)</td></tr>"
    }) -join ''
    $orphanRows = ($profD.orphaned | ForEach-Object {
        "<tr><td style='color:var(--yellow)'>$(hs $_.sid)</td><td style='color:var(--text3)'>$(hs $_.path)</td></tr>"
    }) -join ''

    $profOrphanClass = if ($profD.orphaned.Count -gt 0) { 'card-warn' } else { 'card-ok' }
    $profOrphanColor = if ($profD.orphaned.Count -gt 0) { 'var(--yellow)' } else { 'var(--green)' }
    $profOrphanBlock = if ($orphanRows) { "<table class='dt'><thead><tr><th>SID</th><th>Path</th></tr></thead><tbody>$orphanRows</tbody></table>" } else { "<div style='color:var(--green);font-size:12px;margin-top:6px'>Nessun profilo orfano trovato</div>" }

    $sectionProfiles = @"
<div id="s-profiles" class="section">
  <div class="sec-title"><span class="ac">@</span> Profili Utente RDS</div>
  <div class="g3">
    <div class="card card-ok">
      <div class="c-title">Profili totali</div>
      <div class="c-val">$($profD.profiles.Count)</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Spazio totale profili</div>
      <div class="c-val" style="font-size:20px">$($profD.totalSizeGB) GB</div>
    </div>
    <div class="card $profOrphanClass">
      <div class="c-title">Profili orfani</div>
      <div class="c-val" style="color:$profOrphanColor">$($profD.orphaned.Count)</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="c-title" style="margin:0">Profili per dimensione</div>
        <button class="export-btn" onclick="exportTableCSV('tbl-profiles','profili.csv')">Esporta CSV</button>
      </div>
      <div class="sb"><table class="dt" id="tbl-profiles"><thead><tr><th>Utente</th><th>Dimensione</th><th>Stato</th><th>Ultimo accesso</th></tr></thead><tbody>$profRows</tbody></table></div>
    </div>
    <div class="card">
      <div class="c-title">Profili orfani (registry senza cartella)</div>
      $profOrphanBlock
    </div>
  </div>
</div>
"@

    # --- ANTIVIRUS ---
    $avAgeStatus  = if ($av.definitionAgeDays -gt 3) { 'crit' } elseif ($av.definitionAgeDays -gt 1) { 'warn' } else { 'ok' }
    $avAgeCls     = switch ($avAgeStatus) { 'ok'{'bg'} 'warn'{'by'} default{'br'} }
    $excPaths     = if ($av.exclusionPaths.Count -gt 0) { ($av.exclusionPaths | ForEach-Object { hs $_ }) -join '<br>' } else { 'Nessuna' }
    $excProcs     = if ($av.exclusionProcesses.Count -gt 0) { ($av.exclusionProcesses | ForEach-Object { hs $_ }) -join '<br>' } else { 'Nessuno' }
    $excExts      = if ($av.exclusionExtensions.Count -gt 0) { ($av.exclusionExtensions | ForEach-Object { hs $_ }) -join ', ' } else { 'Nessuna' }
    $avRTBadge    = boolBadge $av.realtimeEnabled -lt 'Attiva (OK)' -lf 'DISABILITATA'
    $avIdleBadge  = boolBadge $av.scanOnlyIfIdle -lt 'Abilitato (OK)' -lf 'Disabilitato'
    $avExclBadge  = boolBadge $av.requiredExclusionsOk -lt 'Configurate (OK)' -lf 'MANCANTI'
    $avKaspBadge  = boolBadge $av.kasperskyDetected -goodIsTrue $false -lt 'Rilevato' -lf 'Non presente'
    $avAgeLine    = "<span class='b $avAgeCls'>$($av.definitionAgeDays) giorni</span>"

    $sectionAv = @"
<div id="s-av" class="section">
  <div class="sec-title"><span class="ac">V</span> Antivirus</div>
  <div class="g2">
    <div class="card">
      <div class="c-title">$(hs $av.product)</div>
      <table class="kv">
        $(kvr 'RealTime Protection' $avRTBadge)
        $(kvr 'Definizioni' (hs $av.definitionVersion))
        $(kvr 'Eta definizioni' $avAgeLine)
        $(kvr 'CPU Load Factor' "$($av.cpuLoadFactor)%")
        $(kvr 'Scan Only If Idle' $avIdleBadge)
        $(kvr 'ASR Rules' "$($av.asrRulesCount) regole")
        $(kvr 'Esclusioni req. OK' $avExclBadge)
        $(kvr 'Kaspersky' $avKaspBadge)
      </table>
    </div>
    <div class="card">
      <div class="c-title">Esclusioni configurate</div>
      <table class="kv">
        $(kvr 'Processi' $excProcs)
        $(kvr 'Percorsi' $excPaths)
        $(kvr 'Estensioni' $excExts)
      </table>
    </div>
  </div>
</div>
"@

    # --- FIREWALL/SMB ---
    $smb1Badge     = if ($smb.smb1Enabled) { "<span class='b br'>Abilitato - INTERVENTO MANUALE</span>" } else { "<span class='b bg'>Disabilitato (OK)</span>" }
    $smb1AlertHtml = ''
    if ($smb.smb1Enabled) {
        $smb1AlertHtml = "<div class='alert a-r' style='margin-top:10px'><b>&#9888; SMB1 ABILITATO - INTERVENTO MANUALE RICHIESTO</b><br>Eseguire manualmente: <code style='background:var(--bg3);padding:2px 6px;border-radius:3px'>Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force</code><br>ATTENZIONE: verificare compatibilita con dispositivi legacy prima di disabilitare.</div>"
    }

    $sectionFw = @"
<div id="s-fw" class="section">
  <div class="sec-title"><span class="ac">F</span> Firewall / SMB</div>
  <div class="g2">
    <div class="card">
      <div class="c-title">Firewall profili</div>
      <table class="kv">
        $(kvr 'Domain Profile'  (boolBadge $fw.domainEnabled  -lt 'Abilitato (OK)' -lf 'DISABILITATO'))
        $(kvr 'Private Profile' (boolBadge $fw.privateEnabled -lt 'Abilitato (OK)' -lf 'DISABILITATO'))
        $(kvr 'Public Profile'  (boolBadge $fw.publicEnabled  -lt 'Abilitato (OK)' -lf 'DISABILITATO'))
        $(kvr 'Regole abilitate' $fw.enabledRulesCount)
      </table>
    </div>
    <div class="card">
      <div class="c-title">SMB</div>
      <table class="kv">
        $(kvr 'SMB1' $smb1Badge)
        $(kvr 'SMB2' (boolBadge $smb.smb2Enabled -lt 'Abilitato (OK)' -lf 'Disabilitato'))
        $(kvr 'Encrypt Data' (boolBadge $smb.encryptData -lt 'Abilitato (OK)' -lf 'Disabilitato'))
        $(kvr 'Require Signature' (boolBadge $smb.requireSignature -lt 'Abilitato (OK)' -lf 'Disabilitato'))
      </table>
      $smb1AlertHtml
    </div>
  </div>
</div>
"@

    # --- REGISTRY ---
    $regSysResp      = if ($null -ne $reg.systemResponsiveness) { "<span class='b bg'>$($reg.systemResponsiveness)%</span>" } else { "<span class='b by'>Default (20%)</span>" }
    $regLargeCache   = if ($null -ne $reg.largeSystemCache)     { "<span class='b bg'>$($reg.largeSystemCache)</span>"       } else { "<span class='b by'>Default</span>" }
    $regDPEBadge     = boolBadge $reg.disablePagingExecutive -lt 'Kernel in RAM (OK)' -lf 'Non configurato'
    $regNtfsLaBadge  = boolBadge (-not $reg.ntfsDisableLastAccess) -lt 'Disabilitato (OK)' -lf 'Abilitato - ottimizzare'
    $regNtfs8Badg    = boolBadge $reg.ntfsDisable8dot3 -lt 'Disabilitato (OK)' -lf 'Abilitato - ottimizzare'
    $regW32Badge     = nullBadge $reg.win32PrioritySeparation 'Default - verificare per RDS' "$($reg.win32PrioritySeparation) (configurato)"
    $regMMCSSBadge   = nullBadge $reg.mmcssGpuPriority 'Non configurato' "Valore: $($reg.mmcssGpuPriority)"
    $regTWBadge      = nullBadge $reg.tcpTimedWaitDelay 'Default 240s - ottimizzare' "$($reg.tcpTimedWaitDelay)s (OK)"
    $regMaxPortBadge = nullBadge $reg.maxUserPort 'Non impostato (ignorato da Win2008+)' "$($reg.maxUserPort) (ignorato da Win2008+)" 'bb'
    $regKABadge      = nullBadge $reg.keepAliveTime 'Default 7200000ms'

    # TcpAckFrequency per iface
    $ackIfaceRows = ''
    if ($reg.tcpAckFreqPerIface -and $reg.tcpAckFreqPerIface.Count -gt 0) {
        $ackIfaceRows = ($reg.tcpAckFreqPerIface | Where-Object { $null -ne $_.value } | ForEach-Object {
            $cls = if ($_.value -eq 1) { 'bg' } else { 'by' }
            $ifShort = $_.iface.Substring(0, [math]::Min(36, $_.iface.Length))
            "<tr><td style='color:var(--text3);font-size:10px'>$ifShort</td><td><span class='b $cls'>$($_.value)</span></td></tr>"
        }) -join ''
    }
    if (-not $ackIfaceRows) { $ackIfaceRows = "<tr><td colspan='2' style='color:var(--text3)'>Non configurato su nessuna interfaccia</td></tr>" }

    # Temp folders
    $tempRows = ''
    if ($reg.tempFolders -and $reg.tempFolders.Count -gt 0) {
        $tempRows = ($reg.tempFolders | ForEach-Object {
            $cls = if ($_.sizeGB -gt 5) { 'br' } elseif ($_.sizeGB -gt 1) { 'by' } else { 'bg' }
            "<tr><td style='color:var(--text3);font-size:10px'>$(hs $_.path)</td><td><span class='b $cls'>$($_.sizeGB) GB</span></td></tr>"
        }) -join ''
        $tempTotalCls = if ($reg.totalTempGB -gt 5) { 'var(--red)' } elseif ($reg.totalTempGB -gt 1) { 'var(--yellow)' } else { 'var(--green)' }
        $tempRows += "<tr><td style='font-weight:700'>Totale</td><td style='font-weight:700;color:$tempTotalCls'>$($reg.totalTempGB) GB</td></tr>"
    }

    $cachedLogonsBadge = if ([int]$reg.cachedLogonsCount -gt 5) { "<span class='b by'>$($reg.cachedLogonsCount) - ridurre</span>" } else { "<span class='b bg'>$($reg.cachedLogonsCount)</span>" }

    $sectionReg = @"
<div id="s-reg" class="section">
  <div class="sec-title"><span class="ac">K</span> Registry - ottimizzazioni</div>
  <div class="g2">
    <div class="card">
      <div class="c-title">TCP / Rete</div>
      <table class="kv">
        $(kvr 'TcpTimedWaitDelay' $regTWBadge)
        $(kvr 'MaxUserPort' $regMaxPortBadge)
        $(kvr 'KeepAliveTime' $regKABadge)
      </table>
      <div class="c-title" style="margin-top:12px;margin-bottom:6px">TcpAckFrequency per interfaccia (ottimale = 1)</div>
      <table class="dt"><thead><tr><th>Interfaccia</th><th>Valore</th></tr></thead><tbody>$ackIfaceRows</tbody></table>
    </div>
    <div class="card">
      <div class="c-title">Memoria / Performance</div>
      <table class="kv">
        $(kvr 'SystemResponsiveness' $regSysResp)
        $(kvr 'LargeSystemCache' $regLargeCache)
        $(kvr 'DisablePagingExecutive' $regDPEBadge)
        $(kvr 'NtfsDisableLastAccess' $regNtfsLaBadge)
        $(kvr 'NtfsDisable8dot3' $regNtfs8Badg)
        $(kvr 'Win32PrioritySeparation' $regW32Badge)
        $(kvr 'MMCSS GPU Priority' $regMMCSSBadge)
        $(kvr 'Cached Logons' $cachedLogonsBadge)
      </table>
    </div>
  </div>
  <div class="card" style="margin-top:10px">
    <div class="c-title">Cartelle temporanee</div>
    <table class="dt"><thead><tr><th>Percorso</th><th>Dimensione</th></tr></thead><tbody>$tempRows</tbody></table>
  </div>
</div>
"@

    # --- SOFTWARE ---
    $swRows = ($sw.items | ForEach-Object {
        "<tr><td>$(hs $_.name)</td><td style='color:var(--text3)'>$(hs $_.version)</td><td style='color:var(--text3)'>$(hs $_.publisher)</td></tr>"
    }) -join ''

    $sectionSw = @"
<div id="s-sw" class="section">
  <div class="sec-title"><span class="ac">&amp;</span> Software installato</div>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <span style="font-size:11.5px;color:var(--text2)">$($sw.totalCount) programmi</span>
      <button class="export-btn" onclick="exportTableCSV('tbl-sw','software.csv')">Esporta CSV</button>
    </div>
    <input class="search-box" type="text" placeholder="Cerca software..." oninput="filterSoftware(this.value)">
    <div class="sb"><table class="dt" id="tbl-sw">
      <thead><tr><th>Nome</th><th>Versione</th><th>Publisher</th></tr></thead>
      <tbody>$swRows</tbody>
    </table></div>
  </div>
</div>
"@

    # --- RIEPILOGO ESECUTIVO ---
    $execStatusWord  = if ($scores.globalScore -ge 70) { 'BUONO' } elseif ($scores.globalScore -ge 40) { 'ATTENZIONE' } else { 'CRITICO' }
    $execStatusColor = if ($scores.globalScore -ge 70) { 'var(--green)' } elseif ($scores.globalScore -ge 40) { 'var(--yellow)' } else { 'var(--red)' }
    $execLines2 = [System.Collections.Generic.List[string]]::new()
    if ($scores.cpu.status    -eq 'crit') { $execLines2.Add("CPU al <b>$($cpu.avgUsagePct)%</b> (critico)") }
    elseif ($scores.cpu.status -eq 'warn') { $execLines2.Add("CPU al <b>$($cpu.avgUsagePct)%</b> (elevato)") }
    if ($scores.ram.status    -eq 'crit') { $execLines2.Add("RAM al <b>$($ram.usagePct)%</b> - $([math]::Round($ram.freeGB,1)) GB liberi") }
    elseif ($scores.ram.status -eq 'warn') { $execLines2.Add("RAM al <b>$($ram.usagePct)%</b> (elevata)") }
    if ($smb.smb1Enabled)           { $execLines2.Add("<b>SMB1 abilitato</b> - vulnerabilita critica") }
    if (-not $rdp.nlaEnabled)       { $execLines2.Add("<b>NLA disabilitato</b> su RDP") }
    if ($certs.expiredCount  -gt 0) { $execLines2.Add("<b>$($certs.expiredCount) certificati scaduti</b>") }
    if ($certs.expiringCount -gt 0) { $execLines2.Add("<b>$($certs.expiringCount) certificati in scadenza</b> entro 30gg") }
    if ($wuUnknown)                 { $execLines2.Add("<b>Stato Windows Update sconosciuto</b> (ricerca non riuscita)") }
    elseif ($wu.pendingUpdates -gt 0) { $execLines2.Add("<b>$($wu.pendingUpdates) aggiornamenti Windows</b> pending") }
    if ($evts.criticalCount  -gt 0) { $execLines2.Add("<b>$($evts.criticalCount) eventi critici</b> in $($evts.periodHours)h") }
    if ($sys.uptimeDays      -gt 30){ $execLines2.Add("Uptime <b>$($sys.uptimeDays) giorni</b> - pianificare riavvio") }
    foreach ($cp2 in ($evts.criticalPatterns | Where-Object { $_.severity -eq 'crit' })) { $execLines2.Add("<b>$($cp2.pattern)</b>: $($cp2.count) occorrenze") }
    if ($execLines2.Count -eq 0) { $execLines2.Add("Nessuna criticita rilevata. Sistema in stato ottimale.") }
    $execBullets2   = ($execLines2 | ForEach-Object { "<div style='padding:3px 0;border-bottom:1px solid var(--border)'>&#8250; $_</div>" }) -join ''
    $execRecsCount2 = $scores.critCount + $scores.warnCount
    $execRecsSfx2   = if ($execRecsCount2 -eq 1) { 'azione richiesta' } else { 'azioni richieste' }
    $execCritClass  = if ($scores.critCount -gt 0) { 'card-crit' } else { 'card-ok' }
    $execCritColor  = if ($scores.critCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $execWarnClass  = if ($scores.warnCount -gt 0) { 'card-warn' } else { 'card-ok' }
    $execWarnColor  = if ($scores.warnCount -gt 0) { 'var(--yellow)' } else { 'var(--green)' }
    $execUptClass   = if ($sys.uptimeDays   -gt 30) { 'card-warn' } else { 'card-ok' }

    $sectionExec = @"
<div id="s-exec" class="section">
  <div class="sec-title"><span class="ac">&#9776;</span> Riepilogo Esecutivo</div>
  <div class="exec-card">
    <div class="exec-status" style="color:$execStatusColor">$execStatusWord</div>
    <div style="font-size:12px;color:var(--text2);margin-bottom:12px">
      Server: <b style="color:var(--text)">$($meta.fqdn)</b> &nbsp;|&nbsp;
      Ruolo: <b style="color:var(--text)">$($meta.serverRole)</b> &nbsp;|&nbsp;
      Audit: <b style="color:var(--text)">$($meta.auditDate)</b> &nbsp;|&nbsp;
      Score: <b style="color:$execStatusColor">$($scores.globalScore)/100</b>
    </div>
    <div class="exec-text">$execBullets2</div>
  </div>
  <div class="g4">
    <div class="card $execCritClass"><div class="c-title">Azioni critiche</div><div class="c-val" style="color:$execCritColor">$($scores.critCount)</div></div>
    <div class="card $execWarnClass"><div class="c-title">Warning</div><div class="c-val" style="color:$execWarnColor">$($scores.warnCount)</div></div>
    <div class="card card-ok"><div class="c-title">Sessioni attive</div><div class="c-val">$($sys.activeUsers)</div></div>
    <div class="card $execUptClass"><div class="c-title">Uptime</div><div class="c-val" style="font-size:18px">$($sys.uptimeDays) giorni</div></div>
  </div>
  <div style="margin-top:10px">
    <button class="export-btn" onclick="showSection('recs')">&#8594; Vai alle raccomandazioni ($execRecsCount2 $execRecsSfx2)</button>
  </div>
</div>
"@

    # --- LOGIN UTENTE RDS ---
    $loginSummaryRows = ""
    $loginDetailRows  = ""
    $loginTotalUsers  = 0
    $loginTotalEvts   = 0
    if ($loginEvts) {
        $loginTotalUsers = if ($loginEvts.summary) { @($loginEvts.summary).Count } else { 0 }
        $loginTotalEvts  = if ($null -ne $loginEvts.totalCount) { [int]$loginEvts.totalCount } else { 0 }

        $loginSummaryRows = (@($loginEvts.summary) | ForEach-Object {
            $u = $_
            $loginsVal  = if ($null -ne $u.logins)        { [int]$u.logins }        else { 0 }
            $logoffsVal = if ($null -ne $u.logoffs)       { [int]$u.logoffs }       else { 0 }
            $discosVal  = if ($null -ne $u.disconnections){ [int]$u.disconnections } else { 0 }
            $reconsVal  = if ($null -ne $u.reconnections) { [int]$u.reconnections } else { 0 }
            "<tr><td style='font-weight:700;color:var(--accent)'>$(hs $u.user)</td><td style='color:var(--green)'>$loginsVal</td><td style='color:var(--text3)'>$logoffsVal</td><td style='color:var(--yellow)'>$discosVal</td><td style='color:var(--blue)'>$reconsVal</td><td style='color:var(--text3)'>$(hs $u.sourceHosts)</td><td style='color:var(--text3)'>$(hs $u.sourceIps)</td><td style='color:var(--text3);font-size:10px'>$($u.lastSeen)</td></tr>"
        }) -join ""

        $loginDetailRows = (@($loginEvts.sessions) | Select-Object -First 100 | ForEach-Object {
            $ev = $_
            $evCol = switch ($ev.eventType) {
                "Login"            { "var(--green)"  }
                "Riconnessione"    { "var(--blue)"   }
                "Disconnessione"   { "var(--yellow)" }
                "Logoff (utente)"  { "var(--text3)"  }
                "Logoff"           { "var(--text3)"  }
                default            { "var(--text2)"  }
            }
            "<tr><td style='color:var(--text3);font-size:10px'>$($ev.time)</td><td style='color:$evCol;font-weight:600'>$(hs $ev.eventType)</td><td style='color:var(--accent)'>$(hs $ev.user)</td><td style='color:var(--text3)'>$(hs $ev.domain)</td><td style='color:var(--text2)'>$(hs $ev.logonType)</td><td style='color:var(--text3)'>$(hs $ev.sourceHost)</td><td style='color:var(--text3)'>$(hs $ev.sourceIp)</td><td style='text-align:center;color:var(--text3);font-size:10px'>$($ev.eventId)</td></tr>"
        }) -join ""
    }
    if (-not $loginSummaryRows) { $loginSummaryRows = "<tr><td colspan='8' style='color:var(--text3);text-align:center;padding:14px'>Nessun evento di accesso trovato (log Security potrebbe essere disabilitato)</td></tr>" }
    if (-not $loginDetailRows)  { $loginDetailRows  = "<tr><td colspan='8' style='color:var(--text3);text-align:center;padding:14px'>Nessun evento disponibile</td></tr>" }

    $sectionLogins = @"
<div id="s-logins" class="section">
  <div class="sec-title"><span class="ac">&#128100;</span> Accessi Utente RDS (ultimi $($d.meta.auditPeriodDays) giorni)</div>
  <div class="g4">
    <div class="card card-ok">
      <div class="c-title">Utenti distinti</div>
      <div class="c-val" style="color:var(--accent)">$loginTotalUsers</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Eventi totali</div>
      <div class="c-val">$loginTotalEvts</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Periodo</div>
      <div class="c-val" style="font-size:15px">$($d.meta.auditPeriodDays) giorni</div>
    </div>
    <div class="card card-ok">
      <div class="c-title">Log sorgente</div>
      <div class="c-val" style="font-size:13px;margin-top:4px">Security</div>
      <div class="c-sub">4624 4647 4778 4779</div>
    </div>
  </div>
  <div class="card" style="margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div class="c-title" style="margin:0">Riepilogo per utente</div>

      <button class="export-btn" onclick="exportTableCSV('tbl-login-summary','accessi_utenti.csv')">Esporta CSV</button>
    </div>
    <div class="sb">
      <table class="dt" id="tbl-login-summary">
        <thead><tr><th>Utente</th><th>Login</th><th>Logoff</th><th>Disconnessioni</th><th>Riconnessioni</th><th>Hostname/Client</th><th>IP Sorgente</th><th>Ultimo accesso</th></tr></thead>
        <tbody>$loginSummaryRows</tbody>
      </table>
    </div>
  </div>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap">
      <div class="c-title" style="margin:0">Dettaglio eventi (ultimi 100)</div>
      <input class="search-box" id="login-search" type="text" placeholder="Cerca utente, IP, host..." oninput="filterLoginEvents(this.value)" style="width:260px;margin-bottom:0">
      <button class="export-btn" onclick="exportTableCSV('tbl-login-detail','accessi_dettaglio.csv')">Esporta CSV</button>
    </div>
    <div class="sb" style="max-height:420px">
      <table class="dt" id="tbl-login-detail">
        <thead><tr><th>Data/Ora</th><th>Tipo evento</th><th>Utente</th><th>Dominio</th><th>Metodo logon</th><th>Client Host</th><th>IP Client</th><th>EventID</th></tr></thead>
        <tbody>$loginDetailRows</tbody>
      </table>
    </div>
  </div>
</div>
"@


    # --- STATO OTTIMIZZAZIONI (da optimizations_state.json) ---
    # Prima la voce di menu esisteva ma la sezione e il contatore non erano mai definiti
    $optStateObj  = Get-OptimizationState -BasePath (Split-Path $JsonPath -Parent)
    $optEntries   = @($optStateObj.fixes.Keys | ForEach-Object { $k = $_; $v = $optStateObj.fixes[$k]; [PSCustomObject]@{ id = $k; status = $v.status; appliedAt = $v.appliedAt; revertedAt = $v.revertedAt; appliedBy = $v.appliedBy; needsReboot = $v.needsReboot; notes = $v.notes } })
    $appliedFixes = @($optEntries | Where-Object { $_.status -eq 'APPLIED' })
    $optRows = ($optEntries | Sort-Object status, id | ForEach-Object {
        $cls = switch ($_.status) { 'APPLIED'{'opt-applied'} 'REVERTED'{'opt-reverted'} 'FAILED'{'opt-failed'} default{'opt-pending'} }
        $rbT = if ($_.needsReboot) { 'SI' } else { '' }
        "<tr><td>$(hs $_.id)</td><td><span class='b $cls'>$(hs $_.status)</span></td><td style='color:var(--text3)'>$(hs $_.appliedAt)</td><td style='color:var(--text3)'>$(hs $_.revertedAt)</td><td style='color:var(--text3)'>$(hs $_.appliedBy)</td><td>$rbT</td><td style='color:var(--text3);font-size:10px'>$(hs $_.notes)</td></tr>"
    }) -join ''
    if (-not $optRows) { $optRows = "<tr><td colspan='7' style='color:var(--text3);text-align:center;padding:14px'>Nessuna ottimizzazione registrata (menu 5 per applicarle)</td></tr>" }
    $sectionOptState = @"
<div id="s-optstate" class="section">
  <div class="sec-title"><span class="ac">*</span> Stato Ottimizzazioni &nbsp;<span style="font-size:11px;font-weight:400;color:var(--text3)">$($appliedFixes.Count) applicate / $($optEntries.Count) registrate</span></div>
  <div class="card">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <div class="c-title" style="margin:0">Storico fix (optimizations_state.json)</div>
      <button class="export-btn" onclick="exportTableCSV('tbl-optstate','ottimizzazioni.csv')">Esporta CSV</button>
    </div>
    <div class="sb" style="max-height:520px"><table class="dt" id="tbl-optstate">
      <thead><tr><th>Fix ID</th><th>Stato</th><th>Applicato</th><th>Revertito</th><th>Utente</th><th>Riavvio</th><th>Note</th></tr></thead>
      <tbody>$optRows</tbody>
    </table></div>
  </div>
</div>
"@

    # ---- NAV DOTS ----
    function navDot { param($s); switch($s){'crit'{'background:var(--red)'}'warn'{'background:var(--yellow)'}default{'background:var(--green)'}} }

    $navRecsStatus    = if ($scores.critCount -gt 0) { 'crit' } elseif ($scores.warnCount -gt 0) { 'warn' } else { 'ok' }
    $navTasksStatus   = if ($tasks.suspicious.Count -gt 0 -or $tasks.failed.Count -gt 5) { 'warn' } else { 'ok' }
    $navProfileStatus = if ($profD.orphaned.Count -gt 0) { 'warn' } else { 'ok' }
    $navRecsStyle    = navDot $navRecsStatus
    $navCpuStyle     = navDot $scores.cpu.status
    $navRamStyle     = navDot $scores.ram.status
    $navDiskStyle    = navDot $scores.disk.status
    $navNetStyle     = navDot $scores.net.status
    $navTasksStyle   = navDot $navTasksStatus
    $navProfStyle    = navDot $navProfileStatus
    $navRdpStyle     = navDot $scores.rdp.status
    $navFwStyle      = navDot $scores.security.status
    $navCertsStyle   = navDot $scores.certs.status
    $navWuStyle      = navDot $scores.updates.status
    $navEvtStatus    = if ($evts.criticalCount -gt 0) { 'crit' } elseif ($evts.errorCount -gt 20) { 'warn' } else { 'ok' }
    $navEvtStyle     = navDot $navEvtStatus

    $nbCpu   = if ($scores.cpu.status     -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.cpu.status     -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbRam   = if ($scores.ram.status     -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.ram.status     -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbDisk  = if ($scores.disk.status    -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.disk.status    -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbNet   = if ($scores.net.status     -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.net.status     -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbRdp   = if ($scores.rdp.status     -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.rdp.status     -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbCerts = if ($scores.certs.status   -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.certs.status   -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbWu    = if ($scores.updates.status -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.updates.status -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }
    $nbSec   = if ($scores.security.status -eq 'crit') { "<span class='nav-badge nb-r'>CRIT</span>" } elseif ($scores.security.status -eq 'warn') { "<span class='nav-badge nb-y'>WARN</span>" } else { '' }

    $sidebar = @"
<div class="sidebar">
  <div class="nav-grp">Overview</div>
  <div class="nav-item" data-sec="exec"     onclick="showSection('exec')"><span class="nav-dot" style="background:var(--accent)"></span> Riepilogo Esecutivo</div>
  <div class="nav-item active" data-sec="dashboard" onclick="showSection('dashboard')"><span class="nav-dot" style="background:var(--accent)"></span> Dashboard</div>
  <div class="nav-item" data-sec="optstate" onclick="showSection('optstate')"><span class="nav-dot" style="background:var(--blue)"></span> Stato Ottimizzazioni <span style="margin-left:auto;font-size:10px;color:var(--green)">$($appliedFixes.Count) OK</span></div>
  <div class="nav-item" data-sec="recs" onclick="showSection('recs')"><span class="nav-dot" style="$navRecsStyle"></span> Raccomandazioni <span style="margin-left:auto;font-size:10px;color:var(--red);font-weight:700">$($recs.Count)</span></div>
  <div class="nav-sep"></div>
  <div class="nav-grp">Hardware</div>
  <div class="nav-item" data-sec="cpu"   onclick="showSection('cpu')"><span class="nav-dot" style="$navCpuStyle"></span> CPU $nbCpu</div>
  <div class="nav-item" data-sec="ram"   onclick="showSection('ram')"><span class="nav-dot" style="$navRamStyle"></span> Memoria RAM $nbRam</div>
  <div class="nav-item" data-sec="disk"  onclick="showSection('disk')"><span class="nav-dot" style="$navDiskStyle"></span> Disco $nbDisk</div>
  <div class="nav-item" data-sec="net"   onclick="showSection('net')"><span class="nav-dot" style="$navNetStyle"></span> Rete $nbNet</div>
  <div class="nav-sep"></div>
  <div class="nav-grp">Sistema</div>
  <div class="nav-item" data-sec="procs"    onclick="showSection('procs')"><span class="nav-dot" style="background:var(--yellow)"></span> Processi</div>
  <div class="nav-item" data-sec="events"   onclick="showSection('events')"><span class="nav-dot" style="$navEvtStyle"></span> Event Log ($([math]::Round($evts.periodHours / 24, 0))gg)</div>
  <div class="nav-item" data-sec="services" onclick="showSection('services')"><span class="nav-dot" style="background:var(--green)"></span> Servizi</div>
  <div class="nav-item" data-sec="tasks"    onclick="showSection('tasks')"><span class="nav-dot" style="$navTasksStyle"></span> Scheduled Tasks</div>
  <div class="nav-item" data-sec="profiles" onclick="showSection('profiles')"><span class="nav-dot" style="$navProfStyle"></span> Profili Utente</div>
  <div class="nav-sep"></div>
  <div class="nav-grp">Sicurezza</div>
  <div class="nav-item" data-sec="logins" onclick="showSection('logins')"><span class="nav-dot" style="background:var(--accent)"></span> Accessi Utente RDS</div>


  <div class="nav-item" data-sec="rdp"   onclick="showSection('rdp')"><span class="nav-dot" style="$navRdpStyle"></span> RDP / RDS $nbRdp</div>
  <div class="nav-item" data-sec="av"    onclick="showSection('av')"><span class="nav-dot" style="background:var(--green)"></span> Antivirus</div>
  <div class="nav-item" data-sec="fw"    onclick="showSection('fw')"><span class="nav-dot" style="$navFwStyle"></span> Firewall / SMB $nbSec</div>
  <div class="nav-item" data-sec="certs" onclick="showSection('certs')"><span class="nav-dot" style="$navCertsStyle"></span> Certificati $nbCerts</div>
  <div class="nav-sep"></div>
  <div class="nav-grp">Config &amp; Update</div>
  <div class="nav-item" data-sec="wu"  onclick="showSection('wu')"><span class="nav-dot" style="$navWuStyle"></span> Windows Update $nbWu</div>
  <div class="nav-item" data-sec="reg" onclick="showSection('reg')"><span class="nav-dot" style="background:var(--yellow)"></span> Registry</div>
  <div class="nav-item" data-sec="sw"  onclick="showSection('sw')"><span class="nav-dot" style="background:var(--green)"></span> Software</div>
</div>
"@

    # ---- SCORE BAR ----
    $sbar = @"
<div class="sbar">
  <div class="chip active" onclick="filterChip(this,'all')"><span class="cdot g"></span><span>Tutto</span></div>
  <div class="chip" onclick="filterChip(this,'crit')"><span class="cdot r"></span><span>Critici</span><span style="color:var(--red);font-weight:700;margin-left:3px">$($scores.critCount)</span></div>
  <div class="chip" onclick="filterChip(this,'warn')"><span class="cdot y"></span><span>Warning</span><span style="color:var(--yellow);font-weight:700;margin-left:3px">$($scores.warnCount)</span></div>
  <div class="chip" onclick="filterChip(this,'ok')"><span class="cdot g"></span><span>OK</span><span style="color:var(--green);font-weight:700;margin-left:3px">$($scores.okCount)</span></div>
  <div style="margin-left:auto;font-size:11px;color:var(--text3)">v$($meta.scriptVersion) WinAuditPro TS</div>
</div>
"@

    # ---- ASSEMBLE HTML ----
    $html = @"
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Audit: $($meta.hostname) - $($meta.auditDate)</title>
  <style>$css</style>
</head>
<body>
<div class="hdr">
  <div class="hdr-l">
    <span class="srv-badge">$($meta.serverRole.ToUpper())</span>
    <span class="hostname">$($meta.fqdn)</span>
  </div>
  <div class="hdr-r">
    <span class="dot-live"></span>
    $($meta.auditDate) &nbsp;|&nbsp; Score: <span style="color:$scoreColor;font-weight:700">$($scores.globalScore)/100</span>
    &nbsp;|&nbsp; <span style="color:var(--text3)">Sezione:</span> <span id="breadcrumb-cur" style="color:var(--accent)">Dashboard</span>
    &nbsp;|&nbsp; SOLA LETTURA
  </div>
</div>
$sbar
<div id="back-top" title="Torna su">&#8679;</div>
<div class="layout">
  $sidebar
  <div class="main">
    $sectionExec
    $sectionLogins
    $sectionDashboard
    $sectionOptState
    $sectionRecs
    $sectionCpu
    $sectionRam
    $sectionDisk
    $sectionNet
    $sectionProcs
    $sectionEvents
    $sectionServices
    $sectionTasks
    $sectionProfiles
    $sectionRdp
    $sectionAv
    $sectionFw
    $sectionCerts
    $sectionWU
    $sectionReg
    $sectionSw
  </div>
</div>
<script>$js</script>

<!-- EVENT MODAL -->
<div id="ev-modal-overlay" class="ev-modal-overlay" onclick="if(event.target===this)closeEventModal()">
  <div class="ev-modal">
    <div class="ev-modal-hdr">
      <span class="ev-modal-title">Dettaglio Evento</span>
      <button class="ev-modal-close" onclick="closeEventModal()">&#10005;</button>
    </div>
    <div class="ev-modal-body">
      <div class="ev-modal-row"><span class="ev-modal-lbl">Data/Ora</span><span class="ev-modal-val" id="em-time"></span></div>
      <div class="ev-modal-row"><span class="ev-modal-lbl">Livello</span><span class="ev-modal-val" id="em-level"></span></div>
      <div class="ev-modal-row"><span class="ev-modal-lbl">Log</span><span class="ev-modal-val" id="em-log"></span></div>
      <div class="ev-modal-row"><span class="ev-modal-lbl">Provider</span><span class="ev-modal-val" id="em-provider"></span></div>
      <div class="ev-modal-row"><span class="ev-modal-lbl">Event ID</span><span class="ev-modal-val" id="em-id"></span></div>
      <div style="margin-top:10px;font-size:11px;color:var(--text3);margin-bottom:4px">Messaggio:</div>
      <div class="ev-modal-msg" id="em-msg"></div>
    </div>
  </div>
</div>

</body>
</html>
"@

    if (-not (Test-Path $ReportOutPath)) { New-Item -ItemType Directory -Path $ReportOutPath -Force | Out-Null }
    $ts      = $meta.auditDate -replace '[: ]','-' -replace '--','-'
    $outFile = Join-Path $ReportOutPath "$($meta.roleCode)_Report_$($meta.hostname)_$ts.html"
    $html | Out-File -FilePath $outFile -Encoding UTF8 -Force

    Write-Host "  [+] Report HTML: $outFile" -ForegroundColor Green
    if ($OpenBrowser) { Start-Process $outFile }
    return $outFile
}


# ==============================================================================
# OPTIMIZATION STATE ENGINE
# ==============================================================================

function Get-OptStateFile {
    param([string]$BasePath = 'C:\PerformanceAudit')
    return Join-Path $BasePath 'optimizations_state.json'
}

function Get-OptimizationState {
    param([string]$BasePath = 'C:\PerformanceAudit')
    $stateFile = Get-OptStateFile $BasePath
    $empty = [ordered]@{ version = '1.0'; lastUpdated = ''; fixes = [ordered]@{} }
    # file principale, poi la copia .bak dell'ultimo salvataggio riuscito (gli snapshot servono al revert)
    $candidates = @($stateFile, "$stateFile.bak") | Where-Object { Test-Path $_ }
    foreach ($sf in $candidates) {
        try {
            $raw = Get-Content $sf -Raw -Encoding UTF8
            $obj = $raw | ConvertFrom-Json
            if ($null -eq $obj) { throw 'file vuoto' }
            # Converti in ordered hashtable
            $state = [ordered]@{ version = $obj.version; lastUpdated = $obj.lastUpdated; fixes = [ordered]@{} }
            foreach ($prop in $obj.fixes.PSObject.Properties) {
                $f = $prop.Value
                $state.fixes[$prop.Name] = [ordered]@{
                    status      = S $f.status       # NOT_APPLIED | APPLIED | REVERTED | FAILED
                    appliedAt   = S $f.appliedAt
                    revertedAt  = S $f.revertedAt
                    appliedBy   = S $f.appliedBy
                    snapshot    = $f.snapshot        # valore/i prima dell'apply
                    currentVal  = $f.currentVal      # valore attuale letto live
                    needsReboot = [bool]$f.needsReboot
                    notes       = S $f.notes
                }
            }
            if ($sf -ne $stateFile) { Write-AuditLog "State file non leggibile: usata la copia $sf" 'WARN' }
            return $state
        } catch {
            Write-AuditLog "Errore lettura state file ${sf}: $_" 'WARN'
        }
    }
    return $empty
}

function Save-OptimizationState {
    param(
        # IDictionary e non [hashtable]: un [ordered] passato a [hashtable] viene COPIATO (le modifiche andrebbero perse)
        [Parameter(Mandatory=$true)][System.Collections.IDictionary]$State,
        [string]$BasePath = 'C:\PerformanceAudit'
    )
    $stateFile = Get-OptStateFile $BasePath
    if (-not (Test-Path $BasePath)) { New-Item -ItemType Directory -Path $BasePath -Force | Out-Null }
    $State.lastUpdated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    try {
        # scrittura atomica: il file contiene gli snapshot necessari al revert, non deve mai restare troncato
        $json = $State | ConvertTo-Json -Depth 10
        $tmp  = "$stateFile.tmp"
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($true)))
        if (Test-Path $stateFile) { [System.IO.File]::Replace($tmp, $stateFile, "$stateFile.bak", $true) }
        else { [System.IO.File]::Move($tmp, $stateFile) }
        return $true
    } catch {
        Write-Host "  [ERRORE] Impossibile salvare state file: $_" -ForegroundColor Red
        return $false
    }
}

function Set-FixState {
    param(
        [Parameter(Mandatory=$true)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory=$true)][string]$FixId,
        [Parameter(Mandatory=$true)][string]$Status,  # NOT_APPLIED|APPLIED|REVERTED|FAILED
        $Snapshot    = $null,
        $CurrentVal  = $null,
        [bool]$NeedsReboot = $false,
        [string]$Notes = ''
    )
    $now  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $user = "$env:USERDOMAIN\$env:USERNAME"
    if (-not $State.fixes.Contains($FixId)) {
        $State.fixes[$FixId] = [ordered]@{
            status='NOT_APPLIED'; appliedAt=''; revertedAt=''; appliedBy=''
            snapshot=$null; currentVal=$null; needsReboot=$false; notes=''
        }
    }
    $State.fixes[$FixId].status     = $Status
    $State.fixes[$FixId].currentVal = $CurrentVal
    $State.fixes[$FixId].needsReboot= $NeedsReboot
    $State.fixes[$FixId].notes      = $Notes
    # All'APPLY lo snapshot va sempre aggiornato (anche se $null = valore assente prima del fix),
    # altrimenti un revert successivo userebbe lo snapshot di un'applicazione precedente
    if ($Status -eq 'APPLIED' -or $null -ne $Snapshot) { $State.fixes[$FixId].snapshot = $Snapshot }
    switch ($Status) {
        'APPLIED'   { $State.fixes[$FixId].appliedAt  = $now; $State.fixes[$FixId].appliedBy = $user }
        'REVERTED'  { $State.fixes[$FixId].revertedAt = $now }
        'FAILED'    { $State.fixes[$FixId].notes      = "FAILED at $now - $Notes" }
    }
}

# ------------------------------------------------------------------------------
# Snapshot / restore generico di valori di registro (usato dai fix con chiave 'regs')
# Lo snapshot e una stringa JSON: [{p,n,exists,value,kind}]
# ------------------------------------------------------------------------------
function Get-RegSnapshot {
    param([array]$Regs)
    $items = @(foreach ($r in $Regs) {
        $exists = $false; $val = $null; $kind = $null
        try {
            $k = Get-Item -LiteralPath $r.p -EA Stop
            if (@($k.GetValueNames()) -contains $r.n) {
                $exists = $true
                $val    = $k.GetValue($r.n, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $kind   = "$($k.GetValueKind($r.n))"
            }
        } catch { }
        [ordered]@{ p = $r.p; n = $r.n; exists = $exists; value = $val; kind = $kind }
    })
    return (ConvertTo-Json -InputObject $items -Compress -Depth 4)
}

function Restore-RegSnapshot {
    param($Snapshot)
    if ([string]::IsNullOrWhiteSpace("$Snapshot")) { throw 'Snapshot assente: revert non possibile' }
    foreach ($i in @("$Snapshot" | ConvertFrom-Json)) {
        if ($i.exists) {
            if (-not (Test-Path -LiteralPath $i.p)) { New-Item -Path $i.p -Force | Out-Null }
            $kind = if ($i.kind) { $i.kind } else { 'DWord' }
            $val  = $i.value
            if ($kind -in 'MultiString') { $val = [string[]]@($val) }
            elseif ($kind -in 'Binary')  { $val = [byte[]]@($val) }
            Set-ItemProperty -LiteralPath $i.p -Name $i.n -Value $val -Type $kind -Force -EA Stop
        } else {
            Remove-ItemProperty -LiteralPath $i.p -Name $i.n -EA SilentlyContinue
        }
    }
}

# Legge i valori correnti dei registri di un fix (per la colonna "Valore attuale")
function Get-RegLiveString {
    param([array]$Regs)
    (@($Regs | ForEach-Object {
        $v = $null
        try { $k = Get-Item -LiteralPath $_.p -EA Stop; if (@($k.GetValueNames()) -contains $_.n) { $v = $k.GetValue($_.n) } } catch { }
        "$($_.n)=$(if ($null -ne $v) { $v } else { 'NC' })"
    }) -join ', ')
}

# Esegue script/snapshot/revert di un fix con ErrorActionPreference=Stop:
# con 'SilentlyContinue' globale un Set-ItemProperty fallito veniva registrato come APPLIED
function Invoke-FixBlock {
    param([scriptblock]$Block, $Argument, [switch]$HasArgument)
    $ErrorActionPreference = 'Stop'
    if ($HasArgument) { & $Block $Argument } else { & $Block }
}

function Get-FixSnapshotValue {
    param($FixDef)
    $snap = $null
    if ($FixDef.snapshot)  { $snap = Invoke-FixBlock -Block $FixDef.snapshot }
    elseif ($FixDef.regs)  { $snap = Get-RegSnapshot $FixDef.regs }
    if ($snap -is [enum])  { $snap = "$snap" }     # es. StartType servizio: salva il nome, non il numero
    return $snap
}

function Test-FixRevertable { param($FixDef) return [bool]($FixDef.revert -or $FixDef.regs) }

function Invoke-FixRevert {
    param($FixDef, $Snapshot)
    if ($Snapshot -is [string] -and $Snapshot -eq '') { $Snapshot = $null }
    if ($FixDef.revert)    { Invoke-FixBlock -Block $FixDef.revert -Argument $Snapshot -HasArgument }
    elseif ($FixDef.regs)  { Restore-RegSnapshot $Snapshot }
    else { throw "Revert non supportato per $($FixDef.id)" }
}

function Read-FixCurrentValue {
    # Legge il valore attuale di un fix dal sistema
    param([string]$FixId, $FixDef)
    try {
        if ($FixDef.reader) { return & $FixDef.reader }
    } catch { }
    return $null
}

function Take-FixSnapshot {
    # Legge e salva il valore corrente prima di applicare un fix
    param([string]$FixId, $FixDef)
    try {
        if ($FixDef.snapshot) { return & $FixDef.snapshot }
    } catch { }
    return $null
}

# ==============================================================================
# ==============================================================================
# INVOKE-OPTIMIZE  (ottimizzazioni RDS - ogni fix separato)
# ==============================================================================

function Invoke-Optimize {
    param(
        [Parameter(Mandatory=$true)][string]$JsonPath,
        [switch]$DryRun,
        [switch]$Console
    )

    if (-not (Test-Path $JsonPath)) { Write-Host "[ERRORE] File non trovato: $JsonPath" -ForegroundColor Red; return }
    try { $d = (Get-Content $JsonPath -Raw -Encoding UTF8) | ConvertFrom-Json }
    catch { Write-Host "[ERRORE] JSON invalido: $_" -ForegroundColor Red; return }

    $reg = $d.registry; $rdp = $d.rdp; $pp = $d.powerPlan; $net = $d.network
    $smb = $d.smb; $cpu = $d.cpu; $ram = $d.ram; $sys = $d.system
    $wu  = $d.windowsUpdate; $fw = $d.firewall; $tasks = $d.scheduledTasks

    $AllFixes = @(

        # ======================================================================
        # TCP / RETE
        # ======================================================================
        @{id='TCP_TIMEDWAIT'; cat='RETE'; prio='warn'; reboot=$true
          desc='TcpTimedWaitDelay = 30s (riduce accumulo connessioni TIME_WAIT)'
          risk='Server: esaurimento porte TCP con molte sessioni RDS simultanee. Utente: errori connessione, lentezza apertura applicazioni di rete.'
          check={ $null -eq $reg.tcpTimedWaitDelay -or [int]$reg.tcpTimedWaitDelay -gt 30 }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay 30 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA SilentlyContinue).TcpTimedWaitDelay }
          revert={ param($s) if ($null -ne $s) { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay ([int]$s) -Type DWord -Force } else { Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay -EA SilentlyContinue } }},

        # MaxUserPort e ignorato da Windows Server 2008 in poi: il fix non viene piu proposto,
        # resta solo per poter fare il revert di applicazioni precedenti (vedi NET_DYNAMIC_PORTS)
        @{id='TCP_MAXUSERPORT'; cat='RETE'; prio='warn'; reboot=$true
          desc='[OBSOLETO] MaxUserPort = 65534 - ignorato da Windows 2008+, mantenuto solo per il revert'
          risk='Nessun effetto su Windows Server 2008 e successivi (il range porte e gestito da netsh dynamicport).'
          check={ $false }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort 65534 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA SilentlyContinue).MaxUserPort }
          revert={ param($s) if ($null -ne $s) { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort ([int]$s) -Type DWord -Force } else { Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort -EA SilentlyContinue } }},

        @{id='NET_DYNAMIC_PORTS'; cat='RETE'; prio='warn'; reboot=$true
          desc='Range porte dinamiche TCP = 10000-65534 (55535 porte) - proposto solo se utilizzo >= 50%'
          risk='Server: con il range di default (16384 porte) molte connessioni in uscita dalle sessioni RDS possono esaurire le porte. Attenzione: verificare che nessun servizio sia in ascolto su porte tra 10000 e 49151.'
          optVal='10000-65534'
          reader={
            try { $t = Get-NetTCPSetting -SettingName Internet -EA Stop; "start=$($t.DynamicPortRangeStartPort) num=$($t.DynamicPortRangeNumberOfPorts)" }
            catch { (netsh int ipv4 show dynamicport tcp 2>$null | Where-Object { $_ -match ':\s*\d+\s*$' }) -join ' ' }
          }
          check={ [int]$net.ephemeralPortsMax -gt 0 -and [int]$net.ephemeralPortsMax -lt 55535 -and ([double]$net.ephemeralPortsInUse / [double]$net.ephemeralPortsMax) -ge 0.5 }
          script={ netsh int ipv4 set dynamicport tcp start=10000 num=55535 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "netsh exit code $LASTEXITCODE" } }
          snapshot={
            $nums = @(netsh int ipv4 show dynamicport tcp 2>$null | ForEach-Object { if ($_ -match ':\s*(\d+)\s*$') { [int]$Matches[1] } })
            if ($nums.Count -ge 2) { "$($nums[0]),$($nums[1])" } else { $null }
          }
          revert={ param($s)
            if ("$s" -notmatch '^(\d+),(\d+)$') { throw 'Snapshot range porte non valido' }
            netsh int ipv4 set dynamicport tcp start=$($Matches[1]) num=$($Matches[2]) | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "netsh exit code $LASTEXITCODE" }
          }},

        @{id='TCP_KEEPALIVE'; cat='RETE'; prio='warn'; reboot=$true
          desc='KeepAliveTime = 300000ms (5 min - rileva connessioni morte piu rapidamente)'
          risk='Server: connessioni zombie occupano handle e porte per ore (default 2h). Utente: sessioni RDS bloccate o che appaiono attive quando in realta'' sono disconnesse.'
          check={ $null -eq $reg.keepAliveTime -or [int]$reg.keepAliveTime -gt 300000 }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' KeepAliveTime 300000 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -EA SilentlyContinue).KeepAliveTime }
          revert={ param($s) if ($null -ne $s) { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' KeepAliveTime ([int]$s) -Type DWord -Force } else { Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' KeepAliveTime -EA SilentlyContinue } }},

        @{id='TCP_ACKFREQ'; cat='RETE'; prio='warn'; reboot=$true
          desc='TcpAckFrequency = 1 per ogni interfaccia (riduce latenza RDS disabilitando il Delayed ACK)'
          risk='Server: con il Delayed ACK gli ACK TCP possono essere ritardati fino a 200ms. Utente: tastiera e mouse lagosi nella sessione RDP, latenza percepita elevata anche su LAN.'
          reader={
            try {
                $ks  = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -EA Stop
                $out = @()
                foreach ($ik in $ks) {
                    $v = (Get-ItemProperty $ik.PSPath -EA SilentlyContinue).TcpAckFrequency
                    $out += $ik.PSChildName.Substring(0,[math]::Min(8,$ik.PSChildName.Length)) + '=' + $(if($null -ne $v){$v}else{'NC'})
                }
                ($out | Select-Object -First 3) -join ', '
            } catch { 'Non configurato' }
          }
          check={
            $noAck = $false
            try {
                $ks = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -EA Stop
                foreach ($k in $ks) {
                    $v = (Get-ItemProperty $k.PSPath -EA SilentlyContinue).TcpAckFrequency
                    if ($null -eq $v -or [int]$v -ne 1) { $noAck = $true; break }
                }
            } catch { $noAck = $true }
            $noAck
          }
          script={
            $ks = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -EA SilentlyContinue
            foreach ($k in $ks) { Set-ItemProperty $k.PSPath TcpAckFrequency 1 -Type DWord -Force -EA SilentlyContinue }
          }
          snapshot={
            $ifBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
            Get-RegSnapshot @(Get-ChildItem $ifBase -EA SilentlyContinue | ForEach-Object { @{ p = "$ifBase\$($_.PSChildName)"; n = 'TcpAckFrequency' } })
          }
          revert={ param($s) Restore-RegSnapshot $s }},

        @{id='NET_DELIVERY_OPT'; cat='RETE'; prio='warn'; reboot=$false
          desc='Delivery Optimization = HTTP only (disabilita P2P su server RDS)'
          risk='Server: DO in modalita'' LAN/Internet usa banda e CPU per distribuire aggiornamenti ad altri PC della rete. Inaccettabile su un Terminal Server in produzione.'
          reader={ try { $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -EA SilentlyContinue).DODownloadMode; if ($null -ne $v) { "DODownloadMode=$v" } else { 'Non configurato' } } catch { 'Non configurato' } }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p DODownloadMode 0 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; n='DODownloadMode'})},

        @{id='NIC_DISABLE_IPV6'; cat='RETE'; prio='warn'; reboot=$false
          desc='Disabilita IPv6 su tutte le NIC attive (solo se sicuramente non utilizzato)'
          risk='Microsoft sconsiglia di togliere il binding IPv6: alcuni componenti (cluster, DirectAccess, alcune app) possono smettere di funzionare. Applicare solo dopo verifica.'
          optVal='Disabilitato'
          check={ $net.adapters | Where-Object { $_.ipv6Enabled -and -not $_.isVirtual } | Select-Object -First 1 }
          script={ Get-NetAdapter -EA SilentlyContinue | ForEach-Object { Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -EA SilentlyContinue } }
          snapshot={ (@(Get-NetAdapterBinding -ComponentID ms_tcpip6 -EA SilentlyContinue | Where-Object { $_.Enabled } | ForEach-Object { $_.Name }) -join '|') }
          revert={ param($s) foreach ($n in ("$s" -split '\|' | Where-Object { $_ })) { Enable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -EA SilentlyContinue } }},

        # ======================================================================
        # NIC - POWER MANAGEMENT
        # ======================================================================
        @{id='NIC_PM_WOL_MAGIC'; cat='NIC'; prio='warn'; reboot=$false
          desc='Disabilita Wake-on-Magic-Packet su tutte le NIC (non necessario su server)'
          risk='Server: traffico broadcast anomalo puo'' mettere la NIC in stato di wake inutilmente. Basso rischio ma inutile su server sempre acceso.'
          check={ $net.adapters | Where-Object { $_.pmWakeOnMagic } | Select-Object -First 1 }
          script={
            Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
                try { Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket Disabled -EA SilentlyContinue } catch { }
            }
          }
          snapshot={ (@(Get-NetAdapterPowerManagement -EA SilentlyContinue | Where-Object { "$($_.WakeOnMagicPacket)" -eq 'Enabled' } | ForEach-Object { $_.Name }) -join '|') }
          revert={ param($s) foreach ($n in ("$s" -split '\|' | Where-Object { $_ })) { Set-NetAdapterPowerManagement -Name $n -WakeOnMagicPacket Enabled -EA SilentlyContinue } }},

        @{id='NIC_PM_WOL_PATTERN'; cat='NIC'; prio='warn'; reboot=$false
          desc='Disabilita Wake-on-Pattern su tutte le NIC'
          check={ $net.adapters | Where-Object { $_.pmWakeOnPattern } | Select-Object -First 1 }
          script={
            Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
                try { Set-NetAdapterPowerManagement -Name $_.Name -WakeOnPattern Disabled -EA SilentlyContinue } catch { }
            }
          }
          snapshot={ (@(Get-NetAdapterPowerManagement -EA SilentlyContinue | Where-Object { "$($_.WakeOnPattern)" -eq 'Enabled' } | ForEach-Object { $_.Name }) -join '|') }
          revert={ param($s) foreach ($n in ("$s" -split '\|' | Where-Object { $_ })) { Set-NetAdapterPowerManagement -Name $n -WakeOnPattern Enabled -EA SilentlyContinue } }},

        @{id='NIC_PM_ALLOW_OFF'; cat='NIC'; prio='warn'; reboot=$true
          desc='Disabilita spegnimento NIC per risparmio energia (Proprieta NIC > Risparmio energia)'
          check={ $net.adapters | Where-Object { $_.pmAllowTurnOff } | Select-Object -First 1 }
          script={
            Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
                try {
                    $adv = Get-NetAdapterAdvancedProperty -Name $_.Name -EA Stop
                    # Imposta PnPCapabilities per disabilitare power management
                    $regBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
                    $keys = Get-ChildItem $regBase -EA SilentlyContinue
                    foreach ($k in $keys) {
                        $kp = Get-ItemProperty $k.PSPath -EA SilentlyContinue
                        if ($kp -and $kp.NetCfgInstanceId -eq $_.DeviceID) {
                            Set-ItemProperty $k.PSPath PnPCapabilities 24 -Type DWord -Force -EA SilentlyContinue
                        }
                    }
                } catch { }
            }
          }
          snapshot={
            $regBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
            $ids = @(Get-NetAdapter -EA SilentlyContinue | ForEach-Object { $_.DeviceID })
            Get-RegSnapshot @(Get-ChildItem $regBase -EA SilentlyContinue | Where-Object {
                $kp = Get-ItemProperty $_.PSPath -EA SilentlyContinue; $kp -and $kp.NetCfgInstanceId -in $ids
            } | ForEach-Object { @{ p = "$regBase\$($_.PSChildName)"; n = 'PnPCapabilities' } })
          }
          revert={ param($s) Restore-RegSnapshot $s }},

        # ======================================================================
        # NIC - ADVANCED FEATURES
        # ======================================================================
        @{id='NIC_RSS_ENABLE'; cat='NIC'; prio='warn'; reboot=$false
          desc='Abilita RSS (Receive Side Scaling) su tutte le NIC - migliora distribuzione carico multi-core'
          risk='Server: senza RSS tutto il traffico di rete e'' gestito da un solo core CPU, creando un bottleneck. Con RDS e molti utenti il core satura prima. Utente: latenza di rete variabile e spike.'
          reader={ try { (@(Get-NetAdapterRss -EA Stop | ForEach-Object { $_.Name + ':' + [string]$_.Enabled })) -join ', ' } catch { 'N/A' } }
          check={ $net.adapters | Where-Object { -not $_.rssEnabled } | Select-Object -First 1 }
          script={
            Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
                try { Enable-NetAdapterRss -Name $_.Name -EA SilentlyContinue } catch { }
            }
          }
          snapshot={ (@(Get-NetAdapterRss -EA SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name }) -join '|') }
          revert={ param($s) foreach ($n in ("$s" -split '\|' | Where-Object { $_ })) { Disable-NetAdapterRss -Name $n -EA SilentlyContinue } }},

        @{id='NIC_INTERRUPT_MOD'; cat='NIC'; prio='warn'; reboot=$false
          desc='Abilita Interrupt Moderation su tutte le NIC (riduce interruzioni CPU)'
          check={
            $net.adapters | Where-Object {
                $_.intrModeration -ne 'N/A' -and $_.intrModeration -notmatch 'Enabl|Adattiv|Adaptive|Adattivo'
            } | Select-Object -First 1
          }
          script={
            Get-NetAdapter -EA SilentlyContinue | ForEach-Object {
                try {
                    # La keyword standard NDIS e '*InterruptModeration' (con asterisco): senza, il comando falliva sempre
                    if (Get-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*InterruptModeration' -EA SilentlyContinue) {
                        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*InterruptModeration' -RegistryValue 1 -EA SilentlyContinue
                    }
                } catch { }
            }
          }
          snapshot={ (@(Get-NetAdapterAdvancedProperty -RegistryKeyword '*InterruptModeration' -EA SilentlyContinue | ForEach-Object { "$($_.Name)=$(@($_.RegistryValue)[0])" }) -join '|') }
          revert={ param($s)
            foreach ($pair in ("$s" -split '\|' | Where-Object { $_ })) {
                $n, $v = $pair -split '=', 2
                Set-NetAdapterAdvancedProperty -Name $n -RegistryKeyword '*InterruptModeration' -RegistryValue $v -EA SilentlyContinue
            }
          }},

        # ======================================================================
        # MEMORIA
        # ======================================================================
        @{id='MEM_PAGING_EXEC'; cat='MEMORIA'; prio='warn'; reboot=$true
          desc='DisablePagingExecutive = 1 (mantiene codice kernel in RAM, evita paging)'
          risk='Server: il kernel viene paginato su disco causando spike di latenza. Utente: freeze improvvisi della sessione RDS, lentezza nelle operazioni di I/O kernel-intensive.'
          check={ -not $reg.disablePagingExecutive }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' DisablePagingExecutive 1 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -EA SilentlyContinue).DisablePagingExecutive }
          revert={ param($s) Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' DisablePagingExecutive ([int]$(if($null -ne $s){$s}else{0})) -Type DWord -Force }},

        @{id='MEM_LARGE_SYS_CACHE'; cat='MEMORIA'; prio='warn'; reboot=$true
          desc='LargeSystemCache = 0 (ottimizza cache per applicazioni, non filesystem - modalita server)'
          check={ $null -eq $reg.largeSystemCache -or [int]$reg.largeSystemCache -ne 0 }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache 0 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -EA SilentlyContinue).LargeSystemCache }
          revert={ param($s) Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache ([int]$(if($null -ne $s){$s}else{1})) -Type DWord -Force }},

        # ======================================================================
        # NTFS
        # ======================================================================
        @{id='NTFS_DISABLE_LASTACCESS'; cat='DISCO'; prio='warn'; reboot=$false
          desc='NtfsDisableLastAccessUpdate = 1 (disabilita aggiornamento timestamp last-access, riduce I/O)'
          risk='Server: ogni accesso a file genera una scrittura di metadata su disco (anche solo lettura). Con molti utenti RDS equivale a migliaia di write extra al secondo. Utente: nessun impatto operativo.'
          check={ $reg.ntfsDisableLastAccess }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' NtfsDisableLastAccessUpdate 1 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -EA SilentlyContinue).NtfsDisableLastAccessUpdate }
          revert={ param($s) Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' NtfsDisableLastAccessUpdate ([int]$(if($null -ne $s){$s}else{0})) -Type DWord -Force }},

        @{id='NTFS_DISABLE_8DOT3'; cat='DISCO'; prio='warn'; reboot=$false
          desc='NtfsDisable8dot3NameCreation = 1 (disabilita nomi file 8.3, riduce overhead metadata)'
          check={ -not $reg.ntfsDisable8dot3 }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' NtfsDisable8dot3NameCreation 1 -Type DWord -Force }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -EA SilentlyContinue).NtfsDisable8dot3NameCreation }
          revert={ param($s) Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' NtfsDisable8dot3NameCreation ([int]$(if($null -ne $s){$s}else{2})) -Type DWord -Force }},

        @{id='DISK_TEMP_CLEANUP'; cat='DISCO'; prio='warn'; reboot=$false
          desc='Pulizia cartelle temporanee (Windows\Temp, SoftwareDistribution\Download)'
          risk='Server: cartelle temp gonfie rallentano la scansione AV e riducono spazio disco. Utente: errori applicativi se il disco si riempie durante la sessione.'
          check={ $null -ne $reg.totalTempGB -and [double]$reg.totalTempGB -gt 1 }
          script={
            if (Test-Path "$env:SystemRoot\Temp") { Get-ChildItem "$env:SystemRoot\Temp" -Recurse -EA SilentlyContinue | Remove-Item -Force -Recurse -EA SilentlyContinue }
            # SoftwareDistribution\Download solo a Windows Update fermo (come indica Microsoft), poi i servizi ripartono come prima
            $dl = "$env:SystemRoot\SoftwareDistribution\Download"
            if (Test-Path $dl) {
                $wu = @(Get-Service wuauserv, bits -EA SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
                try {
                    $wu | Stop-Service -Force -EA Stop
                    Get-ChildItem $dl -Recurse -EA SilentlyContinue | Remove-Item -Force -Recurse -EA SilentlyContinue
                } catch { } finally { $wu | Start-Service -EA SilentlyContinue }
            }
            # Esegui anche cleanmgr in background
            try { Start-Process cleanmgr -ArgumentList '/sagerun:1' -WindowStyle Hidden -EA SilentlyContinue } catch { }
          }},

        # ======================================================================
        # POWER PLAN
        # ======================================================================
        @{id='POWER_HIGHPERF'; cat='PERFORMANCE'; prio='warn'; reboot=$false
          desc='Power Plan: imposta Prestazioni Elevate (High Performance)'
          risk='Server: il power plan Balanced riduce frequenza CPU fino al 50% sotto carico moderato. Utente: applicazioni lente all avvio, latenza variabile, jitter nelle sessioni RDP.'
          reader={ try { $out = powercfg /getactivescheme 2>$null; if ($out -match '\((.+?)\)') { $Matches[1] } else { $out } } catch { 'N/A' } }
          check={ -not $pp.isHighPerformance }
          script={ powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null; if ($LASTEXITCODE -ne 0) { throw "powercfg exit code $LASTEXITCODE (piano High Performance assente?)" } }
          snapshot={ $o = (powercfg /getactivescheme 2>$null) -join ' '; if ($o -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { $Matches[0] } else { $null } }
          revert={ param($s) if ($s -and $s -match '^[0-9a-fA-F-]{36}$') { powercfg /setactive $s | Out-Null } else { throw 'Snapshot piano energetico non valido' } }},

        @{id='CPU_NOPARKING'; cat='PERFORMANCE'; prio='warn'; reboot=$false
          desc='Disabilita CPU Core Parking sul piano attivo (CPMINCORES = 100%, tutti i core sempre disponibili)'
          risk='Server: core in parking hanno latenza wake-up di 10-30ms. Utente: picchi di lentezza quando molti utenti aprono applicazioni simultaneamente.'
          optVal='100%'
          reader={ $v = Get-CpuMinCoresAC; if ($null -ne $v) { if ($v -ge 100) { "CPMINCORES=$v% (parking disattivato)" } else { "CPMINCORES=$v% (parking attivo)" } } else { 'N/A' } }
          check={ $cpu.parkingEnabled }
          # Metodo documentato via powercfg (prima: ValueMax=0 nel registro, che limita il range dell'impostazione e non la disattiva)
          script={
            powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "powercfg exit code $LASTEXITCODE" }
            powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 100 | Out-Null
            powercfg /setactive SCHEME_CURRENT | Out-Null
          }
          snapshot={ Get-CpuMinCoresAC }
          revert={ param($s)
            if ($null -eq $s) {
                # Stato applicato con la versione precedente (tweak registro ValueMax=0): ripristina il default 100
                $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583'
                if ((Get-RegVal $base 'ValueMax') -eq 0) { Set-ItemProperty $base ValueMax 100 -Type DWord -Force }
                return
            }
            if ("$s" -notmatch '^\d+$') { throw 'Snapshot CPMINCORES non valido' }
            powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES ([int]$s) | Out-Null
            powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES ([int]$s) | Out-Null
            powercfg /setactive SCHEME_CURRENT | Out-Null
          }},

        # ======================================================================
        # PERFORMANCE - MMCSS e PRIORITA
        # ======================================================================
        @{id='MMCSS_RESPONSIVENESS'; cat='PERFORMANCE'; prio='warn'; reboot=$true
          desc='SystemResponsiveness = 10 (aumenta reattivita sessioni RDS, default 20)'
          risk='Server: MMCSS con valore 20 dedica troppo tempo a task multimedia. Utente: sessioni RDS meno reattive, specialmente nelle operazioni di input rapido.'
          reader={ try { $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -EA Stop).SystemResponsiveness; if ($null -ne $v) { 'SystemResponsiveness=' + $v } else { 'Non configurato (default 20)' } } catch { 'Non configurato' } }
          check={ $null -eq $reg.systemResponsiveness -or [int]$reg.systemResponsiveness -gt 10 }
          script={
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            Set-ItemProperty $p SystemResponsiveness 10 -Type DWord -Force
          }
          snapshot={ (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -EA SilentlyContinue).SystemResponsiveness }
          revert={ param($s) Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' SystemResponsiveness ([int]$(if($null -ne $s){$s}else{20})) -Type DWord -Force }},

        @{id='MMCSS_GPU_PRIORITY'; cat='PERFORMANCE'; prio='warn'; reboot=$true
          desc='MMCSS Games GPU Priority = 8 (priorita GPU per sessioni RDS)'
          check={ $null -eq $reg.mmcssGpuPriority -or [int]$reg.mmcssGpuPriority -ne 8 }
          script={
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p 'GPU Priority' 8 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; n='GPU Priority'})},

        @{id='MMCSS_PRIORITY'; cat='PERFORMANCE'; prio='warn'; reboot=$true
          desc='MMCSS Games CPU Priority = 6 (priorita CPU per sessioni RDS)'
          check={ $null -eq $reg.mmcssPriority -or [int]$reg.mmcssPriority -ne 6 }
          script={
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p 'Priority' 6 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; n='Priority'})},

        @{id='MMCSS_SCHEDULING'; cat='PERFORMANCE'; prio='warn'; reboot=$true
          desc='MMCSS Games Scheduling Category = High (scheduling alta priorita)'
          check={ $null -eq $reg.mmcssSchedulingCategory -or $reg.mmcssSchedulingCategory -ne 'High' }
          script={
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p 'Scheduling Category' 'High' -Type String -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'; n='Scheduling Category'})},

        @{id='WIN32_PRIORITY_SEP'; cat='PERFORMANCE'; prio='warn'; reboot=$true
          desc='Win32PrioritySeparation = 38 (0x26 - foreground boost bilanciato per RDS multi-sessione)'
          risk='Server: valore default (2) penalizza i processi foreground delle sessioni RDS. Utente: interfaccia lenta e poco reattiva, specialmente con molti utenti connessi.'
          check={ $null -eq $reg.win32PrioritySeparation -or [int]$reg.win32PrioritySeparation -ne 38 }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' Win32PrioritySeparation 38 -Type DWord -Force }
          reader={ try { $v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -EA Stop).Win32PrioritySeparation; if ($null -ne $v) { 'Win32PrioritySep=' + $v } else { 'Non configurato (default 2)' } } catch { 'Non configurato' } }
          snapshot={ (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -EA SilentlyContinue).Win32PrioritySeparation }
          revert={ param($s) Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' Win32PrioritySeparation ([int]$(if($null -ne $s){$s}else{2})) -Type DWord -Force }},

        # ======================================================================
        # RDP - SICUREZZA
        # ======================================================================
        @{id='RDP_NLA'; cat='SICUREZZA'; prio='crit'; reboot=$false
          desc='Abilita NLA (Network Level Authentication) - autenticazione prima della sessione RDP'
          risk='Server: senza NLA il server avvia una sessione RDP completa prima di autenticare, consumando RAM e CPU per ogni tentativo (inclusi attacchi brute force). Utente: nessun impatto negativo, aumenta la sicurezza.'
          check={ -not $rdp.nlaEnabled }
          script={
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1 -Type DWord -Force
            # se il valore e imposto da policy locale, va aggiornata anche quella (prevale sulla WinStation)
            $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if ($null -ne (Get-RegVal $pp 'UserAuthentication')) { Set-ItemProperty $pp UserAuthentication 1 -Type DWord -Force }
          }
          regs=@(@{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='UserAuthentication'}, @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='UserAuthentication'})},

        @{id='RDP_SSL_LAYER'; cat='SICUREZZA'; prio='warn'; reboot=$false
          desc='RDP Security Layer = 2 (SSL/TLS only, nessun fallback a RDP security)'
          risk='Server: il protocollo RDP security nativo e'' vulnerabile a MITM e attacchi di downgrade. Utente: nessun impatto con client moderni, miglior protezione dati in transito.'
          check={ [int]$rdp.securityLayer -ne 2 }
          script={
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' SecurityLayer 2 -Type DWord -Force
            # se il valore e imposto da policy locale, va aggiornata anche quella (prevale sulla WinStation)
            $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if ($null -ne (Get-RegVal $pp 'SecurityLayer')) { Set-ItemProperty $pp SecurityLayer 2 -Type DWord -Force }
          }
          regs=@(@{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='SecurityLayer'}, @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='SecurityLayer'})},

        @{id='RDP_ENCRYPT_HIGH'; cat='SICUREZZA'; prio='warn'; reboot=$false
          desc='RDP Encryption Level = 3 (High - crittografia massima)'
          check={ [int]$rdp.encryptionLevel -lt 3 }
          script={
            Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' MinEncryptionLevel 3 -Type DWord -Force
            # se il valore e imposto da policy locale, va aggiornata anche quella (prevale sulla WinStation)
            $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if ($null -ne (Get-RegVal $pp 'MinEncryptionLevel')) { Set-ItemProperty $pp MinEncryptionLevel 3 -Type DWord -Force }
          }
          regs=@(@{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='MinEncryptionLevel'}, @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='MinEncryptionLevel'})},

        # ======================================================================
        # RDP - PERFORMANCE GRAFICA
        # ======================================================================
        @{id='RDP_NO_WALLPAPER'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Disabilita wallpaper desktop remoto (riduce banda necessaria)'
          risk='Server: bitmap del wallpaper trasmessa ad ogni connessione e aggiornamento schermo. Utente: nessun impatto funzionale, solo estetico.'
          check={ $rdp.wallpaperEnabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p fNoRemoteDesktopWallpaper 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='fNoRemoteDesktopWallpaper'})},

        @{id='RDP_NO_MENU_ANIMS'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Disabilita animazioni menu RDP (riduce banda e latenza percepita)'
          check={ $rdp.menuAnimations }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p fDisableMenuAnims 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='fDisableMenuAnims'})},

        @{id='RDP_NO_FULL_DRAG'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Disabilita trascinamento finestre piene RDP (mostra solo il contorno durante drag)'
          check={ $rdp.fullWindowDrag }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p fDisableFullWindowDrag 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='fDisableFullWindowDrag'})},

        @{id='RDP_NO_CURSOR_SHADOW'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Disabilita ombra cursore RDP (piccolo risparmio banda)'
          check={ $rdp.cursorShadow }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p fDisableCursorShadow 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='fDisableCursorShadow'})},

        @{id='RDP_AVC444'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Abilita AVC444 H.264 (compressione video ottimizzata per desktop RDS)'
          check={ -not $rdp.avc444Enabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p AVC444ModePreferred 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='AVC444ModePreferred'})},

        @{id='RDP_HW_ENCODE'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Abilita Hardware H.264 Encoding (usa GPU per encoding RDS, riduce CPU)'
          check={ -not $rdp.h264HWEnabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p HardwareGraphicsAdapter 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='HardwareGraphicsAdapter'})},

        @{id='RDP_COLOR_16BIT'; cat='RDP-PERF'; prio='warn'; reboot=$false
          desc='Limita color depth RDP a 16 bit (ColorDepth=3, riduce banda rispetto a 32 bit)'
          risk='Attenzione: con profondita colore < 32 bit la modalita grafica AVC/H.264 (AVC444) puo non essere usata. Non combinare con RDP_AVC444.'
          optVal='16 bit'
          check={ [int]$rdp.colorDepthBit -gt 16 -and -not $rdp.avc444Enabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p ColorDepth 3 -Type DWord -Force   # codici policy: 2=15, 3=16, 4=24, 5=32 bit (prima era 4 = 24 bit)
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='ColorDepth'})},

        # ======================================================================
        # RDP - GESTIONE SESSIONI
        # ======================================================================
        @{id='RDP_SINGLE_SESSION'; cat='RDP-MAINT'; prio='warn'; reboot=$false
          desc='SingleSessionPerUser = 1 (un utente = una sessione, evita sessioni duplicate)'
          check={ -not $rdp.singleSessionPerUser }
          script={ Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fSingleSessionPerUser 1 -Type DWord -Force }
          regs=@(@{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'; n='fSingleSessionPerUser'})},

        @{id='RDP_DEL_TEMP_ON_EXIT'; cat='RDP-MAINT'; prio='warn'; reboot=$false
          desc='DeleteTempDirsOnExit = 1 (pulizia cartelle temp utente a fine sessione RDS)'
          check={ -not $rdp.deleteTempOnExit }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p DeleteTempDirsOnExit 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='DeleteTempDirsOnExit'})},

        @{id='RDP_PER_SESSION_TEMP'; cat='RDP-MAINT'; prio='warn'; reboot=$false
          desc='PerSessionTempDir = 1 (cartella temp separata per ogni sessione RDS)'
          check={ -not $rdp.perSessionTempDir }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p PerSessionTempDir 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='PerSessionTempDir'})},

        @{id='RDP_MAX_IDLE_60'; cat='RDP-MAINT'; prio='warn'; reboot=$false
          desc='MaxIdleTime = 60 minuti (disconnette sessioni abbandonate dopo 1 ora)'
          risk='Server: sessioni idle occupano RAM e licenze CAL indefinitamente. Utente: nessun impatto se attivo, sessione viene chiusa solo se inutilizzata.'
          check={ $null -eq $rdp.maxIdleMinutes -or [int]$rdp.maxIdleMinutes -eq 0 }
          script={
            # Policy (come da GPO): il valore sulla WinStation viene ignorato se fInheritMaxIdleTime=1 (default)
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p MaxIdleTime 3600000 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='MaxIdleTime'}, @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='MaxIdleTime'})},

        @{id='RDP_MAX_DISC_120'; cat='RDP-MAINT'; prio='warn'; reboot=$false
          desc='MaxDisconnectionTime = 120 minuti (riconnessione sessione disconnessa entro 2 ore)'
          check={ $null -eq $rdp.maxDisconnectionMinutes -or [int]$rdp.maxDisconnectionMinutes -eq 0 }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p MaxDisconnectionTime 7200000 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; n='MaxDisconnectionTime'}, @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='MaxDisconnectionTime'})},

        # ======================================================================
        # WINDOWS UPDATE - DEFERRAL
        # ======================================================================
        @{id='WU_DEFERRAL_QUALITY'; cat='AGGIORNAMENTI'; prio='warn'; reboot=$false
          desc='WU Quality Updates deferral = 7 giorni (testing prima del deploy)'
          risk='Server: aggiornamenti applicati immediatamente possono causare reboot improvvisi o regressioni durante ore lavorative. Utente: disconnessione forzata dalla sessione RDS.'
          check={ [int]$wu.deferralQualityDays -eq 0 -and -not $wu.wsusEnabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p DeferQualityUpdatesPeriodInDays 7 -Type DWord -Force
            Set-ItemProperty $p DeferQualityUpdates 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; n='DeferQualityUpdatesPeriodInDays'}, @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; n='DeferQualityUpdates'})},

        @{id='WU_DEFERRAL_FEATURE'; cat='AGGIORNAMENTI'; prio='warn'; reboot=$false
          desc='WU Feature Updates deferral = 180 giorni (evita major upgrade su server)'
          check={ [int]$wu.deferralFeatureDays -eq 0 -and -not $wu.wsusEnabled }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p DeferFeatureUpdatesPeriodInDays 180 -Type DWord -Force
            Set-ItemProperty $p DeferFeatureUpdates 1 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; n='DeferFeatureUpdatesPeriodInDays'}, @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; n='DeferFeatureUpdates'})},

        # ======================================================================
        # SICUREZZA - CACHED LOGONS
        # ======================================================================
        @{id='SEC_CACHED_LOGONS'; cat='SICUREZZA'; prio='warn'; reboot=$false
          desc='CachedLogonsCount = 2 (limita credenziali in cache su server domain-joined)'
          risk='Server: credenziali in cache in eccesso aumentano la superficie di attacco in caso di compromissione del server. Utente: nessun impatto se il dominio e'' raggiungibile.'
          check={
            $cl = $null
            try { $cl = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -EA Stop).CachedLogonsCount } catch { }
            $null -eq $cl -or $cl -gt 5
          }
          script={ Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' CachedLogonsCount '2' -Type String -Force }
          regs=@(@{p='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; n='CachedLogonsCount'})},

        # ======================================================================
        # TELEMETRIA (ogni servizio separato)
        # ======================================================================
        @{id='SVC_DIAGTRACK'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita DiagTrack (Connected User Experiences and Telemetry)'
          check={ $sv = Get-Service 'DiagTrack' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'DiagTrack' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'DiagTrack' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'DiagTrack' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'DiagTrack' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'DiagTrack' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_DMWAPPUSH'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita dmwappushservice (WAP Push Message Routing)'
          check={ $sv = Get-Service 'dmwappushservice' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'dmwappushservice' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'dmwappushservice' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'dmwappushservice' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'dmwappushservice' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'dmwappushservice' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WERSVC'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita WerSvc (Windows Error Reporting Service)'
          check={ $sv = Get-Service 'WerSvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WerSvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WerSvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WerSvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'WerSvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WerSvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_PCASVC'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita PcaSvc (Program Compatibility Assistant)'
          check={ $sv = Get-Service 'PcaSvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'PcaSvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'PcaSvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'PcaSvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'PcaSvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'PcaSvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WISVC'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita wisvc (Windows Insider Service)'
          check={ $sv = Get-Service 'wisvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'wisvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'wisvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'wisvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'wisvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'wisvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_MAPBROKER'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita MapsBroker (Downloaded Maps Manager)'
          check={ $sv = Get-Service 'MapsBroker' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'MapsBroker' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'MapsBroker' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'MapsBroker' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'MapsBroker' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'MapsBroker' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WDISERVICEHOST'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita WdiServiceHost (Diagnostic Service Host)'
          check={ $sv = Get-Service 'WdiServiceHost' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WdiServiceHost' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WdiServiceHost' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WdiServiceHost' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'WdiServiceHost' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WdiServiceHost' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WDISYSTEMHOST'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita WdiSystemHost (Diagnostic System Host)'
          check={ $sv = Get-Service 'WdiSystemHost' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WdiSystemHost' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WdiSystemHost' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WdiSystemHost' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'WdiSystemHost' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WdiSystemHost' -EA SilentlyContinue } } catch { } }},

        @{id='REG_TELEMETRY_LEVEL'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='AllowTelemetry = 0 (livello minimo di telemetria Windows)'
          check={ $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -EA SilentlyContinue).AllowTelemetry; $null -eq $v -or [int]$v -ne 0 }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p AllowTelemetry 0 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; n='AllowTelemetry'})},

        @{id='REG_CEIP_DISABLE'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='CEIPEnable = 0 (disabilita Customer Experience Improvement Program)'
          check={ $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -EA SilentlyContinue).CEIPEnable; $null -eq $v -or [int]$v -ne 0 }
          script={
            $p = 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p CEIPEnable 0 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Microsoft\SQMClient\Windows'; n='CEIPEnable'})},

        @{id='REG_CORTANA_DISABLE'; cat='TELEMETRIA'; prio='warn'; reboot=$false
          desc='Disabilita Cortana via policy (non necessaria su server)'
          check={ $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -EA SilentlyContinue).AllowCortana; $null -eq $v -or [int]$v -ne 0 }
          script={
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null }
            Set-ItemProperty $p AllowCortana 0 -Type DWord -Force
          }
          regs=@(@{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; n='AllowCortana'})},

        # ======================================================================
        # SERVIZI NON NECESSARI (ogni servizio separato)
        # ======================================================================
        @{id='SVC_WSEARCH'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita WSearch (Windows Search - indicizzazione, inutile su Terminal Server)'
          risk='Server: indicizzazione continua occupa CPU e IOPS su disco durante le ore di punta. Utente: nessun impatto se non usa la ricerca di file tramite Esplora Risorse.'
          check={ $sv = Get-Service 'WSearch' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WSearch' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WSearch' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WSearch' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'WSearch' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WSearch' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_SYSMAIN'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita SysMain (Superfetch - prefetch inutile su Terminal Server multi-utente)'
          risk='Server: con decine di utenti i pattern di accesso sono imprevedibili, Superfetch spreca RAM e IOPS cercando di precaricare dati per tutti. Utente: nessun beneficio percepibile.'
          check={ $sv = Get-Service 'SysMain' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'SysMain' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'SysMain' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'SysMain' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'SysMain' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'SysMain' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_BTHSERV'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita bthserv (Bluetooth Support Service - inutile su server)'
          check={ $sv = Get-Service 'bthserv' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'bthserv' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'bthserv' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'bthserv' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'bthserv' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'bthserv' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_AUDIOSRV'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita AudioSrv (Windows Audio - inutile se nessun audio su sessioni RDS)'
          check={ $sv = Get-Service 'AudioSrv' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'AudioSrv' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'AudioSrv' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'AudioSrv' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'AudioSrv' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'AudioSrv' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_AUDIOENDPOINT'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita AudioEndpointBuilder (Windows Audio Endpoint Builder)'
          check={ $sv = Get-Service 'AudioEndpointBuilder' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'AudioEndpointBuilder' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'AudioEndpointBuilder' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'AudioEndpointBuilder' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'AudioEndpointBuilder' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'AudioEndpointBuilder' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WPNSERVICE'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita WpnService (Windows Push Notifications - inutile su server)'
          check={ $sv = Get-Service 'WpnService' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WpnService' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WpnService' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WpnService' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'WpnService' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WpnService' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_TABLETINPUT'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita TabletInputService (Touch Keyboard and Handwriting Panel)'
          check={ $sv = Get-Service 'TabletInputService' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'TabletInputService' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'TabletInputService' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'TabletInputService' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'TabletInputService' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'TabletInputService' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_LLTDSVC'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita lltdsvc (Link-Layer Topology Discovery Mapper)'
          check={ $sv = Get-Service 'lltdsvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'lltdsvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'lltdsvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'lltdsvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'lltdsvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'lltdsvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_TRKWKS'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita TrkWks (Distributed Link Tracking Client)'
          check={ $sv = Get-Service 'TrkWks' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'TrkWks' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'TrkWks' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'TrkWks' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'TrkWks' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'TrkWks' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_CDPSVC'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita CDPSvc (Connected Devices Platform Service)'
          check={ $sv = Get-Service 'CDPSvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'CDPSvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'CDPSvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'CDPSvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'CDPSvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'CDPSvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_STISVC'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita stisvc (Windows Image Acquisition - scanner/fotocamere)'
          check={ $sv = Get-Service 'stisvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'stisvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'stisvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'stisvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Automatic' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Automatic' }; try { Set-Service 'stisvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'stisvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_XBLGAMESAVE'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita XblGameSave (Xbox Game Save - inutile su server)'
          check={ $sv = Get-Service 'XblGameSave' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'XblGameSave' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'XblGameSave' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'XblGameSave' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'XblGameSave' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'XblGameSave' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_XBOXNET'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita XboxNetApiSvc (Xbox Live Networking Service)'
          check={ $sv = Get-Service 'XboxNetApiSvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'XboxNetApiSvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'XboxNetApiSvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'XboxNetApiSvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'XboxNetApiSvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'XboxNetApiSvc' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_RETAILDEMO'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita RetailDemo (Retail Demo Experience Service)'
          check={ $sv = Get-Service 'RetailDemo' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'RetailDemo' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'RetailDemo' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'RetailDemo' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'RetailDemo' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'RetailDemo' -EA SilentlyContinue } } catch { } }},

        @{id='SVC_WMPNETWORK'; cat='SERVIZI'; prio='warn'; reboot=$false
          desc='Disabilita WMPNetworkSvc (Windows Media Player Network Sharing)'
          check={ $sv = Get-Service 'WMPNetworkSvc' -EA SilentlyContinue; $sv -and $sv.StartType -ne 'Disabled' }
          script={ Set-Service 'WMPNetworkSvc' -StartupType Disabled -EA SilentlyContinue; Stop-Service 'WMPNetworkSvc' -Force -EA SilentlyContinue }
          snapshot={ $sv = Get-Service 'WMPNetworkSvc' -EA SilentlyContinue; if ($sv) { $sv.StartType } else { 'Manual' } }
          revert={ param($s) $t = if ($s) { $s } else { 'Manual' }; try { Set-Service 'WMPNetworkSvc' -StartupType $t -EA SilentlyContinue; if ($t -ne 'Disabled') { Start-Service 'WMPNetworkSvc' -EA SilentlyContinue } } catch { } }}
        ,

        # ======================================================================
        # SCHEDULED TASKS - task falliti e sospetti
        # ======================================================================
        @{id='TASKS_DISABLE_FAILED_NONMS'; cat='TASKS'; prio='warn'; reboot=$false
          desc='Disabilita task NON-Microsoft falliti negli ultimi 30gg (evita esecuzioni inutili e log di errore)'
          check={
            $failed = @($tasks.failed | Where-Object {
                $_.path -notmatch '^\\Microsoft\\' -and $_.path -notmatch '^\\Windows\\'
            })
            $failed.Count -gt 0
          }
          script={
            $toDisable = @($tasks.failed | Where-Object {
                $_.path -notmatch '^\\Microsoft\\' -and $_.path -notmatch '^\\Windows\\'
            })
            foreach ($t in $toDisable) {
                try {
                    Disable-ScheduledTask -TaskName $t.name -TaskPath $t.path -EA SilentlyContinue | Out-Null
                    Write-AuditLog "Task disabilitato: $($t.path)$($t.name)" 'OK'
                } catch { Write-AuditLog "Errore disabilitazione task $($t.name): $_" 'WARN' }
            }
          }
          snapshot={
            # Serializza lista task con stato attuale per poter fare revert
            $toSnap = @($tasks.failed | Where-Object {
                $_.path -notmatch '^\\Microsoft\\' -and $_.path -notmatch '^\\Windows\\'
            })
            # Leggi stato live (potrebbe gia' essere diverso dal JSON)
            $snapData = @($toSnap | ForEach-Object {
                $live = Get-ScheduledTask -TaskName $_.name -TaskPath $_.path -EA SilentlyContinue
                [ordered]@{
                    name  = $_.name
                    path  = $_.path
                    state = if ($live) { "$($live.State)" } else { 'Ready' }
                }
            })
            $snapData | ConvertTo-Json -Compress -Depth 3
          }
          revert={
            param($s)
            if (-not $s) { return }
            try {
                $items = $s | ConvertFrom-Json
                foreach ($item in $items) {
                    if ($item.state -ne 'Disabled') {
                        try {
                            Enable-ScheduledTask -TaskName $item.name -TaskPath $item.path -EA SilentlyContinue | Out-Null
                            Write-AuditLog "Task riabilitato: $($item.path)$($item.name)" 'OK'
                        } catch { }
                    }
                }
            } catch { }
          }},

        @{id='TASKS_DISABLE_SUSPICIOUS'; cat='TASKS'; prio='warn'; reboot=$false
          desc='Disabilita task sospetti non-Microsoft con eseguibili esterne (potenziale rischio sicurezza)'
          risk='Server: task con eseguibili esterne non verificate possono introdurre payload malevoli o consumare risorse in background. Utente: rallentamenti imprevisti durante le sessioni.'
          check={ $tasks.suspicious.Count -gt 0 }
          script={
            foreach ($t in $tasks.suspicious) {
                try {
                    Disable-ScheduledTask -TaskName $t.name -TaskPath $t.path -EA SilentlyContinue | Out-Null
                    Write-AuditLog "Task sospetto disabilitato: $($t.path)$($t.name)" 'OK'
                } catch { Write-AuditLog "Errore disabilitazione task sospetto $($t.name): $_" 'WARN' }
            }
          }
          snapshot={
            $snapData = @($tasks.suspicious | ForEach-Object {
                $live = Get-ScheduledTask -TaskName $_.name -TaskPath $_.path -EA SilentlyContinue
                [ordered]@{
                    name  = $_.name
                    path  = $_.path
                    state = if ($live) { "$($live.State)" } else { 'Ready' }
                }
            })
            $snapData | ConvertTo-Json -Compress -Depth 3
          }
          revert={
            param($s)
            if (-not $s) { return }
            try {
                $items = $s | ConvertFrom-Json
                foreach ($item in $items) {
                    if ($item.state -ne 'Disabled') {
                        try {
                            Enable-ScheduledTask -TaskName $item.name -TaskPath $item.path -EA SilentlyContinue | Out-Null
                            Write-AuditLog "Task sospetto riabilitato: $($item.path)$($item.name)" 'OK'
                        } catch { }
                    }
                }
            } catch { }
          }}
    )

    # Carica stato persistente
    $BasePath  = Split-Path $JsonPath -Parent
    $OptState  = Get-OptimizationState -BasePath $BasePath

    # Arricchisce ogni fix con stato corrente e valore live
    foreach ($f in $AllFixes) {
        # Leggi valore corrente live tramite reader dedicato, registri o snapshot
        $liveVal = 'N/A'
        try {
            if ($f.reader) {
                $liveVal = & $f.reader
            } elseif ($f.regs) {
                $liveVal = Get-RegLiveString $f.regs
            } elseif ($f.snapshot) {
                $sv = & $f.snapshot
                if ($null -ne $sv) { $liveVal = "$sv" }
            }
        } catch { $liveVal = 'N/A (errore lettura)' }
        if ($null -eq $liveVal -or "$liveVal" -eq '') { $liveVal = 'N/A' }
        $f.liveVal = "$liveVal"

        # Valore ottimale: se non definito lo ricava dalla descrizione ("X = valore ..." / "Disabilita ...")
        if (-not $f.optVal) {
            $f.optVal = if ($f.desc -match '=\s*([^\s(]+)') { $Matches[1] }
                        elseif ($f.desc -match '^Disabilita') { 'Disabilitato' }
                        elseif ($f.desc -match '^Abilita')    { 'Abilitato' }
                        else { '-' }
        }

        # Stato dal file persistente
        $fState = 'NOT_APPLIED'
        if ($OptState.fixes.Contains($f.id)) { $fState = $OptState.fixes[$f.id].status }
        $f.currentState = $fState
        $f.appliedAt    = if ($OptState.fixes.Contains($f.id)) { "$($OptState.fixes[$f.id].appliedAt)" } else { '' }
        $f.needsApply   = [bool](& $f.check)
        $f.canRevert    = Test-FixRevertable $f
    }
    $NeedFixes = @($AllFixes | Where-Object { $_.needsApply })

    if ($DryRun) {
        Write-Host ''
        Write-Host "  [DRY RUN] Fix necessari: $($NeedFixes.Count) su $($AllFixes.Count) totali" -ForegroundColor Magenta
        Write-Host ''
        $AllFixes | ForEach-Object {
            $col   = if ($_.needsApply -and $_.prio -eq 'crit') { 'Red' } elseif ($_.needsApply) { 'Yellow' } else { 'Green' }
            $state = if ($_.currentState -eq 'APPLIED') { '[GIA APPLICATO]' } elseif ($_.needsApply) { '[DA APPLICARE]' } else { '[OK]' }
            $rb    = if ($_.reboot) { ' [RIAVVIO]' } else { '' }
            $rv    = if ($_.canRevert) { '' } else { ' [NO REVERT]' }
            Write-Host "  $state [$($_.cat)] $($_.id)$rb$rv" -ForegroundColor $col
            Write-Host "       Val attuale: $($_.liveVal) | Ottimale: $($_.optVal)" -ForegroundColor DarkGray
            Write-Host "       $($_.desc)" -ForegroundColor DarkGray
        }
        return
    }

    if ($Console) {
        Write-Host ''
        $needReboot = $false
        $AllFixes | ForEach-Object {
            $f   = $_
            $col = if ($f.needsApply) { 'Yellow' } else { 'Green' }
            Write-Host "  [$($f.currentState)] [$($f.cat)] $($f.id)" -ForegroundColor $col
            Write-Host "  Attuale: $($f.liveVal)  Ottimale: $($f.optVal)" -ForegroundColor DarkGray
            Write-Host "  $($f.desc)" -ForegroundColor White
            $canRevertNow = ($f.currentState -eq 'APPLIED' -and $f.canRevert)
            if ($f.needsApply -and $canRevertNow) {
                Write-Host '  [A]pplica / [R]evert / [S]kip (default S): ' -NoNewline -ForegroundColor Cyan
            } elseif ($f.needsApply) {
                Write-Host '  [A]pplica / [S]kip (default S): ' -NoNewline -ForegroundColor Cyan
            } elseif ($canRevertNow) {
                Write-Host '  Gia ottimizzato - [R]evert / [S]kip (default S): ' -NoNewline -ForegroundColor Green
            } else {
                Write-Host '  Gia ottimizzato - [S]kip: ' -NoNewline -ForegroundColor Green
            }
            $ans = "$(Read-Host)".Trim().ToLower()
            if ($ans -eq 'a' -and $f.needsApply) {
                try {
                    $snap = Get-FixSnapshotValue $f
                    Invoke-FixBlock -Block $f.script
                    Set-FixState -State $OptState -FixId $f.id -Status 'APPLIED' -Snapshot $snap -CurrentVal $f.liveVal -NeedsReboot $f.reboot
                    Write-Host '  [OK] Applicato' -ForegroundColor Green
                    if ($f.reboot) { $needReboot = $true }
                } catch { Set-FixState -State $OptState -FixId $f.id -Status 'FAILED' -Notes "$_"; Write-Host "  [FAIL] $_" -ForegroundColor Red }
                Save-OptimizationState -State $OptState -BasePath $BasePath | Out-Null
            } elseif ($ans -eq 'r' -and $canRevertNow) {
                try {
                    Invoke-FixRevert $f $OptState.fixes[$f.id].snapshot
                    Set-FixState -State $OptState -FixId $f.id -Status 'REVERTED' -CurrentVal $f.liveVal -NeedsReboot $f.reboot
                    Save-OptimizationState -State $OptState -BasePath $BasePath | Out-Null
                    Write-Host '  [OK] Revertito' -ForegroundColor Cyan
                    if ($f.reboot) { $needReboot = $true }
                } catch { Write-Host "  [FAIL revert] $_" -ForegroundColor Red }
            } else { Write-Host '  [SKIP]' -ForegroundColor DarkGray }
            Write-Host ''
        }
        if ($needReboot) { Write-Host '  ATTENZIONE: riavvio necessario per alcuni fix.' -ForegroundColor Yellow }
        return
    }

    # ==============================================================================
    # GUI WPF - Apply / Revert / Stato completo
    # ==============================================================================
    Add-Type -AssemblyName PresentationFramework -EA SilentlyContinue
    Add-Type -AssemblyName PresentationCore      -EA SilentlyContinue

    $xaml = @"
<Window xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation'
        xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
        Title='WinAuditPro - Gestione Ottimizzazioni RDS' Width='1100' Height='720'
        WindowStartupLocation='CenterScreen' Background='#0d1117' Foreground='#e6edf3'>
  <Window.Resources>
    <Style x:Key='DarkColHdrStyle' TargetType='DataGridColumnHeader'>
      <Setter Property='Background'      Value='#1c2128'/>
      <Setter Property='Foreground'      Value='#8b949e'/>
      <Setter Property='FontSize'        Value='10'/>
      <Setter Property='FontWeight'      Value='SemiBold'/>
      <Setter Property='Padding'         Value='8,5'/>
      <Setter Property='BorderBrush'     Value='#30363d'/>
      <Setter Property='BorderThickness' Value='0,0,1,1'/>
    </Style>
  </Window.Resources>
  <Grid Margin='14'>
    <Grid.RowDefinitions>
      <RowDefinition Height='Auto'/>
      <RowDefinition Height='Auto'/>
      <RowDefinition Height='Auto'/>
      <RowDefinition Height='*'/>
      <RowDefinition Height='Auto'/>
      <RowDefinition Height='Auto'/>
    </Grid.RowDefinitions>

    <TextBlock Grid.Row='0' Text='Gestione Ottimizzazioni Terminal Server' FontSize='15' FontWeight='Bold' Margin='0,0,0,4'/>
    <TextBlock Grid.Row='1' x:Name='SubTitle' FontSize='11' Foreground='#8b949e' Margin='0,0,0,10'/>

    <StackPanel Grid.Row='2' Orientation='Horizontal' Margin='0,0,0,8'>
      <Button x:Name='BtnAll'      Content='Tutti'              Width='80'  Background='#21262d' Foreground='#e6edf3' Margin='0,0,5,0' Padding='3'/>
      <Button x:Name='BtnPending'  Content='Da applicare'       Width='100' Background='#21262d' Foreground='#e3b341' Margin='0,0,5,0' Padding='3'/>
      <Button x:Name='BtnApplied'  Content='Applicati'          Width='90'  Background='#21262d' Foreground='#56d364' Margin='0,0,5,0' Padding='3'/>
      <Button x:Name='BtnReverted' Content='Revertiti'          Width='90'  Background='#21262d' Foreground='#79c0ff' Margin='0,0,20,0' Padding='3'/>
      <Button x:Name='BtnSelAll'   Content='Seleziona tutto'    Width='120' Background='#21262d' Foreground='#e6edf3' Margin='0,0,5,0' Padding='3'/>
      <Button x:Name='BtnSelNone'  Content='Deseleziona tutto'  Width='130' Background='#21262d' Foreground='#e6edf3' Margin='0,0,5,0' Padding='3'/>
      <Button x:Name='BtnSelPend'  Content='Seleziona pending'  Width='130' Background='#21262d' Foreground='#e3b341' Margin='0,0,5,0' Padding='3'/>
    </StackPanel>

    <DataGrid Grid.Row='3' x:Name='FixGrid'
              AutoGenerateColumns='False' IsReadOnly='False'
              Background='#161b22' Foreground='#e6edf3'
              BorderBrush='#30363d' BorderThickness='1'
              GridLinesVisibility='Horizontal' HorizontalGridLinesBrush='#21262d'
              RowBackground='#161b22' AlternatingRowBackground='#1a2030'
              HeadersVisibility='Column' CanUserResizeRows='False'
              ColumnHeaderStyle='{DynamicResource DarkColHdrStyle}'
              SelectionMode='Extended' SelectionUnit='FullRow'
              FontSize='11' FontFamily='Cascadia Code,Consolas'>
      <DataGrid.Columns>
        <DataGridCheckBoxColumn Header='' Binding='{Binding IsSelected}' Width='30'/>
        <DataGridTextColumn Header='Categoria' Binding='{Binding cat}'   Width='100' IsReadOnly='True'/>
        <DataGridTextColumn Header='Fix ID'    Binding='{Binding id}'    Width='180' IsReadOnly='True'/>
        <DataGridTextColumn Header='Descrizione'  Binding='{Binding desc}' Width='220' IsReadOnly='True'/>
        <DataGridTextColumn Header='Rischio/Causa' Binding='{Binding risk}'  Width='210' IsReadOnly='True'/>
        <DataGridTextColumn Header='Valore attuale' Binding='{Binding liveVal}'  Width='160' IsReadOnly='True'/>
        <DataGridTextColumn Header='Ottimale'  Binding='{Binding optVal}' Width='80'  IsReadOnly='True'/>
        <DataGridTextColumn Header='Stato'     Binding='{Binding stateLabel}' Width='100' IsReadOnly='True'/>
        <DataGridTextColumn Header='Riavvio'   Binding='{Binding rebootStr}'  Width='60'  IsReadOnly='True'/>
        <DataGridTextColumn Header='Revert'    Binding='{Binding revertStr}'  Width='55'  IsReadOnly='True'/>
        <DataGridTextColumn Header='Applicato' Binding='{Binding appliedAt}'  Width='115' IsReadOnly='True'/>
      </DataGrid.Columns>
      <DataGrid.RowStyle>
        <Style TargetType='DataGridRow'>
          <Style.Triggers>
            <DataTrigger Binding='{Binding currentState}' Value='APPLIED'>
              <Setter Property='Foreground' Value='#56d364'/>
            </DataTrigger>
            <DataTrigger Binding='{Binding currentState}' Value='REVERTED'>
              <Setter Property='Foreground' Value='#79c0ff'/>
            </DataTrigger>
            <DataTrigger Binding='{Binding currentState}' Value='FAILED'>
              <Setter Property='Foreground' Value='#ff7b72'/>
            </DataTrigger>
            <DataTrigger Binding='{Binding needsApply}' Value='True'>
              <Setter Property='Foreground' Value='#e3b341'/>
            </DataTrigger>
            <DataTrigger Binding='{Binding rebootStr}' Value='SI'>
              <Setter Property='FontStyle' Value='Italic'/>
            </DataTrigger>
          </Style.Triggers>
        </Style>
      </DataGrid.RowStyle>
    </DataGrid>

    <TextBlock Grid.Row='4' x:Name='StatusText' Foreground='#8b949e' FontSize='11' Margin='0,6,0,6' TextWrapping='Wrap'/>

    <StackPanel Grid.Row='5' Orientation='Horizontal' HorizontalAlignment='Right'>
      <Button x:Name='BtnApplySelected'  Content='Applica selezionati'  Width='150' Background='#0d4429' Foreground='#56d364' FontWeight='Bold' Margin='0,0,8,0' Padding='5'/>
      <Button x:Name='BtnRevertSelected' Content='Revert selezionati'   Width='150' Background='#0c2d6b' Foreground='#79c0ff' FontWeight='Bold' Margin='0,0,8,0' Padding='5'/>
      <Button x:Name='BtnClose'          Content='Chiudi'               Width='80'  Background='#21262d' Foreground='#e6edf3' Padding='5'/>
    </StackPanel>
  </Grid>
</Window>
"@

    try {
        $reader   = [System.Xml.XmlNodeReader]::new([xml]$xaml)
        $window   = [System.Windows.Markup.XamlReader]::Load($reader)
        $grid     = $window.FindName('FixGrid')
        $subTitle = $window.FindName('SubTitle')
        $statTxt  = $window.FindName('StatusText')
        $btnAll      = $window.FindName('BtnAll')
        $btnPending  = $window.FindName('BtnPending')
        $btnApplied  = $window.FindName('BtnApplied')
        $btnReverted = $window.FindName('BtnReverted')
        $btnSelAll   = $window.FindName('BtnSelAll')
        $btnSelNone  = $window.FindName('BtnSelNone')
        $btnSelPend  = $window.FindName('BtnSelPend')
        $btnApplySel  = $window.FindName('BtnApplySelected')
        $btnRevertSel = $window.FindName('BtnRevertSelected')
        $btnClose     = $window.FindName('BtnClose')

        # @() obbligatorio: con un solo risultato .Count restituirebbe il numero di chiavi dell'hashtable del fix
        $appliedCount  = @($AllFixes | Where-Object { $_.currentState -eq 'APPLIED'  }).Count
        $pendingCount  = @($AllFixes | Where-Object { $_.needsApply }).Count
        $revertedCount = @($AllFixes | Where-Object { $_.currentState -eq 'REVERTED' }).Count
        $subTitle.Text = "$($d.meta.hostname) ($($d.meta.serverRole))  |  Totale fix: $($AllFixes.Count)  |  Applicati: $appliedCount  |  Pending: $pendingCount  |  Revertiti: $revertedCount"

        # Prepara items per il DataGrid
        $allItems = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($f in $AllFixes) {
            $stLabel = switch ($f.currentState) {
                'APPLIED'     { 'Applicato' }
                'REVERTED'    { 'Revertito' }
                'FAILED'      { 'Fallito'   }
                default       { if ($f.needsApply) { 'Da applicare' } else { 'OK' } }
            }
            $allItems.Add([PSCustomObject]@{
                IsSelected   = $false
                cat          = $f.cat
                id           = $f.id
                desc         = $f.desc
                liveVal      = $f.liveVal
                optVal       = "$($f.optVal)$(if($f.unit -and $f.unit -ne ''){" $($f.unit)"})"
                stateLabel   = $stLabel
                currentState = $f.currentState
                needsApply   = $f.needsApply
                rebootStr    = if ($f.reboot) { "SI" } else { "no" }
                revertStr    = if ($f.canRevert) { "si" } else { "NO" }
                risk         = if ($f.risk)   { "$($f.risk)".Substring(0,[math]::Min(120,"$($f.risk)".Length)) } else { "" }
                appliedAt    = $f.appliedAt
                fix          = $f
            })
        }

        $grid.ItemsSource = $allItems

        # Filtri - GetNewClosure() necessario per catturare $grid, $statTxt, $allItems
        $applyFilter = {
            param($filterFunc)
            $filtered = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($it in $allItems) { if (& $filterFunc $it) { $filtered.Add($it) } }
            $grid.ItemsSource = $filtered
            $statTxt.Text = "Visualizzando $($filtered.Count) di $($allItems.Count) fix"
        }.GetNewClosure()

        $btnAll.Add_Click(      ({ & $applyFilter { $true } }).GetNewClosure())
        $btnPending.Add_Click(  ({ & $applyFilter { param($it) $it.needsApply } }).GetNewClosure())
        $btnApplied.Add_Click(  ({ & $applyFilter { param($it) $it.currentState -eq 'APPLIED' } }).GetNewClosure())
        $btnReverted.Add_Click( ({ & $applyFilter { param($it) $it.currentState -eq 'REVERTED' } }).GetNewClosure())

        $btnSelAll.Add_Click(({
            foreach ($it in $grid.ItemsSource) { $it.IsSelected = $true }
            $grid.Items.Refresh()
        }).GetNewClosure())
        $btnSelNone.Add_Click(({
            foreach ($it in $grid.ItemsSource) { $it.IsSelected = $false }
            $grid.Items.Refresh()
        }).GetNewClosure())
        $btnSelPend.Add_Click(({
            foreach ($it in $grid.ItemsSource) { $it.IsSelected = $it.needsApply }
            $grid.Items.Refresh()
        }).GetNewClosure())

        $btnApplySel.Add_Click(({
            $selected = @($grid.ItemsSource | Where-Object { $_.IsSelected })
            if ($selected.Count -eq 0) { $statTxt.Text = 'Nessun fix selezionato.'; return }
            $needReboot = $false; $ok = 0; $fail = 0
            foreach ($it in $selected) {
                $f = $it.fix
                try {
                    $snap = Get-FixSnapshotValue $f
                    Invoke-FixBlock -Block $f.script
                    Set-FixState -State $OptState -FixId $f.id -Status 'APPLIED' -Snapshot $snap -CurrentVal $f.liveVal -NeedsReboot $f.reboot
                    $it.currentState = 'APPLIED'
                    $it.stateLabel   = 'Applicato'
                    $it.needsApply   = $false
                    $it.appliedAt    = (Get-Date).ToString('yyyy-MM-dd HH:mm')
                    if ($f.reboot) { $needReboot = $true }
                    $ok++
                } catch {
                    Set-FixState -State $OptState -FixId $f.id -Status 'FAILED' -Notes "$_"
                    $it.currentState = 'FAILED'
                    $it.stateLabel   = 'Fallito'
                    $fail++
                }
            }
            Save-OptimizationState -State $OptState -BasePath $BasePath | Out-Null
            $grid.Items.Refresh()
            $rb = if ($needReboot) { ' | RIAVVIO NECESSARIO' } else { '' }
            $statTxt.Text = "Completato: $ok applicati, $fail falliti$rb"
        }).GetNewClosure())

        $btnRevertSel.Add_Click(({
            $selected = @($grid.ItemsSource | Where-Object { $_.IsSelected -and $_.currentState -eq 'APPLIED' })
            if ($selected.Count -eq 0) { $statTxt.Text = 'Nessun fix APPLICATO selezionato per il revert.'; return }
            $ok = 0; $fail = 0; $skipped = 0; $needReboot = $false
            foreach ($it in $selected) {
                $f = $it.fix
                # Senza revert/snapshot il fix NON va marcato "Revertito" (prima succedeva senza toccare nulla)
                if (-not $f.canRevert) { $it.stateLabel = 'Revert n/d'; $skipped++; continue }
                try {
                    $snap = if ($OptState.fixes.Contains($f.id)) { $OptState.fixes[$f.id].snapshot } else { $null }
                    Invoke-FixRevert $f $snap
                    Set-FixState -State $OptState -FixId $f.id -Status 'REVERTED' -CurrentVal $f.liveVal -NeedsReboot $f.reboot
                    $it.currentState = 'REVERTED'
                    $it.stateLabel   = 'Revertito'
                    if ($f.reboot) { $needReboot = $true }
                    $ok++
                } catch {
                    $it.stateLabel = 'Fail revert'
                    $fail++
                }
            }
            Save-OptimizationState -State $OptState -BasePath $BasePath | Out-Null
            $grid.Items.Refresh()
            $rb = if ($needReboot) { ' | RIAVVIO NECESSARIO' } else { '' }
            $sk = if ($skipped -gt 0) { " | $skipped senza revert disponibile" } else { '' }
            $statTxt.Text = "Revert completato: $ok OK, $fail falliti$sk$rb"
        }).GetNewClosure())

        $btnClose.Add_Click(({ $window.Close() }).GetNewClosure())

        $window.Topmost      = $true
        $window.ShowActivated = $true
        $null = $window.ShowDialog()
        try { $window.Activate() } catch { }

    } catch {
        Write-Host "  [ERRORE GUI] $_  - Uso modalita console." -ForegroundColor Yellow
        Invoke-Optimize -JsonPath $JsonPath -Console
    }
}


# ==============================================================================
# INVOKE-COMPAREBASELINE  (con severity e side-by-side)
# ==============================================================================

function Invoke-CompareBaseline {
    param(
        [Parameter(Mandatory=$true)][string]$BaselinePath,
        [Parameter(Mandatory=$true)][string]$CurrentPath,
        [string]$CompareOutPath = (Split-Path $CurrentPath -Parent),
        [switch]$OpenReport
    )

    Write-Host '  Caricamento file...' -ForegroundColor Cyan
    try {
        $b = (Get-Content $BaselinePath -Raw -Encoding UTF8) | ConvertFrom-Json
        $c = (Get-Content $CurrentPath  -Raw -Encoding UTF8) | ConvertFrom-Json
    } catch { Write-Host "  [ERRORE] $_" -ForegroundColor Red; return }

    $hostname = $c.meta.hostname
    $ts       = Get-Date -Format 'yyyyMMdd_HHmmss'

    # Definisce metriche con soglie di severity
    $metrics = @(
        @{section='Score';   metric='Score globale /100';     bVal=$b.scores.globalScore;  cVal=$c.scores.globalScore;  lowerIsBetter=$false; warnDelta=5;  critDelta=15},
        @{section='Score';   metric='Critici totali';         bVal=$b.scores.critCount;    cVal=$c.scores.critCount;    lowerIsBetter=$true;  warnDelta=1;  critDelta=3},
        @{section='Score';   metric='Warning totali';         bVal=$b.scores.warnCount;    cVal=$c.scores.warnCount;    lowerIsBetter=$true;  warnDelta=3;  critDelta=8},
        @{section='CPU';     metric='Utilizzo %';             bVal=$b.cpu.avgUsagePct;     cVal=$c.cpu.avgUsagePct;     lowerIsBetter=$true;  warnDelta=10; critDelta=20},
        @{section='CPU';     metric='Processor Queue';        bVal=$b.cpu.processorQueue;  cVal=$c.cpu.processorQueue;  lowerIsBetter=$true;  warnDelta=1;  critDelta=4},
        @{section='RAM';     metric='Utilizzo %';             bVal=$b.ram.usagePct;        cVal=$c.ram.usagePct;        lowerIsBetter=$true;  warnDelta=10; critDelta=20},
        @{section='RAM';     metric='RAM libera GB';          bVal=$b.ram.freeGB;          cVal=$c.ram.freeGB;          lowerIsBetter=$false; warnDelta=2;  critDelta=5},
        @{section='RAM';     metric='Pages/sec';              bVal=$b.ram.pagesSec;        cVal=$c.ram.pagesSec;        lowerIsBetter=$true;  warnDelta=5;  critDelta=20},
        @{section='Disco';   metric='Write Latency ms';       bVal=$b.disk.writeLatencyMs; cVal=$c.disk.writeLatencyMs; lowerIsBetter=$true;  warnDelta=5;  critDelta=15},
        @{section='Disco';   metric='Disk Queue';             bVal=$b.disk.queueLength;    cVal=$c.disk.queueLength;    lowerIsBetter=$true;  warnDelta=1;  critDelta=2},
        @{section='Disco';   metric='IOPS';                   bVal=$b.disk.iops;           cVal=$c.disk.iops;           lowerIsBetter=$false; warnDelta=100; critDelta=500},
        @{section='Rete';    metric='TIME_WAIT';               bVal=$b.network.timeWaitCount; cVal=$c.network.timeWaitCount; lowerIsBetter=$true; warnDelta=100; critDelta=500},
        @{section='Rete';    metric='CLOSE_WAIT';              bVal=$b.network.closeWaitCount; cVal=$c.network.closeWaitCount; lowerIsBetter=$true; warnDelta=1; critDelta=10},
        @{section='Sessioni';metric='Utenti attivi';           bVal=$b.system.activeUsers;  cVal=$c.system.activeUsers;  lowerIsBetter=$false; warnDelta=5; critDelta=10},
        @{section='Sessioni';metric='Sessioni disconnesse';    bVal=$b.system.disconnectedSessions; cVal=$c.system.disconnectedSessions; lowerIsBetter=$true; warnDelta=3; critDelta=10},
        @{section='EventLog';metric='Critici';                 bVal=$b.eventLog.criticalCount; cVal=$c.eventLog.criticalCount; lowerIsBetter=$true; warnDelta=1; critDelta=5},
        @{section='EventLog';metric='Errori';                  bVal=$b.eventLog.errorCount; cVal=$c.eventLog.errorCount; lowerIsBetter=$true; warnDelta=10; critDelta=30},
        @{section='Aggiorn.';metric='Pending updates';         bVal=$b.windowsUpdate.pendingUpdates; cVal=$c.windowsUpdate.pendingUpdates; lowerIsBetter=$true; warnDelta=5; critDelta=20}
    )

    $improved = 0; $regressed = 0; $critRegressed = 0; $unchanged = 0
    $tableRows = ''

    foreach ($m in $metrics) {
        if ($null -eq $m.bVal -or $null -eq $m.cVal) { continue }

        $bR    = [math]::Round($m.bVal, 1)
        $cR    = [math]::Round($m.cVal, 1)
        $diff  = [math]::Round($m.cVal - $m.bVal, 1)
        $absDiff = [math]::Abs($diff)

        # Determina se la variazione e positiva o negativa
        $isGood = if ($m.lowerIsBetter) { $diff -le 0 } else { $diff -ge 0 }
        $isBad  = -not $isGood
        # Prima: "freccia giu -N" per ogni miglioramento anche se il valore era salito (es. score +10 mostrato come -10)
        $deltaTxt = if ($diff -gt 0) { "&#9650; +$diff" } elseif ($diff -lt 0) { "&#9660; $diff" } else { '=' }

        $severity = 'unchanged'
        $arrow    = ''
        $rowColor = ''

        if ($absDiff -ge $m.critDelta -and $isBad) {
            $severity = 'crit-regressed'; $critRegressed++; $regressed++
            $arrow    = $deltaTxt
            $rowColor = 'background:rgba(248,81,73,.12);'
        } elseif ($absDiff -ge $m.warnDelta -and $isBad) {
            $severity = 'warn-regressed'; $regressed++
            $arrow    = $deltaTxt
            $rowColor = 'background:rgba(210,153,34,.08);'
        } elseif ($absDiff -ge $m.warnDelta -and $isGood) {
            $severity = 'improved'; $improved++
            $arrow    = $deltaTxt
            $rowColor = 'background:rgba(63,185,80,.06);'
        } elseif ($absDiff -lt $m.warnDelta -and $diff -ne 0) {
            $severity = 'minor'; $unchanged++
            $arrow    = if ($diff -gt 0) { "+$diff" } else { "$diff" }
            $rowColor = ''
        } else {
            $severity = 'unchanged'; $unchanged++
            $arrow    = '='
            $rowColor = ''
        }

        $arrowColor = switch ($severity) {
            'crit-regressed' { '#ff7b72' } 'warn-regressed' { '#e3b341' }
            'improved'       { '#56d364' } default          { '#8b949e' }
        }
        $severityBadge = switch ($severity) {
            'crit-regressed' { "<span style='background:#3d0e0e;color:#ff7b72;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700'>PEGGIO CRITICO</span>" }
            'warn-regressed' { "<span style='background:#3d2e0e;color:#e3b341;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700'>PEGGIORATO</span>" }
            'improved'       { "<span style='background:#0d4429;color:#56d364;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700'>MIGLIORATO</span>" }
            default          { "<span style='color:#6e7681;font-size:10px'>-</span>" }
        }

        $tableRows += "<tr style='$rowColor'><td style='color:var(--text3);font-size:11px'>$($m.section)</td><td style='font-size:12px'>$($m.metric)</td><td style='color:var(--text2)'>$bR</td><td style='font-weight:600'>$cR</td><td style='color:$arrowColor;font-weight:700'>$arrow</td><td>$severityBadge</td></tr>`n"
    }

    $totalMetrics = @($metrics | Where-Object { $null -ne $_.bVal -and $null -ne $_.cVal }).Count

    $css2 = @'
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--text3:#6e7681;--green:#3fb950;--red:#f85149;--yellow:#d29922}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Cascadia Code',Consolas,monospace;font-size:13px;padding:24px;line-height:1.5;max-width:1200px;margin:0 auto}
h1{font-size:18px;margin-bottom:4px;color:var(--text)}
.sub{color:var(--text2);font-size:12px;margin-bottom:20px}
.info-row{display:flex;gap:24px;margin-bottom:20px;font-size:12px;color:var(--text2);flex-wrap:wrap}
.info-val{color:var(--text);font-weight:600}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
@media(max-width:700px){.g4{grid-template-columns:repeat(2,1fr)}}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px}
.c-t{font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
.c-v{font-size:26px;font-weight:700}
.c-s{font-size:11px;color:var(--text2);margin-top:3px}
table{width:100%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th{background:var(--bg3);color:var(--text2);padding:8px 12px;text-align:left;font-size:11px;font-weight:600}
td{padding:7px 12px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(88,166,255,.03)}
.export-btn{background:var(--bg3);border:1px solid var(--border);color:var(--text2);padding:4px 12px;border-radius:4px;font-size:11px;cursor:pointer;margin-bottom:10px;font-family:inherit}
.export-btn:hover{border-color:var(--yellow);color:var(--yellow)}
'@

    $html2 = @"
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<title>Confronto Baseline - $hostname</title>
<style>$css2</style>
</head>
<body>
<h1>Confronto Baseline - $hostname</h1>
<div class="sub">$($c.meta.serverRole) | Generato: $(Get-Date -Format 'dd/MM/yyyy HH:mm')</div>
<div class="info-row">
  <div>Baseline: <span class="info-val">$($b.meta.auditDate)</span> (Score: $($b.scores.globalScore)/100)</div>
  <div>Corrente: <span class="info-val">$($c.meta.auditDate)</span> (Score: $($c.scores.globalScore)/100)</div>
</div>
<div class="g4">
  <div class="card" style="border-left:3px solid var(--red)">
    <div class="c-t">Regressi critici</div>
    <div class="c-v" style="color:var(--red)">$critRegressed</div>
  </div>
  <div class="card" style="border-left:3px solid var(--yellow)">
    <div class="c-t">Regressi warning</div>
    <div class="c-v" style="color:var(--yellow)">$($regressed - $critRegressed)</div>
  </div>
  <div class="card" style="border-left:3px solid var(--green)">
    <div class="c-t">Migliorati</div>
    <div class="c-v" style="color:var(--green)">$improved</div>
  </div>
  <div class="card" style="border-left:3px solid var(--border)">
    <div class="c-t">Invariati / minori</div>
    <div class="c-v" style="color:var(--text2)">$unchanged</div>
    <div class="c-s">su $totalMetrics metriche</div>
  </div>
</div>
<button class="export-btn" onclick="exportCSV()">Esporta CSV</button>
<table id="delta-table">
  <thead>
    <tr>
      <th style="width:80px">Sezione</th>
      <th>Metrica</th>
      <th style="width:100px">Baseline</th>
      <th style="width:100px">Corrente</th>
      <th style="width:110px">Delta</th>
      <th style="width:150px">Severity</th>
    </tr>
  </thead>
  <tbody>
$tableRows
  </tbody>
</table>
<script>
function exportCSV() {
  var t = document.getElementById('delta-table');
  var rows = Array.from(t.querySelectorAll('tr'));
  var csv  = rows.map(function(r){ return Array.from(r.querySelectorAll('th,td')).map(function(c){ return '"'+c.innerText.replace(/"/g,'""')+'"'; }).join(','); }).join('\n');
  var blob = new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8;'});
  var a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='delta_${hostname}.csv'; a.click();
}
</script>
</body>
</html>
"@

    if (-not (Test-Path $CompareOutPath)) { New-Item -ItemType Directory -Path $CompareOutPath -Force | Out-Null }
    $outFile = Join-Path $CompareOutPath "Delta_${hostname}_${ts}.html"
    $html2 | Out-File -FilePath $outFile -Encoding UTF8 -Force
    Write-Host "  [+] Delta report: $outFile" -ForegroundColor Green
    if ($OpenReport) { Start-Process $outFile }
    return $outFile
}


# ==============================================================================
# MENU PRINCIPALE
# ==============================================================================

function Invoke-MainMenu {
    param([string]$MenuOutputPath = $OutputPath)

    if ($Quick) {
        $j = Invoke-FullAudit -AuditOutputPath $MenuOutputPath -OpenReport:$false
        return
    }

    while ($true) {
        Write-Header
        Show-LastAuditStatus
        Write-Host ''
        Write-MenuItem '1' 'Audit completo + Report HTML' ''
        Write-MenuItem '2' 'Audit JSON only (no HTML)' '' DarkGray
        Write-MenuItem '3' 'Genera HTML da JSON esistente' ''
        Write-MenuItem '4' 'Apri ultimo report HTML' '' Cyan
        Write-Host ''
        Write-MenuItem '5' 'Gestisci ottimizzazioni RDS (Apply / Revert / Stato)' '' Yellow
        Write-MenuItem '6' 'Dry run ottimizzazioni (mostra senza applicare)' '' DarkGray
        Write-Host ''
        Write-MenuItem '7' 'Confronta baseline' '' Magenta
        Write-MenuItem '8' 'Lista audit salvati' '' DarkGray
        Write-Host ''
        Write-MenuItem 'C' 'Cambia output path' "  (attuale: $MenuOutputPath)" DarkGray
        Write-MenuItem 'Q' 'Esci' '' Red
        Write-Host ''
        Write-Host '  Scelta: ' -NoNewline -ForegroundColor Cyan
        $choice = "$(Read-Host)".Trim().ToUpper()

        switch ($choice) {

            '1' {
                Write-Header
                $j = Invoke-FullAudit -AuditOutputPath $MenuOutputPath
                Pause-Menu
            }

            '2' {
                Write-Header
                Invoke-FullAudit -AuditOutputPath $MenuOutputPath -JsonOnly
                Pause-Menu
            }

            '3' {
                Write-Header
                $jsons = @(Get-AllJsons)
                if ($jsons.Count -eq 0) { Write-Host "  Nessun JSON trovato in $MenuOutputPath" -ForegroundColor Yellow; Pause-Menu; continue }
                Write-Host '  File JSON disponibili:' -ForegroundColor Cyan
                for ($i = 0; $i -lt $jsons.Count; $i++) {
                    Write-Host "    [$($i+1)] $($jsons[$i].Name) ($([math]::Round($jsons[$i].Length/1KB,1)) KB)" -ForegroundColor White
                }
                Write-Host '  Numero (0=annulla): ' -NoNewline -ForegroundColor Cyan
                $sel = 0; [void][int]::TryParse("$(Read-Host)", [ref]$sel)
                if ($sel -ge 1 -and $sel -le $jsons.Count) {
                    $jPath = $jsons[$sel-1].FullName
                    Write-Host ''
                    $hf = Invoke-NewAuditReport -JsonPath $jPath -ReportOutPath $MenuOutputPath
                    Write-Host '  Aprire il report? [s/N] ' -NoNewline -ForegroundColor Cyan
                    $ans = (Read-Host).Trim().ToLower()
                    if ($ans -eq 's' -and $hf) { Start-Process $hf }
                }
                Pause-Menu
            }

            '4' {
                $htmlFiles = @(Get-ChildItem -Path $MenuOutputPath -Filter '*_Report_*.html' -EA SilentlyContinue | Sort-Object LastWriteTime -Descending)
                if ($htmlFiles.Count -gt 0) { Start-Process $htmlFiles[0].FullName }
                else { Write-Host '  Nessun report HTML trovato.' -ForegroundColor Yellow; Pause-Menu }
            }

            '5' {
                Write-Header
                $j = Get-LastJson
                if (-not $j) { Write-Host '  Nessun audit disponibile. Eseguire prima un audit.' -ForegroundColor Yellow; Pause-Menu; continue }
                Write-Host '  Apertura gestione ottimizzazioni...' -ForegroundColor Cyan
                Invoke-Optimize -JsonPath $j
                Pause-Menu
            }

            '6' {
                Write-Header
                $j = Get-LastJson
                if (-not $j) { Write-Host '  Nessun audit disponibile.' -ForegroundColor Yellow; Pause-Menu; continue }
                Invoke-Optimize -JsonPath $j -DryRun
                Pause-Menu
            }

            '7' {
                Write-Header
                $jsons = @(Get-AllJsons)
                if ($jsons.Count -lt 2) { Write-Host '  Servono almeno 2 audit per confrontare. Eseguire altri audit.' -ForegroundColor Yellow; Pause-Menu; continue }
                Write-Host '  Audit disponibili:' -ForegroundColor Cyan
                for ($i = 0; $i -lt $jsons.Count; $i++) {
                    $szKB = [math]::Round($jsons[$i].Length/1KB,1)
                    Write-Host "    [$($i+1)] $($jsons[$i].Name) ($szKB KB)" -ForegroundColor White
                }
                Write-Host '  Seleziona BASELINE (numero): ' -NoNewline -ForegroundColor Cyan; $bi = 0; [void][int]::TryParse("$(Read-Host)", [ref]$bi)
                Write-Host '  Seleziona CORRENTE (numero): ' -NoNewline -ForegroundColor Cyan; $ci = 0; [void][int]::TryParse("$(Read-Host)", [ref]$ci)
                if ($bi -ge 1 -and $bi -le $jsons.Count -and $ci -ge 1 -and $ci -le $jsons.Count -and $bi -ne $ci) {
                    Write-Host ''
                    $dfPath = Invoke-CompareBaseline -BaselinePath $jsons[$bi-1].FullName -CurrentPath $jsons[$ci-1].FullName -CompareOutPath $MenuOutputPath
                    Write-Host '  Aprire il report delta? [s/N] ' -NoNewline -ForegroundColor Cyan
                    $ans = (Read-Host).Trim().ToLower()
                    if ($ans -eq 's') { Start-Process $dfPath }
                } else { Write-Host '  Selezione non valida.' -ForegroundColor Red }
                Pause-Menu
            }

            '8' {
                Write-Header
                Write-Host '  Audit salvati in: ' -NoNewline -ForegroundColor DarkGray
                Write-Host $MenuOutputPath -ForegroundColor Cyan
                Write-Host ''
                $jsons = @(Get-AllJsons)
                if ($jsons.Count -eq 0) { Write-Host '  Nessun audit trovato.' -ForegroundColor Yellow }
                else {
                    foreach ($jf in $jsons) {
                        try {
                            $jd     = (Get-Content $jf.FullName -Raw -Encoding UTF8) | ConvertFrom-Json
                            $score  = $jd.scores.globalScore
                            $crits  = $jd.scores.critCount
                            $warns  = $jd.scores.warnCount
                            $sCol   = if($score -ge 70){'Green'}elseif($score -ge 40){'Yellow'}else{'Red'}
                            $cCol   = if($crits -gt 0){'Red'}else{'Green'}
                            $wCol   = if($warns -gt 0){'Yellow'}else{'Green'}
                            Write-Host "  $($jf.Name)" -ForegroundColor White -NoNewline
                            Write-Host "   Score: " -ForegroundColor DarkGray -NoNewline
                            Write-Host "$score/100" -ForegroundColor $sCol -NoNewline
                            Write-Host "   Critici: " -ForegroundColor DarkGray -NoNewline
                            Write-Host "$crits" -ForegroundColor $cCol -NoNewline
                            Write-Host "   Warning: " -ForegroundColor DarkGray -NoNewline
                            Write-Host "$warns" -ForegroundColor $wCol
                        } catch { Write-Host "  $($jf.Name)" -ForegroundColor DarkGray }
                    }
                }
                Pause-Menu
            }

            'C' {
                Write-Host '  Nuovo output path: ' -NoNewline -ForegroundColor Cyan
                $np = (Read-Host).Trim()
                if ($np -and (Test-Path $np -IsValid)) {
                    if (-not (Test-Path $np)) { New-Item -ItemType Directory -Path $np -Force | Out-Null }
                    $MenuOutputPath    = $np
                    $script:OutputPath = $np   # usato da Get-LastJson/Get-AllJsons/Write-Header
                    Write-Host "  Path aggiornato: $MenuOutputPath" -ForegroundColor Green
                } else { Write-Host '  Path non valido.' -ForegroundColor Red }
                Pause-Menu
            }

            'Q' { Write-Host '  Arrivederci.' -ForegroundColor DarkGray; Write-Host ''; break }

            default { }
        }

        if ($choice -eq 'Q') { break }
    }
}

# ==============================================================================
# AZIONI NON INTERATTIVE (-Action / -NoGui) - usate anche dal pannello
# ==============================================================================

function Resolve-WapJson([string]$Path) {
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Audit JSON non trovato: $Path" }
        return $Path
    }
    $last = Get-LastJson
    if (-not $last) { throw 'Nessun audit disponibile: eseguire prima un audit.' }
    return $last
}

function Invoke-WapAction([string]$Name) {
    $open = [bool]$script:WapCfg.OpenReport
    try {
        switch ($Name) {
            'Audit' {
                $j = Invoke-FullAudit -AuditOutputPath $OutputPath -OpenReport:$open
                if (-not $j) { Write-Host '[ERRORE] Audit non completato.'; return 1 }
            }
            'AuditJson' {
                $j = Invoke-FullAudit -AuditOutputPath $OutputPath -JsonOnly
                if (-not $j) { Write-Host '[ERRORE] Audit non completato.'; return 1 }
            }
            'Report' {
                $jp = Resolve-WapJson $JsonPath
                $hf = Invoke-NewAuditReport -JsonPath $jp -ReportOutPath $OutputPath -OpenBrowser:$open
                if (-not $hf) { Write-Host '[ERRORE] Report non generato.'; return 1 }
                Write-Host "  [OK] Report: $hf"
            }
            'DryRun' {
                Invoke-Optimize -JsonPath (Resolve-WapJson $JsonPath) -DryRun
            }
            'Optimize' {
                Invoke-Optimize -JsonPath (Resolve-WapJson $JsonPath)
            }
            'Compare' {
                if (-not $BaselinePath -or -not $CurrentPath) { throw 'Servono -BaselinePath e -CurrentPath.' }
                foreach ($p in @($BaselinePath, $CurrentPath)) { if (-not (Test-Path -LiteralPath $p)) { throw "Audit JSON non trovato: $p" } }
                $df = Invoke-CompareBaseline -BaselinePath $BaselinePath -CurrentPath $CurrentPath -CompareOutPath $OutputPath -OpenReport:$open
                if (-not $df) { Write-Host '[ERRORE] Confronto non generato.'; return 1 }
                Write-Host "  [OK] Confronto: $df"
            }
        }
        return 0
    } catch {
        Write-Host "[ERRORE] $($_.Exception.Message)"
        return 1
    }
}

# ==============================================================================
# PANNELLO GRAFICO
# ==============================================================================

function Get-WapAuditList([string]$Dir) {
    $rows = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $Dir -Filter '*AuditData*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        $score = ''; $crit = ''; $warn = ''; $role = ''; $date = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
        try {
            $d = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            $score = "$($d.scores.globalScore)"
            $crit = "$($d.scores.critCount)"
            $warn = "$($d.scores.warnCount)"
            $role = "$($d.meta.serverRole)"
            if ($d.meta.auditDate) { $date = "$($d.meta.auditDate)" }
        } catch { $score = '(illeggibile)' }
        $rows += [pscustomobject]@{ Path = $f.FullName; File = $f.Name; Data = $date; Score = $score; Critici = $crit; Warning = $warn; Ruolo = $role; KB = [math]::Round($f.Length / 1KB, 0); Time = $f.LastWriteTime }
    }
    $rows
}

function Show-WapGui {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $script:Child = $null
    $script:ChildAction = ''
    $script:OutTask = $null
    $script:ErrTask = $null
    $script:CloseWhenDone = $false

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "WinAuditPro $script:WapVersion - $env:COMPUTERNAME"
    $form.Size = New-Object System.Drawing.Size(1180, 780)
    $form.MinimumSize = New-Object System.Drawing.Size(980, 620)
    $form.StartPosition = 'CenterScreen'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # ---------------------------------------------------------- intestazione
    $head = New-Object System.Windows.Forms.Panel
    $head.Dock = 'Top'; $head.Height = 52
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "WinAuditPro $script:WapVersion  -  Audit e ottimizzazione Windows Server / RDS  -  $env:COMPUTERNAME"
    $lblTitle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
    $lblTitle.AutoSize = $true; $lblTitle.Location = New-Object System.Drawing.Point(12, 6)
    $lblLast = New-Object System.Windows.Forms.Label
    $lblLast.AutoSize = $true; $lblLast.Location = New-Object System.Drawing.Point(14, 30); $lblLast.ForeColor = [System.Drawing.Color]::DimGray
    $head.Controls.AddRange(@($lblTitle, $lblLast))

    # ---------------------------------------------------------- colonna sinistra: impostazioni e azioni
    $left = New-Object System.Windows.Forms.FlowLayoutPanel
    $left.Dock = 'Left'; $left.Width = 380; $left.FlowDirection = 'TopDown'; $left.WrapContents = $false; $left.AutoScroll = $true
    $left.Padding = New-Object System.Windows.Forms.Padding(8, 4, 4, 4)

    $grpCfg = New-Object System.Windows.Forms.GroupBox
    $grpCfg.Text = 'Impostazioni'; $grpCfg.Width = 355; $grpCfg.Height = 300
    $tl = New-Object System.Windows.Forms.TableLayoutPanel
    $tl.Dock = 'Fill'; $tl.ColumnCount = 2; $tl.Padding = New-Object System.Windows.Forms.Padding(4)
    [void]$tl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$tl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $tip = New-Object System.Windows.Forms.ToolTip

    function New-WapLabel([string]$Text) {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Text; $l.AutoSize = $true; $l.Anchor = 'Left'; $l.Margin = New-Object System.Windows.Forms.Padding(3, 7, 6, 3)
        $l
    }
    function New-WapNum([int]$Min, [int]$Max) {
        $n = New-Object System.Windows.Forms.NumericUpDown
        $n.Minimum = $Min; $n.Maximum = $Max; $n.Width = 90; $n.Anchor = 'Left'
        $n
    }

    $txtOut = New-Object System.Windows.Forms.TextBox; $txtOut.Anchor = 'Left, Right'
    $btnOut = New-Object System.Windows.Forms.Button; $btnOut.Text = 'Sfoglia...'; $btnOut.AutoSize = $true; $btnOut.Anchor = 'Right'
    $numTimeout = New-WapNum 5 600
    $numDays = New-WapNum 1 90
    $numEvents = New-WapNum 20 10000
    $chkOpen = New-Object System.Windows.Forms.CheckBox; $chkOpen.Text = 'Apri il report al termine'; $chkOpen.AutoSize = $true

    $lOut = New-WapLabel 'Cartella output'
    $tl.Controls.Add($lOut, 0, 0); $tl.Controls.Add($txtOut, 1, 0)
    $tl.Controls.Add($btnOut, 1, 1)
    $lTo = New-WapLabel 'Timeout cmdlet (s)'
    $tl.Controls.Add($lTo, 0, 2); $tl.Controls.Add($numTimeout, 1, 2)
    $lDays = New-WapLabel 'Giorni di eventi'
    $tl.Controls.Add($lDays, 0, 3); $tl.Controls.Add($numDays, 1, 3)
    $lEv = New-WapLabel 'Max eventi per log'
    $tl.Controls.Add($lEv, 0, 4); $tl.Controls.Add($numEvents, 1, 4)
    $tl.Controls.Add($chkOpen, 1, 5)
    $tip.SetToolTip($txtOut, 'Audit JSON, report HTML, confronti e stato delle ottimizzazioni (optimizations_state.json).')
    $tip.SetToolTip($numTimeout, 'Tempo massimo per i cmdlet che possono bloccarsi (contatori, WMI).')
    $tip.SetToolTip($numDays, 'Quanti giorni di Registro eventi analizzare.')
    $tip.SetToolTip($numEvents, 'Numero massimo di eventi letti per ciascun registro.')

    $cfgBtns = New-Object System.Windows.Forms.FlowLayoutPanel
    $cfgBtns.AutoSize = $true; $cfgBtns.WrapContents = $true; $cfgBtns.Width = 330
    $btnSave = New-Object System.Windows.Forms.Button; $btnSave.Text = 'Salva'; $btnSave.AutoSize = $true
    $btnSaveAs = New-Object System.Windows.Forms.Button; $btnSaveAs.Text = 'Salva come...'; $btnSaveAs.AutoSize = $true
    $btnLoad = New-Object System.Windows.Forms.Button; $btnLoad.Text = 'Carica...'; $btnLoad.AutoSize = $true
    $btnDef = New-Object System.Windows.Forms.Button; $btnDef.Text = 'Predefiniti'; $btnDef.AutoSize = $true
    $cfgBtns.Controls.AddRange(@($btnSave, $btnSaveAs, $btnLoad, $btnDef))
    $tl.Controls.Add($cfgBtns, 0, 6); $tl.SetColumnSpan($cfgBtns, 2)
    $lblCfg = New-Object System.Windows.Forms.Label
    $lblCfg.AutoSize = $true; $lblCfg.MaximumSize = New-Object System.Drawing.Size(330, 0); $lblCfg.ForeColor = [System.Drawing.Color]::DimGray
    $tl.Controls.Add($lblCfg, 0, 7); $tl.SetColumnSpan($lblCfg, 2)
    $grpCfg.Controls.Add($tl)

    $grpAct = New-Object System.Windows.Forms.GroupBox
    $grpAct.Text = 'Azioni'; $grpAct.Width = 355; $grpAct.Height = 330
    $actFlow = New-Object System.Windows.Forms.FlowLayoutPanel
    $actFlow.Dock = 'Fill'; $actFlow.FlowDirection = 'TopDown'; $actFlow.WrapContents = $false; $actFlow.Padding = New-Object System.Windows.Forms.Padding(4)
    function New-WapAction([string]$Text, [string]$Tip) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $Text; $b.Width = 330; $b.Height = 30; $b.TextAlign = 'MiddleLeft'
        if ($Tip) { $tip.SetToolTip($b, $Tip) }
        [void]$actFlow.Controls.Add($b)
        $b
    }
    $bAudit = New-WapAction 'Audit completo + report HTML' 'Raccoglie i dati del server e genera il report.'
    $bJson = New-WapAction 'Solo audit (JSON)' 'Raccoglie i dati senza generare il report HTML.'
    $bReport = New-WapAction 'Report HTML dall''audit selezionato' 'Rigenera il report dal JSON selezionato (o dall''ultimo).'
    $bOpenRep = New-WapAction 'Apri ultimo report HTML' ''
    $bOpt = New-WapAction 'Gestisci ottimizzazioni (apply / revert)' 'Apre la finestra delle ottimizzazioni RDS sull''audit selezionato (o sull''ultimo).'
    $bDry = New-WapAction 'Dry run ottimizzazioni' 'Mostra cosa andrebbe applicato, senza modificare nulla.'
    $bCmp = New-WapAction 'Confronta 2 audit selezionati' 'Il piu'' vecchio e'' la baseline, il piu'' recente il corrente.'
    $bFolder = New-WapAction 'Apri cartella output' ''
    $bConsole = New-WapAction 'Menu testuale (console)' 'Apre il menu classico in una finestra PowerShell.'
    $grpAct.Controls.Add($actFlow)
    $left.Controls.AddRange(@($grpCfg, $grpAct))

    # ---------------------------------------------------------- destra: audit salvati e log
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'; $split.Orientation = 'Horizontal'; $split.SplitterDistance = 260

    $lblAud = New-Object System.Windows.Forms.Label
    $lblAud.Text = 'Audit salvati (Ctrl+clic per selezionarne due da confrontare)'; $lblAud.Dock = 'Top'; $lblAud.Height = 20
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.SelectionMode = 'FullRowSelect'; $grid.MultiSelect = $true
    $grid.AutoSizeColumnsMode = 'Fill'; $grid.BackgroundColor = [System.Drawing.Color]::White
    foreach ($c in @(@('File', 34), @('Data', 16), @('Score', 8), @('Critici', 8), @('Warning', 8), @('Ruolo', 14), @('KB', 7))) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $c[0]; $col.HeaderText = $c[0]; $col.FillWeight = $c[1]
        [void]$grid.Columns.Add($col)
    }
    $split.Panel1.Controls.Add($grid)
    $split.Panel1.Controls.Add($lblAud)
    $grid.BringToFront()

    $log = New-Object System.Windows.Forms.RichTextBox
    $log.Dock = 'Fill'; $log.ReadOnly = $true; $log.WordWrap = $false; $log.BackColor = [System.Drawing.Color]::White
    $log.Font = New-Object System.Drawing.Font('Consolas', 9)
    $split.Panel2.Controls.Add($log)

    # ---------------------------------------------------------- barra inferiore
    $bottom = New-Object System.Windows.Forms.Panel
    $bottom.Dock = 'Bottom'; $bottom.Height = 38
    $prog = New-Object System.Windows.Forms.ProgressBar
    $prog.Style = 'Marquee'; $prog.MarqueeAnimationSpeed = 0; $prog.Width = 220; $prog.Height = 18; $prog.Location = New-Object System.Drawing.Point(10, 10)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Annulla'; $btnCancel.Width = 90; $btnCancel.Height = 26; $btnCancel.Location = New-Object System.Drawing.Point(240, 6); $btnCancel.Enabled = $false
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.AutoSize = $true; $lblStatus.Location = New-Object System.Drawing.Point(342, 11); $lblStatus.Text = 'Pronto.'
    $bottom.Controls.AddRange(@($prog, $btnCancel, $lblStatus))

    $form.Controls.Add($split)
    $form.Controls.Add($left)
    $form.Controls.Add($head)
    $form.Controls.Add($bottom)
    $split.BringToFront()

    # ---------------------------------------------------------- helper
    function Add-WapLog([string]$Text, [string]$Level = '') {
        if (-not $Level) {
            if ($Text -match '\[ERROR|\[ERRORE|\[FAIL') { $Level = 'ERROR' }
            elseif ($Text -match '\[WARN|TIMEOUT') { $Level = 'WARN' }
            elseif ($Text -match '\[OK\]|\]\[OK\]|COMPLETATO') { $Level = 'OK' }
            elseif ($Text -match '===\[|\[SECTION\]') { $Level = 'STEP' }
        }
        $color = [System.Drawing.Color]::Black
        if ($Level -eq 'ERROR') { $color = [System.Drawing.Color]::Firebrick }
        elseif ($Level -eq 'WARN') { $color = [System.Drawing.Color]::DarkOrange }
        elseif ($Level -eq 'OK') { $color = [System.Drawing.Color]::DarkGreen }
        elseif ($Level -eq 'STEP') { $color = [System.Drawing.Color]::RoyalBlue }
        $log.SelectionStart = $log.TextLength
        $log.SelectionLength = 0
        $log.SelectionColor = $color
        $log.AppendText($Text + "`r`n")
        $log.SelectionColor = $log.ForeColor
        $log.ScrollToCaret()
    }

    function Set-WapForm($Cfg) {
        $txtOut.Text = [string]$Cfg.OutputPath
        $numTimeout.Value = [decimal][math]::Min([math]::Max([int]$Cfg.CmdletTimeoutSec, 5), 600)
        $numDays.Value = [decimal][math]::Min([math]::Max([int]$Cfg.DaysToScan, 1), 90)
        $numEvents.Value = [decimal][math]::Min([math]::Max([int]$Cfg.MaxEvents, 20), 10000)
        $chkOpen.Checked = [bool]$Cfg.OpenReport
        $lblCfg.Text = "File: $script:WapCfgPath"
    }

    function Get-WapForm {
        $c = Get-WapDefaultConfig
        $c.OutputPath = $txtOut.Text.Trim()
        $c.CmdletTimeoutSec = [int]$numTimeout.Value
        $c.DaysToScan = [int]$numDays.Value
        $c.MaxEvents = [int]$numEvents.Value
        $c.OpenReport = [bool]$chkOpen.Checked
        $c
    }

    function Update-WapAudits {
        $grid.Rows.Clear()
        $dir = $txtOut.Text.Trim()
        $lblLast.Text = 'Nessun audit nella cartella di output.'
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { return }
        $list = @(Get-WapAuditList $dir)
        foreach ($r in $list) {
            $idx = $grid.Rows.Add(@($r.File, $r.Data, $r.Score, $r.Critici, $r.Warning, $r.Ruolo, $r.KB))
            $grid.Rows[$idx].Tag = $r
            if ($r.Critici -and $r.Critici -ne '0') { $grid.Rows[$idx].Cells['Critici'].Style.ForeColor = [System.Drawing.Color]::Firebrick }
        }
        if ($list.Count) {
            $l = $list[0]
            $lblLast.Text = "Ultimo audit: $($l.Data)   Score: $($l.Score)/100   Critici: $($l.Critici)   Warning: $($l.Warning)   ($($list.Count) audit salvati)"
        }
    }

    function Get-WapSelected {
        @($grid.SelectedRows | ForEach-Object { $_.Tag } | Where-Object { $_ } | Sort-Object Time)
    }

    function Set-WapBusy([bool]$On, [string]$Text) {
        foreach ($b in @($bAudit, $bJson, $bReport, $bOpt, $bDry, $bCmp, $bConsole, $btnSave, $btnSaveAs, $btnLoad, $btnDef)) { $b.Enabled = -not $On }
        $tl.Enabled = -not $On
        $btnCancel.Enabled = $On -and ($script:ChildAction -ne 'Optimize')
        if ($On) { $prog.MarqueeAnimationSpeed = 30 } else { $prog.MarqueeAnimationSpeed = 0 }
        $lblStatus.Text = $Text
    }

    function Start-WapChild([string]$Act, [string]$Extra) {
        $cfg = Get-WapForm
        if (-not $cfg.OutputPath) { [void][System.Windows.Forms.MessageBox]::Show('Indicare la cartella di output.', 'WinAuditPro', 'OK', 'Warning'); return }
        $runCfg = Join-Path $script:WapDataDir 'run-config.json'
        try { Save-WapConfig $cfg $runCfg }
        catch { [void][System.Windows.Forms.MessageBox]::Show("Impossibile preparare l'esecuzione: $($_.Exception.Message)", 'WinAuditPro', 'OK', 'Error'); return }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$script:WapScriptPath`" -Action $Act -ConfigPath `"$runCfg`" -OutputPath `"$($cfg.OutputPath)`" $Extra"
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        $script:ChildAction = $Act
        Add-WapLog ('=== {0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $Act) 'STEP'
        try { $script:Child = [System.Diagnostics.Process]::Start($psi) }
        catch { Add-WapLog "Avvio non riuscito: $($_.Exception.Message)" 'ERROR'; return }
        $script:OutTask = $script:Child.StandardOutput.ReadLineAsync()
        $script:ErrTask = $script:Child.StandardError.ReadLineAsync()
        Set-WapBusy $true "In corso: $Act"
    }

    function Receive-WapChild {
        if (-not $script:Child) { return }
        $n = 0
        while ($script:OutTask -and $script:OutTask.IsCompleted -and $n -lt 400) {
            $line = $script:OutTask.Result
            if ($null -eq $line) { $script:OutTask = $null; break }
            Add-WapLog $line
            $n++
            $script:OutTask = $script:Child.StandardOutput.ReadLineAsync()
        }
        while ($script:ErrTask -and $script:ErrTask.IsCompleted -and $n -lt 800) {
            $line = $script:ErrTask.Result
            if ($null -eq $line) { $script:ErrTask = $null; break }
            if ($line.Trim()) { Add-WapLog $line 'ERROR' }
            $n++
            $script:ErrTask = $script:Child.StandardError.ReadLineAsync()
        }
        if (-not $script:OutTask -and -not $script:ErrTask -and $script:Child.HasExited) {
            $code = $script:Child.ExitCode
            $act = $script:ChildAction
            $script:Child.Dispose()
            $script:Child = $null
            if ($code -eq 0) { Add-WapLog "=== $act terminato correttamente." 'OK' }
            else { Add-WapLog "=== $act terminato con errori (codice $code)." 'ERROR' }
            $script:ChildAction = ''
            Set-WapBusy $false 'Pronto.'
            Update-WapAudits
            if ($script:CloseWhenDone) { $form.Close() }
        }
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 150
    $timer.Add_Tick({ Receive-WapChild })

    # ---------------------------------------------------------- eventi
    $btnOut.Add_Click({
        $d = New-Object System.Windows.Forms.FolderBrowserDialog
        $d.ShowNewFolderButton = $true
        if ($txtOut.Text -and (Test-Path -LiteralPath $txtOut.Text)) { $d.SelectedPath = $txtOut.Text }
        if ($d.ShowDialog() -eq 'OK') { $txtOut.Text = $d.SelectedPath; Update-WapAudits }
    })
    $txtOut.Add_Leave({ Update-WapAudits })
    $btnSave.Add_Click({
        try { Save-WapConfig (Get-WapForm) $script:WapCfgPath; $lblCfg.Text = "File: $script:WapCfgPath (salvato)" }
        catch { [void][System.Windows.Forms.MessageBox]::Show("Salvataggio non riuscito: $($_.Exception.Message)", 'WinAuditPro', 'OK', 'Error') }
    })
    $btnSaveAs.Add_Click({
        $d = New-Object System.Windows.Forms.SaveFileDialog
        $d.Filter = 'Configurazione (*.json)|*.json'; $d.FileName = 'config.json'
        if (Test-Path -LiteralPath $script:WapDataDir) { $d.InitialDirectory = $script:WapDataDir }
        if ($d.ShowDialog() -eq 'OK') {
            try { Save-WapConfig (Get-WapForm) $d.FileName; $script:WapCfgPath = $d.FileName; $lblCfg.Text = "File: $script:WapCfgPath (salvato)" }
            catch { [void][System.Windows.Forms.MessageBox]::Show("Salvataggio non riuscito: $($_.Exception.Message)", 'WinAuditPro', 'OK', 'Error') }
        }
    })
    $btnLoad.Add_Click({
        $d = New-Object System.Windows.Forms.OpenFileDialog
        $d.Filter = 'Configurazione (*.json)|*.json'
        if (Test-Path -LiteralPath $script:WapDataDir) { $d.InitialDirectory = $script:WapDataDir }
        if ($d.ShowDialog() -eq 'OK') { $script:WapCfgPath = $d.FileName; Set-WapForm (Read-WapConfig $d.FileName); Update-WapAudits }
    })
    $btnDef.Add_Click({ Set-WapForm (Get-WapDefaultConfig); Update-WapAudits })

    $bAudit.Add_Click({ Start-WapChild 'Audit' '' })
    $bJson.Add_Click({ Start-WapChild 'AuditJson' '' })
    $bReport.Add_Click({
        $sel = @(Get-WapSelected)
        $extra = ''
        if ($sel.Count -ge 1) { $extra = "-JsonPath `"$($sel[-1].Path)`"" }
        Start-WapChild 'Report' $extra
    })
    $bOpenRep.Add_Click({
        $dir = $txtOut.Text.Trim()
        $h = @(Get-ChildItem -LiteralPath $dir -Filter '*_Report_*.html' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        if ($h.Count) { Start-Process $h[0].FullName } else { [void][System.Windows.Forms.MessageBox]::Show('Nessun report HTML nella cartella di output.', 'WinAuditPro') }
    })
    $bOpt.Add_Click({
        $sel = @(Get-WapSelected)
        $extra = ''
        if ($sel.Count -ge 1) { $extra = "-JsonPath `"$($sel[-1].Path)`"" }
        Start-WapChild 'Optimize' $extra
    })
    $bDry.Add_Click({
        $sel = @(Get-WapSelected)
        $extra = ''
        if ($sel.Count -ge 1) { $extra = "-JsonPath `"$($sel[-1].Path)`"" }
        Start-WapChild 'DryRun' $extra
    })
    $bCmp.Add_Click({
        $sel = @(Get-WapSelected)
        if ($sel.Count -ne 2) { [void][System.Windows.Forms.MessageBox]::Show('Selezionare esattamente 2 audit (Ctrl+clic).', 'WinAuditPro', 'OK', 'Information'); return }
        Start-WapChild 'Compare' "-BaselinePath `"$($sel[0].Path)`" -CurrentPath `"$($sel[1].Path)`""
    })
    $bFolder.Add_Click({
        $dir = $txtOut.Text.Trim()
        if ($dir -and (Test-Path -LiteralPath $dir)) { Start-Process explorer.exe $dir }
    })
    $bConsole.Add_Click({
        $a = "-NoProfile -ExecutionPolicy Bypass -File `"$script:WapScriptPath`" -Console -OutputPath `"$($txtOut.Text.Trim())`""
        Start-Process powershell.exe -ArgumentList $a
    })
    $grid.Add_CellDoubleClick({ $bReport.PerformClick() })

    $btnCancel.Add_Click({
        if ($script:Child -and -not $script:Child.HasExited) {
            $r = [System.Windows.Forms.MessageBox]::Show("Interrompere $($script:ChildAction)?`nL'audit e i report sono in sola lettura: interromperli non modifica il server.", 'WinAuditPro', 'YesNo', 'Question')
            if ($r -eq 'Yes') {
                try { $script:Child.Kill() } catch { }
                Add-WapLog 'Interrotto dall''operatore.' 'WARN'
            }
        }
    })

    $form.Add_FormClosing({
        param($s, $e)
        if ($script:Child -and -not $script:Child.HasExited) {
            $e.Cancel = $true
            if ($script:ChildAction -eq 'Optimize') {
                [void][System.Windows.Forms.MessageBox]::Show('Chiudere prima la finestra delle ottimizzazioni.', 'WinAuditPro', 'OK', 'Information')
                return
            }
            $r = [System.Windows.Forms.MessageBox]::Show("$($script:ChildAction) in corso. Interrompere e chiudere?", 'WinAuditPro', 'YesNo', 'Question')
            if ($r -eq 'Yes') { $script:CloseWhenDone = $true; try { $script:Child.Kill() } catch { } }
        }
    })

    $form.Add_Shown({
        Set-WapForm $script:WapCfg
        Update-WapAudits
        Add-WapLog "WinAuditPro $script:WapVersion su $env:COMPUTERNAME. Configurazione: $script:WapCfgPath" 'STEP'
        $timer.Start()
    })

    [void]$form.ShowDialog()
    $timer.Stop()
    $form.Dispose()
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

if ($Action) {
    $rc = @(Invoke-WapAction $Action)
    exit ([int]$rc[-1])
}
if ($Console -or $Quick) {
    Invoke-MainMenu -MenuOutputPath $OutputPath
    return
}
if ($NoGui) {
    $rc = @(Invoke-WapAction 'Audit')
    exit ([int]$rc[-1])
}
Show-WapGui

