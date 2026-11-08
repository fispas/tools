<#
.SYNOPSIS
    Compattazione offline dei VHDX FSLogix non in uso - CompactVHDX.

.DESCRIPTION
    Eseguito dai task FSLogix-CompactVHDX (pianificato) e FSLogix-CompactVHDX-Manual
    (esecuzione immediata da CompactVHDX Manager), come SYSTEM.

    Per ogni VHDX in ProfilePath (config.json):
      - salta i dischi in uso (aperti via SMB, montati, non apribili in esclusiva)
      - salta gli utenti in elenco di esclusione
      - diskpart: attach vdisk readonly -> compact vdisk -> detach vdisk
      - misura la dimensione prima e dopo
    Alla fine: CSV e log, report HTML della run, storico (history.csv) e report
    dell'andamento, eventi nel Registro applicazioni (sorgente CompactVHDX), email
    (se configurata), pulizia di log e report vecchi.

    Stop pulito: file STOP in C:\Scripts\CompactVHDX (lo crea CompactVHDX Manager o
    Stop-CompactVHDX.ps1). Il disco in corso viene completato, poi lo script esce.
    NON terminare il processo: un disco in lavorazione resterebbe agganciato.

.PARAMETER Path
    Una o piu' cartelle dei profili (default: ProfilePaths in config.json).
.PARAMETER User
    Elabora solo il VHDX dell'utente indicato.
.PARAMETER MaxDisks
    Numero massimo di dischi da elaborare, dai più grandi (0 = tutti).
.PARAMETER StopAt
    HH:mm: dopo quest'ora non vengono avviati nuovi dischi (prima occorrenza dopo l'avvio).
.PARAMETER Trigger
    Etichetta della run nello storico (Pianificata / Manuale).
.PARAMETER WhatIf
    Simulazione: nessun disco viene toccato.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$User,
    [int]$MaxDisks = 0,
    [string]$StopAt,
    [string]$Trigger = 'Manuale',
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'CompactVHDX-Common.ps1')

$cfg = Get-CVConfig
$Paths = if ($Path) { @($Path) } else { Get-CVProfilePaths $cfg }
$PathText = $Paths -join '; '
$ReportDir = $cfg.ReportDir
foreach ($d in $script:CVLogDir, $script:CVDataDir, $ReportDir) { New-Item -ItemType Directory -Path $d -Force | Out-Null }

$startTime  = Get-Date
$stamp      = $startTime.ToString('yyyyMMdd_HHmmss')
$log        = Join-Path $script:CVLogDir "Compact_$stamp.log"
$csv        = Join-Path $script:CVLogDir "Compact_$stamp.csv"
$reportPath = Join-Path $ReportDir "Report_CompactVHDX_$stamp.html"
$historyReport = Get-CVHistoryReportPath $cfg
$exclude    = @($cfg.ExcludeUsers | ForEach-Object { "$_".Trim().ToLower() } | Where-Object { $_ })
$errFile    = Join-Path $script:CVLogDir "Errori_$stamp.log"
$errAll     = $script:CVIssuesLog
$transcript = Join-Path $script:CVLogDir "Transcript_$stamp.txt"
$cnt = @{ Index = 0; Total = 0; Ok = 0; Skipped = 0; Excluded = 0; Errors = 0; SavedMB = 0; Warnings = 0 }
$deadline = $null
$issues = New-Object System.Collections.Generic.List[object]
$script:lastError = ''
$script:Utf8 = New-Object System.Text.UTF8Encoding($true)

try { Start-Transcript -Path $transcript -Force | Out-Null } catch { }

function Add-LineSafe([string]$File, [string]$Text) {
    # il file puo' essere momentaneamente aperto da altri processi (antivirus, pannello): ritenta
    for ($i = 1; $i -le 8; $i++) {
        try { [IO.File]::AppendAllText($File, $Text + "`r`n", $script:Utf8); return $true }
        catch { Start-Sleep -Milliseconds (150 * $i) }
    }
    $false
}

function Log([string]$m) {
    $l = '{0}  {1}' -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $l
    [void](Add-LineSafe $log $l)
}

function Write-Issue {
    # Registra errori e avvisi: log della run, file Errori_<run>.log, file cumulativo
    # Errori_e_avvisi.log (salvo -RunOnly) e sezione "Errori e avvisi" del report
    param(
        [ValidateSet('ERRORE', 'AVVISO')][string]$Level,
        [string]$Message,
        $ErrorRecord,
        [switch]$RunOnly
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $lines = @("$ts  [$Level]  $Message")
    $detail = ''
    if ($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        $detail = $ex.Message
        $lines += "      Tipo:      $($ex.GetType().FullName)"
        $lines += "      Messaggio: $($ex.Message)"
        if ($ex.InnerException) { $lines += "      Causa:     $($ex.InnerException.Message)"; $detail += " - $($ex.InnerException.Message)" }
        $ii = $ErrorRecord.InvocationInfo
        if ($ii -and $ii.ScriptLineNumber) { $lines += "      Posizione: $(Split-Path $ii.ScriptName -Leaf) riga $($ii.ScriptLineNumber): $("$($ii.Line)".Trim())" }
        if ($ErrorRecord.ScriptStackTrace) { $ErrorRecord.ScriptStackTrace -split "`n" | ForEach-Object { $lines += "      Stack:     $($_.Trim())" } }
    }
    $text = $lines -join "`r`n"
    [void](Add-LineSafe $errFile $text)
    if (-not $RunOnly) { [void](Add-LineSafe $errAll ("[run $stamp] " + $text)) }
    $issues.Add([pscustomobject]@{ Ora = $ts; Livello = $Level; Messaggio = $Message; Dettaglio = $detail; RunOnly = [bool]$RunOnly })
    if ($Level -eq 'ERRORE') { $script:lastError = "$Message$(if ($detail) { ": $detail" })" } else { $cnt.Warnings++ }
    Log "[$Level] $Message$(if ($detail) { " - $detail" })"
}

function Write-Status([string]$State, [string]$Current = '') {
    try {
        [ordered]@{
            State    = $State
            Pid      = $PID
            RunId    = $stamp
            Trigger  = $Trigger
            Start    = $startTime.ToString('yyyy-MM-dd HH:mm:ss')
            Updated  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            StopAt   = $(if ($deadline) { $deadline.ToString('yyyy-MM-dd HH:mm') } else { '' })
            Index    = $cnt.Index
            Total    = $cnt.Total
            Current  = $Current
            Ok       = $cnt.Ok
            Skipped  = $cnt.Skipped
            Excluded = $cnt.Excluded
            Errors   = $cnt.Errors
            SavedMB  = $cnt.SavedMB
            Warnings = $cnt.Warnings
            LastError = $script:lastError
            Log      = $log
            ErrorsFile = $errFile
            Report   = $reportPath
            WhatIf   = [bool]$WhatIf
        } | ConvertTo-Json | ForEach-Object { Write-CVFileAtomic -Path $script:CVStatus -Text $_ }
    } catch { }
}

function Invoke-Diskpart([string[]]$Commands) {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        Set-Content -LiteralPath $tmp -Value $Commands -Encoding ASCII
        $out  = & diskpart.exe /s $tmp 2>&1
        $code = $LASTEXITCODE
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    [pscustomobject]@{ Code = $code; Output = (($out | ForEach-Object { "$_" }) -join ' | ') }
}

$script:HasSmb = Test-CVHasCommand 'Get-SmbOpenFile'
$script:HasDiskImage = Test-CVHasCommand 'Get-DiskImage'

function Get-InUseReason([string]$File) {
    if ($script:HasSmb) {
        $smb = @(Get-SmbOpenFile -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $File })
        if ($smb.Count) { return "aperto via SMB da $(($smb | ForEach-Object { $_.ClientComputerName } | Sort-Object -Unique) -join ',')" }
    }
    if ($script:HasDiskImage) {
        $img = Get-DiskImage -ImagePath $File -ErrorAction SilentlyContinue
        if ($img -and $img.Attached) { return 'montato localmente' }
    }
    try {
        $fs = [IO.File]::Open($File, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $fs.Close()
    } catch {
        return "non apribile in esclusiva ($($_.Exception.InnerException.Message))"
    }
    return $null
}

function Get-VhdxFiles([string]$Root) {
    # esclusi gli hard link temporanei della cartella CompactVHDX.tmp (stesso file, altro nome)
    @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.vhdx?$' -and -not $_.DirectoryName.EndsWith('\CompactVHDX.tmp', [StringComparison]::OrdinalIgnoreCase) })
}

$stoppedByTime = $false
$stoppedByRequest = $false
$results = New-Object System.Collections.Generic.List[object]

try {
    if ($script:CVConfigIssue) { throw "Configurazione non valida: $script:CVConfigIssue" }
    if (-not $Paths.Count) { throw 'Nessuna cartella dei profili configurata: completa la configurazione guidata in CompactVHDX Manager.' }
    foreach ($p in $Paths) { if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "Cartella profili non trovata: $p" } }
    if (Test-Path -LiteralPath $script:CVStopFile) {
        Remove-Item -LiteralPath $script:CVStopFile -Force
        Write-Issue AVVISO 'Rimosso file di stop residuo di un''esecuzione precedente'
    }
    if (-not $WhatIf) {
        foreach ($m in (Dismount-CVLeftovers $Paths)) {
            Write-Issue $(if ($m -like 'ERRORE*') { 'ERRORE' } else { 'AVVISO' }) "Pulizia iniziale (disco rimasto agganciato da un'esecuzione interrotta) - $m"
        }
        Remove-CVStaleLinks $Paths
    }

    # sessioni RDS: chi ha una sessione aperta (anche disconnessa) potrebbe riagganciare il profilo durante la compattazione
    $sessionHosts = @()
    $script:Sessions = $null
    if ($cfg.SkipActiveSessions) {
        $sessionHosts = @(Get-CVSessionHosts $cfg)
        if ($sessionHosts.Count) { Log "Controllo sessioni RDS attivo su: $($sessionHosts -join ', ')" }
        else { Write-Issue AVVISO 'Controllo delle sessioni RDS non attivo: nessun session host indicato nelle impostazioni ne'' rilevabile dal Connection Broker.' -RunOnly }
    }
    function Test-UserSession([string]$Name, [switch]$Fresh) {
        if (-not $sessionHosts.Count) { return $false }
        if ($Fresh -or -not $script:Sessions -or ((Get-Date) - $script:Sessions.When).TotalSeconds -gt 60) {
            $script:Sessions = Get-CVSessionUsers $sessionHosts
            foreach ($e in $script:Sessions.Errors) { if (-not $script:SessionErrLogged) { Write-Issue AVVISO "Sessioni RDS non leggibili da $e" -RunOnly } }
            if ($script:Sessions.Errors.Count) { $script:SessionErrLogged = $true }
        }
        $script:Sessions.Users.Contains($Name)
    }

    $volBefore = Get-CVVolumeInfo $Paths
    $allVhd = @(foreach ($p in $Paths) { Get-VhdxFiles $p })
    $totalBeforeMB = [math]::Round(($allVhd | Measure-Object -Property Length -Sum).Sum / 1MB)

    $files = $allVhd
    if ($User) { $files = @($files | Where-Object { (Get-CVUserFromFolder $_.Directory.Name) -eq $User }) }
    $files = @($files | Sort-Object Length -Descending)
    if ($MaxDisks -gt 0) { $files = @($files | Select-Object -First $MaxDisks) }
    $cnt.Total = $files.Count

    if ($StopAt) {
        $deadline = (Get-Date).Date.Add(([datetime]::ParseExact($StopAt, 'HH:mm', $null)).TimeOfDay)
        if ($deadline -le (Get-Date)) { $deadline = $deadline.AddDays(1) }
    }

    $mode = if ($WhatIf) { ' [SIMULAZIONE]' } else { '' }
    Log ("Compattazione offline VHDX$mode ($Trigger) - $PathText - dischi da elaborare: $($files.Count)" +
         $(if ($deadline) { " - stop alle $($deadline.ToString('dd/MM HH:mm'))" } else { '' }) +
         $(if ($exclude.Count) { " - esclusi: $($exclude -join ', ')" } else { '' }))
    Write-Status 'running'
    Write-CVEvent 1000 "Avvio compattazione VHDX$mode ($Trigger) su $PathText - dischi: $($files.Count). Log: $log"

    foreach ($f in $files) {
        if (Test-Path -LiteralPath $script:CVStopFile) {
            $stoppedByRequest = $true
            Write-Issue AVVISO "Stop manuale richiesto: nessun nuovo disco avviato dopo il $($cnt.Index) di $($cnt.Total)"
            Write-Status 'stopping'
            break
        }
        if ($deadline -and (Get-Date) -ge $deadline) {
            $stoppedByTime = $true
            Write-Issue AVVISO "Raggiunto l'orario di stop ($($deadline.ToString('HH:mm'))): nessun nuovo disco avviato dopo il $($cnt.Index) di $($cnt.Total)"
            Write-Status 'stopping'
            break
        }

        $row = $null
        $tag = "[$($cnt.Index + 1)/$($cnt.Total)] $($f.Name)"
        try {
            $cnt.Index++
            $userName = Get-CVUserFromFolder $f.Directory.Name
            $tag = "[$($cnt.Index)/$($cnt.Total)] $($f.Name)"
            Write-Status 'running' ('{0} ({1:N0} MB)' -f $f.Name, ($f.Length / 1MB))
            $row = [ordered]@{
                Utente    = $userName
                Tipo      = Get-CVDiskKind $f.Name
                File      = $f.FullName
                BeforeMB  = [math]::Round($f.Length / 1MB)
                AfterMB   = $null
                SavedMB   = $null
                Esito     = ''
                DurataSec = $null
            }

            if ($exclude -contains $userName.ToLower()) {
                $row.Esito = 'ESCLUSO'
                $cnt.Excluded++
                Log "${tag}: escluso da configurazione"
                $results.Add([pscustomobject]$row); continue
            }
            $diskType = Get-CVDiskType $f.FullName
            if ($diskType -in @('Fisso', 'Differenziale')) {
                $row.Esito = "SALTATO: disco $($diskType.ToLower()) (la compattazione non riduce questo tipo di disco)"
                $cnt.Skipped++
                Log "${tag}: $($row.Esito)"
                $results.Add([pscustomobject]$row); continue
            }
            if (Test-UserSession $userName) {
                $row.Esito = 'SALTATO: utente con sessione RDS aperta'
                $cnt.Skipped++
                Log "${tag}: $($row.Esito)"
                $results.Add([pscustomobject]$row); continue
            }
            $reason = Get-InUseReason $f.FullName
            if ($reason) {
                $row.Esito = "SALTATO: $reason"
                $cnt.Skipped++
                Write-Issue AVVISO "${tag}: $($row.Esito)" -RunOnly
                $results.Add([pscustomobject]$row); continue
            }
            if ($WhatIf) {
                $row.Esito = 'DA COMPATTARE'
                Log "${tag}: $($row.BeforeMB) MB - verrebbe compattato"
                $results.Add([pscustomobject]$row); continue
            }

            # percorso con caratteri non ASCII: diskpart lavora su un hard link temporaneo con nome ASCII (stesso file)
            $target = $f.FullName
            $link = $null
            if ($target -match '[^\x20-\x7E]') {
                try { $link = New-CVAsciiLink $target; $target = $link; Log "${tag}: percorso non ASCII, uso l'hard link temporaneo $link" }
                catch {
                    $row.Esito = "SALTATO: percorso non ASCII ($($_.Exception.Message))"
                    $cnt.Skipped++
                    Write-Issue AVVISO "${tag}: $($row.Esito)" -RunOnly
                    $results.Add([pscustomobject]$row); continue
                }
            }
            Log "${tag}: compattazione in corso ($($row.BeforeMB) MB)..."
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try {
                $r = Invoke-Diskpart @(
                    "select vdisk file=`"$target`""
                    'attach vdisk readonly'
                    'compact vdisk'
                    'detach vdisk'
                )
            } finally { $sw.Stop() }
            $row.DurataSec = [math]::Round($sw.Elapsed.TotalSeconds, 1)

            if ($r.Code -ne 0) {
                $row.Esito = "ERRORE diskpart (codice $($r.Code))"
                Write-Issue ERRORE "${tag}: diskpart ha restituito il codice $($r.Code). Output: $($r.Output)"
                $img = if ($script:HasDiskImage) { Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue } else { $null }
                if ($img -and $img.Attached) {
                    Invoke-Diskpart @("select vdisk file=`"$target`"", 'detach vdisk') | Out-Null
                    Write-Issue AVVISO "${tag}: eseguito detach di sicurezza dopo l'errore di diskpart"
                }
            } else {
                $row.Esito = 'OK'
                # verifica: il disco non deve restare agganciato al server dopo il detach
                $img = if ($script:HasDiskImage) { Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue } else { $null }
                if ($img -and $img.Attached) {
                    $d = Invoke-Diskpart @("select vdisk file=`"$target`"", 'detach vdisk')
                    $img = Get-DiskImage -ImagePath $target -ErrorAction SilentlyContinue
                    if ($img -and $img.Attached) {
                        $row.Esito = 'ERRORE: disco rimasto agganciato dopo la compattazione'
                        Write-Issue ERRORE "${tag}: il disco e' rimasto agganciato e il detach di sicurezza non e' riuscito (codice $($d.Code)). L'utente non potra' accedere finche' non viene sganciato."
                    } else {
                        Write-Issue AVVISO "${tag}: disco rimasto agganciato dopo diskpart, sganciato con detach di sicurezza"
                    }
                }
            }

            if ($link) { Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue; $link = $null }
            if ((Test-UserSession $userName -Fresh)) {
                Write-Issue AVVISO "${tag}: l'utente $userName ha aperto una sessione durante la compattazione: verificare che il profilo sia stato caricato correttamente" -RunOnly
            }
            $row.AfterMB = [math]::Round((Get-Item -LiteralPath $f.FullName -Force).Length / 1MB)
            $row.SavedMB = $row.BeforeMB - $row.AfterMB
            if ($row.Esito -eq 'OK') { $cnt.Ok++; $cnt.SavedMB += $row.SavedMB } else { $cnt.Errors++ }
            Log ('{0}: {1} MB -> {2} MB (recuperati {3} MB) in {4}s - {5}' -f $tag, $row.BeforeMB, $row.AfterMB, $row.SavedMB, $row.DurataSec, $row.Esito)
            $results.Add([pscustomobject]$row)
        } catch {
            # un errore su un disco non deve fermare la run: si registra e si passa al successivo
            $err = $_
            $cnt.Errors++
            Write-Issue ERRORE "${tag}: errore imprevisto durante l'elaborazione del disco" $err
            $tp = $f.FullName
            if ($link) { $tp = $link }
            try {
                $img = if ($script:HasDiskImage) { Get-DiskImage -ImagePath $tp -ErrorAction Stop } else { $null }
                if ($img -and $img.Attached) {
                    Invoke-Diskpart @("select vdisk file=`"$tp`"", 'detach vdisk') | Out-Null
                    Write-Issue AVVISO "${tag}: eseguito detach di sicurezza dopo l'errore"
                }
            } catch { }
            # l'hard link si elimina solo dopo lo sgancio
            if ($link) { Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue; $link = $null }
            if (-not $row) {
                $row = [ordered]@{ Utente = (Get-CVUserFromFolder $f.Directory.Name); Tipo = (Get-CVDiskKind $f.Name); File = $f.FullName; BeforeMB = [math]::Round($f.Length / 1MB); AfterMB = $null; SavedMB = $null; Esito = ''; DurataSec = $null }
            }
            $row.Esito = "ERRORE: $($err.Exception.Message)"
            $results.Add([pscustomobject]$row)
        }
    }
} catch {
    $fatal = $_.Exception.Message
    try { Write-Issue ERRORE 'Errore imprevisto: la run si interrompe' $_ } catch { }
    Write-CVEvent 1005 "Errore imprevisto nella compattazione VHDX: $fatal. Dettagli: $errFile" 'Error'
}

# ---------------------------------------------------------------- chiusura
try {
    if ($results.Count) { $results | Export-Csv -LiteralPath $csv -NoTypeInformation -Delimiter ';' -Encoding UTF8 }
    $endTime  = Get-Date
    $volAfter = Get-CVVolumeInfo $Paths
    $totalAfterMB = [math]::Round((@(foreach ($p in $Paths) { Get-VhdxFiles $p }) | Measure-Object -Property Length -Sum).Sum / 1MB)
    $notDone  = [math]::Max(0, $cnt.Total - $results.Count)
    $okRows   = @($results | Where-Object { $_.Esito -eq 'OK' })
    $avgSec   = if ($okRows.Count) { [math]::Round(($okRows | Measure-Object -Property DurataSec -Average).Average, 1) } else { 0 }
    $stopReason = if ($fatal) { 'errore' } elseif ($stoppedByRequest) { 'manuale' } elseif ($stoppedByTime) { 'orario' } else { 'nessuna' }
    $duration = ($endTime - $startTime).TotalSeconds

    $alert = ''
    if ($volAfter -and $volAfter.FreePct -lt $cfg.FreeAlertPct) {
        $alert = "Spazio libero sul volume $($volAfter.Drive) al $($volAfter.FreePct)% ($($volAfter.FreeGB) GB): sotto la soglia del $($cfg.FreeAlertPct)%."
        Write-CVEvent 1004 $alert 'Warning'
        Write-Issue AVVISO $alert
    }
    if ($fatal) { $alert = "Errore imprevisto: $fatal. $alert" }

    Log ('Totale: compattati {0}, saltati {1}, esclusi {2}, errori {3}, non elaborati {4} (interruzione: {5}), recuperati {6:N0} MB' -f `
        $cnt.Ok, $cnt.Skipped, $cnt.Excluded, $cnt.Errors, $notDone, $stopReason, [double]$cnt.SavedMB)

    # report della run
    $info = [ordered]@{
        'Tipo'                 = "$Trigger$(if ($WhatIf) { ' (simulazione)' })"
        'Avvio'                = $startTime.ToString('dd/MM/yyyy HH:mm:ss')
        'Fine'                 = $endTime.ToString('dd/MM/yyyy HH:mm:ss')
        'Orario di stop'       = $(if ($deadline) { $deadline.ToString('dd/MM/yyyy HH:mm') } else { 'nessuno' })
        'Interruzione'         = $(switch ($stopReason) { 'manuale' { 'stop manuale' } 'orario' { 'orario di stop raggiunto' } 'errore' { 'errore imprevisto' } default { 'nessuna: completata' } })
        'Filtro'               = "$(if ($User) { "utente $User" } else { 'tutti gli utenti' })$(if ($MaxDisks -gt 0) { ", max $MaxDisks dischi" })"
        'Peso VHDX prima/dopo' = ('{0:N0} MB / {1:N0} MB' -f $totalBeforeMB, $totalAfterMB)
        'Volume libero prima'  = $(if ($volBefore) { "$($volBefore.FreeGB) GB ($($volBefore.FreePct)%)" } else { 'n/d' })
        'Volume libero dopo'   = $(if ($volAfter) { "$($volAfter.FreeGB) GB ($($volAfter.FreePct)%)" } else { 'n/d' })
        'Durata media per disco' = "$avgSec s"
        'Errori / avvisi'      = "$(@($issues | Where-Object { $_.Livello -eq 'ERRORE' }).Count) / $(@($issues | Where-Object { $_.Livello -eq 'AVVISO' }).Count)"
        'Log'                  = $log
        'Log errori e avvisi'  = $errFile
        'Trascrizione'         = $transcript
        'CSV'                  = $csv
    }
    $summary = @{
        RunId = $stamp; Mode = $(if ($WhatIf) { ' [SIMULAZIONE]' } else { '' }); Server = $env:COMPUTERNAME; Path = $PathText
        Total = $cnt.Total; Ok = $cnt.Ok; SavedMB = $cnt.SavedMB; Skipped = $cnt.Skipped; Excluded = $cnt.Excluded
        Errors = $cnt.Errors; NotDone = $notDone; Duration = (Format-CVDuration $duration); Alert = $alert; Info = $info
    }
    New-CVRunReport -Results $results -Summary $summary -File $reportPath -HistoryFile $historyReport -Issues @($issues | Where-Object { -not $_.RunOnly })
    Log "Report: $reportPath"

    # storico e andamento
    Add-CVHistory @{
        RunId = $stamp; Start = $startTime.ToString('yyyy-MM-dd HH:mm:ss'); End = $endTime.ToString('yyyy-MM-dd HH:mm:ss')
        DurationSec = [math]::Round($duration); Trigger = $Trigger; Simulation = [bool]$WhatIf
        Filter = "$User$(if ($MaxDisks -gt 0) { " max $MaxDisks" })"
        DisksTotal = $cnt.Total; Ok = $cnt.Ok; Skipped = $cnt.Skipped; Excluded = $cnt.Excluded; Errors = $cnt.Errors
        NotDone = $notDone; SavedMB = $cnt.SavedMB; VhdxTotalBeforeMB = $totalBeforeMB; VhdxTotalAfterMB = $totalAfterMB
        VolumeSizeGB = $(if ($volAfter) { $volAfter.SizeGB } else { '' })
        VolumeFreeBeforeGB = $(if ($volBefore) { $volBefore.FreeGB } else { '' })
        VolumeFreeAfterGB = $(if ($volAfter) { $volAfter.FreeGB } else { '' })
        AvgSecPerDisk = $avgSec; StopReason = $stopReason; Report = $reportPath; Csv = $(if ($results.Count) { $csv } else { '' })
    }
    New-CVHistoryReport -Config $cfg -File $historyReport
    Log "Andamento: $historyReport"

    # evento finale
    $msg = 'Compattazione VHDX{0} terminata ({1}): compattati {2}, saltati {3}, esclusi {4}, errori {5}, non elaborati {6}, recuperati {7:N0} MB in {8}. Report: {9}' -f `
        $(if ($WhatIf) { ' (simulazione)' } else { '' }), $stopReason, $cnt.Ok, $cnt.Skipped, $cnt.Excluded, $cnt.Errors, $notDone, [double]$cnt.SavedMB, (Format-CVDuration $duration), $reportPath
    if ($fatal -or $cnt.Errors) { Write-CVEvent 1002 $msg 'Error' }
    elseif ($stopReason -ne 'nessuna') { Write-CVEvent 1003 $msg 'Warning' }
    else { Write-CVEvent 1001 $msg }

    # email
    $hasIssues = [bool]($fatal -or $cnt.Errors -or $alert -or $stopReason -eq 'manuale')
    if ($cfg.Mail.Enabled -and -not $WhatIf -and (-not $cfg.Mail.OnlyOnIssues -or $hasIssues)) {
        try {
            $esito = if ($fatal -or $cnt.Errors) { 'ERRORI' } elseif ($alert) { 'ATTENZIONE' } else { 'OK' }
            $subject = "[CompactVHDX] $env:COMPUTERNAME - $esito - recuperati $('{0:N0}' -f [double]$cnt.SavedMB) MB"
            $body = "<p><b>Compattazione VHDX FSLogix - $env:COMPUTERNAME</b></p>" +
                    "<p>$(ConvertTo-CVHtml $msg)</p>" +
                    $(if ($alert) { "<p style='color:#c53030'><b>$(ConvertTo-CVHtml $alert)</b></p>" } else { '' }) +
                    '<p>In allegato il report della run e l''andamento storico.</p>'
            Send-CVMail -Config $cfg -Subject $subject -HtmlBody $body -Attachments @($reportPath, $historyReport)
            Log 'Email inviata'
        } catch {
            Write-Issue AVVISO 'Email di fine compattazione non inviata' $_
            Write-CVEvent 1005 "Email di fine compattazione non inviata: $($_.Exception.Message)" 'Warning'
        }
    }

    # pulizia
    $removed = Invoke-CVRetention $cfg
    if ($removed) { Log "Pulizia: eliminati $removed file di log/report più vecchi di $($cfg.RetentionDays) giorni" }
} catch {
    try { Write-Issue ERRORE 'Errore nella fase di chiusura (report, storico, email)' $_ } catch { }
    Write-CVEvent 1005 "Errore in chiusura della compattazione VHDX: $($_.Exception.Message). Dettagli: $errFile" 'Error'
} finally {
    $final = if ($fatal) { 'error' } elseif ($stoppedByRequest) { 'stopped' } elseif ($stoppedByTime) { 'stopped-time' } else { 'done' }
    Write-Status $final
    if (Test-Path -LiteralPath $script:CVStopFile) { Remove-Item -LiteralPath $script:CVStopFile -Force -ErrorAction SilentlyContinue }
    try { Stop-Transcript | Out-Null } catch { }
}
