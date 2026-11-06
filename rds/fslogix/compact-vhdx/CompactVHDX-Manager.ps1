<#
.SYNOPSIS
    CompactVHDX Manager - pannello di controllo della compattazione offline dei VHDX FSLogix.

.DESCRIPTION
    Interfaccia grafica a schede:
      Situazione     analisi del volume e dei VHDX, report HTML della situazione
      Esecuzione     avvio immediato (anche simulato o limitato), monitor dal vivo,
                     stop pulito / forzato, sgancio dei dischi rimasti agganciati
      Pianificazione giornaliera, settimanale, mensile (giorni del mese o giorno della
                     settimana), orario di stop, console automatica per gli amministratori
      Report         elenco delle run, report della singola run, andamento storico
      Impostazioni   percorsi, esclusioni, soglie, conservazione, email

    La compattazione gira sempre come SYSTEM in un task: chiudere questa finestra non la
    interrompe.
#>
[CmdletBinding()]
param(
    [ValidateSet('Situazione', 'Esecuzione', 'Pianificazione', 'Report', 'Impostazioni')]
    [string]$StartTab = 'Situazione',
    [switch]$Auto
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'CompactVHDX-Common.ps1')
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --------------------------------------------------------------------- elevazione e istanza unica
if (-not (Test-CVAdmin)) {
    $a = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`" -StartTab $StartTab"
    if ($Auto) { $a += ' -Auto' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}
$created = $false
$script:mutex = New-Object System.Threading.Mutex($true, 'Local\CompactVHDXManager', [ref]$created)
if (-not $created) {
    if (-not $Auto) { [System.Windows.Forms.MessageBox]::Show('CompactVHDX Manager è già aperto in questa sessione.', 'CompactVHDX') | Out-Null }
    return
}

$script:cfg = Get-CVConfig
foreach ($d in $script:CVBase, $script:CVLogDir, $script:CVDataDir) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
if (-not (Test-Path -LiteralPath $script:CVConfig)) { Save-CVConfig $script:cfg }
Set-CVInstallInfo

# --------------------------------------------------------------------- helper UI
$script:Font     = New-Object System.Drawing.Font('Segoe UI', 9)
$script:FontBold = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$script:FontBig  = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
$script:FontMono = New-Object System.Drawing.Font('Consolas', 9)
$cOk   = [System.Drawing.Color]::FromArgb(30, 123, 74)
$cWarn = [System.Drawing.Color]::FromArgb(183, 121, 31)
$cErr  = [System.Drawing.Color]::FromArgb(197, 48, 48)
$cAcc  = [System.Drawing.Color]::FromArgb(43, 108, 176)
$cMut  = [System.Drawing.Color]::FromArgb(97, 110, 124)

function Add-Ctl($Parent, [string]$Type, [int]$X, [int]$Y, [int]$W, [int]$H, [hashtable]$Props = @{}) {
    $c = New-Object "System.Windows.Forms.$Type"
    $c.Location = New-Object System.Drawing.Point($X, $Y)
    $c.Size = New-Object System.Drawing.Size($W, $H)
    foreach ($k in $Props.Keys) { $c.$k = $Props[$k] }
    $Parent.Controls.Add($c)
    $c
}

function Show-Err([string]$m)  { [System.Windows.Forms.MessageBox]::Show($m, 'CompactVHDX', 'OK', 'Error') | Out-Null }
function Show-Info([string]$m) { [System.Windows.Forms.MessageBox]::Show($m, 'CompactVHDX', 'OK', 'Information') | Out-Null }
function Confirm-UI([string]$m) { [System.Windows.Forms.MessageBox]::Show($m, 'CompactVHDX', 'YesNo', 'Warning') -eq 'Yes' }

function Invoke-UI([scriptblock]$Action) {
    try {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        & $Action
    } catch {
        Show-Err $_.Exception.Message
    } finally {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
    }
}

function New-TimePicker($Parent, [int]$X, [int]$Y, [string]$Time) {
    $p = Add-Ctl $Parent 'DateTimePicker' $X $Y 80 24 @{ Format = 'Custom'; CustomFormat = 'HH:mm'; ShowUpDown = $true }
    $p.Value = [datetime]::Today.Add(([datetime]::ParseExact($Time, 'HH:mm', $null)).TimeOfDay)
    $p
}

function New-Tile($Parent, [int]$X, [int]$Y, [string]$Title) {
    $pn = Add-Ctl $Parent 'Panel' $X $Y 150 64 @{ BorderStyle = 'FixedSingle'; BackColor = [System.Drawing.Color]::White }
    $v = Add-Ctl $pn 'Label' 8 4 136 30 @{ Font = $script:FontBig; Text = '-' }
    [void](Add-Ctl $pn 'Label' 8 38 136 20 @{ ForeColor = $cMut; Text = $Title })
    $v
}

function ConvertTo-CVDataTable($Rows, [object[]]$Cols) {
    # Cols: @{ H = intestazione; P = proprieta' o scriptblock; T = tipo }
    $dt = New-Object System.Data.DataTable
    foreach ($c in $Cols) { [void]$dt.Columns.Add($c.H, $(if ($c.T) { $c.T } else { [string] })) }
    foreach ($r in @($Rows)) {
        $dr = $dt.NewRow()
        foreach ($c in $Cols) {
            $v = if ($c.P -is [scriptblock]) { & $c.P $r } else { $r.($c.P) }
            if ($v -is [string] -and $c.T -and $c.T -ne [string] -and $c.T -ne [datetime] -and "$v" -ne '') {
                $v = [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)   # CSV storico: punto decimale
            }
            if ($null -eq $v -or "$v" -eq '') { $dr[$c.H] = [DBNull]::Value }
            else { try { $dr[$c.H] = $v } catch { $dr[$c.H] = [DBNull]::Value } }
        }
        $dt.Rows.Add($dr)
    }
    , $dt
}

function New-Grid($Parent, [int]$X, [int]$Y, [int]$W, [int]$H) {
    Add-Ctl $Parent 'DataGridView' $X $Y $W $H @{
        ReadOnly = $true; AllowUserToAddRows = $false; AllowUserToDeleteRows = $false; RowHeadersVisible = $false
        SelectionMode = 'FullRowSelect'; AutoSizeColumnsMode = 'Fill'; BackgroundColor = [System.Drawing.Color]::White
        Anchor = 'Top,Bottom,Left,Right'
    }
}

# --------------------------------------------------------------------- finestra
$script:form = New-Object System.Windows.Forms.Form
$form.Text = "CompactVHDX Manager $script:CVVersion - $env:COMPUTERNAME"
$form.Size = New-Object System.Drawing.Size(1120, 780)
$form.MinimumSize = New-Object System.Drawing.Size(1000, 700)
$form.StartPosition = 'CenterScreen'
$form.Font = $script:Font

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$form.Controls.Add($tabs)

$strip = New-Object System.Windows.Forms.StatusStrip
$stLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$stLabel.Spring = $true
$stLabel.TextAlign = 'MiddleLeft'
[void]$strip.Items.Add($stLabel)
$form.Controls.Add($strip)

function New-Tab([string]$Name) {
    $t = New-Object System.Windows.Forms.TabPage
    $t.Text = $Name
    $t.Name = $Name
    $t.BackColor = [System.Drawing.Color]::FromArgb(245, 247, 250)
    $t.AutoScroll = $true
    $tabs.TabPages.Add($t)
    $t
}
$tSit = New-Tab 'Situazione'
$tRun = New-Tab 'Esecuzione'
$tSch = New-Tab 'Pianificazione'
$tRep = New-Tab 'Report'
$tSet = New-Tab 'Impostazioni'

# ===================================================================== SITUAZIONE
$btnAnalyze = Add-Ctl $tSit 'Button' 16 14 140 30 @{ Text = 'Analizza ora' }
$btnSitHtml = Add-Ctl $tSit 'Button' 166 14 170 30 @{ Text = 'Apri report situazione'; Enabled = $false }
$lblSit = Add-Ctl $tSit 'Label' 350 20 720 22 @{ ForeColor = $cMut; Text = 'Premi "Analizza ora" per leggere lo stato del volume e dei VHDX.' }
$lblSitAlert = Add-Ctl $tSit 'Label' 16 52 1060 22 @{ ForeColor = $cErr; Font = $script:FontBold; Text = '' }

$tile = @{}
$tileDefs = @(
    @('Vol', 'Volume'), @('Free', 'Libero'), @('Count', 'VHDX'), @('Total', 'Peso totale'), @('Avg', 'Media per profilo'),
    @('Max', 'Profilo più grande'), @('InUse', 'In uso adesso'), @('Stale', 'Inattivi'), @('Near', 'Oltre 80% limite'), @('Locks', 'Lock orfani'))
for ($i = 0; $i -lt $tileDefs.Count; $i++) {
    $x = 16 + ($i % 5) * 160; $y = 80 + [math]::Floor($i / 5) * 72
    $tile[$tileDefs[$i][0]] = New-Tile $tSit $x $y $tileDefs[$i][1]
}
[void](Add-Ctl $tSit 'Label' 16 232 60 22 @{ Text = 'Mostra:' })
$cmbView = Add-Ctl $tSit 'ComboBox' 76 228 300 24 @{ DropDownStyle = 'DropDownList' }
@('I 20 profili più grandi', 'Tutti i profili', 'Profili inattivi', 'Profili oltre l''80% del limite', 'Profili in uso adesso', 'Lock orfani') | ForEach-Object { [void]$cmbView.Items.Add($_) }
$cmbView.SelectedIndex = 0
$gridSit = New-Grid $tSit 16 260 1060 420

$script:inv = $null
$script:sitReport = $null
$diskCols = @(
    @{ H = 'Utente'; P = 'Utente' },
    @{ H = 'Dimensione MB'; P = 'SizeMB'; T = [double] },
    @{ H = '% limite'; P = 'PctOfMax'; T = [double] },
    @{ H = 'Ultima scrittura'; P = 'LastWrite'; T = [datetime] },
    @{ H = 'Giorni inattivo'; P = 'DaysIdle'; T = [int] },
    @{ H = 'In uso da'; P = 'InUseBy' },
    @{ H = 'File'; P = 'File' })

function Update-SitGrid {
    if (-not $script:inv) { return }
    $inv = $script:inv
    $dt = switch ($cmbView.SelectedIndex) {
        0 { ConvertTo-CVDataTable @($inv.Disks | Sort-Object SizeMB -Descending | Select-Object -First 20) $diskCols }
        1 { ConvertTo-CVDataTable @($inv.Disks | Sort-Object SizeMB -Descending) $diskCols }
        2 { ConvertTo-CVDataTable $inv.Stale $diskCols }
        3 { ConvertTo-CVDataTable $inv.NearMax $diskCols }
        4 { ConvertTo-CVDataTable @($inv.Disks | Where-Object { $_.InUse }) $diskCols }
        5 { ConvertTo-CVDataTable $inv.OrphanLocks @(@{ H = 'File'; P = 'File' }, @{ H = 'Ultima scrittura'; P = 'LastWrite'; T = [datetime] }) }
    }
    $gridSit.DataSource = $dt
}

$cmbView.Add_SelectedIndexChanged({ Invoke-UI { Update-SitGrid } })
$btnAnalyze.Add_Click({
    Invoke-UI {
        $lblSit.Text = 'Analisi in corso...'
        $form.Refresh()
        $script:inv = Get-CVInventory $script:cfg
        $inv = $script:inv
        $v = $inv.Volume
        if ($v) {
            $tile.Vol.Text = "$($v.SizeGB) GB"
            $tile.Free.Text = "$($v.FreeGB) GB"
            $tile.Free.ForeColor = $(if ($v.FreePct -lt $script:cfg.FreeAlertPct) { $cErr } else { $cOk })
        }
        $tile.Count.Text = $inv.Count
        $tile.Total.Text = '{0:N1} GB' -f ($inv.TotalMB / 1024)
        $tile.Avg.Text = '{0:N0} MB' -f $inv.AvgMB
        $tile.Max.Text = '{0:N0} MB' -f $inv.MaxMB
        $tile.InUse.Text = $inv.InUse
        $tile.Stale.Text = $inv.Stale.Count
        $tile.Near.Text = $inv.NearMax.Count
        $tile.Locks.Text = $inv.OrphanLocks.Count
        foreach ($k in 'Stale', 'Near', 'Locks') { $tile[$k].ForeColor = $(if ([int]$tile[$k].Text -gt 0) { $cWarn } else { [System.Drawing.Color]::Black }) }

        $alerts = @()
        if ($v -and $v.FreePct -lt $script:cfg.FreeAlertPct) { $alerts += "Spazio libero al $($v.FreePct)%: sotto la soglia del $($script:cfg.FreeAlertPct)%." }
        if ($inv.Leftovers.Count) { $alerts += "$($inv.Leftovers.Count) VHDX agganciati a questo server: usa 'Sgancia dischi rimasti' in Esecuzione." }
        $lblSitAlert.Text = $alerts -join '   '

        $script:sitReport = Join-Path $script:cfg.ReportDir ("Situazione_{0}.html" -f (Get-Date -Format 'yyyyMMdd_HHmm'))
        New-CVStatusReport -Config $script:cfg -Inventory $inv -File $script:sitReport
        $btnSitHtml.Enabled = $true
        $lblSit.Text = "Rilevata il $($inv.Collected.ToString('dd/MM/yyyy HH:mm:ss')) - $($inv.Path)"
        Update-SitGrid
    }
})
$btnSitHtml.Add_Click({ Invoke-UI { if ($script:sitReport) { Invoke-Item -LiteralPath $script:sitReport } } })

# ===================================================================== ESECUZIONE
$grpNew = Add-Ctl $tRun 'GroupBox' 16 10 1060 150 @{ Text = 'Nuova esecuzione immediata'; Anchor = 'Top,Left,Right' }
$rbAll  = Add-Ctl $grpNew 'RadioButton' 16 26 160 22 @{ Text = 'Tutti i dischi'; Checked = $true }
$rbUser = Add-Ctl $grpNew 'RadioButton' 16 54 120 22 @{ Text = 'Solo l''utente:' }
$txtUser = Add-Ctl $grpNew 'TextBox' 140 53 200 24 @{ Enabled = $false }
$chkMax = Add-Ctl $grpNew 'CheckBox' 16 84 170 22 @{ Text = 'Al massimo N dischi:' }
$numMax = Add-Ctl $grpNew 'NumericUpDown' 190 83 80 24 @{ Minimum = 1; Maximum = 10000; Value = 20; Enabled = $false }
$chkSim = Add-Ctl $grpNew 'CheckBox' 16 114 360 22 @{ Text = 'Simulazione (nessun disco viene toccato)' }
$chkRunStop = Add-Ctl $grpNew 'CheckBox' 420 26 260 22 @{ Text = 'Non avviare nuovi dischi dopo le'; Checked = $true }
$tpRunStop = New-TimePicker $grpNew 690 24 '07:00'
[void](Add-Ctl $grpNew 'Label' 420 56 600 40 @{ ForeColor = $cMut; Text = 'La compattazione gira come SYSTEM in background: chiudere questa finestra non la interrompe. I dischi in uso vengono saltati.' })
$btnStart = Add-Ctl $grpNew 'Button' 420 104 160 32 @{ Text = 'Avvia ora'; Font = $script:FontBold }
$rbUser.Add_CheckedChanged({ $txtUser.Enabled = $rbUser.Checked })
$chkMax.Add_CheckedChanged({ $numMax.Enabled = $chkMax.Checked })
$chkRunStop.Add_CheckedChanged({ $tpRunStop.Enabled = $chkRunStop.Checked })

$grpMon = Add-Ctl $tRun 'GroupBox' 16 170 1060 520 @{ Text = 'Stato della compattazione'; Anchor = 'Top,Bottom,Left,Right' }
$lblState = Add-Ctl $grpMon 'Label' 16 24 700 26 @{ Font = $script:FontBig; Text = 'Nessuna esecuzione' }
$lblRunInfo = Add-Ctl $grpMon 'Label' 16 54 1020 20 @{ ForeColor = $cMut; Text = '' }
$prg = Add-Ctl $grpMon 'ProgressBar' 16 78 1020 20 @{ Minimum = 0; Maximum = 100; Anchor = 'Top,Left,Right' }
$lblCurrent = Add-Ctl $grpMon 'Label' 16 104 1020 20 @{ Text = '' }
$lblCounts = Add-Ctl $grpMon 'Label' 16 126 1020 20 @{ Font = $script:FontBold; Text = '' }
$lblErr = Add-Ctl $grpMon 'Label' 16 148 1020 20 @{ ForeColor = $cErr; Text = ''; Anchor = 'Top,Left,Right' }
$btnStop  = Add-Ctl $grpMon 'Button' 16 172 140 30 @{ Text = 'Stop pulito'; Enabled = $false }
$btnKill  = Add-Ctl $grpMon 'Button' 166 172 140 30 @{ Text = 'Stop forzato'; Enabled = $false; ForeColor = $cErr }
$btnRunRep = Add-Ctl $grpMon 'Button' 316 172 160 30 @{ Text = 'Apri report della run'; Enabled = $false }
$btnRunErr = Add-Ctl $grpMon 'Button' 486 172 170 30 @{ Text = 'Errori e avvisi della run'; Enabled = $false }
$btnLeft  = Add-Ctl $grpMon 'Button' 666 172 170 30 @{ Text = 'Sgancia dischi rimasti' }
$txtLog = Add-Ctl $grpMon 'TextBox' 16 210 1020 292 @{ Multiline = $true; ReadOnly = $true; ScrollBars = 'Vertical'; Font = $script:FontMono; WordWrap = $false; BackColor = [System.Drawing.Color]::White; Anchor = 'Top,Bottom,Left,Right' }

$script:lastLogWrite = [datetime]::MinValue
$script:lastLogPath = ''
$script:stopPending = $false

$btnStart.Add_Click({
    Invoke-UI {
        if (Test-CVJobRunning) { throw 'Una compattazione è già in esecuzione.' }
        $opt = @{}
        if ($rbUser.Checked) {
            if (-not $txtUser.Text.Trim()) { throw 'Indica l''utente.' }
            $opt.User = $txtUser.Text.Trim()
        }
        if ($chkMax.Checked) { $opt.MaxDisks = [int]$numMax.Value }
        if ($chkRunStop.Checked) { $opt.StopAt = $tpRunStop.Value.ToString('HH:mm') }
        if ($chkSim.Checked) { $opt.WhatIf = $true }
        $what = "$(if ($opt.User) { "utente $($opt.User)" } else { 'tutti i dischi' })$(if ($opt.MaxDisks) { ", massimo $($opt.MaxDisks)" })"
        if (-not $chkSim.Checked) {
            if (-not (Confirm-UI "Avviare ADESSO la compattazione reale ($what)?`n`nI dischi in uso vengono saltati, ma un utente che entra mentre il suo disco è in lavorazione attende qualche secondo.")) { return }
        }
        Start-CVManualRun $opt
        $script:lastLogPath = ''
        $txtLog.Clear()
        $lblState.Text = 'Avvio in corso...'
        $lblState.ForeColor = $cAcc
    }
})

$btnStop.Add_Click({
    Invoke-UI {
        if (-not (Confirm-UI 'Fermare la compattazione?

Il disco in lavorazione viene completato (pochi secondi), poi il job si ferma e genera il report. Nessun disservizio per gli utenti.')) { return }
        Request-CVStop
        $script:stopPending = $true
        $lblState.Text = 'Stop richiesto: completamento del disco in corso...'
        $lblState.ForeColor = $cWarn
    }
})

$btnKill.Add_Click({
    Invoke-UI {
        if (-not (Confirm-UI 'STOP FORZATO

Interrompe anche il disco in lavorazione e poi lo sgancia. Usalo solo se lo stop pulito non risponde.

Continuare?')) { return }
        $msgs = @(Stop-CVForce (Get-CVProfilePaths $script:cfg))
        Show-Info ("Stop forzato eseguito.`n`n" + $(if ($msgs.Count) { $msgs -join "`n" } else { 'Nessun disco rimasto agganciato.' }))
    }
})

$btnRunRep.Add_Click({
    Invoke-UI {
        $st = Read-CVStatus
        if ($st -and $st.Report -and (Test-Path -LiteralPath $st.Report)) { Invoke-Item -LiteralPath $st.Report }
        else { Show-Info 'Il report viene generato a fine esecuzione.' }
    }
})

$btnRunErr.Add_Click({
    Invoke-UI {
        $st = Read-CVStatus
        if ($st -and $st.ErrorsFile -and (Test-Path -LiteralPath $st.ErrorsFile)) { Start-Process notepad.exe -ArgumentList "`"$($st.ErrorsFile)`"" }
        else { Show-Info 'Nessun errore o avviso registrato in questa run.' }
    }
})

$btnLeft.Add_Click({
    Invoke-UI {
        if (Test-CVJobRunning) { throw 'Compattazione in corso: i dischi agganciati sono quelli in lavorazione. Fermala prima.' }
        $msgs = @(Dismount-CVLeftovers (Get-CVProfilePaths $script:cfg))
        Show-Info $(if ($msgs.Count) { $msgs -join "`n" } else { 'Nessun VHDX dei profili agganciato a questo server.' })
    }
})

function Update-RunTab {
    $st = Read-CVStatus
    $alive = $false
    if ($st -and $st.Pid) {
        $p = Get-Process -Id ([int]$st.Pid) -ErrorAction SilentlyContinue
        $alive = [bool]($p -and $p.ProcessName -match '^(powershell|pwsh)$')
    }
    $btnStop.Enabled = $alive -and -not (Test-Path -LiteralPath $script:CVStopFile)
    $btnKill.Enabled = $alive
    $btnStart.Enabled = -not $alive
    $btnRunRep.Enabled = [bool]($st -and $st.Report -and (Test-Path -LiteralPath $st.Report))
    $btnRunErr.Enabled = [bool]($st -and $st.ErrorsFile -and (Test-Path -LiteralPath $st.ErrorsFile))

    if (-not $st) { return $alive }

    $sim = if ($st.WhatIf) { ' [SIMULAZIONE]' } else { '' }
    $txt, $col = switch ($st.State) {
        'running'      { if ($alive) { "In esecuzione$sim", $cOk } else { 'Interrotta (processo non più attivo)', $cErr } }
        'stopping'     { if ($alive) { 'In arresto: completamento del disco in corso', $cWarn } else { 'Fermata', $cWarn } }
        'stopped'      { "Fermata manualmente$sim", $cWarn }
        'stopped-time' { "Fermata per orario$sim", $cWarn }
        'done'         { if ([int]$st.Errors -gt 0) { "Completata con $($st.Errors) errori$sim", $cWarn } else { "Completata$sim", $cAcc } }
        'error'        { 'Terminata con errore', $cErr }
        'killed'       { 'Terminata con stop forzato', $cErr }
        default        { "$($st.State)", $cMut }
    }
    if (-not ($script:stopPending -and $alive)) { $lblState.Text = $txt; $lblState.ForeColor = $col }
    $lblRunInfo.Text = "Run $($st.RunId) - $($st.Trigger) - avvio $($st.Start)$(if ($st.StopAt) { " - stop nuovi dischi alle $($st.StopAt)" }) - aggiornato $($st.Updated)"
    $pct = if ([int]$st.Total -gt 0) { [math]::Min(100, [math]::Floor([int]$st.Index * 100 / [int]$st.Total)) } else { 0 }
    $prg.Value = [int]$pct
    $lblCurrent.Text = "Disco $($st.Index) di $($st.Total): $($st.Current)"
    $lblCounts.Text = ('Compattati {0}    Saltati {1}    Esclusi {2}    Errori {3}    Avvisi {4}    Recuperati {5:N0} MB' -f $st.Ok, $st.Skipped, $st.Excluded, $st.Errors, $st.Warnings, [double]$st.SavedMB)
    $lblErr.Text = $(if ($st.LastError) { "Ultimo errore: $($st.LastError)" } else { '' })

    if ($st.Log -and (Test-Path -LiteralPath $st.Log)) {
        $lw = (Get-Item -LiteralPath $st.Log).LastWriteTime
        if ($st.Log -ne $script:lastLogPath -or $lw -ne $script:lastLogWrite) {
            $script:lastLogPath = $st.Log
            $script:lastLogWrite = $lw
            $txtLog.Clear()
            $txtLog.AppendText(((@(Get-Content -LiteralPath $st.Log -Tail 400 -Encoding UTF8)) -join "`r`n") + "`r`n")   # AppendText porta in fondo
        }
    }

    if ($script:stopPending -and -not $alive) {
        $script:stopPending = $false
        $msgs = @(Dismount-CVLeftovers (Get-CVProfilePaths $script:cfg))
        Show-Info ("Compattazione fermata in modo pulito.`n`n" + $(if ($msgs.Count) { $msgs -join "`n" } else { 'Nessun disco rimasto agganciato.' }))
    }
    $alive
}

# ===================================================================== PIANIFICAZIONE
$grpCur = Add-Ctl $tSch 'GroupBox' 16 10 1060 84 @{ Text = 'Pianificazione attuale'; Anchor = 'Top,Left,Right' }
$lblSchCur = Add-Ctl $grpCur 'Label' 16 24 1020 22 @{ Font = $script:FontBold; Text = '' }
$lblSchNext = Add-Ctl $grpCur 'Label' 16 50 1020 22 @{ ForeColor = $cMut; Text = '' }

$grpSch = Add-Ctl $tSch 'GroupBox' 16 102 1060 470 @{ Text = 'Nuova pianificazione'; Anchor = 'Top,Left,Right' }
[void](Add-Ctl $grpSch 'Label' 16 30 90 22 @{ Text = 'Frequenza:' })
$cmbFreq = Add-Ctl $grpSch 'ComboBox' 110 26 330 24 @{ DropDownStyle = 'DropDownList' }
$freqMap = @('Daily', 'Weekly', 'MonthlyDays', 'MonthlyDow')
@('Giornaliera', 'Settimanale', 'Mensile - giorni del mese', 'Mensile - giorno della settimana (es. ultima domenica)') | ForEach-Object { [void]$cmbFreq.Items.Add($_) }
$lblEvery = Add-Ctl $grpSch 'Label' 470 30 40 22 @{ Text = 'Ogni' }
$numEvery = Add-Ctl $grpSch 'NumericUpDown' 512 27 60 24 @{ Minimum = 1; Maximum = 52; Value = 1 }
$lblEveryU = Add-Ctl $grpSch 'Label' 578 30 100 22 @{ Text = 'settimane' }

$lblDow = Add-Ctl $grpSch 'Label' 16 66 90 22 @{ Text = 'Giorni:' }
$chkDow = @{}
for ($i = 0; $i -lt 7; $i++) {
    $d = $script:CVDayOrder[$i]
    $chkDow[$d] = Add-Ctl $grpSch 'CheckBox' (110 + $i * 105) 64 100 22 @{ Text = $script:CVDaysIt[$d] }
}
$lblWom = Add-Ctl $grpSch 'Label' 16 98 90 22 @{ Text = 'Settimana:' }
$chkWom = @{}
$i = 0
foreach ($k in $script:CVWeeksIt.Keys) {
    $chkWom[$k] = Add-Ctl $grpSch 'CheckBox' (110 + $i * 105) 96 100 22 @{ Text = $script:CVWeeksIt[$k] }
    $i++
}
$lblDom = Add-Ctl $grpSch 'Label' 16 130 90 22 @{ Text = 'Giorni mese:' }
$clbDom = Add-Ctl $grpSch 'CheckedListBox' 110 128 700 70 @{ MultiColumn = $true; ColumnWidth = 52; CheckOnClick = $true }
1..31 | ForEach-Object { [void]$clbDom.Items.Add("$_") }
[void]$clbDom.Items.Add('Ultimo')
$lblMon = Add-Ctl $grpSch 'Label' 16 212 90 22 @{ Text = 'Mesi:' }
$chkMon = @{}
for ($i = 0; $i -lt 12; $i++) {
    $chkMon[$script:CVMonths[$i]] = Add-Ctl $grpSch 'CheckBox' (110 + ($i % 6) * 80) (210 + [math]::Floor($i / 6) * 26) 76 22 @{ Text = $script:CVMonthsIt[$i] }
}

[void](Add-Ctl $grpSch 'Label' 16 278 90 22 @{ Text = 'Avvio alle:' })
$tpStart = New-TimePicker $grpSch 110 275 '21:00'
$chkSchStop = Add-Ctl $grpSch 'CheckBox' 220 277 260 22 @{ Text = 'Non avviare nuovi dischi dopo le' }
$tpSchStop = New-TimePicker $grpSch 484 275 '07:00'
$chkSchMax = Add-Ctl $grpSch 'CheckBox' 16 312 200 22 @{ Text = 'Al massimo N dischi per run:' }
$numSchMax = Add-Ctl $grpSch 'NumericUpDown' 220 311 80 24 @{ Minimum = 1; Maximum = 10000; Value = 100 }
$chkSchMon = Add-Ctl $grpSch 'CheckBox' 16 344 700 22 @{ Text = 'All''avvio apri CompactVHDX Manager agli amministratori collegati al server' }
[void](Add-Ctl $grpSch 'Label' 16 374 1020 40 @{ ForeColor = $cMut; Text = 'L''orario segue l''ora locale anche al cambio ora legale/solare. Il task ha un limite di sicurezza pari alla finestra fino allo stop + 1 ora; lo stop vero avviene sempre a fine disco.' })
$btnSchSave = Add-Ctl $grpSch 'Button' 16 420 220 32 @{ Text = 'Salva e attiva pianificazione'; Font = $script:FontBold }
$btnSchDis  = Add-Ctl $grpSch 'Button' 246 420 120 32 @{ Text = 'Disabilita' }
$btnSchEn   = Add-Ctl $grpSch 'Button' 376 420 120 32 @{ Text = 'Abilita' }
$btnSchDel  = Add-Ctl $grpSch 'Button' 506 420 180 32 @{ Text = 'Elimina pianificazione'; ForeColor = $cErr }

function Update-SchVisibility {
    $t = $freqMap[$cmbFreq.SelectedIndex]
    $lblEvery.Visible = $t -in 'Daily', 'Weekly'; $numEvery.Visible = $lblEvery.Visible; $lblEveryU.Visible = $lblEvery.Visible
    $lblEveryU.Text = $(if ($t -eq 'Daily') { 'giorni' } else { 'settimane' })
    $showDow = $t -in 'Weekly', 'MonthlyDow'
    $lblDow.Visible = $showDow; foreach ($c in $chkDow.Values) { $c.Visible = $showDow }
    $lblWom.Visible = $t -eq 'MonthlyDow'; foreach ($c in $chkWom.Values) { $c.Visible = $t -eq 'MonthlyDow' }
    $lblDom.Visible = $t -eq 'MonthlyDays'; $clbDom.Visible = $t -eq 'MonthlyDays'
    $showMon = $t -in 'MonthlyDays', 'MonthlyDow'
    $lblMon.Visible = $showMon; foreach ($c in $chkMon.Values) { $c.Visible = $showMon }
}

function Show-Schedule($S) {
    $cmbFreq.SelectedIndex = [math]::Max(0, $freqMap.IndexOf("$($S.Type)"))
    $numEvery.Value = [math]::Max(1, [math]::Min(52, [int]$S.Interval))
    foreach ($d in $chkDow.Keys) { $chkDow[$d].Checked = @($S.DaysOfWeek) -contains $d }
    foreach ($w in $chkWom.Keys) { $chkWom[$w].Checked = @($S.WeeksOfMonth | ForEach-Object { "$_" }) -contains $w }
    for ($i = 0; $i -lt $clbDom.Items.Count; $i++) {
        $key = if ($i -eq 31) { 'Last' } else { "$($i + 1)" }
        $clbDom.SetItemChecked($i, (@($S.DaysOfMonth | ForEach-Object { "$_" }) -contains $key))
    }
    foreach ($m in $chkMon.Keys) { $chkMon[$m].Checked = @($S.Months) -contains $m }
    $tpStart.Value = [datetime]::Today.Add(([datetime]::ParseExact($S.Start, 'HH:mm', $null)).TimeOfDay)
    $chkSchStop.Checked = [bool]$S.StopEnabled
    $tpSchStop.Value = [datetime]::Today.Add(([datetime]::ParseExact($S.StopAt, 'HH:mm', $null)).TimeOfDay)
    $chkSchMax.Checked = [int]$S.MaxDisks -gt 0
    if ([int]$S.MaxDisks -gt 0) { $numSchMax.Value = [int]$S.MaxDisks }
    $chkSchMon.Checked = [bool]$S.MonitorForAdmins
    Update-SchVisibility
}

function Read-ScheduleUI {
    $t = $freqMap[$cmbFreq.SelectedIndex]
    $S = [ordered]@{
        Type             = $t
        Interval         = [int]$numEvery.Value
        DaysOfWeek       = @($script:CVDayOrder | Where-Object { $chkDow[$_].Checked })
        DaysOfMonth      = @(for ($i = 0; $i -lt $clbDom.Items.Count; $i++) { if ($clbDom.GetItemChecked($i)) { if ($i -eq 31) { 'Last' } else { "$($i + 1)" } } })
        WeeksOfMonth     = @($script:CVWeeksIt.Keys | Where-Object { $chkWom[$_].Checked })
        Months           = @($script:CVMonths | Where-Object { $chkMon[$_].Checked })
        Start            = $tpStart.Value.ToString('HH:mm')
        StopEnabled      = $chkSchStop.Checked
        StopAt           = $tpSchStop.Value.ToString('HH:mm')
        MaxDisks         = $(if ($chkSchMax.Checked) { [int]$numSchMax.Value } else { 0 })
        MonitorForAdmins = $chkSchMon.Checked
    }
    if ($t -in 'Weekly', 'MonthlyDow' -and -not $S.DaysOfWeek.Count) { throw 'Seleziona almeno un giorno della settimana.' }
    if ($t -eq 'MonthlyDow' -and -not $S.WeeksOfMonth.Count) { throw 'Seleziona almeno una settimana del mese.' }
    if ($t -eq 'MonthlyDays' -and -not $S.DaysOfMonth.Count) { throw 'Seleziona almeno un giorno del mese.' }
    if ($t -in 'MonthlyDays', 'MonthlyDow' -and -not $S.Months.Count) { throw 'Seleziona almeno un mese.' }
    if ($S.StopEnabled -and $S.StopAt -eq $S.Start) { throw 'L''orario di stop coincide con quello di avvio.' }
    $S
}

function Update-SchCurrent {
    $job = Get-ScheduledTask -TaskName $script:CVTaskJob -ErrorAction SilentlyContinue
    if (-not $job) {
        $lblSchCur.Text = 'Nessuna pianificazione attiva'
        $lblSchCur.ForeColor = $cMut
        $lblSchNext.Text = ''
        return
    }
    $ji = $job | Get-ScheduledTaskInfo
    $lblSchCur.Text = Get-CVScheduleText $script:cfg.Schedule
    $lblSchCur.ForeColor = $(if ($job.State -eq 'Disabled') { $cWarn } else { $cOk })
    $mon = if (Get-ScheduledTask -TaskName $script:CVTaskMonitor -ErrorAction SilentlyContinue) { 'console automatica attiva' } else { 'console automatica non attiva' }
    $lblSchNext.Text = "Stato: $(if ($job.State -eq 'Disabled') { 'DISABILITATA' } else { $job.State }) - prossima esecuzione: $(if ($ji.NextRunTime) { $ji.NextRunTime.ToString('dddd dd/MM/yyyy HH:mm') } else { 'n/d' }) - ultima: $(if ($ji.LastRunTime -and $ji.LastRunTime.Year -gt 2000) { $ji.LastRunTime.ToString('dd/MM/yyyy HH:mm') } else { 'mai' }) - $mon"
}

$cmbFreq.Add_SelectedIndexChanged({ Update-SchVisibility })
$btnSchSave.Add_Click({
    Invoke-UI {
        $S = Read-ScheduleUI
        $script:cfg.Schedule = $S
        Save-CVConfig $script:cfg
        Register-CVSchedule $script:cfg
        Update-SchCurrent
        Show-Info "Pianificazione salvata:`n$(Get-CVScheduleText $S)"
    }
})
$btnSchDis.Add_Click({ Invoke-UI { Disable-ScheduledTask -TaskName $script:CVTaskJob | Out-Null; Disable-ScheduledTask -TaskName $script:CVTaskMonitor -ErrorAction SilentlyContinue | Out-Null; Update-SchCurrent } })
$btnSchEn.Add_Click({ Invoke-UI { Enable-ScheduledTask -TaskName $script:CVTaskJob | Out-Null; Enable-ScheduledTask -TaskName $script:CVTaskMonitor -ErrorAction SilentlyContinue | Out-Null; Update-SchCurrent } })
$btnSchDel.Add_Click({
    Invoke-UI {
        if (-not (Confirm-UI 'Eliminare la pianificazione? Log, report e storico vengono conservati.')) { return }
        Unregister-ScheduledTask -TaskName $script:CVTaskJob -Confirm:$false -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $script:CVTaskMonitor -Confirm:$false -ErrorAction SilentlyContinue
        Update-SchCurrent
    }
})

# ===================================================================== REPORT
$btnHist   = Add-Ctl $tRep 'Button' 16 14 200 30 @{ Text = 'Apri andamento storico'; Font = $script:FontBold }
$btnRepDir = Add-Ctl $tRep 'Button' 226 14 170 30 @{ Text = 'Apri cartella report' }
$btnLogDir = Add-Ctl $tRep 'Button' 406 14 160 30 @{ Text = 'Apri cartella log' }
$btnRepRef = Add-Ctl $tRep 'Button' 576 14 120 30 @{ Text = 'Aggiorna' }
$btnIssues = Add-Ctl $tRep 'Button' 706 14 210 30 @{ Text = 'Log errori e avvisi (tutte le run)' }
[void](Add-Ctl $tRep 'Label' 16 52 1060 22 @{ ForeColor = $cMut; Text = 'Doppio clic su una run per aprirne il report.' })
$gridRep = New-Grid $tRep 16 78 1060 600

function Update-RepGrid {
    $h = @(Get-CVHistory | Sort-Object RunId -Descending)
    $gridRep.DataSource = ConvertTo-CVDataTable $h @(
        @{ H = 'Run'; P = 'RunId' },
        @{ H = 'Avvio'; P = { param($r) [datetime]::ParseExact($r.Start, 'yyyy-MM-dd HH:mm:ss', $null) }; T = [datetime] },
        @{ H = 'Durata'; P = { param($r) Format-CVDuration ([double]$r.DurationSec) } },
        @{ H = 'Tipo'; P = { param($r) "$($r.Trigger)$(if ($r.Simulation -eq 'True') { ' (sim.)' })" } },
        @{ H = 'Dischi'; P = 'DisksTotal'; T = [int] },
        @{ H = 'Compattati'; P = 'Ok'; T = [int] },
        @{ H = 'Saltati'; P = 'Skipped'; T = [int] },
        @{ H = 'Esclusi'; P = 'Excluded'; T = [int] },
        @{ H = 'Errori'; P = 'Errors'; T = [int] },
        @{ H = 'Non elab.'; P = 'NotDone'; T = [int] },
        @{ H = 'Recuperati MB'; P = 'SavedMB'; T = [double] },
        @{ H = 'Libero dopo GB'; P = 'VolumeFreeAfterGB'; T = [double] },
        @{ H = 'Interruzione'; P = 'StopReason' },
        @{ H = 'Report'; P = 'Report' })
    if ($gridRep.Columns['Report']) { $gridRep.Columns['Report'].Visible = $false }
}

$btnHist.Add_Click({
    Invoke-UI {
        $f = Get-CVHistoryReportPath $script:cfg
        New-CVHistoryReport -Config $script:cfg -File $f
        Invoke-Item -LiteralPath $f
    }
})
$btnRepDir.Add_Click({ Invoke-UI { New-Item -ItemType Directory -Path $script:cfg.ReportDir -Force | Out-Null; Invoke-Item -LiteralPath $script:cfg.ReportDir } })
$btnLogDir.Add_Click({ Invoke-UI { Invoke-Item -LiteralPath $script:CVLogDir } })
$btnRepRef.Add_Click({ Invoke-UI { Update-RepGrid } })
$btnIssues.Add_Click({
    Invoke-UI {
        if (Test-Path -LiteralPath $script:CVIssuesLog) { Start-Process notepad.exe -ArgumentList "`"$script:CVIssuesLog`"" }
        else { Show-Info 'Nessun errore o avviso registrato finora.' }
    }
})
$gridRep.Add_CellDoubleClick({
    param($s, $e)
    Invoke-UI {
        if ($e.RowIndex -lt 0) { return }
        $p = "$($gridRep.Rows[$e.RowIndex].Cells['Report'].Value)"
        if ($p -and (Test-Path -LiteralPath $p)) { Invoke-Item -LiteralPath $p } else { Show-Info 'Report non più disponibile (eliminato dalla pulizia automatica?).' }
    }
})

# ===================================================================== IMPOSTAZIONI
$grpPath = Add-Ctl $tSet 'GroupBox' 16 10 520 340 @{ Text = 'Percorsi e soglie' }
[void](Add-Ctl $grpPath 'Label' 16 28 140 22 @{ Text = 'Cartelle profili:' })
$txtProfs = Add-Ctl $grpPath 'TextBox' 160 25 346 62 @{ Multiline = $true; ScrollBars = 'Vertical'; WordWrap = $false }
$btnAddProf = Add-Ctl $grpPath 'Button' 160 92 120 26 @{ Text = 'Aggiungi...' }
$btnWizard = Add-Ctl $grpPath 'Button' 286 92 220 26 @{ Text = 'Configurazione guidata...' }
[void](Add-Ctl $grpPath 'Label' 16 132 140 22 @{ Text = 'Cartella report:' })
$txtRepDir = Add-Ctl $grpPath 'TextBox' 160 129 270 24
$btnRepDirB = Add-Ctl $grpPath 'Button' 436 128 70 26 @{ Text = 'Sfoglia' }
[void](Add-Ctl $grpPath 'Label' 16 170 260 22 @{ Text = 'Avviso se lo spazio libero scende sotto (%):' })
$numAlert = Add-Ctl $grpPath 'NumericUpDown' 300 167 70 24 @{ Minimum = 1; Maximum = 90 }
[void](Add-Ctl $grpPath 'Label' 16 204 260 22 @{ Text = 'Limite profilo FSLogix (MB, SizeInMBs):' })
$numSizeMB = Add-Ctl $grpPath 'NumericUpDown' 300 201 90 24 @{ Minimum = 1000; Maximum = 1000000; Increment = 1000 }
[void](Add-Ctl $grpPath 'Label' 16 238 260 22 @{ Text = 'Profilo inattivo dopo (giorni):' })
$numStale = Add-Ctl $grpPath 'NumericUpDown' 300 235 70 24 @{ Minimum = 7; Maximum = 3650 }
[void](Add-Ctl $grpPath 'Label' 16 272 280 22 @{ Text = 'Conserva log e report per (giorni, 0 = sempre):' })
$numRet = Add-Ctl $grpPath 'NumericUpDown' 300 269 70 24 @{ Minimum = 0; Maximum = 3650 }
[void](Add-Ctl $grpPath 'Label' 16 304 490 30 @{ ForeColor = $cMut; Text = 'Una cartella per riga, locale su questo server. Lo storico delle run (history.csv) non viene mai cancellato dalla pulizia.' })

$grpExc = Add-Ctl $tSet 'GroupBox' 16 358 520 260 @{ Text = 'Utenti esclusi (uno per riga)' }
$txtExc = Add-Ctl $grpExc 'TextBox' 16 26 488 196 @{ Multiline = $true; ScrollBars = 'Vertical' }
[void](Add-Ctl $grpExc 'Label' 16 226 488 30 @{ ForeColor = $cMut; Text = 'Nome utente come compare nella cartella del profilo (SID_utente o utente_SID), es. mario.rossi' })

$grpMail = Add-Ctl $tSet 'GroupBox' 552 10 524 400 @{ Text = 'Email a fine esecuzione' }
$chkMail = Add-Ctl $grpMail 'CheckBox' 16 24 300 22 @{ Text = 'Invia email a fine compattazione' }
[void](Add-Ctl $grpMail 'Label' 16 54 70 22 @{ Text = 'Metodo:' })
$rbGraph = Add-Ctl $grpMail 'RadioButton' 90 52 230 22 @{ Text = 'Microsoft 365 (Graph API)' }
$rbSmtp  = Add-Ctl $grpMail 'RadioButton' 326 52 190 22 @{ Text = 'SMTP relay anonimo' }
# Microsoft 365
$lblTen = Add-Ctl $grpMail 'Label' 16 88 120 22 @{ Text = 'Tenant ID:' }
$txtTenant = Add-Ctl $grpMail 'TextBox' 140 85 364 24
$lblCli = Add-Ctl $grpMail 'Label' 16 118 120 22 @{ Text = 'Client ID (app):' }
$txtClient = Add-Ctl $grpMail 'TextBox' 140 115 364 24
$lblSec = Add-Ctl $grpMail 'Label' 16 148 120 22 @{ Text = 'Segreto client:' }
$txtSecret = Add-Ctl $grpMail 'TextBox' 140 145 364 24 @{ UseSystemPasswordChar = $true }
$lblSecHint = Add-Ctl $grpMail 'Label' 140 171 364 20 @{ ForeColor = $cMut; Text = '' }
# SMTP
$lblSmtp = Add-Ctl $grpMail 'Label' 16 88 120 22 @{ Text = 'Server SMTP:' }
$txtSmtp = Add-Ctl $grpMail 'TextBox' 140 85 230 24
$lblPort = Add-Ctl $grpMail 'Label' 380 88 40 22 @{ Text = 'Porta:' }
$numPort = Add-Ctl $grpMail 'NumericUpDown' 424 85 80 24 @{ Minimum = 1; Maximum = 65535 }
$chkSsl = Add-Ctl $grpMail 'CheckBox' 140 116 200 22 @{ Text = 'Usa SSL/TLS' }
$lblSmtpHint = Add-Ctl $grpMail 'Label' 140 142 364 40 @{ ForeColor = $cMut; Text = 'Solo relay che accettano invii senza autenticazione (es. connettore Microsoft 365 o relay interno). smtp.office365.com richiede autenticazione: usa Microsoft 365.' }
# comuni
[void](Add-Ctl $grpMail 'Label' 16 200 120 22 @{ Text = 'Mittente:' })
$txtFrom = Add-Ctl $grpMail 'TextBox' 140 197 364 24
[void](Add-Ctl $grpMail 'Label' 16 230 120 22 @{ Text = 'Destinatari:' })
$txtTo = Add-Ctl $grpMail 'TextBox' 140 227 364 24
[void](Add-Ctl $grpMail 'Label' 140 253 364 20 @{ ForeColor = $cMut; Text = 'Più indirizzi separati da ; o ,' })
$chkIssues = Add-Ctl $grpMail 'CheckBox' 16 278 480 22 @{ Text = 'Solo se ci sono errori, avvisi di spazio o stop manuali' }
$btnMailTest = Add-Ctl $grpMail 'Button' 16 314 180 30 @{ Text = 'Invia email di prova' }
$lblMailHint = Add-Ctl $grpMail 'Label' 206 312 300 80 @{ ForeColor = $cMut; Text = '' }

function Update-MailVisibility {
    $g = $rbGraph.Checked
    foreach ($c in $lblTen, $txtTenant, $lblCli, $txtClient, $lblSec, $txtSecret, $lblSecHint) { $c.Visible = $g }
    foreach ($c in $lblSmtp, $txtSmtp, $lblPort, $numPort, $chkSsl, $lblSmtpHint) { $c.Visible = -not $g }
    $lblMailHint.Text = $(if ($g) { 'Il mittente deve essere una casella (anche condivisa) del tenant. Il segreto è cifrato e utilizzabile solo su questo server.' } else { 'Nessuna credenziale salvata.' })
}
$rbGraph.Add_CheckedChanged({ Update-MailVisibility })

$grpAct = Add-Ctl $tSet 'GroupBox' 552 418 524 200 @{ Text = 'Salvataggio e manutenzione' }
$btnSetSave = Add-Ctl $grpAct 'Button' 16 30 200 34 @{ Text = 'Salva impostazioni'; Font = $script:FontBold }
$btnScripts = Add-Ctl $grpAct 'Button' 16 76 200 30 @{ Text = 'Apri cartella script' }
$btnEvents  = Add-Ctl $grpAct 'Button' 16 114 200 30 @{ Text = 'Apri eventi CompactVHDX' }
$btnUninst  = Add-Ctl $grpAct 'Button' 16 152 200 30 @{ Text = 'Disinstalla CompactVHDX...'; ForeColor = $cErr }
[void](Add-Ctl $grpAct 'Label' 232 24 280 170 @{ ForeColor = $cMut; Text = "Versione $script:CVVersion`n`nScript: $script:CVBase`nLog: $script:CVLogDir`nStorico: $script:CVHistory`n`nGli eventi sono nel Registro applicazioni, sorgente CompactVHDX (ID 1000 avvio, 1001 ok, 1002 errori, 1003 interrotta, 1004 spazio sotto soglia, 1005 errore imprevisto)." })

function Show-Settings {
    $c = $script:cfg
    $txtProfs.Text = (@(Get-CVProfilePaths $c) -join "`r`n")
    $txtRepDir.Text = $c.ReportDir
    $numAlert.Value = [math]::Max(1, [math]::Min(90, [int]$c.FreeAlertPct))
    $numSizeMB.Value = [math]::Max(1000, [math]::Min(1000000, [int]$c.FslogixSizeMB))
    $numStale.Value = [math]::Max(7, [math]::Min(3650, [int]$c.StaleDays))
    $numRet.Value = [math]::Max(0, [math]::Min(3650, [int]$c.RetentionDays))
    $txtExc.Text = (@($c.ExcludeUsers) -join "`r`n")
    $chkMail.Checked = [bool]$c.Mail.Enabled
    $rbGraph.Checked = "$($c.Mail.Method)" -eq 'Graph'
    $rbSmtp.Checked = -not $rbGraph.Checked
    $txtTenant.Text = $c.Mail.TenantId
    $txtClient.Text = $c.Mail.ClientId
    $txtSecret.Text = ''
    $lblSecHint.Text = $(if ($c.Mail.SecretEnc) { 'Segreto salvato: lascia vuoto per mantenerlo.' } else { 'Nessun segreto salvato.' })
    Update-MailVisibility
    $txtSmtp.Text = $c.Mail.SmtpServer
    $numPort.Value = [math]::Max(1, [math]::Min(65535, [int]$c.Mail.Port))
    $chkSsl.Checked = [bool]$c.Mail.UseSsl
    $txtFrom.Text = $c.Mail.From
    $txtTo.Text = $c.Mail.To
    $chkIssues.Checked = [bool]$c.Mail.OnlyOnIssues
}

function Read-SettingsUI {
    $c = $script:cfg
    $paths = @($txtProfs.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $paths.Count) { throw 'Indica almeno una cartella dei profili.' }
    foreach ($p in $paths) {
        if ($p.StartsWith('\\')) { throw "Percorso di rete non ammesso: $p`n`nCompactVHDX va installato sul server che ospita i profili e usa percorsi locali (es. D:\Profili)." }
        if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "Cartella profili non trovata: $p" }
    }
    $c.ProfilePaths = $paths
    $c.ReportDir = $txtRepDir.Text.Trim()
    $c.FreeAlertPct = [int]$numAlert.Value
    $c.FslogixSizeMB = [int]$numSizeMB.Value
    $c.StaleDays = [int]$numStale.Value
    $c.RetentionDays = [int]$numRet.Value
    $c.ExcludeUsers = @($txtExc.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $c.Mail.Enabled = $chkMail.Checked
    $c.Mail.Method = $(if ($rbGraph.Checked) { 'Graph' } else { 'Smtp' })
    $c.Mail.TenantId = $txtTenant.Text.Trim()
    $c.Mail.ClientId = $txtClient.Text.Trim()
    if ($txtSecret.Text) {
        $c.Mail.SecretEnc = Protect-CVSecret $txtSecret.Text
        $txtSecret.Text = ''
        $lblSecHint.Text = 'Segreto salvato: lascia vuoto per mantenerlo.'
        try { Set-CVSecureFolder $script:CVBase } catch { }
    }
    if ($rbGraph.Checked -and $c.Mail.Enabled -and (-not $c.Mail.TenantId -or -not $c.Mail.ClientId -or -not $c.Mail.SecretEnc)) {
        throw 'Per Microsoft 365 servono Tenant ID, Client ID e segreto client.'
    }
    $c.Mail.SmtpServer = $txtSmtp.Text.Trim()
    $c.Mail.Port = [int]$numPort.Value
    $c.Mail.UseSsl = $chkSsl.Checked
    $c.Mail.From = $txtFrom.Text.Trim()
    $c.Mail.To = $txtTo.Text.Trim()
    $c.Mail.OnlyOnIssues = $chkIssues.Checked
    $c
}

function Select-Folder([string]$Current) {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($Current -and (Test-Path -LiteralPath $Current)) { $dlg.SelectedPath = $Current }
    if ($dlg.ShowDialog() -eq 'OK') { $dlg.SelectedPath } else { $Current }
}
$btnAddProf.Add_Click({
    $f = Select-Folder ''
    if ($f) {
        $cur = @($txtProfs.Lines | Where-Object { $_.Trim() })
        if ($cur -notcontains $f) { $txtProfs.Text = (@($cur) + $f) -join "`r`n" }
    }
})
$btnWizard.Add_Click({
    if (Show-CVSetupWizard) {
        $script:cfg = Get-CVConfig
        Show-Settings
        Show-Schedule $script:cfg.Schedule
        Update-SchCurrent
    }
})
$btnRepDirB.Add_Click({ $txtRepDir.Text = Select-Folder $txtRepDir.Text })
$btnSetSave.Add_Click({
    Invoke-UI {
        $script:cfg = Read-SettingsUI
        Save-CVConfig $script:cfg
        New-Item -ItemType Directory -Path $script:cfg.ReportDir -Force | Out-Null
        Show-Info 'Impostazioni salvate. Valgono dalla prossima esecuzione.'
    }
})
$btnMailTest.Add_Click({
    Invoke-UI {
        $c = Read-SettingsUI
        Send-CVMail -Config $c -Subject "[CompactVHDX] $env:COMPUTERNAME - email di prova" -HtmlBody "<p>Email di prova di CompactVHDX Manager da <b>$env:COMPUTERNAME</b> ($((Get-Date).ToString('dd/MM/yyyy HH:mm'))).</p>"
        Show-Info "Email di prova inviata a $($c.Mail.To)."
    }
})
$btnScripts.Add_Click({ Invoke-UI { Invoke-Item -LiteralPath $script:CVBase } })
$btnEvents.Add_Click({
    Invoke-UI {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $script:CVEventSource } -MaxEvents 50 -ErrorAction SilentlyContinue)
        if (-not $ev.Count) { Show-Info 'Nessun evento CompactVHDX nel Registro applicazioni.'; return }
        $ev | Select-Object TimeCreated, Id, LevelDisplayName, Message | Out-GridView -Title 'Eventi CompactVHDX (ultimi 50)'
    }
})
$btnUninst.Add_Click({
    Invoke-UI {
        if (Test-CVJobRunning) { throw 'Compattazione in corso: fermala prima di disinstallare.' }
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "Disinstallare CompactVHDX da questo server?`n`nSì: rimuove task pianificati, collegamenti, registrazione e l'intera cartella $script:CVBase (script, configurazione, log e storico).`n`nNo: rimuove task pianificati, collegamenti e registrazione, ma conserva la cartella con configurazione, log e storico.`n`nAnnulla: nessuna modifica.",
            'Disinstalla CompactVHDX', 'YesNoCancel', 'Warning')
        if ($ans -eq 'Cancel') { return }
        foreach ($t in $script:CVTaskJob, $script:CVTaskMonitor, $script:CVTaskManual) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
        Remove-CVShortcuts
        Remove-Item -Path $script:CVRegKey -Recurse -Force -ErrorAction SilentlyContinue
        $msg = 'CompactVHDX è stato disinstallato.'
        if ($ans -eq 'Yes') {
            # la cartella contiene questo script in esecuzione: si elimina pochi secondi dopo la chiusura
            Start-Process cmd.exe -WindowStyle Hidden -ArgumentList "/c ping 127.0.0.1 -n 6 >nul & rmdir /s /q `"$script:CVBase`""
            $msg += "`n`nLa cartella $script:CVBase verrà eliminata alla chiusura."
            if ($script:cfg.ReportDir -and -not $script:cfg.ReportDir.StartsWith($script:CVBase)) { $msg += "`nLa cartella dei report $($script:cfg.ReportDir) non è stata toccata." }
        } else {
            $msg += "`n`nLa cartella $script:CVBase è stata conservata."
        }
        Show-Info $msg
        $script:form.Close()
    }
})

# ===================================================================== configurazione guidata
function Test-CVSetupComplete {
    $p = Get-CVProfilePaths $script:cfg
    [bool]($script:cfg.SetupDone -and $p.Count -and -not @($p | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Container) }).Count)
}

function Show-CVSetupWizard {
    $cfgW = Get-CVConfig
    $w = New-Object System.Windows.Forms.Form
    $w.Text = 'CompactVHDX - configurazione guidata'
    $w.Size = New-Object System.Drawing.Size(840, 700)
    $w.StartPosition = 'CenterScreen'
    $w.FormBorderStyle = 'FixedDialog'
    $w.MaximizeBox = $false
    $w.MinimizeBox = $false
    $w.Font = $script:Font

    [void](Add-Ctl $w 'Label' 16 10 800 30 @{ Font = $script:FontBig; Text = 'Configurazione di CompactVHDX' })
    [void](Add-Ctl $w 'Label' 16 44 800 20 @{ ForeColor = $cMut; Text = "Server $env:COMPUTERNAME - cartella di installazione $script:CVBase - versione $script:CVVersion" })

    # 1. requisiti
    $g1 = Add-Ctl $w 'GroupBox' 16 70 792 160 @{ Text = '1. Requisiti' }
    $lv = Add-Ctl $g1 'ListView' 12 22 768 128 @{ View = 'Details'; FullRowSelect = $true; HeaderStyle = 'Nonclickable' }
    [void]$lv.Columns.Add('Verifica', 300); [void]$lv.Columns.Add('Esito', 70); [void]$lv.Columns.Add('Nota', 380)
    $prereq = @(Test-CVPrerequisites)
    foreach ($r in $prereq) {
        $it = New-Object System.Windows.Forms.ListViewItem($r.Verifica)
        [void]$it.SubItems.Add($r.Esito); [void]$it.SubItems.Add($r.Nota)
        $it.ForeColor = $(switch ($r.Esito) { 'OK' { $cOk } 'AVVISO' { $cWarn } default { $cErr } })
        [void]$lv.Items.Add($it)
    }

    # 2. cartelle dei profili
    $g2 = Add-Ctl $w 'GroupBox' 16 238 792 190 @{ Text = '2. Cartelle dei profili FSLogix da compattare' }
    $clb = Add-Ctl $g2 'CheckedListBox' 12 22 610 128 @{ CheckOnClick = $true; HorizontalScrollbar = $true }
    $btnDet = Add-Ctl $g2 'Button' 634 22 146 28 @{ Text = 'Rileva automaticamente' }
    $btnAdd = Add-Ctl $g2 'Button' 634 56 146 28 @{ Text = 'Aggiungi cartella...' }
    $btnRem = Add-Ctl $g2 'Button' 634 90 146 28 @{ Text = 'Rimuovi selezionata' }
    [void](Add-Ctl $g2 'Label' 12 154 768 32 @{ ForeColor = $cMut; Text = 'Spunta le cartelle locali che contengono le cartelle per utente (SID_utente o utente_SID) con i file VHD/VHDX. CompactVHDX va installato sul server che ospita i profili.' })
    $wmap = @{}

    function Add-WizPath([string]$Path, [string]$Info, [bool]$Checked) {
        $Path = $Path.TrimEnd('\')
        foreach ($k in @($wmap.Keys)) { if ($wmap[$k] -ieq $Path) { return } }
        $text = if ($Info) { "$Path    ($Info)" } else { $Path }
        $wmap[$text] = $Path
        $i = $clb.Items.Add($text)
        $clb.SetItemChecked($i, $Checked)
    }
    function Invoke-WizDetect([bool]$CheckFound) {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        try {
            $found = @(Find-CVProfileFolders)
            foreach ($f in $found) { Add-WizPath $f.Path "$($f.Count) VHDX, $($f.SizeGB) GB - $($f.Detail)" $CheckFound }
            $found.Count
        } finally { [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default }
    }

    foreach ($p in (Get-CVProfilePaths $cfgW)) { Add-WizPath $p 'configurata' $true }
    $nFound = Invoke-WizDetect (-not (Get-CVProfilePaths $cfgW).Count)

    $btnDet.Add_Click({
        $n = Invoke-WizDetect $false
        if (-not $n) { Show-Info 'Nessuna cartella con profili FSLogix trovata nelle condivisioni di questo server. Aggiungila a mano con "Aggiungi cartella...".' }
    })
    $btnAdd.Add_Click({
        $f = Select-Folder ''
        if ($f) {
            $n = @(Get-ChildItem -LiteralPath $f -Recurse -Depth 2 -File -Force -Filter '*.vhd*' -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.vhdx?$' }).Count
            Add-WizPath $f "$n VHD/VHDX trovati" $true
        }
    })
    $btnRem.Add_Click({
        if ($clb.SelectedIndex -ge 0) {
            $wmap.Remove("$($clb.SelectedItem)")
            $clb.Items.RemoveAt($clb.SelectedIndex)
        }
    })

    # 3. report e soglie
    $g3 = Add-Ctl $w 'GroupBox' 16 436 792 104 @{ Text = '3. Report e soglie' }
    [void](Add-Ctl $g3 'Label' 12 28 140 22 @{ Text = 'Cartella report:' })
    $txtR = Add-Ctl $g3 'TextBox' 160 25 530 24 @{ Text = $cfgW.ReportDir }
    $btnR = Add-Ctl $g3 'Button' 698 24 82 26 @{ Text = 'Sfoglia' }
    $btnR.Add_Click({ $f = Select-Folder $txtR.Text; if ($f) { $txtR.Text = $f } })
    [void](Add-Ctl $g3 'Label' 12 64 140 22 @{ Text = 'Limite FSLogix (MB):' })
    $numL = Add-Ctl $g3 'NumericUpDown' 160 61 90 24 @{ Minimum = 1000; Maximum = 1000000; Increment = 1000 }
    $detMB = Get-CVFslogixSizeMB
    $numL.Value = $(if ((Test-Path -LiteralPath $script:CVConfig) -and $cfgW.SetupDone) { [math]::Max(1000, [int]$cfgW.FslogixSizeMB) } else { $detMB })
    [void](Add-Ctl $g3 'Label' 258 64 230 22 @{ ForeColor = $cMut; Text = "(SizeInMBs; rilevato/predefinito: $detMB)" })
    [void](Add-Ctl $g3 'Label' 500 64 200 22 @{ Text = 'Avviso spazio libero sotto (%):' })
    $numA = Add-Ctl $g3 'NumericUpDown' 700 61 80 24 @{ Minimum = 1; Maximum = 90 }
    $numA.Value = [math]::Max(1, [math]::Min(90, [int]$cfgW.FreeAlertPct))

    # 4. pianificazione
    $g4 = Add-Ctl $w 'GroupBox' 16 548 792 70 @{ Text = '4. Pianificazione' }
    $existingTask = [bool](Get-ScheduledTask -TaskName $script:CVTaskJob -ErrorAction SilentlyContinue)
    $chkS = Add-Ctl $g4 'CheckBox' 12 24 290 22 @{ Text = 'Compatta ogni domenica alle'; Checked = -not $existingTask }
    $tpS = New-TimePicker $g4 300 22 $cfgW.Schedule.Start
    [void](Add-Ctl $g4 'Label' 390 26 220 22 @{ Text = 'senza avviare nuovi dischi dopo le' })
    $tpE = New-TimePicker $g4 612 22 $cfgW.Schedule.StopAt
    $chkM = Add-Ctl $g4 'CheckBox' 12 46 600 20 @{ Text = 'All''avvio apri il pannello agli amministratori collegati'; Checked = [bool]$cfgW.Schedule.MonitorForAdmins }
    if ($existingTask) { $chkS.Text = 'Sostituisci la pianificazione esistente: domenica alle' }

    $btnOk = Add-Ctl $w 'Button' 520 626 180 32 @{ Text = 'Salva e continua'; Font = $script:FontBold }
    $btnCancel = Add-Ctl $w 'Button' 708 626 100 32 @{ Text = 'Annulla' }
    $w.CancelButton = $btnCancel
    $btnCancel.Add_Click({ $w.DialogResult = 'Cancel'; $w.Close() })

    $btnOk.Add_Click({
        try {
            $paths = @(foreach ($it in $clb.CheckedItems) { $wmap["$it"] })
            if (-not $paths.Count) { throw 'Spunta almeno una cartella dei profili.' }
            foreach ($p in $paths) {
                if ($p.StartsWith('\\')) { throw "Percorso di rete non ammesso: $p`n`nInstalla CompactVHDX sul server che ospita i profili e usa il percorso locale." }
                if (-not (Test-Path -LiteralPath $p -PathType Container)) { throw "Cartella non trovata: $p" }
            }
            $empty = @($paths | Where-Object { -not @(Get-ChildItem -LiteralPath $_ -Recurse -Depth 2 -File -Force -Filter '*.vhd*' -ErrorAction SilentlyContinue | Select-Object -First 1).Count })
            if ($empty.Count -and -not (Confirm-UI "Nelle seguenti cartelle non ci sono VHD/VHDX:`n$($empty -join "`n")`n`nSalvare comunque?")) { return }
            if (-not $txtR.Text.Trim()) { throw 'Indica la cartella dei report.' }
            New-Item -ItemType Directory -Path $txtR.Text.Trim() -Force | Out-Null
            if (@($prereq | Where-Object { $_.Esito -eq 'ERRORE' }).Count -and -not (Confirm-UI 'Alcuni requisiti non sono soddisfatti: la compattazione potrebbe non funzionare. Salvare comunque?')) { return }

            $c = Get-CVConfig
            $c.ProfilePaths = $paths
            $c.ReportDir = $txtR.Text.Trim()
            $c.FslogixSizeMB = [int]$numL.Value
            $c.FreeAlertPct = [int]$numA.Value
            $c.SetupDone = $true
            if ($chkS.Checked) {
                $c.Schedule.Type = 'Weekly'; $c.Schedule.Interval = 1; $c.Schedule.DaysOfWeek = @('Sunday')
                $c.Schedule.Start = $tpS.Value.ToString('HH:mm')
                $c.Schedule.StopEnabled = $true
                $c.Schedule.StopAt = $tpE.Value.ToString('HH:mm')
                $c.Schedule.MonitorForAdmins = $chkM.Checked
            }
            Save-CVConfig $c
            if ($chkS.Checked) { Register-CVSchedule $c }
            $w.DialogResult = 'OK'
            $w.Close()
        } catch { Show-Err $_.Exception.Message }
    })

    ($w.ShowDialog() -eq 'OK')
}

# ===================================================================== timer e avvio
$script:tick = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({
    try {
        $alive = Update-RunTab
        $script:tick++
        if ($script:tick % 15 -eq 1) {
            $job = Get-ScheduledTask -TaskName $script:CVTaskJob -ErrorAction SilentlyContinue
            $script:nextRun = if ($job -and $job.State -ne 'Disabled') { $ni = ($job | Get-ScheduledTaskInfo).NextRunTime; if ($ni) { $ni.ToString('ddd dd/MM HH:mm') } else { 'n/d' } } elseif ($job) { 'pianificazione disabilitata' } else { 'nessuna pianificazione' }
        }
        $stLabel.Text = "Compattazione: $(if ($alive) { 'IN ESECUZIONE' } else { 'ferma' })    |    Prossima esecuzione: $script:nextRun    |    Profili: $((Get-CVProfilePaths $script:cfg) -join '; ')"
    } catch { }
})

$form.Add_Shown({
    if (-not (Test-CVSetupComplete)) {
        if (-not (Show-CVSetupWizard)) {
            Show-Info 'Configurazione non completata: CompactVHDX Manager verrà chiuso. Riaprilo quando vuoi completarla.'
            $form.Close()
            return
        }
        $script:cfg = Get-CVConfig
    }
    Invoke-UI {
        # migrazione dai task della versione a script singoli (argomento -LogDir non piu' supportato)
        $old = Get-ScheduledTask -TaskName $script:CVTaskJob -ErrorAction SilentlyContinue
        if ($old -and ((@($old.Actions) | ForEach-Object { $_.Arguments }) -join ' ') -match '-LogDir') {
            Register-CVSchedule $script:cfg
            Show-Info "Trovata la pianificazione della versione precedente: aggiornata al nuovo formato.`n`n$(Get-CVScheduleText $script:cfg.Schedule)"
        }
        Show-Settings
        Show-Schedule $script:cfg.Schedule
        Update-SchCurrent
        Update-RepGrid
        [void](Update-RunTab)
        $tabs.SelectedTab = $tabs.TabPages[$StartTab]
        $timer.Start()
    }
})
$form.Add_FormClosing({ $timer.Stop() })

[void]$form.ShowDialog()
$script:mutex.ReleaseMutex()
