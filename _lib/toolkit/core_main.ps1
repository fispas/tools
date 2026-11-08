
#region CONFIGURAZIONE E INTERFACCIA (libreria _lib/toolkit)
. $Engine

# etichette dell'interfaccia: ogni tool puo' personalizzarle in $Tool
foreach ($kv in @{ ItemNoun = 'elementi'; ItemTab = 'Elementi'; StartLabel = 'Avvia'; RunningLabel = 'Operazione in corso'; CloseWarning = '' }.GetEnumerator()) {
    if (-not $Tool.ContainsKey($kv.Key)) { $Tool[$kv.Key] = $kv.Value }
}

$ToolDataDir = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name)
$DefaultConfigPath = Join-Path $ToolDataDir 'config.json'

function ConvertTo-ConfigValue($Field, $Value) {
    switch ($Field.Type) {
        'Int' { try { return [int]$Value } catch { return $null } }
        'Bool' { return [bool]$Value }
        'List' {
            if ($null -eq $Value) { return , @() }
            $arr = @(@($Value) | ForEach-Object { "$_" -split '[;\r\n]+' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return , $arr
        }
        'Choice' {
            if (@($Field.Choices) -contains [string]$Value) { return [string]$Value }
            return $null
        }
        default {
            if ($null -eq $Value) { return '' }
            return [string]$Value
        }
    }
}

function Read-ToolConfig([string]$Path) {
    $cfg = Get-ToolDefaultConfig
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $loaded = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($f in $ToolSchema) {
            if (-not $f.Key) { continue }
            $p = $loaded.PSObject.Properties[$f.Key]
            if ($p) {
                $v = ConvertTo-ConfigValue $f $p.Value
                if ($null -ne $v) { $cfg[$f.Key] = $v }
            }
        }
    }
    $cfg
}

function Save-ToolConfig($Config, [string]$Path) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = [pscustomobject]$Config | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($true)))
}

function Initialize-ToolLog($Config) {
    $dir = [string]$Config.LogDir
    if (-not $dir) { $dir = Join-Path $ToolDataDir 'Log' }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $State.LogDir = $dir
    $State.LogFile = Join-Path $dir ('{0}_{1}.log' -f $Tool.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

# ------------------------------------------------------------------ modalita' senza GUI
if ($NoGui) {
    $cfgPath = $DefaultConfigPath
    if ($ConfigPath) {
        if (-not (Test-Path -LiteralPath $ConfigPath)) { Write-Error "File di configurazione non trovato: $ConfigPath"; exit 1 }
        $cfgPath = $ConfigPath
    }
    $Config = Read-ToolConfig $cfgPath
    if ($Simulate) { $Config.DryRun = $true }
    Initialize-ToolLog $Config
    Write-ToolLog "Configurazione: $cfgPath"
    foreach ($w in @(Get-ToolPrereqIssues $Config)) { Write-ToolLog $w 'WARN' }
    $errs = @(Test-ToolConfig $Config)
    if ($errs.Count) { foreach ($e in $errs) { Write-ToolLog $e 'ERROR' }; exit 1 }
    $items = @(Get-ToolItems -Config $Config | Where-Object { $_.Selectable })
    if ($User) { $items = @($items | Where-Object { $User -contains $_.Utente }) }
    if (-not $items.Count) { Write-ToolLog "Nessun elemento da elaborare ($($Tool.ItemNoun))." 'WARN'; exit 0 }
    $res = @(Invoke-ToolRun -Config $Config -Items $items)
    if (@($res | Where-Object { $_.Esito -eq 'Fallito' }).Count) { exit 2 }
    exit 0
}

# ------------------------------------------------------------------ GUI
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
# testo nitido sugli schermi ad alta densita' (prima di creare qualsiasi finestra)
try {
    if (-not ('FispaTools.Dpi' -as [type])) { Add-Type -Namespace FispaTools -Name Dpi -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();' }
    [void][FispaTools.Dpi]::SetProcessDPIAware()
} catch { }
[System.Windows.Forms.Application]::EnableVisualStyles()

# ---------------------------------------------------------- tema grafico (comune a tutti i tool)
function New-UiColor([string]$Hex) { [System.Drawing.ColorTranslator]::FromHtml($Hex) }
$Ui = @{
    Bg = New-UiColor '#F6F7FB'; Surface = New-UiColor '#FFFFFF'; Surface2 = New-UiColor '#F1F4F9'; Border = New-UiColor '#E3E8F0'
    Text = New-UiColor '#0F172A'; Muted = New-UiColor '#64748B'; Accent = New-UiColor '#2563EB'; AccentDark = New-UiColor '#1D4ED8'; AccentSoft = New-UiColor '#DBEAFE'
    Header = New-UiColor '#0F172A'; HeaderText = New-UiColor '#F8FAFC'; HeaderMuted = New-UiColor '#94A3B8'
    Ok = New-UiColor '#16A34A'; OkSoft = New-UiColor '#DCFCE7'; Warn = New-UiColor '#B45309'; WarnSoft = New-UiColor '#FEF3C7'
    Err = New-UiColor '#DC2626'; ErrSoft = New-UiColor '#FEE2E2'; Sim = New-UiColor '#7C3AED'; SimSoft = New-UiColor '#EDE9FE'
    Info = New-UiColor '#0E7490'; InfoSoft = New-UiColor '#CFFAFE'; Neutral = New-UiColor '#475569'; NeutralSoft = New-UiColor '#E2E8F0'
    LogBg = New-UiColor '#0B1020'; LogText = New-UiColor '#CBD5E1'
}
$installed = @((New-Object System.Drawing.Text.InstalledFontCollection).Families | ForEach-Object { $_.Name })
$Ui.FontName = if ($installed -contains 'Segoe UI Variable Text') { 'Segoe UI Variable Text' } else { 'Segoe UI' }
$Ui.FontSemi = if ($installed -contains 'Segoe UI Variable Display Semib') { 'Segoe UI Variable Display Semib' } elseif ($installed -contains 'Segoe UI Semibold') { 'Segoe UI Semibold' } else { $Ui.FontName }
$Ui.Font = New-Object System.Drawing.Font($Ui.FontName, 9.5)
$Ui.FontBold = New-Object System.Drawing.Font($Ui.FontSemi, 9.5)
$Ui.MonoName = if ($installed -contains 'Cascadia Mono') { 'Cascadia Mono' } else { 'Consolas' }

# Pulsanti piatti: Primary (azione principale), Secondary, Danger
function Set-UiButton($Button, [string]$Kind = 'Secondary') {
    $Button.FlatStyle = 'Flat'
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand
    $Button.Font = $Ui.FontBold
    $Button.Padding = New-Object System.Windows.Forms.Padding(10, 2, 10, 2)
    $Button.Margin = New-Object System.Windows.Forms.Padding(4, 3, 4, 3)
    if ($Button.Height -lt 32) { $Button.Height = 32 }
    $Button.UseVisualStyleBackColor = $false
    switch ($Kind) {
        'Primary' { $Button.BackColor = $Ui.Accent; $Button.ForeColor = [System.Drawing.Color]::White; $Button.FlatAppearance.BorderSize = 0; $Button.FlatAppearance.MouseOverBackColor = $Ui.AccentDark; $Button.FlatAppearance.MouseDownBackColor = $Ui.AccentDark }
        'Danger' { $Button.BackColor = $Ui.Surface; $Button.ForeColor = $Ui.Err; $Button.FlatAppearance.BorderColor = $Ui.ErrSoft; $Button.FlatAppearance.BorderSize = 1; $Button.FlatAppearance.MouseOverBackColor = $Ui.ErrSoft }
        default { $Button.BackColor = $Ui.Surface; $Button.ForeColor = $Ui.Text; $Button.FlatAppearance.BorderColor = $Ui.Border; $Button.FlatAppearance.BorderSize = 1; $Button.FlatAppearance.MouseOverBackColor = $Ui.Surface2 }
    }
}

# Colori della pillola di un esito
function Get-UiTone([string]$Status) {
    switch -Regex ($Status) {
        '^(OK|Conforme)' { return @($Ui.OkSoft, $Ui.Ok) }
        '^(Attenzione|Saltato|Da applicare)' { return @($Ui.WarnSoft, $Ui.Warn) }
        '^(Fallito|Critico)' { return @($Ui.ErrSoft, $Ui.Err) }
        '^(Simulato)' { return @($Ui.SimSoft, $Ui.Sim) }
        '^(Info|Pronto|In corso)' { return @($Ui.InfoSoft, $Ui.Info) }
        default { return @($Ui.NeutralSoft, $Ui.Neutral) }
    }
}

function New-UiRoundPath([System.Drawing.Rectangle]$R, [int]$Radius) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $Radius * 2
    $p.AddArc($R.X, $R.Y, $d, $d, 180, 90)
    $p.AddArc($R.Right - $d, $R.Y, $d, $d, 270, 90)
    $p.AddArc($R.Right - $d, $R.Bottom - $d, $d, $d, 0, 90)
    $p.AddArc($R.X, $R.Bottom - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    $p
}

function Show-Err([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'OK', 'Error') }
function Show-Info([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'OK', 'Information') }
function Confirm-UI([string]$m) { [System.Windows.Forms.MessageBox]::Show($m, $Tool.Title, 'YesNo', 'Question') -eq 'Yes' }

$script:CurrentConfigPath = $DefaultConfigPath
if ($ConfigPath) { $script:CurrentConfigPath = $ConfigPath }
try { $Config = Read-ToolConfig $script:CurrentConfigPath }
catch { Show-Err "Configurazione non leggibile, uso i valori predefiniti.`n$($_.Exception.Message)"; $Config = Get-ToolDefaultConfig }
Initialize-ToolLog $Config

$script:Running = $false
$script:CloseWhenDone = $false
$script:Handle = $null
$script:PS = $null
$script:Runspace = $null
$script:LastDone = $null

$form = New-Object System.Windows.Forms.Form
$form.Text = '{0} {1}' -f $Tool.Title, $Tool.Version
$form.Size = New-Object System.Drawing.Size(1150, 780)
$form.MinimumSize = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = 'CenterScreen'
$form.Font = $Ui.Font
$form.BackColor = $Ui.Bg
$form.ForeColor = $Ui.Text

# intestazione: titolo, versione, computer, modalita'
$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'
$header.Height = 68
$header.BackColor = $Ui.Header
$hdrBadge = New-Object System.Windows.Forms.Label
$hdrBadge.Text = (($Tool.Name -creplace '[^A-Z]', '') + 'FT').Substring(0, 2)
$hdrBadge.Size = New-Object System.Drawing.Size(40, 40)
$hdrBadge.Location = New-Object System.Drawing.Point(20, 14)
$hdrBadge.TextAlign = 'MiddleCenter'
$hdrBadge.BackColor = $Ui.Accent
$hdrBadge.ForeColor = [System.Drawing.Color]::White
$hdrBadge.Font = New-Object System.Drawing.Font($Ui.FontSemi, 11)
$hdrTitle = New-Object System.Windows.Forms.Label
$hdrTitle.Text = $Tool.Title
$hdrTitle.AutoSize = $true
$hdrTitle.Location = New-Object System.Drawing.Point(72, 12)
$hdrTitle.ForeColor = $Ui.HeaderText
$hdrTitle.Font = New-Object System.Drawing.Font($Ui.FontSemi, 14)
$hdrSub = New-Object System.Windows.Forms.Label
$hdrSub.Text = 'Versione {0}  -  {1}  -  {2}\{3}' -f $Tool.Version, $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME
$hdrSub.AutoSize = $true
$hdrSub.Location = New-Object System.Drawing.Point(74, 40)
$hdrSub.ForeColor = $Ui.HeaderMuted
$hdrMode = New-Object System.Windows.Forms.Label
$hdrMode.AutoSize = $false
$hdrMode.Size = New-Object System.Drawing.Size(210, 28)
$hdrMode.Anchor = 'Top, Right'
$hdrMode.TextAlign = 'MiddleCenter'
$hdrMode.Font = $Ui.FontBold
$header.Controls.AddRange(@($hdrBadge, $hdrTitle, $hdrSub, $hdrMode))
$header.Add_Resize({ $hdrMode.Location = New-Object System.Drawing.Point(($header.Width - $hdrMode.Width - 20), 20) })
$hdrBadge.Add_Paint({
    param($s, $e)
    $e.Graphics.SmoothingMode = 'AntiAlias'
    $e.Graphics.Clear($Ui.Header)
    $path = New-UiRoundPath (New-Object System.Drawing.Rectangle(0, 0, ($s.Width - 1), ($s.Height - 1))) 10
    $brush = New-Object System.Drawing.SolidBrush($Ui.Accent)
    $e.Graphics.FillPath($brush, $path)
    [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $s.Text, $s.Font, $s.ClientRectangle, [System.Drawing.Color]::White, [System.Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter')
    $brush.Dispose(); $path.Dispose()
})

# chip della modalita': sola lettura, simulazione o esecuzione reale
function Update-ModeChip($Cfg) {
    $txt = 'ESECUZIONE REALE'; $bg = $Ui.Err; $fg = [System.Drawing.Color]::White
    if ($Cfg -and $Cfg.Contains('DryRun') -and $Cfg.DryRun) { $txt = 'SIMULAZIONE'; $bg = $Ui.Sim }
    if ($Tool.ReadOnly) { $txt = 'SOLA LETTURA'; $bg = $Ui.Ok }
    $hdrMode.Text = $txt; $hdrMode.BackColor = $bg; $hdrMode.ForeColor = $fg
}

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$tabs.DrawMode = 'OwnerDrawFixed'
$tabs.SizeMode = 'Fixed'
$tabs.ItemSize = New-Object System.Drawing.Size(170, 38)
$tabs.Padding = New-Object System.Drawing.Point(18, 6)
$tabs.Add_DrawItem({
    param($s, $e)
    $g = $e.Graphics
    $g.SmoothingMode = 'AntiAlias'
    $r = $s.GetTabRect($e.Index)
    $sel = $e.Index -eq $s.SelectedIndex
    $bgBrush = New-Object System.Drawing.SolidBrush($Ui.Bg)
    $g.FillRectangle($bgBrush, (New-Object System.Drawing.Rectangle(($r.X - 2), ($r.Y - 2), ($r.Width + 4), ($r.Height + 4))))
    $fg = $Ui.Muted
    if ($sel) {
        $fg = $Ui.Accent
        $lineBrush = New-Object System.Drawing.SolidBrush($Ui.Accent)
        $g.FillRectangle($lineBrush, (New-Object System.Drawing.Rectangle(($r.X + 14), ($r.Bottom - 3), ($r.Width - 28), 3)))
        $lineBrush.Dispose()
    }
    $font = $Ui.Font
    if ($sel) { $font = $Ui.FontBold }
    [System.Windows.Forms.TextRenderer]::DrawText($g, $s.TabPages[$e.Index].Text, $font, $r, $fg, [System.Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter')
    $bgBrush.Dispose()
})
$tabCfg = New-Object System.Windows.Forms.TabPage('Configurazione')
$tabPro = New-Object System.Windows.Forms.TabPage($Tool.ItemTab)
$tabLog = New-Object System.Windows.Forms.TabPage('Log')
$tabs.TabPages.AddRange(@($tabCfg, $tabPro, $tabLog))

# ---------------------------------------------------------- scheda Configurazione
$tlp = New-Object System.Windows.Forms.TableLayoutPanel
$tlp.Dock = 'Fill'
$tlp.AutoScroll = $true
$tlp.ColumnCount = 3
$tlp.Padding = New-Object System.Windows.Forms.Padding(24, 8, 24, 16)
$tlp.BackColor = $Ui.Surface
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
[void]$tlp.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
$tip = New-Object System.Windows.Forms.ToolTip
$Ctl = @{}
$row = 0
foreach ($f in $ToolSchema) {
    if ($f.Type -eq 'Section') {
        $sec = New-Object System.Windows.Forms.Label
        $sec.Text = $f.Label
        $sec.AutoSize = $true
        $sec.Text = $f.Label.ToUpperInvariant()
        $sec.Font = New-Object System.Drawing.Font($Ui.FontSemi, 9)
        $sec.ForeColor = $Ui.Accent
        $sec.Margin = New-Object System.Windows.Forms.Padding(0, 22, 0, 6)
        $tlp.Controls.Add($sec, 0, $row)
        $tlp.SetColumnSpan($sec, 3)
        $row++
        continue
    }
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = $f.Label
    $lbl.AutoSize = $true
    $lbl.Anchor = 'Left'
    $lbl.Margin = New-Object System.Windows.Forms.Padding(3, 6, 12, 3)
    switch ($f.Type) {
        'Int' {
            $c = New-Object System.Windows.Forms.NumericUpDown
            $c.Minimum = [decimal]$f.Min
            $c.Maximum = [decimal]$f.Max
            $c.Width = 140
            $c.Anchor = 'Left'
        }
        'Choice' {
            $c = New-Object System.Windows.Forms.ComboBox
            $c.DropDownStyle = 'DropDownList'
            [void]$c.Items.AddRange([object[]]@($f.Choices))
            $c.Width = 240
            $c.Anchor = 'Left'
        }
        'Bool' {
            $c = New-Object System.Windows.Forms.CheckBox
            $c.AutoSize = $true
            $c.Anchor = 'Left'
        }
        default {
            $c = New-Object System.Windows.Forms.TextBox
            $c.Anchor = 'Left, Right'
        }
    }
    $tlp.Controls.Add($lbl, 0, $row)
    $tlp.Controls.Add($c, 1, $row)
    if ($f.Type -in @('Folder', 'File')) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text = 'Sfoglia...'
        $btn.AutoSize = $true
        $btn.Tag = @{ Box = $c; Type = $f.Type; Filter = $f.Filter }
        $btn.Add_Click({
            param($s, $e)
            $t = $s.Tag
            if ($t.Type -eq 'Folder') {
                $d = New-Object System.Windows.Forms.FolderBrowserDialog
                $d.ShowNewFolderButton = $true
                if ($t.Box.Text -and (Test-Path -LiteralPath $t.Box.Text)) { $d.SelectedPath = $t.Box.Text }
                if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.SelectedPath }
            } else {
                $d = New-Object System.Windows.Forms.OpenFileDialog
                if ($t.Filter) { $d.Filter = $t.Filter }
                if ($d.ShowDialog() -eq 'OK') { $t.Box.Text = $d.FileName }
            }
        })
        $tlp.Controls.Add($btn, 2, $row)
    }
    if ($f.Help) { $tip.SetToolTip($lbl, $f.Help); $tip.SetToolTip($c, $f.Help) }
    $row++
    if ($f.Help) {
        $h = New-Object System.Windows.Forms.Label
        $h.Text = $f.Help
        $h.AutoSize = $true
        $h.MaximumSize = New-Object System.Drawing.Size(760, 0)
        $h.ForeColor = $Ui.Muted
        $h.Font = New-Object System.Drawing.Font($Ui.FontName, 8.5)
        $h.Margin = New-Object System.Windows.Forms.Padding(3, 0, 3, 6)
        $tlp.Controls.Add($h, 1, $row)
        $tlp.SetColumnSpan($h, 2)
        $row++
    }
    $Ctl[$f.Key] = $c
}
$tlp.RowCount = $row + 1

function Set-FormFromConfig($Cfg) {
    foreach ($f in $ToolSchema) {
        if (-not $f.Key) { continue }
        $c = $Ctl[$f.Key]
        $v = $Cfg[$f.Key]
        switch ($f.Type) {
            'Int' { $c.Value = [decimal][math]::Min([math]::Max([double]$v, [double]$f.Min), [double]$f.Max) }
            'Choice' { $c.SelectedItem = [string]$v; if ($c.SelectedIndex -lt 0 -and $c.Items.Count) { $c.SelectedIndex = 0 } }
            'Bool' { $c.Checked = [bool]$v }
            'List' { $c.Text = (@($v) -join '; ') }
            default { $c.Text = [string]$v }
        }
    }
}

function Get-ConfigFromForm {
    $cfg = Get-ToolDefaultConfig
    foreach ($f in $ToolSchema) {
        if (-not $f.Key) { continue }
        $c = $Ctl[$f.Key]
        switch ($f.Type) {
            'Int' { $cfg[$f.Key] = [int]$c.Value }
            'Choice' { $cfg[$f.Key] = [string]$c.SelectedItem }
            'Bool' { $cfg[$f.Key] = [bool]$c.Checked }
            'List' { $cfg[$f.Key] = ConvertTo-ConfigValue $f $c.Text }
            default { $cfg[$f.Key] = $c.Text.Trim() }
        }
    }
    $cfg
}

$cfgBar = New-Object System.Windows.Forms.FlowLayoutPanel
$cfgBar.Dock = 'Bottom'
$cfgBar.AutoSize = $true
$cfgBar.Padding = New-Object System.Windows.Forms.Padding(14, 10, 14, 10)
$cfgBar.BackColor = $Ui.Bg
$btnSave = New-Object System.Windows.Forms.Button; $btnSave.Text = 'Salva'; $btnSave.AutoSize = $true
$btnSaveAs = New-Object System.Windows.Forms.Button; $btnSaveAs.Text = 'Salva come...'; $btnSaveAs.AutoSize = $true
$btnLoad = New-Object System.Windows.Forms.Button; $btnLoad.Text = 'Carica...'; $btnLoad.AutoSize = $true
$btnDefaults = New-Object System.Windows.Forms.Button; $btnDefaults.Text = 'Valori predefiniti'; $btnDefaults.AutoSize = $true
$lblCfg = New-Object System.Windows.Forms.Label; $lblCfg.AutoSize = $true; $lblCfg.Margin = New-Object System.Windows.Forms.Padding(12, 8, 3, 3)
$cfgBar.Controls.AddRange(@($btnSave, $btnSaveAs, $btnLoad, $btnDefaults, $lblCfg))
$tabCfg.Controls.Add($tlp)
$tabCfg.Controls.Add($cfgBar)
$tlp.BringToFront()

function Update-CfgLabel { $lblCfg.Text = "File: $script:CurrentConfigPath" }

$btnSave.Add_Click({
    try { Save-ToolConfig (Get-ConfigFromForm) $script:CurrentConfigPath; Update-CfgLabel; Show-Info "Configurazione salvata in`n$script:CurrentConfigPath" }
    catch { Show-Err "Salvataggio non riuscito: $($_.Exception.Message)" }
})
$btnSaveAs.Add_Click({
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Filter = 'Configurazione (*.json)|*.json'
    $d.InitialDirectory = $ToolDataDir
    $d.FileName = 'config.json'
    if ($d.ShowDialog() -eq 'OK') {
        try { Save-ToolConfig (Get-ConfigFromForm) $d.FileName; $script:CurrentConfigPath = $d.FileName; Update-CfgLabel }
        catch { Show-Err "Salvataggio non riuscito: $($_.Exception.Message)" }
    }
})
$btnLoad.Add_Click({
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Filter = 'Configurazione (*.json)|*.json'
    if (Test-Path -LiteralPath $ToolDataDir) { $d.InitialDirectory = $ToolDataDir }
    if ($d.ShowDialog() -eq 'OK') {
        try { Set-FormFromConfig (Read-ToolConfig $d.FileName); $script:CurrentConfigPath = $d.FileName; Update-CfgLabel }
        catch { Show-Err "Configurazione non valida: $($_.Exception.Message)" }
    }
})
$btnDefaults.Add_Click({ if (Confirm-UI 'Ripristinare i valori predefiniti? Le modifiche non salvate vanno perse.') { Set-FormFromConfig (Get-ToolDefaultConfig) } })

# ---------------------------------------------------------- scheda elementi (analisi e selezione)
$proBar = New-Object System.Windows.Forms.FlowLayoutPanel
$proBar.Dock = 'Top'
$proBar.AutoSize = $true
$proBar.Padding = New-Object System.Windows.Forms.Padding(14, 10, 14, 10)
$proBar.BackColor = $Ui.Bg
$btnScan = New-Object System.Windows.Forms.Button; $btnScan.Text = 'Analizza'; $btnScan.AutoSize = $true
$btnAll = New-Object System.Windows.Forms.Button; $btnAll.Text = 'Seleziona tutti'; $btnAll.AutoSize = $true
$btnNone = New-Object System.Windows.Forms.Button; $btnNone.Text = 'Nessuno'; $btnNone.AutoSize = $true
$lblFilter = New-Object System.Windows.Forms.Label; $lblFilter.Text = 'Filtro:'; $lblFilter.AutoSize = $true; $lblFilter.Margin = New-Object System.Windows.Forms.Padding(16, 8, 3, 3)
$txtFilter = New-Object System.Windows.Forms.TextBox; $txtFilter.Width = 260; $txtFilter.Margin = New-Object System.Windows.Forms.Padding(3, 7, 3, 3)
$lblCount = New-Object System.Windows.Forms.Label; $lblCount.AutoSize = $true; $lblCount.Margin = New-Object System.Windows.Forms.Padding(16, 8, 3, 3)
$proBar.Controls.AddRange(@($btnScan, $btnAll, $btnNone, $lblFilter, $txtFilter, $lblCount))

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'Fill'
$grid.BackgroundColor = $Ui.Surface
$grid.BorderStyle = 'None'
$grid.CellBorderStyle = 'SingleHorizontal'
$grid.GridColor = $Ui.Border
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersBorderStyle = 'None'
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.ColumnHeadersHeight = 38
$grid.ColumnHeadersDefaultCellStyle.BackColor = $Ui.Surface2
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $Ui.Muted
$grid.ColumnHeadersDefaultCellStyle.Font = $Ui.FontBold
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Ui.Surface2
$grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
$grid.RowTemplate.Height = 32
$grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(8, 0, 8, 0)
$grid.DefaultCellStyle.SelectionBackColor = $Ui.AccentSoft
$grid.DefaultCellStyle.SelectionForeColor = $Ui.Text
$grid.DefaultCellStyle.ForeColor = $Ui.Text
$grid.AlternatingRowsDefaultCellStyle.BackColor = New-UiColor '#FAFBFD'
# esito come pillola colorata
$grid.Add_CellPainting({
    param($s, $e)
    if ($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0) { return }
    if ($s.Columns[$e.ColumnIndex].Name -ne 'Esito') { return }
    $v = [string]$e.Value
    $e.PaintBackground($e.CellBounds, $true)
    if ($v) {
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $tone = Get-UiTone $v
        $sz = [System.Windows.Forms.TextRenderer]::MeasureText($v, $Ui.FontBold)
        $w = [math]::Min($e.CellBounds.Width - 12, $sz.Width + 18)
        $rect = New-Object System.Drawing.Rectangle(($e.CellBounds.X + 8), ($e.CellBounds.Y + [int](($e.CellBounds.Height - 22) / 2)), $w, 22)
        $path = New-UiRoundPath $rect 11
        $b = New-Object System.Drawing.SolidBrush($tone[0])
        $g.FillPath($b, $path)
        [System.Windows.Forms.TextRenderer]::DrawText($g, $v, $Ui.FontBold, $rect, $tone[1], [System.Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter, EndEllipsis')
        $b.Dispose(); $path.Dispose()
    }
    $e.Handled = $true
})
$colSel = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colSel.Name = 'Sel'; $colSel.HeaderText = ''; $colSel.Width = 32; $colSel.AutoSizeMode = 'None'
[void]$grid.Columns.Add($colSel)
foreach ($col in $ToolColumns) {
    $gc = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $gc.Name = $col.Name; $gc.HeaderText = $col.Header; $gc.ReadOnly = $true; $gc.FillWeight = $col.Weight
    [void]$grid.Columns.Add($gc)
}
$colEsito = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colEsito.Name = 'Esito'; $colEsito.HeaderText = 'Esito'; $colEsito.ReadOnly = $true; $colEsito.FillWeight = 8
[void]$grid.Columns.Add($colEsito)
$tabPro.Controls.Add($grid)
$tabPro.Controls.Add($proBar)
$grid.BringToFront()

function Update-Count {
    $sel = 0; $ok = 0
    foreach ($r in $grid.Rows) { if ($r.Tag.Selectable) { $ok++ }; if ($r.Cells['Sel'].Value -eq $true) { $sel++ } }
    $lblCount.Text = 'Selezionati {0} / {1} migrabili ({2} trovati)' -f $sel, $ok, $grid.Rows.Count
}

function Show-Items($Items) {
    $grid.Rows.Clear()
    foreach ($it in @($Items)) {
        $vals = New-Object System.Collections.Generic.List[object]
        $vals.Add($false)
        foreach ($col in $ToolColumns) { $vals.Add([string]$it.($col.Name)) }
        $vals.Add('')
        $idx = $grid.Rows.Add($vals.ToArray())
        $r = $grid.Rows[$idx]
        $r.Tag = $it
        if (-not $it.Selectable) {
            $r.Cells['Sel'].ReadOnly = $true
            $r.DefaultCellStyle.ForeColor = $Ui.Muted
        } elseif ($it.Stato -ne 'Pronto') {
            $r.DefaultCellStyle.ForeColor = $Ui.Warn
        }
    }
    Update-Count
}

$grid.Add_CurrentCellDirtyStateChanged({ if ($grid.IsCurrentCellDirty) { [void]$grid.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) } })
$grid.Add_CellValueChanged({ Update-Count })
$btnAll.Add_Click({
    $grid.EndEdit() | Out-Null
    foreach ($r in $grid.Rows) { if ($r.Visible -and $r.Tag.Selectable) { $r.Cells['Sel'].Value = $true } }
    Update-Count
})
$btnNone.Add_Click({
    $grid.EndEdit() | Out-Null
    foreach ($r in $grid.Rows) { $r.Cells['Sel'].Value = $false }
    Update-Count
})
$txtFilter.Add_TextChanged({
    $q = $txtFilter.Text.Trim()
    $grid.CurrentCell = $null
    foreach ($r in $grid.Rows) {
        if (-not $q) { $r.Visible = $true; continue }
        $hit = $false
        foreach ($cell in $r.Cells) { if ([string]$cell.Value -like "*$q*") { $hit = $true; break } }
        $r.Visible = $hit
    }
})
$btnScan.Add_Click({
    $cfg = Get-ConfigFromForm
    $errs = @(Test-ToolConfig $cfg -Scan)
    if ($errs.Count) { Show-Err ($errs -join "`n"); return }
    $form.UseWaitCursor = $true
    [System.Windows.Forms.Application]::DoEvents()
    try {
        $items = @(Get-ToolItems -Config $cfg)
        Show-Items $items
        Write-ToolLog ('Analisi completata: {0} {1} trovati, {2} elaborabili.' -f $items.Count, $Tool.ItemNoun, @($items | Where-Object { $_.Selectable }).Count) 'OK'
    } catch {
        Write-ToolLog "Analisi non riuscita: $($_.Exception.Message)" 'ERROR'
        Show-Err "Analisi non riuscita:`n$($_.Exception.Message)"
    } finally { $form.UseWaitCursor = $false }
})

# ---------------------------------------------------------- scheda Log
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock = 'Fill'
$logBox.ReadOnly = $true
$logBox.WordWrap = $false
$logBox.BackColor = $Ui.LogBg
$logBox.ForeColor = $Ui.LogText
$logBox.BorderStyle = 'None'
$logBox.Font = New-Object System.Drawing.Font($Ui.MonoName, 9.5)
$tabLog.Controls.Add($logBox)

function Add-LogLine([string]$Text, [string]$Level) {
    $color = switch ($Level) {
        'OK' { New-UiColor '#4ADE80' }
        'WARN' { New-UiColor '#FBBF24' }
        'ERROR' { New-UiColor '#F87171' }
        'STEP' { New-UiColor '#60A5FA' }
        default { $Ui.LogText }
    }
    $logBox.SelectionStart = $logBox.TextLength
    $logBox.SelectionLength = 0
    $logBox.SelectionColor = $color
    $logBox.AppendText($Text + "`r`n")
    $logBox.SelectionColor = $logBox.ForeColor
    $logBox.ScrollToCaret()
}

# ---------------------------------------------------------- barra inferiore
$bottom = New-Object System.Windows.Forms.Panel
$bottom.Dock = 'Bottom'
$bottom.Height = 64
$bottom.BackColor = $Ui.Surface
# barra di avanzamento sottile (stessa interfaccia Maximum/Value di una ProgressBar)
$prog = New-Object System.Windows.Forms.Panel
$prog.Dock = 'Top'
$prog.Height = 4
$prog.BackColor = $Ui.Border
$progFill = New-Object System.Windows.Forms.Panel
$progFill.Dock = 'Left'
$progFill.Width = 0
$progFill.BackColor = $Ui.Accent
$prog.Controls.Add($progFill)
$script:ProgMax = 1
function Set-UiProgress([int]$Value, [int]$Max) {
    $script:ProgMax = [math]::Max(1, $Max)
    $v = [math]::Max(0, [math]::Min($Value, $script:ProgMax))
    $progFill.Width = [int]($prog.Width * $v / $script:ProgMax)
}
$runBar = New-Object System.Windows.Forms.FlowLayoutPanel
$runBar.Dock = 'Fill'
$runBar.Padding = New-Object System.Windows.Forms.Padding(14, 10, 14, 0)
$btnStart = New-Object System.Windows.Forms.Button; $btnStart.Text = $Tool.StartLabel; $btnStart.Width = 160; $btnStart.Height = 30
$btnStart.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$btnCancel = New-Object System.Windows.Forms.Button; $btnCancel.Text = 'Annulla'; $btnCancel.Width = 100; $btnCancel.Height = 30; $btnCancel.Enabled = $false
$btnOpenLog = New-Object System.Windows.Forms.Button; $btnOpenLog.Text = 'Cartella log e report'; $btnOpenLog.AutoSize = $true; $btnOpenLog.Height = 30
$lblStatus = New-Object System.Windows.Forms.Label; $lblStatus.AutoSize = $true; $lblStatus.Margin = New-Object System.Windows.Forms.Padding(12, 11, 3, 3); $lblStatus.Text = 'Pronto.'; $lblStatus.ForeColor = $Ui.Muted
$runBar.Controls.AddRange(@($btnStart, $btnCancel, $btnOpenLog, $lblStatus))
$bottom.Controls.Add($runBar)
$bottom.Controls.Add($prog)
$runBar.BringToFront()

$form.Controls.Add($tabs)
$form.Controls.Add($bottom)
$form.Controls.Add($header)
$tabs.BringToFront()
foreach ($tp in @($tabCfg, $tabPro, $tabLog)) { $tp.BackColor = $Ui.Bg; $tp.Padding = New-Object System.Windows.Forms.Padding(0) }

# stile dei pulsanti
Set-UiButton $btnStart 'Primary'
Set-UiButton $btnScan 'Primary'
Set-UiButton $btnCancel 'Danger'
foreach ($b in @($btnOpenLog, $btnAll, $btnNone, $btnSave, $btnSaveAs, $btnLoad, $btnDefaults)) { Set-UiButton $b }
foreach ($c in $tlp.Controls) {
    if ($c -is [System.Windows.Forms.Button]) { Set-UiButton $c }
    elseif ($c -is [System.Windows.Forms.TextBox]) { $c.BorderStyle = 'FixedSingle' }
}
$lblCfg.ForeColor = $Ui.Muted
$lblCount.ForeColor = $Ui.Muted
# il chip della modalita' segue la casella Simulazione
if ($Ctl.ContainsKey('DryRun')) { $Ctl['DryRun'].Add_CheckedChanged({ Update-ModeChip (Get-ConfigFromForm) }) }
if ($Ctl.ContainsKey('Mode')) { $Ctl['Mode'].Add_SelectedIndexChanged({ $c = Get-ConfigFromForm; [void](Test-ToolConfig $c -Scan); Update-ModeChip $c }) }

function Set-Running([bool]$On) {
    $script:Running = $On
    $btnStart.Enabled = -not $On
    $btnScan.Enabled = -not $On
    $btnCancel.Enabled = $On
    $tlp.Enabled = -not $On
    $cfgBar.Enabled = -not $On
}

function Receive-ToolMessage($Msg) {
    switch ($Msg.T) {
        'log' { Add-LogLine $Msg.M $Msg.L }
        'prog' {
            Set-UiProgress ([int]$Msg.C) ([int]$Msg.N)
            $lblStatus.Text = "In corso: $($Msg.M)"
        }
        'row' {
            foreach ($r in $grid.Rows) {
                if ($r.Tag.Key -eq $Msg.K) {
                    $r.Cells['Esito'].Value = $Msg.E
                    break
                }
            }
        }
        'done' { $script:LastDone = $Msg }
    }
}

function Receive-AllMessages {
    $msg = $null
    while ($State.Queue.TryDequeue([ref]$msg)) { Receive-ToolMessage $msg }
}

function Complete-Run {
    $h = $script:Handle
    $script:Handle = $null
    try { [void]$script:PS.EndInvoke($h) } catch { Write-ToolLog "Errore interno: $($_.Exception.Message)" 'ERROR' }
    foreach ($e in @($script:PS.Streams.Error)) { Write-ToolLog "Errore interno: $e" 'ERROR' }
    try { $script:PS.Dispose(); $script:Runspace.Close(); $script:Runspace.Dispose() } catch { }
    Receive-AllMessages
    Set-Running $false
    Set-UiProgress $script:ProgMax $script:ProgMax
    if ($script:LastDone) {
        $lblStatus.Text = $script:LastDone.S
        if (-not $script:CloseWhenDone) {
            $txt = "Operazione terminata.`n`n$($script:LastDone.S)"
            if ($script:LastDone.R) { $txt += "`n`nReport: $($script:LastDone.R)" }
            if ($script:LastDone.F -gt 0) { Show-Err $txt } else { Show-Info $txt }
        }
    } else {
        $lblStatus.Text = 'Terminato con errori: vedere il log.'
    }
    if ($script:CloseWhenDone) { $form.Close() }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 200
$timer.Add_Tick({
    Receive-AllMessages
    if ($script:Handle -and $script:Handle.IsCompleted) { Complete-Run }
})

$btnStart.Add_Click({
    $cfg = Get-ConfigFromForm
    $errs = @(Test-ToolConfig $cfg)
    if ($errs.Count) { Show-Err ($errs -join "`n"); return }
    $grid.EndEdit() | Out-Null
    $items = @(foreach ($r in $grid.Rows) { if ($r.Cells['Sel'].Value -eq $true -and $r.Tag.Selectable) { $r.Tag } })
    if (-not $items.Count) { Show-Info "Nessun elemento selezionato.`nScheda $($Tool.ItemTab): premere Analizza e spuntare $($Tool.ItemNoun) da elaborare."; $tabs.SelectedTab = $tabPro; return }
    $mode = 'ESECUZIONE REALE'
    if ($cfg.DryRun) { $mode = 'SIMULAZIONE (nessuna modifica)' }
    if ($Tool.ReadOnly) { $mode = 'SOLA LETTURA (nessuna modifica)' }
    $msg = "$($Tool.ItemTab) da elaborare: $($items.Count)`n"
    foreach ($k in $Tool.ConfirmKeys) { $msg += "$k : $(@($cfg[$k]) -join '; ')`n" }
    $msg += "`nModalita': $mode`n`nProcedere?"
    Update-ModeChip $cfg
    if (-not (Confirm-UI $msg)) { return }
    Initialize-ToolLog $cfg
    $State.Cancel = $false
    $script:LastDone = $null
    foreach ($r in $grid.Rows) { $r.Cells['Esito'].Value = '' }
    Set-Running $true
    $tabs.SelectedTab = $tabLog
    $script:Runspace = [runspacefactory]::CreateRunspace()
    $script:Runspace.Open()
    $script:Runspace.SessionStateProxy.SetVariable('Config', $cfg)
    $script:Runspace.SessionStateProxy.SetVariable('Items', $items)
    $script:Runspace.SessionStateProxy.SetVariable('State', $State)
    $script:Runspace.SessionStateProxy.SetVariable('Tool', $Tool)
    $script:PS = [powershell]::Create()
    $script:PS.Runspace = $script:Runspace
    [void]$script:PS.AddScript($Engine.ToString() + "`r`nInvoke-ToolRun -Config `$Config -Items `$Items | Out-Null")
    $script:Handle = $script:PS.BeginInvoke()
})

$btnCancel.Add_Click({
    $State.Cancel = $true
    $btnCancel.Enabled = $false
    Write-ToolLog "Annullamento richiesto: termino l'elemento in corso e mi fermo." 'WARN'
})

$btnOpenLog.Add_Click({ if ($State.LogDir -and (Test-Path -LiteralPath $State.LogDir)) { Start-Process explorer.exe $State.LogDir } })

$form.Add_FormClosing({
    param($s, $e)
    if ($script:Running) {
        $e.Cancel = $true
        if ($script:CloseWhenDone) { return }
        if (Confirm-UI "$($Tool.RunningLabel).`nInterrompere dopo l'elemento in corso e chiudere?$($Tool.CloseWarning)") {
            $State.Cancel = $true
            $script:CloseWhenDone = $true
            $btnCancel.Enabled = $false
            Write-ToolLog "Chiusura richiesta: attendo la fine dell'elemento in corso." 'WARN'
        }
    }
})

$form.Add_Shown({
    Set-FormFromConfig $Config
    Update-ModeChip $Config
    $hdrMode.Location = New-Object System.Drawing.Point(($header.Width - $hdrMode.Width - 20), 20)
    Update-CfgLabel
    Update-Count
    Write-ToolLog ('{0} {1} su {2} - log: {3}' -f $Tool.Title, $Tool.Version, $env:COMPUTERNAME, $State.LogFile) 'STEP'
    foreach ($w in @(Get-ToolPrereqIssues $Config)) { Write-ToolLog $w 'WARN' }
    $timer.Start()
})

[void]$form.ShowDialog()
$timer.Stop()
$form.Dispose()
#endregion
