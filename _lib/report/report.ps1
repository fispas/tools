function ConvertTo-RptHtml([object]$Text) { [System.Net.WebUtility]::HtmlEncode([string]$Text) }

# Tono grafico di un esito: ok / warn / err / info / sim / neutral
function Get-RptTone([string]$Status) {
    switch -Regex ($Status) {
        '^(OK|Conforme|Completato|Compattato|Riuscito)' { return 'ok' }
        '^(Attenzione|Saltato|Avviso|Da applicare|Warning)' { return 'warn' }
        '^(Fallito|Critico|Errore|Error)' { return 'err' }
        '^(Simulato|Simulazione)' { return 'sim' }
        '^(Info|Non applicabile|Pronto)' { return 'info' }
        default { return 'neutral' }
    }
}

function New-RptBadge([string]$Status, [string]$Tone) {
    if (-not $Tone) { $Tone = Get-RptTone $Status }
    "<span class=`"badge $Tone`">$(ConvertTo-RptHtml $Status)</span>"
}

function New-RptKpi([object]$Value, [string]$Label, [string]$Tone = '') {
    "<div class=`"kpi $Tone`"><div class=`"v`">$(ConvertTo-RptHtml $Value)</div><div class=`"l`">$(ConvertTo-RptHtml $Label)</div></div>"
}

# Anello percentuale (es. punteggio 0-100)
function New-RptScore([int]$Percent, [string]$Label, [string]$Tone = '') {
    $c = switch ($Tone) { 'ok' { 'var(--ok)' } 'warn' { 'var(--warn)' } 'err' { 'var(--err)' } default { 'var(--accent)' } }
    $p = [math]::Max(0, [math]::Min(100, $Percent))
    "<div class=`"kpi $Tone`"><div class=`"score`"><div class=`"ring`" style=`"--p:$p;--c:$c`"><b>$p</b></div><div><div class=`"v`" style=`"font-size:20px`">$(ConvertTo-RptHtml $Label)</div><div class=`"l`">su 100</div></div></div></div>"
}

function New-RptCard([string]$Title, [string]$BodyHtml, [string]$Note = '') {
    $n = ''
    if ($Note) { $n = "<span class=`"n`">$(ConvertTo-RptHtml $Note)</span>" }
    "<section class=`"card`"><h2>$(ConvertTo-RptHtml $Title) $n</h2><div class=`"body`">$BodyHtml</div></section>"
}

# Tabella con ricerca, filtro per stato e ordinamento.
# Columns: @{ Name; Header; Num = $true; Badge = $true; Mono = $true }
function New-RptTable {
    param([string]$Title, $Rows, $Columns, [string]$StatusColumn = 'Esito', [switch]$HideEmpty)
    $rows = @($Rows)
    $cols = @($Columns)
    if ($HideEmpty) { $cols = @($cols | Where-Object { $c = $_; $c.Badge -or @($rows | Where-Object { [string]$_.($c.Name) -ne '' }).Count }) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class=`"card`" data-filter><h2>$(ConvertTo-RptHtml $Title) <span class=`"n`"></span></h2>")
    [void]$sb.Append('<div class="toolbar"><input type="search" placeholder="Cerca...">')
    if ($StatusColumn) {
        foreach ($g in @($rows | Group-Object { [string]$_.$StatusColumn } | Sort-Object Name)) {
            if (-not $g.Name) { continue }
            [void]$sb.Append("<span class=`"chip`" data-v=`"$(ConvertTo-RptHtml $g.Name)`">$(ConvertTo-RptHtml $g.Name)<span class=`"c`">$($g.Count)</span></span>")
        }
    }
    [void]$sb.Append('</div>')
    if (-not $rows.Count) { [void]$sb.Append('<div class="empty">Nessun elemento.</div></section>'); return $sb.ToString() }
    [void]$sb.Append('<div class="tw"><table class="sort"><thead><tr>')
    foreach ($c in $cols) { [void]$sb.Append("<th>$(ConvertTo-RptHtml $c.Header)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $rows) {
        $s = ''
        if ($StatusColumn) { $s = [string]$r.$StatusColumn }
        [void]$sb.Append("<tr data-row data-s=`"$(ConvertTo-RptHtml $s)`">")
        foreach ($c in $cols) {
            $v = $r.($c.Name)
            if ($v -is [array]) { $v = $v -join '; ' }
            if ($c.Badge -and "$v") { [void]$sb.Append("<td data-v=`"$(ConvertTo-RptHtml $v)`">$(New-RptBadge ([string]$v))</td>") }
            elseif ($c.Num) { [void]$sb.Append("<td class=`"num`">$(ConvertTo-RptHtml $v)</td>") }
            elseif ($c.Mono) { [void]$sb.Append("<td class=`"mono`">$(ConvertTo-RptHtml $v)</td>") }
            else { [void]$sb.Append("<td>$(ConvertTo-RptHtml $v)</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div></section>')
    $sb.ToString()
}

# Documento completo: barra superiore (tema chiaro/scuro, espandi, stampa), indicatori, contenuto
function New-RptDocument {
    param([string]$Title, [string]$Subtitle, [string]$Badge = 'FT', [string]$HeroHtml = '', [string]$BodyHtml = '', [string]$Footer = '', [string]$ExtraCss = '')
    $ini = ConvertTo-RptHtml $Badge
    $hero = ''
    if ($HeroHtml) { $hero = "<div class=`"hero`">$HeroHtml</div>" }
    if (-not $Footer) { $Footer = "Generato il $((Get-Date).ToString('dd/MM/yyyy HH:mm')) su $env:COMPUTERNAME da $env:USERDOMAIN\$env:USERNAME" }
    @"
<!DOCTYPE html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark">
<title>$(ConvertTo-RptHtml $Title)</title><style>$script:RptCss
$ExtraCss</style><script>$script:RptJs</script></head>
<body><header class="top"><div class="in"><div class="logo">$ini</div><div><h1>$(ConvertTo-RptHtml $Title)</h1><div class="sub">$(ConvertTo-RptHtml $Subtitle)</div></div>
<div class="act"><button class="btn" id="expand" type="button">Espandi tutto</button><button class="btn" id="theme" type="button">Tema</button><button class="btn" id="print" type="button">Stampa / PDF</button></div></div></header>
<main>$hero$BodyHtml</main><footer>$(ConvertTo-RptHtml $Footer)</footer></body></html>
"@
}

# Report standard di un'esecuzione: indicatori per esito e tabella dei risultati
function New-RptRunReport {
    param([string]$Title, [string]$Subtitle, [string]$Badge, $Results, [string]$Path, [string]$ItemHeader = 'Elemento')
    $res = @($Results)
    $kpi = New-Object System.Collections.Generic.List[string]
    $kpi.Add((New-RptKpi $res.Count 'Elementi elaborati'))
    foreach ($e in @('OK', 'Simulato', 'Info', 'Attenzione', 'Critico', 'Non verificato', 'Saltato', 'Fallito', 'Annullato')) {
        $n = @($res | Where-Object { $_.Esito -eq $e }).Count
        if ($n) { $kpi.Add((New-RptKpi $n $e (Get-RptTone $e))) }
    }
    $dur = ($res | Measure-Object -Property DurataSec -Sum).Sum
    if ($dur) { $kpi.Add((New-RptKpi ('{0:N0} s' -f $dur) 'Durata totale' 'neutral')) }
    $cols = @(
        @{ Name = 'Utente'; Header = $ItemHeader }
        @{ Name = 'Esito'; Header = 'Esito'; Badge = $true }
        @{ Name = 'Messaggio'; Header = 'Dettaglio' }
        @{ Name = 'Origine'; Header = 'Origine'; Mono = $true }
        @{ Name = 'Destinazione'; Header = 'Destinazione'; Mono = $true }
        @{ Name = 'DimensioneMB'; Header = 'MB'; Num = $true }
        @{ Name = 'DurataSec'; Header = 'Secondi'; Num = $true }
    )
    $body = New-RptTable -Title 'Risultati' -Rows $res -Columns $cols -HideEmpty
    $html = New-RptDocument -Title $Title -Subtitle $Subtitle -Badge $Badge -HeroHtml ($kpi -join '') -BodyHtml $body
    [System.IO.File]::WriteAllText($Path, $html, (New-Object System.Text.UTF8Encoding($true)))
    $Path
}
