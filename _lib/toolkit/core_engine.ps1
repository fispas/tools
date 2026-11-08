    #region MOTORE BASE (libreria _lib/toolkit, comune a tutti i tool GUI del repo)
#region RPT-ASSETS (generato da _lib/build.py da _lib/report: non modificare qui)
function ConvertTo-RptHtml([object]$Text) { [System.Net.WebUtility]::HtmlEncode([string]$Text) }

# Tono grafico di un esito: ok / warn / err / info / sim / neutral
function Get-RptTone([string]$Status) {
    switch -Regex ($Status) {
        '^(OK|Conforme|Completato|Compattato|Riuscito|Risolto|Migliorato)' { return 'ok' }
        '^(Attenzione|Saltato|Avviso|Da applicare|Warning|Peggiorato|Nuove evidenze)' { return 'warn' }
        '^(Fallito|Critico|Errore|Error|Nuovo rischio)' { return 'err' }
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
$script:RptCss = @'
:root{--bg:#f6f7fb;--surface:#ffffff;--surface2:#f1f4f9;--border:#e3e8f0;--text:#0f172a;--muted:#64748b;--accent:#2563eb;--accent-soft:#dbeafe;--ok:#16a34a;--ok-soft:#dcfce7;--warn:#d97706;--warn-soft:#fef3c7;--err:#dc2626;--err-soft:#fee2e2;--info:#0891b2;--info-soft:#cffafe;--sim:#7c3aed;--sim-soft:#ede9fe;--neutral:#64748b;--neutral-soft:#e2e8f0;--radius:14px;--shadow:0 1px 2px rgba(15,23,42,.05),0 4px 16px rgba(15,23,42,.06)}
[data-theme=dark]{--bg:#0b1020;--surface:#121a2e;--surface2:#18223a;--border:#24304d;--text:#e6ebf5;--muted:#94a3b8;--accent:#60a5fa;--accent-soft:#1e3a8a55;--ok:#4ade80;--ok-soft:#14532d66;--warn:#fbbf24;--warn-soft:#78350f66;--err:#f87171;--err-soft:#7f1d1d66;--info:#22d3ee;--info-soft:#164e6366;--sim:#a78bfa;--sim-soft:#4c1d9566;--neutral:#94a3b8;--neutral-soft:#33415566;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35)}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.top{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--border)}
.top .in{max-width:1240px;margin:0 auto;padding:14px 28px;display:flex;align-items:center;gap:16px}
.logo{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),#7c3aed);display:grid;place-items:center;color:#fff;font-weight:700;font-size:15px;flex:none}
.top h1{font-size:17px;margin:0;font-weight:650;letter-spacing:-.01em}
.top .sub{color:var(--muted);font-size:12.5px}
.top .act{margin-left:auto;display:flex;gap:8px}
.btn{border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:10px;padding:7px 12px;font:inherit;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
main{max-width:1240px;margin:0 auto;padding:24px 28px 60px}
.hero{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:22px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.kpi:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--tone,var(--accent))}
.kpi .v{font-size:28px;font-weight:700;letter-spacing:-.02em;line-height:1.1}
.kpi .l{color:var(--muted);font-size:12.5px;margin-top:4px}
.kpi.ok{--tone:var(--ok)}.kpi.warn{--tone:var(--warn)}.kpi.err{--tone:var(--err)}.kpi.info{--tone:var(--info)}.kpi.sim{--tone:var(--sim)}.kpi.neutral{--tone:var(--neutral)}
.score{display:flex;align-items:center;gap:18px}
.ring{--p:0;--c:var(--accent);width:64px;height:64px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*1%),var(--surface2) 0);display:grid;place-items:center;flex:none}
.ring b{width:50px;height:50px;border-radius:50%;background:var(--surface);display:grid;place-items:center;font-size:15px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);margin:0 0 18px;overflow:hidden}
.card>h2{font-size:15px;margin:0;padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;font-weight:650}
.card>h2 .n{color:var(--muted);font-weight:500;font-size:13px}
.card .body{padding:16px 18px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 18px;border-bottom:1px solid var(--border);background:var(--surface2)}
.toolbar input{flex:1;min-width:200px;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:10px;padding:8px 12px;font:inherit}
.toolbar input:focus{outline:2px solid var(--accent-soft);border-color:var(--accent)}
.chip{border:1px solid var(--border);background:var(--surface);color:var(--muted);border-radius:999px;padding:5px 11px;font-size:12.5px;cursor:pointer;user-select:none}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
.chip .c{opacity:.75;margin-left:4px}
.tw{overflow:auto;max-height:72vh}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;text-align:left;padding:10px 14px;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;z-index:1}
th:hover{color:var(--text)}
th.asc:after{content:" \2191"}th.desc:after{content:" \2193"}
td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--surface2)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;white-space:nowrap;background:var(--neutral-soft);color:var(--neutral)}
.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.ok{background:var(--ok-soft);color:var(--ok)}.badge.warn{background:var(--warn-soft);color:var(--warn)}.badge.err{background:var(--err-soft);color:var(--err)}.badge.info{background:var(--info-soft);color:var(--info)}.badge.sim{background:var(--sim-soft);color:var(--sim)}
.muted{color:var(--muted)}
.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12.5px}
details.item{border-bottom:1px solid var(--border)}
details.item:last-child{border-bottom:0}
details.item>summary{list-style:none;cursor:pointer;padding:12px 18px;display:flex;gap:12px;align-items:center}
details.item>summary::-webkit-details-marker{display:none}
details.item>summary:before{content:"\203A";color:var(--muted);font-size:18px;transition:transform .15s;width:10px}
details.item[open]>summary:before{transform:rotate(90deg)}
details.item>summary .t{flex:1;font-weight:600}
details.item .det{padding:0 18px 16px 40px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;font-size:13.5px}
.kv b{color:var(--muted);font-weight:600}
.bar{height:8px;background:var(--surface2);border-radius:99px;overflow:hidden}
.bar i{display:block;height:100%;background:var(--accent);border-radius:99px}
.empty{padding:28px;text-align:center;color:var(--muted)}
footer{max-width:1240px;margin:0 auto;padding:0 28px 40px;color:var(--muted);font-size:12px}
.hidden{display:none!important}
@media (max-width:720px){.top .in,main{padding-left:14px;padding-right:14px}.top .act{display:none}}
@media print{.top{position:static;backdrop-filter:none}.top .act,.toolbar{display:none}.tw{max-height:none;overflow:visible}body{background:#fff}.card,.kpi{box-shadow:none;break-inside:avoid}details.item{break-inside:avoid}details.item>.det{display:block}}
'@
$script:RptJs = @'
(function(){
var root=document.documentElement,key='fispa-report-theme';
try{var t=localStorage.getItem(key);if(t)root.dataset.theme=t;else if(window.matchMedia&&matchMedia('(prefers-color-scheme: dark)').matches)root.dataset.theme='dark';}catch(e){}
function q(s,r){return (r||document).querySelector(s)}function qa(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
document.addEventListener('DOMContentLoaded',function(){
var tb=q('#theme');if(tb)tb.addEventListener('click',function(){var d=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=d;try{localStorage.setItem(key,d)}catch(e){}});
var pb=q('#print');if(pb)pb.addEventListener('click',function(){qa('details.item').forEach(function(d){d.open=true});window.print()});
var xb=q('#expand');if(xb)xb.addEventListener('click',function(){var all=qa('details.item'),open=all.some(function(d){return !d.open});all.forEach(function(d){d.open=open})});
qa('[data-filter]').forEach(function(card){
 var input=q('input[type=search]',card),chips=qa('.chip',card),rows=qa('[data-row]',card),cnt=q('.n',card);
 function apply(){var term=(input&&input.value||'').toLowerCase().trim(),on=chips.filter(function(c){return c.classList.contains('on')}).map(function(c){return c.dataset.v}),vis=0;
  rows.forEach(function(r){var okT=!term||r.textContent.toLowerCase().indexOf(term)>=0,okC=!on.length||on.indexOf(r.dataset.s)>=0,show=okT&&okC;r.classList.toggle('hidden',!show);if(show)vis++});
  if(cnt)cnt.textContent=vis+' / '+rows.length}
 if(input)input.addEventListener('input',apply);chips.forEach(function(c){c.addEventListener('click',function(){c.classList.toggle('on');apply()})});apply();
});
qa('table.sort').forEach(function(t){qa('th',t).forEach(function(th,i){th.addEventListener('click',function(){
 var body=t.tBodies[0],rows=Array.prototype.slice.call(body.rows),asc=!th.classList.contains('asc');qa('th',t).forEach(function(h){h.classList.remove('asc','desc')});th.classList.add(asc?'asc':'desc');
 rows.sort(function(a,b){var x=a.cells[i].dataset.v||a.cells[i].textContent,y=b.cells[i].dataset.v||b.cells[i].textContent,nx=parseFloat(x),ny=parseFloat(y);
  var r=(!isNaN(nx)&&!isNaN(ny)&&/^-?[\d.,]+$/.test(x.trim())&&/^-?[\d.,]+$/.test(y.trim()))?nx-ny:x.localeCompare(y,'it',{numeric:true,sensitivity:'base'});return asc?r:-r});
 rows.forEach(function(r){body.appendChild(r)})})})});
});
})();
'@
#endregion RPT-ASSETS

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

    function Invoke-ToolRun($Config, $Items) {
        $list = @($Items)
        $n = $list.Count
        $results = New-Object System.Collections.Generic.List[object]
        $mode = 'ESECUZIONE REALE'
        if ($Config.DryRun) { $mode = 'SIMULAZIONE (nessuna modifica)' }
        if ($Tool.ReadOnly) { $mode = 'SOLA LETTURA' }
        Write-ToolLog ('=== {0} {1} - {2} {3} - {4}' -f $Tool.Title, $Tool.Version, $n, $Tool.ItemNoun, $mode) 'STEP'
        foreach ($k in @($Config.Keys)) { Write-ToolLog ('  {0} = {1}' -f $k, (@($Config[$k]) -join '; ')) }
        for ($i = 0; $i -lt $n; $i++) {
            $item = $list[$i]
            if ($State.Cancel) {
                for ($j = $i; $j -lt $n; $j++) {
                    $results.Add([pscustomobject]@{ Utente = $list[$j].Utente; SID = $list[$j].SID; Origine = $list[$j].Origine; Destinazione = ''; Esito = 'Annullato'; Messaggio = "Annullato dall'operatore"; DurataSec = 0; DimensioneMB = '' })
                    Send-ToolMessage @{ T = 'row'; K = $list[$j].Key; E = 'Annullato' }
                }
                Write-ToolLog "Annullato dall'operatore: $($n - $i) $($Tool.ItemNoun) non elaborati." 'WARN'
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
            $lvl = switch ($r.Esito) { 'OK' { 'OK' } 'Fallito' { 'ERROR' } 'Critico' { 'ERROR' } 'Saltato' { 'WARN' } 'Attenzione' { 'WARN' } default { 'INFO' } }
            $txt = $r.Esito
            if ($r.Messaggio) { $txt += " - $($r.Messaggio)" }
            Write-ToolLog ('{0}: {1} ({2:N0} s)' -f $item.Utente, $txt, $sw.Elapsed.TotalSeconds) $lvl
            Send-ToolMessage @{ T = 'row'; K = $item.Key; E = $r.Esito }
            $results.Add([pscustomobject]@{
                Utente = $item.Utente; SID = $item.SID; Origine = $item.Origine; Destinazione = $r.Destinazione
                Esito = $r.Esito; Messaggio = $r.Messaggio; DurataSec = [math]::Round($sw.Elapsed.TotalSeconds, 0); DimensioneMB = $r.DimensioneMB
                Dati = $r['Dati']
            })
        }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $State.ReportFile = Join-Path $State.LogDir ('{0}_Report_{1}.csv' -f $Tool.Name, $stamp)
        try { $results | Select-Object -Property * -ExcludeProperty Dati | Export-Csv -LiteralPath $State.ReportFile -NoTypeInformation -Delimiter ';' -Encoding UTF8 -ErrorAction Stop }
        catch { Write-ToolLog "Report CSV non scritto: $($_.Exception.Message)" 'ERROR'; $State.ReportFile = $null }
        # report HTML standard (stile comune _lib/report), sostituito da quello del tool se definito
        try {
            $badge = (($Tool.Name -creplace '[^A-Z]', '') + 'FT').Substring(0, 2)
            $sub = '{0} {1} - {2} - {3} - {4}' -f $Tool.Title, $Tool.Version, $env:COMPUTERNAME, (Get-Date).ToString('dd/MM/yyyy HH:mm'), $mode
            $State.ReportFile = New-RptRunReport -Title "$($Tool.Title): risultati" -Subtitle $sub -Badge $badge -Results $results.ToArray() -Path (Join-Path $State.LogDir ('{0}_Report_{1}.html' -f $Tool.Name, $stamp))
        } catch { Write-ToolLog "Report HTML non scritto: $($_.Exception.Message)" 'WARN' }
        # report aggiuntivo del tool (es. HTML), se il tool definisce Complete-ToolRun
        if (Get-Command Complete-ToolRun -CommandType Function -ErrorAction SilentlyContinue) {
            try {
                $extra = Complete-ToolRun -Config $Config -Results $results.ToArray()
                if ($extra) { $State.ReportFile = [string]@($extra)[-1] }
            } catch { Write-ToolLog "Report finale non generato: $($_.Exception.Message)" 'ERROR' }
        }
        $count = @{}
        foreach ($g in @($results | Group-Object Esito)) { $count[$g.Name] = $g.Count }
        $parts = @("Totale $n")
        foreach ($e in @('OK', 'Simulato', 'Info', 'Attenzione', 'Critico', 'Non verificato', 'Saltato', 'Fallito', 'Annullato')) { if ($count[$e]) { $parts += "$e $($count[$e])" } }
        $summary = $parts -join ' | '
        if (-not $count['Fallito']) { $count['Fallito'] = 0 }
        $lvl = 'OK'
        if ($count['Fallito'] -gt 0 -or $count['Critico'] -gt 0) { $lvl = 'ERROR' } elseif ($count['Saltato'] -or $count['Annullato'] -or $count['Attenzione']) { $lvl = 'WARN' }
        Write-ToolLog "=== Fine. $summary" $lvl
        if ($State.ReportFile) { Write-ToolLog "Report: $($State.ReportFile)" }
        Send-ToolMessage @{ T = 'done'; S = $summary; F = $count['Fallito']; R = $State.ReportFile }
        , $results.ToArray()
    }
    #endregion
