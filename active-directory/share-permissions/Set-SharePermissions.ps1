<#
.SYNOPSIS
    Migra i permessi delle share da utenti a gruppi AD e applica l'hardening delle condivisioni, con GUI configurabile.

.DESCRIPTION
    Analisi (sola lettura) di ogni share di un file server, locale o remoto:
      - utenti con permessi espliciti (lettura o modifica), gruppi, SID orfani
      - accessi troppo ampi (Everyone, Users, Authenticated Users, Domain Users) su NTFS e share
      - ereditarieta', Access-Based Enumeration, cifratura SMB
    Migrazione e hardening, per ogni share selezionata (ogni passo attivabile dalla configurazione):
      1. backup di ACL NTFS (icacls /save) e permessi della share, con il comando di ripristino nel log
      2. gruppi AD per share (<prefisso><Share>_RW e _RO, oppure un gruppo unico), creati via LDAP
      3. utenti trovati nelle ACL aggiunti al gruppo del livello corrispondente
      4. ACE NTFS del gruppo sulla cartella della share (ereditata da tutto l'albero)
      5. rimozione delle ACE esplicite degli utenti migrati, solo se sono membri del gruppo
      6. permessi share standard, Access-Based Enumeration, cifratura SMB
    Non serve il modulo ActiveDirectory. Simulazione attiva di default.

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\SharePermissions\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia con la configurazione salvata.

.PARAMETER User
    Con -NoGui: elabora solo queste share (nome).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione.

.EXAMPLE
    .\Set-SharePermissions.ps1

.EXAMPLE
    .\Set-SharePermissions.ps1 -NoGui -ConfigPath D:\Share\fs01.json -User Contabilita,Tecnico -Simulate

.NOTES
    Versione: 1.0.0
    Repo:     fispas/tools (active-directory/share-permissions)
    Richiede: amministratore sul file server, diritti di creazione gruppi nell'OU indicata, PowerShell 5.1
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name         = 'SharePermissions'
    Title        = 'Share: migrazione a gruppi e hardening'
    Version      = '1.0.0'
    ItemNoun     = 'share'
    ItemTab      = 'Share'
    StartLabel   = 'Applica alle share'
    RunningLabel = 'Elaborazione delle share in corso'
    CloseWarning = ''
    ConfirmKeys  = @('FileServer', 'GroupOU', 'GroupMode', 'GroupScope', 'CreateGroups', 'PopulateGroups', 'GrantGroupNtfs', 'RemoveUserAces', 'SharePermissions', 'EnableABE', 'EncryptData', 'BackupDir')
}

#region AVVIO (libreria _lib/toolkit)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
# $Tool.RequiresAdmin = $false per i tool in sola lettura che funzionano anche da utente standard
$needAdmin = -not ($Tool.ContainsKey('RequiresAdmin') -and -not $Tool.RequiresAdmin)
if (-not $NoGui -and ((-not $isAdmin -and $needAdmin) -or -not $isSta)) {
    $argList = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($ConfigPath) { $argList += @('-ConfigPath', "`"$ConfigPath`"") }
    try {
        if ($isAdmin -or -not $needAdmin) { Start-Process -FilePath powershell.exe -ArgumentList $argList }
        else { Start-Process -FilePath powershell.exe -ArgumentList $argList -Verb RunAs }
    } catch {
        Write-Error "Avvio come amministratore annullato o non riuscito: $($_.Exception.Message)"
    }
    return
}
if (-not $isAdmin -and $needAdmin) {
    Write-Error 'Servono i privilegi di amministratore: aprire PowerShell come amministratore.'
    exit 1
}

$State = [hashtable]::Synchronized(@{
    Queue      = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    Cancel     = $false
    Headless   = [bool]$NoGui
    LogDir     = $null
    LogFile    = $null
    ReportFile = $null
})
#endregion

# Motore: definito una volta, usato dalla GUI, dal runspace di esecuzione e dalla modalita' -NoGui
$Engine = {
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
        # configurazione nel log, senza i valori segreti (password, token, chiavi)
        foreach ($k in @($Config.Keys)) {
            $v = if ($k -match 'Password|Secret|Token|ApiKey|Credential') { '(nascosto)' } else { (@($Config[$k]) -join '; ') }
            Write-ToolLog ('  {0} = {1}' -f $k, $v)
        }
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

    #region SPECIFICO: share -> gruppi AD e hardening

    $script:DcName = $null
    $script:SidCache = @{}

    function Get-ToolDefaultConfig {
        [ordered]@{
            FileServer       = [string]$env:COMPUTERNAME
            IncludeShares    = @()
            ExcludeShares    = @('NETLOGON', 'SYSVOL', 'print$')
            IncludeHidden    = $false
            DomainController = ''
            GroupOU          = ''
            GroupPrefix      = 'GR-'
            GroupMode        = 'Separati (RW/RO)'
            GroupSuffixRW    = '_RW'
            GroupSuffixRO    = '_RO'
            GroupScope       = 'DomainLocal'
            CreateGroups     = $true
            PopulateGroups   = $true
            IncludeAclGroups = $false
            GrantGroupNtfs   = $true
            RemoveUserAces   = 'No'
            SharePermissions = 'Non modificare'
            EnableABE        = $false
            EncryptData      = $false
            BackupDir        = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Backup'))
            BackupTree       = $false
            ExcludeUsers     = @()
            LogDir           = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun           = $true
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) { $w += 'Cmdlet SMB (Get-SmbShare) non disponibili: serve Windows Server 2012 / Windows 8 o successivi.' }
        if (-not $env:USERDNSDOMAIN) { $w += "Sessione non di dominio: gruppi e utenti AD non saranno risolti." }
        $w
    }

    # ------------------------------------------------------------------ AD via LDAP (niente modulo ActiveDirectory)

    function Get-DcPrefix($Config) {
        if (-not $script:DcName) {
            if ($Config.DomainController) { $script:DcName = [string]$Config.DomainController }
            else {
                try { $script:DcName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name }
                catch { throw "Nessun domain controller raggiungibile: $($_.Exception.Message)" }
            }
            Write-ToolLog "Domain controller usato per tutte le operazioni LDAP: $script:DcName"
        }
        'LDAP://' + $script:DcName + '/'
    }

    function ConvertTo-LdapFilterValue([string]$Value) {
        $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
    }

    function ConvertTo-AdsPath([string]$Dn) { $Dn.Replace('/', '\/') }

    # SID -> oggetto AD (classe, DN, sAMAccountName). $null se non e' un oggetto del dominio
    function Get-AdObjectBySid($Config, [string]$Sid) {
        if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
        $o = $null
        try {
            $de = [adsi]((Get-DcPrefix $Config) + "<SID=$Sid>")
            $classes = @($de.Properties['objectClass'])
            if ($classes.Count) {
                $cls = 'altro'
                if ($classes -contains 'computer') { $cls = 'computer' }
                elseif ($classes -contains 'user') { $cls = 'user' }
                elseif ($classes -contains 'group') { $cls = 'group' }
                $o = [pscustomobject]@{
                    Sid  = $Sid
                    Dn   = [string]$de.Properties['distinguishedName'][0]
                    Sam  = [string]$de.Properties['sAMAccountName'][0]
                    Name = [string]$de.Properties['name'][0]
                    Class = $cls
                    GroupType = $(if ($cls -eq 'group') { [int]$de.Properties['groupType'][0] } else { 0 })
                }
            }
        } catch { $o = $null }
        $script:SidCache[$Sid] = $o
        $o
    }

    function Find-AdGroup($Config, [string]$Sam) {
        $root = [adsi]((Get-DcPrefix $Config) + 'RootDSE')
        $base = [adsi]((Get-DcPrefix $Config) + [string]$root.Properties['defaultNamingContext'][0])
        $ds = New-Object System.DirectoryServices.DirectorySearcher($base)
        $ds.Filter = '(&(objectCategory=group)(sAMAccountName={0}))' -f (ConvertTo-LdapFilterValue $Sam)
        [void]$ds.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid'))
        $r = $ds.FindOne()
        if (-not $r) { return $null }
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($r.Properties['objectsid'][0], 0)).Value
        [pscustomobject]@{ Sam = $Sam; Dn = [string]$r.Properties['distinguishedname'][0]; Sid = $sid; Created = $false }
    }

    function New-AdGroupLdap($Config, [string]$Sam, [string]$Description) {
        $types = @{ 'Global' = -2147483646; 'DomainLocal' = -2147483644; 'Universal' = -2147483640 }
        $ou = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Config.GroupOU))
        $g = $ou.Create('group', "CN=$Sam")
        $g.Put('sAMAccountName', $Sam)
        $g.Put('groupType', [int]$types[$Config.GroupScope])
        $g.Put('description', $Description)
        $g.SetInfo()
        $g.RefreshCache(@('objectSid', 'distinguishedName'))
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($g.Properties['objectSid'][0], 0)).Value
        [pscustomobject]@{ Sam = $Sam; Dn = [string]$g.Properties['distinguishedName'][0]; Sid = $sid; Created = $true }
    }

    # Aggiunge un membro. Restituisce 'aggiunto', 'presente' o lancia un errore
    function Add-AdGroupMemberLdap($Config, $Group, [string]$MemberDn) {
        $g = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Group.Dn))
        $mPath = (Get-DcPrefix $Config) + (ConvertTo-AdsPath $MemberDn)
        if ($g.IsMember($mPath)) { return 'presente' }
        $g.Add($mPath)
        'aggiunto'
    }

    # ------------------------------------------------------------------ file server

    function Test-IsLocalServer([string]$Server) {
        $s = ([string]$Server).Trim().ToLower()
        if (-not $s -or $s -in @('.', 'localhost', '127.0.0.1')) { return $true }
        $names = @($env:COMPUTERNAME.ToLower())
        try { $names += [System.Net.Dns]::GetHostEntry('localhost').HostName.ToLower() } catch { }
        if ($env:USERDNSDOMAIN) { $names += ($env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN).ToLower() }
        $names -contains $s
    }

    function New-ToolCim($Config) {
        if (Test-IsLocalServer $Config.FileServer) { return $null }
        try { return New-CimSession -ComputerName $Config.FileServer -ErrorAction Stop }
        catch {
            Write-ToolLog "WinRM non disponibile verso $($Config.FileServer), provo DCOM: $($_.Exception.Message)" 'WARN'
            $opt = New-CimSessionOption -Protocol Dcom
            return New-CimSession -ComputerName $Config.FileServer -SessionOption $opt -ErrorAction Stop
        }
    }

    function Get-CimParams($Cim) {
        $p = @{ ErrorAction = 'Stop' }
        if ($Cim) { $p.CimSession = $Cim }
        $p
    }

    function Get-AdminPath($Config, [string]$LocalPath) {
        if (Test-IsLocalServer $Config.FileServer) { return $LocalPath }
        if ($LocalPath -match '^[A-Za-z]:') { return '\\' + $Config.FileServer + '\' + $LocalPath.Replace(':', '$') }
        $LocalPath
    }

    # Nome locale (sul file server) di un SID ben noto: i nomi cambiano con la lingua di Windows
    function Get-WellKnownName($Cim, [string]$Sid) {
        $p = Get-CimParams $Cim
        $a = Get-CimInstance @p -ClassName Win32_SystemAccount -Filter "SID='$Sid'" | Select-Object -First 1
        if (-not $a) { $a = Get-CimInstance @p -ClassName Win32_Group -Filter "LocalAccount=TRUE AND SID='$Sid'" | Select-Object -First 1 }
        if (-not $a) { $a = Get-CimInstance @p -ClassName Win32_Group -Filter "SID='$Sid'" | Select-Object -First 1 }   # domain controller: niente account locali
        if (-not $a) { throw "Account $Sid non trovato sul file server" }
        [string]$a.Name
    }

    function Get-SidName([string]$Sid) {
        try { (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $Sid }
    }

    # Categoria di un SID trovato in una ACL
    function Get-SidCategory($Config, [string]$Sid) {
        if ($Sid -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545', 'S-1-5-4', 'S-1-5-2') -or $Sid -match '^S-1-5-21-.+-(513|515)$') { return 'ampio' }
        if ($Sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20', 'S-1-5-32-544', 'S-1-5-32-549', 'S-1-5-32-551', 'S-1-3-0', 'S-1-3-1', 'S-1-3-4', 'S-1-5-9') -or
            $Sid -match '^S-1-5-21-.+-(500|512|518|519|520)$') { return 'amministrativo' }
        if ($Sid -notmatch '^S-1-5-21-') { return 'sistema' }
        $o = Get-AdObjectBySid $Config $Sid
        if (-not $o) { return 'orfano' }
        switch ($o.Class) { 'user' { 'utente' } 'group' { 'gruppo' } default { 'sistema' } }
    }

    # Fotografia di una share: ACL NTFS della cartella, permessi share, impostazioni
    function Get-ShareAnalysis($Config, $Share, $Cim) {
        $adminPath = Get-AdminPath $Config $Share.Path
        $acl = Get-Acl -LiteralPath $adminPath -ErrorAction Stop
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $writeMask = 0xD0006 -bor 0x50000000
        $usersRW = @{}; $usersRO = @{}; $groupsRW = @{}; $groupsRO = @{}
        $broad = @{}; $orphans = @{}; $deny = 0; $explicitUsers = 0
        foreach ($r in $rules) {
            $sid = $r.IdentityReference.Value
            if ($r.AccessControlType -ne 'Allow') { $deny++; continue }
            $isRW = ([int64]$r.FileSystemRights -band $writeMask) -ne 0
            $cat = Get-SidCategory $Config $sid
            switch ($cat) {
                'ampio' { $broad[$sid] = (Get-SidName $sid) }
                'orfano' { $orphans[$sid] = $true }
                'utente' {
                    if (-not $r.IsInherited) { $explicitUsers++ }
                    if ($isRW) { $usersRW[$sid] = $true; $usersRO.Remove($sid) } elseif (-not $usersRW.ContainsKey($sid)) { $usersRO[$sid] = $true }
                }
                'gruppo' {
                    if ($isRW) { $groupsRW[$sid] = $true; $groupsRO.Remove($sid) } elseif (-not $groupsRW.ContainsKey($sid)) { $groupsRO[$sid] = $true }
                }
            }
        }
        $p = Get-CimParams $Cim
        $access = @(Get-SmbShareAccess @p -Name $Share.Name)
        $shareText = (@($access | ForEach-Object { '{0}:{1}{2}' -f $_.AccountName, $_.AccessRight, $(if ($_.AccessControlType -ne 'Allow') { '(deny)' } else { '' }) }) -join ', ')
        [pscustomobject]@{
            AdminPath       = $adminPath
            UsersRW         = @($usersRW.Keys)
            UsersRO         = @($usersRO.Keys)
            GroupsRW        = @($groupsRW.Keys)
            GroupsRO        = @($groupsRO.Keys)
            Broad           = @($broad.Values)
            Orphans         = @($orphans.Keys)
            Deny            = $deny
            ExplicitUsers   = $explicitUsers
            Protected       = $acl.AreAccessRulesProtected
            ShareAccess     = $access
            ShareText       = $shareText
            EveryoneFull    = [bool](@($access | Where-Object { $_.AccessRight -eq 'Full' -and $_.AccessControlType -eq 'Allow' -and $_.AccountName -match '^(Everyone|Tutti|Jeder|Tout le monde|Todos)$' }).Count)
            ABE             = [string]$Share.FolderEnumerationMode
            Encrypt         = [bool]$Share.EncryptData
        }
    }

    function Get-GroupBaseName($Config, [string]$ShareName) {
        $ti = (Get-Culture).TextInfo
        $clean = $ti.ToTitleCase($ShareName.TrimEnd('$').ToLower()) -replace '[^A-Za-z0-9_.-]', ''
        $base = [string]$Config.GroupPrefix + $clean
        if ($base.Length -gt 60) { $base = $base.Substring(0, 60) }
        $base
    }

    function Get-PlannedGroups($Config, [string]$ShareName) {
        $base = Get-GroupBaseName $Config $ShareName
        if ($Config.GroupMode -like 'Unico*') {
            return @([pscustomobject]@{ Sam = $base; Level = 'RW'; Rights = 'M'; Label = 'Modifica' })
        }
        @(
            [pscustomobject]@{ Sam = $base + $Config.GroupSuffixRW; Level = 'RW'; Rights = 'M'; Label = 'Modifica' }
            [pscustomobject]@{ Sam = $base + $Config.GroupSuffixRO; Level = 'RO'; Rights = 'RX'; Label = 'Lettura' }
        )
    }

    function Get-ShareList($Config, $Cim) {
        $p = Get-CimParams $Cim
        $all = @(Get-SmbShare @p | Where-Object { -not $_.Special -and "$($_.ShareType)" -match 'FileSystemDirectory' -and $_.Path })
        $all = @($all | Where-Object { @($Config.ExcludeShares) -notcontains $_.Name })
        if (-not $Config.IncludeHidden) { $all = @($all | Where-Object { -not $_.Name.EndsWith('$') }) }
        if (@($Config.IncludeShares).Count) {
            $all = @($all | Where-Object { $n = $_.Name; @(@($Config.IncludeShares) | Where-Object { $n -like $_ }).Count -gt 0 })
        }
        @($all | Sort-Object Name)
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if (-not $Config.FileServer) { $e += 'Indicare il file server.' }
        if ($Scan) { return $e }
        if ($Config.CreateGroups -or $Config.PopulateGroups -or $Config.GrantGroupNtfs) {
            if ([string]$Config.GroupPrefix -notmatch '^[A-Za-z0-9_.-]*$') { $e += 'Il prefisso dei gruppi puo'' contenere solo lettere, numeri, punto, trattino e trattino basso.' }
        }
        if ($Config.CreateGroups) {
            if (-not $Config.GroupOU) { $e += "Indicare l'OU in cui creare i gruppi (distinguishedName, es. OU=Gruppi,DC=contoso,DC=local)." }
            else {
                try {
                    $ou = [adsi]((Get-DcPrefix $Config) + (ConvertTo-AdsPath $Config.GroupOU))
                    if (-not $ou.Properties['distinguishedName'].Count) { $e += "OU non trovata: $($Config.GroupOU)" }
                } catch { $e += "OU non raggiungibile ($($Config.GroupOU)): $($_.Exception.Message)" }
            }
        }
        if ($Config.RemoveUserAces -ne 'No' -and -not ($Config.PopulateGroups -and $Config.GrantGroupNtfs)) {
            $e += "La rimozione delle ACE degli utenti richiede anche 'Popola i gruppi' e 'Permesso NTFS ai gruppi': senza, gli utenti perderebbero l'accesso."
        }
        if (-not $Config.BackupDir) { $e += 'Indicare la cartella dei backup.' }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        $e
    }

    function Get-ToolItems($Config) {
        Write-ToolLog "Analisi delle share di $($Config.FileServer)" 'STEP'
        $cim = New-ToolCim $Config
        try {
            $shares = Get-ShareList $Config $cim
            Write-ToolLog "Share trovate: $($shares.Count)"
            foreach ($sh in $shares) {
                $groups = @(Get-PlannedGroups $Config $sh.Name | ForEach-Object { $_.Sam }) -join ', '
                try {
                    $a = Get-ShareAnalysis $Config $sh $cim
                    $flags = @()
                    if ($a.Broad.Count) { $flags += 'accesso ampio' }
                    if ($a.EveryoneFull) { $flags += 'Everyone Full sulla share' }
                    if ($a.ExplicitUsers) { $flags += "$($a.ExplicitUsers) ACE utente" }
                    if ($a.Orphans.Count) { $flags += "$($a.Orphans.Count) SID orfani" }
                    if ($a.Deny) { $flags += "$($a.Deny) deny" }
                    if ($a.Protected) { $flags += 'ereditarieta disattivata' }
                    $stato = 'Da migliorare: ' + ($flags -join ', ')
                    if (-not $flags.Count) { $stato = 'Pronto' }
                    [pscustomobject]@{
                        Key          = $sh.Name
                        Utente       = $sh.Name
                        SID          = ''
                        Origine      = $a.AdminPath
                        Share        = $sh.Name
                        Percorso     = $sh.Path
                        Utenti       = ('RW {0} / RO {1}' -f $a.UsersRW.Count, $a.UsersRO.Count)
                        GruppiAcl    = ($a.GroupsRW.Count + $a.GroupsRO.Count)
                        Ampio        = ($a.Broad -join ', ')
                        PermShare    = $a.ShareText
                        ABE          = $(if ($a.ABE -eq 'AccessBased') { 'si' } else { 'no' })
                        Gruppi       = $groups
                        Stato        = $stato
                        Selectable   = $true
                        Analysis     = $a
                        ShareObj     = $sh
                    }
                } catch {
                    Write-ToolLog "Share $($sh.Name): analisi non riuscita - $($_.Exception.Message)" 'ERROR'
                    [pscustomobject]@{
                        Key = $sh.Name; Utente = $sh.Name; SID = ''; Origine = $sh.Path; Share = $sh.Name; Percorso = $sh.Path
                        Utenti = ''; GruppiAcl = ''; Ampio = ''; PermShare = ''; ABE = ''; Gruppi = $groups
                        Stato = "Errore: $($_.Exception.Message)"; Selectable = $false; Analysis = $null; ShareObj = $sh
                    }
                }
            }
        } finally { if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue } }
    }

    function Invoke-Icacls([string[]]$IcaclsArgs, [string]$What) {
        $out = & icacls.exe @IcaclsArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "$What non riuscito (icacls exit $LASTEXITCODE): $(@($out) -join ' ')" }
    }

    function Invoke-ToolItem($Config, $Item) {
        $res = @{ Esito = 'Fallito'; Messaggio = ''; Destinazione = ''; DimensioneMB = '' }
        $cim = New-ToolCim $Config
        try {
            $p = Get-CimParams $Cim
            $share = Get-SmbShare @p -Name $Item.Share
            $a = Get-ShareAnalysis $Config $share $cim          # rilettura: lo stato puo' essere cambiato dall'analisi
            $path = $a.AdminPath
            $planned = @(Get-PlannedGroups $Config $share.Name)
            $exclude = @($Config.ExcludeUsers)
            $members = @{}
            foreach ($g in $planned) { $members[$g.Sam] = New-Object System.Collections.Generic.List[string] }
            $rw = $planned[0].Sam
            $ro = $planned[-1].Sam
            foreach ($sid in $a.UsersRW) { $members[$rw].Add($sid) }
            foreach ($sid in $a.UsersRO) { $members[$ro].Add($sid) }
            if ($Config.IncludeAclGroups) {
                foreach ($sid in $a.GroupsRW) { $members[$rw].Add($sid) }
                foreach ($sid in $a.GroupsRO) { $members[$ro].Add($sid) }
            }
            foreach ($k in @($members.Keys)) {
                $keep = New-Object System.Collections.Generic.List[string]
                foreach ($sid in $members[$k]) {
                    $o = Get-AdObjectBySid $Config $sid
                    if ($o -and $exclude -contains $o.Sam) { Write-ToolLog "Escluso da configurazione: $($o.Sam)"; continue }
                    $keep.Add($sid)
                }
                $members[$k] = $keep
            }

            Write-ToolLog "Percorso: $path"
            Write-ToolLog ('Utenti in ACL: RW {0}, RO {1}; gruppi in ACL: {2}; accesso ampio: {3}' -f $a.UsersRW.Count, $a.UsersRO.Count, ($a.GroupsRW.Count + $a.GroupsRO.Count), ($(if ($a.Broad.Count) { $a.Broad -join ', ' } else { 'nessuno' })))
            foreach ($g in $planned) {
                $names = @($members[$g.Sam] | ForEach-Object { $o = Get-AdObjectBySid $Config $_; if ($o) { $o.Sam } else { $_ } })
                Write-ToolLog ('Gruppo {0} ({1}): {2} membri da ACL{3}' -f $g.Sam, $g.Label, $names.Count, $(if ($names.Count) { ' - ' + ($names -join ', ') } else { '' }))
            }

            if ($Config.DryRun) {
                $steps = @()
                if ($Config.CreateGroups) { $steps += 'creazione gruppi mancanti' }
                if ($Config.PopulateGroups) { $steps += 'popolamento gruppi' }
                if ($Config.GrantGroupNtfs) { $steps += 'ACE NTFS dei gruppi' }
                if ($Config.RemoveUserAces -ne 'No') { $steps += "rimozione ACE utente ($($Config.RemoveUserAces))" }
                if ($Config.SharePermissions -ne 'Non modificare') { $steps += 'permessi share standard' }
                if ($Config.EnableABE) { $steps += 'Access-Based Enumeration' }
                if ($Config.EncryptData) { $steps += 'cifratura SMB' }
                Write-ToolLog ('[Simulazione] passi: backup, ' + ($steps -join ', '))
                $res.Esito = 'Simulato'
                $res.Messaggio = ($steps -join ', ')
                return $res
            }

            # 1. backup
            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $bdir = Join-Path $Config.BackupDir ('{0}\{1}' -f $Config.FileServer, $stamp)
            New-Item -ItemType Directory -Path $bdir -Force | Out-Null
            $safe = $share.Name -replace '[^A-Za-z0-9_.-]', '_'
            $aclFile = Join-Path $bdir "$safe.acl"
            $icArgs = @($path, '/save', $aclFile, '/C', '/Q')
            if ($Config.BackupTree) { $icArgs += '/T' }
            Invoke-Icacls $icArgs 'Backup ACL'
            $shareInfo = [pscustomobject]@{
                Name = $share.Name; Path = $share.Path; FolderEnumerationMode = [string]$share.FolderEnumerationMode; EncryptData = [bool]$share.EncryptData
                Access = @($a.ShareAccess | ForEach-Object { [pscustomobject]@{ AccountName = $_.AccountName; AccessControlType = [string]$_.AccessControlType; AccessRight = [string]$_.AccessRight } })
            }
            [System.IO.File]::WriteAllText((Join-Path $bdir "$safe.share.json"), ($shareInfo | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($true)))
            $parent = Split-Path -Parent $path
            Write-ToolLog "Backup in $bdir. Ripristino ACL: icacls `"$parent`" /restore `"$aclFile`"" 'OK'
            $res.Destinazione = $bdir

            $done = @()
            # 2. gruppi
            $groupObj = @{}
            foreach ($g in $planned) {
                $obj = Find-AdGroup $Config $g.Sam
                if (-not $obj) {
                    if (-not $Config.CreateGroups) { throw "Il gruppo $($g.Sam) non esiste e la creazione e' disattivata." }
                    $obj = New-AdGroupLdap $Config $g.Sam ("Accesso {0} alla share {1} su {2}" -f $g.Label, $share.Name, $Config.FileServer)
                    Write-ToolLog "Gruppo creato: $($obj.Dn)" 'OK'
                    $done += "creato $($g.Sam)"
                } else { Write-ToolLog "Gruppo esistente: $($obj.Dn)" }
                $groupObj[$g.Sam] = $obj
            }

            # 3. membri
            $migrated = @{}
            if ($Config.PopulateGroups) {
                $added = 0
                foreach ($g in $planned) {
                    foreach ($sid in $members[$g.Sam]) {
                        $o = Get-AdObjectBySid $Config $sid
                        if (-not $o) { continue }
                        try {
                            $r = Add-AdGroupMemberLdap $Config $groupObj[$g.Sam] $o.Dn
                            if ($r -eq 'aggiunto') { $added++; Write-ToolLog "  + $($o.Sam) in $($g.Sam)" }
                            $migrated[$sid] = $g.Level
                        } catch { Write-ToolLog "  Impossibile aggiungere $($o.Sam) a $($g.Sam): $($_.Exception.Message)" 'WARN' }
                    }
                }
                $done += "$added membri aggiunti"
            }

            # 4. ACE NTFS dei gruppi (sulla radice, ereditata da file e sottocartelle)
            $granted = @{}
            if ($Config.GrantGroupNtfs) {
                foreach ($g in $planned) {
                    $gs = $groupObj[$g.Sam].Sid
                    Invoke-Icacls @($path, '/grant', ('*{0}:(OI)(CI){1}' -f $gs, $g.Rights), '/C', '/Q') "Permesso NTFS a $($g.Sam)"
                    $granted[$g.Level] = $true
                    Write-ToolLog "ACE NTFS: $($g.Sam) = $($g.Label)" 'OK'
                }
                $done += 'ACE gruppi'
            }

            # 5. rimozione ACE esplicite degli utenti migrati (solo se membri del gruppo del loro livello, e il gruppo ha l'ACE)
            if ($Config.RemoveUserAces -ne 'No') {
                $removed = 0
                foreach ($sid in @($migrated.Keys)) {
                    if (-not $granted.ContainsKey($migrated[$sid])) { continue }
                    $o = Get-AdObjectBySid $Config $sid
                    if (-not $o -or $o.Class -ne 'user') { continue }
                    $rmArgs = @($path, '/remove:g', "*$sid", '/C', '/Q')
                    if ($Config.RemoveUserAces -like 'Intero*') { $rmArgs += '/T' }
                    try { Invoke-Icacls $rmArgs "Rimozione ACE di $($o.Sam)"; $removed++; Write-ToolLog "  - ACE esplicita rimossa: $($o.Sam)" }
                    catch { Write-ToolLog $_.Exception.Message 'WARN' }
                }
                $done += "$removed ACE utente rimosse"
            }

            # 6. permessi share, ABE, cifratura
            if ($Config.SharePermissions -ne 'Non modificare') {
                $auth = Get-WellKnownName $cim 'S-1-5-11'
                $adm = Get-WellKnownName $cim 'S-1-5-32-544'
                $every = Get-WellKnownName $cim 'S-1-1-0'
                Grant-SmbShareAccess @p -Name $share.Name -AccountName $auth -AccessRight Change -Force | Out-Null
                Grant-SmbShareAccess @p -Name $share.Name -AccountName $adm -AccessRight Full -Force | Out-Null
                if (@($a.ShareAccess | Where-Object { $_.AccountName -match ('(^|\\)' + [regex]::Escape($every) + '$') }).Count) {
                    Revoke-SmbShareAccess @p -Name $share.Name -AccountName $every -Force | Out-Null
                    Write-ToolLog "Permesso share rimosso: $every"
                }
                Write-ToolLog "Permessi share: $auth = Modifica, $adm = Controllo completo (i permessi effettivi li decide NTFS)" 'OK'
                $done += 'permessi share'
            }
            if ($Config.EnableABE -and $share.FolderEnumerationMode -ne 'AccessBased') {
                Set-SmbShare @p -Name $share.Name -FolderEnumerationMode AccessBased -Force
                Write-ToolLog 'Access-Based Enumeration attivata' 'OK'
                $done += 'ABE'
            }
            if ($Config.EncryptData -and -not $share.EncryptData) {
                Set-SmbShare @p -Name $share.Name -EncryptData $true -Force
                Write-ToolLog 'Cifratura SMB attivata (i client senza SMB 3 non accedono piu)' 'WARN'
                $done += 'cifratura SMB'
            }

            $res.Esito = 'OK'
            $res.Messaggio = ($done -join ', ')
            $res
        } finally {
            if ($cim) { Remove-CimSession $cim -ErrorAction SilentlyContinue }
        }
    }
    #endregion
}

#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'File server e share' }
    @{ Key = 'FileServer'; Label = 'File server'; Type = 'Text'; Help = 'Nome del server con le share. Predefinito: questa macchina. In remoto servono WinRM (o DCOM) e i diritti di amministratore sul server.' }
    @{ Key = 'IncludeShares'; Label = 'Solo queste share'; Type = 'List'; Help = 'Nomi o caratteri jolly separati da punto e virgola (es. Contab*; Tecnico). Vuoto = tutte.' }
    @{ Key = 'ExcludeShares'; Label = 'Share escluse'; Type = 'List'; Help = 'Le share amministrative (C$, ADMIN$, IPC$) sono sempre escluse.' }
    @{ Key = 'IncludeHidden'; Label = 'Includi le share nascoste (nome$)'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Gruppi AD' }
    @{ Key = 'GroupOU'; Label = 'OU dei gruppi'; Type = 'Text'; Help = 'distinguishedName dell''OU in cui creare i gruppi, es. OU=Condivisioni,OU=Gruppi,DC=contoso,DC=local.' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente. Tutte le operazioni LDAP usano lo stesso DC, cosi'' un gruppo appena creato e'' subito utilizzabile.' }
    @{ Key = 'GroupPrefix'; Label = 'Prefisso'; Type = 'Text'; Help = 'Il nome del gruppo e'' <prefisso><NomeShare><suffisso>, es. GR-Contabilita_RW.' }
    @{ Key = 'GroupMode'; Label = 'Gruppi per share'; Type = 'Choice'; Choices = @('Separati (RW/RO)', 'Unico (Modifica)'); Help = 'Separati: un gruppo in modifica e uno in lettura, con gli utenti assegnati in base al permesso che hanno oggi. Unico: un solo gruppo in modifica (come gli script originali).' }
    @{ Key = 'GroupSuffixRW'; Label = 'Suffisso modifica'; Type = 'Text' }
    @{ Key = 'GroupSuffixRO'; Label = 'Suffisso lettura'; Type = 'Text' }
    @{ Key = 'GroupScope'; Label = 'Ambito dei gruppi'; Type = 'Choice'; Choices = @('DomainLocal', 'Global', 'Universal'); Help = 'DomainLocal e'' la scelta consigliata per i gruppi di risorsa (modello AGDLP: utenti -> gruppi globali di ruolo -> gruppi locali di dominio sulla risorsa).' }
    @{ Type = 'Section'; Label = 'Migrazione dei permessi' }
    @{ Key = 'CreateGroups'; Label = 'Crea i gruppi mancanti'; Type = 'Bool' }
    @{ Key = 'PopulateGroups'; Label = 'Popola i gruppi con gli utenti trovati nelle ACL'; Type = 'Bool'; Help = 'Utenti con permesso di scrittura -> gruppo modifica; solo lettura -> gruppo lettura. Account amministrativi, di sistema e orfani non vengono aggiunti.' }
    @{ Key = 'IncludeAclGroups'; Label = 'Aggiungi anche i gruppi presenti nelle ACL come membri'; Type = 'Bool'; Help = 'Annida nei nuovi gruppi i gruppi che oggi hanno permessi sulla share (Domain Users e simili esclusi).' }
    @{ Key = 'GrantGroupNtfs'; Label = 'Permesso NTFS ai gruppi sulla cartella della share'; Type = 'Bool'; Help = 'Modifica / Lettura ed esecuzione, ereditato da tutte le sottocartelle e file.' }
    @{ Key = 'RemoveUserAces'; Label = 'Rimuovi le ACE esplicite degli utenti migrati'; Type = 'Choice'; Choices = @('No', 'Solo radice', 'Intero albero'); Help = "Solo per gli utenti aggiunti con successo al gruppo del loro livello. 'Intero albero' toglie anche i loro permessi espliciti nelle sottocartelle: chi aveva accessi particolari in una sottocartella li perde. Valutare prima con la simulazione." }
    @{ Type = 'Section'; Label = 'Hardening della share' }
    @{ Key = 'SharePermissions'; Label = 'Permessi della share'; Type = 'Choice'; Choices = @('Non modificare', 'Standard (Authenticated Users Modifica, Administrators Full)'); Help = "Standard: i permessi effettivi li decide NTFS; viene rimosso Everyone. I nomi degli account sono risolti sul file server, quindi funziona con qualunque lingua di Windows." }
    @{ Key = 'EnableABE'; Label = 'Attiva Access-Based Enumeration'; Type = 'Bool'; Help = "Ogni utente vede solo le cartelle a cui ha accesso." }
    @{ Key = 'EncryptData'; Label = 'Attiva la cifratura SMB'; Type = 'Bool'; Help = 'Richiede client SMB 3 (Windows 8 / Server 2012 e successivi): gli altri non accedono piu''.' }
    @{ Type = 'Section'; Label = 'Backup, log e simulazione' }
    @{ Key = 'BackupDir'; Label = 'Cartella dei backup'; Type = 'Folder'; Help = 'Per ogni share: ACL (icacls /save) e permessi della share in JSON, prima di qualunque modifica. Il comando di ripristino e'' scritto nel log.' }
    @{ Key = 'BackupTree'; Label = "Backup delle ACL di tutto l'albero"; Type = 'Bool'; Help = "Consigliato se si rimuovono le ACE nell'intero albero. Su share molto grandi richiede tempo." }
    @{ Key = 'ExcludeUsers'; Label = 'Utenti da non migrare'; Type = 'List'; Help = 'SamAccountName separati da punto e virgola: restano con i permessi attuali.' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = 'Attiva di default: per ogni share mostra gruppi, membri e passi che verrebbero eseguiti.' }
)

$ToolColumns = @(
    @{ Name = 'Share'; Header = 'Share'; Weight = 10 }
    @{ Name = 'Percorso'; Header = 'Percorso'; Weight = 14 }
    @{ Name = 'Utenti'; Header = 'Utenti in ACL'; Weight = 8 }
    @{ Name = 'GruppiAcl'; Header = 'Gruppi in ACL'; Weight = 6 }
    @{ Name = 'Ampio'; Header = 'Accesso ampio'; Weight = 12 }
    @{ Name = 'PermShare'; Header = 'Permessi share'; Weight = 14 }
    @{ Name = 'ABE'; Header = 'ABE'; Weight = 4 }
    @{ Name = 'Gruppi'; Header = 'Gruppi previsti'; Weight = 14 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 16 }
)
#endregion

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
