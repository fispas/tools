<#
.SYNOPSIS
    Active Directory: fotografia di sicurezza (fase 1) e hardening guidato (fase 2), con GUI configurabile.

.DESCRIPTION
    Modalita' Fotografia (sola lettura): controlli in stile PingCastle / Purple Knight sul dominio corrente,
    via LDAP/ADSI senza moduli aggiuntivi. Per ogni controllo: esito, punti di rischio, evidenze, remediation.
    Output: report HTML navigabile, JSON completo, CSV dei risultati e delle evidenze.

    Modalita' Hardening: azioni correttive selezionabili una per una. Per ciascuna lo strumento verifica lo
    stato attuale (Analizza), mostra il piano, salva lo stato precedente (backup JSON), applica e verifica di
    nuovo. Simulazione attiva di default. Aree: dominio (cestino AD, MachineAccountQuota, pre-Windows 2000,
    KDS root key, policy password), account privilegiati (Schema Admins, sensibili non delegabili, Protected
    Users, PSO admin, adminCount orfani, rotazione krbtgt in due passaggi), account (preautenticazione, DES,
    cifratura reversibile, password non obbligatoria, Guest, inattivi), Windows LAPS (schema, permessi, GPO),
    GPO di hardening per DC e membri (firma LDAP/SMB, channel binding, NTLMv2, SMBv1, Spooler, RunAsPPL,
    WDigest, registri), criteri di controllo avanzati sui DC, tier model (OU, gruppi, GPO di deny logon).
    Modalita' Ripristino: annulla le azioni di un'esecuzione di hardening partendo dai suoi backup JSON.
    La fotografia si confronta in automatico con la precedente dello stesso dominio (rischi nuovi e risolti).
    L'hardening richiede gli strumenti RSAT (ActiveDirectory, GroupPolicy) e un account Domain Admins
    (alcune azioni Enterprise o Schema Admins).

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\ADAssessment\config.json

.PARAMETER NoGui
    Esegue senza interfaccia (operazione pianificata): fotografia completa, oppure le azioni di hardening
    da applicare secondo la configurazione (Mode, DryRun). In hardening o ripristino reale (DryRun false)
    serve -User con l'elenco delle azioni: senza elenco lo strumento si ferma.

.PARAMETER User
    Con -NoGui: esegue solo questi controlli o azioni (ID, es. K-ASREP-01 oppure HD-MAQ).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione (nessuna modifica) anche se la configurazione dice il contrario.

.EXAMPLE
    .\Invoke-ADAssessment.ps1

.EXAMPLE
    .\Invoke-ADAssessment.ps1 -NoGui -ConfigPath D:\Assessment\contoso.json

.EXAMPLE
    .\Invoke-ADAssessment.ps1 -NoGui -ConfigPath D:\Assessment\contoso-hardening.json -User HD-MAQ,HD-PRE2K -Simulate

.NOTES
    Versione: 0.3.1 (fotografia, hardening, ripristino, confronto)
    Repo:     fispas/tools (active-directory/ad-hardening)
    Richiede: macchina nel dominio, PowerShell 5.1; per l'hardening RSAT AD + GPMC
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name         = 'ADAssessment'
    Title        = 'Active Directory: fotografia e hardening'
    Version      = '0.3.1'
    ReadOnly     = $true
    RequiresAdmin = $false
    ItemNoun     = 'controlli o azioni'
    ItemTab      = 'Controlli e azioni'
    StartLabel   = 'Esegui'
    RunningLabel = 'Esecuzione in corso'
    CloseWarning = "`nIn hardening l'azione in corso viene completata prima di chiudere."
    ConfirmKeys  = @('Mode', 'DryRun', 'DomainController', 'GpoLinkMode', 'OutputDir')
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

    #region SPECIFICO: fotografia di sicurezza di Active Directory (sola lettura)

    $script:Dom = $null

    function Get-ToolDefaultConfig {
        [ordered]@{
            Mode             = 'Fotografia'
            DryRun           = $true
            CompareWith      = ''
            RestoreFolder    = ''
            DomainController = ''
            InactiveDays     = 90
            KrbtgtMaxDays    = 180
            PrivilegedMax    = 5
            MaxEvidence      = 200
            CheckDcServices  = $true
            ScanSysvolGpp    = $true
            OutputDir        = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Report'))
            LogDir           = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            # fase 2 - hardening
            GpoPrefix              = 'FispaTools'
            GpoLinkMode            = 'Collegata e attiva'
            MemberHardeningOus     = @()
            LmCompatibilityLevel   = 5
            LdapChannelBinding     = 'Se supportato'
            SecurityLogMaxMB       = 4096
            StopSpoolerNow         = $true
            DomainMinPasswordLength = 12
            DomainLockoutThreshold = 10
            DomainLockoutMinutes   = 15
            AdminPsoMinLength      = 16
            AdminPsoMaxAgeDays     = 365
            ProtectedUsersMode     = 'Elenco'
            ProtectedUsersList     = @()
            BreakGlassAccounts     = @()
            InactiveAction         = 'Disattiva'
            QuarantineOu           = ''
            InactiveExclude        = @()
            InactiveSkipWithSpn    = $true
            KrbtgtMinHours         = 24
            LapsOus                = @()
            LapsPasswordLength     = 20
            LapsPasswordAgeDays    = 30
            LapsAdminAccount       = ''
            TierRootName           = 'Admin'
            TierLinkGpos           = $false
        }
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        if (-not $env:USERDNSDOMAIN) { $w += 'Sessione non di dominio: eseguire da una macchina del dominio con un account di dominio.' }
        if ([string]$Config.Mode -eq 'Hardening') {
            foreach ($m in @('ActiveDirectory', 'GroupPolicy')) { if (-not (Get-Module -ListAvailable -Name $m)) { $w += "Hardening: modulo $m mancante (strumenti RSAT)." } }
            $groups = @([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | ForEach-Object { $_.Value })
            if (-not @($groups | Where-Object { $_ -match '-(512|519)$' }).Count) { $w += 'Hardening: l''account corrente non e'' Domain Admins ne'' Enterprise Admins: molte azioni non avranno i permessi.' }
            if (-not $Config.DryRun) { $w += 'Hardening in ESECUZIONE REALE: le azioni selezionate modificano il dominio (backup dello stato precedente nella cartella dei report).' }
        }
        $w
    }

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        $hard = [string]$Config.Mode -eq 'Hardening'
        # in fotografia lo strumento e' in sola lettura; in hardening e ripristino vale la simulazione
        $Tool.ReadOnly = [string]$Config.Mode -eq 'Fotografia'
        if ([string]$Config.Mode -eq 'Ripristino' -and -not ($Config.RestoreFolder -and (Test-Path -LiteralPath ([string]$Config.RestoreFolder)))) { $e += 'Ripristino: indicare la cartella di un''esecuzione di hardening (Hardening_<dominio>_<data>).' }
        if ($Config.CompareWith -and -not (Test-Path -LiteralPath ([string]$Config.CompareWith))) { $e += "Fotografia da confrontare non trovata: $($Config.CompareWith)" }
        # senza interfaccia niente modifiche "di tutto quello che serve": le azioni reali vanno elencate una per una
        if ($State.Headless -and [string]$Config.Mode -in @('Hardening', 'Ripristino') -and -not $Config.DryRun -and -not $User) {
            $e += 'Senza interfaccia l''hardening o il ripristino reale richiedono l''elenco esplicito delle azioni (-User HD-MAQ,HD-PRE2K...); per vedere cosa verrebbe fatto usare -Simulate.'
        }
        try { [void](Get-AdContext $Config) } catch { $e += "Dominio non raggiungibile: $($_.Exception.Message)" }
        if (-not $Scan -and -not $Config.OutputDir) { $e += 'Indicare la cartella dei report.' }
        if ($hard) {
            if ([string]$Config.GpoPrefix -notmatch '^[A-Za-z0-9 _.-]{2,40}$') { $e += 'Prefisso delle GPO non valido (2-40 caratteri: lettere, numeri, spazio, _ . -).' }
            if ([string]$Config.TierRootName -notmatch '^[A-Za-z0-9 _-]{1,40}$') { $e += 'Nome dell''OU radice del tier model non valido.' }
            if ([string]$Config.InactiveAction -eq 'Disattiva e sposta' -and -not $Config.QuarantineOu) { $e += 'Indicare l''OU di quarantena per gli account inattivi.' }
            foreach ($ou in @(@($Config.MemberHardeningOus) + @($Config.LapsOus) + @($Config.QuarantineOu) | Where-Object { $_ })) {
                if ($ou -notmatch '^(OU|CN)=.+,DC=') { $e += "OU non valida (serve il distinguished name): $ou" }
            }
            if ([int]$Config.LmCompatibilityLevel -lt 3 -or [int]$Config.LmCompatibilityLevel -gt 5) { $e += 'LmCompatibilityLevel: da 3 a 5.' }
        }
        $e
    }

    # ------------------------------------------------------------------ accesso LDAP

    function Get-AdContext($Config) {
        if ($script:Dom) { return $script:Dom }
        $dc = [string]$Config.DomainController
        if (-not $dc) { $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name }
        $root = [adsi]"LDAP://$dc/RootDSE"
        $dn = [string]$root.Properties['defaultNamingContext'][0]
        if (-not $dn) { throw "RootDSE non leggibile su $dc" }
        $domObj = [adsi]"LDAP://$dc/$dn"
        $sid = (New-Object System.Security.Principal.SecurityIdentifier($domObj.Properties['objectSid'][0], 0)).Value
        $script:Dom = [pscustomobject]@{
            Dc        = $dc
            Dn        = $dn
            Dns       = ($dn -replace '^DC=', '' -replace ',DC=', '.')
            ConfigDn  = [string]$root.Properties['configurationNamingContext'][0]
            SchemaDn  = [string]$root.Properties['schemaNamingContext'][0]
            Sid       = $sid
            DomainFL  = [int]$root.Properties['domainFunctionality'][0]
            ForestFL  = [int]$root.Properties['forestFunctionality'][0]
            Now       = [DateTime]::UtcNow
        }
        $script:Dom
    }

    function Search-Ldap($Config, [string]$Filter, [string[]]$Props, [string]$Base, [string]$Scope = 'Subtree') {
        $ctx = Get-AdContext $Config
        if (-not $Base) { $Base = $ctx.Dn }
        $de = [adsi]"LDAP://$($ctx.Dc)/$($Base.Replace('/', '\/'))"
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
        $ds.Filter = $Filter
        $ds.PageSize = 1000
        $ds.SearchScope = $Scope
        [void]$ds.PropertiesToLoad.AddRange($Props)
        $out = New-Object System.Collections.Generic.List[object]
        $res = $ds.FindAll()
        try {
            foreach ($r in $res) {
                $h = @{}
                foreach ($p in $Props) {
                    $v = @($r.Properties[$p.ToLower()])
                    if ($v.Count -eq 1) { $h[$p] = $v[0] } elseif ($v.Count -gt 1) { $h[$p] = $v } else { $h[$p] = $null }
                }
                $out.Add([pscustomobject]$h)
            }
        } finally { $res.Dispose() }
        , $out.ToArray()
    }

    function Get-LdapObject($Config, [string]$Dn, [string[]]$Props) {
        $r = @(Search-Ldap $Config '(objectClass=*)' $Props $Dn 'Base')
        if ($r.Count) { $r[0] } else { $null }
    }

    function ConvertFrom-FileTime($v) {
        if ($null -eq $v) { return $null }
        $n = [int64]$v
        if ($n -le 0 -or $n -ge [DateTime]::MaxValue.ToFileTimeUtc()) { return $null }
        [DateTime]::FromFileTimeUtc($n)
    }

    function Get-AgeDays($v) {
        $d = ConvertFrom-FileTime $v
        if (-not $d) { return $null }
        [math]::Floor(((Get-AdContext $null).Now - $d).TotalDays)
    }

    function Get-SidDn($Config, [string]$Sid) {
        $ctx = Get-AdContext $Config
        try { [string]([adsi]"LDAP://$($ctx.Dc)/<SID=$Sid>").Properties['distinguishedName'][0] } catch { $null }
    }

    # Membri ricorsivi (utenti) di un gruppo, via LDAP_MATCHING_RULE_IN_CHAIN
    function Get-GroupMembersRecursive($Config, [string]$GroupDn) {
        if (-not $GroupDn) { return @() }
        $f = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f $GroupDn.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a')
        @(Search-Ldap $Config $f @('sAMAccountName', 'distinguishedName', 'userAccountControl', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'objectSid', 'servicePrincipalName'))
    }

    function Get-ObjSid($o) {
        if ($o.objectSid -is [byte[]]) { return (New-Object System.Security.Principal.SecurityIdentifier($o.objectSid, 0)).Value }
        ''
    }

    function Test-Uac($o, [int]$Flag) { ([int]$o.userAccountControl -band $Flag) -ne 0 }

    $script:UserProps = @('sAMAccountName', 'distinguishedName', 'userAccountControl', 'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'servicePrincipalName', 'objectSid', 'whenCreated')

    function Get-PrivilegedGroups($Config) {
        $ctx = Get-AdContext $Config
        @(
            @{ Name = 'Domain Admins'; Sid = "$($ctx.Sid)-512" }
            @{ Name = 'Enterprise Admins'; Sid = "$($ctx.Sid)-519" }
            @{ Name = 'Schema Admins'; Sid = "$($ctx.Sid)-518" }
            @{ Name = 'Administrators'; Sid = 'S-1-5-32-544' }
            @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548' }
            @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549' }
            @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550' }
            @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551' }
            @{ Name = 'Replicator'; Sid = 'S-1-5-32-552' }
            @{ Name = 'Key Admins'; Sid = "$($ctx.Sid)-526" }
            @{ Name = 'Enterprise Key Admins'; Sid = "$($ctx.Sid)-527" }
        )
    }

    function Get-PrivilegedUsers($Config) {
        if ($script:PrivUsers) { return $script:PrivUsers }
        $map = @{}
        foreach ($g in (Get-PrivilegedGroups $Config)) {
            $dn = Get-SidDn $Config $g.Sid
            foreach ($u in (Get-GroupMembersRecursive $Config $dn)) {
                $k = [string]$u.distinguishedName
                if (-not $map.ContainsKey($k)) { $map[$k] = [pscustomobject]@{ User = $u; Groups = New-Object System.Collections.Generic.List[string] } }
                $map[$k].Groups.Add($g.Name)
            }
        }
        $script:PrivUsers = @($map.Values)
        $script:PrivUsers
    }
    $script:PrivUsers = $null

    # Risultato standard di un controllo
    function New-CheckResult([string]$Status, [string]$Summary, $Evidence = @(), [string]$Remediation = '') {
        [pscustomobject]@{ Status = $Status; Summary = $Summary; Evidence = @($Evidence); Remediation = $Remediation }
    }

    function Format-Evidence($Objects, [scriptblock]$Text, $Config) {
        $max = [int]$Config.MaxEvidence
        if ($max -le 0) { $max = 200 }
        $all = @($Objects)
        $out = @($all | Select-Object -First $max | ForEach-Object { & $Text $_ })
        if ($all.Count -gt $max) { $out += "... altri $($all.Count - $max) (vedi JSON)" }
        $out
    }

    # ------------------------------------------------------------------ catalogo dei controlli
    # Ogni controllo: Id, Categoria, Titolo, Peso (punti di rischio se Critico; meta' se Attenzione), Richiede, Run (scriptblock che riceve $Config)

    function Get-AdChecks {
        @(
            # ----------------------------------------------------- salute
            @{ Id = 'H-DC-01'; Cat = 'Salute del dominio'; Title = 'Domain controller e sistemi operativi'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $dcs = @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'lastLogonTimestamp'))
                # 2003/2008: fuori supporto; 2012/2012 R2: anche gli ESU sono finiti il 13/10/2026; 2016: supporto fino al 12/01/2027
                $old = @($dcs | Where-Object { "$($_.operatingSystem)" -match '2003|2008|2012' })
                $soon = @($dcs | Where-Object { "$($_.operatingSystem)" -match '2016' })
                $ev = Format-Evidence $dcs { param($d) '{0} - {1} {2}' -f $d.dNSHostName, $d.operatingSystem, $d.operatingSystemVersion } $Config
                if ($old.Count) { return New-CheckResult 'Critico' "$($dcs.Count) DC, di cui $($old.Count) con sistema operativo fuori supporto (2003, 2008 o 2012/2012 R2: niente piu' aggiornamenti, ESU compresi)" $ev 'Sostituire subito i DC fuori supporto: un DC senza patch espone tutto il dominio.' }
                if ($soon.Count) { return New-CheckResult 'Attenzione' "$($dcs.Count) DC, di cui $($soon.Count) con Windows Server 2016 (supporto fino al 12 gennaio 2027)" $ev 'Pianificare ora la sostituzione dei DC 2016 con 2022 o 2025.' }
                if ($dcs.Count -lt 2) { return New-CheckResult 'Attenzione' 'Un solo domain controller: nessuna ridondanza' $ev 'Aggiungere almeno un secondo DC.' }
                New-CheckResult 'OK' "$($dcs.Count) DC con sistema operativo supportato" $ev
            } }
            @{ Id = 'H-FL-01'; Cat = 'Salute del dominio'; Title = 'Livello funzionale di dominio e foresta'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $names = @{ 0 = '2000'; 1 = '2003 interim'; 2 = '2003'; 3 = '2008'; 4 = '2008 R2'; 5 = '2012'; 6 = '2012 R2'; 7 = '2016'; 10 = '2025' }
                $txt = 'Dominio {0}, foresta {1}' -f $names[$ctx.DomainFL], $names[$ctx.ForestFL]
                if ($ctx.DomainFL -lt 6) { return New-CheckResult 'Attenzione' $txt @() 'Alzare il livello funzionale (almeno 2012 R2, meglio 2016) dopo aver sostituito i DC obsoleti: abilita Protected Users completo, Kerberos armoring, gMSA migliori.' }
                if ($ctx.DomainFL -lt 7) { return New-CheckResult 'Info' $txt @() 'Valutare il passaggio al livello 2016.' }
                New-CheckResult 'OK' $txt
            } }
            @{ Id = 'H-SYSVOL-01'; Cat = 'Salute del dominio'; Title = 'Replica SYSVOL: DFSR o FRS'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $g = Get-LdapObject $Config ("CN=DFSR-GlobalSettings,CN=System,$($ctx.Dn)") @('msDFSR-Flags')
                $flags = $null
                if ($g) { $flags = $g.'msDFSR-Flags' }
                $states = @{ 0 = 'Start (FRS)'; 16 = 'Prepared'; 32 = 'Redirected'; 48 = 'Eliminated (solo DFSR)' }
                if ($null -eq $flags) {
                    # domini creati direttamente con DFSR: nessuno stato di migrazione, ma le sottoscrizioni SYSVOL dei DC esistono
                    $subs = @(Search-Ldap $Config '(&(objectClass=msDFSR-Subscription)(cn=SYSVOL Subscription))' @('distinguishedName'))
                    if ($subs.Count) { return New-CheckResult 'OK' "SYSVOL replicata con DFSR ($($subs.Count) DC sottoscritti)" }
                    if ($ctx.DomainFL -ge 3) { return New-CheckResult 'Critico' 'Migrazione da FRS a DFSR mai avviata: SYSVOL replicata con FRS' @() 'Migrare SYSVOL a DFSR con dfsrmig (prepared, redirected, eliminated). FRS non e'' supportato da Windows Server 2019 in poi.' }
                    return New-CheckResult 'Critico' 'SYSVOL replicata con FRS (livello funzionale < 2008)' @() 'Alzare il livello funzionale e migrare a DFSR.' }
                $st = $states[[int]$flags]
                if ([int]$flags -eq 48) { return New-CheckResult 'OK' "SYSVOL replicata con DFSR (stato: $st)" }
                New-CheckResult 'Critico' "Migrazione FRS -> DFSR incompleta (stato: $st)" @() 'Completare la migrazione con dfsrmig /setglobalstate 3 e verificare con dfsrmig /getmigrationstate.'
            } }
            @{ Id = 'H-BIN-01'; Cat = 'Salute del dominio'; Title = 'Cestino di Active Directory'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $f = Get-LdapObject $Config ("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ctx.ConfigDn)") @('msDS-EnabledFeatureBL')
                if ($f -and $f.'msDS-EnabledFeatureBL') { return New-CheckResult 'OK' 'Cestino AD attivo' }
                New-CheckResult 'Attenzione' 'Cestino AD non attivo: gli oggetti eliminati si recuperano solo da backup' @() 'Enable-ADOptionalFeature "Recycle Bin Feature" (richiede livello foresta 2008 R2, operazione irreversibile).'
            } }
            @{ Id = 'H-FSMO-01'; Cat = 'Salute del dominio'; Title = 'Ruoli FSMO'; Weight = 0; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $f = $d.Forest
                $ev = @("PDC: $($d.PdcRoleOwner.Name)", "RID: $($d.RidRoleOwner.Name)", "Infrastructure: $($d.InfrastructureRoleOwner.Name)", "Schema: $($f.SchemaRoleOwner.Name)", "Domain naming: $($f.NamingRoleOwner.Name)")
                New-CheckResult 'Info' "PDC emulator: $($d.PdcRoleOwner.Name)" $ev
            } }

            # ----------------------------------------------------- account privilegiati
            @{ Id = 'P-ADM-01'; Cat = 'Account privilegiati'; Title = 'Membri dei gruppi privilegiati'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $priv = @(Get-PrivilegedUsers $Config)
                $ctx = Get-AdContext $Config
                $da = @(Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-512"))
                $sa = @(Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-518"))
                $ops = @($priv | Where-Object { @($_.Groups | Where-Object { $_ -like '*Operators' }).Count })
                $ev = Format-Evidence $priv { param($p) '{0} - {1}' -f $p.User.sAMAccountName, (($p.Groups | Sort-Object -Unique) -join ', ') } $Config
                $issues = @()
                if ($da.Count -gt [int]$Config.PrivilegedMax) { $issues += "$($da.Count) Domain Admins (soglia $($Config.PrivilegedMax))" }
                if ($sa.Count) { $issues += "$($sa.Count) membri di Schema Admins (va lasciato vuoto)" }
                if ($ops.Count) { $issues += "$($ops.Count) membri dei gruppi Operators (vanno lasciati vuoti)" }
                $sum = "$($priv.Count) account con privilegi amministrativi"
                if ($issues.Count) { return New-CheckResult 'Attenzione' ($sum + ': ' + ($issues -join '; ')) $ev 'Ridurre al minimo i membri, usare account amministrativi dedicati e separati dagli account quotidiani, svuotare Schema Admins e Operators.' }
                New-CheckResult 'OK' $sum $ev
            } }
            @{ Id = 'P-KRB-01'; Cat = 'Account privilegiati'; Title = 'Eta'' della password di krbtgt'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $k = @(Search-Ldap $Config '(&(objectClass=user)(sAMAccountName=krbtgt))' @('pwdLastSet'))
                $age = Get-AgeDays $k[0].pwdLastSet
                $txt = "Password di krbtgt cambiata $age giorni fa"
                if ($age -gt 3 * [int]$Config.KrbtgtMaxDays) { return New-CheckResult 'Critico' $txt @() 'Ruotare la password di krbtgt due volte, attendendo la replica completa tra le due rotazioni (script ufficiale Microsoft New-KrbtgtKeys).' }
                if ($age -gt [int]$Config.KrbtgtMaxDays) { return New-CheckResult 'Attenzione' $txt @() 'Ruotare periodicamente la password di krbtgt (due rotazioni distanziate).' }
                New-CheckResult 'OK' $txt
            } }
            @{ Id = 'P-ADM-02'; Cat = 'Account privilegiati'; Title = 'Account Administrator integrato'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $a = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-500") @('sAMAccountName', 'pwdLastSet', 'lastLogonTimestamp', 'userAccountControl')
                $pw = Get-AgeDays $a.pwdLastSet
                $ll = Get-AgeDays $a.lastLogonTimestamp
                $ev = @("Nome: $($a.sAMAccountName)", "Password cambiata $pw giorni fa", "Ultimo logon (circa): $(if ($null -ne $ll) { "$ll giorni fa" } else { 'mai' })")
                $iss = @()
                if ($null -ne $ll -and $ll -lt 30) { $iss += 'usato di recente' }
                if ($pw -gt 365) { $iss += 'password vecchia di oltre un anno' }
                if (-not (Test-Uac $a 0x100000)) { $iss += 'non marcato come sensibile e non delegabile' }
                if ($iss.Count) { return New-CheckResult 'Attenzione' ('Administrator integrato: ' + ($iss -join ', ')) $ev 'Usare account amministrativi nominativi; tenere l''Administrator integrato come emergenza, con password lunga custodita, sensibile e non delegabile.' }
                New-CheckResult 'OK' 'Administrator integrato non usato e protetto' $ev
            } }
            @{ Id = 'P-ADC-01'; Cat = 'Account privilegiati'; Title = 'adminCount orfani'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $priv = @{}
                foreach ($p in (Get-PrivilegedUsers $Config)) { $priv[[string]$p.User.distinguishedName] = $true }
                $ac = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(adminCount=1))' @('sAMAccountName', 'distinguishedName'))
                $orph = @($ac | Where-Object { -not $priv.ContainsKey([string]$_.distinguishedName) -and $_.sAMAccountName -ne 'krbtgt' })
                if (-not $orph.Count) { return New-CheckResult 'OK' 'Nessun account con adminCount=1 fuori dai gruppi privilegiati' }
                New-CheckResult 'Attenzione' "$($orph.Count) account con adminCount=1 non piu' privilegiati: ereditarieta' delle ACL bloccata" (Format-Evidence $orph { param($u) $u.sAMAccountName } $Config) 'Azzerare adminCount e riattivare l''ereditarieta'' delle autorizzazioni su questi account.'
            } }
            @{ Id = 'P-SENS-01'; Cat = 'Account privilegiati'; Title = 'Admin non protetti dalla delega'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $pu = @{}
                foreach ($u in (Get-GroupMembersRecursive $Config (Get-SidDn $Config "$($ctx.Sid)-525"))) { $pu[[string]$u.distinguishedName] = $true }
                $bad = @(Get-PrivilegedUsers $Config | Where-Object { -not (Test-Uac $_.User 0x100000) -and -not $pu.ContainsKey([string]$_.User.distinguishedName) -and -not (Test-Uac $_.User 2) })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Tutti gli account privilegiati attivi sono sensibili o in Protected Users' }
                New-CheckResult 'Attenzione' "$($bad.Count) account privilegiati delegabili e fuori da Protected Users" (Format-Evidence $bad { param($p) $p.User.sAMAccountName } $Config) 'Impostare "Account sensibile e non delegabile" e valutare Protected Users (mai per gli account di servizio; tenere un account break-glass fuori).'
            } }
            @{ Id = 'P-PU-01'; Cat = 'Account privilegiati'; Title = 'Gruppo Protected Users'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $dn = Get-SidDn $Config "$($ctx.Sid)-525"
                if (-not $dn) { return New-CheckResult 'Attenzione' 'Gruppo Protected Users assente (serve un PDC 2012 R2 o successivo)' }
                $m = @(Get-GroupMembersRecursive $Config $dn)
                if (-not $m.Count) { return New-CheckResult 'Attenzione' 'Protected Users e'' vuoto' @() 'Aggiungere gli account amministrativi dopo aver verificato la compatibilita'' (niente NTLM, delega, DES/RC4, credenziali in cache).' }
                New-CheckResult 'OK' "$($m.Count) account in Protected Users" (Format-Evidence $m { param($u) $u.sAMAccountName } $Config)
            } }

            # ----------------------------------------------------- Kerberos
            @{ Id = 'K-SPN-01'; Cat = 'Kerberos'; Title = 'Account utente con SPN (kerberoasting)'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account utente attivo con SPN' }
                $priv = @{}
                foreach ($p in (Get-PrivilegedUsers $Config)) { $priv[[string]$p.User.distinguishedName] = $true }
                $privSpn = @($u | Where-Object { $priv.ContainsKey([string]$_.distinguishedName) })
                $ev = Format-Evidence $u { param($x) '{0} - password di {1} giorni{2}' -f $x.sAMAccountName, (Get-AgeDays $x.pwdLastSet), $(if ($priv.ContainsKey([string]$x.distinguishedName)) { ' - PRIVILEGIATO' } else { '' }) } $Config
                if ($privSpn.Count) { return New-CheckResult 'Critico' "$($u.Count) account con SPN, di cui $($privSpn.Count) privilegiati: la loro password si puo' attaccare offline" $ev 'Convertire i servizi in gMSA; dove non possibile, password di almeno 25 caratteri e togliere i privilegi.' }
                New-CheckResult 'Attenzione' "$($u.Count) account utente con SPN esposti al kerberoasting" $ev 'Convertire i servizi in gMSA o usare password lunghe (25+ caratteri) e cifratura AES.'
            } }
            @{ Id = 'K-ASREP-01'; Cat = 'Kerberos'; Title = 'Preautenticazione Kerberos disattivata (AS-REP roasting)'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account senza preautenticazione' }
                New-CheckResult 'Critico' "$($u.Count) account senza preautenticazione Kerberos" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere "Non richiedere la preautenticazione Kerberos" dagli account.'
            } }
            @{ Id = 'K-DEL-01'; Cat = 'Kerberos'; Title = 'Delega non vincolata'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $o = @(Search-Ldap $Config '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'objectClass'))
                if (-not $o.Count) { return New-CheckResult 'OK' 'Nessun oggetto (esclusi i DC) con delega non vincolata' }
                New-CheckResult 'Critico' "$($o.Count) oggetti con delega non vincolata: chi li compromette ottiene i ticket di chi vi si autentica" (Format-Evidence $o { param($x) $x.sAMAccountName } $Config) 'Passare alla delega vincolata (o RBCD) solo verso i servizi necessari.'
            } }
            @{ Id = 'K-DES-01'; Cat = 'Kerberos'; Title = 'Account con cifratura DES'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(userAccountControl:1.2.840.113556.1.4.803:=2097152)' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account limitato a DES' }
                New-CheckResult 'Attenzione' "$($u.Count) account con 'Usa solo tipi di crittografia DES'" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere l''opzione DES: e'' disattivato di default da Windows 7 / 2008 R2.'
            } }

            # ----------------------------------------------------- password e account
            @{ Id = 'W-POL-01'; Cat = 'Password e account'; Title = 'Policy delle password di dominio'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $d = Get-LdapObject $Config $ctx.Dn @('minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'lockoutThreshold', 'pwdProperties')
                $maxAge = 0
                if ($d.maxPwdAge -and [int64]$d.maxPwdAge -ne [int64]::MinValue) { $maxAge = [math]::Round([math]::Abs([int64]$d.maxPwdAge) / 864000000000) }
                $complex = ([int]$d.pwdProperties -band 1) -ne 0
                $ev = @("Lunghezza minima: $($d.minPwdLength)", "Cronologia: $($d.pwdHistoryLength)", "Scadenza: $(if ($maxAge) { "$maxAge giorni" } else { 'mai' })", "Blocco dopo: $(if ([int]$d.lockoutThreshold) { "$($d.lockoutThreshold) tentativi" } else { 'mai' })", "Complessita': $(if ($complex) { 'si' } else { 'no' })")
                $iss = @()
                $crit = $false
                if ([int]$d.minPwdLength -lt 8) { $iss += 'lunghezza minima sotto 8'; $crit = $true } elseif ([int]$d.minPwdLength -lt 12) { $iss += 'lunghezza minima sotto 12' }
                if (-not [int]$d.lockoutThreshold) { $iss += 'nessun blocco dopo tentativi errati' }
                if (-not $complex) { $iss += 'complessita'' disattivata' }
                if ([int]$d.pwdHistoryLength -lt 12) { $iss += 'cronologia sotto 12' }
                $rem = 'Lunghezza minima di almeno 12-14 caratteri (meglio passphrase), blocco dopo 5-10 tentativi, cronologia 24; per gli admin una PSO piu'' restrittiva.'
                if ($crit) { return New-CheckResult 'Critico' ('Policy debole: ' + ($iss -join ', ')) $ev $rem }
                if ($iss.Count) { return New-CheckResult 'Attenzione' ('Policy da rafforzare: ' + ($iss -join ', ')) $ev $rem }
                New-CheckResult 'OK' 'Policy delle password adeguata' $ev
            } }
            @{ Id = 'W-NREQ-01'; Cat = 'Password e account'; Title = 'Account con password non obbligatoria'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account attivo con PASSWD_NOTREQD' }
                New-CheckResult 'Critico' "$($u.Count) account attivi possono avere password vuota" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere il flag PASSWD_NOTREQD (userAccountControl 0x20) e impostare una password.'
            } }
            @{ Id = 'W-REV-01'; Cat = 'Password e account'; Title = 'Password con cifratura reversibile'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))' @('sAMAccountName'))
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account con cifratura reversibile' }
                New-CheckResult 'Critico' "$($u.Count) account con password memorizzata in modo reversibile" (Format-Evidence $u { param($x) $x.sAMAccountName } $Config) 'Togliere l''opzione e far cambiare la password.'
            } }
            @{ Id = 'W-NEXP-01'; Cat = 'Password e account'; Title = 'Password che non scadono'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                if (-not $u.Count) { return New-CheckResult 'OK' 'Nessun account attivo con password senza scadenza' }
                New-CheckResult 'Attenzione' "$($u.Count) account attivi con password che non scade" (Format-Evidence $u { param($x) '{0} - password di {1} giorni' -f $x.sAMAccountName, (Get-AgeDays $x.pwdLastSet) } $Config) 'Per gli account di servizio passare a gMSA; per gli utenti togliere l''opzione o usare password lunghe con controllo delle password compromesse.'
            } }
            @{ Id = 'W-INACT-01'; Cat = 'Password e account'; Title = 'Utenti attivi inutilizzati'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $days = [int]$Config.InactiveDays
                $u = @(Search-Ldap $Config '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' $script:UserProps)
                $old = @($u | Where-Object { $ll = Get-AgeDays $_.lastLogonTimestamp; $cr = $_.whenCreated; ($null -eq $ll -and $cr -and ((Get-Date) - [datetime]$cr).TotalDays -gt $days) -or ($null -ne $ll -and $ll -gt $days) })
                if (-not $old.Count) { return New-CheckResult 'OK' "Nessun utente attivo inutilizzato da oltre $days giorni" }
                New-CheckResult 'Attenzione' "$($old.Count) utenti attivi senza logon da oltre $days giorni (su $($u.Count))" (Format-Evidence $old { param($x) $ll = Get-AgeDays $x.lastLogonTimestamp; '{0} - ultimo logon {1}' -f $x.sAMAccountName, $(if ($null -ne $ll) { "$ll giorni fa" } else { 'mai' }) } $Config) 'Disabilitare gli account non usati e spostarli in un''OU dedicata; eliminarli dopo un periodo di attesa.'
            } }
            @{ Id = 'W-COMP-01'; Cat = 'Password e account'; Title = 'Computer obsoleti o inattivi'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $days = [int]$Config.InactiveDays
                $c = @(Search-Ldap $Config '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName', 'operatingSystem', 'lastLogonTimestamp'))
                # fuori supporto: XP-8.1, Server 2003-2012 R2 (ESU finiti il 13/10/2026); solo con ESU: Windows 10 non LTSC (dal 14/10/2025); in scadenza: Server 2016 (12/01/2027)
                $eol = @($c | Where-Object { "$($_.operatingSystem)" -match 'Windows (XP|Vista|7|8 |8\.1)|Server (2003|2008|2012)' })
                $esu = @($c | Where-Object { "$($_.operatingSystem)" -match '^Windows 10' -and "$($_.operatingSystem)" -notmatch 'LTSC|LTSB' })
                $soon = @($c | Where-Object { "$($_.operatingSystem)" -match 'Server 2016' })
                $inact = @($c | Where-Object { $ll = Get-AgeDays $_.lastLogonTimestamp; $null -ne $ll -and $ll -gt $days })
                $ev = @(Format-Evidence $eol { param($x) 'Fuori supporto: {0} - {1}' -f $x.sAMAccountName, $x.operatingSystem } $Config) +
                      @(Format-Evidence $esu { param($x) 'Solo con ESU: {0} - {1}' -f $x.sAMAccountName, $x.operatingSystem } $Config) +
                      @(Format-Evidence $soon { param($x) 'Supporto fino al 12/01/2027: {0} - {1}' -f $x.sAMAccountName, $x.operatingSystem } $Config) +
                      @(Format-Evidence $inact { param($x) 'Inattivo: {0} - {1} giorni' -f $x.sAMAccountName, (Get-AgeDays $x.lastLogonTimestamp) } $Config)
                $sum = "$($eol.Count) fuori supporto, $($esu.Count) Windows 10 (solo con ESU), $($soon.Count) Server 2016 in scadenza, $($inact.Count) inattivi da oltre $days giorni (su $($c.Count))"
                if ($eol.Count) { return New-CheckResult 'Critico' $sum $ev 'Sostituire o isolare i sistemi fuori supporto; per Windows 10 verificare la copertura ESU o passare a Windows 11; pianificare i Server 2016; disabilitare i computer inattivi.' }
                if ($esu.Count -or $soon.Count -or $inact.Count) { return New-CheckResult 'Attenzione' $sum $ev 'Windows 10: ESU attivi o migrazione a Windows 11; Server 2016: sostituzione entro gennaio 2027; computer inattivi: disabilitare e poi eliminare.' }
                New-CheckResult 'OK' "$($c.Count) computer attivi, nessuno obsoleto o inattivo"
            } }

            # ----------------------------------------------------- configurazione
            @{ Id = 'C-MAQ-01'; Cat = 'Configurazione del dominio'; Title = 'MachineAccountQuota'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $d = Get-LdapObject $Config $ctx.Dn @('ms-DS-MachineAccountQuota')
                $q = [int]$d.'ms-DS-MachineAccountQuota'
                if ($q -eq 0) { return New-CheckResult 'OK' 'MachineAccountQuota = 0' }
                New-CheckResult 'Attenzione' "MachineAccountQuota = $($q): ogni utente puo' aggiungere $q computer al dominio" @() 'Impostare ms-DS-MachineAccountQuota a 0 e delegare il join a un gruppo dedicato (base di molti attacchi RBCD).'
            } }
            @{ Id = 'C-PRE2K-01'; Cat = 'Configurazione del dominio'; Title = 'Accesso compatibile pre-Windows 2000'; Weight = 10; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $g = Get-LdapObject $Config (Get-SidDn $Config 'S-1-5-32-554') @('member')
                $members = @($g.member | Where-Object { $_ })
                $bad = @($members | Where-Object { $_ -match 'S-1-1-0|S-1-5-7' })
                $ev = @($members | ForEach-Object { "$_" })
                if ($bad.Count) { return New-CheckResult 'Critico' 'Everyone o ANONYMOUS LOGON nel gruppo "Accesso compatibile precedente a Windows 2000": lettura anonima della directory' $ev 'Rimuovere Everyone e ANONYMOUS LOGON dal gruppo (lasciare Authenticated Users solo se necessario).' }
                New-CheckResult 'OK' 'Nessun accesso anonimo tramite il gruppo pre-Windows 2000' $ev
            } }
            @{ Id = 'C-LAPS-01'; Cat = 'Configurazione del dominio'; Title = 'LAPS: copertura delle password degli admin locali'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $win = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-PasswordExpirationTime)' @('lDAPDisplayName') $ctx.SchemaDn 'OneLevel').Count -gt 0
                $leg = @(Search-Ldap $Config '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)' @('lDAPDisplayName') $ctx.SchemaDn 'OneLevel').Count -gt 0
                if (-not $win -and -not $leg) { return New-CheckResult 'Critico' 'LAPS non installato (schema non esteso): password degli admin locali probabilmente uguali ovunque' @() 'Implementare Windows LAPS (Update-LapsADSchema, permessi sulle OU, GPO).' }
                $props = @('sAMAccountName')
                if ($win) { $props += 'msLAPS-PasswordExpirationTime' }
                if ($leg) { $props += 'ms-Mcs-AdmPwdExpirationTime' }
                $c = @(Search-Ldap $Config '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))' $props)
                $cov = @($c | Where-Object { ($win -and $_.'msLAPS-PasswordExpirationTime') -or ($leg -and $_.'ms-Mcs-AdmPwdExpirationTime') })
                $miss = @($c | Where-Object { -not (($win -and $_.'msLAPS-PasswordExpirationTime') -or ($leg -and $_.'ms-Mcs-AdmPwdExpirationTime')) })
                $pct = 0
                if ($c.Count) { $pct = [math]::Round($cov.Count * 100 / $c.Count) }
                $kind = @(); if ($win) { $kind += 'Windows LAPS' }; if ($leg) { $kind += 'LAPS legacy' }
                $sum = "$($kind -join ' + '): $($cov.Count) computer su $($c.Count) coperti ($pct%)"
                $ev = Format-Evidence $miss { param($x) "Senza LAPS: $($x.sAMAccountName)" } $Config
                if ($pct -lt 50) { return New-CheckResult 'Critico' $sum $ev 'Estendere la GPO LAPS a tutte le OU dei computer.' }
                if ($pct -lt 95) { return New-CheckResult 'Attenzione' $sum $ev 'Estendere la GPO LAPS ai computer mancanti.' }
                New-CheckResult 'OK' $sum $ev
            } }
            @{ Id = 'C-GMSA-01'; Cat = 'Configurazione del dominio'; Title = 'gMSA e KDS root key'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $keys = @(Search-Ldap $Config '(objectClass=msKds-ProvRootKey)' @('cn') ("CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($ctx.ConfigDn)") 'OneLevel')
                $g = @(Search-Ldap $Config '(objectClass=msDS-GroupManagedServiceAccount)' @('sAMAccountName'))
                $ev = Format-Evidence $g { param($x) $x.sAMAccountName } $Config
                if (-not $keys.Count) { return New-CheckResult 'Attenzione' 'KDS root key assente: i gMSA non si possono usare' $ev 'Add-KdsRootKey -EffectiveImmediately (diventa utilizzabile dopo 10 ore), poi convertire i servizi in gMSA.' }
                if (-not $g.Count) { return New-CheckResult 'Info' 'KDS root key presente, nessun gMSA in uso' $ev 'Convertire in gMSA i servizi che girano con account utente (vedi K-SPN-01 e W-NEXP-01).' }
                New-CheckResult 'OK' "$($g.Count) gMSA in uso" $ev
            } }
            @{ Id = 'C-GPP-01'; Cat = 'Configurazione del dominio'; Title = 'Password nelle Group Policy Preferences (cpassword)'; Weight = 15; Needs = 'Utente di dominio (lettura SYSVOL)'; Run = {
                param($Config)
                if (-not $Config.ScanSysvolGpp) { return New-CheckResult 'Non verificato' 'Controllo disattivato nella configurazione' }
                $ctx = Get-AdContext $Config
                $root = "\\$($ctx.Dns)\SYSVOL\$($ctx.Dns)\Policies"
                if (-not (Test-Path -LiteralPath $root)) { return New-CheckResult 'Non verificato' "SYSVOL non raggiungibile: $root" }
                $hits = @(Get-ChildItem -LiteralPath $root -Recurse -Include *.xml -File -ErrorAction SilentlyContinue | Where-Object { Select-String -LiteralPath $_.FullName -Pattern 'cpassword="[^"]+' -Quiet })
                if (-not $hits.Count) { return New-CheckResult 'OK' 'Nessuna password GPP trovata in SYSVOL' }
                New-CheckResult 'Critico' "$($hits.Count) file GPP con password (decifrabili da chiunque nel dominio)" (Format-Evidence $hits { param($f) $f.FullName.Substring($root.Length) } $Config) 'Eliminare le preferenze con password, cambiare subito le password esposte e usare LAPS o gMSA.'
            } }
            @{ Id = 'C-TRUST-01'; Cat = 'Configurazione del dominio'; Title = 'Trust'; Weight = 5; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $t = @(Search-Ldap $Config '(objectClass=trustedDomain)' @('name', 'trustDirection', 'trustType', 'trustAttributes'))
                if (-not $t.Count) { return New-CheckResult 'OK' 'Nessun trust' }
                $dir = @{ 1 = 'in ingresso'; 2 = 'in uscita'; 3 = 'bidirezionale' }
                # il SID filtering protegge chi si fida: conta sui trust in uscita (2) o bidirezionali (3) di questo dominio
                $out = @($t | Where-Object { [int]$_.trustDirection -band 2 })
                $noFilter = @($out | Where-Object { [int]$_.trustType -eq 2 -and ([int]$_.trustAttributes -band 0x8) -eq 0 -and ([int]$_.trustAttributes -band 0x4) -eq 0 })
                $sidHist = @($out | Where-Object { ([int]$_.trustAttributes -band 0x8) -and ([int]$_.trustAttributes -band 0x40) })
                $tgtDel = @($t | Where-Object { [int]$_.trustAttributes -band 0x800 })
                $ev = Format-Evidence $t { param($x) '{0} - {1}, attributi 0x{2:X}' -f $x.name, $dir[[int]$x.trustDirection], [int]$x.trustAttributes } $Config
                $iss = @()
                if ($noFilter.Count) { $iss += "$($noFilter.Count) trust esterni senza SID filtering (quarantine)" }
                if ($sidHist.Count) { $iss += "$($sidHist.Count) trust di foresta con SID history abilitata" }
                if ($tgtDel.Count) { $iss += "$($tgtDel.Count) trust con delega dei TGT abilitata" }
                if ($iss.Count) { return New-CheckResult 'Attenzione' "$($t.Count) trust: $($iss -join '; ')" $ev 'netdom trust ... /quarantine:yes sui trust esterni, /enablesidhistory:no sui trust di foresta, /EnableTgtDelegation:no; valutare la selective authentication.' }
                New-CheckResult 'Info' "$($t.Count) trust configurati" $ev
            } }
            @{ Id = 'C-SPOOL-01'; Cat = 'Configurazione del dominio'; Title = 'Print Spooler sui domain controller'; Weight = 10; Needs = 'Amministratore sui DC (WMI/WinRM)'; Run = {
                param($Config)
                if (-not $Config.CheckDcServices) { return New-CheckResult 'Non verificato' 'Controllo disattivato nella configurazione' }
                $dcs = @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))
                $on = @(); $ko = @()
                foreach ($d in $dcs) {
                    try {
                        $s = Get-CimInstance -ComputerName $d.dNSHostName -ClassName Win32_Service -Filter "Name='Spooler'" -OperationTimeoutSec 20 -ErrorAction Stop
                        if ($s.State -eq 'Running') { $on += $d.dNSHostName }
                    } catch { $ko += $d.dNSHostName }
                }
                $ev = @($on | ForEach-Object { "Spooler attivo: $_" }) + @($ko | ForEach-Object { "Non verificato (accesso negato o WinRM chiuso): $_" })
                if ($on.Count) { return New-CheckResult 'Critico' "Print Spooler attivo su $($on.Count) DC (PrintNightmare, coercizione dell'autenticazione)" $ev 'Disattivare e fermare il servizio Spooler sui DC via GPO.' }
                if ($ko.Count -eq $dcs.Count) { return New-CheckResult 'Non verificato' 'Nessun DC interrogabile: servono privilegi di amministratore e WinRM' $ev }
                New-CheckResult 'OK' 'Print Spooler fermo sui DC verificati' $ev
            } }
        ) + @(Get-AdChecksExtra)
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria

    function Get-ToolItems($Config) {
        if ([string]$Config.Mode -eq 'Hardening') { return Get-HardItems $Config }
        if ([string]$Config.Mode -eq 'Ripristino') { return Get-RestoreItems $Config }
        $ctx = Get-AdContext $Config
        Write-ToolLog "Dominio $($ctx.Dns) - DC $($ctx.Dc)" 'STEP'
        foreach ($c in (Get-AdChecks)) {
            [pscustomobject]@{
                Key        = $c.Id
                Utente     = $c.Id
                SID        = ''
                Origine    = $c.Cat
                Id         = $c.Id
                Categoria  = $c.Cat
                Controllo  = $c.Title
                Peso       = $c.Weight
                Richiede   = $c.Needs
                Stato      = 'Pronto'
                Selectable = $true
            }
        }
    }

    function Invoke-ToolItem($Config, $Item) {
        if ([string]$Config.Mode -eq 'Hardening') { return Invoke-HardItem $Config $Item }
        if ([string]$Config.Mode -eq 'Ripristino') { return Invoke-RestoreItem $Config $Item }
        $c = @(Get-AdChecks | Where-Object { $_.Id -eq $Item.Id })[0]
        if (-not $c) { throw "Controllo sconosciuto: $($Item.Id)" }
        $r = & $c.Run $Config
        if (-not $r) { throw 'Il controllo non ha restituito un risultato' }
        $points = 0
        if ($r.Status -eq 'Critico') { $points = $c.Weight } elseif ($r.Status -eq 'Attenzione') { $points = [math]::Ceiling($c.Weight / 2) }
        $dati = [pscustomobject]@{
            Id = $c.Id; Categoria = $c.Cat; Titolo = $c.Title; Peso = $c.Weight; Punti = $points; Richiede = $c.Needs
            Esito = $r.Status; Sintesi = $r.Summary; Evidenze = @($r.Evidence); Remediation = $r.Remediation
        }
        foreach ($e in @($r.Evidence | Select-Object -First 5)) { Write-ToolLog "    $e" }
        @{ Esito = $r.Status; Messaggio = $r.Summary; Dati = $dati }
    }

    function ConvertTo-HtmlText($s) { [System.Net.WebUtility]::HtmlEncode([string]$s) }

    # Report HTML, JSON e CSV delle evidenze. Restituisce il percorso del report HTML
    function Complete-ToolRun($Config, $Results) {
        if ([string]$Config.Mode -in @('Hardening', 'Ripristino')) { return Complete-HardRun $Config $Results }
        $ctx = Get-AdContext $Config
        $dir = [string]$Config.OutputDir
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $base = Join-Path $dir ('ADAssessment_{0}_{1}' -f $ctx.Dns, $stamp)
        $checks = @($Results | Where-Object { $_.Dati } | ForEach-Object { $_.Dati })
        foreach ($f in @($Results | Where-Object { -not $_.Dati -and $_.Esito -eq 'Fallito' })) {
            $checks += [pscustomobject]@{ Id = $f.Utente; Categoria = $f.Origine; Titolo = $f.Utente; Peso = 0; Punti = 0; Richiede = ''; Esito = 'Non verificato'; Sintesi = "Errore: $($f.Messaggio)"; Evidenze = @(); Remediation = '' }
        }
        $risk = [int](($checks | Measure-Object -Property Punti -Sum).Sum)
        $score = [math]::Max(0, 100 - $risk)
        $meta = [pscustomobject]@{ Dominio = $ctx.Dns; DC = $ctx.Dc; Data = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Eseguito = "$env:USERDOMAIN\$env:USERNAME"; Da = $env:COMPUTERNAME; Versione = $Tool.Version; Punteggio = $score; Rischio = $risk }

        # JSON e CSV
        [System.IO.File]::WriteAllText("$base.json", ([pscustomobject]@{ Meta = $meta; Controlli = $checks } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
        $checks | Select-Object Id, Categoria, Titolo, Esito, Punti, Sintesi, Remediation | Export-Csv -LiteralPath "$base`_controlli.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        @(foreach ($c in $checks) { foreach ($e in @($c.Evidenze)) { [pscustomobject]@{ Id = $c.Id; Esito = $c.Esito; Evidenza = $e } } }) |
            Export-Csv -LiteralPath "$base`_evidenze.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8

        # HTML (stile comune _lib/report) con confronto con la fotografia precedente
        $prev = Get-PreviousSnapshot $Config "$base.json"
        if ($prev) { Write-ToolLog "Confronto con $($prev.File) (punteggio $($prev.Meta.Punteggio))" }
        [void](New-FotoHtml $Config $meta $checks $base $prev)
        $cnt = @{}
        foreach ($k in @('Critico', 'Attenzione')) { $cnt[$k] = @($checks | Where-Object { $_.Esito -eq $k }).Count }
        Write-ToolLog ('Punteggio {0}/100 (rischio {1} punti) - Critici {2}, Attenzione {3}' -f $score, $risk, $cnt['Critico'], $cnt['Attenzione']) 'STEP'
        Write-ToolLog "Report HTML: $base.html" 'OK'
        "$base.html"
    }
    #endregion
    #region SPECIFICO: fase 2 - hardening (azioni con simulazione, backup, verifica)

    $script:RunDir = $null
    $script:HardReady = $false

    # Moduli RSAT e server unico per tutte le operazioni (coerenza tra LDAP, GPO e SYSVOL)
    function Initialize-Hardening($Config) {
        if ($script:HardReady) { return }
        foreach ($m in @('ActiveDirectory', 'GroupPolicy')) {
            if (-not (Get-Module -ListAvailable -Name $m)) { throw "Modulo $m mancante: installare gli strumenti RSAT (Install-WindowsFeature RSAT-AD-PowerShell, GPMC oppure Add-WindowsCapability Rsat.*)." }
        }
        Import-Module ActiveDirectory, GroupPolicy -ErrorAction Stop -Verbose:$false
        $ctx = Get-AdContext $Config
        $global:PSDefaultParameterValues['*-AD*:Server'] = $ctx.Dc
        $global:PSDefaultParameterValues['*-GP*:Server'] = $ctx.Dc
        $global:PSDefaultParameterValues['*-GP*:Domain'] = $ctx.Dns
        $script:HardReady = $true
    }

    function Get-RunDir($Config) {
        if (-not $script:RunDir) {
            $prefix = 'Hardening'
            if ([string]$Config.Mode -eq 'Ripristino') { $prefix = 'Ripristino' }
            $script:RunDir = Join-Path ([string]$Config.OutputDir) ('{0}_{1}_{2}' -f $prefix, (Get-AdContext $Config).Dns, (Get-Date -Format 'yyyyMMdd_HHmmss'))
            New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
        }
        $script:RunDir
    }

    # Stato precedente di ogni modifica, per l'annullamento
    function Save-Backup($Config, [string]$Id, $Data) {
        $f = Join-Path (Get-RunDir $Config) "$Id.backup.json"
        $o = [pscustomobject]@{ Id = $Id; Data = $Data; Date = (Get-Date).ToString('s'); By = "$env:USERDOMAIN\$env:USERNAME"; Dc = (Get-AdContext $Config).Dc }
        [System.IO.File]::WriteAllText($f, ($o | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($true)))
        Write-ToolLog "    backup: $f"
        $f
    }

    function New-Plan([bool]$Ok, [string]$Detail, $Targets = @(), [string]$Plan = '') {
        [pscustomobject]@{ Ok = $Ok; Detail = $Detail; Targets = @($Targets); Plan = $Plan }
    }

    function ConvertTo-LdapValue([string]$s) { $s.Replace('\', '\5c').Replace('(', '\28').Replace(')', '\29').Replace('*', '\2a').Replace([string][char]0, '\00') }

    function Get-DcOu($Config) { (Get-ADDomain).DomainControllersContainer }

    function Test-InList([string]$Name, $List) { @($List | Where-Object { $_ -and $_.Trim() -ieq $Name }).Count -gt 0 }

    # ------------------------------------------------------------------ GPO

    function Get-HardGpoName($Config, [string]$Suffix) { '{0} - {1}' -f [string]$Config.GpoPrefix, $Suffix }

    function Get-HardGpo($Config, [string]$Suffix, [switch]$Create, [string]$Comment) {
        $name = Get-HardGpoName $Config $Suffix
        $g = $null
        try { $g = Get-GPO -Name $name -ErrorAction Stop } catch { $g = $null }
        if (-not $g -and $Create) {
            $g = New-GPO -Name $name -Comment $Comment
            Write-ToolLog "    creata la GPO '$name' ($($g.Id))" 'OK'
            Start-Sleep -Seconds 2
        }
        $g
    }

    function Test-GpoLink($Config, $Gpo, $Targets) {
        if ([string]$Config.GpoLinkMode -eq 'Non collegata') { return $true }
        foreach ($t in @($Targets)) {
            if (-not $t) { continue }
            $l = @((Get-GPInheritance -Target $t).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
            if (-not $l.Count) { return $false }
            if ([string]$Config.GpoLinkMode -eq 'Collegata e attiva' -and -not $l[0].Enabled) { return $false }
        }
        $true
    }

    function Set-GpoLinks($Config, $Gpo, $Targets) {
        $mode = [string]$Config.GpoLinkMode
        if ($mode -eq 'Non collegata') { return 'GPO non collegata (da collegare a mano)' }
        $en = 'No'
        if ($mode -eq 'Collegata e attiva') { $en = 'Yes' }
        $done = @()
        foreach ($t in @($Targets)) {
            if (-not $t) { continue }
            $l = @((Get-GPInheritance -Target $t).GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
            if ($l.Count) { Set-GPLink -Guid $Gpo.Id -Target $t -LinkEnabled $en | Out-Null } else { New-GPLink -Guid $Gpo.Id -Target $t -LinkEnabled $en | Out-Null }
            $done += $t
        }
        if (-not $done.Count) { return 'GPO creata senza collegamenti (nessuna OU indicata)' }
        "collegata a: $($done -join '; ') ($mode)"
    }

    function Test-GpoRegistryValue($Gpo, [string]$Key, [string]$Name, $Value) {
        if (-not $Gpo) { return $false }
        try {
            $v = Get-GPRegistryValue -Guid $Gpo.Id -Key $Key -ValueName $Name -ErrorAction Stop
            return ([string]$v.Value -eq [string]$Value)
        } catch { return $false }
    }

    function Get-GpoSysvolPath($Config, $Gpo) {
        $ctx = Get-AdContext $Config
        "\\$($ctx.Dc)\SYSVOL\$($ctx.Dns)\Policies\{$($Gpo.Id)}"
    }

    # Aggiunge un'estensione lato client alla GPO (computer) e incrementa la versione in AD e in GPT.INI
    function Add-GpoMachineExtension($Config, $Gpo, [string]$Cse) {
        $ctx = Get-AdContext $Config
        $de = [adsi]"LDAP://$($ctx.Dc)/CN={$($Gpo.Id)},CN=Policies,CN=System,$($ctx.Dn)"
        $cur = [string]$de.Properties['gPCMachineExtensionNames'].Value
        $parts = @([regex]::Matches($cur, '\[[^\]]+\]') | ForEach-Object { $_.Value })
        if ($parts -notcontains $Cse) { $parts += $Cse }
        $parts = @($parts | Sort-Object { $_.ToUpperInvariant() })
        $de.Properties['gPCMachineExtensionNames'].Value = ($parts -join '')
        $ver = [int]$de.Properties['versionNumber'].Value
        $user = $ver -band 0xFFFF0000
        $machine = (($ver -band 0xFFFF) + 1) -band 0xFFFF
        $new = $user -bor $machine
        $de.Properties['versionNumber'].Value = $new
        $de.CommitChanges()
        $ini = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'GPT.INI'
        $txt = if (Test-Path -LiteralPath $ini) { [System.IO.File]::ReadAllText($ini) } else { "[General]`r`n" }
        if ($txt -match 'Version=\d+') { $txt = $txt -replace 'Version=\d+', "Version=$new" } else { $txt = $txt.TrimEnd() + "`r`nVersion=$new`r`n" }
        [System.IO.File]::WriteAllText($ini, $txt, [System.Text.Encoding]::ASCII)
    }

    $script:CseSecurity = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $script:CseAudit = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

    # Diritti utente (Privilege Rights) in GptTmpl.inf: sostituisce solo le voci gestite, mantiene il resto del file
    function Set-GpoPrivilegeRights($Config, $Gpo, [hashtable]$Rights) {
        $dir = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\SecEdit'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $file = Join-Path $dir 'GptTmpl.inf'
        $sections = [ordered]@{}
        $cur = $null
        if (Test-Path -LiteralPath $file) {
            foreach ($l in [System.IO.File]::ReadAllLines($file)) {
                if ($l -match '^\s*\[(.+)\]\s*$') { $cur = $Matches[1]; if (-not $sections.Contains($cur)) { $sections[$cur] = New-Object System.Collections.Generic.List[string] }; continue }
                if ($cur -and $l.Trim()) { $sections[$cur].Add($l) }
            }
        }
        $sections['Unicode'] = New-Object System.Collections.Generic.List[string]; $sections['Unicode'].Add('Unicode=yes')
        $sections['Version'] = New-Object System.Collections.Generic.List[string]; $sections['Version'].Add('signature="$CHICAGO$"'); $sections['Version'].Add('Revision=1')
        $pr = New-Object System.Collections.Generic.List[string]
        if ($sections.Contains('Privilege Rights')) { foreach ($l in $sections['Privilege Rights']) { if ($l -match '^\s*(\w+)\s*=' -and -not $Rights.ContainsKey($Matches[1])) { $pr.Add($l) } } }
        foreach ($k in ($Rights.Keys | Sort-Object)) { $pr.Add(('{0} = {1}' -f $k, ((@($Rights[$k]) | ForEach-Object { "*$_" }) -join ','))) }
        $sections['Privilege Rights'] = $pr
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($name in @('Unicode', 'Version') + @($sections.Keys | Where-Object { $_ -notin @('Unicode', 'Version') })) {
            $lines.Add("[$name]")
            foreach ($l in $sections[$name]) { $lines.Add($l) }
        }
        [System.IO.File]::WriteAllLines($file, $lines, [System.Text.Encoding]::Unicode)
        Add-GpoMachineExtension $Config $Gpo $script:CseSecurity
    }

    function Get-GpoPrivilegeRights($Config, $Gpo) {
        $h = @{}
        if (-not $Gpo) { return $h }
        $file = Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        if (-not (Test-Path -LiteralPath $file)) { return $h }
        $in = $false
        foreach ($l in [System.IO.File]::ReadAllLines($file)) {
            if ($l -match '^\s*\[(.+)\]') { $in = $Matches[1] -eq 'Privilege Rights'; continue }
            if ($in -and $l -match '^\s*(\w+)\s*=\s*(.*)$') { $h[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }) }
        }
        $h
    }

    # Criteri di controllo avanzati (audit.csv)
    $script:AuditBaseline = @(
        , @('Account Logon', 'Audit Credential Validation', '{0cce923f-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Logon', 'Audit Kerberos Authentication Service', '{0cce9242-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Logon', 'Audit Kerberos Service Ticket Operations', '{0cce9240-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Computer Account Management', '{0cce9236-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Other Account Management Events', '{0cce923a-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit Security Group Management', '{0cce9237-69ae-11d9-bed3-505054503030}', 3)
        , @('Account Management', 'Audit User Account Management', '{0cce9235-69ae-11d9-bed3-505054503030}', 3)
        , @('Detailed Tracking', 'Audit PNP Activity', '{0cce9248-69ae-11d9-bed3-505054503030}', 1)
        , @('Detailed Tracking', 'Audit Process Creation', '{0cce922b-69ae-11d9-bed3-505054503030}', 1)
        , @('DS Access', 'Audit Directory Service Access', '{0cce923b-69ae-11d9-bed3-505054503030}', 3)
        , @('DS Access', 'Audit Directory Service Changes', '{0cce923c-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Account Lockout', '{0cce9217-69ae-11d9-bed3-505054503030}', 2)
        , @('Logon/Logoff', 'Audit Group Membership', '{0cce9249-69ae-11d9-bed3-505054503030}', 1)
        , @('Logon/Logoff', 'Audit Logoff', '{0cce9216-69ae-11d9-bed3-505054503030}', 1)
        , @('Logon/Logoff', 'Audit Logon', '{0cce9215-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Other Logon/Logoff Events', '{0cce921c-69ae-11d9-bed3-505054503030}', 3)
        , @('Logon/Logoff', 'Audit Special Logon', '{0cce921b-69ae-11d9-bed3-505054503030}', 1)
        , @('Object Access', 'Audit Detailed File Share', '{0cce9244-69ae-11d9-bed3-505054503030}', 2)
        , @('Object Access', 'Audit File Share', '{0cce9224-69ae-11d9-bed3-505054503030}', 3)
        , @('Object Access', 'Audit Other Object Access Events', '{0cce9227-69ae-11d9-bed3-505054503030}', 3)
        , @('Object Access', 'Audit Removable Storage', '{0cce9245-69ae-11d9-bed3-505054503030}', 3)
        , @('Policy Change', 'Audit Audit Policy Change', '{0cce922f-69ae-11d9-bed3-505054503030}', 3)
        , @('Policy Change', 'Audit Authentication Policy Change', '{0cce9230-69ae-11d9-bed3-505054503030}', 1)
        , @('Policy Change', 'Audit Authorization Policy Change', '{0cce9231-69ae-11d9-bed3-505054503030}', 1)
        , @('Policy Change', 'Audit MPSSVC Rule-Level Policy Change', '{0cce9232-69ae-11d9-bed3-505054503030}', 3)
        , @('Privilege Use', 'Audit Sensitive Privilege Use', '{0cce9228-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit Other System Events', '{0cce9214-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit Security State Change', '{0cce9210-69ae-11d9-bed3-505054503030}', 1)
        , @('System', 'Audit Security System Extension', '{0cce9211-69ae-11d9-bed3-505054503030}', 3)
        , @('System', 'Audit System Integrity', '{0cce9212-69ae-11d9-bed3-505054503030}', 3)
    )

    function Get-AuditCsvPath($Config, $Gpo) { Join-Path (Get-GpoSysvolPath $Config $Gpo) 'Machine\Microsoft\Windows NT\Audit\audit.csv' }

    function Set-GpoAuditBaseline($Config, $Gpo) {
        $file = Get-AuditCsvPath $Config $Gpo
        New-Item -ItemType Directory -Path (Split-Path $file) -Force | Out-Null
        $txt = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success and Failure' }
        $lines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
        foreach ($a in $script:AuditBaseline) { $lines += (',System,{0},{1},{2},,{3}' -f $a[1], $a[2], $txt[$a[3]], $a[3]) }
        [System.IO.File]::WriteAllLines($file, $lines, (New-Object System.Text.UTF8Encoding($false)))
        Add-GpoMachineExtension $Config $Gpo $script:CseAudit
    }

    function Test-GpoAuditBaseline($Config, $Gpo) {
        if (-not $Gpo) { return $false }
        $file = Get-AuditCsvPath $Config $Gpo
        if (-not (Test-Path -LiteralPath $file)) { return $false }
        $rows = @(Import-Csv -LiteralPath $file)
        foreach ($a in $script:AuditBaseline) {
            $r = @($rows | Where-Object { $_.'Subcategory GUID' -eq $a[2] })
            if (-not $r.Count -or [int]$r[0].'Setting Value' -ne $a[3]) { return $false }
        }
        $true
    }

    # ------------------------------------------------------------------ account

    function Search-Accounts($Config, [string]$Filter, [string[]]$Props) {
        @(Search-Ldap $Config $Filter (@('sAMAccountName', 'distinguishedName', 'userAccountControl', 'objectSid', 'objectClass') + $Props))
    }

    function Get-EnabledUsersWithFlag($Config, [int]$Flag) {
        Search-Accounts $Config ('(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={0})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -f $Flag) @()
    }

    # Imposta o toglie un bit di userAccountControl con backup del valore precedente
    function Set-UacFlag($Config, [string]$Id, $Accounts, [int]$Flag, [bool]$On) {
        $bk = @()
        $n = 0
        foreach ($a in @($Accounts)) {
            $de = [adsi]"LDAP://$((Get-AdContext $Config).Dc)/$(([string]$a.distinguishedName).Replace('/', '\/'))"
            $old = [int]$de.Properties['userAccountControl'].Value
            $new = if ($On) { $old -bor $Flag } else { $old -band (-bnot $Flag) }
            if ($new -eq $old) { continue }
            $bk += [pscustomobject]@{ Account = [string]$a.sAMAccountName; Dn = [string]$a.distinguishedName; OldUac = $old; NewUac = $new }
            $de.Properties['userAccountControl'].Value = $new
            $de.CommitChanges()
            $n++
            Write-ToolLog "    $($a.sAMAccountName): userAccountControl 0x$('{0:X}' -f $old) -> 0x$('{0:X}' -f $new)"
        }
        if ($bk.Count) { [void](Save-Backup $Config $Id $bk) }
        $n
    }

    function Get-PrivilegedEnabled($Config) {
        @(Get-PrivilegedUsers $Config | Where-Object { -not (Test-Uac $_.User 2) } | ForEach-Object { $_.User })
    }

    function Get-RandomPassword([int]$Length = 64) {
        $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!#%+-=?@_'
        $bytes = New-Object byte[] $Length
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
    }

    # ------------------------------------------------------------------ catalogo delle azioni
    # Ogni azione: Id, Cat, Title, Impact (Basso/Medio/Alto), Needs, Undo, Test { param($Config) -> New-Plan }, Apply { param($Config, $Plan) -> messaggio }

    function Get-RegistryActions($Config) {
        $lm = [int]$Config.LmCompatibilityLevel
        $cb = 1
        if ([string]$Config.LdapChannelBinding -eq 'Sempre') { $cb = 2 }
        $logKb = [int]$Config.SecurityLogMaxMB * 1024
        @(
            @{ Id = 'HD-DC-LDAPSIGN'; Title = 'Firma LDAP obbligatoria sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity', 'DWord', 2))
               Undo = 'Rimuovere il valore LDAPServerIntegrity dalla GPO. Prima: verificare negli eventi 2889 del Directory Service i client che usano bind non firmati.' }
            @{ Id = 'HD-DC-LDAPCB'; Title = 'Channel binding LDAPS sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LdapEnforceChannelBinding', 'DWord', $cb))
               Undo = 'Rimuovere LdapEnforceChannelBinding dalla GPO (eventi 3039/3040 per i client non compatibili).' }
            @{ Id = 'HD-DC-SMBSIGN'; Title = 'Firma SMB obbligatoria sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'EnableSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature', 'DWord', 1))
               Undo = 'Rimuovere i valori RequireSecuritySignature/EnableSecuritySignature dalla GPO.' }
            @{ Id = 'HD-DC-SMB1'; Title = 'SMBv1 disattivato sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'SMB1', 'DWord', 0))
               Undo = 'Rimuovere il valore SMB1 dalla GPO.' }
            @{ Id = 'HD-DC-NTLM'; Title = "Solo NTLMv2 sui DC (LmCompatibilityLevel $lm)"; Impact = 'Alto'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 'DWord', $lm))
               Undo = 'Rimuovere LmCompatibilityLevel dalla GPO. Prima: verificare con l''audit NTLM (evento 4624, Package Name NTLM V1) che nessun client usi LM/NTLMv1.' }
            @{ Id = 'HD-DC-SPOOLER'; Title = 'Print Spooler disattivato sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Services\Spooler', 'Start', 'DWord', 4))
               Undo = 'Rimuovere il valore Start del servizio Spooler dalla GPO e riavviare il servizio sui DC.' }
            @{ Id = 'HD-DC-LSAPPL'; Title = 'Protezione LSA (RunAsPPL) sui DC'; Impact = 'Medio'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 'DWord', 1))
               Undo = 'Rimuovere RunAsPPL dalla GPO e riavviare (verificare prima i plugin LSA di terze parti, eventi 3065/3066).' }
            @{ Id = 'HD-DC-WDIGEST'; Title = 'WDigest senza password in memoria sui DC'; Impact = 'Basso'; Gpo = 'DC Hardening'; Scope = 'DC'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 'DWord', 0))
               Undo = 'Rimuovere UseLogonCredential dalla GPO.' }
            @{ Id = 'HD-DC-LOGS'; Title = "Registri di sicurezza e PowerShell sui DC (Security $($Config.SecurityLogMaxMB) MB)"; Impact = 'Basso'; Gpo = 'DC Audit'; Scope = 'DC'
               Values = @(@('HKLM\Software\Policies\Microsoft\Windows\EventLog\Security', 'MaxSize', 'DWord', $logKb), @('HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 'ProcessCreationIncludeCmdLine_Enabled', 'DWord', 1), @('HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'SCENoApplyLegacyAuditPolicy', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO DC Audit.' }
            @{ Id = 'HD-DC-NTLMAUDIT'; Title = 'Audit dell''uso di NTLM sui DC (prima di restringerlo)'; Impact = 'Basso'; Gpo = 'DC Audit'; Scope = 'DC'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'AuditNTLMInDomain', 'DWord', 7), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 'DWord', 2))
               Undo = 'Rimuovere i valori dalla GPO DC Audit. Eventi in Applicazioni e servizi > Microsoft > Windows > NTLM > Operational (8001-8004).' }
            @{ Id = 'HD-MB-NTLMAUDIT'; Title = 'Audit dell''uso di NTLM su server e client'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'AuditReceivingNTLMTraffic', 'DWord', 2), @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0', 'RestrictSendingNTLMTraffic', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO Member Hardening.' }
            @{ Id = 'HD-MB-CREDGUARD'; Title = 'Credential Guard su server e client (senza blocco UEFI)'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'EnableVirtualizationBasedSecurity', 'DWord', 1), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'RequirePlatformSecurityFeatures', 'DWord', 1), @('HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard', 'LsaCfgFlags', 'DWord', 2))
               Undo = 'Rimuovere i valori dalla GPO e riavviare. Richiede UEFI, Secure Boot e virtualizzazione; non usare sui DC. Incompatibile con delega non vincolata, NTLMv1, DES.' }
            @{ Id = 'HD-MB-RCG'; Title = 'Remote Credential Guard / Restricted Admin per RDP'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowProtectedCreds', 'DWord', 1))
               Undo = 'Rimuovere AllowProtectedCreds dalla GPO. Uso: mstsc /remoteGuard dai PC amministrativi.' }
            @{ Id = 'HD-MB-SMB1'; Title = 'SMBv1 disattivato su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'SMB1', 'DWord', 0), @('HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start', 'DWord', 4), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation', 'DependOnService', 'MultiString', @('Bowser', 'MRxSmb20', 'NSI')))
               Undo = 'Rimuovere i valori dalla GPO Member Hardening (verificare prima stampanti/NAS che usano SMBv1). La dipendenza del servizio Workstation da MRxSmb10 va tolta insieme al driver, come indicato da Microsoft, altrimenti il servizio non si avvia.' }
            @{ Id = 'HD-MB-WDIGEST'; Title = 'WDigest senza password in memoria su server e client'; Impact = 'Basso'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 'DWord', 0))
               Undo = 'Rimuovere UseLogonCredential dalla GPO.' }
            @{ Id = 'HD-MB-LSAPPL'; Title = 'Protezione LSA (RunAsPPL) su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 'DWord', 1))
               Undo = 'Rimuovere RunAsPPL dalla GPO e riavviare.' }
            @{ Id = 'HD-MB-NTLM'; Title = "Solo NTLMv2 su server e client (LmCompatibilityLevel $lm)"; Impact = 'Alto'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(, @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'LmCompatibilityLevel', 'DWord', $lm))
               Undo = 'Rimuovere LmCompatibilityLevel dalla GPO.' }
            @{ Id = 'HD-MB-SMBSIGN'; Title = 'Firma SMB obbligatoria su server e client'; Impact = 'Medio'; Gpo = 'Member Hardening'; Scope = 'Member'
               Values = @(@('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'RequireSecuritySignature', 'DWord', 1), @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature', 'DWord', 1))
               Undo = 'Rimuovere i valori dalla GPO (verificare prima NAS e dispositivi senza firma SMB).' }
        )
    }

    function Get-RegistryActionTargets($Config, $A) {
        if ($A.Scope -eq 'DC') { return @(Get-DcOu $Config) }
        @($Config.MemberHardeningOus | Where-Object { $_ })
    }

    function New-RegistryAction($A) {
        $act = @{ Id = $A.Id; Cat = 'GPO di hardening'; Title = $A.Title; Impact = $A.Impact; Needs = 'Domain Admins'; Undo = $A.Undo; Def = $A }
        $act.Test = {
            param($Config, $Act)
            $a = $Act.Def
            $g = Get-HardGpo $Config $a.Gpo
            $missing = @($a.Values | Where-Object { -not (Test-GpoRegistryValue $g $_[0] $_[1] $_[3]) })
            $targets = @(Get-RegistryActionTargets $Config $a)
            if ($a.Scope -eq 'Member' -and -not $targets.Count) { return New-Plan $true 'Non applicabile: nessuna OU indicata in "OU per server e client"' }
            $linked = $g -and (Test-GpoLink $Config $g $targets)
            $plan = "GPO '$(Get-HardGpoName $Config $a.Gpo)': " + ((@($a.Values) | ForEach-Object { "$($_[0])\$($_[1]) = $($_[3])" }) -join '; ')
            if (-not $missing.Count -and $linked) { return New-Plan $true 'Impostazioni presenti nella GPO e collegamento attivo' }
            New-Plan $false ("Da impostare: $($missing.Count) valori" + $(if (-not $linked) { ', collegamento mancante o disattivato' } else { '' })) $targets $plan
        }
        $act.Apply = {
            param($Config, $Act, $Plan)
            $a = $Act.Def
            $g = Get-HardGpo $Config $a.Gpo -Create -Comment 'FispaTools ad-hardening: impostazioni di sicurezza (vedi report)'
            $bk = @()
            foreach ($v in $a.Values) {
                $old = $null
                $oldType = $null
                try { $cur = Get-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -ErrorAction Stop; $old = $cur.Value; $oldType = [string]$cur.Type } catch { }
                $bk += [pscustomobject]@{ Gpo = $g.DisplayName; Key = $v[0]; Name = $v[1]; Old = $old; OldType = $oldType; New = $v[3]; Type = $v[2] }
                Set-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -Type $v[2] -Value $v[3] | Out-Null
            }
            [void](Save-Backup $Config $a.Id $bk)
            $link = Set-GpoLinks $Config $g (Get-RegistryActionTargets $Config $a)
            $msg = "Impostati $($a.Values.Count) valori; $link"
            if ($a.Id -eq 'HD-DC-SPOOLER' -and $Config.StopSpoolerNow) {
                foreach ($d in @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))) {
                    try {
                        $s = Get-CimInstance -ComputerName $d.dNSHostName -ClassName Win32_Service -Filter "Name='Spooler'" -OperationTimeoutSec 30 -ErrorAction Stop
                        [void](Invoke-CimMethod -InputObject $s -MethodName ChangeStartMode -Arguments @{ StartMode = 'Disabled' })
                        [void](Invoke-CimMethod -InputObject $s -MethodName StopService)
                        Write-ToolLog "    Spooler fermato su $($d.dNSHostName)" 'OK'
                    } catch { Write-ToolLog "    Spooler non fermato su $($d.dNSHostName): $($_.Exception.Message)" 'WARN' }
                }
            }
            $msg
        }
        $act
    }

    function Get-HardeningActions($Config) {
        $list = New-Object System.Collections.Generic.List[object]

        # ---------------------------------------------------------- dominio e foresta
        $list.Add(@{ Id = 'HD-BIN'; Cat = 'Dominio'; Title = 'Attiva il cestino di Active Directory'; Impact = 'Basso'; Needs = 'Enterprise Admins'
            Undo = 'Irreversibile (e'' un''opzione della foresta senza effetti negativi).'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $f = Get-LdapObject $Config "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$($ctx.ConfigDn)" @('msDS-EnabledFeatureBL')
                if ($f -and $f.'msDS-EnabledFeatureBL') { return New-Plan $true 'Cestino gia'' attivo' }
                if ($ctx.ForestFL -lt 4) { return New-Plan $true 'Non applicabile: livello funzionale della foresta inferiore a 2008 R2' }
                New-Plan $false 'Cestino non attivo' @() 'Enable-ADOptionalFeature "Recycle Bin Feature" sulla foresta'
            }
            Apply = { param($Config, $Act, $Plan)
                Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false
                'Cestino AD attivato'
            } })

        $list.Add(@{ Id = 'HD-MAQ'; Cat = 'Dominio'; Title = 'MachineAccountQuota a 0 (gli utenti non aggiungono computer al dominio)'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Ripristinare ms-DS-MachineAccountQuota al valore nel backup. Per i join usare un gruppo delegato sull''OU dei computer.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $v = [int](Get-LdapObject $Config $ctx.Dn @('ms-DS-MachineAccountQuota')).'ms-DS-MachineAccountQuota'
                if ($v -eq 0) { return New-Plan $true 'Gia'' a 0' }
                New-Plan $false "Valore attuale $v" @($v) 'ms-DS-MachineAccountQuota = 0 sull''oggetto dominio'
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$($ctx.Dn)"
                [void](Save-Backup $Config $Act.Id @{ Old = [int]$de.Properties['ms-DS-MachineAccountQuota'].Value })
                $de.Properties['ms-DS-MachineAccountQuota'].Value = 0
                $de.CommitChanges()
                'MachineAccountQuota impostato a 0'
            } })

        $list.Add(@{ Id = 'HD-PRE2K'; Cat = 'Dominio'; Title = 'Togli Anonymous ed Everyone da "Accesso compatibile pre-Windows 2000"'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riaggiungere i membri elencati nel backup al gruppo S-1-5-32-554.'
            Test = { param($Config, $Act)
                $g = Get-LdapObject $Config (Get-SidDn $Config 'S-1-5-32-554') @('member', 'distinguishedName')
                $bad = @(@($g.member) | Where-Object { $_ -match '^CN=(S-1-5-7|S-1-1-0),' })
                if (-not $bad.Count) { return New-Plan $true 'Ne'' Anonymous Logon ne'' Everyone sono membri' }
                New-Plan $false "$($bad.Count) membri da togliere" $bad ('Rimuovere: ' + ($bad -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config 'S-1-5-32-554').Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Group = 'S-1-5-32-554'; Removed = @($Plan.Targets) })
                foreach ($m in $Plan.Targets) { [void]$de.Properties['member'].Remove([string]$m) }
                $de.CommitChanges()
                "Rimossi $($Plan.Targets.Count) membri"
            } })

        $list.Add(@{ Id = 'HD-KDS'; Cat = 'Dominio'; Title = 'Crea la KDS root key (necessaria ai gMSA)'; Impact = 'Basso'; Needs = 'Domain Admins (dominio radice)'
            Undo = 'Nessuno necessario.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $k = @(Search-Ldap $Config '(objectClass=msKds-ProvRootKey)' @('cn') "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($ctx.ConfigDn)" 'OneLevel')
                if ($k.Count) { return New-Plan $true "$($k.Count) KDS root key presenti" }
                New-Plan $false 'Nessuna KDS root key' @() 'Add-KdsRootKey -EffectiveImmediately (utilizzabile dopo 10 ore)'
            }
            Apply = { param($Config, $Act, $Plan)
                [void](Add-KdsRootKey -EffectiveImmediately)
                'KDS root key creata: i gMSA si possono creare tra 10 ore (replica tra i DC)'
            } })

        $list.Add(@{ Id = 'HD-PWDPOL'; Cat = 'Dominio'; Title = "Policy password di dominio (minimo $($Config.DomainMinPasswordLength) caratteri, blocco dopo $($Config.DomainLockoutThreshold) errori)"; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Set-ADDefaultDomainPasswordPolicy con i valori del backup. I nuovi requisiti valgono al prossimo cambio password di ogni utente.'
            Test = { param($Config, $Act)
                $p = Get-ADDefaultDomainPasswordPolicy
                $iss = @()
                if ($p.MinPasswordLength -lt [int]$Config.DomainMinPasswordLength) { $iss += "lunghezza minima $($p.MinPasswordLength)" }
                if (-not $p.ComplexityEnabled) { $iss += 'complessita'' disattivata' }
                if ($p.ReversibleEncryptionEnabled) { $iss += 'cifratura reversibile' }
                if ($p.LockoutThreshold -eq 0 -or $p.LockoutThreshold -gt [int]$Config.DomainLockoutThreshold) { $iss += "soglia di blocco $($p.LockoutThreshold)" }
                if (-not $iss.Count) { return New-Plan $true 'Policy conforme' }
                New-Plan $false ($iss -join ', ') @() ("Minimo $($Config.DomainMinPasswordLength) caratteri, complessita'', niente cifratura reversibile, blocco dopo $($Config.DomainLockoutThreshold) errori per $($Config.DomainLockoutMinutes) minuti")
            }
            Apply = { param($Config, $Act, $Plan)
                $p = Get-ADDefaultDomainPasswordPolicy
                [void](Save-Backup $Config $Act.Id ($p | Select-Object MinPasswordLength, ComplexityEnabled, ReversibleEncryptionEnabled, LockoutThreshold, @{ n = 'LockoutDuration'; e = { $_.LockoutDuration.ToString() } }, @{ n = 'LockoutObservationWindow'; e = { $_.LockoutObservationWindow.ToString() } }, @{ n = 'MaxPasswordAge'; e = { $_.MaxPasswordAge.ToString() } }, PasswordHistoryCount))
                $min = [TimeSpan]::FromMinutes([int]$Config.DomainLockoutMinutes)
                $len = [math]::Max([int]$p.MinPasswordLength, [int]$Config.DomainMinPasswordLength)
                Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength $len -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -LockoutThreshold ([int]$Config.DomainLockoutThreshold) -LockoutDuration $min -LockoutObservationWindow $min -PasswordHistoryCount ([math]::Max([int]$p.PasswordHistoryCount, 24))
                'Policy password di dominio aggiornata'
            } })

        # ---------------------------------------------------------- account privilegiati
        $list.Add(@{ Id = 'HD-SCHEMA'; Cat = 'Account privilegiati'; Title = 'Svuota Schema Admins (da riempire solo per le modifiche allo schema)'; Impact = 'Medio'; Needs = 'Enterprise Admins'
            Undo = 'Riaggiungere i membri elencati nel backup.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $g = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-518") @('member')
                $m = @($g.member | Where-Object { $_ })
                if (-not $m.Count) { return New-Plan $true 'Schema Admins vuoto' }
                New-Plan $false "$($m.Count) membri" $m ('Rimuovere: ' + ($m -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-518").Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Group = 'Schema Admins'; Removed = @($Plan.Targets) })
                foreach ($m in $Plan.Targets) { [void]$de.Properties['member'].Remove([string]$m) }
                $de.CommitChanges()
                "Rimossi $($Plan.Targets.Count) membri da Schema Admins"
            } })

        $list.Add(@{ Id = 'HD-SENSITIVE'; Cat = 'Account privilegiati'; Title = 'Account privilegiati "sensibili e non delegabili"'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Togliere il flag NOT_DELEGATED (0x100000) dagli account del backup.'
            Test = { param($Config, $Act)
                $t = @(Get-PrivilegedEnabled $Config | Where-Object { -not (Test-Uac $_ 0x100000) -and -not $_.servicePrincipalName })
                if (-not $t.Count) { return New-Plan $true 'Tutti gli account privilegiati attivi sono gia'' non delegabili' }
                New-Plan $false "$($t.Count) account delegabili" $t ('Impostare NOT_DELEGATED su: ' + (($t | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan) "Aggiornati $(Set-UacFlag $Config $Act.Id $Plan.Targets 0x100000 $true) account" } })

        $list.Add(@{ Id = 'HD-PROTUSERS'; Cat = 'Account privilegiati'; Title = 'Account amministrativi in Protected Users'; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Togliere dal gruppo Protected Users gli account del backup. Effetti: niente NTLM, delega, DES/RC4, credenziali in cache, ticket di 4 ore.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $pu = Get-SidDn $Config "$($ctx.Sid)-525"
                if (-not $pu) { return New-Plan $true 'Non applicabile: gruppo Protected Users assente (serve un PDC 2012 R2+)' }
                $in = @(Get-GroupMembersRecursive $Config $pu | ForEach-Object { [string]$_.distinguishedName })
                $cand = if ([string]$Config.ProtectedUsersMode -eq 'Tutti gli account privilegiati') {
                    @(Get-PrivilegedEnabled $Config | Where-Object { -not $_.servicePrincipalName })
                } else {
                    @(foreach ($n in @($Config.ProtectedUsersList | Where-Object { $_ })) { Search-Accounts $Config ('(&(objectCategory=person)(objectClass=user)(sAMAccountName={0}))' -f (ConvertTo-LdapValue $n.Trim())) @('servicePrincipalName') })
                }
                $t = @($cand | Where-Object { $in -notcontains [string]$_.distinguishedName -and -not (Test-InList ([string]$_.sAMAccountName) $Config.BreakGlassAccounts) -and -not ((Get-ObjSid $_) -like '*-500') })
                if (-not $t.Count) { return New-Plan $true 'Nessun account da aggiungere (elenco vuoto o gia'' presenti)' }
                New-Plan $false "$($t.Count) account da aggiungere" $t ('Aggiungere: ' + (($t | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-525").Replace('/', '\/'))"
                [void](Save-Backup $Config $Act.Id @{ Added = @($Plan.Targets | ForEach-Object { [string]$_.distinguishedName }) })
                foreach ($u in $Plan.Targets) { [void]$de.Properties['member'].Add([string]$u.distinguishedName) }
                $de.CommitChanges()
                "Aggiunti $($Plan.Targets.Count) account a Protected Users (vale dal prossimo logon)"
            } })

        $list.Add(@{ Id = 'HD-ADMINPSO'; Cat = 'Account privilegiati'; Title = "Policy password dedicata agli admin (PSO, minimo $($Config.AdminPsoMinLength) caratteri)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Remove-ADFineGrainedPasswordPolicy con il nome indicato nel backup.'
            Test = { param($Config, $Act)
                $name = "$($Config.GpoPrefix)-Admins"
                $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
                $ctx = Get-AdContext $Config
                $groups = @(@("$($ctx.Sid)-512", "$($ctx.Sid)-519", "$($ctx.Sid)-518") | ForEach-Object { Get-SidDn $Config $_ } | Where-Object { $_ })
                $missing = $groups
                if ($pso) {
                    $subj = @(Get-ADFineGrainedPasswordPolicySubject -Identity $pso | ForEach-Object { $_.DistinguishedName })
                    $missing = @($groups | Where-Object { $subj -notcontains $_ })
                    if (-not $missing.Count -and $pso.MinPasswordLength -ge [int]$Config.AdminPsoMinLength) { return New-Plan $true "PSO $name presente e applicata" }
                }
                New-Plan $false "PSO $name assente o incompleta" $missing "PSO $name (precedenza 10, minimo $($Config.AdminPsoMinLength) caratteri, blocco dopo 5 errori) su Domain Admins, Enterprise Admins, Schema Admins"
            }
            Apply = { param($Config, $Act, $Plan)
                $name = "$($Config.GpoPrefix)-Admins"
                $pso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
                $min = [TimeSpan]::FromMinutes([int]$Config.DomainLockoutMinutes)
                if (-not $pso) {
                    New-ADFineGrainedPasswordPolicy -Name $name -Precedence 10 -MinPasswordLength ([int]$Config.AdminPsoMinLength) -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -PasswordHistoryCount 24 -LockoutThreshold 5 -LockoutDuration $min -LockoutObservationWindow $min -MaxPasswordAge ([TimeSpan]::FromDays([int]$Config.AdminPsoMaxAgeDays)) -MinPasswordAge ([TimeSpan]::FromDays(1)) -Description 'FispaTools ad-hardening: password degli amministratori'
                    $pso = Get-ADFineGrainedPasswordPolicy -Identity $name
                } else { Set-ADFineGrainedPasswordPolicy -Identity $pso -MinPasswordLength ([int]$Config.AdminPsoMinLength) }
                [void](Save-Backup $Config $Act.Id @{ Pso = $name })
                if ($Plan.Targets.Count) { Add-ADFineGrainedPasswordPolicySubject -Identity $pso -Subjects @($Plan.Targets) }
                "PSO $name aggiornata, applicata a $($Plan.Targets.Count) nuovi gruppi"
            } })

        $list.Add(@{ Id = 'HD-ADMINCOUNT'; Cat = 'Account privilegiati'; Title = 'Azzera adminCount orfani e ripristina l''ereditarieta'' delle ACL'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Reimpostare adminCount=1 sugli account del backup (le ACL ereditate restano).'
            Test = { param($Config, $Act)
                $priv = @(Get-PrivilegedUsers $Config | ForEach-Object { [string]$_.User.distinguishedName })
                $o = @(Search-Accounts $Config '(&(objectCategory=person)(objectClass=user)(adminCount=1))' @() | Where-Object { $priv -notcontains [string]$_.distinguishedName -and (Get-ObjSid $_) -notlike '*-502' })
                if (-not $o.Count) { return New-Plan $true 'Nessun adminCount orfano' }
                New-Plan $false "$($o.Count) account" $o ('Azzerare adminCount e riattivare l''ereditarieta'' su: ' + (($o | ForEach-Object { $_.sAMAccountName }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                [void](Save-Backup $Config $Act.Id @(@($Plan.Targets) | ForEach-Object { [string]$_.distinguishedName }))
                foreach ($u in $Plan.Targets) {
                    $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$u.distinguishedName).Replace('/', '\/'))"
                    $de.Properties['adminCount'].Clear()
                    $sec = $de.psbase.ObjectSecurity
                    $sec.SetAccessRuleProtection($false, $true)
                    $de.psbase.ObjectSecurity = $sec
                    $de.CommitChanges()
                }
                "Sistemati $($Plan.Targets.Count) account"
            } })

        $list.Add(@{ Id = 'HD-KRBTGT'; Cat = 'Account privilegiati'; Title = 'Rotazione della password di krbtgt (due passaggi distanziati)'; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Nessuno: e'' una rotazione. Il secondo passaggio va eseguito dopo l''intervallo configurato e la replica completa.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $k = Get-LdapObject $Config (Get-SidDn $Config "$($ctx.Sid)-502") @('pwdLastSet')
                $last = ConvertFrom-FileTime $k.pwdLastSet
                $age = [math]::Floor(($ctx.Now - $last).TotalDays)
                $state = Get-KrbtgtState
                $hours = ($ctx.Now - $last).TotalHours
                if ($state.Pending -and $hours -ge [int]$Config.KrbtgtMinHours) { return New-Plan $false "Primo passaggio eseguito $([math]::Floor($hours)) ore fa: manca il secondo" @() 'Secondo reset della password di krbtgt' }
                if ($state.Pending) { return New-Plan $true "Primo passaggio eseguito $([math]::Floor($hours)) ore fa: secondo passaggio dopo $($Config.KrbtgtMinHours) ore" }
                if ($age -le [int]$Config.KrbtgtMaxDays) { return New-Plan $true "Password cambiata $age giorni fa" }
                New-Plan $false "Password cambiata $age giorni fa" @() 'Primo reset della password di krbtgt (rigenerata dal sistema), poi secondo reset dopo l''intervallo configurato'
            }
            Apply = { param($Config, $Act, $Plan)
                $ctx = Get-AdContext $Config
                $dn = Get-SidDn $Config "$($ctx.Sid)-502"
                # tutti i DC devono avere la stessa versione della password prima di ruotare di nuovo
                $vals = @()
                foreach ($d in @(Search-Ldap $Config '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dNSHostName'))) {
                    try {
                        $ds = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$($d.dNSHostName)/$($dn.Replace('/', '\/'))", '(objectClass=*)', [string[]]@('pwdLastSet'), [System.DirectoryServices.SearchScope]::Base)
                        $r = $ds.FindOne()
                        if (-not $r -or -not $r.Properties['pwdlastset'].Count) { throw 'pwdLastSet non leggibile' }
                        $vals += [string][int64]$r.Properties['pwdlastset'][0]
                    } catch { throw "DC $($d.dNSHostName) non raggiungibile o non leggibile: rotazione annullata (serve la replica su tutti i DC). $($_.Exception.Message)" }
                }
                if (@($vals | Select-Object -Unique).Count -gt 1) { throw 'La password di krbtgt non e'' ancora replicata su tutti i DC: attendere e riprovare.' }
                $state = Get-KrbtgtState
                Set-ADAccountPassword -Identity $dn -Reset -NewPassword (ConvertTo-SecureString (Get-RandomPassword 64) -AsPlainText -Force)
                $pending = -not $state.Pending
                Save-KrbtgtState $pending
                if ($pending) { return "Primo passaggio eseguito: ripetere questa azione dopo almeno $($Config.KrbtgtMinHours) ore" }
                'Secondo passaggio eseguito: rotazione di krbtgt completata'
            } })

        # ---------------------------------------------------------- account
        $flags = @(
            @{ Id = 'HD-ASREP'; Flag = 0x400000; Title = 'Richiedi la preautenticazione Kerberos (AS-REP roasting)'; Impact = 'Basso'; Undo = 'Riattivare DONT_REQ_PREAUTH (0x400000) sugli account del backup.' }
            @{ Id = 'HD-DES'; Flag = 0x200000; Title = 'Togli "Usa solo crittografia DES"'; Impact = 'Basso'; Undo = 'Riattivare USE_DES_KEY_ONLY (0x200000) sugli account del backup.' }
            @{ Id = 'HD-REVERSIBLE'; Flag = 0x80; Title = 'Togli la cifratura reversibile delle password'; Impact = 'Basso'; Undo = 'Riattivare ENCRYPTED_TEXT_PWD_ALLOWED (0x80). La copia reversibile sparisce al prossimo cambio password.' }
            @{ Id = 'HD-PWDNOTREQD'; Flag = 0x20; Title = 'Togli "password non obbligatoria"'; Impact = 'Basso'; Undo = 'Riattivare PASSWD_NOTREQD (0x20) sugli account del backup.' }
        )
        foreach ($f in $flags) {
            $list.Add(@{ Id = $f.Id; Cat = 'Account'; Title = $f.Title; Impact = $f.Impact; Needs = 'Domain Admins'; Undo = $f.Undo; Flag = $f.Flag
                Test = { param($Config, $Act)
                    $t = @(Get-EnabledUsersWithFlag $Config $Act.Flag)
                    if (-not $t.Count) { return New-Plan $true 'Nessun account attivo con questa impostazione' }
                    New-Plan $false "$($t.Count) account" $t ('Account: ' + (($t | Select-Object -First 50 | ForEach-Object { $_.sAMAccountName }) -join ', '))
                }
                Apply = { param($Config, $Act, $Plan) "Aggiornati $(Set-UacFlag $Config $Act.Id $Plan.Targets $Act.Flag $false) account" } })
        }

        $list.Add(@{ Id = 'HD-GUEST'; Cat = 'Account'; Title = 'Disattiva l''account Guest'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Riattivare l''account Guest.'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $g = @(Search-Accounts $Config ('(objectSid={0}-501)' -f $ctx.Sid) @())
                if (-not $g.Count -or (Test-Uac $g[0] 2)) { return New-Plan $true 'Guest disattivato' }
                New-Plan $false 'Guest attivo' $g 'Disattivare Guest'
            }
            Apply = { param($Config, $Act, $Plan) "Disattivato ($(Set-UacFlag $Config $Act.Id $Plan.Targets 2 $true) account)" } })

        $list.Add(@{ Id = 'HD-INACTIVE-USERS'; Cat = 'Account'; Title = "Disattiva gli utenti inattivi da oltre $($Config.InactiveDays) giorni"; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riattivare (e riportare nell''OU d''origine) gli account del backup: Enable-ADAccount.'
            Test = { param($Config, $Act) Get-InactivePlan $Config $false }
            Apply = { param($Config, $Act, $Plan) Disable-Inactive $Config $Act.Id $Plan.Targets } })

        $list.Add(@{ Id = 'HD-INACTIVE-COMPUTERS'; Cat = 'Account'; Title = "Disattiva i computer inattivi da oltre $($Config.InactiveDays) giorni"; Impact = 'Medio'; Needs = 'Domain Admins'
            Undo = 'Riattivare (e riportare nell''OU d''origine) i computer del backup.'
            Test = { param($Config, $Act) Get-InactivePlan $Config $true }
            Apply = { param($Config, $Act, $Plan) Disable-Inactive $Config $Act.Id $Plan.Targets } })

        # ---------------------------------------------------------- LAPS
        $list.Add(@{ Id = 'HD-LAPS-SCHEMA'; Cat = 'LAPS'; Title = 'Windows LAPS: estensione dello schema'; Impact = 'Basso'; Needs = 'Schema Admins'
            Undo = 'Irreversibile (estensione dello schema).'
            Test = { param($Config, $Act)
                $ctx = Get-AdContext $Config
                $a = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-Password)' @('cn') $ctx.SchemaDn 'OneLevel')
                if ($a.Count) { return New-Plan $true 'Schema gia'' esteso per Windows LAPS' }
                if (-not (Get-Command Update-LapsADSchema -ErrorAction SilentlyContinue)) { return New-Plan $true 'Non applicabile qui: modulo LAPS assente (Windows Server 2019+ aggiornato, o RSAT recenti)' }
                New-Plan $false 'Attributi msLAPS-* assenti' @() 'Update-LapsADSchema'
            }
            Apply = { param($Config, $Act, $Plan) Update-LapsADSchema -Confirm:$false; 'Schema esteso per Windows LAPS' } })

        $list.Add(@{ Id = 'HD-LAPS-PERM'; Cat = 'LAPS'; Title = 'Windows LAPS: permesso dei computer di scrivere la propria password'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Rimuovere dall''OU l''ACE di SELF sugli attributi msLAPS-*.'
            Test = { param($Config, $Act)
                $ous = @($Config.LapsOus | Where-Object { $_ })
                if (-not $ous.Count) { return New-Plan $true 'Nessuna OU indicata in LapsOus' }
                if (-not (Get-Command Set-LapsADComputerSelfPermission -ErrorAction SilentlyContinue)) { return New-Plan $true 'Non applicabile qui: modulo LAPS assente' }
                $missing = @($ous | Where-Object { -not (Test-LapsSelfPermission $Config $_) })
                if (-not $missing.Count) { return New-Plan $true 'Permessi presenti su tutte le OU' }
                New-Plan $false "$($missing.Count) OU senza permesso" $missing ('Set-LapsADComputerSelfPermission su: ' + ($missing -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                foreach ($ou in $Plan.Targets) { [void](Set-LapsADComputerSelfPermission -Identity $ou) }
                [void](Save-Backup $Config $Act.Id @{ Ous = @($Plan.Targets) })
                "Permessi impostati su $($Plan.Targets.Count) OU"
            } })

        $list.Add(@{ Id = 'HD-LAPS-GPO'; Cat = 'LAPS'; Title = "Windows LAPS: GPO (password $($Config.LapsPasswordLength) caratteri, rotazione $($Config.LapsPasswordAgeDays) giorni)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Scollegare o eliminare la GPO Windows LAPS (le password restano quelle correnti).'
            Test = { param($Config, $Act)
                $ous = @($Config.LapsOus | Where-Object { $_ })
                if (-not $ous.Count) { return New-Plan $true 'Nessuna OU indicata in LapsOus' }
                $g = Get-HardGpo $Config 'Windows LAPS'
                $vals = Get-LapsValues $Config
                $missing = @($vals | Where-Object { -not (Test-GpoRegistryValue $g $_[0] $_[1] $_[3]) })
                if (-not $missing.Count -and (Test-GpoLink $Config $g $ous)) { return New-Plan $true 'GPO Windows LAPS presente e collegata' }
                New-Plan $false 'GPO assente, incompleta o non collegata' $ous ("GPO '$(Get-HardGpoName $Config 'Windows LAPS')' su: " + ($ous -join '; '))
            }
            Apply = { param($Config, $Act, $Plan)
                $g = Get-HardGpo $Config 'Windows LAPS' -Create -Comment 'FispaTools ad-hardening: Windows LAPS'
                foreach ($v in (Get-LapsValues $Config)) { Set-GPRegistryValue -Guid $g.Id -Key $v[0] -ValueName $v[1] -Type $v[2] -Value $v[3] | Out-Null }
                [void](Save-Backup $Config $Act.Id @{ Gpo = $g.DisplayName })
                Set-GpoLinks $Config $g $Plan.Targets
            } })

        # ---------------------------------------------------------- GPO di hardening (registro) e audit
        foreach ($a in (Get-RegistryActions $Config)) { $list.Add((New-RegistryAction $a)) }

        $list.Add(@{ Id = 'HD-DC-AUDIT'; Cat = 'GPO di hardening'; Title = 'Criteri di controllo avanzati sui DC (baseline Microsoft)'; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Eliminare audit.csv dalla GPO DC Audit o scollegarla.'
            Test = { param($Config, $Act)
                $g = Get-HardGpo $Config 'DC Audit'
                if ((Test-GpoAuditBaseline $Config $g) -and (Test-GpoLink $Config $g @(Get-DcOu $Config))) { return New-Plan $true 'Baseline di audit presente e collegata ai DC' }
                New-Plan $false 'Baseline di audit assente o non collegata' @(Get-DcOu $Config) "GPO '$(Get-HardGpoName $Config 'DC Audit')' con $($script:AuditBaseline.Count) sottocategorie (account, Kerberos, gruppi, processi, DS, logon, policy, privilegi, sistema)"
            }
            Apply = { param($Config, $Act, $Plan)
                $g = Get-HardGpo $Config 'DC Audit' -Create -Comment 'FispaTools ad-hardening: criteri di controllo avanzati'
                Set-GpoAuditBaseline $Config $g
                Set-GPRegistryValue -Guid $g.Id -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 | Out-Null
                [void](Save-Backup $Config $Act.Id @{ Gpo = $g.DisplayName; Subcategories = $script:AuditBaseline.Count })
                'Baseline di audit scritta; ' + (Set-GpoLinks $Config $g $Plan.Targets)
            } })

        # ---------------------------------------------------------- tier model
        $list.Add(@{ Id = 'HD-TIER-OU'; Cat = 'Tier model'; Title = "Struttura del tier model (OU '$($Config.TierRootName)', gruppi Tier0/1/2)"; Impact = 'Basso'; Needs = 'Domain Admins'
            Undo = 'Le OU sono protette dall''eliminazione accidentale: togliere la protezione ed eliminarle (vuote).'
            Test = { param($Config, $Act)
                $miss = @(Get-TierModel $Config | Where-Object { -not (Get-LdapObject $Config $_.Dn @('distinguishedName')) })
                if (-not $miss.Count) { return New-Plan $true 'Struttura presente' }
                New-Plan $false "$($miss.Count) oggetti da creare" $miss ('Creare: ' + (($miss | ForEach-Object { $_.Name }) -join ', '))
            }
            Apply = { param($Config, $Act, $Plan) New-TierModel $Config $Act.Id } })

        $list.Add(@{ Id = 'HD-TIER-LOGON'; Cat = 'Tier model'; Title = 'GPO di restrizione dei logon tra tier (deny logon)'; Impact = 'Alto'; Needs = 'Domain Admins'
            Undo = 'Scollegare le GPO Tier0/Tier1 Restrizioni logon.'
            Test = { param($Config, $Act)
                $plan = Get-TierLogonPlan $Config
                $bad = @($plan | Where-Object { -not $_.Ok })
                if (-not $bad.Count) { return New-Plan $true 'GPO di restrizione presenti' }
                New-Plan $false "$($bad.Count) GPO da creare o aggiornare" $plan (($plan | ForEach-Object { "$($_.Gpo): nega logon a $($_.Names -join ', ')" + $(if ($Config.TierLinkGpos) { " (collegata a $($_.Targets -join '; '))" } else { ' (non collegata)' }) }) -join ' | ')
            }
            Apply = { param($Config, $Act, $Plan)
                [void](New-TierModel $Config 'HD-TIER-OU')
                $out = @()
                foreach ($p in (Get-TierLogonPlan $Config)) {
                    $g = Get-HardGpo $Config $p.Suffix -Create -Comment 'FispaTools ad-hardening: restrizioni di logon del tier model'
                    $rights = @{}
                    foreach ($r in @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight', 'SeDenyNetworkLogonRight')) { $rights[$r] = $p.Sids }
                    Set-GpoPrivilegeRights $Config $g $rights
                    if ($Config.TierLinkGpos) { $out += "$($g.DisplayName): " + (Set-GpoLinks $Config $g $p.Targets) } else { $out += "$($g.DisplayName): creata non collegata" }
                }
                [void](Save-Backup $Config $Act.Id @{ Gpo = @($out) })
                $out -join ' | '
            } })

        $list.ToArray()
    }

    # ------------------------------------------------------------------ supporto delle azioni

    function Get-KrbtgtState {
        $f = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\krbtgt-rotation.json')
        if (Test-Path -LiteralPath $f) { try { return (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json) } catch { } }
        [pscustomobject]@{ Pending = $false; Date = $null }
    }

    function Save-KrbtgtState([bool]$Pending) {
        $f = Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\krbtgt-rotation.json')
        New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
        [System.IO.File]::WriteAllText($f, ([pscustomobject]@{ Pending = $Pending; Date = (Get-Date).ToString('s') } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    }

    function Get-InactivePlan($Config, [bool]$Computers) {
        $ctx = Get-AdContext $Config
        $limit = $ctx.Now.AddDays(-[int]$Config.InactiveDays).ToFileTimeUtc()
        # utenti: esclusi gli account di trust tra domini (0x800), che disattivati romperebbero il trust
        $cls = if ($Computers) { '(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67108864))' } else { '(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2048))' }
        $f = "(&$cls(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(lastLogonTimestamp<=$limit)(!(lastLogonTimestamp=*)))(pwdLastSet<=$limit))"
        $all = @(Search-Accounts $Config $f @('lastLogonTimestamp', 'pwdLastSet', 'whenCreated', 'servicePrincipalName', 'isCriticalSystemObject'))
        $created = (Get-Date).AddDays(-[int]$Config.InactiveDays)
        $t = @($all | Where-Object {
            $sid = Get-ObjSid $_
            -not ($sid -match '-(500|501|502)$') -and -not $_.isCriticalSystemObject -and
            -not (Test-InList ([string]$_.sAMAccountName) $Config.BreakGlassAccounts) -and -not (Test-InList ([string]$_.sAMAccountName) $Config.InactiveExclude) -and
            -not (@($_.servicePrincipalName) -match 'MSClusterVirtualServer|MSServerClusterMgmtAPI') -and
            -not ($Config.InactiveSkipWithSpn -and -not $Computers -and $_.servicePrincipalName) -and
            ($null -eq $_.whenCreated -or [datetime]$_.whenCreated -lt $created)
        })
        $what = if ($Computers) { 'computer' } else { 'utenti' }
        if (-not $t.Count) { return New-Plan $true "Nessun $what inattivo da disattivare" }
        $dest = ''
        if ([string]$Config.InactiveAction -eq 'Disattiva e sposta' -and $Config.QuarantineOu) { $dest = " e spostare in $($Config.QuarantineOu)" }
        New-Plan $false "$($t.Count) $what inattivi" $t ("Disattivare$dest`: " + (($t | Select-Object -First 50 | ForEach-Object { $_.sAMAccountName }) -join ', ') + $(if ($t.Count -gt 50) { " ... (+$($t.Count - 50))" } else { '' }))
    }

    function Disable-Inactive($Config, [string]$Id, $Targets) {
        $ctx = Get-AdContext $Config
        $move = [string]$Config.InactiveAction -eq 'Disattiva e sposta' -and $Config.QuarantineOu
        $bk = @()
        $stamp = "Disattivato da FispaTools ad-hardening il $((Get-Date).ToString('yyyy-MM-dd')) per inattivita'"
        foreach ($a in @($Targets)) {
            $dn = [string]$a.distinguishedName
            $de = [adsi]"LDAP://$($ctx.Dc)/$($dn.Replace('/', '\/'))"
            $old = [int]$de.Properties['userAccountControl'].Value
            $bk += [pscustomobject]@{ Account = [string]$a.sAMAccountName; Dn = $dn; OldUac = $old; Description = [string]$de.Properties['description'].Value }
            $de.Properties['userAccountControl'].Value = $old -bor 2
            $desc = $stamp
            $oldDesc = [string]$de.Properties['description'].Value
            if ($oldDesc) { $desc = "$stamp - $oldDesc" }
            if ($desc.Length -gt 1024) { $desc = $desc.Substring(0, 1024) }
            $de.Properties['description'].Value = $desc
            $de.CommitChanges()
            if ($move) {
                try { Move-ADObject -Identity $dn -TargetPath ([string]$Config.QuarantineOu) }
                catch { Write-ToolLog "    $($a.sAMAccountName) disattivato ma non spostato: $($_.Exception.Message)" 'WARN' }
            }
        }
        [void](Save-Backup $Config $Id $bk)
        "Disattivati $($bk.Count) account" + $(if ($move) { " e spostati in $($Config.QuarantineOu)" } else { '' })
    }

    function Get-LapsValues($Config) {
        $k = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
        $v = @(
            , @($k, 'BackupDirectory', 'DWord', 2)
            , @($k, 'PasswordComplexity', 'DWord', 4)
            , @($k, 'PasswordLength', 'DWord', [int]$Config.LapsPasswordLength)
            , @($k, 'PasswordAgeDays', 'DWord', [int]$Config.LapsPasswordAgeDays)
            , @($k, 'PostAuthenticationResetDelay', 'DWord', 24)
            , @($k, 'PostAuthenticationActions', 'DWord', 3)
        )
        if ($Config.LapsAdminAccount) { $v += , @($k, 'AdministratorAccountName', 'String', [string]$Config.LapsAdminAccount) }
        $v
    }

    function Test-LapsSelfPermission($Config, [string]$Ou) {
        $ctx = Get-AdContext $Config
        $attr = @(Search-Ldap $Config '(lDAPDisplayName=msLAPS-Password)' @('schemaIDGUID') $ctx.SchemaDn 'OneLevel')
        if (-not $attr.Count) { return $false }
        $guid = New-Object Guid (, [byte[]]$attr[0].schemaIDGUID)
        try {
            $acl = ([adsi]"LDAP://$($ctx.Dc)/$($Ou.Replace('/', '\/'))").psbase.ObjectSecurity
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            return @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-10' -and $_.ObjectType -eq $guid -and ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) }).Count -gt 0
        } catch { return $false }
    }

    # Struttura: OU radice, Tier0/1/2 con Accounts, Groups, Devices, ServiceAccounts; gruppi TierN-Admins
    function Get-TierModel($Config) {
        $ctx = Get-AdContext $Config
        $root = "OU=$($Config.TierRootName),$($ctx.Dn)"
        $o = @([pscustomobject]@{ Name = "OU $($Config.TierRootName)"; Dn = $root; Kind = 'OU'; Parent = $ctx.Dn; Cn = [string]$Config.TierRootName })
        foreach ($t in 0..2) {
            $tdn = "OU=Tier$t,$root"
            $o += [pscustomobject]@{ Name = "OU Tier$t"; Dn = $tdn; Kind = 'OU'; Parent = $root; Cn = "Tier$t" }
            foreach ($s in @('Accounts', 'Groups', 'Devices', 'ServiceAccounts')) { $o += [pscustomobject]@{ Name = "OU Tier$t\$s"; Dn = "OU=$s,$tdn"; Kind = 'OU'; Parent = $tdn; Cn = $s } }
            $o += [pscustomobject]@{ Name = "gruppo Tier$t-Admins"; Dn = "CN=Tier$t-Admins,OU=Groups,$tdn"; Kind = 'Group'; Parent = "OU=Groups,$tdn"; Cn = "Tier$t-Admins" }
        }
        $o
    }

    function New-TierModel($Config, [string]$Id) {
        $created = @()
        foreach ($x in (Get-TierModel $Config)) {
            if (Get-LdapObject $Config $x.Dn @('distinguishedName')) { continue }
            if ($x.Kind -eq 'OU') { New-ADOrganizationalUnit -Name $x.Cn -Path $x.Parent -ProtectedFromAccidentalDeletion $true -Description 'FispaTools ad-hardening: tier model' }
            else { New-ADGroup -Name $x.Cn -SamAccountName $x.Cn -GroupScope Global -GroupCategory Security -Path $x.Parent -Description "Amministratori del $($x.Cn.Replace('-Admins', '')) (tier model)" }
            $created += $x.Dn
            Write-ToolLog "    creato: $($x.Name)" 'OK'
        }
        if ($created.Count) { [void](Save-Backup $Config $Id @{ Created = $created }) }
        "Creati $($created.Count) oggetti"
    }

    # Tier0 non accede ai dispositivi Tier1/Tier2; Tier1 non accede ai dispositivi Tier2
    function Get-TierLogonPlan($Config) {
        $ctx = Get-AdContext $Config
        $root = "OU=$($Config.TierRootName),$($ctx.Dn)"
        $sid = { param($dn) $o = Get-LdapObject $Config $dn @('objectSid'); if ($o) { Get-ObjSid $o } else { $null } }
        $t0 = & $sid "CN=Tier0-Admins,OU=Groups,OU=Tier0,$root"
        $t1 = & $sid "CN=Tier1-Admins,OU=Groups,OU=Tier1,$root"
        $t0Sids = @(@("$($ctx.Sid)-512", "$($ctx.Sid)-519", "$($ctx.Sid)-518", $t0) | Where-Object { $_ })
        $plans = @(
            @{ Suffix = 'Tier0 Restrizioni logon'; Sids = $t0Sids; Names = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Tier0-Admins'); Targets = @("OU=Devices,OU=Tier1,$root", "OU=Devices,OU=Tier2,$root") }
            @{ Suffix = 'Tier1 Restrizioni logon'; Sids = @(@($t1) | Where-Object { $_ }); Names = @('Tier1-Admins'); Targets = @("OU=Devices,OU=Tier2,$root") }
        )
        foreach ($p in $plans) {
            $g = Get-HardGpo $Config $p.Suffix
            $cur = Get-GpoPrivilegeRights $Config $g
            $ok = [bool]$g -and $p.Sids.Count -gt 0
            if ($ok) { foreach ($s in $p.Sids) { if (@($cur['SeDenyInteractiveLogonRight']) -notcontains $s) { $ok = $false } } }
            if ($ok -and $Config.TierLinkGpos) { $ok = Test-GpoLink $Config $g $p.Targets }
            [pscustomobject]@{ Suffix = $p.Suffix; Gpo = (Get-HardGpoName $Config $p.Suffix); Sids = $p.Sids; Names = $p.Names; Targets = $p.Targets; Ok = $ok }
        }
    }

    # ------------------------------------------------------------------ interfaccia verso la libreria (modalita' Hardening)

    function Get-HardItems($Config) {
        Initialize-Hardening $Config
        $ctx = Get-AdContext $Config
        Write-ToolLog "Hardening - dominio $($ctx.Dns) - DC $($ctx.Dc) - verifica dello stato attuale" 'STEP'
        foreach ($a in (Get-HardeningActions $Config)) {
            $p = $null; $state = ''; $sel = $false
            try {
                $p = & $a.Test $Config $a
                if ($p.Ok) { $state = 'Conforme: ' + $p.Detail } else { $state = 'Da applicare: ' + $p.Detail; $sel = $true }
            } catch { $state = 'Non verificabile: ' + $_.Exception.Message }
            [pscustomobject]@{
                Key = $a.Id; Utente = $a.Id; SID = ''; Origine = $a.Cat
                Id = $a.Id; Categoria = $a.Cat; Controllo = $a.Title; Peso = $a.Impact; Richiede = $a.Needs; Stato = $state
                Selectable = $sel
            }
        }
    }

    function Invoke-HardItem($Config, $Item) {
        Initialize-Hardening $Config
        $a = @(Get-HardeningActions $Config | Where-Object { $_.Id -eq $Item.Id })[0]
        if (-not $a) { throw "Azione sconosciuta: $($Item.Id)" }
        $p = & $a.Test $Config $a
        $dati = [pscustomobject]@{ Id = $a.Id; Categoria = $a.Cat; Titolo = $a.Title; Impatto = $a.Impact; Richiede = $a.Needs; Prima = $p.Detail; Piano = $p.Plan; Esito = ''; Messaggio = ''; Dopo = ''; Annullamento = $a.Undo }
        if ($p.Ok) { $dati.Esito = 'OK'; $dati.Messaggio = 'Gia'' conforme: ' + $p.Detail; return @{ Esito = 'OK'; Messaggio = $dati.Messaggio; Dati = $dati } }
        Write-ToolLog "    piano: $($p.Plan)"
        if ($Config.DryRun) {
            $dati.Esito = 'Simulato'; $dati.Messaggio = 'Verrebbe applicato: ' + $p.Plan
            return @{ Esito = 'Simulato'; Messaggio = $dati.Messaggio; Dati = $dati }
        }
        $msg = [string](@(& $a.Apply $Config $a $p) -join ' ')
        $after = $null
        try { $after = & $a.Test $Config $a } catch { }
        $dati.Messaggio = $msg
        if ($after) { $dati.Dopo = $after.Detail }
        if ($after -and -not $after.Ok) { $dati.Esito = 'Attenzione'; $dati.Messaggio = "$msg (verifica successiva: $($after.Detail); replica o applicazione GPO in corso)" }
        else { $dati.Esito = 'OK' }
        @{ Esito = $dati.Esito; Messaggio = $dati.Messaggio; Dati = $dati }
    }

    function Complete-HardRun($Config, $Results) {
        $ctx = Get-AdContext $Config
        $acts = @($Results | Where-Object { $_.Dati } | ForEach-Object { $_.Dati })
        foreach ($f in @($Results | Where-Object { -not $_.Dati })) {
            $acts += [pscustomobject]@{ Id = $f.Utente; Categoria = $f.Origine; Titolo = $f.Utente; Impatto = ''; Richiede = ''; Prima = ''; Piano = ''; Esito = $f.Esito; Messaggio = $f.Messaggio; Dopo = ''; Annullamento = '' }
        }
        $restore = [string]$Config.Mode -eq 'Ripristino'
        $dir = if ($script:RunDir) { $script:RunDir } else { Get-RunDir $Config }
        $mode = if ($Config.DryRun) { 'SIMULAZIONE - nessuna modifica eseguita' } else { 'ESECUZIONE REALE' }
        $name = if ($restore) { 'ripristino' } else { 'hardening' }
        $base = Join-Path $dir $name
        $acts | Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        [System.IO.File]::WriteAllText("$base.json", ([pscustomobject]@{ Dominio = $ctx.Dns; DC = $ctx.Dc; Data = (Get-Date).ToString('s'); Modalita = $mode; Eseguito = "$env:USERDOMAIN\$env:USERNAME"; Azioni = $acts } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
        $hero = New-Object System.Collections.Generic.List[string]
        $hero.Add((New-RptKpi $acts.Count 'Azioni elaborate'))
        foreach ($e in @('OK', 'Simulato', 'Attenzione', 'Fallito', 'Annullato')) {
            $n = @($acts | Where-Object { $_.Esito -eq $e }).Count
            if ($n) { $hero.Add((New-RptKpi $n $e (Get-RptTone $e))) }
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("<section class=`"card`" data-filter><h2>Azioni <span class=`"n`"></span></h2><div class=`"toolbar`"><input type=`"search`" placeholder=`"Cerca...`">")
        foreach ($g in @($acts | Group-Object Esito)) { [void]$sb.Append("<span class=`"chip`" data-v=`"$(ConvertTo-RptHtml $g.Name)`">$(ConvertTo-RptHtml $g.Name)<span class=`"c`">$($g.Count)</span></span>") }
        [void]$sb.Append('</div>')
        foreach ($x in $acts) {
            $imp = ''
            if ($x.Impatto) { $imp = "<span class=`"muted`">impatto $(ConvertTo-RptHtml $x.Impatto)</span>" }
            [void]$sb.Append("<details class=`"item`" data-row data-s=`"$(ConvertTo-RptHtml $x.Esito)`"><summary>$(New-RptBadge ([string]$x.Esito))<span class=`"mono muted`">$(ConvertTo-RptHtml $x.Id)</span><span class=`"t`">$(ConvertTo-RptHtml $x.Titolo)</span>$imp</summary><div class=`"det`"><div class=`"kv`">")
            foreach ($r in @(@('Categoria', $x.Categoria), @('Prima', $x.Prima), @('Piano', $x.Piano), @('Risultato', $x.Messaggio), @('Dopo', $x.Dopo), @('Come annullare', $x.Annullamento), @('Richiede', $x.Richiede))) {
                if ($r[1]) { [void]$sb.Append("<b>$($r[0])</b><span>$(ConvertTo-RptHtml $r[1])</span>") }
            }
            [void]$sb.Append('</div></div></details>')
        }
        [void]$sb.Append("</section><p class=`"muted`">Backup dello stato precedente: file *.backup.json in $(ConvertTo-RptHtml $dir). Per annullare: modalita' Ripristino su questa cartella.</p>")
        $title = if ($restore) { 'Ripristino hardening Active Directory' } else { 'Hardening Active Directory' }
        $html = New-RptDocument -Title "$title - $($ctx.Dns)" -Subtitle "DC $($ctx.Dc) - $((Get-Date).ToString('dd/MM/yyyy HH:mm')) - $env:USERDOMAIN\$env:USERNAME - $mode" -Badge 'AD' -HeroHtml ($hero -join '') -BodyHtml $sb.ToString()
        [System.IO.File]::WriteAllText("$base.html", $html, (New-Object System.Text.UTF8Encoding($true)))
        Write-ToolLog "Report: $base.html" 'OK'
        "$base.html"
    }
    #endregion
    #region SPECIFICO: controlli ADCS e ACL, confronto tra fotografie, report, ripristino dai backup

    # ACL (DACL) di un oggetto, letta con DirectorySearcher (SecurityMasks Dacl: basta un utente di dominio)
    function Get-ObjectAcl($Config, [string]$Dn) {
        $ctx = Get-AdContext $Config
        $de = [adsi]"LDAP://$($ctx.Dc)/$($Dn.Replace('/', '\/'))"
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de, '(objectClass=*)', [string[]]@('nTSecurityDescriptor'), [System.DirectoryServices.SearchScope]::Base)
        $ds.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $r = $ds.FindOne()
        if (-not $r -or -not $r.Properties['ntsecuritydescriptor'].Count) { return @() }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$r.Properties['ntsecuritydescriptor'][0])
        @($sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    }

    # Diritto completo presente (i diritti generici sono combinazioni di bit)
    function Test-Right($Rule, [string]$Name) {
        $v = [int][System.DirectoryServices.ActiveDirectoryRights]$Name
        ([int]$Rule.ActiveDirectoryRights -band $v) -eq $v
    }

    function Get-SidLabel([string]$Sid) {
        $n = $null
        try { $n = Resolve-SidAccount $Sid } catch { }
        if ($n) { "$n ($Sid)" } else { $Sid }
    }

    # Principali che per impostazione predefinita hanno diritti estesi sul dominio
    $script:DefaultAdminSidRx = '^S-1-5-(18|9)$|^S-1-5-32-544$|-(498|512|516|518|519)$'
    $script:LowPrivSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545')

    function Get-AdChecksExtra {
        @(
            @{ Id = 'A-ESC-01'; Cat = 'Servizi certificati (ADCS)'; Title = 'Modelli di certificato sfruttabili (ESC1-ESC4)'; Weight = 20; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $pks = "CN=Public Key Services,CN=Services,$($ctx.ConfigDn)"
                $cas = @(Search-Ldap $Config '(objectClass=pKIEnrollmentService)' @('cn', 'dNSHostName', 'certificateTemplates') "CN=Enrollment Services,$pks" 'OneLevel')
                if (-not $cas.Count) { return New-CheckResult 'OK' 'Nessuna CA aziendale registrata in Active Directory' }
                $published = @($cas | ForEach-Object { @($_.certificateTemplates) } | Where-Object { $_ } | Select-Object -Unique)
                $tpls = @(Search-Ldap $Config '(objectClass=pKICertificateTemplate)' @('cn', 'distinguishedName', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy') "CN=Certificate Templates,$pks" 'OneLevel')
                $low = @($script:LowPrivSids) + @("$($ctx.Sid)-513", "$($ctx.Sid)-514", "$($ctx.Sid)-515")
                $enrollG = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
                $autoG = [guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
                $authEku = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '2.5.29.37.0')
                $ev = @(); $bad = 0
                foreach ($t in $tpls) {
                    if ($published -notcontains $t.cn) { continue }
                    $rules = @(Get-ObjectAcl $Config ([string]$t.distinguishedName) | Where-Object { $_.AccessControlType -eq 'Allow' -and $low -contains $_.IdentityReference.Value })
                    $canEnroll = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or ((Test-Right $_ 'ExtendedRight') -and ($_.ObjectType -eq $enrollG -or $_.ObjectType -eq $autoG -or $_.ObjectType -eq [guid]::Empty)) }).Count -gt 0
                    $canWrite = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or ((Test-Right $_ 'WriteProperty') -and $_.ObjectType -eq [guid]::Empty) }).Count -gt 0
                    $eku = @(@($t.pKIExtendedKeyUsage) + @($t.'msPKI-Certificate-Application-Policy') | Where-Object { $_ } | Select-Object -Unique)
                    $approval = ([int]$t.'msPKI-Enrollment-Flag' -band 2) -ne 0
                    $ra = [int]$t.'msPKI-RA-Signature' -gt 0
                    $supplies = ([int]$t.'msPKI-Certificate-Name-Flag' -band 1) -ne 0
                    $iss = @()
                    if ($canEnroll -and -not $approval -and -not $ra) {
                        if ($supplies -and ($eku.Count -eq 0 -or @($eku | Where-Object { $authEku -contains $_ }).Count)) { $iss += 'ESC1: soggetto scelto dal richiedente e uso per autenticazione' }
                        if ($eku.Count -eq 0 -or $eku -contains '2.5.29.37.0') { $iss += 'ESC2: uso qualsiasi o nessun EKU' }
                        if ($eku -contains '1.3.6.1.4.1.311.20.2.1') { $iss += 'ESC3: agente di richiesta certificati' }
                    }
                    if ($canWrite) { $iss += 'ESC4: utenti non privilegiati possono modificare il modello' }
                    if ($iss.Count) { $bad++; $ev += "$($t.cn): $($iss -join '; ')" }
                }
                $ev += @($cas | ForEach-Object { "CA: $($_.cn) ($($_.dNSHostName))" })
                if ($bad) { return New-CheckResult 'Critico' "$bad modelli pubblicati permettono a utenti comuni di ottenere certificati validi per altri utenti, anche amministratori" $ev 'Per ogni modello segnalato: soggetto costruito da AD (non "fornito nella richiesta"), approvazione del responsabile o firma autorizzata, registrazione solo per gruppi dedicati, nessun permesso di scrittura agli utenti comuni; non pubblicare i modelli inutilizzati.' }
                New-CheckResult 'OK' "$(@($tpls | Where-Object { $published -contains $_.cn }).Count) modelli pubblicati su $($cas.Count) CA: nessuna configurazione ESC1-ESC4" $ev
            } }

            @{ Id = 'C-DCSYNC-01'; Cat = 'Configurazione del dominio'; Title = 'Diritti di replica (DCSync) e controllo del dominio'; Weight = 20; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $repl = @([guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', [guid]'89e95b76-444d-4c62-991a-0facbeda640c')
                $rules = @(Get-ObjectAcl $Config $ctx.Dn | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notmatch $script:DefaultAdminSidRx })
                $bad = @($rules | Where-Object {
                    (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or
                    ((Test-Right $_ 'ExtendedRight') -and ($repl -contains $_.ObjectType -or $_.ObjectType -eq [guid]::Empty))
                })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Replica e controllo completo del dominio solo ai gruppi predefiniti' }
                $ev = @($bad | Group-Object { $_.IdentityReference.Value } | ForEach-Object { "$(Get-SidLabel $_.Name): $(($_.Group | ForEach-Object { [string]$_.ActiveDirectoryRights }) -join ', ')" })
                $sync = @($ev | Where-Object { $_ -match 'MSOL_|AAD_|Sync_' })
                if ($sync.Count -eq $ev.Count) { return New-CheckResult 'Attenzione' "Diritti di replica a $($ev.Count) account di sincronizzazione (Entra Connect): leciti ma da proteggere come Tier 0" $ev 'Trattare l''account e il server di sincronizzazione come Tier 0: password lunga, nessun accesso interattivo, server protetto come un DC.' }
                New-CheckResult 'Critico' "$($ev.Count) principali non standard possono replicare i segreti (DCSync) o controllare l'oggetto dominio" $ev 'Rimuovere i diritti "Replicating Directory Changes All" e i permessi di controllo completo concessi a utenti o gruppi non amministrativi; se servono a un prodotto, isolarne l''account come Tier 0.'
            } }

            @{ Id = 'C-ADMSD-01'; Cat = 'Configurazione del dominio'; Title = 'Permessi su AdminSDHolder'; Weight = 15; Needs = 'Utente di dominio'; Run = {
                param($Config)
                $ctx = Get-AdContext $Config
                $rules = @(Get-ObjectAcl $Config "CN=AdminSDHolder,CN=System,$($ctx.Dn)" | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notmatch $script:DefaultAdminSidRx })
                $bad = @($rules | Where-Object { (Test-Right $_ 'GenericAll') -or (Test-Right $_ 'WriteDacl') -or (Test-Right $_ 'WriteOwner') -or ((Test-Right $_ 'WriteProperty') -and $_.ObjectType -eq [guid]::Empty) })
                if (-not $bad.Count) { return New-CheckResult 'OK' 'Nessun permesso di modifica anomalo su AdminSDHolder' }
                $ev = @($bad | Group-Object { $_.IdentityReference.Value } | ForEach-Object { "$(Get-SidLabel $_.Name): $(($_.Group | ForEach-Object { [string]$_.ActiveDirectoryRights }) -join ', ')" })
                New-CheckResult 'Critico' "$($ev.Count) principali non standard possono modificare AdminSDHolder: i loro permessi vengono copiati su tutti gli account privilegiati ogni ora" $ev 'Rimuovere le voci anomale da CN=AdminSDHolder,CN=System (tipica persistenza dopo una compromissione): verificare chi le ha aggiunte.'
            } }
        )
    }

    # ------------------------------------------------------------------ confronto con una fotografia precedente

    function Get-PreviousSnapshot($Config, [string]$CurrentJson) {
        $ctx = Get-AdContext $Config
        $file = [string]$Config.CompareWith
        if (-not $file) {
            $file = @(Get-ChildItem -LiteralPath ([string]$Config.OutputDir) -Filter ('ADAssessment_{0}_*.json' -f $ctx.Dns) -File -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne $CurrentJson } | Sort-Object Name -Descending | Select-Object -First 1 | ForEach-Object { $_.FullName })[0]
        }
        if (-not $file -or -not (Test-Path -LiteralPath $file)) { return $null }
        try {
            $j = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
            [pscustomobject]@{ File = $file; Meta = $j.Meta; Checks = @($j.Controlli) }
        } catch { Write-ToolLog "Fotografia precedente non leggibile ($file): $($_.Exception.Message)" 'WARN'; $null }
    }

    function Get-SnapshotDiff($Prev, $Checks) {
        $sev = @{ 'OK' = 0; 'Info' = 0; 'Attenzione' = 1; 'Critico' = 2 }
        $rows = @()
        foreach ($c in $Checks) {
            $p = @($Prev.Checks | Where-Object { $_.Id -eq $c.Id })[0]
            $before = if ($p) { [string]$p.Esito } else { '(nuovo controllo)' }
            $var = 'Invariato'
            if ($p -and $sev.ContainsKey($before) -and $sev.ContainsKey([string]$c.Esito)) {
                $a = $sev[$before]; $b = $sev[[string]$c.Esito]
                if ($b -gt $a -and $a -eq 0) { $var = 'Nuovo rischio' } elseif ($b -gt $a) { $var = 'Peggiorato' } elseif ($b -lt $a -and $b -eq 0) { $var = 'Risolto' } elseif ($b -lt $a) { $var = 'Migliorato' }
            } elseif (-not $p) { $var = 'Nuovo controllo' }
            $newEv = 0
            if ($p) { $old = @($p.Evidenze); $newEv = @(@($c.Evidenze) | Where-Object { $old -notcontains $_ }).Count }
            if ($var -eq 'Invariato' -and $newEv -gt 0 -and $sev[[string]$c.Esito] -gt 0) { $var = 'Nuove evidenze' }
            $rows += [pscustomobject]@{ Id = $c.Id; Titolo = $c.Titolo; Prima = $before; Ora = $c.Esito; Variazione = $var; NuoveEvidenze = $newEv }
        }
        , $rows
    }

    # ------------------------------------------------------------------ report HTML della fotografia (stile _lib/report)

    function New-FotoHtml($Config, $Meta, $Checks, [string]$Base, $Prev) {
        $tone = @{ 'OK' = 'ok'; 'Info' = 'info'; 'Attenzione' = 'warn'; 'Critico' = 'err'; 'Non verificato' = 'neutral' }
        $order = @{ 'Critico' = 0; 'Attenzione' = 1; 'Non verificato' = 2; 'Info' = 3; 'OK' = 4 }
        $st = 'ok'
        if ($Meta.Punteggio -lt 50) { $st = 'err' } elseif ($Meta.Punteggio -lt 75) { $st = 'warn' }
        $hero = New-Object System.Collections.Generic.List[string]
        $hero.Add((New-RptScore ([int]$Meta.Punteggio) 'Punteggio' $st))
        foreach ($k in @('Critico', 'Attenzione', 'Non verificato', 'Info', 'OK')) {
            $hero.Add((New-RptKpi (@($Checks | Where-Object { $_.Esito -eq $k }).Count) $k $tone[$k]))
        }
        $diffRows = $null
        if ($Prev) {
            $delta = [int]$Meta.Punteggio - [int]$Prev.Meta.Punteggio
            $sign = ''
            if ($delta -gt 0) { $sign = '+' }
            $dt = 'neutral'
            if ($delta -gt 0) { $dt = 'ok' } elseif ($delta -lt 0) { $dt = 'err' }
            $hero.Add((New-RptKpi "$sign$delta" "rispetto al $($Prev.Meta.Data)" $dt))
            $diffRows = Get-SnapshotDiff $Prev $Checks
        }
        $body = New-Object System.Text.StringBuilder
        # riepilogo per categoria
        $cat = @(foreach ($g in @($Checks | Group-Object Categoria)) {
            [pscustomobject]@{
                Categoria = $g.Name; Controlli = $g.Count
                Critici = @($g.Group | Where-Object { $_.Esito -eq 'Critico' }).Count
                Attenzione = @($g.Group | Where-Object { $_.Esito -eq 'Attenzione' }).Count
                Punti = [int](($g.Group | Measure-Object -Property Punti -Sum).Sum)
            }
        })
        [void]$body.Append((New-RptTable -Title 'Rischio per categoria' -Rows $cat -StatusColumn '' -Columns @(
            @{ Name = 'Categoria'; Header = 'Categoria' }, @{ Name = 'Controlli'; Header = 'Controlli'; Num = $true }, @{ Name = 'Critici'; Header = 'Critici'; Num = $true },
            @{ Name = 'Attenzione'; Header = 'Attenzione'; Num = $true }, @{ Name = 'Punti'; Header = 'Punti di rischio'; Num = $true })))
        if ($diffRows) {
            $changed = @($diffRows | Where-Object { $_.Variazione -ne 'Invariato' })
            $note = "Confronto con $([System.IO.Path]::GetFileName($Prev.File)): $($changed.Count) variazioni"
            [void]$body.Append((New-RptTable -Title $note -Rows $changed -StatusColumn 'Variazione' -Columns @(
                @{ Name = 'Variazione'; Header = 'Variazione'; Badge = $true }, @{ Name = 'Id'; Header = 'ID'; Mono = $true }, @{ Name = 'Titolo'; Header = 'Controllo' },
                @{ Name = 'Prima'; Header = 'Prima'; Badge = $true }, @{ Name = 'Ora'; Header = 'Ora'; Badge = $true }, @{ Name = 'NuoveEvidenze'; Header = 'Nuove evidenze'; Num = $true })))
        }
        foreach ($g in @($Checks | Group-Object Categoria)) {
            $items = New-Object System.Text.StringBuilder
            foreach ($c in @($g.Group | Sort-Object { $order[$_.Esito] }, Id)) {
                $t = $tone[[string]$c.Esito]
                if (-not $t) { $t = 'neutral' }
                $pts = ''
                if ($c.Punti) { $pts = "<span class=`"muted`">$($c.Punti) punti</span>" }
                [void]$items.Append("<details class=`"item`" data-row data-s=`"$(ConvertTo-RptHtml $c.Esito)`"><summary>$(New-RptBadge ([string]$c.Esito) $t)<span class=`"mono muted`">$(ConvertTo-RptHtml $c.Id)</span><span class=`"t`">$(ConvertTo-RptHtml $c.Titolo)</span>$pts</summary><div class=`"det`"><div class=`"kv`">")
                [void]$items.Append("<b>Esito</b><span>$(ConvertTo-RptHtml $c.Sintesi)</span>")
                if ($c.Remediation -and $c.Esito -ne 'OK') { [void]$items.Append("<b>Cosa fare</b><span>$(ConvertTo-RptHtml $c.Remediation)</span>") }
                [void]$items.Append("<b>Richiede</b><span>$(ConvertTo-RptHtml $c.Richiede)</span></div>")
                $ev = @($c.Evidenze)
                if ($ev.Count) { [void]$items.Append("<div style=`"margin-top:10px`" class=`"mono`">$((@($ev) | ForEach-Object { ConvertTo-RptHtml $_ }) -join '<br>')</div>") }
                [void]$items.Append('</div></details>')
            }
            [void]$body.Append("<section class=`"card`" data-filter><h2>$(ConvertTo-RptHtml $g.Name) <span class=`"n`"></span></h2><div class=`"toolbar`"><input type=`"search`" placeholder=`"Cerca nei controlli e nelle evidenze...`">")
            foreach ($k in @('Critico', 'Attenzione', 'Non verificato', 'Info', 'OK')) {
                $n = @($g.Group | Where-Object { $_.Esito -eq $k }).Count
                if ($n) { [void]$body.Append("<span class=`"chip`" data-v=`"$k`">$k<span class=`"c`">$n</span></span>") }
            }
            [void]$body.Append("</div>$($items.ToString())</section>")
        }
        [void]$body.Append("<p class=`"muted`">Fotografia in sola lettura: nessuna modifica al dominio. File: $(ConvertTo-RptHtml $Base).json, _controlli.csv, _evidenze.csv</p>")
        $sub = "Dominio $($Meta.Dominio) - DC $($Meta.DC) - $($Meta.Data) - $($Meta.Eseguito) su $($Meta.Da) - $($Tool.Title) $($Tool.Version)"
        $html = New-RptDocument -Title "Fotografia di sicurezza Active Directory - $($Meta.Dominio)" -Subtitle $sub -Badge 'AD' -HeroHtml ($hero -join '') -BodyHtml $body.ToString()
        [System.IO.File]::WriteAllText("$Base.html", $html, (New-Object System.Text.UTF8Encoding($true)))
        "$Base.html"
    }

    # ------------------------------------------------------------------ ripristino dai backup dell'hardening

    # Come si annulla ogni azione (Kind) e cosa non e' annullabile in automatico
    function Get-RestoreKind([string]$Id) {
        switch -Regex ($Id) {
            '^HD-(SENSITIVE|ASREP|DES|REVERSIBLE|PWDNOTREQD|GUEST)$' { return 'Uac' }
            '^HD-(DC|MB)-' { return 'GpoRegistry' }
            '^HD-INACTIVE-' { return 'Inactive' }
            '^HD-(PRE2K|SCHEMA)$' { return 'GroupReadd' }
            '^HD-PROTUSERS$' { return 'GroupRemove' }
            '^HD-MAQ$' { return 'Maq' }
            '^HD-PWDPOL$' { return 'PwdPol' }
            '^HD-ADMINPSO$' { return 'Pso' }
            '^HD-ADMINCOUNT$' { return 'AdminCount' }
            '^HD-(DC-AUDIT|LAPS-GPO|TIER-LOGON)$' { return 'GpoUnlink' }
            default { return '' }
        }
    }

    function Get-RestoreItems($Config) {
        Initialize-Hardening $Config
        $dir = [string]$Config.RestoreFolder
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { throw 'Indicare la cartella di un''esecuzione di hardening (Hardening_<dominio>_<data>) nel campo "Cartella da ripristinare".' }
        Write-ToolLog "Ripristino - backup in $dir" 'STEP'
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.backup.json' -File | Sort-Object LastWriteTime -Descending)) {
            $b = $null
            try { $b = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { }
            $id = if ($b) { [string]$b.Id } else { $f.Name }
            $kind = Get-RestoreKind $id
            $state = 'Annullabile'
            if (-not $b) { $state = 'Backup non leggibile' } elseif (-not $kind) { $state = 'Non annullabile in automatico (vedi report di hardening)' }
            [pscustomobject]@{
                Key = $f.FullName; Utente = $id; SID = ''; Origine = $f.Name
                Id = $id; Categoria = 'Ripristino'; Controllo = "Annulla $id (backup del $(if ($b) { $b.Date } else { '?' }) di $(if ($b) { $b.By } else { '?' }))"
                Peso = ''; Richiede = 'Domain Admins'; Stato = $state; Selectable = [bool]($b -and $kind); File = $f.FullName
            }
        }
    }

    function Invoke-RestoreItem($Config, $Item) {
        Initialize-Hardening $Config
        $ctx = Get-AdContext $Config
        $b = Get-Content -LiteralPath $Item.Key -Raw -Encoding UTF8 | ConvertFrom-Json
        $kind = Get-RestoreKind ([string]$b.Id)
        $data = $b.Data
        $plan = @()
        $do = -not $Config.DryRun
        switch ($kind) {
            'Uac' {
                foreach ($a in @($data)) {
                    # solo i bit modificati dall'hardening: le altre modifiche successive (es. account disattivato) restano
                    $mask = [int]$a.OldUac -bxor [int]$a.NewUac
                    $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$a.Dn).Replace('/', '\/'))"
                    $now = [int]$de.Properties['userAccountControl'].Value
                    $target = ($now -band (-bnot $mask)) -bor ([int]$a.OldUac -band $mask)
                    if ($target -eq $now) { $plan += "$($a.Account): gia' come prima"; continue }
                    $plan += "$($a.Account): userAccountControl 0x$('{0:X}' -f $now) -> 0x$('{0:X}' -f $target)"
                    if ($do) { $de.Properties['userAccountControl'].Value = $target; $de.CommitChanges() }
                }
            }
            'GpoRegistry' {
                foreach ($v in @($data)) {
                    $g = Get-GPO -Name ([string]$v.Gpo) -ErrorAction Stop
                    if ($null -eq $v.Old) {
                        $plan += "$($v.Gpo): rimuovi $($v.Key)\$($v.Name)"
                        if ($do) { Remove-GPRegistryValue -Guid $g.Id -Key $v.Key -ValueName $v.Name -ErrorAction SilentlyContinue | Out-Null }
                    } else {
                        $plan += "$($v.Gpo): $($v.Key)\$($v.Name) = $(@($v.Old) -join ', ')"
                        # tipo del valore precedente (backup recenti), altrimenti quello impostato dall'hardening; DWord per i backup vecchi
                        $type = if ($v.OldType) { [string]$v.OldType } elseif ($v.Type) { [string]$v.Type } else { 'DWord' }
                        $val = switch ($type) { 'DWord' { [int]$v.Old } 'QWord' { [int64]$v.Old } 'MultiString' { [string[]]@($v.Old) } default { [string]$v.Old } }
                        if ($do) { Set-GPRegistryValue -Guid $g.Id -Key $v.Key -ValueName $v.Name -Type $type -Value $val | Out-Null }
                    }
                }
            }
            'Inactive' {
                foreach ($a in @($data)) {
                    $cur = @(Search-Ldap $Config ('(sAMAccountName={0})' -f (ConvertTo-LdapValue ([string]$a.Account))) @('distinguishedName'))[0]
                    if (-not $cur) { $plan += "$($a.Account): non trovato"; continue }
                    $origParent = ([string]$a.Dn) -replace '^(?:[^,\\]|\\.)+,', ''
                    $plan += "$($a.Account): riattiva, ripristina la descrizione" + $(if ([string]$cur.distinguishedName -ne [string]$a.Dn) { " e riporta in $origParent" } else { '' })
                    if ($do) {
                        $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$cur.distinguishedName).Replace('/', '\/'))"
                        # si toglie solo la disattivazione fatta dall'hardening (bit 2), il resto di userAccountControl resta com'e'
                        $now = [int]$de.Properties['userAccountControl'].Value
                        if (-not ([int]$a.OldUac -band 2)) { $now = $now -band (-bnot 2) }
                        $de.Properties['userAccountControl'].Value = $now
                        if ($a.Description) { $de.Properties['description'].Value = [string]$a.Description } else { $de.Properties['description'].Clear() }
                        $de.CommitChanges()
                        if ([string]$cur.distinguishedName -ne [string]$a.Dn) { Move-ADObject -Identity ([string]$cur.distinguishedName) -TargetPath $origParent }
                    }
                }
            }
            'GroupReadd' {
                $gdn = if ([string]$b.Id -eq 'HD-SCHEMA') { Get-SidDn $Config "$($ctx.Sid)-518" } else { Get-SidDn $Config 'S-1-5-32-554' }
                $de = [adsi]"LDAP://$($ctx.Dc)/$($gdn.Replace('/', '\/'))"
                foreach ($m in @($data.Removed)) {
                    $plan += "Riaggiungi $m"
                    if ($do -and -not ($de.Properties['member'] -contains [string]$m)) { [void]$de.Properties['member'].Add([string]$m) }
                }
                if ($do) { $de.CommitChanges() }
            }
            'GroupRemove' {
                $de = [adsi]"LDAP://$($ctx.Dc)/$((Get-SidDn $Config "$($ctx.Sid)-525").Replace('/', '\/'))"
                foreach ($m in @($data.Added)) {
                    $plan += "Togli da Protected Users: $m"
                    if ($do -and ($de.Properties['member'] -contains [string]$m)) { [void]$de.Properties['member'].Remove([string]$m) }
                }
                if ($do) { $de.CommitChanges() }
            }
            'Maq' {
                $plan += "ms-DS-MachineAccountQuota = $($data.Old)"
                if ($do) { $de = [adsi]"LDAP://$($ctx.Dc)/$($ctx.Dn)"; $de.Properties['ms-DS-MachineAccountQuota'].Value = [int]$data.Old; $de.CommitChanges() }
            }
            'PwdPol' {
                $plan += "Policy di dominio: minimo $($data.MinPasswordLength), complessita' $($data.ComplexityEnabled), blocco $($data.LockoutThreshold), cronologia $($data.PasswordHistoryCount)"
                if ($do) {
                    Set-ADDefaultDomainPasswordPolicy -Identity $ctx.Dn -MinPasswordLength ([int]$data.MinPasswordLength) -ComplexityEnabled ([bool]$data.ComplexityEnabled) -ReversibleEncryptionEnabled ([bool]$data.ReversibleEncryptionEnabled) `
                        -LockoutThreshold ([int]$data.LockoutThreshold) -LockoutDuration ([TimeSpan]::Parse([string]$data.LockoutDuration)) -LockoutObservationWindow ([TimeSpan]::Parse([string]$data.LockoutObservationWindow)) -PasswordHistoryCount ([int]$data.PasswordHistoryCount)
                }
            }
            'Pso' {
                $name = [string]$data.Pso
                if ($name -notlike "$($Config.GpoPrefix)-*") { throw "La PSO $name non e' stata creata da questo strumento: non la elimino." }
                $plan += "Elimina la PSO $name"
                if ($do) { Remove-ADFineGrainedPasswordPolicy -Identity $name -Confirm:$false }
            }
            'AdminCount' {
                foreach ($dn in @($data)) {
                    $plan += "adminCount = 1 su $dn"
                    if ($do) { $de = [adsi]"LDAP://$($ctx.Dc)/$(([string]$dn).Replace('/', '\/'))"; $de.Properties['adminCount'].Value = 1; $de.CommitChanges() }
                }
            }
            'GpoUnlink' {
                $names = @(@($data.Gpo) | ForEach-Object { ([string]$_ -split ':')[0].Trim() } | Where-Object { $_ })
                foreach ($n in $names) {
                    $g = $null
                    try { $g = Get-GPO -Name $n -ErrorAction Stop } catch { $plan += "$n non trovata"; continue }
                    $links = @(Get-GpoLinkTargets $Config $g)
                    $plan += "Disattiva i collegamenti di '$n' ($($links.Count))"
                    if ($do) { foreach ($t in $links) { Set-GPLink -Guid $g.Id -Target $t -LinkEnabled No | Out-Null } }
                }
            }
            default { throw 'Azione non annullabile in automatico.' }
        }
        foreach ($p in $plan) { Write-ToolLog "    $p" }
        $esito = 'OK'
        $msg = ($plan -join '; ')
        if (-not $do) { $esito = 'Simulato'; $msg = 'Verrebbe eseguito: ' + $msg }
        $dati = [pscustomobject]@{ Id = [string]$b.Id; Categoria = 'Ripristino'; Titolo = "Annulla $($b.Id)"; Impatto = ''; Richiede = 'Domain Admins'; Prima = "Backup del $($b.Date) di $($b.By)"; Piano = ($plan -join '; '); Esito = $esito; Messaggio = $msg; Dopo = ''; Annullamento = '' }
        @{ Esito = $esito; Messaggio = $msg; Dati = $dati }
    }

    # OU e dominio a cui e' collegata una GPO (dal report XML della GPO)
    function Get-GpoLinkTargets($Config, $Gpo) {
        $ctx = Get-AdContext $Config
        $guid = "{$($Gpo.Id)}"
        @(Search-Ldap $Config ('(gPLink=*{0}*)' -f $guid) @('distinguishedName') | ForEach-Object { [string]$_.distinguishedName })
    }
    #endregion
}
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Modalita''' }
    @{ Key = 'Mode'; Label = 'Modalita'''; Type = 'Choice'; Choices = @('Fotografia', 'Hardening', 'Ripristino'); Help = 'Fotografia: controlli in sola lettura e report. Hardening: azioni correttive selezionabili una per una, con verifica prima e dopo, backup e report. Ripristino: annulla le azioni di un''esecuzione di hardening partendo dai suoi backup. Dopo il cambio premere Analizza.' }
    @{ Key = 'DryRun'; Label = 'Simulazione (hardening)'; Type = 'Bool'; Help = 'Attiva di default: mostra cosa verrebbe fatto senza modificare nulla. Toglierla solo dopo aver letto il report di simulazione.' }
    @{ Key = 'CompareWith'; Label = 'Fotografia da confrontare'; Type = 'File'; Filter = 'Fotografia (*.json)|*.json'; Help = 'Vuoto = l''ultima fotografia dello stesso dominio nella cartella dei report. Il report mostra rischi nuovi, risolti, peggiorati e la variazione del punteggio.' }
    @{ Key = 'RestoreFolder'; Label = 'Cartella da ripristinare'; Type = 'Folder'; Help = 'Solo modalita'' Ripristino: cartella Hardening_<dominio>_<data> con i file *.backup.json da annullare.' }
    @{ Type = 'Section'; Label = 'Dominio' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente. Letture LDAP, GPO e SYSVOL usano tutte questo DC (niente conflitti di replica).' }
    @{ Type = 'Section'; Label = 'Soglie' }
    @{ Key = 'InactiveDays'; Label = 'Giorni di inattivita'''; Type = 'Int'; Min = 30; Max = 730; Help = 'Utenti e computer senza logon oltre questa soglia: segnalati in fotografia, disattivabili in hardening.' }
    @{ Key = 'KrbtgtMaxDays'; Label = 'Eta'' massima password krbtgt (giorni)'; Type = 'Int'; Min = 30; Max = 3650; Help = 'Oltre: Attenzione; oltre il triplo: Critico. In hardening: oltre questa eta'' si propone la rotazione.' }
    @{ Key = 'PrivilegedMax'; Label = 'Numero massimo di Domain Admins'; Type = 'Int'; Min = 1; Max = 100 }
    @{ Key = 'MaxEvidence'; Label = 'Evidenze massime per controllo'; Type = 'Int'; Min = 10; Max = 100000; Help = 'Righe mostrate nel report HTML; il JSON e il CSV delle evidenze contengono lo stesso limite.' }
    @{ Type = 'Section'; Label = 'Controlli opzionali (fotografia)' }
    @{ Key = 'CheckDcServices'; Label = 'Interroga i servizi dei DC (Print Spooler)'; Type = 'Bool'; Help = 'Richiede privilegi di amministratore sui DC e WinRM/WMI raggiungibile; altrimenti il controllo risulta Non verificato.' }
    @{ Key = 'ScanSysvolGpp'; Label = 'Cerca password GPP in SYSVOL (cpassword)'; Type = 'Bool'; Help = 'Legge tutti i file XML delle GPO in SYSVOL.' }
    @{ Type = 'Section'; Label = 'Hardening - GPO' }
    @{ Key = 'GpoPrefix'; Label = 'Prefisso delle GPO e della PSO'; Type = 'Text'; Help = 'Es. FispaTools: GPO "FispaTools - DC Hardening", "FispaTools - DC Audit", "FispaTools - Member Hardening", "FispaTools - Windows LAPS".' }
    @{ Key = 'GpoLinkMode'; Label = 'Collegamento delle GPO'; Type = 'Choice'; Choices = @('Collegata e attiva', 'Collegata disattivata', 'Non collegata'); Help = 'Collegata disattivata: la GPO e'' pronta e si attiva a mano dopo la revisione in GPMC.' }
    @{ Key = 'MemberHardeningOus'; Label = 'OU per server e client'; Type = 'List'; Help = 'Distinguished name separati da ; (es. OU=Server,DC=contoso,DC=local). Vuoto = azioni HD-MB-* non applicabili.' }
    @{ Key = 'LmCompatibilityLevel'; Label = 'Livello NTLM (LmCompatibilityLevel)'; Type = 'Int'; Min = 3; Max = 5; Help = '5 = solo NTLMv2, rifiuta LM e NTLMv1 (consigliato); 3 = invia solo NTLMv2 ma accetta tutto.' }
    @{ Key = 'LdapChannelBinding'; Label = 'Channel binding LDAPS'; Type = 'Choice'; Choices = @('Se supportato', 'Sempre'); Help = '"Sempre" rifiuta i client che non lo supportano: prima usare "Se supportato" e controllare gli eventi 3039.' }
    @{ Key = 'SecurityLogMaxMB'; Label = 'Dimensione del registro Security sui DC (MB)'; Type = 'Int'; Min = 128; Max = 4096 }
    @{ Key = 'StopSpoolerNow'; Label = 'Ferma subito lo Spooler sui DC'; Type = 'Bool'; Help = 'Oltre alla GPO, ferma e disattiva il servizio via WMI/CIM (servono WinRM e privilegi sui DC).' }
    @{ Type = 'Section'; Label = 'Hardening - password e account privilegiati' }
    @{ Key = 'DomainMinPasswordLength'; Label = 'Lunghezza minima password di dominio'; Type = 'Int'; Min = 8; Max = 14; Help = 'Policy di dominio (massimo 14 senza l''opzione relax). Vale al prossimo cambio di ogni utente.' }
    @{ Key = 'DomainLockoutThreshold'; Label = 'Blocco dopo N tentativi errati'; Type = 'Int'; Min = 3; Max = 50 }
    @{ Key = 'DomainLockoutMinutes'; Label = 'Durata del blocco (minuti)'; Type = 'Int'; Min = 5; Max = 1440 }
    @{ Key = 'AdminPsoMinLength'; Label = 'Lunghezza minima password admin (PSO)'; Type = 'Int'; Min = 14; Max = 128 }
    @{ Key = 'AdminPsoMaxAgeDays'; Label = 'Scadenza password admin (giorni, 0 = mai)'; Type = 'Int'; Min = 0; Max = 3650 }
    @{ Key = 'ProtectedUsersMode'; Label = 'Protected Users'; Type = 'Choice'; Choices = @('Elenco', 'Tutti gli account privilegiati'); Help = 'Elenco = solo gli account indicati sotto. Gli account con SPN, l''Administrator integrato e i break-glass sono sempre esclusi.' }
    @{ Key = 'ProtectedUsersList'; Label = 'Account da mettere in Protected Users'; Type = 'List'; Help = 'sAMAccountName separati da ;' }
    @{ Key = 'BreakGlassAccounts'; Label = 'Account di emergenza (break-glass)'; Type = 'List'; Help = 'Mai in Protected Users e mai disattivati per inattivita''.' }
    @{ Key = 'KrbtgtMinHours'; Label = 'Ore minime tra le due rotazioni di krbtgt'; Type = 'Int'; Min = 10; Max = 720; Help = 'Almeno la durata massima dei ticket (10 ore) piu'' la replica completa.' }
    @{ Type = 'Section'; Label = 'Hardening - account inattivi' }
    @{ Key = 'InactiveAction'; Label = 'Azione sugli inattivi'; Type = 'Choice'; Choices = @('Disattiva', 'Disattiva e sposta') }
    @{ Key = 'QuarantineOu'; Label = 'OU di quarantena'; Type = 'Text'; Help = 'Distinguished name dell''OU in cui spostare gli account disattivati.' }
    @{ Key = 'InactiveExclude'; Label = 'Account esclusi'; Type = 'List'; Help = 'sAMAccountName (anche computer, con $) separati da ;' }
    @{ Key = 'InactiveSkipWithSpn'; Label = 'Escludi gli utenti con SPN (account di servizio)'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Hardening - Windows LAPS' }
    @{ Key = 'LapsOus'; Label = 'OU dei computer gestiti da LAPS'; Type = 'List'; Help = 'Distinguished name separati da ; (permessi SELF e collegamento della GPO). Vuoto = azioni LAPS non applicabili.' }
    @{ Key = 'LapsPasswordLength'; Label = 'Lunghezza della password LAPS'; Type = 'Int'; Min = 14; Max = 64 }
    @{ Key = 'LapsPasswordAgeDays'; Label = 'Rotazione della password LAPS (giorni)'; Type = 'Int'; Min = 1; Max = 365 }
    @{ Key = 'LapsAdminAccount'; Label = 'Account admin locale gestito'; Type = 'Text'; Help = 'Vuoto = Administrator integrato (RID 500).' }
    @{ Type = 'Section'; Label = 'Hardening - tier model' }
    @{ Key = 'TierRootName'; Label = 'OU radice del tier model'; Type = 'Text'; Help = 'Creata sotto la radice del dominio con Tier0/1/2 (Accounts, Groups, Devices, ServiceAccounts) e i gruppi TierN-Admins.' }
    @{ Key = 'TierLinkGpos'; Label = 'Collega le GPO di restrizione dei logon'; Type = 'Bool'; Help = 'Spento = GPO create ma non collegate. Prima spostare server e PC nelle OU Devices dei tier giusti.' }
    @{ Type = 'Section'; Label = 'Output' }
    @{ Key = 'OutputDir'; Label = 'Cartella dei report'; Type = 'Folder'; Help = 'Fotografia: HTML, JSON, CSV. Hardening: una cartella per esecuzione con report e backup dello stato precedente.' }
    @{ Key = 'LogDir'; Label = 'Cartella log'; Type = 'Folder' }
)

$ToolColumns = @(
    @{ Name = 'Id'; Header = 'ID'; Weight = 9 }
    @{ Name = 'Categoria'; Header = 'Categoria'; Weight = 12 }
    @{ Name = 'Controllo'; Header = 'Controllo / azione'; Weight = 28 }
    @{ Name = 'Peso'; Header = 'Peso / impatto'; Weight = 6 }
    @{ Name = 'Stato'; Header = 'Stato attuale'; Weight = 26 }
    @{ Name = 'Richiede'; Header = 'Richiede'; Weight = 11 }
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
