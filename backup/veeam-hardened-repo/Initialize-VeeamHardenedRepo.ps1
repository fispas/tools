<#
.SYNOPSIS
    Configura via SSH un server Ubuntu come hardened repository Veeam (iSCSI, multipath, LUN XFS, utente, blindatura), con GUI configurabile.

.DESCRIPTION
    Pannello Windows che guida la configurazione della macchina "vrepo" appena installata.
    Il lavoro sul server lo fa vrepo-setup.sh (incorporato in questo file), eseguito via OpenSSH:
      1. Accesso: chiave SSH dedicata, installazione di vrepo-setup.sh e regola sudo limitata allo script
      2. Pacchetti (open-iscsi, xfsprogs, parted, multipath-tools) e ora di sistema (NTP)
      3. Initiator iSCSI (nome, node.startup automatico)
      4. Target: discovery sui portali indicati, login con avvio automatico, CHAP, record non usati eliminati
      5. Multipath: profilo QNAP o generico, alias multipath con il nome della LUN
      6. LUN: GPT, XFS reflink/crc 4K, fstab per UUID (_netdev,nofail), mount protetto con chattr +i
      7. Utente Veeam: creazione, password generata, sudo temporaneo, permessi 700 sui repository
      8. Blindatura dopo l'aggiunta in VBR: via sudo, password bloccata, chiave e regola del tool rimosse, SSH spento
    Analizza legge lo stato del server e propone i passi e le LUN trovate. Simulazione attiva di default.
    Lo stesso script si usa anche da solo sul server: sudo ./vrepo-setup.sh (wizard a menu).

.PARAMETER ConfigPath
    File di configurazione JSON. Default: %ProgramData%\FispaTools\VeeamHardenedRepo\config.json

.PARAMETER NoGui
    Esecuzione senza interfaccia con la configurazione salvata. Richiede -User con i passi da eseguire.

.PARAMETER User
    Con -NoGui: passi da eseguire, con il nome mostrato nella colonna Passo
    (Accesso, Pacchetti, NTP, Initiator, Target, Multipath, LUN:<nome>, Utente, Blindatura, Disconnessione).

.PARAMETER Simulate
    Con -NoGui: forza la simulazione.

.EXAMPLE
    .\Initialize-VeeamHardenedRepo.ps1

.EXAMPLE
    .\Initialize-VeeamHardenedRepo.ps1 -NoGui -ConfigPath D:\Profili\vrepo01.json -User Pacchetti,NTP,Initiator,Target,Multipath -Simulate

.NOTES
    Versione: 1.0.0
    Repo:     fispas/tools (backup/veeam-hardened-repo)
    Richiede: client OpenSSH di Windows (ssh.exe, ssh-keygen.exe), PowerShell 5.1; sul server Ubuntu 22.04/24.04 con un utente amministratore (sudo)
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$NoGui,
    [string[]]$User,
    [switch]$Simulate
)

$Tool = @{
    Name          = 'VeeamHardenedRepo'
    Title         = 'Veeam Hardened Repository: configurazione vrepo'
    Version       = '1.0.0'
    ItemNoun      = 'passi'
    ItemTab       = 'Passi'
    StartLabel    = 'Esegui i passi'
    RunningLabel  = 'Configurazione del server in corso'
    CloseWarning  = "`nUn comando gia' avviato sul server prosegue fino alla fine."
    RequiresAdmin = $false
    ConfirmKeys   = @('Host', 'SshUser', 'IscsiPortals', 'Multipath', 'MountBase', 'VeeamUser', 'ForceFormat', 'SshDisable')
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

    #region SPECIFICO: hardened repository Veeam su Ubuntu via OpenSSH

    # vrepo-setup.sh incorporato da _lib/build.py (base64, fine riga LF)
    $script:VrepoB64 = 'IyEvdXNyL2Jpbi9lbnYgYmFzaAojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiMgdnJlcG8tc2V0dXAuc2ggLSBjb25maWd1cmF6aW9uZSBndWlkYXRhIGRpIHVuIGhhcmRlbmVkIHJlcG9zaXRvcnkgVmVlYW0gc3UgVWJ1bnR1CiMKIyBpU0NTSSAoaW5pdGlhdG9yLCBkaXNjb3ZlcnksIGxvZ2luIGF1dG9tYXRpY28sIENIQVApLCBtdWx0aXBhdGggKHByb2ZpbG8gUU5BUAojIG8gZ2VuZXJpY28sIGFsaWFzIHBlciBMVU4pLCBMVU4gKEdQVCwgWEZTIHJlZmxpbmssIGZzdGFiIHBlciBVVUlELCBtb3VudAojIHByb3RldHRvKSwgdXRlbnRlIFZlZWFtIGNvbiBzdWRvIHRlbXBvcmFuZW8sIGJsaW5kYXR1cmEgZG9wbyBsJ2FnZ2l1bnRhIGluIFZCUiwKIyByaWFwZXJ0dXJhIHRlbXBvcmFuZWEgcGVyIGdsaSBhZ2dpb3JuYW1lbnRpIFZlZWFtLCBkaXNjb25uZXNzaW9uZSBkZWkgdGFyZ2V0LgojCiMgVXNvOiAgc3VkbyAuL3ZyZXBvLXNldHVwLnNoICAgICAgICAgICAgICAgICAgd2l6YXJkIGludGVyYXR0aXZvIChtZW51KQojICAgICAgIHN1ZG8gLi92cmVwby1zZXR1cC5zaCAtLWhlbHAgICAgICAgICAgIHR1dHRpIGkgY29tYW5kaSBlIGxlIG9wemlvbmkKIwojIFJlcG86IGZpc3Bhcy90b29scyAoYmFja3VwL3ZlZWFtLWhhcmRlbmVkLXJlcG8pCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0Kc2V0IC1vIHBpcGVmYWlsCnVtYXNrIDAyMgpleHBvcnQgTENfQUxMPUMuVVRGLTggMj4vZGV2L251bGwgfHwgZXhwb3J0IExDX0FMTD1DCgpWRVJTSU9OPSIxLjAuMCIKQlQ9IlZlZWFtIEhhcmRlbmVkIFJlcG9zaXRvcnkgLSB2cmVwby1zZXR1cCAkVkVSU0lPTiIKU1RBVEVfRElSPS9ldGMvdnJlcG8tc2V0dXAKU1RBVEVfUkVQT1M9JFNUQVRFX0RJUi9yZXBvcyAgICAgICAgICAjIG5vbWV8d3dpZHx1dWlkfG1vdW50ClNUQVRFX0FMSUFTRVM9JFNUQVRFX0RJUi9hbGlhc2VzICAgICAgIyB3d2lkfGFsaWFzIG11bHRpcGF0aApTVEFURV9NUFBST0ZJTEU9JFNUQVRFX0RJUi9tdWx0aXBhdGgtcHJvZmlsZQpTQVZFRF9DT05GPSRTVEFURV9ESVIvdnJlcG8uY29uZgpMT0dfRklMRT0vdmFyL2xvZy92cmVwby1zZXR1cC5sb2cKSU5TVEFMTF9QQVRIPS91c3IvbG9jYWwvc2Jpbi92cmVwby1zZXR1cC5zaApTVURPRVJTX0ZJTEU9L2V0Yy9zdWRvZXJzLmQvOTAtdnJlcG8tc2V0dXAKS0VZX0NPTU1FTlQ9dnJlcG8tc2V0dXAKTVBfTUFSSz0iIyB2cmVwby1zZXR1cDogZmlsZSBnZW5lcmF0byIKCkRSWV9SVU49MApHVUk9MApJTlRFUkFDVElWRT0wCkFTU1VNRV9ZRVM9MApDT05GSUdfRklMRT0iIgpPUFRfREVWPSIiCk9QVF9XV0lEPSIiCk9QVF9OQU1FPSIiCk9QVF9NT1VOVD0iIgpPUFRfVEFSR0VUPSIiCldBUk5JTkdTPTAKRVJST1JTPTAKCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBjb25maWd1cmF6aW9uZQpDT05GSUdfS0VZUz0iSU5JVElBVE9SX05BTUUgSVNDU0lfUE9SVEFMUyBJU0NTSV9QT1JUIElTQ1NJX1RBUkdFVFMgT05MWV9MSVNURURfUE9SVEFMUyBDSEFQX1VTRVIgQ0hBUF9QQVNTV09SRApNVUxUSVBBVEggTVVMVElQQVRIX1BST0ZJTEUgTVVMVElQQVRIX0FMSUFTIExVTl9QUkVGSVggTFVOX05BTUVTIE1PVU5UX0JBU0UgUEFSVElUSU9OIEZPUkNFX0ZPUk1BVApWRUVBTV9VU0VSIFZFRUFNX1BBU1NXT1JEIE5UUF9TRVJWRVJTIFRJTUVaT05FIFNTSF9ESVNBQkxFIExPQ0tfVkVFQU1fUEFTU1dPUkQgTE9DS0RPV05fRk9SQ0UKUkVNT1ZFX1RBUkdFVFMgUkVNT1ZFX0RJU0NPVkVSWSBBRE1JTl9VU0VSIgpTRUNSRVRfS0VZUz0iIENIQVBfUEFTU1dPUkQgVkVFQU1fUEFTU1dPUkQgIgoKQ0ZHX0lOSVRJQVRPUl9OQU1FPSIiICAgICAgICAjIHZ1b3RvID0gbWFudGllbmUgcXVlbGxvIGF0dHVhbGUKQ0ZHX0lTQ1NJX1BPUlRBTFM9IiIgICAgICAgICAjIElQIGRlbCB0YXJnZXQsIHNlcGFyYXRpIGRhIHNwYXppby92aXJnb2xhICh1bm8gcGVyIHBlcmNvcnNvKQpDRkdfSVNDU0lfUE9SVD0iMzI2MCIKQ0ZHX0lTQ1NJX1RBUkdFVFM9IiIgICAgICAgICAjIElRTiBvIGNhcmF0dGVyaSBqb2xseTsgdnVvdG8gPSB0dXR0aSBxdWVsbGkgc2NvcGVydGkKQ0ZHX09OTFlfTElTVEVEX1BPUlRBTFM9InllcyIgIyBsb2dpbiBzb2xvIHN1aSBwb3J0YWxpIGluZGljYXRpIChub24gc3VnbGkgYWx0cmkgSVAgZGVsIE5BUykKQ0ZHX0NIQVBfVVNFUj0iIgpDRkdfQ0hBUF9QQVNTV09SRD0iIgpDRkdfTVVMVElQQVRIPSJhdXRvIiAgICAgICAgICMgYXV0byB8IHllcyB8IG5vCkNGR19NVUxUSVBBVEhfUFJPRklMRT0icW5hcCIgIyBxbmFwIHwgZ2VuZXJpYwpDRkdfTVVMVElQQVRIX0FMSUFTPSJ5ZXMiICAgICMgYWxpYXMgbXVsdGlwYXRoID0gbm9tZSBkZWxsYSBMVU4KQ0ZHX0xVTl9QUkVGSVg9InZlZWFtLXJlcG8iCkNGR19MVU5fTkFNRVM9IiIgICAgICAgICAgICAgIyB3d2lkPW5vbWU7c2RiPW5vbWU7Li4uCkNGR19NT1VOVF9CQVNFPSIvbW50IgpDRkdfUEFSVElUSU9OPSJ5ZXMiCkNGR19GT1JDRV9GT1JNQVQ9Im5vIgpDRkdfVkVFQU1fVVNFUj0idmVlYW1iY2siCkNGR19WRUVBTV9QQVNTV09SRD0iIiAgICAgICAgIyB2dW90byA9IGdlbmVyYXRhCkNGR19OVFBfU0VSVkVSUz0iIgpDRkdfVElNRVpPTkU9IiIKQ0ZHX1NTSF9ESVNBQkxFPSJ5ZXMiCkNGR19MT0NLX1ZFRUFNX1BBU1NXT1JEPSJ5ZXMiCkNGR19MT0NLRE9XTl9GT1JDRT0ibm8iCkNGR19SRU1PVkVfVEFSR0VUUz0iIgpDRkdfUkVNT1ZFX0RJU0NPVkVSWT0ibm8iCkNGR19BRE1JTl9VU0VSPSIiCgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gbG9nCl9sb2coKSB7CiAgICBsb2NhbCBsdmw9JDE7IHNoaWZ0CiAgICBsb2NhbCBtc2c9IiQqIiBjCiAgICBwcmludGYgJyVzIFslc10gJXNcbicgIiQoZGF0ZSAnKyVGICVUJykiICIkbHZsIiAiJG1zZyIgPj4iJExPR19GSUxFIiAyPi9kZXYvbnVsbAogICAgY2FzZSAkbHZsIGluIFdBUk4pIFdBUk5JTkdTPSQoKFdBUk5JTkdTICsgMSkpIDs7IEVSUikgRVJST1JTPSQoKEVSUk9SUyArIDEpKSA7OyBlc2FjCiAgICBpZiAoKCBHVUkgKSkgfHwgW1sgISAtdCAxIF1dOyB0aGVuCiAgICAgICAgcHJpbnRmICdbJXNdICVzXG4nICIkbHZsIiAiJG1zZyIKICAgIGVsc2UKICAgICAgICBjYXNlICRsdmwgaW4gT0spIGM9MzIgOzsgV0FSTikgYz0zMyA7OyBFUlIpIGM9MzEgOzsgU1RFUCkgYz0zNiA7OyBTSU0pIGM9MzUgOzsgKikgYz0wIDs7IGVzYWMKICAgICAgICBwcmludGYgJ1xlWyVzbVslc11cZVswbSAlc1xuJyAiJGMiICIkbHZsIiAiJG1zZyIKICAgIGZpCn0KaW5mbygpIHsgX2xvZyBJTkZPICIkKiI7IH0Kb2soKSAgIHsgX2xvZyBPSyAiJCoiOyB9Cndhcm4oKSB7IF9sb2cgV0FSTiAiJCoiOyB9CmVycigpICB7IF9sb2cgRVJSICIkKiI7IH0Kc3RlcCgpIHsgX2xvZyBTVEVQICIkKiI7IH0Kc2ltKCkgIHsgX2xvZyBTSU0gIiQqIjsgfQpkaWUoKSAgeyBlcnIgIiQqIjsgZXhpdCAxOyB9CgojIGNvbWFuZG8gY2hlIG1vZGlmaWNhIGlsIHNpc3RlbWE6IHNpbXVsYXRvIGNvbiAtLWRyeS1ydW4sIG91dHB1dCBuZWwgbG9nCnJ1bigpIHsKICAgIGlmICgoIERSWV9SVU4gKSk7IHRoZW4gc2ltICIkKHByaW50ZiAnJXEgJyAiJEAiKSI7IHJldHVybiAwOyBmaQogICAgbG9jYWwgb3V0IHJjCiAgICBvdXQ9JCgiJEAiIDI+JjEpOyByYz0kPwogICAgW1sgLW4gJG91dCBdXSAmJiBwcmludGYgJyVzXG4nICIkb3V0IiA+PiIkTE9HX0ZJTEUiIDI+L2Rldi9udWxsCiAgICBpZiAoKCByYyAhPSAwICkpOyB0aGVuCiAgICAgICAgZXJyICJDb21hbmRvIGZhbGxpdG8gKGNvZGljZSAkcmMpOiAkKHByaW50ZiAnJXEgJyAiJEAiKSIKICAgICAgICBbWyAtbiAkb3V0IF1dICYmIHByaW50ZiAnJXNcbicgIiRvdXQiIHwgaGVhZCAtbiA0IHwgd2hpbGUgSUZTPSByZWFkIC1yIGw7IGRvIF9sb2cgRVJSICIgICRsIjsgZG9uZQogICAgZmkKICAgIHJldHVybiAkcmMKfQoKIyBjb21lIHJ1biwgbWEgdW4gZmFsbGltZW50byBlJyBzb2xvIGluZm9ybWF0aXZvICh1bml0YScgYXNzZW50aSwgcmVjb3JkIGdpYScgcmltb3NzaS4uLikKcnVuX3F1aWV0KCkgewogICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBzaW0gIiQocHJpbnRmICclcSAnICIkQCIpIjsgcmV0dXJuIDA7IGZpCiAgICBsb2NhbCBvdXQgcmMKICAgIG91dD0kKCIkQCIgMj4mMSk7IHJjPSQ/CiAgICBbWyAtbiAkb3V0IF1dICYmIHByaW50ZiAnJXNcbicgIiRvdXQiID4+IiRMT0dfRklMRSIgMj4vZGV2L251bGwKICAgIHJldHVybiAkcmMKfQoKIyBjb21lIHJ1biwgbWEgbmVsIGxvZyBpbCBjb21hbmRvIGUnIG1hc2NoZXJhdG8gKGNvbnRpZW5lIHNlZ3JldGkpCnJ1bl9zZWNyZXQoKSB7CiAgICBsb2NhbCBsYWJlbD0kMTsgc2hpZnQKICAgIGlmICgoIERSWV9SVU4gKSk7IHRoZW4gc2ltICIkbGFiZWwiOyByZXR1cm4gMDsgZmkKICAgIGxvY2FsIG91dCByYwogICAgb3V0PSQoIiRAIiAyPiYxKTsgcmM9JD8KICAgICgoIHJjICE9IDAgKSkgJiYgZXJyICJDb21hbmRvIGZhbGxpdG8gKGNvZGljZSAkcmMpOiAkbGFiZWwiCiAgICByZXR1cm4gJHJjCn0KCiMgbW9zdHJhIGwnb3V0cHV0IGRpIHVuIGNvbWFuZG8gZGkgc29sYSBsZXR0dXJhCnNob3coKSB7CiAgICBsb2NhbCBsCiAgICAiJEAiIDI+JjEgfCB3aGlsZSBJRlM9IHJlYWQgLXIgbDsgZG8gX2xvZyBJTkZPICIgICRsIjsgZG9uZQp9CgpwYXVzZSgpIHsgKCggSU5URVJBQ1RJVkUgKSkgJiYgeyBlY2hvOyByZWFkIC1yIC1wICJQcmVtaSBJbnZpbyBwZXIgY29udGludWFyZS4uLiIgXzsgfTsgcmV0dXJuIDA7IH0KCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSB1dGlsaXRhJwppc195ZXMoKSB7IFtbICR7MSwsfSA9fiBeKHllc3x5fHNpfHN8dHJ1ZXwxfG9uKSQgXV07IH0KaXNfbm8oKSAgeyBbWyAkezEsLH0gPX4gXihub3xufGZhbHNlfDB8b2ZmKSQgXV07IH0KdHJpbSgpICAgeyBsb2NhbCBzPSQxOyBzPSR7cyMiJHtzJSVbIVs6c3BhY2U6XV0qfSJ9OyBzPSR7cyUiJHtzIyMqWyFbOnNwYWNlOl1dfSJ9OyBwcmludGYgJyVzJyAiJHMiOyB9Cm5vcm1fbGlzdCgpIHsgbG9jYWwgcz0kezEvL1ssO10vIH07IHM9JCh0cmltICIkcyIpOyBwcmludGYgJyVzJyAiJHMiIHwgdHIgLXMgJyAnOyB9CmhzaXplKCkgeyBbWyAkMSA9fiBeWzAtOV0rJCBdXSAmJiBudW1mbXQgLS10bz1pZWMgLS1zdWZmaXg9QiAiJDEiIDI+L2Rldi9udWxsIHx8IHByaW50ZiAnJXMnICIkezE6LS19IjsgfQoKdmFsaWRfbmFtZSgpIHsgW1sgJDEgPX4gXltBLVphLXowLTldW0EtWmEtejAtOS5fLV17MCwzMX0kIF1dOyB9CnZhbGlkX3VzZXIoKSB7IFtbICQxID1+IF5bYS16X11bYS16MC05Xy1dezAsMzF9JCBdXTsgfQp2YWxpZF9wYXRoKCkgeyBbWyAkMSA9fiBeL1tBLVphLXowLTkvLl8tXSskICYmICQxICE9ICouLiogJiYgJDEgIT0gLyAmJiAkMSAhPSAqLyBdXTsgfQp2YWxpZF9ob3N0KCkgeyBbWyAkMSA9fiBeW0EtWmEtejAtOS46Xy1dKyQgXV07IH0KdmFsaWRfaXFuKCkgIHsgW1sgJDEgPX4gXihpcW5cLlswLTldezR9LVswLTldezJ9XC58ZXVpXC58bmFhXC4pW1s6Z3JhcGg6XV0rJCAmJiAkMSAhPSAqXHwqIF1dOyB9CgpnZW5fcGFzc3dvcmQoKSB7IGxvY2FsIHA7IHA9JChMQ19BTEw9QyB0ciAtZGMgJ0EtWmEtejAtOScgPC9kZXYvdXJhbmRvbSAyPi9kZXYvbnVsbCB8IGhlYWQgLWMgMjApOyBwcmludGYgJyVzJyAiJHAiOyB9CgpiYWNrdXBfZmlsZSgpIHsKICAgIFtbIC1mICQxIF1dIHx8IHJldHVybiAwCiAgICAoKCBEUllfUlVOICkpICYmIHJldHVybiAwCiAgICBsb2NhbCBiOyBiPSIkMS5iYWstJChkYXRlICslWSVtJWQtJUglTSVTKSIKICAgIGNwIC1hICIkMSIgIiRiIiAmJiBpbmZvICJCYWNrdXA6ICRiIgp9CgojIHdyaXRlX2ZpbGUgPHBlcmNvcnNvPiA8bW9kbyBzZSBudW92bz4gPGNvbnRlbnV0bz46IGlkZW1wb3RlbnRlLCBiYWNrdXAsIHNjcml0dHVyYSBhdG9taWNhCndyaXRlX2ZpbGUoKSB7CiAgICBsb2NhbCBwYXRoPSQxIG1vZGU9JDIgY29udGVudD0kMyBjdXIgdG1wCiAgICBpZiBbWyAtZiAkcGF0aCBdXTsgdGhlbgogICAgICAgIGN1cj0kKGNhdCAiJHBhdGgiIDI+L2Rldi9udWxsKQogICAgICAgIFtbICRjdXIgPT0gIiRjb250ZW50IiBdXSAmJiB7IGluZm8gIiRwYXRoIGdpYScgY29ycmV0dG8iOyByZXR1cm4gMDsgfQogICAgICAgIG1vZGU9JChzdGF0IC1jICVhICIkcGF0aCIgMj4vZGV2L251bGwgfHwgZWNobyAiJG1vZGUiKQogICAgZmkKICAgIGlmICgoIERSWV9SVU4gKSk7IHRoZW4KICAgICAgICBzaW0gIlNjcml2ZXJlaSAkcGF0aDoiCiAgICAgICAgcHJpbnRmICclc1xuJyAiJGNvbnRlbnQiIHwgd2hpbGUgSUZTPSByZWFkIC1yIGw7IGRvIF9sb2cgU0lNICIgICAgJGwiOyBkb25lCiAgICAgICAgcmV0dXJuIDAKICAgIGZpCiAgICBta2RpciAtcCAiJChkaXJuYW1lICIkcGF0aCIpIiB8fCByZXR1cm4gMQogICAgYmFja3VwX2ZpbGUgIiRwYXRoIgogICAgdG1wPSQobWt0ZW1wICIkcGF0aC5YWFhYWFgiKSB8fCByZXR1cm4gMQogICAgaWYgcHJpbnRmICclc1xuJyAiJGNvbnRlbnQiID4iJHRtcCIgJiYgY2htb2QgIiRtb2RlIiAiJHRtcCIgJiYgbXYgLWYgIiR0bXAiICIkcGF0aCI7IHRoZW4KICAgICAgICBvayAiU2NyaXR0byAkcGF0aCIKICAgIGVsc2UKICAgICAgICBybSAtZiAiJHRtcCI7IGVyciAiU2NyaXR0dXJhIGRpICRwYXRoIG5vbiByaXVzY2l0YSI7IHJldHVybiAxCiAgICBmaQp9Cgpsb2FkX2NvbmZpZygpIHsKICAgIGxvY2FsIGY9JDEgbGluZSBrZXkgdmFsIG49MAogICAgW1sgJGYgPT0gLSBdXSAmJiBmPS9kZXYvc3RkaW4KICAgIFtbIC1yICRmIF1dIHx8IGRpZSAiRmlsZSBkaSBjb25maWd1cmF6aW9uZSBub24gbGVnZ2liaWxlOiAkMSIKICAgIHdoaWxlIElGUz0gcmVhZCAtciBsaW5lIHx8IFtbIC1uICRsaW5lIF1dOyBkbwogICAgICAgIGxpbmU9JHtsaW5lJSQnXHInfQogICAgICAgIFtbICRsaW5lID1+IF5bWzpzcGFjZTpdXSooI3wkKSBdXSAmJiBjb250aW51ZQogICAgICAgIGlmIFtbICRsaW5lID1+IF5bWzpzcGFjZTpdXSooW0EtWl9dKylbWzpzcGFjZTpdXSo9KC4qKSQgXV07IHRoZW4KICAgICAgICAgICAga2V5PSR7QkFTSF9SRU1BVENIWzFdfQogICAgICAgICAgICB2YWw9JCh0cmltICIke0JBU0hfUkVNQVRDSFsyXX0iKQogICAgICAgICAgICBpZiBbWyAkdmFsID1+IF5cIiguKilcIiQgfHwgJHZhbCA9fiBeXCcoLiopXCckIF1dOyB0aGVuIHZhbD0ke0JBU0hfUkVNQVRDSFsxXX07IGZpCiAgICAgICAgICAgIGlmIFtbICIgJHtDT05GSUdfS0VZUy8vJCdcbicvIH0gIiA9PSAqIiAka2V5ICIqIF1dOyB0aGVuCiAgICAgICAgICAgICAgICBwcmludGYgLXYgIkNGR18ka2V5IiAnJXMnICIkdmFsIjsgbj0kKChuICsgMSkpCiAgICAgICAgICAgIGVsc2UKICAgICAgICAgICAgICAgIHdhcm4gIkNoaWF2ZSBkaSBjb25maWd1cmF6aW9uZSBzY29ub3NjaXV0YSBpZ25vcmF0YTogJGtleSIKICAgICAgICAgICAgZmkKICAgICAgICBlbHNlCiAgICAgICAgICAgIHdhcm4gIlJpZ2EgZGkgY29uZmlndXJhemlvbmUgaWdub3JhdGE6ICRsaW5lIgogICAgICAgIGZpCiAgICBkb25lIDwiJGYiCiAgICBpbmZvICJDb25maWd1cmF6aW9uZSBjYXJpY2F0YSAoJG4gdmFsb3JpKSIKfQoKc2F2ZV9jb25maWcoKSB7CiAgICAoKCBEUllfUlVOICkpICYmIHJldHVybiAwCiAgICBsb2NhbCBrIHYgb3V0CiAgICBvdXQ9IiMgdnJlcG8tc2V0dXAgJFZFUlNJT04gLSBjb25maWd1cmF6aW9uZSBzYWx2YXRhIGlsICQoZGF0ZSAnKyVGICVUJykgKHNlbnphIHBhc3N3b3JkKSIKICAgIGZvciBrIGluICRDT05GSUdfS0VZUzsgZG8KICAgICAgICBbWyAkU0VDUkVUX0tFWVMgPT0gKiIgJGsgIiogXV0gJiYgY29udGludWUKICAgICAgICB2PSJDRkdfJGsiOyBvdXQrPSQnXG4nIiRrPVwiJHshdn1cIiIKICAgIGRvbmUKICAgIG1rZGlyIC1wICIkU1RBVEVfRElSIiAmJiBwcmludGYgJyVzXG4nICIkb3V0IiA+IiRTQVZFRF9DT05GIiAmJiBjaG1vZCA2MDAgIiRTQVZFRF9DT05GIiAmJiBpbmZvICJDb25maWd1cmF6aW9uZSBzYWx2YXRhIGluICRTQVZFRF9DT05GIgp9Cgp2YWxpZGF0ZV9jb25maWcoKSB7CiAgICBsb2NhbCBiYWQ9MCBwCiAgICBbWyAteiAkQ0ZHX0lOSVRJQVRPUl9OQU1FIF1dIHx8IHZhbGlkX2lxbiAiJENGR19JTklUSUFUT1JfTkFNRSIgfHwgeyBlcnIgIklOSVRJQVRPUl9OQU1FIG5vbiB2YWxpZG86ICRDRkdfSU5JVElBVE9SX05BTUUiOyBiYWQ9MTsgfQogICAgZm9yIHAgaW4gJChub3JtX2xpc3QgIiRDRkdfSVNDU0lfUE9SVEFMUyIpOyBkbyB2YWxpZF9ob3N0ICIkcCIgfHwgeyBlcnIgIlBvcnRhbGUgaVNDU0kgbm9uIHZhbGlkbzogJHAiOyBiYWQ9MTsgfTsgZG9uZQogICAgW1sgJENGR19JU0NTSV9QT1JUID1+IF5bMC05XXsxLDV9JCBdXSB8fCB7IGVyciAiSVNDU0lfUE9SVCBub24gdmFsaWRvIjsgYmFkPTE7IH0KICAgIHZhbGlkX3VzZXIgIiRDRkdfVkVFQU1fVVNFUiIgfHwgeyBlcnIgIlZFRUFNX1VTRVIgbm9uIHZhbGlkbzogJENGR19WRUVBTV9VU0VSIjsgYmFkPTE7IH0KICAgIHZhbGlkX3BhdGggIiRDRkdfTU9VTlRfQkFTRSIgfHwgeyBlcnIgIk1PVU5UX0JBU0Ugbm9uIHZhbGlkbzogJENGR19NT1VOVF9CQVNFIjsgYmFkPTE7IH0KICAgIFtbICRDRkdfTFVOX1BSRUZJWCA9fiBeW0EtWmEtejAtOV1bQS1aYS16MC05Ll8tXXswLDI4fSQgXV0gfHwgeyBlcnIgIkxVTl9QUkVGSVggbm9uIHZhbGlkbyI7IGJhZD0xOyB9CiAgICBbWyAkQ0ZHX01VTFRJUEFUSCA9fiBeKGF1dG98eWVzfG5vfHNpKSQgXV0gfHwgeyBlcnIgIk1VTFRJUEFUSCBkZXZlIGVzc2VyZSBhdXRvLCB5ZXMgbyBubyI7IGJhZD0xOyB9CiAgICBbWyAkQ0ZHX01VTFRJUEFUSF9QUk9GSUxFID1+IF4ocW5hcHxnZW5lcmljKSQgXV0gfHwgeyBlcnIgIk1VTFRJUEFUSF9QUk9GSUxFIGRldmUgZXNzZXJlIHFuYXAgbyBnZW5lcmljIjsgYmFkPTE7IH0KICAgIFtbIC16ICRDRkdfVElNRVpPTkUgfHwgJENGR19USU1FWk9ORSA9fiBeW0EtWmEtejAtOS9fKy1dKyQgXV0gfHwgeyBlcnIgIlRJTUVaT05FIG5vbiB2YWxpZG8iOyBiYWQ9MTsgfQogICAgZm9yIHAgaW4gJChub3JtX2xpc3QgIiRDRkdfTlRQX1NFUlZFUlMiKTsgZG8gdmFsaWRfaG9zdCAiJHAiIHx8IHsgZXJyICJTZXJ2ZXIgTlRQIG5vbiB2YWxpZG86ICRwIjsgYmFkPTE7IH07IGRvbmUKICAgIFtbIC16ICRDRkdfQURNSU5fVVNFUiBdXSB8fCB2YWxpZF91c2VyICIkQ0ZHX0FETUlOX1VTRVIiIHx8IHsgZXJyICJBRE1JTl9VU0VSIG5vbiB2YWxpZG8iOyBiYWQ9MTsgfQogICAgW1sgJENGR19DSEFQX1VTRVIkQ0ZHX0NIQVBfUEFTU1dPUkQgIT0gKiQnXG4nKiBdXSB8fCBiYWQ9MQogICAgcmV0dXJuICRiYWQKfQoKcmVxdWlyZV9yb290KCkgeyBbWyAkRVVJRCAtZXEgMCBdXSB8fCBkaWUgIlNlcnZvbm8gaSBwcml2aWxlZ2kgZGkgcm9vdDogc3VkbyAkMCAkKiI7IH0KCm9zX2luZm8oKSB7ICguIC9ldGMvb3MtcmVsZWFzZSAyPi9kZXYvbnVsbDsgcHJpbnRmICclc3wlc3wlcycgIiR7SUQ6LT99IiAiJHtWRVJTSU9OX0lEOi0/fSIgIiR7UFJFVFRZX05BTUU6LT99Iik7IH0KCmNoZWNrX29zKCkgewogICAgbG9jYWwgaWQgdmVyIHByZXR0eQogICAgSUZTPSd8JyByZWFkIC1yIGlkIHZlciBwcmV0dHkgPDw8IiQob3NfaW5mbykiCiAgICBpZiBbWyAkaWQgIT0gdWJ1bnR1IF1dOyB0aGVuIHdhcm4gIlNpc3RlbWEgJHByZXR0eTogbG8gc2NyaXB0IGUnIHBlbnNhdG8gcGVyIFVidW50dSIKICAgIGVsc2UgY2FzZSAkdmVyIGluIDIwLjA0fDIyLjA0fDI0LjA0fDI2LjA0KSBpbmZvICJTaXN0ZW1hOiAkcHJldHR5IiA7OyAqKSB3YXJuICJTaXN0ZW1hICRwcmV0dHk6IHZlcnNpb25lIG5vbiB2ZXJpZmljYXRhLCBjb250cm9sbGFyZSBsYSBjb21wYXRpYmlsaXRhJyBWZWVhbSIgOzsgZXNhYwogICAgZmkKfQoKcGtnX2luc3RhbGxlZCgpIHsgZHBrZy1xdWVyeSAtVyAtZj0nJHtTdGF0dXN9JyAiJDEiIDI+L2Rldi9udWxsIHwgZ3JlcCAtcSAnaW5zdGFsbCBvayBpbnN0YWxsZWQnOyB9CgplbnN1cmVfcGtncygpIHsKICAgIGxvY2FsIG1pc3Npbmc9KCkgcAogICAgZm9yIHAgaW4gIiRAIjsgZG8gcGtnX2luc3RhbGxlZCAiJHAiIHx8IG1pc3NpbmcrPSgiJHAiKTsgZG9uZQogICAgaWYgKCggJHsjbWlzc2luZ1tAXX0gPT0gMCApKTsgdGhlbiBpbmZvICJQYWNjaGV0dGkgcHJlc2VudGk6ICQqIjsgcmV0dXJuIDA7IGZpCiAgICBpbmZvICJJbnN0YWxsbzogJHttaXNzaW5nWypdfSIKICAgIHJ1biBlbnYgREVCSUFOX0ZST05URU5EPW5vbmludGVyYWN0aXZlIGFwdC1nZXQgdXBkYXRlIC1xIHx8IHdhcm4gImFwdC1nZXQgdXBkYXRlIG5vbiByaXVzY2l0bzogcHJvdm8gY29tdW5xdWUgbCdpbnN0YWxsYXppb25lIgogICAgcnVuIGVudiBERUJJQU5fRlJPTlRFTkQ9bm9uaW50ZXJhY3RpdmUgYXB0LWdldCBpbnN0YWxsIC15IC1xICIke21pc3NpbmdbQF19IiB8fCB7IGVyciAiSW5zdGFsbGF6aW9uZSBkaSAke21pc3NpbmdbKl19IG5vbiByaXVzY2l0YSI7IHJldHVybiAxOyB9CiAgICBvayAiSW5zdGFsbGF0aTogJHttaXNzaW5nWypdfSIKfQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHdoaXB0YWlsCnd0KCkgICAgeyB3aGlwdGFpbCAtLWJhY2t0aXRsZSAiJEJUIiAiJEAiIDM+JjEgMT4mMiAyPiYzOyB9CmFzaygpICAgeyB3dCAtLXRpdGxlICIkMSIgLS1pbnB1dGJveCAiJDIiIDE0IDc4ICIkMyI7IH0KYXNrcHcoKSB7IHd0IC0tdGl0bGUgIiQxIiAtLXBhc3N3b3JkYm94ICIkMiIgMTIgNzg7IH0KeWVzbm8oKSB7IHdoaXB0YWlsIC0tYmFja3RpdGxlICIkQlQiIC0tdGl0bGUgIiQxIiAtLXllc25vICIkMiIgMTggNzg7IH0Kbm95ZXMoKSB7IHdoaXB0YWlsIC0tYmFja3RpdGxlICIkQlQiIC0tdGl0bGUgIiQxIiAtLWRlZmF1bHRubyAtLXllc25vICIkMiIgMTggNzg7IH0KbXNnKCkgICB7IHdoaXB0YWlsIC0tYmFja3RpdGxlICIkQlQiIC0tdGl0bGUgIiQxIiAtLXNjcm9sbHRleHQgLS1tc2dib3ggIiQyIiAyMiA3ODsgfQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIHN0YXRvCnN0YXRlX2xvb2t1cCgpICAgICAgeyBbWyAtZiAkU1RBVEVfUkVQT1MgXV0gJiYgYXdrIC1GJ3wnIC12IGM9IiQxIiAtdiB2PSIkMiIgJyRjPT12e3ByaW50OyBleGl0fScgIiRTVEFURV9SRVBPUyI7IHJldHVybiAwOyB9CnN0YXRlX2FkZF9yZXBvKCkgewogICAgbWtkaXIgLXAgIiRTVEFURV9ESVIiCiAgICBsb2NhbCB0bXA7IHRtcD0kKG1rdGVtcCkKICAgIFtbIC1mICRTVEFURV9SRVBPUyBdXSAmJiBhd2sgLUYnfCcgLXYgbj0iJDEiICckMSE9bicgIiRTVEFURV9SRVBPUyIgPiIkdG1wIgogICAgcHJpbnRmICclc3wlc3wlc3wlc1xuJyAiJDEiICIkMiIgIiQzIiAiJDQiID4+IiR0bXAiCiAgICBtdiAtZiAiJHRtcCIgIiRTVEFURV9SRVBPUyIgJiYgY2htb2QgNjQ0ICIkU1RBVEVfUkVQT1MiCn0KcmVwb19tb3VudHMoKSB7IFtbIC1mICRTVEFURV9SRVBPUyBdXSAmJiBhd2sgLUYnfCcgJ3twcmludCAkNH0nICIkU1RBVEVfUkVQT1MiOyByZXR1cm4gMDsgfQoKIyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIGRpc2NoaQojIGRpc2NoaSBjaGUgb3NwaXRhbm8gLywgL2Jvb3QsIC9ib290L2VmaSBlIGxvIHN3YXA6IG1haSBwcm9wb3N0aQpzeXN0ZW1fZGlza3MoKSB7CiAgICBsb2NhbCBzcmMgbQogICAgewogICAgICAgIGZvciBtIGluIC8gL2Jvb3QgL2Jvb3QvZWZpOyBkbyBmaW5kbW50IC1ubyBTT1VSQ0UgIiRtIiAyPi9kZXYvbnVsbDsgZG9uZQogICAgICAgIHN3YXBvbiAtLW5vaGVhZGluZ3MgLS1zaG93PU5BTUUgMj4vZGV2L251bGwKICAgIH0gfCBzZWQgJ3MvXFsuKi8vJyB8IHNvcnQgLXUgfCB3aGlsZSByZWFkIC1yIHNyYzsgZG8KICAgICAgICBbWyAtYiAkc3JjIF1dIHx8IGNvbnRpbnVlCiAgICAgICAgbHNibGsgLW5zbHBvIE5BTUUsVFlQRSAiJHNyYyIgMj4vZGV2L251bGwgfCBhd2sgJyQyPT0iZGlzayJ8fCQyPT0ibXBhdGgie3ByaW50ICQxfScKICAgIGRvbmUgfCBzb3J0IC11Cn0KCmRldl93d2lkKCkgewogICAgbG9jYWwgZD0kMSBrIHUKICAgIGs9JChiYXNlbmFtZSAiJChyZWFkbGluayAtZiAiJGQiKSIpCiAgICBpZiBbWyAtciAvc3lzL2Jsb2NrLyRrL2RtL3V1aWQgXV07IHRoZW4KICAgICAgICB1PSQoPCIvc3lzL2Jsb2NrLyRrL2RtL3V1aWQiKQogICAgICAgIFtbICR1ID09IG1wYXRoLSogXV0gJiYgeyBwcmludGYgJyVzJyAiJHt1I21wYXRoLX0iOyByZXR1cm47IH0KICAgIGZpCiAgICB1ZGV2YWRtIGluZm8gLS1xdWVyeT1wcm9wZXJ0eSAtLW5hbWU9IiRkIiAyPi9kZXYvbnVsbCB8IHNlZCAtbiAncy9eSURfU0VSSUFMPS8vcCcgfCBoZWFkIC1uIDEKfQoKIyBudW1lcm8gZGkgTFVOIHZpc3RlIHN1IHBpdScgcGVyY29yc2kgKHN0ZXNzbyBXV0lEIHN1IHBpdScgZGlzY2hpIHNkKQpkZXRlY3RfbXVsdGlfcGF0aHMoKSB7CiAgICBsb2NhbCBkCiAgICBsc2JsayAtZG5wbyBOQU1FLFRZUEUgMj4vZGV2L251bGwgfCBhd2sgJyQyPT0iZGlzayJ7cHJpbnQgJDF9JyB8IHdoaWxlIHJlYWQgLXIgZDsgZG8gZGV2X3d3aWQgIiRkIjsgZWNobzsgZG9uZSBcCiAgICAgICAgfCBhd2sgJ05GJyB8IHNvcnQgfCB1bmlxIC1kIHwgd2MgLWwKfQoKIyBMVU5TW106IGRldnxrbmFtZXx3d2lkfGJ5dGV8bW9kZWxsb3xwZXJjb3JzaXx0cmFzcG9ydG98c3RhdG98ZnN0eXBlfG1vdW50fG5vbWUKYWRkX2x1bigpIHsKICAgIGxvY2FsIGRldj0kMSBrPSQyIHd3aWQ9JDMgcGF0aHM9JDQgdHJhbj0kNSBtb2RlbD0kNgogICAgbG9jYWwgc2l6ZSBmc3R5cGUgbW50IGNoaWxkcmVuIHN0YXRlPSJsaWJlcm8iIG5hbWU9Ii0iIHJlYwogICAgc2l6ZT0kKGxzYmxrIC1kbmJvIFNJWkUgIiRkZXYiIDI+L2Rldi9udWxsIHwgeGFyZ3MpCiAgICBbWyAteiAkbW9kZWwgXV0gJiYgbW9kZWw9JChsc2JsayAtZG5vIFZFTkRPUixNT0RFTCAiJGRldiIgMj4vZGV2L251bGwgfCB4YXJncykKICAgIGZzdHlwZT0kKGxzYmxrIC1kbm8gRlNUWVBFICIkZGV2IiAyPi9kZXYvbnVsbCB8IHhhcmdzKQogICAgW1sgLXogJGZzdHlwZSBdXSAmJiBmc3R5cGU9JChibGtpZCAtcCAtcyBUWVBFIC1vIHZhbHVlICIkZGV2IiAyPi9kZXYvbnVsbCB8fCBibGtpZCAtcCAtcyBQVFRZUEUgLW8gdmFsdWUgIiRkZXYiIDI+L2Rldi9udWxsKQogICAgY2hpbGRyZW49JChsc2JsayAtbmxwbyBOQU1FICIkZGV2IiAyPi9kZXYvbnVsbCB8IHRhaWwgLW4gKzIgfCB3YyAtbCkKICAgIG1udD0kKGxzYmxrIC1ubHBvIE1PVU5UUE9JTlQgIiRkZXYiIDI+L2Rldi9udWxsIHwgYXdrICdORicgfCBoZWFkIC1uIDEpCiAgICByZWM9IiIKICAgIFtbIC1uICR3d2lkIF1dICYmIHJlYz0kKHN0YXRlX2xvb2t1cCAyICIkd3dpZCIpCiAgICBpZiBbWyAteiAkcmVjIF1dOyB0aGVuICMgYW5jaGUgcGVyIFVVSUQgZGVsIGZpbGVzeXN0ZW0gKFdXSUQgY2FtYmlhdG8gbyBhc3NlbnRlKQogICAgICAgIGxvY2FsIGZ1IHBkCiAgICAgICAgZm9yIHBkIGluICQobHNibGsgLW5scG8gTkFNRSAiJGRldiIgMj4vZGV2L251bGwpOyBkbwogICAgICAgICAgICBmdT0kKGJsa2lkIC1zIFVVSUQgLW8gdmFsdWUgIiRwZCIgMj4vZGV2L251bGwpCiAgICAgICAgICAgIFtbIC1uICRmdSBdXSAmJiByZWM9JChzdGF0ZV9sb29rdXAgMyAiJGZ1IikgJiYgW1sgLW4gJHJlYyBdXSAmJiBicmVhawogICAgICAgIGRvbmUKICAgIGZpCiAgICBpZiBbWyAtbiAkcmVjIF1dOyB0aGVuCiAgICAgICAgc3RhdGU9ImNvbmZpZ3VyYXRvIjsgbmFtZT0ke3JlYyUlfCp9CiAgICBlbGlmIFtbIC1uICRmc3R5cGUgfHwgJGNoaWxkcmVuIC1ndCAwIHx8IC1uICRtbnQgXV07IHRoZW4KICAgICAgICBzdGF0ZT0iaW5fdXNvIgogICAgZWxpZiBjb21wZ2VuIC1HICIvc3lzL2Jsb2NrLyRrL2hvbGRlcnMvKiIgPi9kZXYvbnVsbDsgdGhlbgogICAgICAgIHN0YXRlPSJpbl91c28iCiAgICBlbGlmIFtbIC1uICQoYmxraWQgLXAgLW8gZXhwb3J0ICIkZGV2IiAyPi9kZXYvbnVsbCkgXV07IHRoZW4KICAgICAgICBzdGF0ZT0iaW5fdXNvIgogICAgZmkKICAgIFtbIC16ICRmc3R5cGUgJiYgJGNoaWxkcmVuIC1ndCAwIF1dICYmIGZzdHlwZT0kKGxzYmxrIC1ubHBvIEZTVFlQRSAiJGRldiIgMj4vZGV2L251bGwgfCBhd2sgJ05GJyB8IGhlYWQgLW4gMSkKICAgIG1vZGVsPSR7bW9kZWwvL3wvIH0KICAgIExVTlMrPSgiJGRldnwka3wke3d3aWQ6LS19fCR7c2l6ZTotMH18JHttb2RlbDotLX18JHBhdGhzfCR7dHJhbjotLX18JHN0YXRlfCR7ZnN0eXBlOi0tfXwke21udDotLX18JG5hbWUiKQp9CgpzY2FuX2x1bnMoKSB7CiAgICBMVU5TPSgpCiAgICBsb2NhbCBzeXNkIGQgayB1IG5hbWUgZGV2IHMgbiB0cmFuIG1vZGVsCiAgICBzeXNkPSIgJChzeXN0ZW1fZGlza3MgfCB0ciAnXG4nICcgJykgIgogICAgZGVjbGFyZSAtQSBzbGF2ZT0oKQogICAgZm9yIGQgaW4gL3N5cy9ibG9jay9kbS0qOyBkbwogICAgICAgIFtbIC1yICRkL2RtL3V1aWQgXV0gfHwgY29udGludWUKICAgICAgICB1PSQoPCIkZC9kbS91dWlkIik7IFtbICR1ID09IG1wYXRoLSogXV0gfHwgY29udGludWUKICAgICAgICBrPSR7ZCMjKi99OyBuYW1lPSQoPCIkZC9kbS9uYW1lIik7IGRldj0vZGV2L21hcHBlci8kbmFtZQogICAgICAgIG49MDsgdHJhbj0iIjsgbW9kZWw9IiIKICAgICAgICBmb3IgcyBpbiAiJGQiL3NsYXZlcy8qOyBkbwogICAgICAgICAgICBbWyAtZSAkcyBdXSB8fCBjb250aW51ZQogICAgICAgICAgICBzbGF2ZVske3MjIyovfV09MTsgbj0kKChuICsgMSkpCiAgICAgICAgICAgIFtbIC16ICR0cmFuIF1dICYmIHRyYW49JChsc2JsayAtZG5vIFRSQU4gIi9kZXYvJHtzIyMqL30iIDI+L2Rldi9udWxsIHwgeGFyZ3MpCiAgICAgICAgICAgIFtbIC16ICRtb2RlbCBdXSAmJiBtb2RlbD0kKGxzYmxrIC1kbm8gVkVORE9SLE1PREVMICIvZGV2LyR7cyMjKi99IiAyPi9kZXYvbnVsbCB8IHhhcmdzKQogICAgICAgIGRvbmUKICAgICAgICBbWyAkc3lzZCA9PSAqIiAkZGV2ICIqIHx8ICRzeXNkID09ICoiIC9kZXYvJGsgIiogXV0gJiYgY29udGludWUKICAgICAgICBhZGRfbHVuICIkZGV2IiAiJGsiICIke3UjbXBhdGgtfSIgIiRuIiAiJHt0cmFuOi1tcGF0aH0iICIkbW9kZWwiCiAgICBkb25lCiAgICB3aGlsZSByZWFkIC1yIGRldiB0eXBlIHRyYW47IGRvCiAgICAgICAgIyBWUkVQT19URVNUX0xPT1A9MTogaW5jbHVkZSBpIGxvb3AgZGV2aWNlIChzb2xvIHBlciBpIHRlc3QpCiAgICAgICAgW1sgJHR5cGUgPT0gZGlzayB8fCAoICR0eXBlID09IGxvb3AgJiYgJHtWUkVQT19URVNUX0xPT1A6LX0gPT0gMSApIF1dIHx8IGNvbnRpbnVlCiAgICAgICAgaz0ke2RldiMjKi99CiAgICAgICAgW1sgLW4gJHtzbGF2ZVska106LX0gXV0gJiYgY29udGludWUKICAgICAgICBbWyAkc3lzZCA9PSAqIiAkZGV2ICIqIF1dICYmIGNvbnRpbnVlCiAgICAgICAgY2FzZSAkayBpbiBzcip8ZmQqfHpyYW0qfHJhbSp8bmJkKikgY29udGludWUgOzsgZXNhYwogICAgICAgIGFkZF9sdW4gIiRkZXYiICIkayIgIiQoZGV2X3d3aWQgIiRkZXYiKSIgMSAiJHRyYW4iICIiCiAgICBkb25lIDwgPChsc2JsayAtZG5wbyBOQU1FLFRZUEUsVFJBTiAyPi9kZXYvbnVsbCkKfQoKZmluZF9sdW4oKSB7ICMgcGVyIGRpc3Bvc2l0aXZvLCBrbmFtZSBvIHd3aWQKICAgIGxvY2FsIHE9JDEgcgogICAgZm9yIHIgaW4gIiR7TFVOU1tAXX0iOyBkbwogICAgICAgIElGUz0nfCcgcmVhZCAtciBkIGsgdyBfIDw8PCIkciIKICAgICAgICBbWyAkcSA9PSAiJGQiIHx8ICRxID09ICIkayIgfHwgJHEgPT0gIi9kZXYvJGsiIHx8ICRxID09ICIkdyIgXV0gJiYgeyBwcmludGYgJyVzJyAiJHIiOyByZXR1cm4gMDsgfQogICAgZG9uZQogICAgcmV0dXJuIDEKfQoKbHVuX2xhYmVsKCkgeyAjIHRlc3RvIGxlZ2dpYmlsZSBwZXIgZWxlbmNoaSBlIGNoZWNrbGlzdAogICAgbG9jYWwgZCBrIHcgc3ogbW8gcCB0IHN0IGZzIG1udCBubQogICAgSUZTPSd8JyByZWFkIC1yIGQgayB3IHN6IG1vIHAgdCBzdCBmcyBtbnQgbm0gPDw8IiQxIgogICAgcHJpbnRmICclLTIycyAlOHMgICVzIHBlcmMuICAlLTZzICVzJyAiJGQiICIkKGhzaXplICIkc3oiKSIgIiRwIiAiJHQiICIke21vOjA6MjB9IgogICAgY2FzZSAkc3QgaW4gaW5fdXNvKSBpZiBbWyAkbW50ICE9IC0gXV07IHRoZW4gcHJpbnRmICcgIFtJTiBVU086IG1vbnRhdG8gc3UgJXNdJyAiJG1udCI7IGVsc2UgcHJpbnRmICcgIFtJTiBVU086ICVzXScgIiRmcyI7IGZpIDs7IGNvbmZpZ3VyYXRvKSBwcmludGYgJyAgW3JlcG8gJXNdJyAiJG5tIiA7OyBlc2FjCn0KCmNvbmZpZ3VyZWRfbmFtZV9mb3IoKSB7ICMgbm9tZSBkYWxsYSBtYXBwYSBMVU5fTkFNRVMgKHd3aWQ9bm9tZSBvIGtuYW1lPW5vbWUpCiAgICBsb2NhbCB3PSQxIGs9JDIgZQogICAgZm9yIGUgaW4gJChub3JtX2xpc3QgIiRDRkdfTFVOX05BTUVTIik7IGRvCiAgICAgICAgW1sgJGUgPT0gKj0qIF1dIHx8IGNvbnRpbnVlCiAgICAgICAgW1sgJHtlJSU9Kn0gPT0gIiR3IiB8fCAke2UlJT0qfSA9PSAiJGsiIHx8ICR7ZSUlPSp9ID09ICIvZGV2LyRrIiBdXSAmJiB7IHByaW50ZiAnJXMnICIke2UjKj19IjsgcmV0dXJuIDA7IH0KICAgIGRvbmUKICAgIHJldHVybiAxCn0KCnN1Z2dlc3RfbmFtZSgpIHsgIyBub21lIGxpYmVybyA8cHJlZmlzc28+Tk4KICAgIGxvY2FsIGk9MSBuCiAgICB3aGlsZSA6OyBkbwogICAgICAgIHByaW50ZiAtdiBuICclcyUwMmQnICIkQ0ZHX0xVTl9QUkVGSVgiICIkaSIKICAgICAgICBpZiBbWyAteiAkKHN0YXRlX2xvb2t1cCAxICIkbiIpICYmICEgLWUgJENGR19NT1VOVF9CQVNFLyRuICYmICIgJHtSRVNFUlZFRF9OQU1FUzotfSAiICE9ICoiICRuICIqIF1dOyB0aGVuIHByaW50ZiAnJXMnICIkbiI7IHJldHVybjsgZmkKICAgICAgICBpPSQoKGkgKyAxKSkKICAgIGRvbmUKfQoKZmluZF9wYXJ0aXRpb24oKSB7CiAgICBsb2NhbCB0PSQxIHAgaQogICAgZm9yIGkgaW4gMSAyIDMgNCA1IDY7IGRvCiAgICAgICAgcD0kKGxzYmxrIC1sbnBvIE5BTUUsVFlQRSAiJHQiIDI+L2Rldi9udWxsIHwgYXdrICckMj09InBhcnQie3ByaW50ICQxOyBleGl0fScpCiAgICAgICAgW1sgLW4gJHAgJiYgLWIgJHAgXV0gJiYgeyBwcmludGYgJyVzJyAiJHAiOyByZXR1cm4gMDsgfQogICAgICAgIGZvciBwIGluICIkdC1wYXJ0MSIgIiR7dH1wMSIgIiR7dH0xIjsgZG8gW1sgLWIgJHAgXV0gJiYgeyBwcmludGYgJyVzJyAiJHAiOyByZXR1cm4gMDsgfTsgZG9uZQogICAgICAgIHNsZWVwIDE7IHVkZXZhZG0gc2V0dGxlIDI+L2Rldi9udWxsCiAgICBkb25lCiAgICByZXR1cm4gMQp9CgojIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gaVNDU0kKaXNjc2lfc2Vzc2lvbnMoKSB7ICMgcG9ydGFsZSBpcW4gcGVyIG9nbmkgc2Vzc2lvbmUgYXR0aXZhCiAgICBpc2NzaWFkbSAtbSBzZXNzaW9uIDI+L2Rldi9udWxsIHwgYXdrICd7cD0kMzsgc3ViKC8sLiovLCIiLHApOyBwcmludCBwLCAkNH0nCn0Kc2Vzc2lvbl9jb3VudCgpIHsgaXNjc2lfc2Vzc2lvbnMgfCBhd2sgJ05GJyB8IHdjIC1sOyB9Cgpwb3J0YWxfaXAoKSB7IGxvY2FsIHA9JHsxJToqfTsgcD0ke3AjW307IHA9JHtwJV19OyBwcmludGYgJyVzJyAiJHAiOyB9Cgp0YXJnZXRfd2FudGVkKCkgewogICAgbG9jYWwgaXFuPSQxIHBhdCBsaXN0CiAgICBsaXN0PSQobm9ybV9saXN0ICIkQ0ZHX0lTQ1NJX1RBUkdFVFMiKQogICAgW1sgLXogJGxpc3QgXV0gJiYgcmV0dXJuIDAKICAgIGZvciBwYXQgaW4gJGxpc3Q7IGRvCiAgICAgICAgIyBzaGVsbGNoZWNrIGRpc2FibGU9U0MyMDUzCiAgICAgICAgW1sgJGlxbiA9PSAkcGF0IF1dICYmIHJldHVybiAwCiAgICBkb25lCiAgICByZXR1cm4gMQp9CnBvcnRhbF93YW50ZWQoKSB7CiAgICBsb2NhbCBpcCBwCiAgICBpc195ZXMgIiRDRkdfT05MWV9MSVNURURfUE9SVEFMUyIgfHwgcmV0dXJuIDAKICAgIGlwPSQocG9ydGFsX2lwICIkMSIpCiAgICBmb3IgcCBpbiAkKG5vcm1fbGlzdCAiJENGR19JU0NTSV9QT1JUQUxTIik7IGRvIFtbICRwID09ICIkaXAiIF1dICYmIHJldHVybiAwOyBkb25lCiAgICByZXR1cm4gMQp9CgojIERJU0NbXTogInBvcnRhbGUgaXFuIiBkYWxsYSBkaXNjb3Zlcnkgc3VpIHBvcnRhbGkgaW5kaWNhdGkKZGlzY292ZXJfdGFyZ2V0cygpIHsKICAgIGxvY2FsIG5vbnBlcnNpc3Q9JDEgcCBvdXQgcmMgbGluZSBwb3J0YWwgaXFuCiAgICBESVNDPSgpCiAgICBmb3IgcCBpbiAkKG5vcm1fbGlzdCAiJENGR19JU0NTSV9QT1JUQUxTIik7IGRvCiAgICAgICAgaWYgW1sgJG5vbnBlcnNpc3QgPT0gMSBdXTsgdGhlbiBvdXQ9JChpc2NzaWFkbSAtbSBkaXNjb3ZlcnkgLXQgc3QgLXAgIiRwOiRDRkdfSVNDU0lfUE9SVCIgLW8gbm9ucGVyc2lzdGVudCAyPiYxKTsgcmM9JD8KICAgICAgICBlbHNlIG91dD0kKGlzY3NpYWRtIC1tIGRpc2NvdmVyeSAtdCBzdCAtcCAiJHA6JENGR19JU0NTSV9QT1JUIiAyPiYxKTsgcmM9JD87IGZpCiAgICAgICAgaWYgKCggcmMgIT0gMCApKTsgdGhlbiB3YXJuICJEaXNjb3Zlcnkgc3UgJHA6JENGR19JU0NTSV9QT1JUIG5vbiByaXVzY2l0YTogJCh0YWlsIC1uIDEgPDw8IiRvdXQiKSI7IGNvbnRpbnVlOyBmaQogICAgICAgIHdoaWxlIHJlYWQgLXIgcG9ydGFsIGlxbjsgZG8KICAgICAgICAgICAgW1sgLW4gJGlxbiBdXSB8fCBjb250aW51ZQogICAgICAgICAgICBwb3J0YWw9JHtwb3J0YWwlJSwqfQogICAgICAgICAgICBbWyAiICR7RElTQ1sqXX0gIiA9PSAqIiAkcG9ydGFsICRpcW4gIiogXV0gfHwgRElTQys9KCIkcG9ydGFsICRpcW4iKQogICAgICAgIGRvbmUgPDw8IiRvdXQiCiAgICBkb25lCn0KCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBtdWx0aXBhdGgKbXBfcHJvZmlsZSgpIHsgW1sgLXMgJFNUQVRFX01QUFJPRklMRSBdXSAmJiBjYXQgIiRTVEFURV9NUFBST0ZJTEUiIHx8IHByaW50ZiAnJXMnICIkQ0ZHX01VTFRJUEFUSF9QUk9GSUxFIjsgfQoKbXVsdGlwYXRoX2NvbmZfY29udGVudCgpIHsKICAgIGxvY2FsIHByb2Y9JHsxOi0kKG1wX3Byb2ZpbGUpfSB3IGEKICAgIHByaW50ZiAnJXMgKHByb2ZpbG8gJXMpOiBsZSBtb2RpZmljaGUgbWFudWFsaSB2ZW5nb25vIHNvdnJhc2NyaXR0ZVxuJyAiJE1QX01BUksiICIkcHJvZiIKICAgIGlmIFtbICRwcm9mID09IHFuYXAgXV07IHRoZW4KICAgICAgICBjYXQgPDwnRU9GJwpkZWZhdWx0cyB7CiAgICB1c2VyX2ZyaWVuZGx5X25hbWVzIHllcwogICAgZmluZF9tdWx0aXBhdGhzIHllcwogICAgcG9sbGluZ19pbnRlcnZhbCAxMAogICAgcGF0aF9zZWxlY3RvciAicm91bmQtcm9iaW4gMCIKICAgIHBhdGhfZ3JvdXBpbmdfcG9saWN5IG11bHRpYnVzCiAgICB1aWRfYXR0cmlidXRlIElEX1NFUklBTAogICAgcHJpbyBhbHVhCiAgICBwYXRoX2NoZWNrZXIgcmVhZHNlY3RvcjAKICAgIHJyX21pbl9pbyAxMDAKICAgIG1heF9mZHMgODE5MgogICAgcnJfd2VpZ2h0IHByaW9yaXRpZXMKICAgIGZhaWxiYWNrIGltbWVkaWF0ZQogICAgbm9fcGF0aF9yZXRyeSBmYWlsCn0KRU9GCiAgICBlbHNlCiAgICAgICAgY2F0IDw8J0VPRicKZGVmYXVsdHMgewogICAgdXNlcl9mcmllbmRseV9uYW1lcyB5ZXMKICAgIGZpbmRfbXVsdGlwYXRocyB5ZXMKfQpFT0YKICAgIGZpCiAgICBpZiBbWyAtcyAkU1RBVEVfQUxJQVNFUyBdXTsgdGhlbgogICAgICAgIGVjaG8gIm11bHRpcGF0aHMgeyIKICAgICAgICB3aGlsZSBJRlM9J3wnIHJlYWQgLXIgdyBhOyBkbwogICAgICAgICAgICBbWyAtbiAkdyAmJiAtbiAkYSBdXSAmJiBwcmludGYgJyAgICBtdWx0aXBhdGgge1xuICAgICAgICB3d2lkICVzXG4gICAgICAgIGFsaWFzICVzXG4gICAgfVxuJyAiJHciICIkYSIKICAgICAgICBkb25lIDwiJFNUQVRFX0FMSUFTRVMiCiAgICAgICAgZWNobyAifSIKICAgIGZpCn0KCm11bHRpcGF0aF9jaGVja19jb25mKCkgewogICAgKCggRFJZX1JVTiApKSAmJiByZXR1cm4gMAogICAgbG9jYWwgdwogICAgdz0kKG11bHRpcGF0aCAtdCAyPiYxID4vZGV2L251bGwgfCBncmVwIC1pRSAnaW52YWxpZHx1bmtub3dufGRlcHJlY2F0fGlnbm9yfGVycm9yJyB8IHNvcnQgLXUpCiAgICBpZiBbWyAtbiAkdyBdXTsgdGhlbgogICAgICAgIHdhcm4gIm11bHRpcGF0aCBzZWduYWxhIHByb2JsZW1pIG5lbGxhIGNvbmZpZ3VyYXppb25lOiIKICAgICAgICB3aGlsZSBJRlM9IHJlYWQgLXIgbDsgZG8gd2FybiAiICAkbCI7IGRvbmUgPDw8IiR3IgogICAgZmkKfQoKc2V0X21wYXRoX2FsaWFzKCkgewogICAgbG9jYWwgd3dpZD0kMSBhbGlhcz0kMiBpIHRtcAogICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBzaW0gIkFsaWFzIG11bHRpcGF0aCAkYWxpYXMgcGVyIFdXSUQgJHd3aWQgKG11bHRpcGF0aHMgaW4gL2V0Yy9tdWx0aXBhdGguY29uZikiOyByZXR1cm4gMDsgZmkKICAgIG1rZGlyIC1wICIkU1RBVEVfRElSIjsgdG1wPSQobWt0ZW1wKQogICAgW1sgLWYgJFNUQVRFX0FMSUFTRVMgXV0gJiYgYXdrIC1GJ3wnIC12IHc9IiR3d2lkIiAtdiBhPSIkYWxpYXMiICckMSE9dyAmJiAkMiE9YScgIiRTVEFURV9BTElBU0VTIiA+IiR0bXAiCiAgICBwcmludGYgJyVzfCVzXG4nICIkd3dpZCIgIiRhbGlhcyIgPj4iJHRtcCI7IG12IC1mICIkdG1wIiAiJFNUQVRFX0FMSUFTRVMiCiAgICB3cml0ZV9maWxlIC9ldGMvbXVsdGlwYXRoLmNvbmYgMDY0NCAiJChtdWx0aXBhdGhfY29uZl9jb250ZW50KSIgfHwgcmV0dXJuIDEKICAgIHJ1bl9xdWlldCBtdWx0aXBhdGhkIHJlY29uZmlndXJlIHx8IHJ1biBzeXN0ZW1jdGwgcmVsb2FkIG11bHRpcGF0aGQgfHwgcmV0dXJuIDEKICAgIGZvciBpIGluICQoc2VxIDEgMTUpOyBkbyBbWyAtYiAvZGV2L21hcHBlci8kYWxpYXMgXV0gJiYgeyBvayAiQWxpYXMgbXVsdGlwYXRoIGF0dGl2bzogL2Rldi9tYXBwZXIvJGFsaWFzIjsgcmV0dXJuIDA7IH07IHNsZWVwIDE7IGRvbmUKICAgIGVyciAiQWxpYXMgL2Rldi9tYXBwZXIvJGFsaWFzIG5vbiBjb21wYXJzbyI7IHJldHVybiAxCn0KCiMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSB1dGVudGUgZSBwZXJtZXNzaQp1c2VyX2hhc19wYXNzd29yZCgpIHsgW1sgJChwYXNzd2QgLVMgIiQxIiAyPi9kZXYvbnVsbCB8IGF3ayAne3ByaW50ICQyfScpID09IFAgXV07IH0KdXNlcl9pbl9zdWRvKCkgeyBpZCAtbkcgIiQxIiAyPi9kZXYvbnVsbCB8IHRyICcgJyAnXG4nIHwgZ3JlcCAtcXggc3VkbzsgfQoKYXBwbHlfcmVwb19wZXJtcygpIHsKICAgIGxvY2FsIG1wPSQxIHU9JENGR19WRUVBTV9VU0VSCiAgICBpZiAhIGlkICIkdSIgPi9kZXYvbnVsbCAyPiYxOyB0aGVuCiAgICAgICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBzaW0gImNob3duICR1OiR1ICRtcDsgY2htb2QgNzAwICRtcCI7IGVsc2UgaW5mbyAiVXRlbnRlICR1IG5vbiBhbmNvcmEgY3JlYXRvOiBpIHBlcm1lc3NpIHN1ICRtcCB2ZW5nb25vIGFwcGxpY2F0aSBuZWwgcGFzc28gVXRlbnRlIjsgZmkKICAgICAgICByZXR1cm4gMAogICAgZmkKICAgIHJ1biBjaG93biAiJHU6JHUiICIkbXAiICYmIHJ1biBjaG1vZCA3MDAgIiRtcCIgJiYgb2sgIlBlcm1lc3NpIHN1ICRtcDogJHUsIDcwMCIKfQoKcHJvdGVjdF9tb3VudHBvaW50KCkgewogICAgbG9jYWwgbXA9JDEKICAgIG1vdW50cG9pbnQgLXEgIiRtcCIgMj4vZGV2L251bGwgJiYgcmV0dXJuIDAKICAgIGlmICgoIERSWV9SVU4gKSk7IHRoZW4gc2ltICJjaG1vZCAwMDAgKyBjaGF0dHIgK2kgJG1wIChzZSBsYSBMVU4gbm9uIGUnIG1vbnRhdGEgbmVzc3VubyBzY3JpdmUgc3VsIGRpc2NvIGRpIHNpc3RlbWEpIjsgcmV0dXJuIDA7IGZpCiAgICBjaG93biByb290OnJvb3QgIiRtcCIgJiYgY2htb2QgMDAwICIkbXAiCiAgICBpZiBjaGF0dHIgK2kgIiRtcCIgMj4vZGV2L251bGw7IHRoZW4gb2sgIlB1bnRvIGRpIG1vdW50IHByb3RldHRvIChpbW11dGFiaWxlIHF1YW5kbyBsYSBMVU4gbm9uIGUnIG1vbnRhdGEpOiAkbXAiCiAgICBlbHNlIHdhcm4gImNoYXR0ciBub24gc3VwcG9ydGF0byBzdWwgZmlsZXN5c3RlbSBkaSBzaXN0ZW1hOiAkbXAgbm9uIHByb3RldHRvIjsgZmkKfQoKdmVlYW1faGludCgpIHsKICAgIGxvY2FsIG1wcyBpcHMKICAgIG1wcz0kKHJlcG9fbW91bnRzIHwgdHIgJ1xuJyAnICcpCiAgICBpcHM9JChob3N0bmFtZSAtSSAyPi9kZXYvbnVsbCB8IHhhcmdzKQogICAgY2F0IDw8RU9GClByb3NzaW1pIHBhc3NpIGluIFZlZWFtIEJhY2t1cCAmIFJlcGxpY2F0aW9uOgogMS4gQmFja3VwIEluZnJhc3RydWN0dXJlID4gTWFuYWdlZCBTZXJ2ZXJzID4gQWRkIFNlcnZlciA+IExpbnV4CiAgICBob3N0OiAkKGhvc3RuYW1lKSAoJHtpcHM6LUlQIGRlbCBzZXJ2ZXJ9KQogICAgY3JlZGVuemlhbGk6ICJTaW5nbGUtdXNlIGNyZWRlbnRpYWxzIGZvciBoYXJkZW5lZCByZXBvc2l0b3J5IiwKICAgIHV0ZW50ZSAkQ0ZHX1ZFRUFNX1VTRVIgY29uIGxhIHN1YSBwYXNzd29yZCAoZWxldmF6aW9uZSBjb24gc3VkbykKIDIuIEJhY2t1cCBSZXBvc2l0b3JpZXMgPiBBZGQgPiBEaXJlY3QgYXR0YWNoZWQgc3RvcmFnZSA+IExpbnV4IChIYXJkZW5lZCBSZXBvc2l0b3J5KQogICAgcGVyY29yc286ICR7bXBzOi08cHVudG8gZGkgbW91bnQgZGVsbGEgTFVOPn0KICAgICJVc2UgZmFzdCBjbG9uaW5nIG9uIFhGUyB2b2x1bWVzIiBlIGltbXV0YWJpbGl0YScgKGdpb3JuaSkKIDMuIFBvaSBzdWwgc2VydmVyOiAgc3VkbyAkSU5TVEFMTF9QQVRIIGxvY2tkb3duCiAgICAodG9nbGllIGlsIHN1ZG8gYWxsJ3V0ZW50ZSBWZWVhbSwgYmxvY2NhIGxhIHBhc3N3b3JkLCBkaXNhdHRpdmEgU1NIKQpFT0YKfQoKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09IFBBU1NJCnN0ZXBfcGFja2FnZXMoKSB7CiAgICBzdGVwICJQcmVyZXF1aXNpdGkgZSBwYWNjaGV0dGkiCiAgICBjaGVja19vcwogICAgbG9jYWwgcGs9KG9wZW4taXNjc2kgeGZzcHJvZ3MgcGFydGVkKQogICAgaXNfbm8gIiRDRkdfTVVMVElQQVRIIiB8fCBways9KG11bHRpcGF0aC10b29scykKICAgIGVuc3VyZV9wa2dzICIke3BrW0BdfSIKfQoKc3RlcF9udHAoKSB7CiAgICBzdGVwICJPcmEgZGkgc2lzdGVtYSAobCdpbW11dGFiaWxpdGEnIGRpcGVuZGUgZGEgdW4gb3JvbG9naW8gY29ycmV0dG8pIgogICAgbG9jYWwgc2VydmVycyBzeW5jZWQKICAgIHNlcnZlcnM9JChub3JtX2xpc3QgIiRDRkdfTlRQX1NFUlZFUlMiKQogICAgaWYgW1sgLW4gJENGR19USU1FWk9ORSBdXTsgdGhlbiBydW4gdGltZWRhdGVjdGwgc2V0LXRpbWV6b25lICIkQ0ZHX1RJTUVaT05FIiAmJiBvayAiRnVzbyBvcmFyaW86ICRDRkdfVElNRVpPTkUiOyBmaQogICAgaWYgW1sgLW4gJHNlcnZlcnMgXV07IHRoZW4KICAgICAgICBpZiBzeXN0ZW1jdGwgaXMtYWN0aXZlIC1xIGNocm9ueSAyPi9kZXYvbnVsbDsgdGhlbgogICAgICAgICAgICB3YXJuICJjaHJvbnkgYXR0aXZvOiBpIHNlcnZlciBOVFAgdmFubm8gY29uZmlndXJhdGkgaW4gL2V0Yy9jaHJvbnkvY2hyb255LmNvbmYgKG5vbiBtb2RpZmljbykiCiAgICAgICAgZWxzZQogICAgICAgICAgICB3cml0ZV9maWxlIC9ldGMvc3lzdGVtZC90aW1lc3luY2QuY29uZi5kL3ZyZXBvLXNldHVwLmNvbmYgMDY0NCAiW1RpbWVdCk5UUD0kc2VydmVycyIgJiYgcnVuIHN5c3RlbWN0bCByZXN0YXJ0IHN5c3RlbWQtdGltZXN5bmNkCiAgICAgICAgZmkKICAgIGZpCiAgICBydW4gdGltZWRhdGVjdGwgc2V0LW50cCB0cnVlCiAgICAoKCBEUllfUlVOICkpICYmIHJldHVybiAwCiAgICBzbGVlcCAyCiAgICBzeW5jZWQ9JCh0aW1lZGF0ZWN0bCBzaG93IC1wIE5UUFN5bmNocm9uaXplZCAtLXZhbHVlIDI+L2Rldi9udWxsKQogICAgaWYgW1sgJHN5bmNlZCA9PSB5ZXMgXV07IHRoZW4gb2sgIk9yb2xvZ2lvIHNpbmNyb25penphdG86ICQoZGF0ZSAnKyVGICVUICVaJykiCiAgICBlbHNlIHdhcm4gIk9yb2xvZ2lvIG5vbiBhbmNvcmEgc2luY3Jvbml6emF0byB2aWEgTlRQICgkKGRhdGUgJyslRiAlVCAlWicpKTogdmVyaWZpY2FyZSBjaGUgaWwgc2VydmVyIHJhZ2dpdW5nYSB1biBOVFAiOyBmaQp9CgpzdGVwX2luaXRpYXRvcigpIHsKICAgIHN0ZXAgIkluaXRpYXRvciBpU0NTSSBlIGF2dmlvIGF1dG9tYXRpY28iCiAgICBlbnN1cmVfcGtncyBvcGVuLWlzY3NpIHx8IHJldHVybiAxCiAgICBsb2NhbCBmPS9ldGMvaXNjc2kvaW5pdGlhdG9ybmFtZS5pc2NzaSBjPS9ldGMvaXNjc2kvaXNjc2lkLmNvbmYgY3VyIG5ldyBjaGFuZ2VkPTAKICAgIGN1cj0kKHNlZCAtbiAncy9eSW5pdGlhdG9yTmFtZT0vL3AnICIkZiIgMj4vZGV2L251bGwgfCBoZWFkIC1uIDEpCiAgICBpZiBbWyAtbiAkQ0ZHX0lOSVRJQVRPUl9OQU1FICYmICRDRkdfSU5JVElBVE9SX05BTUUgIT0gIiRjdXIiIF1dOyB0aGVuCiAgICAgICAgdmFsaWRfaXFuICIkQ0ZHX0lOSVRJQVRPUl9OQU1FIiB8fCB7IGVyciAiSW5pdGlhdG9yTmFtZSBub24gdmFsaWRvOiAkQ0ZHX0lOSVRJQVRPUl9OQU1FIjsgcmV0dXJuIDE7IH0KICAgICAgICAoKCAkKHNlc3Npb25fY291bnQpID4gMCApKSAmJiB3YXJuICJDaSBzb25vIHNlc3Npb25pIGlTQ1NJIGF0dGl2ZTogaWwgbnVvdm8gSW5pdGlhdG9yTmFtZSB2YWxlIGRhbCBwcm9zc2ltbyBsb2dpbiIKICAgICAgICB3cml0ZV9maWxlICIkZiIgMDYwMCAiSW5pdGlhdG9yTmFtZT0kQ0ZHX0lOSVRJQVRPUl9OQU1FIiB8fCByZXR1cm4gMQogICAgICAgIGN1cj0kQ0ZHX0lOSVRJQVRPUl9OQU1FOyBjaGFuZ2VkPTEKICAgIGZpCiAgICBvayAiSW5pdGlhdG9yTmFtZTogJGN1ciAgKGRhIGF1dG9yaXp6YXJlIHN1bCB0YXJnZXQsIGVzLiBRTkFQID4gaVNDU0kgPiBjcml0ZXJpIGRpIGFjY2Vzc28pIgogICAgaWYgW1sgLWYgJGMgXV07IHRoZW4KICAgICAgICBpZiBncmVwIC1xRSAnXltbOnNwYWNlOl1dKm5vZGVcLnN0YXJ0dXBbWzpzcGFjZTpdXSo9W1s6c3BhY2U6XV0qYXV0b21hdGljJyAiJGMiICYmICEgZ3JlcCAtcUUgJ15bWzpzcGFjZTpdXSpub2RlXC5zdGFydHVwW1s6c3BhY2U6XV0qPVtbOnNwYWNlOl1dKm1hbnVhbCcgIiRjIjsgdGhlbgogICAgICAgICAgICBpbmZvICJub2RlLnN0YXJ0dXAgPSBhdXRvbWF0aWMgZ2lhJyBpbXBvc3RhdG8iCiAgICAgICAgZWxzZQogICAgICAgICAgICBuZXc9JChzZWQgLUUgJ3MvXltbOnNwYWNlOl1dKiM/W1s6c3BhY2U6XV0qbm9kZVwuc3RhcnR1cFtbOnNwYWNlOl1dKj0uKi9ub2RlLnN0YXJ0dXAgPSBhdXRvbWF0aWMvJyAiJGMiKQogICAgICAgICAgICBuZXc9JChhd2sgJy9ebm9kZVwuc3RhcnR1cCA9IGF1dG9tYXRpYyQve2lmKHNlZW4rKyluZXh0fTEnIDw8PCIkbmV3IikKICAgICAgICAgICAgd3JpdGVfZmlsZSAiJGMiIDA2MDAgIiRuZXciIHx8IHJldHVybiAxCiAgICAgICAgICAgIGNoYW5nZWQ9MQogICAgICAgIGZpCiAgICBlbHNlCiAgICAgICAgZXJyICIkYyBub24gdHJvdmF0bzogb3Blbi1pc2NzaSBpbnN0YWxsYXRvIGNvcnJldHRhbWVudGU/IjsgcmV0dXJuIDEKICAgIGZpCiAgICBydW5fcXVpZXQgc3lzdGVtY3RsIGVuYWJsZSBpc2NzaWQuc2VydmljZSBvcGVuLWlzY3NpLnNlcnZpY2UgfHwgcnVuIHN5c3RlbWN0bCBlbmFibGUgb3Blbi1pc2NzaS5zZXJ2aWNlCiAgICBpZiAoKCBjaGFuZ2VkICkpOyB0aGVuCiAgICAgICAgcnVuIHN5c3RlbWN0bCByZXN0YXJ0IGlzY3NpZAogICAgICAgIGlmICgoICQoc2Vzc2lvbl9jb3VudCkgPT0gMCApKTsgdGhlbiBydW4gc3lzdGVtY3RsIHJlc3RhcnQgb3Blbi1pc2NzaTsgZWxzZSBpbmZvICJvcGVuLWlzY3NpIG5vbiByaWF2dmlhdG86IHNlc3Npb25pIGF0dGl2ZSI7IGZpCiAgICBmaQogICAgb2sgIkluaXRpYXRvciBwcm9udG8iCn0KCnN0ZXBfdGFyZ2V0cygpIHsKICAgIHN0ZXAgIkNvbm5lc3Npb25lIGFpIHRhcmdldCBpU0NTSSIKICAgIGVuc3VyZV9wa2dzIG9wZW4taXNjc2kgfHwgcmV0dXJuIDEKICAgIFtbIC1uICQobm9ybV9saXN0ICIkQ0ZHX0lTQ1NJX1BPUlRBTFMiKSBdXSB8fCB7IGVyciAiTmVzc3VuIHBvcnRhbGUgaVNDU0kgaW5kaWNhdG8gKElTQ1NJX1BPUlRBTFMpIjsgcmV0dXJuIDE7IH0KICAgIGRpc2NvdmVyX3RhcmdldHMgIiREUllfUlVOIgogICAgaWYgKCggJHsjRElTQ1tAXX0gPT0gMCApKTsgdGhlbiBlcnIgIk5lc3N1biB0YXJnZXQgc2NvcGVydG86IGNvbnRyb2xsYXJlIElQLCByZXRlIGlTQ1NJIGUgY3JpdGVyaSBkaSBhY2Nlc3NvIHN1bCBOQVMgKEluaXRpYXRvck5hbWUpIjsgcmV0dXJuIDE7IGZpCiAgICBsb2NhbCBlIHBvcnRhbCBpcW4gc2VsPSgpIGl0ZW1zPSgpIGNob3NlbiBhY3RpdmUKICAgIGFjdGl2ZT0kKGlzY3NpX3Nlc3Npb25zKQogICAgZm9yIGUgaW4gIiR7RElTQ1tAXX0iOyBkbwogICAgICAgIHJlYWQgLXIgcG9ydGFsIGlxbiA8PDwiJGUiCiAgICAgICAgaWYgdGFyZ2V0X3dhbnRlZCAiJGlxbiIgJiYgcG9ydGFsX3dhbnRlZCAiJHBvcnRhbCI7IHRoZW4gaXRlbXMrPSgiJGUiICJPTiIpOyBlbHNlIGl0ZW1zKz0oIiRlIiAiT0ZGIik7IGZpCiAgICBkb25lCiAgICBpZiAoKCBJTlRFUkFDVElWRSApKTsgdGhlbgogICAgICAgIGxvY2FsIGFyZ3M9KCkgaQogICAgICAgIGZvciAoKGkgPSAwOyBpIDwgJHsjaXRlbXNbQF19OyBpICs9IDIpKTsgZG8gYXJncys9KCIke2l0ZW1zW2ldfSIgIiIgIiR7aXRlbXNbaSsxXX0iKTsgZG9uZQogICAgICAgIGNob3Nlbj0kKHd0IC0tdGl0bGUgIlRhcmdldCBzY29wZXJ0aSIgLS1zZXBhcmF0ZS1vdXRwdXQgLS1jaGVja2xpc3QgXAogICAgICAgICAgICAiU3B1bnRhIHBvcnRhbGUgZSB0YXJnZXQgc3UgY3VpIGZhcmUgbG9naW4gKHVubyBwZXIgcGVyY29yc28pLlxuSSByZWNvcmQgbm9uIHNjZWx0aSB2ZW5nb25vIGVsaW1pbmF0aSwgY29zaScgYWwgcmlhdnZpbyBub24gc2kgY29sbGVnYSBhbHRyby4iIFwKICAgICAgICAgICAgMjIgMTAwIDEyICIke2FyZ3NbQF19IikgfHwgcmV0dXJuIDEKICAgICAgICB3aGlsZSBJRlM9IHJlYWQgLXIgZTsgZG8gW1sgLW4gJGUgXV0gJiYgc2VsKz0oIiRlIik7IGRvbmUgPDw8IiRjaG9zZW4iCiAgICBlbHNlCiAgICAgICAgZm9yICgoaSA9IDA7IGkgPCAkeyNpdGVtc1tAXX07IGkgKz0gMikpOyBkbyBbWyAke2l0ZW1zW2krMV19ID09IE9OIF1dICYmIHNlbCs9KCIke2l0ZW1zW2ldfSIpOyBkb25lCiAgICBmaQogICAgKCggJHsjc2VsW0BdfSApKSB8fCB7IGVyciAiTmVzc3VuIHRhcmdldCBzZWxlemlvbmF0byAoSVNDU0lfVEFSR0VUUyAvIE9OTFlfTElTVEVEX1BPUlRBTFMpIjsgcmV0dXJuIDE7IH0KICAgIGxvY2FsIG5fb2s9MAogICAgZm9yIGUgaW4gIiR7RElTQ1tAXX0iOyBkbwogICAgICAgIHJlYWQgLXIgcG9ydGFsIGlxbiA8PDwiJGUiCiAgICAgICAgaWYgW1sgIiAke3NlbFsqXX0gIiAhPSAqIiAkZSAiKiBdXTsgdGhlbgogICAgICAgICAgICBpZiBncmVwIC1xeEYgIiRwb3J0YWwgJGlxbiIgPDw8IiRhY3RpdmUiOyB0aGVuIGluZm8gIk5vbiBzZWxlemlvbmF0byBtYSBjb25uZXNzbywgbG8gbGFzY2lvOiAkaXFuIEAgJHBvcnRhbCIKICAgICAgICAgICAgZWxzZSBydW5fcXVpZXQgaXNjc2lhZG0gLW0gbm9kZSAtVCAiJGlxbiIgLXAgIiRwb3J0YWwiIC1vIGRlbGV0ZSAmJiBpbmZvICJSZWNvcmQgbm9uIHVzYXRvIGVsaW1pbmF0bzogJGlxbiBAICRwb3J0YWwiOyBmaQogICAgICAgICAgICBjb250aW51ZQogICAgICAgIGZpCiAgICAgICAgaW5mbyAiVGFyZ2V0ICRpcW4gQCAkcG9ydGFsIgogICAgICAgIHJ1biBpc2NzaWFkbSAtbSBub2RlIC1UICIkaXFuIiAtcCAiJHBvcnRhbCIgLW8gdXBkYXRlIC1uIG5vZGUuc3RhcnR1cCAtdiBhdXRvbWF0aWMgfHwgY29udGludWUKICAgICAgICBydW4gaXNjc2lhZG0gLW0gbm9kZSAtVCAiJGlxbiIgLXAgIiRwb3J0YWwiIC1vIHVwZGF0ZSAtbiAnbm9kZS5jb25uWzBdLnN0YXJ0dXAnIC12IGF1dG9tYXRpYwogICAgICAgIGlmIFtbIC1uICRDRkdfQ0hBUF9VU0VSIF1dOyB0aGVuCiAgICAgICAgICAgIHJ1biBpc2NzaWFkbSAtbSBub2RlIC1UICIkaXFuIiAtcCAiJHBvcnRhbCIgLW8gdXBkYXRlIC1uIG5vZGUuc2Vzc2lvbi5hdXRoLmF1dGhtZXRob2QgLXYgQ0hBUAogICAgICAgICAgICBydW4gaXNjc2lhZG0gLW0gbm9kZSAtVCAiJGlxbiIgLXAgIiRwb3J0YWwiIC1vIHVwZGF0ZSAtbiBub2RlLnNlc3Npb24uYXV0aC51c2VybmFtZSAtdiAiJENGR19DSEFQX1VTRVIiCiAgICAgICAgICAgIHJ1bl9zZWNyZXQgImlzY3NpYWRtIC4uLiBub2RlLnNlc3Npb24uYXV0aC5wYXNzd29yZCA9IChuYXNjb3N0YSkiIGlzY3NpYWRtIC1tIG5vZGUgLVQgIiRpcW4iIC1wICIkcG9ydGFsIiAtbyB1cGRhdGUgLW4gbm9kZS5zZXNzaW9uLmF1dGgucGFzc3dvcmQgLXYgIiRDRkdfQ0hBUF9QQVNTV09SRCIKICAgICAgICBmaQogICAgICAgIGlmIGdyZXAgLXF4RiAiJHBvcnRhbCAkaXFuIiA8PDwiJGFjdGl2ZSI7IHRoZW4gb2sgIkdpYScgY29ubmVzc286ICRpcW4gQCAkcG9ydGFsIjsgbl9vaz0kKChuX29rICsgMSkpOyBjb250aW51ZTsgZmkKICAgICAgICBpZiAoKCBEUllfUlVOICkpOyB0aGVuIHNpbSAiaXNjc2lhZG0gLW0gbm9kZSAtVCAkaXFuIC1wICRwb3J0YWwgLS1sb2dpbiI7IG5fb2s9JCgobl9vayArIDEpKTsgY29udGludWU7IGZpCiAgICAgICAgbG9jYWwgb3V0IHJjCiAgICAgICAgb3V0PSQoaXNjc2lhZG0gLW0gbm9kZSAtVCAiJGlxbiIgLXAgIiRwb3J0YWwiIC0tbG9naW4gMj4mMSk7IHJjPSQ/CiAgICAgICAgaWYgKCggcmMgPT0gMCB8fCByYyA9PSAxNSApKTsgdGhlbiBvayAiTG9naW46ICRpcW4gQCAkcG9ydGFsIjsgbl9vaz0kKChuX29rICsgMSkpCiAgICAgICAgZWxzZSBlcnIgIkxvZ2luIG5vbiByaXVzY2l0byBzdSAkaXFuIEAgJHBvcnRhbDogJCh0YWlsIC1uIDEgPDw8IiRvdXQiKSI7IGZpCiAgICBkb25lCiAgICBydW5fcXVpZXQgaXNjc2lhZG0gLW0gc2Vzc2lvbiAtLXJlc2NhbgogICAgKCggRFJZX1JVTiApKSB8fCB7IHVkZXZhZG0gc2V0dGxlIDI+L2Rldi9udWxsOyBzbGVlcCAyOyB9CiAgICAoKCBuX29rICkpIHx8IHsgZXJyICJOZXNzdW4gbG9naW4gcml1c2NpdG8iOyByZXR1cm4gMTsgfQogICAgb2sgIlNlc3Npb25pIGF0dGl2ZTogJChzZXNzaW9uX2NvdW50KSIKICAgICgoIERSWV9SVU4gKSkgfHwgc2hvdyBpc2NzaWFkbSAtbSBzZXNzaW9uCiAgICBsb2NhbCBtcGQ7IG1wZD0kKGRldGVjdF9tdWx0aV9wYXRocykKICAgICgoIG1wZCA+IDAgKSkgJiYgaW5mbyAiUmlsZXZhdGUgJG1wZCBMVU4gdmlzaWJpbGkgc3UgcGl1JyBwZXJjb3JzaTogc2VydmUgaWwgbXVsdGlwYXRoIgogICAgcmV0dXJuIDAKfQoKc3RlcF9tdWx0aXBhdGgoKSB7CiAgICBzdGVwICJNdWx0aXBhdGgiCiAgICBsb2NhbCB3YW50PSRDRkdfTVVMVElQQVRIIG5wYXRocwogICAgaWYgW1sgJHdhbnQgPT0gYXV0byBdXTsgdGhlbgogICAgICAgIG5wYXRocz0kKGRldGVjdF9tdWx0aV9wYXRocykKICAgICAgICBpZiAoKCBucGF0aHMgPiAwICkpIHx8IFtbICQod2MgLXcgPDw8IiQobm9ybV9saXN0ICIkQ0ZHX0lTQ1NJX1BPUlRBTFMiKSIpIC1ndCAxIF1dOyB0aGVuIHdhbnQ9eWVzOyBlbHNlIHdhbnQ9bm87IGZpCiAgICAgICAgaW5mbyAiTXVsdGlwYXRoIGF1dG9tYXRpY286ICR3YW50IChMVU4gY29uIHBpdScgcGVyY29yc2k6ICRucGF0aHMpIgogICAgZmkKICAgIGlmICEgaXNfeWVzICIkd2FudCI7IHRoZW4gaW5mbyAiTXVsdGlwYXRoIG5vbiByaWNoaWVzdG86IHNhbHRvIjsgcmV0dXJuIDA7IGZpCiAgICBlbnN1cmVfcGtncyBtdWx0aXBhdGgtdG9vbHMgfHwgcmV0dXJuIDEKICAgIGlmICgoICEgRFJZX1JVTiApKTsgdGhlbiBta2RpciAtcCAiJFNUQVRFX0RJUiI7IHByaW50ZiAnJXMnICIkQ0ZHX01VTFRJUEFUSF9QUk9GSUxFIiA+IiRTVEFURV9NUFBST0ZJTEUiOyBmaQogICAgaWYgW1sgLWYgL2V0Yy9tdWx0aXBhdGguY29uZiBdXSAmJiAhIGdyZXAgLXFGICIkTVBfTUFSSyIgL2V0Yy9tdWx0aXBhdGguY29uZjsgdGhlbiBpbmZvICIvZXRjL211bHRpcGF0aC5jb25mIGVzaXN0ZW50ZSBub24gZ2VuZXJhdG8gZGFsIHRvb2w6IHZpZW5lIHNhbHZhdG8gdW4gYmFja3VwIjsgZmkKICAgIHdyaXRlX2ZpbGUgL2V0Yy9tdWx0aXBhdGguY29uZiAwNjQ0ICIkKG11bHRpcGF0aF9jb25mX2NvbnRlbnQgIiRDRkdfTVVMVElQQVRIX1BST0ZJTEUiKSIgfHwgcmV0dXJuIDEKICAgIHJ1bl9xdWlldCBzeXN0ZW1jdGwgZW5hYmxlIG11bHRpcGF0aGQuc2VydmljZQogICAgcnVuIHN5c3RlbWN0bCByZXN0YXJ0IG11bHRpcGF0aGQgfHwgcmV0dXJuIDEKICAgICgoIERSWV9SVU4gKSkgJiYgcmV0dXJuIDAKICAgIHNsZWVwIDM7IG11bHRpcGF0aCAtciA+L2Rldi9udWxsIDI+JjE7IHVkZXZhZG0gc2V0dGxlIDI+L2Rldi9udWxsCiAgICBtdWx0aXBhdGhfY2hlY2tfY29uZgogICAgbG9jYWwgbWFwczsgbWFwcz0kKG11bHRpcGF0aCAtbCAyPi9kZXYvbnVsbCB8IGdyZXAgLWMgJ2RtLScpCiAgICBpZiAoKCBtYXBzID4gMCApKTsgdGhlbiBvayAiRGlzcG9zaXRpdmkgbXVsdGlwYXRoOiAkbWFwcyI7IHNob3cgbXVsdGlwYXRoIC1sbAogICAgZWxzZSB3YXJuICJOZXNzdW4gZGlzcG9zaXRpdm8gbXVsdGlwYXRoIGNyZWF0bzogbGUgTFVOIGhhbm5vIHVuIHNvbG8gcGVyY29yc28gbyBpbCBXV0lEIG5vbiBjb2luY2lkZSI7IGZpCn0KCiMgY29uZmlndXJlX2x1biA8ZGlzcG9zaXRpdm98d3dpZD4gPG5vbWU+IDxtb3VudD4KY29uZmlndXJlX2x1bigpIHsKICAgIGxvY2FsIHE9JDEgbmFtZT0kMiBtcD0kMyByZWMgZGV2IGsgd3dpZCBzaXplIG1vZGVsIHBhdGhzIHRyYW4gc3RhdGUgZnN0eXBlIG1udCBjdXIKICAgIHZhbGlkX25hbWUgIiRuYW1lIiB8fCB7IGVyciAiTm9tZSBMVU4gbm9uIHZhbGlkbzogJyRuYW1lJyAobGV0dGVyZSwgbnVtZXJpLCAuIF8gLSwgbWF4IDMyKSI7IHJldHVybiAxOyB9CiAgICBbWyAtbiAkbXAgXV0gfHwgbXA9JENGR19NT1VOVF9CQVNFLyRuYW1lCiAgICB2YWxpZF9wYXRoICIkbXAiIHx8IHsgZXJyICJQdW50byBkaSBtb3VudCBub24gdmFsaWRvOiAkbXAiOyByZXR1cm4gMTsgfQogICAgc2Nhbl9sdW5zCiAgICByZWM9JChmaW5kX2x1biAiJHEiKSB8fCB7IGVyciAiJHEgbm9uIHRyb3ZhdG8gdHJhIGkgZGlzY2hpIHV0aWxpenphYmlsaSAoaSBkaXNjaGkgZGkgc2lzdGVtYSBzb25vIGVzY2x1c2kpIjsgcmV0dXJuIDE7IH0KICAgIElGUz0nfCcgcmVhZCAtciBkZXYgayB3d2lkIHNpemUgbW9kZWwgcGF0aHMgdHJhbiBzdGF0ZSBmc3R5cGUgbW50IGN1ciA8PDwiJHJlYyIKICAgIGNhc2UgJHN0YXRlIGluCiAgICAgICAgY29uZmlndXJhdG8pCiAgICAgICAgICAgIGlmIFtbICRjdXIgPT0gIiRuYW1lIiBdXTsgdGhlbiBvayAiTFVOICRuYW1lIGdpYScgY29uZmlndXJhdGEgKCRkZXYpIjsgYXBwbHlfcmVwb19wZXJtcyAiJChzdGF0ZV9sb29rdXAgMSAiJG5hbWUiIHwgY3V0IC1kJ3wnIC1mNCkiOyByZXR1cm4gMDsgZmkKICAgICAgICAgICAgZXJyICIkZGV2IGUnIGdpYScgaWwgcmVwb3NpdG9yeSAkY3VyIjsgcmV0dXJuIDEgOzsKICAgICAgICBpbl91c28pCiAgICAgICAgICAgIFtbICRtbnQgIT0gLSBdXSAmJiB7IGVyciAiJGRldiBlJyBtb250YXRvIHN1ICRtbnQ6IG5vbiBsbyB0b2NjbyI7IHJldHVybiAxOyB9CiAgICAgICAgICAgIGNvbXBnZW4gLUcgIi9zeXMvYmxvY2svJGsvaG9sZGVycy8qIiA+L2Rldi9udWxsICYmIFtbICRrICE9IGRtLSogXV0gJiYgeyBlcnIgIiRkZXYgZScgaW4gdXNvIChMVk0vUkFJRC9tdWx0aXBhdGgpOiBub24gbG8gdG9jY28iOyByZXR1cm4gMTsgfQogICAgICAgICAgICBpc195ZXMgIiRDRkdfRk9SQ0VfRk9STUFUIiB8fCB7IGVyciAiJGRldiBjb250aWVuZSBkYXRpIG8gcGFydGl6aW9uaSAoJGZzdHlwZSk6IHBlciBjYW5jZWxsYXJsbyBGT1JDRV9GT1JNQVQ9eWVzIjsgcmV0dXJuIDE7IH0KICAgICAgICAgICAgd2FybiAiRk9SQ0VfRk9STUFUOiBpbCBjb250ZW51dG8gZGkgJGRldiAoJGZzdHlwZSkgdmllbmUgY2FuY2VsbGF0byIgOzsKICAgIGVzYWMKICAgIFtbIC1uICQoc3RhdGVfbG9va3VwIDEgIiRuYW1lIikgXV0gJiYgeyBlcnIgIkVzaXN0ZSBnaWEnIHVuIHJlcG9zaXRvcnkgY29uIG5vbWUgJG5hbWUiOyByZXR1cm4gMTsgfQogICAgbW91bnRwb2ludCAtcSAiJG1wIiAyPi9kZXYvbnVsbCAmJiB7IGVyciAiJG1wIGUnIGdpYScgdW4gcHVudG8gZGkgbW91bnQiOyByZXR1cm4gMTsgfQogICAgW1sgLWQgJG1wICYmIC1uICQobHMgLUEgIiRtcCIgMj4vZGV2L251bGwpIF1dICYmIHsgZXJyICIkbXAgbm9uIGUnIHZ1b3RhIjsgcmV0dXJuIDE7IH0KICAgIGF3ayAtdiBtPSIkbXAiICckMCAhfiAvXltbOnNwYWNlOl1dKiMvICYmICQyPT1tIHtmPTF9IEVORHtleGl0ICFmfScgL2V0Yy9mc3RhYiAmJiB7IGVyciAiJG1wIGUnIGdpYScgaW4gL2V0Yy9mc3RhYiI7IHJldHVybiAxOyB9CgogICAgc3RlcCAiTFVOICRkZXYgLT4gJG5hbWUgKCQoaHNpemUgIiRzaXplIiksICRwYXRocyBwZXJjb3JzaSwgJHRyYW4pIHN1ICRtcCIKICAgIGxvY2FsIHRhcmdldD0kZGV2IHBhcnQgdXVpZCBvcHRzPSJkZWZhdWx0cyxub2ZhaWwiCiAgICBpZiBbWyAkayA9PSBkbS0qIF1dICYmIGlzX3llcyAiJENGR19NVUxUSVBBVEhfQUxJQVMiICYmIFtbICR7ZGV2IyMqL30gIT0gIiRuYW1lIiBdXSAmJiBbWyAkd3dpZCAhPSAtIF1dOyB0aGVuCiAgICAgICAgc2V0X21wYXRoX2FsaWFzICIkd3dpZCIgIiRuYW1lIiB8fCByZXR1cm4gMQogICAgICAgICgoIERSWV9SVU4gKSkgfHwgdGFyZ2V0PS9kZXYvbWFwcGVyLyRuYW1lCiAgICBmaQogICAgW1sgJHRyYW4gPT0gaXNjc2kgXV0gJiYgb3B0cz0iZGVmYXVsdHMsX25ldGRldixub2ZhaWwiCiAgICBydW4gd2lwZWZzIC1hICIkdGFyZ2V0IiB8fCByZXR1cm4gMQogICAgcGFydD0kdGFyZ2V0CiAgICBpZiBpc195ZXMgIiRDRkdfUEFSVElUSU9OIjsgdGhlbgogICAgICAgIHJ1biBwYXJ0ZWQgLXMgIiR0YXJnZXQiIG1rbGFiZWwgZ3B0IG1rcGFydCAiJG5hbWUiIHhmcyAwJSAxMDAlIHx8IHJldHVybiAxCiAgICAgICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBwYXJ0PSIkdGFyZ2V0IChwYXJ0aXppb25lIDEpIgogICAgICAgIGVsc2UKICAgICAgICAgICAgdWRldmFkbSBzZXR0bGUgMj4vZGV2L251bGwKICAgICAgICAgICAgW1sgJGsgPT0gZG0tKiBdXSAmJiB7IGtwYXJ0eCAtdSAiJHRhcmdldCIgPi9kZXYvbnVsbCAyPiYxOyB1ZGV2YWRtIHNldHRsZSAyPi9kZXYvbnVsbDsgfQogICAgICAgICAgICBwYXJ0PSQoZmluZF9wYXJ0aXRpb24gIiR0YXJnZXQiKSB8fCB7IGVyciAiUGFydGl6aW9uZSBkaSAkdGFyZ2V0IG5vbiB0cm92YXRhIjsgcmV0dXJuIDE7IH0KICAgICAgICAgICAgaW5mbyAiUGFydGl6aW9uZTogJHBhcnQiCiAgICAgICAgZmkKICAgIGZpCiAgICBydW4gbWtmcy54ZnMgLWYgLWIgc2l6ZT00MDk2IC1tIHJlZmxpbms9MSxjcmM9MSAtTCAiJHtuYW1lOjA6MTJ9IiAiJHBhcnQiIHx8IHJldHVybiAxCiAgICBpZiAoKCBEUllfUlVOICkpOyB0aGVuIHV1aWQ9IjxVVUlEPiIKICAgIGVsc2UKICAgICAgICB1ZGV2YWRtIHNldHRsZSAyPi9kZXYvbnVsbAogICAgICAgIHV1aWQ9JChibGtpZCAtcyBVVUlEIC1vIHZhbHVlICIkcGFydCIgMj4vZGV2L251bGwpCiAgICAgICAgW1sgLW4gJHV1aWQgXV0gfHwgeyBlcnIgIlVVSUQgZGkgJHBhcnQgbm9uIGxldHRvIjsgcmV0dXJuIDE7IH0KICAgICAgICBvayAiWEZTIGNyZWF0byAocmVmbGluaywgY3JjLCBibG9jY2hpIDRLKSwgVVVJRCAkdXVpZCIKICAgIGZpCiAgICBbWyAtZCAkbXAgXV0gfHwgcnVuIG1rZGlyIC1wICIkbXAiIHx8IHJldHVybiAxCiAgICBwcm90ZWN0X21vdW50cG9pbnQgIiRtcCIKICAgIGxvY2FsIGxpbmU9IlVVSUQ9JHV1aWQgJG1wIHhmcyAkb3B0cyAwIDAiCiAgICBpZiAoKCBEUllfUlVOICkpOyB0aGVuIHNpbSAiQWdnaXVuZ2VyZWkgYSAvZXRjL2ZzdGFiOiAkbGluZSIKICAgIGVsaWYgISBncmVwIC1xICJVVUlEPSR1dWlkIiAvZXRjL2ZzdGFiOyB0aGVuCiAgICAgICAgYmFja3VwX2ZpbGUgL2V0Yy9mc3RhYgogICAgICAgIHByaW50ZiAnIyB2cmVwby1zZXR1cDogTFVOICVzICh3d2lkICVzKVxuJXNcbicgIiRuYW1lIiAiJHd3aWQiICIkbGluZSIgPj4vZXRjL2ZzdGFiIHx8IHsgZXJyICJTY3JpdHR1cmEgZGkgL2V0Yy9mc3RhYiBub24gcml1c2NpdGEiOyByZXR1cm4gMTsgfQogICAgICAgIG9rICJmc3RhYjogJGxpbmUiCiAgICAgICAgZmluZG1udCAtLXZlcmlmeSAtLXRhYi1maWxlIC9ldGMvZnN0YWIgPi9kZXYvbnVsbCAyPiYxIHx8IHdhcm4gImZpbmRtbnQgLS12ZXJpZnkgc2VnbmFsYSBhdnZpc2kgc3UgL2V0Yy9mc3RhYjogY29udHJvbGxhcmUiCiAgICBmaQogICAgcnVuX3F1aWV0IHN5c3RlbWN0bCBkYWVtb24tcmVsb2FkCiAgICBydW4gbW91bnQgIiRtcCIgfHwgcmV0dXJuIDEKICAgIGlmICgoICEgRFJZX1JVTiApKTsgdGhlbgogICAgICAgIG1vdW50cG9pbnQgLXEgIiRtcCIgfHwgeyBlcnIgIiRtcCBub24gcmlzdWx0YSBtb250YXRvIjsgcmV0dXJuIDE7IH0KICAgICAgICBsb2NhbCB4aTsgeGk9JCh4ZnNfaW5mbyAiJG1wIiAyPi9kZXYvbnVsbCkKICAgICAgICBncmVwIC1xICdyZWZsaW5rPTEnIDw8PCIkeGkiICYmIG9rICJyZWZsaW5rIGF0dGl2byAoRmFzdCBDbG9uZSkiIHx8IHdhcm4gInJlZmxpbmsgTk9OIGF0dGl2byBzdSAkbXAiCiAgICAgICAgc3RhdGVfYWRkX3JlcG8gIiRuYW1lIiAiJHd3aWQiICIkdXVpZCIgIiRtcCIKICAgIGZpCiAgICBhcHBseV9yZXBvX3Blcm1zICIkbXAiCiAgICBvayAiUmVwb3NpdG9yeSAkbmFtZSBwcm9udG8gc3UgJG1wJCggKChEUllfUlVOKSkgfHwgcHJpbnRmICIgKCVzKSIgIiQoZGYgLWggLS1vdXRwdXQ9c2l6ZSAiJG1wIiAyPi9kZXYvbnVsbCB8IHRhaWwgLW4gMSB8IHhhcmdzKSIpIgp9CgojIHR1dHRlIGxlIExVTiBsaWJlcmUgKG1vZGFsaXRhJyBub24gaW50ZXJhdHRpdmE6IHNlcnZlIC0teWVzKQpzdGVwX2x1bnNfYXV0bygpIHsKICAgIHN0ZXAgIlByZXBhcmF6aW9uZSBkZWxsZSBMVU4gbGliZXJlIgogICAgc2Nhbl9sdW5zCiAgICBsb2NhbCByIGQgayB3IHN0IG4gcmM9MCBhbnk9MAogICAgUkVTRVJWRURfTkFNRVM9IiIKICAgIGZvciByIGluICIke0xVTlNbQF19IjsgZG8KICAgICAgICBJRlM9J3wnIHJlYWQgLXIgZCBrIHcgXyBfIF8gXyBzdCBfIDw8PCIkciIKICAgICAgICBbWyAkc3QgPT0gbGliZXJvIF1dIHx8IHsgaW5mbyAiU2FsdG8gJChsdW5fbGFiZWwgIiRyIikiOyBjb250aW51ZTsgfQogICAgICAgIG49JChjb25maWd1cmVkX25hbWVfZm9yICIkdyIgIiRrIikgfHwgbj0kKHN1Z2dlc3RfbmFtZSkKICAgICAgICBSRVNFUlZFRF9OQU1FUys9IiAkbiIKICAgICAgICBhbnk9MQogICAgICAgIGNvbmZpZ3VyZV9sdW4gIiRkIiAiJG4iICIkQ0ZHX01PVU5UX0JBU0UvJG4iIHx8IHJjPTEKICAgIGRvbmUKICAgICgoIGFueSApKSB8fCB3YXJuICJOZXNzdW5hIExVTiBsaWJlcmEgdHJvdmF0YSIKICAgIHJldHVybiAkcmMKfQoKc3RlcF91c2VyKCkgewogICAgc3RlcCAiVXRlbnRlIFZlZWFtIGUgcGVybWVzc2kiCiAgICBsb2NhbCB1PSRDRkdfVkVFQU1fVVNFUiBwdz0kQ0ZHX1ZFRUFNX1BBU1NXT1JEIGdlbj0wIGNyZWF0ZWQ9MCBtcAogICAgdmFsaWRfdXNlciAiJHUiIHx8IHsgZXJyICJOb21lIHV0ZW50ZSBub24gdmFsaWRvOiAkdSI7IHJldHVybiAxOyB9CiAgICBpZiBpZCAiJHUiID4vZGV2L251bGwgMj4mMTsgdGhlbiBpbmZvICJVdGVudGUgJHUgZXNpc3RlbnRlIgogICAgZWxzZSBydW4gdXNlcmFkZCAtbSAtcyAvYmluL2Jhc2ggIiR1IiB8fCByZXR1cm4gMTsgY3JlYXRlZD0xOyBvayAiVXRlbnRlICR1IGNyZWF0byI7IGZpCiAgICBpZiBbWyAteiAkcHcgXV0gJiYgeyAoKCBjcmVhdGVkICkpIHx8ICEgdXNlcl9oYXNfcGFzc3dvcmQgIiR1IjsgfTsgdGhlbiBwdz0kKGdlbl9wYXNzd29yZCk7IGdlbj0xOyBmaQogICAgaWYgW1sgLW4gJHB3IF1dOyB0aGVuCiAgICAgICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBzaW0gIkltcG9zdGVyZWkgbGEgcGFzc3dvcmQgZGkgJHUiCiAgICAgICAgZWxzZSBwcmludGYgJyVzOiVzXG4nICIkdSIgIiRwdyIgfCBjaHBhc3N3ZCB8fCB7IGVyciAiUGFzc3dvcmQgZGkgJHUgbm9uIGltcG9zdGF0YSI7IHJldHVybiAxOyB9OyBwYXNzd2QgLXUgIiR1IiA+L2Rldi9udWxsIDI+JjE7IG9rICJQYXNzd29yZCBkaSAkdSBpbXBvc3RhdGEiOyBmaQogICAgZWxzZSBpbmZvICJQYXNzd29yZCBkaSAkdSBpbnZhcmlhdGEiOyBmaQogICAgcnVuIHVzZXJtb2QgLWFHIHN1ZG8gIiR1IiAmJiBvayAiJHUgbmVsIGdydXBwbyBzdWRvICh0ZW1wb3JhbmVvOiBsbyB0b2dsaWUgbGEgYmxpbmRhdHVyYSkiCiAgICB3aGlsZSByZWFkIC1yIG1wOyBkbyBbWyAtbiAkbXAgJiYgLWQgJG1wIF1dICYmIGFwcGx5X3JlcG9fcGVybXMgIiRtcCI7IGRvbmUgPCA8KHJlcG9fbW91bnRzKQogICAgaWYgKCggZ2VuICYmICEgRFJZX1JVTiApKTsgdGhlbgogICAgICAgIG9rICJQQVNTV09SRCBHRU5FUkFUQSBwZXIgJHU6ICRwdyIKICAgICAgICBpbmZvICJTZXJ2ZSBzb2xvIHBlciBhZ2dpdW5nZXJlIGlsIHNlcnZlciBpbiBWQlIgKGNyZWRlbnppYWxpIHNpbmdsZS11c2UpOyBsYSBibGluZGF0dXJhIGxhIGJsb2NjYS4iCiAgICBmaQogICAgd2hpbGUgSUZTPSByZWFkIC1yIGw7IGRvIGluZm8gIiRsIjsgZG9uZSA8PDwiJCh2ZWVhbV9oaW50KSIKfQoKdmVlYW1fcHJlc2VudCgpIHsgW1sgLWQgL29wdC92ZWVhbSBdXSB8fCBzeXN0ZW1jdGwgbGlzdC11bml0LWZpbGVzIDI+L2Rldi9udWxsIHwgZ3JlcCAtcWkgJ152ZWVhbSc7IH0KCnN0ZXBfbG9ja2Rvd24oKSB7CiAgICBzdGVwICJCbGluZGF0dXJhIChkb3BvIGwnYWdnaXVudGEgZGVsIHJlcG9zaXRvcnkgaW4gVmVlYW0pIgogICAgbG9jYWwgdT0kQ0ZHX1ZFRUFNX1VTRVIgZgogICAgaWYgISB2ZWVhbV9wcmVzZW50OyB0aGVuCiAgICAgICAgaWYgaXNfeWVzICIkQ0ZHX0xPQ0tET1dOX0ZPUkNFIjsgdGhlbiB3YXJuICJDb21wb25lbnRpIFZlZWFtIG5vbiB0cm92YXRpOiBwcm9jZWRvIHBlcmNoZScgTE9DS0RPV05fRk9SQ0U9eWVzIgogICAgICAgIGVsaWYgKCggSU5URVJBQ1RJVkUgKSk7IHRoZW4gbm95ZXMgIkJsaW5kYXR1cmEiICJOb24gdHJvdm8gaSBjb21wb25lbnRpIFZlZWFtICgvb3B0L3ZlZWFtKTogaWwgc2VydmVyIG5vbiBzZW1icmEgYW5jb3JhIGFnZ2l1bnRvIGEgVkJSLlxuXG5Eb3BvIGxhIGJsaW5kYXR1cmEgU1NIIGUnIHNwZW50byBlIGwndXRlbnRlIG5vbiBoYSBwaXUnIHN1ZG8uXG5cblByb2NlZGVyZSBjb211bnF1ZT8iIHx8IHJldHVybiAxCiAgICAgICAgZWxzZSBlcnIgIkNvbXBvbmVudGkgVmVlYW0gbm9uIHRyb3ZhdGk6IGFnZ2l1bmdlcmUgcHJpbWEgaWwgc2VydmVyIGluIFZCUiAobyBMT0NLRE9XTl9GT1JDRT15ZXMpIjsgcmV0dXJuIDE7IGZpCiAgICBlbHNlIG9rICJDb21wb25lbnRpIFZlZWFtIHByZXNlbnRpIjsgZmkKICAgIGlmIGlkICIkdSIgPi9kZXYvbnVsbCAyPiYxOyB0aGVuCiAgICAgICAgaWYgdXNlcl9pbl9zdWRvICIkdSI7IHRoZW4gcnVuIGdwYXNzd2QgLWQgIiR1IiBzdWRvICYmIG9rICIkdSByaW1vc3NvIGRhbCBncnVwcG8gc3VkbyI7IGVsc2UgaW5mbyAiJHUgbm9uIGUnIG5lbCBncnVwcG8gc3VkbyI7IGZpCiAgICAgICAgaWYgKCggISBEUllfUlVOICkpICYmIHN1ZG8gLWwgLVUgIiR1IiAyPi9kZXYvbnVsbCB8IGdyZXAgLXEgJ21heSBydW4nOyB0aGVuIHdhcm4gIiR1IGhhIGFuY29yYSByZWdvbGUgc3VkbyAoY29udHJvbGxhcmUgL2V0Yy9zdWRvZXJzIGUgL2V0Yy9zdWRvZXJzLmQpIjsgZmkKICAgICAgICBpZiBpc195ZXMgIiRDRkdfTE9DS19WRUVBTV9QQVNTV09SRCI7IHRoZW4gcnVuIHBhc3N3ZCAtbCAiJHUiICYmIG9rICJQYXNzd29yZCBkaSAkdSBibG9jY2F0YSAoVmVlYW0gdXNhIGkgY2VydGlmaWNhdGksIG5vbiBsYSBwYXNzd29yZCkiOyBmaQogICAgZWxzZSB3YXJuICJVdGVudGUgJHUgbm9uIHRyb3ZhdG8iOyBmaQogICAgaWYgW1sgLWYgJFNVRE9FUlNfRklMRSBdXTsgdGhlbiBydW4gcm0gLWYgIiRTVURPRVJTX0ZJTEUiICYmIG9rICJSaW1vc3NhIGxhIHJlZ29sYSBzdWRvIGRlbCB0b29sICgkU1VET0VSU19GSUxFKSI7IGZpCiAgICBmb3IgZiBpbiAvcm9vdC8uc3NoL2F1dGhvcml6ZWRfa2V5cyAvaG9tZS8qLy5zc2gvYXV0aG9yaXplZF9rZXlzOyBkbwogICAgICAgIFtbIC1mICRmIF1dICYmIGdyZXAgLXEgIiAkS0VZX0NPTU1FTlRcJCIgIiRmIiB8fCBjb250aW51ZQogICAgICAgIHJ1biBzZWQgLWkgIi8gJEtFWV9DT01NRU5UXCQvZCIgIiRmIiAmJiBvayAiUmltb3NzYSBsYSBjaGlhdmUgU1NIIGRlbCB0b29sIGRhICRmIgogICAgZG9uZQogICAgaWYgaXNfeWVzICIkQ0ZHX1NTSF9ESVNBQkxFIjsgdGhlbgogICAgICAgIG9rICJEaXNhdHRpdm8gU1NIIChyaWF0dGl2YWJpbGUgc29sbyBkYSBjb25zb2xlOiBzdWRvICRJTlNUQUxMX1BBVEggdW5sb2NrKSIKICAgICAgICBydW5fcXVpZXQgc3lzdGVtY3RsIGRpc2FibGUgLS1ub3cgc3NoLnNvY2tldAogICAgICAgIHJ1bl9xdWlldCBzeXN0ZW1jdGwgZGlzYWJsZSAtLW5vdyBzc2guc2VydmljZSB8fCBydW5fcXVpZXQgc3lzdGVtY3RsIGRpc2FibGUgLS1ub3cgc3NoZC5zZXJ2aWNlCiAgICAgICAgaWYgKCggISBEUllfUlVOICkpICYmIHN5c3RlbWN0bCBpcy1lbmFibGVkIC1xIHNzaC5zZXJ2aWNlIDI+L2Rldi9udWxsOyB0aGVuIHdhcm4gInNzaC5zZXJ2aWNlIHJpc3VsdGEgYW5jb3JhIGFiaWxpdGF0byI7IGZpCiAgICBlbHNlIGluZm8gIlNTSCBsYXNjaWF0byBhdHRpdm8gKFNTSF9ESVNBQkxFPW5vKSI7IGZpCiAgICBvayAiQmxpbmRhdHVyYSBjb21wbGV0YXRhIgp9CgpzdGVwX3VubG9jaygpIHsKICAgIHN0ZXAgIlJpYXBlcnR1cmEgdGVtcG9yYW5lYSAoYWdnaW9ybmFtZW50byBjb21wb25lbnRpIFZlZWFtKSIKICAgICgoIElOVEVSQUNUSVZFICkpIHx8IHsgZXJyICJMYSByaWFwZXJ0dXJhIHNpIGZhIHNvbG8gZGEgY29uc29sZSwgaW4gbW9kbyBpbnRlcmF0dGl2byI7IHJldHVybiAxOyB9CiAgICBsb2NhbCB1PSRDRkdfVkVFQU1fVVNFUiBwdwogICAgaWQgIiR1IiA+L2Rldi9udWxsIDI+JjEgfHwgeyBlcnIgIlV0ZW50ZSAkdSBub24gdHJvdmF0byI7IHJldHVybiAxOyB9CiAgICBwdz0kKGFza3B3ICJQYXNzd29yZCB0ZW1wb3JhbmVhIiAiTnVvdmEgcGFzc3dvcmQgcGVyICR1ICh2dW90byA9IGdlbmVyYXRhKSIpIHx8IHJldHVybiAxCiAgICBbWyAteiAkcHcgXV0gJiYgcHc9JChnZW5fcGFzc3dvcmQpCiAgICBpZiAoKCBEUllfUlVOICkpOyB0aGVuIHNpbSAiSW1wb3N0ZXJlaSBsYSBwYXNzd29yZCBkaSAkdSIKICAgIGVsc2UgcHJpbnRmICclczolc1xuJyAiJHUiICIkcHciIHwgY2hwYXNzd2QgJiYgcGFzc3dkIC11ICIkdSIgPi9kZXYvbnVsbCAyPiYxOyBmaQogICAgcnVuIHVzZXJtb2QgLWFHIHN1ZG8gIiR1IgogICAgcnVuX3F1aWV0IHN5c3RlbWN0bCBlbmFibGUgLS1ub3cgc3NoLnNlcnZpY2UgfHwgcnVuIHN5c3RlbWN0bCBlbmFibGUgLS1ub3cgc3NoLnNvY2tldAogICAgb2sgIlJpYXBlcnRvOiBTU0ggYXR0aXZvLCAkdSBuZWwgZ3J1cHBvIHN1ZG8sIHBhc3N3b3JkOiAkcHciCiAgICBpbmZvICJJbiBWQlI6IGFnZ2lvcm5hcmUgaSBjb21wb25lbnRpIGNvbiBjcmVkZW56aWFsaSBzaW5nbGUtdXNlOyBwb2kgcmllc2VndWlyZTogc3VkbyAkSU5TVEFMTF9QQVRIIGxvY2tkb3duIgp9CgpzdGVwX3JlbW92ZV90YXJnZXRzKCkgewogICAgc3RlcCAiRGlzY29ubmVzc2lvbmUgdGFyZ2V0IGlTQ1NJIgogICAgbG9jYWwgcz0oKSBlIHBvcnRhbCBpcW4gY2hvc2VuIHNlbD0oKSBwYXRzIG1udHMKICAgIHdoaWxlIHJlYWQgLXIgcG9ydGFsIGlxbjsgZG8gW1sgLW4gJGlxbiBdXSAmJiBzKz0oIiRwb3J0YWwgJGlxbiIpOyBkb25lIDwgPChpc2NzaV9zZXNzaW9ucykKICAgICgoICR7I3NbQF19ICkpIHx8IHsgaW5mbyAiTmVzc3VuYSBzZXNzaW9uZSBpU0NTSSBhdHRpdmEiOyByZXR1cm4gMDsgfQogICAgaWYgKCggSU5URVJBQ1RJVkUgKSk7IHRoZW4KICAgICAgICBsb2NhbCBhcmdzPSgpCiAgICAgICAgZm9yIGUgaW4gIiR7c1tAXX0iOyBkbyBhcmdzKz0oIiRlIiAiIiBPRkYpOyBkb25lCiAgICAgICAgY2hvc2VuPSQod3QgLS10aXRsZSAiRGlzY29ubmV0dGkgdGFyZ2V0IiAtLXNlcGFyYXRlLW91dHB1dCAtLWNoZWNrbGlzdCAiU2Vzc2lvbmkgZGEgY2hpdWRlcmUgKGxvZ291dCBlZCBlbGltaW5hemlvbmUgZGVsIG5vZG8pOiIgMjAgMTAwIDEwICIke2FyZ3NbQF19IikgfHwgcmV0dXJuIDEKICAgICAgICB3aGlsZSBJRlM9IHJlYWQgLXIgZTsgZG8gW1sgLW4gJGUgXV0gJiYgc2VsKz0oIiRlIik7IGRvbmUgPDw8IiRjaG9zZW4iCiAgICBlbHNlCiAgICAgICAgcGF0cz0kKG5vcm1fbGlzdCAiJHtPUFRfVEFSR0VUOi0kQ0ZHX1JFTU9WRV9UQVJHRVRTfSIpCiAgICAgICAgW1sgLW4gJHBhdHMgXV0gfHwgeyBlcnIgIkluZGljYXJlIGkgdGFyZ2V0IGRhIGRpc2Nvbm5ldHRlcmUgKFJFTU9WRV9UQVJHRVRTIG8gLS10YXJnZXQpIjsgcmV0dXJuIDE7IH0KICAgICAgICBmb3IgZSBpbiAiJHtzW0BdfSI7IGRvCiAgICAgICAgICAgIHJlYWQgLXIgcG9ydGFsIGlxbiA8PDwiJGUiCiAgICAgICAgICAgICMgc2hlbGxjaGVjayBkaXNhYmxlPVNDMjA1MwogICAgICAgICAgICBmb3IgcCBpbiAkcGF0czsgZG8gW1sgJGlxbiA9PSAkcCBdXSAmJiB7IHNlbCs9KCIkZSIpOyBicmVhazsgfTsgZG9uZQogICAgICAgIGRvbmUKICAgIGZpCiAgICAoKCAkeyNzZWxbQF19ICkpIHx8IHsgd2FybiAiTmVzc3VuYSBzZXNzaW9uZSBjb3JyaXNwb25kZSI7IHJldHVybiAwOyB9CiAgICBsb2NhbCByYz0wIHNpZCBkZXYKICAgIGZvciBlIGluICIke3NlbFtAXX0iOyBkbwogICAgICAgIHJlYWQgLXIgcG9ydGFsIGlxbiA8PDwiJGUiCiAgICAgICAgbW50cz0iIgogICAgICAgIGZvciBzaWQgaW4gL3N5cy9jbGFzcy9pc2NzaV9zZXNzaW9uL3Nlc3Npb24qOyBkbwogICAgICAgICAgICBbWyAkKGNhdCAiJHNpZC90YXJnZXRuYW1lIiAyPi9kZXYvbnVsbCkgPT0gIiRpcW4iIF1dIHx8IGNvbnRpbnVlCiAgICAgICAgICAgIGZvciBkZXYgaW4gIiRzaWQiL2RldmljZS90YXJnZXQqLyovYmxvY2svKjsgZG8KICAgICAgICAgICAgICAgIFtbIC1lICRkZXYgXV0gJiYgbW50cys9JChsc2JsayAtbmxwbyBNT1VOVFBPSU5UICIvZGV2LyR7ZGV2IyMqL30iIDI+L2Rldi9udWxsIHwgYXdrICdORicgfCB0ciAnXG4nICcgJykKICAgICAgICAgICAgZG9uZQogICAgICAgIGRvbmUKICAgICAgICBpZiBbWyAtbiAkKHRyaW0gIiRtbnRzIikgXV07IHRoZW4gZXJyICIkaXFuIGhhIGRpc2NoaSBtb250YXRpICgkbW50cyk6IHNtb250YXJsaSBlIHRvZ2xpZXJlIGxlIHJpZ2hlIGRhIC9ldGMvZnN0YWIgcHJpbWEiOyByYz0xOyBjb250aW51ZTsgZmkKICAgICAgICBydW4gaXNjc2lhZG0gLW0gbm9kZSAtVCAiJGlxbiIgLXAgIiRwb3J0YWwiIC11ICYmIG9rICJMb2dvdXQ6ICRpcW4gQCAkcG9ydGFsIgogICAgICAgIHJ1biBpc2NzaWFkbSAtbSBub2RlIC1UICIkaXFuIiAtcCAiJHBvcnRhbCIgLW8gZGVsZXRlICYmIG9rICJOb2RvIGVsaW1pbmF0bzogJGlxbiBAICRwb3J0YWwiCiAgICAgICAgaWYgaXNfeWVzICIkQ0ZHX1JFTU9WRV9ESVNDT1ZFUlkiOyB0aGVuIHJ1bl9xdWlldCBpc2NzaWFkbSAtbSBkaXNjb3ZlcnlkYiAtdCBzZW5kdGFyZ2V0cyAtcCAiJHBvcnRhbCIgLW8gZGVsZXRlICYmIGluZm8gIkRpc2NvdmVyeSBlbGltaW5hdGE6ICRwb3J0YWwiOyBmaQogICAgZG9uZQogICAgcmV0dXJuICRyYwp9CgpzdGVwX2luc3RhbGxfYWNjZXNzKCkgewogICAgc3RlcCAiSW5zdGFsbGF6aW9uZSBkZWwgdG9vbCBlIGFjY2Vzc28gcGVyIGxhIEdVSSIKICAgIGxvY2FsIGFkbWluPSR7Q0ZHX0FETUlOX1VTRVI6LSR7U1VET19VU0VSOi19fSBzcmMKICAgIHNyYz0kKHJlYWRsaW5rIC1mICIkMCIpCiAgICBbWyAtbiAkYWRtaW4gJiYgJGFkbWluICE9IHJvb3QgXV0gfHwgeyBlcnIgIkVzZWd1aXJlIGNvbiBzdWRvIGRhbGwndXRlbnRlIGFtbWluaXN0cmF0b3JlIChTVURPX1VTRVIgbm9uIGRpc3BvbmliaWxlKSI7IHJldHVybiAxOyB9CiAgICB2YWxpZF91c2VyICIkYWRtaW4iIHx8IHsgZXJyICJVdGVudGUgYW1taW5pc3RyYXRvcmUgbm9uIHZhbGlkbzogJGFkbWluIjsgcmV0dXJuIDE7IH0KICAgIGlmIFtbICRzcmMgIT0gIiRJTlNUQUxMX1BBVEgiIF1dOyB0aGVuIHJ1biBpbnN0YWxsIC1vIHJvb3QgLWcgcm9vdCAtbSAwNzU1ICIkc3JjIiAiJElOU1RBTExfUEFUSCIgfHwgcmV0dXJuIDE7IG9rICJTY3JpcHQgaW5zdGFsbGF0byBpbiAkSU5TVEFMTF9QQVRIIjsgZmkKICAgIGxvY2FsIHJ1bGU9IiRhZG1pbiBBTEw9KHJvb3QpIE5PUEFTU1dEOiAkSU5TVEFMTF9QQVRIIgogICAgaWYgKCggRFJZX1JVTiApKTsgdGhlbiBzaW0gIlJlZ29sYSBzdWRvOiAkcnVsZSI7IHJldHVybiAwOyBmaQogICAgbG9jYWwgdG1wOyB0bXA9JChta3RlbXApCiAgICBwcmludGYgJyMgdnJlcG8tc2V0dXA6IGxhIEdVSSBlc2VndWUgc29sbyBxdWVzdG8gc2NyaXB0IHNlbnphIHBhc3N3b3JkLiBSaW1vc3NhIGRhbGxhIGJsaW5kYXR1cmEuXG4lc1xuJyAiJHJ1bGUiID4iJHRtcCIKICAgIGlmIHZpc3VkbyAtY2YgIiR0bXAiID4vZGV2L251bGwgMj4mMTsgdGhlbiBpbnN0YWxsIC1vIHJvb3QgLWcgcm9vdCAtbSAwNDQwICIkdG1wIiAiJFNVRE9FUlNfRklMRSIgJiYgb2sgIlJlZ29sYSBzdWRvOiAkcnVsZSIKICAgIGVsc2UgZXJyICJSZWdvbGEgc3VkbyBub24gdmFsaWRhLCBub24gaW5zdGFsbGF0YSI7IHJtIC1mICIkdG1wIjsgcmV0dXJuIDE7IGZpCiAgICBybSAtZiAiJHRtcCIKfQoKc3RlcF9zdGF0dXMoKSB7CiAgICBzdGVwICJTdGF0byBkZWwgc2VydmVyICQoaG9zdG5hbWUpIgogICAgbG9jYWwgaWQgdmVyIHByZXR0eSByIGQgayB3IHN6IG1vIHAgdCBzdCBmcyBtbnQgbm0gdT0kQ0ZHX1ZFRUFNX1VTRVIKICAgIElGUz0nfCcgcmVhZCAtciBpZCB2ZXIgcHJldHR5IDw8PCIkKG9zX2luZm8pIgogICAgaW5mbyAiU2lzdGVtYTogJHByZXR0eSwga2VybmVsICQodW5hbWUgLXIpLCBJUDogJChob3N0bmFtZSAtSSAyPi9kZXYvbnVsbCB8IHhhcmdzKSIKICAgIGluZm8gIk9yYTogJChkYXRlICcrJUYgJVQgJVonKSwgTlRQIHNpbmNyb25penphdG86ICQodGltZWRhdGVjdGwgc2hvdyAtcCBOVFBTeW5jaHJvbml6ZWQgLS12YWx1ZSAyPi9kZXYvbnVsbCkiCiAgICBpbmZvICJJbml0aWF0b3JOYW1lOiAkKHNlZCAtbiAncy9eSW5pdGlhdG9yTmFtZT0vL3AnIC9ldGMvaXNjc2kvaW5pdGlhdG9ybmFtZS5pc2NzaSAyPi9kZXYvbnVsbCkiCiAgICBpbmZvICJTZXNzaW9uaSBpU0NTSTogJChzZXNzaW9uX2NvdW50KSIKICAgIGlzY3NpX3Nlc3Npb25zIHwgd2hpbGUgcmVhZCAtciBwIHc7IGRvIFtbIC1uICR3IF1dICYmIGluZm8gIiAgJHcgQCAkcCI7IGRvbmUKICAgIGlmIHN5c3RlbWN0bCBpcy1hY3RpdmUgLXEgbXVsdGlwYXRoZCAyPi9kZXYvbnVsbDsgdGhlbiBpbmZvICJtdWx0aXBhdGhkIGF0dGl2bywgbWFwcGU6ICQobXVsdGlwYXRoIC1sIDI+L2Rldi9udWxsIHwgZ3JlcCAtYyAnZG0tJykiOyBlbHNlIGluZm8gIm11bHRpcGF0aGQgbm9uIGF0dGl2byI7IGZpCiAgICBzY2FuX2x1bnMKICAgIGluZm8gIkRpc2NoaSB1dGlsaXp6YWJpbGkgKGVzY2x1c2kgcXVlbGxpIGRpIHNpc3RlbWEpOiAkeyNMVU5TW0BdfSIKICAgIGZvciByIGluICIke0xVTlNbQF19IjsgZG8gaW5mbyAiICAkKGx1bl9sYWJlbCAiJHIiKSI7IGRvbmUKICAgIGlmIFtbIC1zICRTVEFURV9SRVBPUyBdXTsgdGhlbgogICAgICAgIHdoaWxlIElGUz0nfCcgcmVhZCAtciBubSB3IGQgbW50OyBkbwogICAgICAgICAgICBpZiBtb3VudHBvaW50IC1xICIkbW50IiAyPi9kZXYvbnVsbDsgdGhlbgogICAgICAgICAgICAgICAgbG9jYWwgb3duOyBvd249JChzdGF0IC1jICclVSAlYScgIiRtbnQiKQogICAgICAgICAgICAgICAgbG9jYWwgcmY7IHJmPSQoeGZzX2luZm8gIiRtbnQiIDI+L2Rldi9udWxsIHwgZ3JlcCAtbyAncmVmbGluaz1bMDFdJykKICAgICAgICAgICAgICAgIG9rICJSZXBvc2l0b3J5ICRubSBzdSAkbW50OiAkKGRmIC1oIC0tb3V0cHV0PXNpemUsYXZhaWwgIiRtbnQiIHwgdGFpbCAtbiAxIHwgeGFyZ3MpLCBvd25lci9wZXJtZXNzaSAkb3duLCAkcmYiCiAgICAgICAgICAgIGVsc2UgZXJyICJSZXBvc2l0b3J5ICRubTogJG1udCBOT04gbW9udGF0byI7IGZpCiAgICAgICAgZG9uZSA8IiRTVEFURV9SRVBPUyIKICAgIGZpCiAgICBpZiBpZCAiJHUiID4vZGV2L251bGwgMj4mMTsgdGhlbgogICAgICAgIGxvY2FsIHBzdDsgcHN0PSQocGFzc3dkIC1TICIkdSIgMj4vZGV2L251bGwgfCBhd2sgJ3twcmludCAkMn0nKQogICAgICAgIGluZm8gIlV0ZW50ZSAkdTogc3VkbyAkKHVzZXJfaW5fc3VkbyAiJHUiICYmIGVjaG8gU0kgfHwgZWNobyBubyksIHBhc3N3b3JkICQoIFtbICRwc3QgPT0gTCBdXSAmJiBlY2hvIGJsb2NjYXRhIHx8IGVjaG8gYXR0aXZhKSIKICAgIGVsc2UgaW5mbyAiVXRlbnRlICR1IG5vbiBwcmVzZW50ZSI7IGZpCiAgICBpbmZvICJDb21wb25lbnRpIFZlZWFtOiAkKHZlZWFtX3ByZXNlbnQgJiYgZWNobyBwcmVzZW50aSB8fCBlY2hvIGFzc2VudGkpIgogICAgaW5mbyAiU1NIOiAkKHN5c3RlbWN0bCBpcy1hY3RpdmUgc3NoLnNlcnZpY2UgMj4vZGV2L251bGwpIC8gc29ja2V0ICQoc3lzdGVtY3RsIGlzLWFjdGl2ZSBzc2guc29ja2V0IDI+L2Rldi9udWxsKSwgcmVnb2xhIHN1ZG8gZGVsIHRvb2w6ICQoW1sgLWYgJFNVRE9FUlNfRklMRSBdXSAmJiBlY2hvIHByZXNlbnRlIHx8IGVjaG8gYXNzZW50ZSkiCn0KCiMgb3V0cHV0IGEgcmlnaGUgcGVyIGxhIEdVSTogVElQT3xjYW1waS4uLgpzdGVwX3NjYW4oKSB7CiAgICBsb2NhbCBpZCB2ZXIgcHJldHR5IHIgZCBrIHcgc3ogbW8gcCB0IHN0IGZzIG1udCBubSB1PSRDRkdfVkVFQU1fVVNFUgogICAgSUZTPSd8JyByZWFkIC1yIGlkIHZlciBwcmV0dHkgPDw8IiQob3NfaW5mbykiCiAgICBlY2hvICJWRVJ8JFZFUlNJT04iCiAgICBlY2hvICJIT1NUfCQoaG9zdG5hbWUpfCRwcmV0dHl8JChob3N0bmFtZSAtSSAyPi9kZXYvbnVsbCB8IHhhcmdzKSIKICAgIGVjaG8gIklOSVRJQVRPUnwkKHNlZCAtbiAncy9eSW5pdGlhdG9yTmFtZT0vL3AnIC9ldGMvaXNjc2kvaW5pdGlhdG9ybmFtZS5pc2NzaSAyPi9kZXYvbnVsbCkiCiAgICBsb2NhbCBwa3M9b2s7IGZvciBwIGluIG9wZW4taXNjc2kgeGZzcHJvZ3MgcGFydGVkOyBkbyBwa2dfaW5zdGFsbGVkICIkcCIgfHwgcGtzPXRvZG87IGRvbmUKICAgIGVjaG8gIlNURVB8UEFDS0FHRVN8JHBrc3xvcGVuLWlzY3NpLCB4ZnNwcm9ncywgcGFydGVkJChwa2dfaW5zdGFsbGVkIG11bHRpcGF0aC10b29scyAmJiBlY2hvICcsIG11bHRpcGF0aC10b29scycpIgogICAgbG9jYWwgc3k7IHN5PSQodGltZWRhdGVjdGwgc2hvdyAtcCBOVFBTeW5jaHJvbml6ZWQgLS12YWx1ZSAyPi9kZXYvbnVsbCkKICAgIGVjaG8gIlNURVB8TlRQfCQoW1sgJHN5ID09IHllcyBdXSAmJiBlY2hvIG9rIHx8IGVjaG8gdG9kbyl8TlRQIHNpbmNyb25penphdG86ICR7c3k6LT99LCAkKGRhdGUgJyslRiAlVCAlWicpIgogICAgbG9jYWwgbnM9dG9kbzsgZ3JlcCAtcUUgJ15bWzpzcGFjZTpdXSpub2RlXC5zdGFydHVwW1s6c3BhY2U6XV0qPVtbOnNwYWNlOl1dKmF1dG9tYXRpYycgL2V0Yy9pc2NzaS9pc2NzaWQuY29uZiAyPi9kZXYvbnVsbCAmJiBucz1vawogICAgZWNobyAiU1RFUHxJTklUSUFUT1J8JG5zfG5vZGUuc3RhcnR1cCBhdXRvbWF0aWM6ICRucyIKICAgIGxvY2FsIHNjOyBzYz0kKHNlc3Npb25fY291bnQpCiAgICBlY2hvICJTVEVQfFRBUkdFVFN8JCggKChzYyA+IDApKSAmJiBlY2hvIG9rIHx8IGVjaG8gdG9kbyl8c2Vzc2lvbmkgYXR0aXZlOiAkc2MiCiAgICBsb2NhbCBtcGM9dG9kbzsgZ3JlcCAtcUYgIiRNUF9NQVJLIiAvZXRjL211bHRpcGF0aC5jb25mIDI+L2Rldi9udWxsICYmIHN5c3RlbWN0bCBpcy1hY3RpdmUgLXEgbXVsdGlwYXRoZCAyPi9kZXYvbnVsbCAmJiBtcGM9b2sKICAgIGVjaG8gIlNURVB8TVVMVElQQVRIfCRtcGN8bXVsdGlwYXRoLmNvbmYgZGVsIHRvb2w6ICRtcGMsIExVTiBjb24gcGl1JyBwZXJjb3JzaTogJChkZXRlY3RfbXVsdGlfcGF0aHMpIgogICAgbG9jYWwgdXM9dG9kbzsgaWQgIiR1IiA+L2Rldi9udWxsIDI+JjEgJiYgdXM9b2sKICAgIGVjaG8gIlNURVB8VVNFUnwkdXN8dXRlbnRlICR1OiAkdXMkKGlkICIkdSIgPi9kZXYvbnVsbCAyPiYxICYmIHVzZXJfaW5fc3VkbyAiJHUiICYmIGVjaG8gJywgaW4gc3VkbycpIgogICAgZWNobyAiU1RFUHxMT0NLRE9XTnx0b2RvfGNvbXBvbmVudGkgVmVlYW06ICQodmVlYW1fcHJlc2VudCAmJiBlY2hvIHByZXNlbnRpIHx8IGVjaG8gYXNzZW50aSkiCiAgICB3aGlsZSByZWFkIC1yIHAgdzsgZG8gW1sgLW4gJHcgXV0gJiYgZWNobyAiU0VTU0lPTnwkcHwkdyI7IGRvbmUgPCA8KGlzY3NpX3Nlc3Npb25zKQogICAgaWYgW1sgLW4gJChub3JtX2xpc3QgIiRDRkdfSVNDU0lfUE9SVEFMUyIpIF1dOyB0aGVuCiAgICAgICAgZGlzY292ZXJfdGFyZ2V0cyAxIDI+L2Rldi9udWxsCiAgICAgICAgZm9yIHIgaW4gIiR7RElTQ1tAXX0iOyBkbyByZWFkIC1yIHAgdyA8PDwiJHIiOyBlY2hvICJUQVJHRVR8JHB8JHciOyBkb25lCiAgICBmaQogICAgc2Nhbl9sdW5zCiAgICBmb3IgciBpbiAiJHtMVU5TW0BdfSI7IGRvIGVjaG8gIkxVTnwkciI7IGRvbmUKICAgIFtbIC1zICRTVEFURV9SRVBPUyBdXSAmJiB3aGlsZSBJRlM9J3wnIHJlYWQgLXIgbm0gdyBkIG1udDsgZG8gZWNobyAiUkVQT3wkbm18JHd8JG1udHwkKG1vdW50cG9pbnQgLXEgIiRtbnQiIDI+L2Rldi9udWxsICYmIGVjaG8gbW9udGF0byB8fCBlY2hvIHNtb250YXRvKSI7IGRvbmUgPCIkU1RBVEVfUkVQT1MiCiAgICByZXR1cm4gMAp9CgpzdGVwX3ByZXBhcmUoKSB7CiAgICBsb2NhbCByYz0wCiAgICBzdGVwX3BhY2thZ2VzIHx8IHJldHVybiAxCiAgICBzdGVwX250cAogICAgc3RlcF9pbml0aWF0b3IgfHwgcmV0dXJuIDEKICAgIHN0ZXBfdGFyZ2V0cyB8fCByZXR1cm4gMQogICAgc3RlcF9tdWx0aXBhdGggfHwgcmM9MQogICAgaWYgKCggQVNTVU1FX1lFUyApKTsgdGhlbiBzdGVwX2x1bnNfYXV0byB8fCByYz0xCiAgICBlbHNlIGluZm8gIkxVTjogbmVzc3VuYSBmb3JtYXR0YXRhIHNlbnphIC0teWVzICh1c2FyZSBpbCBjb21hbmRvICdsdW4nIG8gJ2x1bnMgLS15ZXMnKSI7IGZpCiAgICBzdGVwX3VzZXIgfHwgcmM9MQogICAgcmV0dXJuICRyYwp9CgojID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0gV0laQVJECndpemFyZF9uZXR3b3JrKCkgewogICAgbG9jYWwgY3VyIHYKICAgIGN1cj0kKHNlZCAtbiAncy9eSW5pdGlhdG9yTmFtZT0vL3AnIC9ldGMvaXNjc2kvaW5pdGlhdG9ybmFtZS5pc2NzaSAyPi9kZXYvbnVsbCkKICAgIHY9JChhc2sgIkluaXRpYXRvciBpU0NTSSIgIkluaXRpYXRvck5hbWUgZGkgcXVlc3RvIHNlcnZlciAodmEgYXV0b3JpenphdG8gc3VsIE5BUy90YXJnZXQpLlxuTGFzY2lhcmUgcXVlbGxvIHByb3Bvc3RvIHBlciBub24gY2FtYmlhcmxvLiIgIiR7Q0ZHX0lOSVRJQVRPUl9OQU1FOi0kY3VyfSIpIHx8IHJldHVybiAxCiAgICBbWyAkdiA9PSAiJGN1ciIgXV0gJiYgdj0iIgogICAgQ0ZHX0lOSVRJQVRPUl9OQU1FPSR2CiAgICB2PSQoYXNrICJQb3J0YWxpIGlTQ1NJIiAiSVAgZGVsIHRhcmdldCBzZXBhcmF0aSBkYSBzcGF6aW8uXG5Db24gbXVsdGlwYXRoOiB1biBJUCBwZXIgb2duaSBwZXJjb3JzbyAoZXMuIDEwLjEwLjEuMTAgMTAuMTAuMi4xMCkuIiAiJENGR19JU0NTSV9QT1JUQUxTIikgfHwgcmV0dXJuIDEKICAgIENGR19JU0NTSV9QT1JUQUxTPSQobm9ybV9saXN0ICIkdiIpCiAgICB2PSQoYXNrICJQb3J0YSBpU0NTSSIgIlBvcnRhIFRDUCBkZWwgdGFyZ2V0IiAiJENGR19JU0NTSV9QT1JUIikgfHwgcmV0dXJuIDEKICAgIENGR19JU0NTSV9QT1JUPSR2CiAgICB2PSQoYXNrICJUYXJnZXQiICJJUU4gZGEgdXNhcmUsIGFuY2hlIGNvbiAqIChlcy4gaXFuLjIwMDQtMDQuY29tLnFuYXA6KnZlZWFtKikuXG5WdW90byA9IHNjZWxnbyBkYWxsJ2VsZW5jbyBzY29wZXJ0by4iICIkQ0ZHX0lTQ1NJX1RBUkdFVFMiKSB8fCByZXR1cm4gMQogICAgQ0ZHX0lTQ1NJX1RBUkdFVFM9JHYKICAgIGlmIG5veWVzICJDSEFQIiAiSWwgdGFyZ2V0IHJpY2hpZWRlIGF1dGVudGljYXppb25lIENIQVA/IjsgdGhlbgogICAgICAgIENGR19DSEFQX1VTRVI9JChhc2sgIkNIQVAiICJVdGVudGUgQ0hBUCIgIiRDRkdfQ0hBUF9VU0VSIikgfHwgcmV0dXJuIDEKICAgICAgICBDRkdfQ0hBUF9QQVNTV09SRD0kKGFza3B3ICJDSEFQIiAiUGFzc3dvcmQgQ0hBUCAoMTItMTYgY2FyYXR0ZXJpIHN1IFFOQVApIikgfHwgcmV0dXJuIDEKICAgIGVsc2UgQ0ZHX0NIQVBfVVNFUj0iIjsgQ0ZHX0NIQVBfUEFTU1dPUkQ9IiI7IGZpCiAgICB2YWxpZGF0ZV9jb25maWcgfHwgeyBtc2cgIkVycm9yZSIgIlZhbG9yaSBub24gdmFsaWRpOiB2ZWRlcmUgaSBtZXNzYWdnaSBuZWwgdGVybWluYWxlLiI7IHJldHVybiAxOyB9Cn0KCndpemFyZF9udHAoKSB7CiAgICBsb2NhbCB2CiAgICB2PSQoYXNrICJPcmEgZGkgc2lzdGVtYSIgIlNlcnZlciBOVFAgc2VwYXJhdGkgZGEgc3BhemlvICh2dW90byA9IHByZWRlZmluaXRpIGRpIFVidW50dSkuXG5Db24gbCdpbW11dGFiaWxpdGEnIGwnb3JvbG9naW8gY29ycmV0dG8gZScgZXNzZW56aWFsZS4iICIkQ0ZHX05UUF9TRVJWRVJTIikgfHwgcmV0dXJuIDEKICAgIENGR19OVFBfU0VSVkVSUz0kdgogICAgdj0kKGFzayAiRnVzbyBvcmFyaW8iICJGdXNvIG9yYXJpbyAodnVvdG8gPSBub24gY2FtYmlhcmUpLiBBdHR1YWxlOiAkKHRpbWVkYXRlY3RsIHNob3cgLXAgVGltZXpvbmUgLS12YWx1ZSAyPi9kZXYvbnVsbCkiICIkQ0ZHX1RJTUVaT05FIikgfHwgcmV0dXJuIDEKICAgIENGR19USU1FWk9ORT0kdgp9Cgp3aXphcmRfbXVsdGlwYXRoKCkgewogICAgbG9jYWwgbiBjaCBkZWY9bm8KICAgIG49JChkZXRlY3RfbXVsdGlfcGF0aHMpCiAgICAoKCBuID4gMCApKSAmJiBkZWY9cW5hcAogICAgY2g9JCh3dCAtLXRpdGxlICJNdWx0aXBhdGgiIC0tZGVmYXVsdC1pdGVtICIkZGVmIiAtLW1lbnUgIkxVTiB2aXN0ZSBzdSBwaXUnIHBlcmNvcnNpOiAkblxuU2NlZ2xpIGxhIGNvbmZpZ3VyYXppb25lOiIgMTYgNzggNCBcCiAgICAgICAgcW5hcCAiUHJvZmlsbyBRTkFQIChyb3VuZC1yb2JpbiwgbXVsdGlidXMsIGFsdWEpIiBcCiAgICAgICAgZ2VuZXJpYyAiUHJvZmlsbyBnZW5lcmljbyAoaW1wb3N0YXppb25pIGRpIGRlZmF1bHQpIiBcCiAgICAgICAgbm8gIk5lc3N1biBtdWx0aXBhdGgiKSB8fCByZXR1cm4gMQogICAgaWYgW1sgJGNoID09IG5vIF1dOyB0aGVuIENGR19NVUxUSVBBVEg9bm87IGVsc2UgQ0ZHX01VTFRJUEFUSD15ZXM7IENGR19NVUxUSVBBVEhfUFJPRklMRT0kY2g7IGZpCiAgICBpZiBbWyAkQ0ZHX01VTFRJUEFUSCA9PSB5ZXMgXV07IHRoZW4KICAgICAgICBpZiB5ZXNubyAiQWxpYXMiICJEYXJlIGFsbGUgTFVOIG11bHRpcGF0aCBpbCBub21lIGRlbCByZXBvc2l0b3J5ICgvZGV2L21hcHBlci88bm9tZT4pIGludmVjZSBkaSBtcGF0aGEsIG1wYXRoYi4uLj8iOyB0aGVuIENGR19NVUxUSVBBVEhfQUxJQVM9eWVzOyBlbHNlIENGR19NVUxUSVBBVEhfQUxJQVM9bm87IGZpCiAgICBmaQp9Cgp3aXphcmRfbHVucygpIHsKICAgIHNjYW5fbHVucwogICAgaWYgKCggJHsjTFVOU1tAXX0gPT0gMCApKTsgdGhlbiBtc2cgIkxVTiIgIk5lc3N1biBkaXNjbyB1dGlsaXp6YWJpbGUgdHJvdmF0byAoZGlzY2hpIGRpIHNpc3RlbWEgZXNjbHVzaSkuXG5Db250cm9sbGFyZSBsb2dpbiBpU0NTSSBlIG11bHRpcGF0aC4iOyByZXR1cm4gMTsgZmkKICAgIGxvY2FsIGFyZ3M9KCkgciBkIGsgdyBzdCBzZWwgbmFtZXM9KCkgbXBzPSgpIGRldnM9KCkgZm9yY2U9KCkgbiBtIHBsYW49IiIgaSB2CiAgICBmb3IgciBpbiAiJHtMVU5TW0BdfSI7IGRvCiAgICAgICAgSUZTPSd8JyByZWFkIC1yIGQgayB3IF8gXyBfIF8gc3QgXyA8PDwiJHIiCiAgICAgICAgW1sgJHN0ID09IGNvbmZpZ3VyYXRvIF1dICYmIGNvbnRpbnVlCiAgICAgICAgYXJncys9KCIkZCIgIiQobHVuX2xhYmVsICIkciIgfCBjdXQgLWMyNC0pIiAiJChbWyAkc3QgPT0gbGliZXJvIF1dICYmIGVjaG8gT04gfHwgZWNobyBPRkYpIikKICAgIGRvbmUKICAgICgoICR7I2FyZ3NbQF19ICkpIHx8IHsgbXNnICJMVU4iICJUdXR0aSBpIGRpc2NoaSBzb25vIGdpYScgY29uZmlndXJhdGkgY29tZSByZXBvc2l0b3J5LiI7IHJldHVybiAwOyB9CiAgICBzZWw9JCh3dCAtLXRpdGxlICJMVU4gZGEgcHJlcGFyYXJlIiAtLXNlcGFyYXRlLW91dHB1dCAtLWNoZWNrbGlzdCAiTGUgTFVOIHNlbGV6aW9uYXRlIHZlcnJhbm5vIFBBUlRJWklPTkFURSBlIEZPUk1BVFRBVEUgaW4gWEZTLlxuUXVlbGxlIElOIFVTTyBjb250ZW5nb25vIGRhdGkuIiAyMiAxMDAgMTIgIiR7YXJnc1tAXX0iKSB8fCByZXR1cm4gMQogICAgW1sgLW4gJHNlbCBdXSB8fCByZXR1cm4gMAogICAgdj0kKGFzayAiUHVudGkgZGkgbW91bnQiICJDYXJ0ZWxsYSBiYXNlIGRlaSBwdW50aSBkaSBtb3VudCIgIiRDRkdfTU9VTlRfQkFTRSIpIHx8IHJldHVybiAxCiAgICBDRkdfTU9VTlRfQkFTRT0kdgogICAgUkVTRVJWRURfTkFNRVM9IiIKICAgIHdoaWxlIElGUz0gcmVhZCAtciBkOyBkbwogICAgICAgIFtbIC1uICRkIF1dIHx8IGNvbnRpbnVlCiAgICAgICAgcj0kKGZpbmRfbHVuICIkZCIpOyBJRlM9J3wnIHJlYWQgLXIgZCBrIHcgXyBfIF8gXyBzdCBfIDw8PCIkciIKICAgICAgICBuPSQoY29uZmlndXJlZF9uYW1lX2ZvciAiJHciICIkayIpIHx8IG49JChzdWdnZXN0X25hbWUpCiAgICAgICAgbj0kKGFzayAiTm9tZSBMVU4iICIkKGx1bl9sYWJlbCAiJHIiKVxuXG5Ob21lIGRlbCByZXBvc2l0b3J5IChldGljaGV0dGEgWEZTLCBhbGlhcyBtdWx0aXBhdGgsIGNhcnRlbGxhKToiICIkbiIpIHx8IHJldHVybiAxCiAgICAgICAgdmFsaWRfbmFtZSAiJG4iIHx8IHsgbXNnICJFcnJvcmUiICJOb21lIG5vbiB2YWxpZG86ICRuIjsgcmV0dXJuIDE7IH0KICAgICAgICBSRVNFUlZFRF9OQU1FUys9IiAkbiIKICAgICAgICBtPSQoYXNrICJQdW50byBkaSBtb3VudCIgIlB1bnRvIGRpIG1vdW50IHBlciAkbiIgIiRDRkdfTU9VTlRfQkFTRS8kbiIpIHx8IHJldHVybiAxCiAgICAgICAgaWYgW1sgJHN0ID09IGluX3VzbyBdXTsgdGhlbgogICAgICAgICAgICBub3llcyAiQVRURU5aSU9ORSIgIiRkIGNvbnRpZW5lIGRhdGkgbyBwYXJ0aXppb25pLlxuXG4kKGx1bl9sYWJlbCAiJHIiKVxuXG5DYW5jZWxsYXJlIFRVVFRPIGlsIGNvbnRlbnV0bz8iIHx8IGNvbnRpbnVlCiAgICAgICAgICAgIGZvcmNlKz0oInllcyIpCiAgICAgICAgZWxzZSBmb3JjZSs9KCJubyIpOyBmaQogICAgICAgIGRldnMrPSgiJGQiKTsgbmFtZXMrPSgiJG4iKTsgbXBzKz0oIiRtIikKICAgICAgICBwbGFuKz0iJGQgLT4gJG4gc3UgJG1cbiIKICAgIGRvbmUgPDw8IiRzZWwiCiAgICAoKCAkeyNkZXZzW0BdfSApKSB8fCByZXR1cm4gMAogICAgdj0kKGFzayAiQ29uZmVybWEiICJWZXJyYW5ubyBjYW5jZWxsYXRlIGUgZm9ybWF0dGF0ZTpcblxuJHBsYW5cblNjcml2aSBGT1JNQVRUQSBwZXIgcHJvY2VkZXJlOiIgIiIpIHx8IHJldHVybiAxCiAgICBbWyAkdiA9PSBGT1JNQVRUQSBdXSB8fCB7IG1zZyAiTFVOIiAiQW5udWxsYXRvOiBuZXNzdW5hIG1vZGlmaWNhLiI7IHJldHVybiAxOyB9CiAgICBjbGVhcgogICAgbG9jYWwgc2F2ZWY9JENGR19GT1JDRV9GT1JNQVQKICAgIGZvciBpIGluICIkeyFkZXZzW0BdfSI7IGRvCiAgICAgICAgQ0ZHX0ZPUkNFX0ZPUk1BVD0ke2ZvcmNlW2ldfQogICAgICAgIGNvbmZpZ3VyZV9sdW4gIiR7ZGV2c1tpXX0iICIke25hbWVzW2ldfSIgIiR7bXBzW2ldfSIKICAgIGRvbmUKICAgIENGR19GT1JDRV9GT1JNQVQ9JHNhdmVmCiAgICBwYXVzZQp9Cgp3aXphcmRfdXNlcigpIHsKICAgIGxvY2FsIHYgcHcgcHcyCiAgICB2PSQoYXNrICJVdGVudGUgVmVlYW0iICJVdGVudGUgbG9jYWxlIHVzYXRvIGRhIFZlZWFtIHBlciBpbCByZXBvc2l0b3J5IiAiJENGR19WRUVBTV9VU0VSIikgfHwgcmV0dXJuIDEKICAgIHZhbGlkX3VzZXIgIiR2IiB8fCB7IG1zZyAiRXJyb3JlIiAiTm9tZSB1dGVudGUgbm9uIHZhbGlkbzogJHYiOyByZXR1cm4gMTsgfQogICAgQ0ZHX1ZFRUFNX1VTRVI9JHYKICAgIHB3PSQoYXNrcHcgIlBhc3N3b3JkIiAiUGFzc3dvcmQgcGVyICR2ICh2dW90byA9IGdlbmVyYXRhLCBvcHB1cmUgaW52YXJpYXRhIHNlIGVzaXN0ZSBnaWEnKSIpIHx8IHJldHVybiAxCiAgICBpZiBbWyAtbiAkcHcgXV07IHRoZW4KICAgICAgICBwdzI9JChhc2twdyAiUGFzc3dvcmQiICJSaXBldGkgbGEgcGFzc3dvcmQiKSB8fCByZXR1cm4gMQogICAgICAgIFtbICRwdyA9PSAiJHB3MiIgXV0gfHwgeyBtc2cgIkVycm9yZSIgIkxlIHBhc3N3b3JkIG5vbiBjb2luY2lkb25vLiI7IHJldHVybiAxOyB9CiAgICBmaQogICAgQ0ZHX1ZFRUFNX1BBU1NXT1JEPSRwdwogICAgY2xlYXI7IHN0ZXBfdXNlcjsgQ0ZHX1ZFRUFNX1BBU1NXT1JEPSIiOyBwYXVzZQp9Cgp3aXphcmRfZnVsbCgpIHsKICAgIGxvY2FsIGlwcyBjdXIKICAgIGlwcz0kKGhvc3RuYW1lIC1JIDI+L2Rldi9udWxsIHwgeGFyZ3MpCiAgICBjdXI9JChzZWQgLW4gJ3MvXkluaXRpYXRvck5hbWU9Ly9wJyAvZXRjL2lzY3NpL2luaXRpYXRvcm5hbWUuaXNjc2kgMj4vZGV2L251bGwpCiAgICBtc2cgIkNvbmZpZ3VyYXppb25lIGd1aWRhdGEiICJTZXJ2ZXI6ICQoaG9zdG5hbWUpICAoJGlwcylcblNpc3RlbWE6ICQob3NfaW5mbyB8IGN1dCAtZCd8JyAtZjMpXG5Jbml0aWF0b3JOYW1lOiAke2N1cjotKG9wZW4taXNjc2kgbm9uIGluc3RhbGxhdG8pfVxuXG5QYXNzaTpcbiAxLiBwYWNjaGV0dGkgZSBvcmEgZGkgc2lzdGVtYVxuIDIuIGluaXRpYXRvciBlIHRhcmdldCBpU0NTSVxuIDMuIG11bHRpcGF0aFxuIDQuIExVTjogR1BULCBYRlMgcmVmbGluaywgZnN0YWIsIG1vdW50IHByb3RldHRvXG4gNS4gdXRlbnRlIFZlZWFtIGNvbiBzdWRvIHRlbXBvcmFuZW9cblxuRG9wbyBsJ2FnZ2l1bnRhIGluIFZCUjogQmxpbmRhdHVyYSBkYWwgbWVudS5cblNpbXVsYXppb25lOiAkKCAoKERSWV9SVU4pKSAmJiBlY2hvIEFUVElWQSB8fCBlY2hvIG5vKSIgfHwgcmV0dXJuCiAgICB3aXphcmRfbmV0d29yayB8fCByZXR1cm4KICAgIHdpemFyZF9udHAgfHwgcmV0dXJuCiAgICBjbGVhcgogICAgc3RlcF9wYWNrYWdlcyAmJiBzdGVwX250cCAmJiBzdGVwX2luaXRpYXRvciB8fCB7IHBhdXNlOyByZXR1cm47IH0KICAgIHN0ZXBfdGFyZ2V0cyB8fCB7IHBhdXNlOyByZXR1cm47IH0KICAgIHBhdXNlCiAgICB3aXphcmRfbXVsdGlwYXRoIHx8IHJldHVybgogICAgY2xlYXI7IHN0ZXBfbXVsdGlwYXRoOyBwYXVzZQogICAgd2l6YXJkX2x1bnMKICAgIHdpemFyZF91c2VyIHx8IHJldHVybgogICAgc2F2ZV9jb25maWcKICAgIG1zZyAiRmF0dG8iICIkKHZlZWFtX2hpbnQpIgp9Cgp3aXphcmRfbWVudSgpIHsKICAgIGxvY2FsIGNoCiAgICB3aGlsZSA6OyBkbwogICAgICAgIGNoPSQod3QgLS10aXRsZSAiTWVudSBwcmluY2lwYWxlIiAtLW1lbnUgIkhvc3QgJChob3N0bmFtZSkgLSAkKGhvc3RuYW1lIC1JIDI+L2Rldi9udWxsIHwgeGFyZ3MpXG5TaW11bGF6aW9uZTogJCggKChEUllfUlVOKSkgJiYgZWNobyBBVFRJVkEgfHwgZWNobyBubykiIDI0IDgwIDE0IFwKICAgICAgICAgICAgMSAiQ29uZmlndXJhemlvbmUgZ3VpZGF0YSBjb21wbGV0YSIgXAogICAgICAgICAgICAyICJQYWNjaGV0dGkgZSBvcmEgZGkgc2lzdGVtYSAoTlRQKSIgXAogICAgICAgICAgICAzICJJbml0aWF0b3IgaVNDU0kiIFwKICAgICAgICAgICAgNCAiQ29ubmVzc2lvbmUgYWkgdGFyZ2V0IGlTQ1NJIiBcCiAgICAgICAgICAgIDUgIk11bHRpcGF0aCIgXAogICAgICAgICAgICA2ICJQcmVwYXJhIExVTiAoR1BULCBYRlMsIGZzdGFiLCBtb3VudCkiIFwKICAgICAgICAgICAgNyAiVXRlbnRlIFZlZWFtIGUgcGVybWVzc2kiIFwKICAgICAgICAgICAgOCAiQmxpbmRhdHVyYSAoZG9wbyBsJ2FnZ2l1bnRhIGluIFZlZWFtKSIgXAogICAgICAgICAgICA5ICJSaWFwcmkgcGVyIGFnZ2lvcm5hbWVudG8gVmVlYW0gKHRlbXBvcmFuZW8pIiBcCiAgICAgICAgICAgIDEwICJEaXNjb25uZXR0aSB0YXJnZXQgaVNDU0kiIFwKICAgICAgICAgICAgMTEgIlN0YXRvIGUgdmVyaWZpY2EiIFwKICAgICAgICAgICAgMTIgIlNpbXVsYXppb25lIG9uL29mZiIgXAogICAgICAgICAgICAwICJFc2NpIikgfHwgYnJlYWsKICAgICAgICBjYXNlICRjaCBpbgogICAgICAgICAgICAxKSB3aXphcmRfZnVsbCA7OwogICAgICAgICAgICAyKSB3aXphcmRfbnRwICYmIHsgY2xlYXI7IHN0ZXBfcGFja2FnZXM7IHN0ZXBfbnRwOyBwYXVzZTsgfSA7OwogICAgICAgICAgICAzKSB3aXphcmRfbmV0d29yayAmJiB7IGNsZWFyOyBzdGVwX2luaXRpYXRvcjsgcGF1c2U7IH0gOzsKICAgICAgICAgICAgNCkgeyBbWyAtbiAkQ0ZHX0lTQ1NJX1BPUlRBTFMgXV0gfHwgd2l6YXJkX25ldHdvcms7IH0gJiYgeyBjbGVhcjsgc3RlcF90YXJnZXRzOyBwYXVzZTsgfSA7OwogICAgICAgICAgICA1KSB3aXphcmRfbXVsdGlwYXRoICYmIHsgY2xlYXI7IHN0ZXBfbXVsdGlwYXRoOyBwYXVzZTsgfSA7OwogICAgICAgICAgICA2KSB3aXphcmRfbHVucyA7OwogICAgICAgICAgICA3KSB3aXphcmRfdXNlciA7OwogICAgICAgICAgICA4KSBjbGVhcjsgc3RlcF9sb2NrZG93bjsgcGF1c2UgOzsKICAgICAgICAgICAgOSkgY2xlYXI7IHN0ZXBfdW5sb2NrOyBwYXVzZSA7OwogICAgICAgICAgICAxMCkgY2xlYXI7IHN0ZXBfcmVtb3ZlX3RhcmdldHM7IHBhdXNlIDs7CiAgICAgICAgICAgIDExKSBjbGVhcjsgc3RlcF9zdGF0dXM7IHBhdXNlIDs7CiAgICAgICAgICAgIDEyKSBEUllfUlVOPSQoKDEgLSBEUllfUlVOKSkgOzsKICAgICAgICAgICAgMCkgYnJlYWsgOzsKICAgICAgICBlc2FjCiAgICAgICAgc2F2ZV9jb25maWcKICAgIGRvbmUKICAgIGNsZWFyCn0KCiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PSBNQUlOCnVzYWdlKCkgewogICAgY2F0IDw8RU9GCnZyZXBvLXNldHVwICRWRVJTSU9OIC0gaGFyZGVuZWQgcmVwb3NpdG9yeSBWZWVhbSBzdSBVYnVudHUKClVzbzogc3VkbyAkMCBbb3B6aW9uaV0gW2NvbWFuZG9dCgpDb21hbmRpOgogIHdpemFyZCAgICAgICAgICBtZW51IGludGVyYXR0aXZvIChwcmVkZWZpbml0byBkYSB0ZXJtaW5hbGUpCiAgcHJlcGFyZSAgICAgICAgIHBhY2NoZXR0aSwgTlRQLCBpbml0aWF0b3IsIHRhcmdldCwgbXVsdGlwYXRoLCB1dGVudGUgKExVTiBzb2xvIGNvbiAtLXllcykKICBwYWNrYWdlcyB8IG50cCB8IGluaXRpYXRvciB8IHRhcmdldHMgfCBtdWx0aXBhdGggfCB1c2VyICAgIHNpbmdvbGkgcGFzc2kKICBsdW4gICAgICAgICAgICAgcHJlcGFyYSB1bmEgTFVOOiAtLWRldiAvZGV2L3NkWHwtLXd3aWQgVyAgLS1uYW1lIE5PTUUgIFstLW1vdW50IFBFUkNPUlNPXQogIGx1bnMgLS15ZXMgICAgICBwcmVwYXJhIHR1dHRlIGxlIExVTiBsaWJlcmUgKG5vbWkgZGEgTFVOX05BTUVTIG8gPHByZWZpc3NvPk5OKQogIGxvY2tkb3duICAgICAgICBibGluZGF0dXJhIGRvcG8gbCdhZ2dpdW50YSBpbiBWQlIKICB1bmxvY2sgICAgICAgICAgcmlhcGVydHVyYSB0ZW1wb3JhbmVhIHBlciBhZ2dpb3JuYXJlIGkgY29tcG9uZW50aSBWZWVhbSAoc29sbyBjb25zb2xlKQogIHJlbW92ZS10YXJnZXRzICBsb2dvdXQgZWQgZWxpbWluYXppb25lIGRlaSB0YXJnZXQgKFJFTU9WRV9UQVJHRVRTIG8gLS10YXJnZXQgSVFOKQogIHN0YXR1cyAgICAgICAgICBzdGF0byBlIHZlcmlmaWNhCiAgc2NhbiAgICAgICAgICAgIHN0YXRvIGluIGZvcm1hdG8gbWFjY2hpbmEgKHBlciBsYSBHVUkpCiAgaW5zdGFsbC1hY2Nlc3MgIGluc3RhbGxhIGxvIHNjcmlwdCBpbiAkSU5TVEFMTF9QQVRIIGUgbGEgcmVnb2xhIHN1ZG8gcGVyIGxhIEdVSQogIHZlcnNpb24KCk9wemlvbmk6CiAgLS1jb25maWcgRklMRSAgIGNvbmZpZ3VyYXppb25lIEtFWT1WQUxVRSAoLSA9IHN0YW5kYXJkIGlucHV0KTsgcHJlZGVmaW5pdGEgJFNBVkVEX0NPTkYKICAtLWRyeS1ydW4gICAgICAgc2ltdWxhemlvbmU6IG1vc3RyYSBjb3NhIGZhcmViYmUgc2VuemEgbW9kaWZpY2FyZSBudWxsYQogIC0teWVzICAgICAgICAgICBjb25mZXJtYSBsZSBhemlvbmkgZGlzdHJ1dHRpdmUgaW4gbW9kYWxpdGEnIG5vbiBpbnRlcmF0dGl2YQogIC0tZ3VpICAgICAgICAgICBvdXRwdXQgc2VtcGxpY2UgcGVyIGxhIEdVSSwgbmVzc3VuYSBkb21hbmRhCgpMb2c6ICRMT0dfRklMRQpFT0YKfQoKbWFpbigpIHsKICAgIGxvY2FsIGNtZD0iIiBhCiAgICB3aGlsZSAoKCAkIyApKTsgZG8KICAgICAgICBhPSQxOyBzaGlmdAogICAgICAgIGNhc2UgJGEgaW4KICAgICAgICAgICAgLS1jb25maWcpIENPTkZJR19GSUxFPSR7MTotfTsgc2hpZnQgOzsKICAgICAgICAgICAgLS1kcnktcnVufC0tc2ltdWxhdGUpIERSWV9SVU49MSA7OwogICAgICAgICAgICAtLXllc3wteSkgQVNTVU1FX1lFUz0xIDs7CiAgICAgICAgICAgIC0tZ3VpKSBHVUk9MSA7OwogICAgICAgICAgICAtLWRldikgT1BUX0RFVj0kezE6LX07IHNoaWZ0IDs7CiAgICAgICAgICAgIC0td3dpZCkgT1BUX1dXSUQ9JHsxOi19OyBzaGlmdCA7OwogICAgICAgICAgICAtLW5hbWUpIE9QVF9OQU1FPSR7MTotfTsgc2hpZnQgOzsKICAgICAgICAgICAgLS1tb3VudCkgT1BUX01PVU5UPSR7MTotfTsgc2hpZnQgOzsKICAgICAgICAgICAgLS10YXJnZXQpIE9QVF9UQVJHRVQ9JHsxOi19OyBzaGlmdCA7OwogICAgICAgICAgICAtaHwtLWhlbHB8aGVscCkgdXNhZ2U7IGV4aXQgMCA7OwogICAgICAgICAgICB2ZXJzaW9ufC0tdmVyc2lvbikgZWNobyAiJFZFUlNJT04iOyBleGl0IDAgOzsKICAgICAgICAgICAgLSopIGVjaG8gIk9wemlvbmUgc2Nvbm9zY2l1dGE6ICRhIiA+JjI7IHVzYWdlID4mMjsgZXhpdCAyIDs7CiAgICAgICAgICAgICopIFtbIC16ICRjbWQgXV0gJiYgY21kPSRhIHx8IHsgZWNobyAiQ29tYW5kbyBpbiBwaXUnOiAkYSIgPiYyOyBleGl0IDI7IH0gOzsKICAgICAgICBlc2FjCiAgICBkb25lCiAgICBpZiBbWyAteiAkY21kIF1dOyB0aGVuCiAgICAgICAgaWYgW1sgLXQgMCAmJiAtdCAxIF1dICYmICgoICEgR1VJICkpOyB0aGVuIGNtZD13aXphcmQ7IGVsc2UgdXNhZ2U7IGV4aXQgMjsgZmkKICAgIGZpCiAgICByZXF1aXJlX3Jvb3QgIiRjbWQiCiAgICB0b3VjaCAiJExPR19GSUxFIiAyPi9kZXYvbnVsbCAmJiBjaG1vZCA2MDAgIiRMT0dfRklMRSIgMj4vZGV2L251bGwKICAgIGxvY2FsIHE9IiI7IFtbICRjbWQgPT0gc2NhbiBdXSAmJiBxPTEKICAgIGlmIFtbIC1uICRDT05GSUdfRklMRSBdXTsgdGhlbiBpZiBbWyAtbiAkcSBdXTsgdGhlbiBsb2FkX2NvbmZpZyAiJENPTkZJR19GSUxFIiA+L2Rldi9udWxsOyBlbHNlIGxvYWRfY29uZmlnICIkQ09ORklHX0ZJTEUiOyBmaQogICAgZWxpZiBbWyAtciAkU0FWRURfQ09ORiBdXTsgdGhlbiBsb2FkX2NvbmZpZyAiJFNBVkVEX0NPTkYiID4vZGV2L251bGw7IGZpCiAgICBbWyAkY21kID09IHNjYW4gXV0gfHwgeyB2YWxpZGF0ZV9jb25maWcgfHwgZXhpdCAyOyB9CiAgICBpZiBbWyAkY21kID09IHdpemFyZCB8fCAkY21kID09IHVubG9jayBdXTsgdGhlbgogICAgICAgICgoIEdVSSApKSAmJiB7IGVyciAiSWwgY29tYW5kbyAkY21kIHJpY2hpZWRlIHVuIHRlcm1pbmFsZSI7IGV4aXQgMjsgfQogICAgICAgIGNvbW1hbmQgLXYgd2hpcHRhaWwgPi9kZXYvbnVsbCAyPiYxIHx8IGVuc3VyZV9wa2dzIHdoaXB0YWlsIHx8IGRpZSAid2hpcHRhaWwgbm9uIGRpc3BvbmliaWxlIgogICAgICAgIElOVEVSQUNUSVZFPTEKICAgIGZpCiAgICBbWyAkY21kID09IHNjYW4gXV0gfHwgaW5mbyAidnJlcG8tc2V0dXAgJFZFUlNJT04gLSBjb21hbmRvICRjbWQkKCAoKERSWV9SVU4pKSAmJiBlY2hvICcgKFNJTVVMQVpJT05FKScpIgogICAgbG9jYWwgcmM9MAogICAgY2FzZSAkY21kIGluCiAgICAgICAgd2l6YXJkKSB3aXphcmRfbWVudSA7OwogICAgICAgIHByZXBhcmUpIHN0ZXBfcHJlcGFyZSB8fCByYz0xIDs7CiAgICAgICAgcGFja2FnZXMpIHN0ZXBfcGFja2FnZXMgfHwgcmM9MSA7OwogICAgICAgIG50cCkgc3RlcF9udHAgfHwgcmM9MSA7OwogICAgICAgIGluaXRpYXRvcikgc3RlcF9pbml0aWF0b3IgfHwgcmM9MSA7OwogICAgICAgIHRhcmdldHMpIHN0ZXBfdGFyZ2V0cyB8fCByYz0xIDs7CiAgICAgICAgbXVsdGlwYXRoKSBzdGVwX211bHRpcGF0aCB8fCByYz0xIDs7CiAgICAgICAgbHVuKQogICAgICAgICAgICBbWyAtbiAke09QVF9ERVY6LSRPUFRfV1dJRH0gXV0gfHwgZGllICJJbmRpY2FyZSAtLWRldiBvIC0td3dpZCIKICAgICAgICAgICAgaWYgW1sgLXogJE9QVF9OQU1FIF1dOyB0aGVuIHNjYW5fbHVuczsgcj0kKGZpbmRfbHVuICIke09QVF9ERVY6LSRPUFRfV1dJRH0iKSAmJiBJRlM9J3wnIHJlYWQgLXIgXyBrIHcgXyA8PDwiJHIiOyBPUFRfTkFNRT0kKGNvbmZpZ3VyZWRfbmFtZV9mb3IgIiR7dzotfSIgIiR7azotfSIpIHx8IE9QVF9OQU1FPSQoc3VnZ2VzdF9uYW1lKTsgZmkKICAgICAgICAgICAgY29uZmlndXJlX2x1biAiJHtPUFRfREVWOi0kT1BUX1dXSUR9IiAiJE9QVF9OQU1FIiAiJE9QVF9NT1VOVCIgfHwgcmM9MSA7OwogICAgICAgIGx1bnMpICgoIEFTU1VNRV9ZRVMgKSkgfHwgZGllICJJbCBjb21hbmRvIGx1bnMgZm9ybWF0dGEgaSBkaXNjaGk6IGFnZ2l1bmdlcmUgLS15ZXMiOyBzdGVwX2x1bnNfYXV0byB8fCByYz0xIDs7CiAgICAgICAgdXNlcikgc3RlcF91c2VyIHx8IHJjPTEgOzsKICAgICAgICBsb2NrZG93bikgc3RlcF9sb2NrZG93biB8fCByYz0xIDs7CiAgICAgICAgdW5sb2NrKSBzdGVwX3VubG9jayB8fCByYz0xIDs7CiAgICAgICAgcmVtb3ZlLXRhcmdldHMpIHN0ZXBfcmVtb3ZlX3RhcmdldHMgfHwgcmM9MSA7OwogICAgICAgIHN0YXR1cykgc3RlcF9zdGF0dXMgOzsKICAgICAgICBzY2FuKSBzdGVwX3NjYW47IGV4aXQgMCA7OwogICAgICAgIGluc3RhbGwtYWNjZXNzKSBzdGVwX2luc3RhbGxfYWNjZXNzIHx8IHJjPTEgOzsKICAgICAgICAqKSBlY2hvICJDb21hbmRvIHNjb25vc2NpdXRvOiAkY21kIiA+JjI7IHVzYWdlID4mMjsgZXhpdCAyIDs7CiAgICBlc2FjCiAgICAoKCByYyA9PSAwICYmIEVSUk9SUyA+IDAgKSkgJiYgcmM9MQogICAgaWYgW1sgJGNtZCAhPSB3aXphcmQgXV07IHRoZW4KICAgICAgICBpZiAoKCByYyA9PSAwICkpOyB0aGVuIG9rICJGaW5lOiAkY21kIGNvbXBsZXRhdG8gKCRXQVJOSU5HUyBhdnZpc2kpIjsgZWxzZSBlcnIgIkZpbmU6ICRjbWQgdGVybWluYXRvIGNvbiBlcnJvcmkgKCRFUlJPUlMgZXJyb3JpLCAkV0FSTklOR1MgYXZ2aXNpKSI7IGZpCiAgICBmaQogICAgZXhpdCAkcmMKfQoKbWFpbiAiJEAiCg=='
    $script:RemoteScript = '/usr/local/sbin/vrepo-setup.sh'
    $script:KeyComment = 'vrepo-setup'

    function Get-ToolDefaultConfig {
        [ordered]@{
            Host              = ''
            Port              = 22
            SshUser           = ''
            SshKeyFile        = (Join-Path $env:USERPROFILE '.ssh\vrepo_ed25519')
            InitiatorName     = ''
            IscsiPortals      = @()
            IscsiPort         = 3260
            IscsiTargets      = @()
            OnlyListedPortals = $true
            ChapUser          = ''
            ChapPassword      = ''
            Multipath         = 'Automatico'
            MultipathProfile  = 'QNAP'
            MultipathAlias    = $true
            LunPrefix         = 'veeam-repo'
            LunNames          = @()
            MountBase         = '/mnt'
            Partition         = $true
            ForceFormat       = $false
            VeeamUser         = 'veeambck'
            NtpServers        = @()
            Timezone          = ''
            SshDisable        = $true
            LockVeeamPassword = $true
            LockdownForce     = $false
            RemoveTargets     = @()
            RemoveDiscovery   = $false
            ScriptPath        = ''
            LogDir            = (Join-Path $env:ProgramData ('FispaTools\' + $Tool.Name + '\Log'))
            DryRun            = $true
        }
    }

    # ------------------------------------------------------------------ OpenSSH di Windows

    function Get-OpenSshExe([string]$Name) {
        $cands = @()
        if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) { $cands += (Join-Path $env:WINDIR "Sysnative\OpenSSH\$Name.exe") }
        $cands += (Join-Path $env:WINDIR "System32\OpenSSH\$Name.exe")
        foreach ($c in $cands) { if (Test-Path -LiteralPath $c) { return $c } }
        $cmd = Get-Command "$Name.exe" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
        $null
    }

    function Get-ToolPrereqIssues($Config) {
        $w = @()
        foreach ($n in @('ssh', 'ssh-keygen')) {
            if (-not (Get-OpenSshExe $n)) { $w += "$n.exe non trovato: installare il Client OpenSSH (Impostazioni > App > Funzionalita' facoltative, oppure Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0)." }
        }
        $w
    }

    # argomenti per la riga di comando di Windows (regole di CommandLineToArgvW)
    function Join-ProcessArgs([string[]]$List) {
        $out = foreach ($a in $List) {
            if ($a -eq '') { '""' }
            elseif ($a -notmatch '[\s"]') { $a }
            else { '"' + (($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
        }
        $out -join ' '
    }

    function Get-SshArgs($Config, [switch]$Batch, [switch]$Tty) {
        $a = @('-p', [string]$Config.Port, '-i', [string]$Config.SshKeyFile,
            '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=30')
        if ($Batch) { $a += @('-o', 'BatchMode=yes') }
        if ($Tty) { $a += '-t' }
        $a + @(('{0}@{1}' -f $Config.SshUser, $Config.Host))
    }

    # valore sicuro tra apici singoli per la shell remota
    function ConvertTo-ShQuote([string]$s) { "'" + $s.Replace("'", "'\''") + "'" }

    function Get-VrepoScriptBytes($Config) {
        if ($Config.ScriptPath) {
            $bytes = [System.IO.File]::ReadAllBytes([string]$Config.ScriptPath)
        } else {
            if ($script:VrepoB64 -like '__EMBED*') { throw 'vrepo-setup.sh non incorporato: generare il tool con python _lib/build.py oppure indicare il percorso dello script.' }
            $bytes = [Convert]::FromBase64String($script:VrepoB64)
        }
        $txt = [System.Text.Encoding]::UTF8.GetString($bytes).Replace("`r`n", "`n")
        [System.Text.Encoding]::UTF8.GetBytes($txt)
    }

    function Get-VrepoLocalVersion($Config) {
        try {
            $t = [System.Text.Encoding]::UTF8.GetString((Get-VrepoScriptBytes $Config))
            if ($t -match '(?m)^VERSION="([^"]+)"') { return $Matches[1] }
        } catch { }
        ''
    }

    function Get-YesNo($v) { if ($v) { 'yes' } else { 'no' } }

    # configurazione per vrepo-setup.sh (KEY="valore"), inviata su standard input
    function ConvertTo-VrepoConf($Config) {
        $mp = switch ([string]$Config.Multipath) { 'Si' { 'yes' } 'No' { 'no' } default { 'auto' } }
        $prof = if ([string]$Config.MultipathProfile -eq 'Generico') { 'generic' } else { 'qnap' }
        $map = [ordered]@{
            INITIATOR_NAME      = [string]$Config.InitiatorName
            ISCSI_PORTALS       = (@($Config.IscsiPortals) -join ' ')
            ISCSI_PORT          = [string]$Config.IscsiPort
            ISCSI_TARGETS       = (@($Config.IscsiTargets) -join ' ')
            ONLY_LISTED_PORTALS = (Get-YesNo $Config.OnlyListedPortals)
            CHAP_USER           = [string]$Config.ChapUser
            CHAP_PASSWORD       = [string]$Config.ChapPassword
            MULTIPATH           = $mp
            MULTIPATH_PROFILE   = $prof
            MULTIPATH_ALIAS     = (Get-YesNo $Config.MultipathAlias)
            LUN_PREFIX          = [string]$Config.LunPrefix
            LUN_NAMES           = (@($Config.LunNames) -join ';')
            MOUNT_BASE          = [string]$Config.MountBase
            PARTITION           = (Get-YesNo $Config.Partition)
            FORCE_FORMAT        = (Get-YesNo $Config.ForceFormat)
            VEEAM_USER          = [string]$Config.VeeamUser
            NTP_SERVERS         = (@($Config.NtpServers) -join ' ')
            TIMEZONE            = [string]$Config.Timezone
            SSH_DISABLE         = (Get-YesNo $Config.SshDisable)
            LOCK_VEEAM_PASSWORD = (Get-YesNo $Config.LockVeeamPassword)
            LOCKDOWN_FORCE      = (Get-YesNo $Config.LockdownForce)
            REMOVE_TARGETS      = (@($Config.RemoveTargets) -join ' ')
            REMOVE_DISCOVERY    = (Get-YesNo $Config.RemoveDiscovery)
            ADMIN_USER          = [string]$Config.SshUser
        }
        $lines = foreach ($k in $map.Keys) { '{0}="{1}"' -f $k, (([string]$map[$k]) -replace '[\r\n]', '') }
        ($lines -join "`n") + "`n"
    }

    # riga di vrepo-setup.sh --gui -> log del tool
    function Write-VrepoLine([string]$Line) {
        if ($Line -match '^\[(INFO|OK|WARN|ERR|STEP|SIM)\] (.*)$') {
            switch ($Matches[1]) {
                'OK' { Write-ToolLog $Matches[2] 'OK' }
                'WARN' { Write-ToolLog $Matches[2] 'WARN' }
                'ERR' { Write-ToolLog $Matches[2] 'ERROR' }
                'STEP' { Write-ToolLog $Matches[2] 'STEP' }
                'SIM' { Write-ToolLog ('[simulazione] ' + $Matches[2]) 'INFO' }
                default { Write-ToolLog $Matches[2] 'INFO' }
            }
        } elseif ($Line.Trim()) { Write-ToolLog ('  ' + $Line) 'INFO' }
    }

    # comando remoto non interattivo (chiave SSH, BatchMode); output riga per riga nel log o restituito
    function Invoke-VrepoRemote($Config, [string]$Command, [byte[]]$StdIn, [switch]$Capture) {
        $ssh = Get-OpenSshExe 'ssh'
        if (-not $ssh) { throw 'ssh.exe non trovato (Client OpenSSH di Windows).' }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ssh
        $psi.Arguments = Join-ProcessArgs (@(Get-SshArgs $Config -Batch) + @($Command))
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $psi.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $lines = New-Object System.Collections.Generic.List[string]
        try {
            $errTask = $p.StandardError.ReadToEndAsync()
            try {
                if ($StdIn) { $p.StandardInput.BaseStream.Write($StdIn, 0, $StdIn.Length); $p.StandardInput.BaseStream.Flush() }
            } catch { }
            try { $p.StandardInput.Close() } catch { }
            while ($null -ne ($line = $p.StandardOutput.ReadLine())) {
                $lines.Add($line)
                if (-not $Capture) { Write-VrepoLine $line }
            }
            $p.WaitForExit()
            [pscustomobject]@{ ExitCode = $p.ExitCode; Lines = $lines.ToArray(); StdErr = [string]$errTask.Result }
        } finally { $p.Dispose() }
    }

    # comando remoto in una finestra console (password SSH e/o sudo digitate dall'operatore)
    function Invoke-VrepoConsole($Config, [string]$Command, [switch]$Tty) {
        $ssh = Get-OpenSshExe 'ssh'
        if (-not $ssh) { throw 'ssh.exe non trovato (Client OpenSSH di Windows).' }
        $sshArgs = @(Get-SshArgs $Config -Tty:$Tty) + @($Command)
        $p = Start-Process -FilePath $ssh -ArgumentList (Join-ProcessArgs $sshArgs) -Wait -PassThru
        $p.ExitCode
    }

    function Get-SshFailureText($Result, $Config) {
        $e = [string]$Result.StdErr
        if ($e -match 'REMOTE HOST IDENTIFICATION HAS CHANGED') { return "La chiave host del server e' cambiata (reinstallato?). Se e' atteso: ssh-keygen -R $($Config.Host)" }
        if ($e -match 'Permission denied') { return 'Accesso con la chiave non riuscito: eseguire il passo Accesso.' }
        if ($e -match 'timed out|Connection refused|No route|Could not resolve') { return "Server non raggiungibile in SSH: $(($e.Trim() -split "`n")[-1])" }
        if ($e -match 'sudo: .*password' -or ($Result.Lines -join "`n") -match 'sudo: .*password') { return "Regola sudo del tool assente: eseguire il passo Accesso." }
        if ($e -match 'UNPROTECTED PRIVATE KEY|bad permissions') { return 'Permessi della chiave privata troppo aperti: usare una chiave nel profilo utente (.ssh).' }
        $t = $e.Trim()
        if ($t) { return ($t -split "`n")[-1] }
        "codice $($Result.ExitCode)"
    }

    # ------------------------------------------------------------------ verifica configurazione

    function Test-ToolConfig($Config, [switch]$Scan) {
        $e = @()
        if ([string]$Config.Host -notmatch '^[A-Za-z0-9.:_-]+$') { $e += 'Indicare il server (IP o nome).' }
        if ([string]$Config.SshUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') { $e += "Indicare l'utente amministratore del server (minuscole, numeri, _ e -)." }
        if (-not $Config.SshKeyFile) { $e += 'Indicare il percorso della chiave SSH (viene creata se non esiste).' }
        if (-not (Get-OpenSshExe 'ssh')) { $e += 'Client OpenSSH di Windows non installato (ssh.exe).' }
        if ($Config.ScriptPath -and -not (Test-Path -LiteralPath $Config.ScriptPath)) { $e += "Script non trovato: $($Config.ScriptPath)" }
        foreach ($p in @($Config.IscsiPortals) + @($Config.NtpServers)) { if ($p -notmatch '^[A-Za-z0-9.:_-]+$') { $e += "Indirizzo non valido: $p" } }
        if ($Config.InitiatorName -and [string]$Config.InitiatorName -notmatch '^(iqn\.\d{4}-\d{2}\.|eui\.|naa\.)\S+$') { $e += 'InitiatorName non valido (es. iqn.2004-10.com.ubuntu:01:vrepo01).' }
        foreach ($t in @($Config.IscsiTargets) + @($Config.RemoveTargets)) { if ($t -match '\s|\|') { $e += "Target non valido: $t" } }
        if ([string]$Config.VeeamUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') { $e += "Utente Veeam non valido: $($Config.VeeamUser)" }
        if ([string]$Config.MountBase -notmatch '^/[A-Za-z0-9/._-]+$' -or [string]$Config.MountBase -match '\.\.|/$') { $e += "Cartella dei punti di mount non valida: $($Config.MountBase)" }
        if ([string]$Config.LunPrefix -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,28}$') { $e += 'Prefisso dei nomi LUN non valido.' }
        foreach ($n in @($Config.LunNames)) { if ($n -notmatch '^[^=\s]+=[A-Za-z0-9][A-Za-z0-9._-]{0,31}$') { $e += "Nome LUN non valido (formato WWID=nome): $n" } }
        if ($Config.Timezone -and [string]$Config.Timezone -notmatch '^[A-Za-z0-9/_+-]+$') { $e += 'Fuso orario non valido.' }
        if ([string]$Config.ChapUser + [string]$Config.ChapPassword -match '[\r\n]') { $e += 'Credenziali CHAP non valide.' }
        if ($Scan) { return $e }
        if (-not $Config.LogDir) { $e += 'Indicare la cartella dei log.' }
        if ($State.Headless -and -not $User) { $e += 'Con -NoGui indicare i passi da eseguire con -User (es. -User Pacchetti,NTP,Initiator,Target,Multipath).' }
        $e
    }

    # ------------------------------------------------------------------ analisi

    function New-VrepoItem([string]$Key, [string]$Name, [string]$Step, [string]$Detail, [string]$Status, [bool]$Selectable) {
        [pscustomobject]@{
            Key = $Key; Utente = $Name; SID = ''; Origine = $Detail
            Passo = $Name; Dettaglio = $Detail; Dispositivo = ''; Dimensione = ''; Percorsi = ''; Nome = ''; Mount = ''
            Stato = $Status; Selectable = $Selectable; Step = $Step; Device = ''; LunName = ''; Wwid = ''
        }
    }

    function Format-Bytes([string]$b) {
        $n = 0.0
        if (-not [double]::TryParse($b, [ref]$n) -or $n -le 0) { return '' }
        $u = @('B', 'KB', 'MB', 'GB', 'TB', 'PB'); $i = 0
        while ($n -ge 1024 -and $i -lt $u.Count - 1) { $n /= 1024; $i++ }
        '{0:N1} {1}' -f $n, $u[$i]
    }

    function Get-ToolItems($Config) {
        Write-ToolLog "Analisi di $($Config.SshUser)@$($Config.Host)" 'STEP'
        $items = New-Object System.Collections.Generic.List[object]
        $local = Get-VrepoLocalVersion $Config
        $scan = $null; $why = ''
        if (-not (Test-Path -LiteralPath $Config.SshKeyFile)) { $why = 'chiave SSH non ancora creata' }
        else {
            try {
                $r = Invoke-VrepoRemote -Config $Config -Command "sudo -n $script:RemoteScript --config - scan" -StdIn ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-VrepoConf $Config))) -Capture
                if ($r.ExitCode -eq 0 -and ($r.Lines -match '^VER\|')) { $scan = $r.Lines }
                else { $why = Get-SshFailureText $r $Config }
            } catch { $why = $_.Exception.Message }
        }
        $st = @{}; $luns = @(); $repos = @(); $targets = @(); $sessions = @(); $ver = ''; $init = ''; $hostInfo = ''
        foreach ($l in @($scan)) {
            $f = $l -split '\|'
            switch ($f[0]) {
                'VER' { $ver = $f[1] }
                'HOST' { $hostInfo = '{0}, {1}, IP {2}' -f $f[1], $f[2], $f[3] }
                'INITIATOR' { $init = $f[1] }
                'STEP' { $st[$f[1]] = @{ S = $f[2]; D = ($f[3..($f.Count - 1)] -join '|') } }
                'LUN' { $luns += , $f }
                'REPO' { $repos += , $f }
                'TARGET' { $targets += ('{0} @ {1}' -f $f[2], $f[1]) }
                'SESSION' { $sessions += ('{0} @ {1}' -f $f[2], $f[1]) }
            }
        }
        if ($scan) {
            Write-ToolLog "Server: $hostInfo" 'OK'
            if ($init) { Write-ToolLog "InitiatorName: $init (da autorizzare sul NAS/target)" 'INFO' }
            foreach ($t in $targets) { Write-ToolLog "Target scoperto: $t" 'INFO' }
            foreach ($t in $sessions) { Write-ToolLog "Sessione attiva: $t" 'INFO' }
        } else { Write-ToolLog "Stato del server non leggibile: $why" 'WARN' }

        # 1. accesso
        if ($scan) {
            if ($ver -eq $local) { $items.Add((New-VrepoItem 'ACCESS' 'Accesso' 'ACCESS' "Chiave e regola sudo attive, script $ver" 'Fatto' $true)) }
            else { $items.Add((New-VrepoItem 'ACCESS' 'Accesso' 'ACCESS' "Script sul server $ver, nel tool $local`: rieseguire per aggiornarlo" 'Pronto' $true)) }
        } else {
            $items.Add((New-VrepoItem 'ACCESS' 'Accesso' 'ACCESS' "Da eseguire per primo ($why): chiede password SSH e sudo in una console" 'Pronto' $true))
        }
        $steps = @(
            , @('PACKAGES', 'Pacchetti', 'packages', 'open-iscsi, xfsprogs, parted, multipath-tools')
            , @('NTP', 'NTP', 'ntp', 'Fuso orario, server NTP, sincronizzazione')
            , @('INITIATOR', 'Initiator', 'initiator', 'InitiatorName e node.startup automatico')
            , @('TARGETS', 'Target', 'targets', 'Discovery e login sui portali indicati')
            , @('MULTIPATH', 'Multipath', 'multipath', 'multipath.conf e alias')
        )
        foreach ($s in $steps) {
            $d = $s[3]; $stato = 'Da verificare'
            if ($scan -and $st.ContainsKey($s[0])) {
                $d = $st[$s[0]].D
                $stato = if ($st[$s[0]].S -eq 'ok') { 'Fatto' } else { 'Pronto' }
            }
            if ($s[0] -eq 'INITIATOR' -and $init) { $d = "$init - $d" }
            if ($s[0] -eq 'TARGETS' -and $scan) { $d = "{0}; target scoperti: {1}" -f $d, $targets.Count }
            if ($s[0] -eq 'TARGETS' -and -not @($Config.IscsiPortals).Count) { $d = 'Indicare i portali del target nella configurazione'; $stato = 'Non configurato' }
            $items.Add((New-VrepoItem $s[0] $s[1] $s[2] $d $stato ($stato -ne 'Non configurato')))
        }

        # LUN viste dal server
        $used = @($repos | ForEach-Object { $_[1] })
        $reserved = New-Object System.Collections.Generic.List[string]
        $i = 1
        foreach ($f in $luns) {
            # LUN|dev|kname|wwid|byte|modello|percorsi|trasporto|stato|fstype|mount|nome
            $dev = $f[1]; $k = $f[2]; $wwid = $f[3]; $state = $f[8]; $fs = $f[9]; $mnt = $f[10]; $cur = $f[11]
            # stato prima del nome: i nomi si assegnano solo alle LUN utilizzabili
            $sel = $true; $stato = 'Pronto'
            switch ($state) {
                'libero' { }
                'configurato' { $stato = 'Fatto' }
                default {
                    if ($mnt -ne '-') { $stato = "In uso: montato su $mnt"; $sel = $false }
                    elseif ($Config.ForceFormat) { $stato = "DATI PRESENTI ($fs): verranno cancellati" }
                    else { $stato = "In uso ($fs): serve 'Consenti di formattare'"; $sel = $false }
                }
            }
            $name = ''
            if ($state -eq 'configurato' -and $cur -ne '-') { $name = $cur }
            elseif ($sel) {
                foreach ($e in @($Config.LunNames)) {
                    $kv = $e -split '=', 2
                    if ($kv[0] -in @($wwid, $k, $dev)) { $name = $kv[1] }
                }
                while (-not $name) {
                    $cand = '{0}{1:D2}' -f $Config.LunPrefix, $i; $i++
                    if ($cand -notin $used -and $cand -notin $reserved) { $name = $cand }
                }
                $reserved.Add($name)
            }
            $label = if ($name) { 'LUN:' + $name } else { 'LUN:' + $k }
            $mount = ''
            if ($state -eq 'configurato' -and $mnt -ne '-') { $mount = $mnt }
            elseif ($name) { $mount = '{0}/{1}' -f ([string]$Config.MountBase).TrimEnd('/'), $name }
            $it = New-VrepoItem ('LUN:' + $dev) $label 'LUN' ("$($f[5]) - $($f[7]) - WWID $wwid") $stato $sel
            $it.Dispositivo = $dev; $it.Dimensione = Format-Bytes $f[4]; $it.Percorsi = $f[6]; $it.Nome = $name; $it.Mount = $mount
            $it.Device = $dev; $it.LunName = $name; $it.Wwid = $wwid
            $items.Add($it)
        }
        if ($scan -and -not $luns.Count) {
            $items.Add((New-VrepoItem 'LUN:none' 'LUN' 'NONE' 'Nessun disco utilizzabile: eseguire Target (e Multipath), poi di nuovo Analizza' 'Non disponibile' $false))
        }

        $u = 'Da verificare'; $ud = "Utente $($Config.VeeamUser), password generata nel log, sudo temporaneo, permessi 700"
        if ($scan -and $st.ContainsKey('USER')) { $ud = $st['USER'].D; $u = if ($st['USER'].S -eq 'ok') { 'Fatto' } else { 'Pronto' } }
        $items.Add((New-VrepoItem 'USER' 'Utente' 'user' $ud $u $true))
        $ld = "Solo dopo l'aggiunta in VBR: via sudo, password bloccata, chiave e regola del tool rimosse"
        if ($Config.SshDisable) { $ld += ', SSH spento' }
        if ($scan -and $st.ContainsKey('LOCKDOWN')) { $ld += ' (' + $st['LOCKDOWN'].D + ')' }
        $items.Add((New-VrepoItem 'LOCKDOWN' 'Blindatura' 'lockdown' $ld 'Dopo VBR' $true))
        if (@($Config.RemoveTargets).Count) {
            $items.Add((New-VrepoItem 'REMOVE' 'Disconnessione' 'remove-targets' ('Logout ed eliminazione: ' + (@($Config.RemoveTargets) -join ', ')) 'Pronto' $true))
        }
        $items.ToArray()
    }

    # ------------------------------------------------------------------ esecuzione

    function Invoke-VrepoAccess($Config) {
        $key = [string]$Config.SshKeyFile
        if (-not (Test-Path -LiteralPath $key)) {
            $dir = Split-Path -Parent $key
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $kg = Get-OpenSshExe 'ssh-keygen'
            if (-not $kg) { throw 'ssh-keygen.exe non trovato (Client OpenSSH di Windows).' }
            $r = Invoke-ProcessCapture $kg ('-q -t ed25519 -N "" -C {0} -f {1}' -f $script:KeyComment, (Join-ProcessArgs @($key)))
            if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $key)) { throw "Creazione della chiave non riuscita: $($r.StdErr)" }
            Write-ToolLog "Chiave SSH creata: $key" 'OK'
        }
        $pubFile = "$key.pub"
        if (-not (Test-Path -LiteralPath $pubFile)) { throw "Chiave pubblica non trovata: $pubFile" }
        $pub = ((Get-Content -LiteralPath $pubFile -Raw) -split "`n")[0].Trim()
        $parts = $pub -split '\s+'
        if ($parts.Count -lt 2 -or $parts[0] -notmatch '^(ssh-|ecdsa-)') { throw "Chiave pubblica non valida: $pubFile" }
        $line = '{0} {1} {2}' -f $parts[0], $parts[1], $script:KeyComment

        $t = Invoke-VrepoRemote -Config $Config -Command 'true' -Capture
        if ($t.ExitCode -ne 0) {
            Write-ToolLog "Installazione della chiave: nella finestra console inserire la password SSH di $($Config.SshUser)" 'STEP'
            $cmd = "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qF '$($parts[1])' ~/.ssh/authorized_keys || echo '$line' >> ~/.ssh/authorized_keys) && echo 'Chiave installata' && sleep 2"
            $rc = Invoke-VrepoConsole -Config $Config -Command $cmd
            if ($rc -ne 0) { throw "Installazione della chiave non riuscita (codice $rc): password errata o accesso SSH con password disattivato." }
            $t = Invoke-VrepoRemote -Config $Config -Command 'true' -Capture
            if ($t.ExitCode -ne 0) { throw "Accesso con la chiave ancora non riuscito: $(Get-SshFailureText $t $Config)" }
            Write-ToolLog 'Accesso con la chiave attivo' 'OK'
        } else { Write-ToolLog 'Accesso con la chiave gia'' attivo' 'OK' }

        $local = Get-VrepoLocalVersion $Config
        $v = Invoke-VrepoRemote -Config $Config -Command "sudo -n $script:RemoteScript version" -Capture
        if ($v.ExitCode -eq 0 -and (@($v.Lines)[-1]).Trim() -eq $local) {
            Write-ToolLog "vrepo-setup.sh $local gia' installato con la regola sudo" 'OK'
            return @{ Esito = 'OK'; Messaggio = "Accesso gia' configurato (script $local)" }
        }
        $up = Invoke-VrepoRemote -Config $Config -Command 'umask 077; cat > /tmp/vrepo-setup.sh && chmod 700 /tmp/vrepo-setup.sh' -StdIn (Get-VrepoScriptBytes $Config) -Capture
        if ($up.ExitCode -ne 0) { throw "Copia dello script non riuscita: $(Get-SshFailureText $up $Config)" }
        Write-ToolLog "Installazione dello script e della regola sudo: nella console inserire la password sudo di $($Config.SshUser)" 'STEP'
        $cmd = 'sudo bash /tmp/vrepo-setup.sh install-access; rc=$?; rm -f /tmp/vrepo-setup.sh; if [ $rc -ne 0 ]; then echo; echo ERRORE: vedere i messaggi sopra; sleep 15; else sleep 3; fi; exit $rc'
        $rc = Invoke-VrepoConsole -Config $Config -Command $cmd -Tty
        if ($rc -ne 0) { throw "Installazione sul server non riuscita (codice $rc)." }
        $v = Invoke-VrepoRemote -Config $Config -Command "sudo -n $script:RemoteScript version" -Capture
        if ($v.ExitCode -ne 0) { throw "Verifica non riuscita: $(Get-SshFailureText $v $Config)" }
        Write-ToolLog "vrepo-setup.sh $((@($v.Lines)[-1]).Trim()) installato in $script:RemoteScript" 'OK'
        @{ Esito = 'OK'; Messaggio = "Chiave, script $local e regola sudo installati" }
    }

    function Invoke-ToolItem($Config, $Item) {
        if ($Item.Step -eq 'ACCESS') {
            if ($Config.DryRun) { Write-ToolLog "Il passo Accesso viene eseguito anche in simulazione: installa solo chiave, script e regola sudo." 'INFO' }
            return (Invoke-VrepoAccess $Config)
        }
        $cmd = [string]$Item.Step
        if ($Item.Step -eq 'LUN') {
            $cmd = 'lun --dev {0} --name {1} --mount {2}' -f (ConvertTo-ShQuote $Item.Device), (ConvertTo-ShQuote $Item.LunName), (ConvertTo-ShQuote $Item.Mount)
        }
        $dry = if ($Config.DryRun) { '--dry-run ' } else { '' }
        $remote = "sudo -n $script:RemoteScript --config - --gui $dry$cmd 2>&1"
        $r = Invoke-VrepoRemote -Config $Config -Command $remote -StdIn ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-VrepoConf $Config)))
        $out = @($r.Lines)
        $last = @($out | Where-Object { $_ -match '^\[ERR\]' } | Select-Object -Last 1)
        $warn = 0
        $fine = @($out | Where-Object { $_ -match 'Fine: .*\((\d+) avvisi\)' } | Select-Object -Last 1)
        if ($fine.Count -and $fine[0] -match '\((\d+) avvisi\)') { $warn = [int]$Matches[1] }
        switch ($r.ExitCode) {
            0 {
                $msg = ''
                if ($Item.Step -eq 'user' -and ($out -match 'PASSWORD GENERATA')) { $msg = 'Password generata: vedere il log. ' }
                if ($Item.Step -eq 'lockdown' -and $Config.SshDisable -and -not $Config.DryRun) { $msg = "SSH spento: la GUI non si collega piu' (riapertura da console: sudo vrepo-setup.sh unlock). " }
                if ($Config.DryRun) { return @{ Esito = 'Simulato'; Messaggio = ($msg + 'Comandi mostrati nel log') } }
                if ($warn -gt 0) { return @{ Esito = 'Attenzione'; Messaggio = ($msg + "$warn avvisi: vedere il log") } }
                return @{ Esito = 'OK'; Messaggio = $msg.Trim() }
            }
            255 { return @{ Esito = 'Fallito'; Messaggio = (Get-SshFailureText $r $Config) } }
            2 { return @{ Esito = 'Fallito'; Messaggio = 'Configurazione rifiutata dallo script: vedere il log' } }
            default {
                if (($out -join "`n") -match 'sudo: .*password') { return @{ Esito = 'Fallito'; Messaggio = 'Regola sudo del tool assente: eseguire il passo Accesso' } }
                $m = if ($last.Count) { $last[0] -replace '^\[ERR\] ', '' } else { "codice $($r.ExitCode)" }
                return @{ Esito = 'Fallito'; Messaggio = $m }
            }
        }
    }
    #endregion
}

#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Server vrepo (SSH)' }
    @{ Key = 'Host'; Label = 'Server'; Type = 'Text'; Help = 'IP o nome del server Ubuntu appena installato (rete di gestione).' }
    @{ Key = 'Port'; Label = 'Porta SSH'; Type = 'Int'; Min = 1; Max = 65535 }
    @{ Key = 'SshUser'; Label = 'Utente amministratore'; Type = 'Text'; Help = "Utente creato durante l'installazione di Ubuntu (con sudo). Al passo Accesso si inseriscono una volta la sua password SSH e quella di sudo in una finestra console." }
    @{ Key = 'SshKeyFile'; Label = 'Chiave SSH privata'; Type = 'File'; Help = 'Chiave dedicata al tool: se non esiste viene creata (ed25519) al passo Accesso. La blindatura la rimuove dal server.' }
    @{ Type = 'Section'; Label = 'iSCSI' }
    @{ Key = 'InitiatorName'; Label = 'InitiatorName'; Type = 'Text'; Help = "Vuoto = mantiene quello generato da Ubuntu (mostrato da Analizza, da autorizzare sul NAS). Es. iqn.2004-10.com.ubuntu:01:vrepo01" }
    @{ Key = 'IscsiPortals'; Label = 'Portali del target'; Type = 'List'; Help = 'IP del NAS/SAN separati da punto e virgola: uno per percorso, es. 10.10.1.10; 10.10.2.10. Con due o piu'' portali il multipath si attiva in automatico.' }
    @{ Key = 'IscsiPort'; Label = 'Porta iSCSI'; Type = 'Int'; Min = 1; Max = 65535 }
    @{ Key = 'IscsiTargets'; Label = 'Target (IQN)'; Type = 'List'; Help = 'IQN o caratteri jolly, es. iqn.2004-04.com.qnap:*:veeam*. Vuoto = tutti i target scoperti. I record degli altri target vengono eliminati, cosi'' al riavvio non si collega altro.' }
    @{ Key = 'OnlyListedPortals'; Label = 'Login solo sui portali indicati'; Type = 'Bool'; Help = "Il NAS annuncia il target su tutte le sue interfacce (anche la LAN di gestione): con questa opzione il login avviene solo sugli IP indicati sopra." }
    @{ Key = 'ChapUser'; Label = 'Utente CHAP'; Type = 'Text'; Help = 'Vuoto = nessuna autenticazione CHAP.' }
    @{ Key = 'ChapPassword'; Label = 'Password CHAP'; Type = 'Text'; Help = 'Attenzione: viene salvata in chiaro nel profilo JSON (non nel log). Lasciare vuoto se non serve.' }
    @{ Type = 'Section'; Label = 'Multipath' }
    @{ Key = 'Multipath'; Label = 'Multipath'; Type = 'Choice'; Choices = @('Automatico', 'Si', 'No'); Help = "Automatico: attivo se ci sono piu' portali o LUN viste su piu' percorsi." }
    @{ Key = 'MultipathProfile'; Label = 'Profilo'; Type = 'Choice'; Choices = @('QNAP', 'Generico'); Help = "QNAP: round-robin 0, multibus, alua, uid ID_SERIAL, failback immediate, no_path_retry fail. Generico: user_friendly_names e find_multipaths. /etc/multipath.conf esistente salvato in backup." }
    @{ Key = 'MultipathAlias'; Label = 'Alias multipath = nome della LUN'; Type = 'Bool'; Help = '/dev/mapper/<nome> invece di mpatha, mpathb...' }
    @{ Type = 'Section'; Label = 'LUN e repository' }
    @{ Key = 'LunPrefix'; Label = 'Prefisso dei nomi'; Type = 'Text'; Help = 'Nomi proposti per le LUN senza nome assegnato: <prefisso>01, <prefisso>02... Il nome e'' etichetta XFS (primi 12 caratteri), alias multipath e cartella di mount.' }
    @{ Key = 'LunNames'; Label = 'Nomi delle LUN'; Type = 'List'; Help = 'Associazioni WWID=nome o dispositivo=nome separate da punto e virgola, es. 36e843b6...=repo-giornaliero; sdc=repo-mensile. Il WWID si copia dalla scheda Passi dopo Analizza.' }
    @{ Key = 'MountBase'; Label = 'Cartella dei punti di mount'; Type = 'Text'; Help = 'Ogni LUN si monta in <cartella>/<nome>, es. /mnt/veeam-repo01. Il punto di mount vuoto e'' reso immutabile (chattr +i): se la LUN non si monta nessuno scrive sul disco di sistema.' }
    @{ Key = 'Partition'; Label = 'Crea una partizione GPT'; Type = 'Bool'; Help = 'Una partizione su tutto il disco (consigliato). Senza, XFS viene creato direttamente sul dispositivo.' }
    @{ Key = 'ForceFormat'; Label = 'Consenti di formattare LUN con dati'; Type = 'Bool'; Help = 'Disattivo: le LUN con filesystem, partizioni o firme esistenti non si toccano. Le LUN montate o in uso non si toccano mai.' }
    @{ Type = 'Section'; Label = 'Utente Veeam e sistema' }
    @{ Key = 'VeeamUser'; Label = 'Utente Veeam'; Type = 'Text'; Help = "Utente locale per le credenziali single-use in VBR. La password viene generata e mostrata nel log al passo Utente; la blindatura la blocca." }
    @{ Key = 'NtpServers'; Label = 'Server NTP'; Type = 'List'; Help = "Vuoto = predefiniti di Ubuntu. L'immutabilita' dipende da un orologio corretto: con rete isolata indicare un NTP interno (es. il domain controller)." }
    @{ Key = 'Timezone'; Label = 'Fuso orario'; Type = 'Text'; Help = 'Es. Europe/Rome. Vuoto = non modificare.' }
    @{ Type = 'Section'; Label = "Blindatura (dopo l'aggiunta del repository in VBR)" }
    @{ Key = 'SshDisable'; Label = 'Disattiva SSH'; Type = 'Bool'; Help = "Dopo la blindatura la GUI non si collega piu'. Per aggiornare i componenti Veeam: da console sudo vrepo-setup.sh unlock, poi di nuovo lockdown." }
    @{ Key = 'LockVeeamPassword'; Label = "Blocca la password dell'utente Veeam"; Type = 'Bool'; Help = 'Dopo l''aggiunta VBR usa i certificati: la password non serve piu''.' }
    @{ Key = 'LockdownForce'; Label = 'Blinda anche se Veeam non risulta installato'; Type = 'Bool'; Help = "Normalmente la blindatura si rifiuta se non trova /opt/veeam, per non chiudere fuori l'operatore prima dell'aggiunta in VBR." }
    @{ Key = 'RemoveTargets'; Label = 'Target da disconnettere'; Type = 'List'; Help = 'IQN o caratteri jolly: aggiunge il passo Disconnessione (logout ed eliminazione del nodo). Le LUN montate bloccano la disconnessione.' }
    @{ Key = 'RemoveDiscovery'; Label = 'Elimina anche la discovery del portale'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Script, log e simulazione' }
    @{ Key = 'ScriptPath'; Label = 'vrepo-setup.sh alternativo'; Type = 'File'; Filter = 'Script bash (*.sh)|*.sh|Tutti i file (*.*)|*.*'; Help = 'Vuoto = la versione incorporata in questo tool (consigliato).' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = "Attiva di default: ogni passo mostra i comandi che eseguirebbe sul server. Fa eccezione il passo Accesso, che installa chiave e script anche in simulazione (non tocca storage, rete o utenti)." }
)

$ToolColumns = @(
    @{ Name = 'Passo'; Header = 'Passo'; Weight = 9 }
    @{ Name = 'Dettaglio'; Header = 'Dettaglio'; Weight = 26 }
    @{ Name = 'Dispositivo'; Header = 'Dispositivo'; Weight = 10 }
    @{ Name = 'Dimensione'; Header = 'Dimensione'; Weight = 6 }
    @{ Name = 'Percorsi'; Header = 'Percorsi'; Weight = 5 }
    @{ Name = 'Nome'; Header = 'Nome'; Weight = 9 }
    @{ Name = 'Mount'; Header = 'Mount'; Weight = 11 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 10 }
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
