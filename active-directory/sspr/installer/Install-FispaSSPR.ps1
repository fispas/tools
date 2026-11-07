<#
.SYNOPSIS
    Installazione guidata di FispaSSPR (Self Service Password Reset on-prem).

.DESCRIPTION
    Procedura passo passo con interfaccia grafica: chiede solo le informazioni necessarie ed esegue tutto il resto.
      1. pacchetto dell'applicazione (cartella app accanto allo script, zip, oppure download da GitHub con token)
      2. prerequisiti e strumenti RSAT (installati in automatico se mancano)
      3. estensione dello schema AD (una volta per foresta, con conferma)
      4. KDS root key e gMSA dedicato, installato e verificato su questo server, SPN HTTP
      5. OU abilitate, gruppi SSPR-Admins / SSPR-Helpdesk, deleghe minime sulle OU
      6. certificato HTTPS (esistente, CA aziendale, PFX o autofirmato) e accesso del gMSA alla chiave privata
      7. impostazioni del portale, SMTP e gateway SMS con pulsanti di test
      8. chiave master protetta verso il gMSA con backup cifrato da password
      9. servizio Windows, firewall, Registro eventi, avvio e verifica
    Lo stato viene salvato: se serve attendere (es. KDS root key appena creata) si riprende dal punto lasciato.
    Rieseguito su un'installazione esistente aggiorna l'applicazione mantenendo configurazione e chiavi.

.PARAMETER PackagePath
    Cartella o zip del pacchetto. Default: cartella dello script.

.PARAMETER Uninstall
    Rimuove servizio, programma e regola firewall (con scelta se mantenere dati e chiave master).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-FispaSSPR.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Install-FispaSSPR.ps1 -Uninstall

.NOTES
    Versione: 0.3.0
    Repo:     fispas/tools (active-directory/sspr/installer)
    Richiede: server membro del dominio (non DC), Windows Server 2016+, amministratore locale e diritti AD adeguati
              (Domain Admins per gMSA/deleghe/gruppi, Schema Admins solo per lo schema)
#>
[CmdletBinding()]
param(
    [string]$PackagePath,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ elevazione e STA
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $a = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($PackagePath) { $a += @('-PackagePath', "`"$PackagePath`"") }
    if ($Uninstall) { $a += '-Uninstall' }
    if ($isAdmin) { Start-Process powershell.exe -ArgumentList $a } else { Start-Process powershell.exe -ArgumentList $a -Verb RunAs }
    return
}

Add-Type -AssemblyName System.Windows.Forms, System.Drawing, System.DirectoryServices
[System.Windows.Forms.Application]::EnableVisualStyles()
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Version = '0.3.0'
$DataDir = Join-Path $env:ProgramData 'FispaSSPR'
$InstallDir = Join-Path $env:ProgramFiles 'FispaSSPR'
$StateFile = Join-Path $DataDir 'installer-state.json'
$LogFile = Join-Path $DataDir ('installer_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$ServiceName = 'FispaSSPR'
$SchemaGuids = @{
    Totp = 'e0101ee0-1337-489b-af18-19030f5541b3'; Mobile = 'add97609-b42b-4356-b2fa-de347b6296a5'
    Email = 'f5f5c563-eb3b-401c-888b-9228100d4316'; State = 'e7b77c31-6dde-4b73-a8e5-25603cc507a5'
}
$G_UserClass = 'bf967aba-0de6-11d0-a285-00aa003049e2'
$G_ResetPassword = '00299570-246d-11d0-a768-00aa006e0529'
$G_LockoutTime = '28630ebf-41d5-11d1-a9c1-0000f80367c1'
$G_PwdLastSet = 'bf967a0a-0de6-11d0-a285-00aa003049e2'
$G_TokenGroups = 'b7c69e6d-2cc7-11d2-854e-00a0c983f608'
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

# ------------------------------------------------------------------ stato (niente segreti su disco)
$W = [ordered]@{
    Package = ''; Schema = $false; GmsaName = 'gmsa-sspr'; GmsaSid = ''; GmsaOu = ''; SpnDone = $false; Alias = ''
    UserOus = @(); ExcludedGroups = @(); AdminGroup = 'SSPR-Admins'; HelpdeskGroup = 'SSPR-Helpdesk'; GroupOu = ''; AddMeToAdmins = $true
    AdminGroupSid = ''; HelpdeskGroupSid = ''; ExcludedGroupSids = @(); Delegated = $false
    CertMode = 'Esistente'; CertThumbprint = ''; CertTemplate = 'WebServer'; Port = 443
    Company = ''; Helpdesk = ''; Totp = $true; Sms = $true; Email = $true; MinMethods = 2; ResetVerifications = 2
    SmtpHost = ''; SmtpPort = 25; SmtpTls = $true; SmtpFrom = ''; SmtpUser = ''
    SmsProvider = 'AndroidGatewayLocal'; SmsEndpoint = 'http://192.168.1.50:8080/message'; SmsUser = ''
    Breached = 'OnlineKAnonymity'; BannedWords = @(); BackupFile = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'FispaSSPR-chiave-backup.json')
}
if (Test-Path -LiteralPath $StateFile) {
    try {
        $saved = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
        foreach ($p in $saved.PSObject.Properties) { if ($W.Contains($p.Name)) { $W[$p.Name] = $p.Value } }
    } catch { }
}
$Secrets = @{ SmtpPassword = ''; SmsPassword = ''; BackupPassword = '' }
function Save-State { ([pscustomobject]$W | ConvertTo-Json -Depth 4) | Set-Content -LiteralPath $StateFile -Encoding UTF8 }

# ------------------------------------------------------------------ utilita'
$script:LogBox = $null
function Log([string]$m, [string]$level = 'INFO') {
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $level, $m
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
    if ($script:LogBox) {
        $c = switch ($level) { 'OK' { 'DarkGreen' } 'WARN' { 'DarkOrange' } 'ERROR' { 'Firebrick' } default { 'Black' } }
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.SelectionColor = [System.Drawing.Color]::$c
        $script:LogBox.AppendText($line + "`r`n")
        $script:LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}
function Show-Error([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, 'FispaSSPR', 'OK', 'Error') }
function Show-Info([string]$m) { [void][System.Windows.Forms.MessageBox]::Show($m, 'FispaSSPR', 'OK', 'Information') }
function Confirm-Box([string]$m) { [System.Windows.Forms.MessageBox]::Show($m, 'FispaSSPR', 'YesNo', 'Question') -eq 'Yes' }

# Esegue un blocco in background mantenendo l'interfaccia reattiva; rilancia gli errori
function Invoke-Async([scriptblock]$Script, [hashtable]$Vars = @{}) {
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState = 'STA'; $rs.Open()
    foreach ($k in $Vars.Keys) { $rs.SessionStateProxy.SetVariable($k, $Vars[$k]) }
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript('$ErrorActionPreference = "Stop"; ' + $Script.ToString())
    $h = $ps.BeginInvoke()
    $form.UseWaitCursor = $true
    try {
        while (-not $h.IsCompleted) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 80 }
        try { $out = $ps.EndInvoke($h) } catch { throw $_.Exception.InnerException }
        if ($ps.Streams.Error.Count) { throw $ps.Streams.Error[0].Exception }
        return $out
    } finally { $form.UseWaitCursor = $false; $ps.Dispose(); $rs.Close() }
}

function Get-DomainInfo {
    $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $root = [adsi]'LDAP://RootDSE'
    [pscustomobject]@{
        Dns = $d.Name; NetBios = $env:USERDOMAIN; Dn = [string]$root.defaultNamingContext; Schema = [string]$root.schemaNamingContext
        ForestDn = [string]$root.rootDomainNamingContext; SchemaMaster = $d.Forest.SchemaRoleOwner.Name; Dc = $d.FindDomainController().Name
    }
}

function Test-Schema {
    $di = Get-DomainInfo
    $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$($di.Schema)", '(lDAPDisplayName=fispaSsprTotp)')
    [bool]$s.FindOne()
}

function Get-AllOus {
    $di = Get-DomainInfo
    $s = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$($di.Dn)", '(objectClass=organizationalUnit)')
    $s.PageSize = 1000; [void]$s.PropertiesToLoad.Add('distinguishedName')
    @($s.FindAll() | ForEach-Object { [string]$_.Properties['distinguishedname'][0] } | Sort-Object { ($_ -split ',').Count }, { $_ })
}

function Ensure-Rsat {
    if (Get-Module -ListAvailable ActiveDirectory) { return }
    Log 'Modulo ActiveDirectory mancante: installazione degli strumenti RSAT in corso...'
    Invoke-Async {
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) { Install-WindowsFeature RSAT-AD-PowerShell, RSAT-ADDS-Tools | Out-Null }
        else { Get-WindowsCapability -Online -Name 'Rsat.ActiveDirectory*' | Add-WindowsCapability -Online | Out-Null }
    } | Out-Null
    Log 'Strumenti RSAT installati.' 'OK'
}

# ------------------------------------------------------------------ disinstallazione
if ($Uninstall) {
    $keep = [System.Windows.Forms.MessageBox]::Show("Disinstallare FispaSSPR da $env:COMPUTERNAME?`r`n`r`nSi = rimuove servizio, programma e regola firewall, MANTIENE dati e chiave master in $DataDir (reinstallazione senza perdere le registrazioni).`r`nNo = rimuove anche $DataDir (le registrazioni in AD diventano illeggibili senza il backup della chiave).`r`nAnnulla = esce.", 'FispaSSPR', 'YesNoCancel', 'Warning')
    if ($keep -eq 'Cancel') { return }
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue; & sc.exe delete $ServiceName | Out-Null }
    Get-NetFirewallRule -DisplayName 'FispaSSPR HTTPS' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Start-Sleep -Seconds 2
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    if ($keep -eq 'No' -and (Test-Path $DataDir)) { Remove-Item $DataDir -Recurse -Force }
    [void][System.Windows.Forms.MessageBox]::Show("Disinstallazione completata.`r`nRestano in Active Directory (da rimuovere a mano se non servono): gMSA, gruppi operatori, deleghe sulle OU, SPN, estensione dello schema (permanente).", 'FispaSSPR', 'OK', 'Information')
    return
}

# ------------------------------------------------------------------ interfaccia: telaio della procedura
$form = New-Object System.Windows.Forms.Form
$form.Text = "Installazione FispaSSPR $Version - $env:COMPUTERNAME"
$form.Size = New-Object System.Drawing.Size(1000, 760)
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.MinimumSize = New-Object System.Drawing.Size(900, 680)

$steps = New-Object System.Windows.Forms.ListBox
$steps.Dock = 'Left'; $steps.Width = 230; $steps.Enabled = $false; $steps.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$content = New-Object System.Windows.Forms.Panel
$content.Dock = 'Fill'; $content.AutoScroll = $true; $content.Padding = New-Object System.Windows.Forms.Padding(16)
$bottom = New-Object System.Windows.Forms.Panel
$bottom.Dock = 'Bottom'; $bottom.Height = 190
$logBox = New-Object System.Windows.Forms.RichTextBox
$logBox.Dock = 'Fill'; $logBox.ReadOnly = $true; $logBox.Font = New-Object System.Drawing.Font('Consolas', 8.5); $logBox.BackColor = [System.Drawing.Color]::White
$script:LogBox = $logBox
$nav = New-Object System.Windows.Forms.FlowLayoutPanel
$nav.Dock = 'Bottom'; $nav.Height = 44; $nav.FlowDirection = 'RightToLeft'; $nav.Padding = New-Object System.Windows.Forms.Padding(8)
$btnNext = New-Object System.Windows.Forms.Button; $btnNext.Text = 'Avanti >'; $btnNext.Width = 120; $btnNext.Height = 30
$btnBack = New-Object System.Windows.Forms.Button; $btnBack.Text = '< Indietro'; $btnBack.Width = 110; $btnBack.Height = 30
$btnClose = New-Object System.Windows.Forms.Button; $btnClose.Text = 'Chiudi'; $btnClose.Width = 90; $btnClose.Height = 30
$nav.Controls.AddRange(@($btnNext, $btnBack, $btnClose))
$bottom.Controls.Add($logBox); $bottom.Controls.Add($nav); $logBox.BringToFront()
$form.Controls.Add($content); $form.Controls.Add($steps); $form.Controls.Add($bottom); $content.BringToFront()

# helper per costruire le pagine
$script:Y = 0
function New-Page([string]$Title, [string]$Intro) {
    $content.Controls.Clear(); $script:Y = 4
    $t = New-Object System.Windows.Forms.Label; $t.Text = $Title; $t.AutoSize = $true; $t.Location = New-Object System.Drawing.Point(4, $script:Y)
    $t.Font = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold); $content.Controls.Add($t); $script:Y += 36
    if ($Intro) { Add-Text $Intro }
}
function Add-Text([string]$Text, [string]$Color = 'DimGray') {
    $l = New-Object System.Windows.Forms.Label; $l.Text = $Text; $l.AutoSize = $true; $l.MaximumSize = New-Object System.Drawing.Size(700, 0)
    $l.ForeColor = [System.Drawing.Color]::$Color; $l.Location = New-Object System.Drawing.Point(4, $script:Y); $content.Controls.Add($l)
    $script:Y += $l.PreferredHeight + 10; $l
}
function Add-Field([string]$Label, [string]$Value, [switch]$Password, [int]$Width = 420) {
    $l = New-Object System.Windows.Forms.Label; $l.Text = $Label; $l.AutoSize = $true; $l.Location = New-Object System.Drawing.Point(4, ($script:Y + 4)); $content.Controls.Add($l)
    $t = New-Object System.Windows.Forms.TextBox; $t.Location = New-Object System.Drawing.Point(250, $script:Y); $t.Width = $Width; $t.Text = [string]$Value
    if ($Password) { $t.UseSystemPasswordChar = $true }
    $content.Controls.Add($t); $script:Y += 30; $t
}
function Add-Check([string]$Label, [bool]$Checked) {
    $c = New-Object System.Windows.Forms.CheckBox; $c.Text = $Label; $c.AutoSize = $true; $c.Checked = $Checked
    $c.Location = New-Object System.Drawing.Point(4, $script:Y); $content.Controls.Add($c); $script:Y += 28; $c
}
function Add-Combo([string]$Label, [string[]]$Items, [string]$Selected, [int]$Width = 420) {
    $l = New-Object System.Windows.Forms.Label; $l.Text = $Label; $l.AutoSize = $true; $l.Location = New-Object System.Drawing.Point(4, ($script:Y + 4)); $content.Controls.Add($l)
    $c = New-Object System.Windows.Forms.ComboBox; $c.DropDownStyle = 'DropDownList'; $c.Location = New-Object System.Drawing.Point(250, $script:Y); $c.Width = $Width
    [void]$c.Items.AddRange([object[]]$Items); if ($Selected -and $c.Items.Contains($Selected)) { $c.SelectedItem = $Selected } elseif ($c.Items.Count) { $c.SelectedIndex = 0 }
    $content.Controls.Add($c); $script:Y += 30; $c
}
function Add-Button([string]$Text, [scriptblock]$OnClick, [int]$X = 250) {
    $b = New-Object System.Windows.Forms.Button; $b.Text = $Text; $b.AutoSize = $true; $b.Location = New-Object System.Drawing.Point($X, $script:Y)
    $b.Tag = $OnClick
    $b.Add_Click({ param($s, $e) try { & $s.Tag } catch { Log $_.Exception.Message 'ERROR'; Show-Error $_.Exception.Message } })
    $content.Controls.Add($b); $script:Y += 36; $b
}

# ------------------------------------------------------------------ pagine
$Pages = New-Object System.Collections.Generic.List[object]
function Add-Page([string]$Name, [scriptblock]$Show, [scriptblock]$Leave) { $Pages.Add(@{ Name = $Name; Show = $Show; Leave = $Leave }); [void]$steps.Items.Add($Name) }

# 1 - pacchetto e prerequisiti -------------------------------------------------------------
Add-Page 'Pacchetto e prerequisiti' {
    New-Page 'Pacchetto e prerequisiti' "Questa procedura installa il portale FispaSSPR su questo server ($env:COMPUTERNAME). Serve il pacchetto dell'applicazione: se lo script e' nella cartella del pacchetto viene trovato da solo."
    $pkg = $W.Package
    if (-not $pkg) { $base = if ($PackagePath) { $PackagePath } else { $PSScriptRoot }; $pkg = $base }
    $script:fPkg = Add-Field 'Pacchetto (cartella o .zip)' $pkg -Width 520
    Add-Button 'Sfoglia zip...' { $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Filter = 'Pacchetto (*.zip)|*.zip'; if ($d.ShowDialog() -eq 'OK') { $script:fPkg.Text = $d.FileName } } | Out-Null
    Add-Text 'Oppure scarica l''ultimo pacchetto compilato da GitHub (repo privato: serve un token fine-grained con permesso Actions: Read).'
    $script:fRepo = Add-Field 'Repository (proprietario/nome)' 'fispas/tools'
    $script:fToken = Add-Field 'Token GitHub' '' -Password
    Add-Button 'Scarica pacchetto' {
        $repo = $script:fRepo.Text.Trim(); $tok = $script:fToken.Text.Trim()
        if (-not $tok) { throw 'Inserire il token.' }
        Log "Ricerca dell'ultimo pacchetto su $repo..."
        $dest = Join-Path $DataDir 'package'
        Invoke-Async {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $h = @{ Authorization = "Bearer $tok"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'FispaSSPR-Installer' }
            $a = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/artifacts?name=FispaSSPR-package&per_page=1" -Headers $h
            if (-not $a.artifacts) { throw 'Nessun pacchetto FispaSSPR-package trovato (la pipeline e'' stata eseguita?).' }
            $zip = Join-Path $env:TEMP 'FispaSSPR-package.zip'
            Invoke-WebRequest -Uri $a.artifacts[0].archive_download_url -Headers $h -OutFile $zip -UseBasicParsing
            if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
            Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force
            Remove-Item $zip -Force
        } @{ repo = $repo; tok = $tok; dest = $dest } | Out-Null
        $script:fToken.Text = ''
        $script:fPkg.Text = $dest
        Log "Pacchetto scaricato in $dest" 'OK'
    } | Out-Null
    $script:Y += 8
    Add-Text 'Prerequisiti verificati premendo Avanti: server membro del dominio (non domain controller), Windows Server 2016 o successivo, strumenti RSAT (installati se mancano).'
} {
    $p = $script:fPkg.Text.Trim()
    if ($p -like '*.zip') {
        $dest = Join-Path $DataDir 'package'
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        Expand-Archive -LiteralPath $p -DestinationPath $dest -Force; $p = $dest
    }
    $exe = @(Get-ChildItem -LiteralPath $p -Recurse -Filter 'FispaSSPR.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $exe) { throw "FispaSSPR.exe non trovato in $p : indicare la cartella del pacchetto o scaricarlo." }
    $W.Package = $exe[0].DirectoryName
    $cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
    if (-not $cs.PartOfDomain) { throw 'Il server non e'' membro di un dominio.' }
    if ($cs.DomainRole -ge 4) { throw 'Questo server e'' un domain controller: installare il portale su un server membro.' }
    if ([version]$os.Version -lt [version]'10.0.14393') { throw 'Serve Windows Server 2016 o successivo.' }
    Ensure-Rsat
    Import-Module ActiveDirectory
    Log "Pacchetto: $($W.Package)" 'OK'
    $true
}

# 2 - schema -------------------------------------------------------------------------------
Add-Page 'Schema Active Directory' {
    New-Page 'Schema Active Directory' 'Il portale salva i metodi registrati in 4 attributi confidenziali (classe ausiliaria fispaSsprUser). L''estensione si fa una sola volta per foresta ed e'' PERMANENTE: gli attributi si possono disattivare, non eliminare. Serve un membro di Schema Admins.'
    $ok = Test-Schema
    $W.Schema = $ok
    if ($ok) { Add-Text 'Schema gia'' esteso: nessuna azione necessaria.' 'DarkGreen' | Out-Null; return }
    $di = Get-DomainInfo
    Add-Text "Schema Master: $($di.SchemaMaster)   Foresta: $($di.ForestDn)" | Out-Null
    $script:cSchema = Add-Check 'Ho capito che l''estensione dello schema e'' permanente' $false
    Add-Button 'Estendi lo schema (account corrente)' { Invoke-Schema $null } | Out-Null
    Add-Button 'Estendi con credenziali di uno Schema Admin...' { $c = Get-Credential -Message 'Account membro di Schema Admins'; if ($c) { Invoke-Schema $c } } | Out-Null
    Add-Text 'In alternativa uno Schema Admin puo'' importare il file schema\FispaSSPR-Schema.ldf del pacchetto (comando nel README); poi premere Avanti.'
} {
    if (-not (Test-Schema)) { throw 'Lo schema non risulta ancora esteso.' }
    $W.Schema = $true; $true
}
function Invoke-Schema($cred) {
    if (-not $script:cSchema.Checked) { throw 'Confermare di aver capito che l''estensione e'' permanente.' }
    $ldf = @(Get-ChildItem -LiteralPath (Split-Path $W.Package -Parent), $W.Package, $PSScriptRoot -Recurse -Filter 'FispaSSPR-Schema.ldf' -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $ldf) { throw 'File FispaSSPR-Schema.ldf non trovato nel pacchetto.' }
    if (-not (Get-Command ldifde.exe -ErrorAction SilentlyContinue)) {
        Log 'Installazione di ldifde (RSAT-ADDS-Tools)...'
        Invoke-Async { Install-WindowsFeature RSAT-ADDS-Tools | Out-Null } | Out-Null
    }
    $di = Get-DomainInfo
    $logDir = Join-Path $DataDir 'schema-log'; New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    $args2 = @('-i', '-f', "`"$($ldf[0].FullName)`"", '-s', $di.SchemaMaster, '-c', '"DC=X"', "`"$($di.ForestDn)`"", '-k', '-j', "`"$logDir`"")
    Log "Import dello schema su $($di.SchemaMaster)..."
    $p = if ($cred) { Start-Process ldifde.exe -ArgumentList $args2 -Credential $cred -Wait -PassThru } else { Start-Process ldifde.exe -ArgumentList $args2 -Wait -PassThru -WindowStyle Hidden }
    if ($p.ExitCode -ne 0) { throw "ldifde terminato con codice $($p.ExitCode): vedere i log in $logDir (servono i diritti di Schema Admins)." }
    Start-Sleep -Seconds 5
    if (-not (Test-Schema)) { throw 'Import eseguito ma attributi non ancora visibili: attendere la replica e premere Avanti.' }
    Log 'Schema esteso.' 'OK'
    Show-Info 'Schema esteso correttamente.'
}

# 3 - gMSA ---------------------------------------------------------------------------------
Add-Page 'Account del servizio (gMSA)' {
    New-Page 'Account del servizio (gMSA)' 'Il portale gira con un Group Managed Service Account: nessuna password da gestire, rotazione automatica. Lo creo e lo installo su questo server.'
    $script:fGmsa = Add-Field 'Nome del gMSA (max 15 caratteri)' $W.GmsaName
    $script:fAlias = Add-Field 'Nome DNS del portale (opzionale)' $W.Alias
    Add-Text "Es. password.$((Get-DomainInfo).Dns): se indicato, registro anche il suo SPN; il record DNS (CNAME verso $env:COMPUTERNAME) va creato sul DNS." | Out-Null
    $kds = @(Get-KdsRootKey -ErrorAction SilentlyContinue)
    if ($kds.Count) {
        $eff = ($kds | Sort-Object EffectiveTime | Select-Object -First 1).EffectiveTime
        if ($eff -gt (Get-Date)) { Add-Text "KDS root key presente ma utilizzabile dal $($eff): tornare dopo quell'ora (lo stato della procedura e' salvato)." 'DarkOrange' | Out-Null }
        else { Add-Text 'KDS root key presente e valida.' 'DarkGreen' | Out-Null }
    } else {
        Add-Text 'KDS root key assente: va creata una volta per foresta. Diventa utilizzabile dopo 10 ore (tempo di replica tra i DC).' 'DarkOrange' | Out-Null
        Add-Button 'Crea la KDS root key' { Add-KdsRootKey -EffectiveImmediately | Out-Null; Log 'KDS root key creata: utilizzabile tra 10 ore.' 'WARN'; Show-Info "KDS root key creata. Il gMSA si potra' creare tra 10 ore: chiudere e rieseguire l'installer piu' tardi." } | Out-Null
        Add-Button 'Ambiente con UN SOLO domain controller: rendila subito utilizzabile' {
            if (Confirm-Box 'Solo se il dominio ha un unico DC (laboratorio o piccola realta''). Con piu'' DC la chiave potrebbe non essere ancora replicata. Procedere?') {
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null; Log 'KDS root key creata e subito valida (singolo DC).' 'WARN'; & $Pages[2].Show
            }
        } | Out-Null
    }
} {
    $name = $script:fGmsa.Text.Trim()
    if ($name -notmatch '^[A-Za-z0-9-]{1,15}$') { throw 'Nome gMSA non valido (lettere, numeri, trattino; massimo 15 caratteri).' }
    $W.GmsaName = $name; $W.Alias = $script:fAlias.Text.Trim()
    $kds = @(Get-KdsRootKey -ErrorAction SilentlyContinue | Where-Object { $_.EffectiveTime -le (Get-Date) })
    if (-not $kds.Count) { throw 'KDS root key assente o non ancora valida.' }
    $di = Get-DomainInfo
    $me = Get-ADComputer $env:COMPUTERNAME
    $g = Get-ADServiceAccount -Filter "Name -eq '$name'" -Properties PrincipalsAllowedToRetrieveManagedPassword
    if (-not $g) {
        Log "Creazione del gMSA $name..."
        New-ADServiceAccount -Name $name -DNSHostName "$name.$($di.Dns)" -PrincipalsAllowedToRetrieveManagedPassword $me -KerberosEncryptionType AES128, AES256 -Description 'FispaSSPR - portale password'
        $g = Get-ADServiceAccount -Identity $name -Properties PrincipalsAllowedToRetrieveManagedPassword
    } elseif (@($g.PrincipalsAllowedToRetrieveManagedPassword) -notcontains $me.DistinguishedName) {
        Log "Autorizzo $env:COMPUTERNAME a usare il gMSA esistente $name..."
        Set-ADServiceAccount -Identity $name -PrincipalsAllowedToRetrieveManagedPassword (@($g.PrincipalsAllowedToRetrieveManagedPassword) + $me.DistinguishedName)
    }
    Install-ADServiceAccount -Identity $name
    if (-not (Test-ADServiceAccount -Identity $name)) { throw "Test-ADServiceAccount fallito: verificare che $env:COMPUTERNAME sia autorizzato e riprovare (se appena autorizzato puo' servire un klist purge -li 0x3e7)." }
    $W.GmsaSid = $g.SID.Value
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    foreach ($spn in @("HTTP/$fqdn", "HTTP/$env:COMPUTERNAME") + @(if ($W.Alias) { "HTTP/$($W.Alias)" })) {
        $out = & setspn.exe -S $spn "$($di.NetBios)\$name`$" 2>&1
        Log "setspn $spn : $(@($out)[-1])"
    }
    $W.SpnDone = $true
    Log "gMSA $name pronto (SID $($W.GmsaSid))." 'OK'
    $true
}

# 4 - OU e gruppi --------------------------------------------------------------------------
Add-Page 'Utenti abilitati e operatori' {
    New-Page 'Utenti abilitati e operatori' 'Scegli le OU degli utenti che potranno usare il portale (comprese le sotto-OU). Gli account privilegiati restano comunque esclusi.'
    $script:lOus = New-Object System.Windows.Forms.CheckedListBox
    $script:lOus.Location = New-Object System.Drawing.Point(4, $script:Y); $script:lOus.Size = New-Object System.Drawing.Size(700, 200); $script:lOus.CheckOnClick = $true
    foreach ($ou in (Get-AllOus)) { $i = $script:lOus.Items.Add($ou); if (@($W.UserOus) -contains $ou) { $script:lOus.SetItemChecked($i, $true) } }
    $content.Controls.Add($script:lOus); $script:Y += 210
    $script:fExcl = Add-Field 'Gruppi esclusi (nomi, separati da ;)' ((@($W.ExcludedGroups)) -join '; ')
    $script:fAdmG = Add-Field 'Gruppo amministratori del portale' $W.AdminGroup
    $script:fHdG = Add-Field 'Gruppo help desk' $W.HelpdeskGroup
    $script:cGroupOu = Add-Combo 'OU in cui creare i gruppi' (@('(contenitore Users)') + (Get-AllOus)) $W.GroupOu -Width 520
    $script:cMe = Add-Check "Aggiungi $env:USERNAME al gruppo amministratori" ([bool]$W.AddMeToAdmins)
} {
    $ous = @($script:lOus.CheckedItems | ForEach-Object { [string]$_ })
    if (-not $ous.Count) { throw 'Selezionare almeno una OU.' }
    $W.UserOus = $ous
    $W.ExcludedGroups = @($script:fExcl.Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $W.AdminGroup = $script:fAdmG.Text.Trim(); $W.HelpdeskGroup = $script:fHdG.Text.Trim()
    $W.GroupOu = if ($script:cGroupOu.SelectedIndex -le 0) { '' } else { [string]$script:cGroupOu.SelectedItem }
    $W.AddMeToAdmins = $script:cMe.Checked
    $sids = @()
    foreach ($gn in $W.ExcludedGroups) { $g = Get-ADGroup -Filter "Name -eq '$gn'"; if (-not $g) { throw "Gruppo escluso non trovato: $gn" }; $sids += $g.SID.Value }
    $W.ExcludedGroupSids = $sids
    foreach ($pair in @(@($W.AdminGroup, 'AdminGroupSid', 'FispaSSPR - amministratori del portale password'), @($W.HelpdeskGroup, 'HelpdeskGroupSid', 'FispaSSPR - help desk del portale password'))) {
        $g = Get-ADGroup -Filter "Name -eq '$($pair[0])'"
        if (-not $g) {
            $p = @{ Name = $pair[0]; GroupScope = 'Global'; GroupCategory = 'Security'; Description = $pair[2] }
            if ($W.GroupOu) { $p.Path = $W.GroupOu }
            New-ADGroup @p; $g = Get-ADGroup -Identity $pair[0]; Log "Creato il gruppo $($pair[0])" 'OK'
        }
        $W[$pair[1]] = $g.SID.Value
    }
    if ($W.AddMeToAdmins) { Add-ADGroupMember -Identity $W.AdminGroup -Members ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value) -ErrorAction SilentlyContinue; Log "$env:USERNAME aggiunto a $($W.AdminGroup) (vale dal prossimo logon)." }
    # deleghe minime sulle OU
    $sid = New-Object Security.Principal.SecurityIdentifier($W.GmsaSid)
    $user = [guid]$G_UserClass
    $inh = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
    foreach ($ou in $W.UserOus) {
        $de = ([adsi]"LDAP://$ou").psbase
        $sec = $de.ObjectSecurity
        $rules = @(
            (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', [guid]$G_ResetPassword, $inh, $user)),
            (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ReadProperty, WriteProperty', 'Allow', [guid]$G_LockoutTime, $inh, $user)),
            (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ReadProperty, WriteProperty', 'Allow', [guid]$G_PwdLastSet, $inh, $user)),
            (New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ReadProperty', 'Allow', [guid]$G_TokenGroups, $inh, $user))
        )
        foreach ($g in $SchemaGuids.Values) { $rules += New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, 'ReadProperty, WriteProperty, ExtendedRight', 'Allow', [guid]$g, $inh, $user) }
        foreach ($r in $rules) { $sec.AddAccessRule($r) }
        $de.ObjectSecurity = $sec
        $de.CommitChanges()
        Log "Deleghe applicate su $ou" 'OK'
    }
    $W.Delegated = $true
    $true
}

# 5 - certificato --------------------------------------------------------------------------
Add-Page 'Certificato HTTPS' {
    New-Page 'Certificato HTTPS' 'Il portale risponde solo in HTTPS. Scegli come ottenere il certificato.'
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    $script:cMode = Add-Combo 'Origine' @('Esistente', 'CA aziendale', 'File PFX', 'Autofirmato (solo test)') $W.CertMode
    $certs = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } | Sort-Object NotAfter -Descending)
    $script:cCert = Add-Combo 'Certificato esistente' @($certs | ForEach-Object { '{0} | {1} | scade {2:dd/MM/yyyy}' -f $_.Thumbprint, $_.Subject, $_.NotAfter }) '' -Width 640
    $script:fTpl = Add-Field 'Modello della CA' $W.CertTemplate
    $script:fNames = Add-Field 'Nomi DNS del certificato' ((@($fqdn) + @(if ($W.Alias) { $W.Alias })) -join ', ') -Width 520
    $script:fPfx = Add-Field 'File PFX' ''
    $script:fPfxPwd = Add-Field 'Password del PFX' '' -Password
    $script:fPort = Add-Field 'Porta HTTPS' $W.Port -Width 80
} {
    $mode = [string]$script:cMode.SelectedItem; $W.CertMode = $mode
    $port = 0; if (-not [int]::TryParse($script:fPort.Text, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw 'Porta non valida.' }
    $W.Port = $port
    $names = @($script:fNames.Text -split '[,; ]+' | Where-Object { $_ })
    switch -Wildcard ($mode) {
        'Esistente' { if (-not $script:cCert.SelectedItem) { throw 'Nessun certificato selezionato.' }; $tp = ([string]$script:cCert.SelectedItem).Split('|')[0].Trim() }
        'CA*' {
            $W.CertTemplate = $script:fTpl.Text.Trim()
            Log "Richiesta del certificato alla CA (modello $($W.CertTemplate))..."
            $r = Get-Certificate -Template $W.CertTemplate -DnsName $names -SubjectName "CN=$($names[0])" -CertStoreLocation Cert:\LocalMachine\My
            if ($r.Status -ne 'Issued') { throw "Richiesta non emessa subito (stato $($r.Status)): approvarla sulla CA e scegliere 'Esistente'." }
            $tp = $r.Certificate.Thumbprint
        }
        'File*' {
            $pw = ConvertTo-SecureString $script:fPfxPwd.Text -AsPlainText -Force
            $tp = (Import-PfxCertificate -FilePath $script:fPfx.Text.Trim() -CertStoreLocation Cert:\LocalMachine\My -Password $pw -Exportable:$false).Thumbprint
            $script:fPfxPwd.Text = ''
        }
        default {
            if (-not (Confirm-Box 'Il certificato autofirmato genera avvisi nei browser: usarlo solo per prove. Procedere?')) { return $false }
            $tp = (New-SelfSignedCertificate -DnsName $names -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2) -KeyExportPolicy NonExportable).Thumbprint
        }
    }
    $cert = Get-Item "Cert:\LocalMachine\My\$tp"
    # accesso del gMSA alla chiave privata
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $keyFile = $null
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $u = $rsa.Key.UniqueName
        $keyFile = @("$env:ProgramData\Microsoft\Crypto\Keys\$u", "$env:ProgramData\Microsoft\Crypto\SystemKeys\$u") | Where-Object { Test-Path $_ } | Select-Object -First 1
    } elseif ($rsa) {
        $keyFile = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($rsa.CspKeyContainerInfo.UniqueKeyContainerName)"
    }
    if (-not $keyFile -or -not (Test-Path $keyFile)) { throw 'File della chiave privata non trovato: usare un certificato RSA con chiave nel computer.' }
    $o = & icacls.exe $keyFile /grant "*$($W.GmsaSid):R" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Permesso sulla chiave privata non assegnato: $o" }
    $W.CertThumbprint = $tp
    Log "Certificato $tp pronto, letto dal gMSA." 'OK'
    $true
}

# 6 - impostazioni e canali ----------------------------------------------------------------
Add-Page 'Portale, email e SMS' {
    New-Page 'Portale, email e SMS' 'Impostazioni principali (tutte modificabili poi dal pannello di amministrazione).'
    $script:fCompany = Add-Field 'Nome azienda' $W.Company
    $script:fHelp = Add-Field 'Contatto help desk' $W.Helpdesk
    $script:cTotp = Add-Check 'App di autenticazione (TOTP)' ([bool]$W.Totp)
    $script:cSms = Add-Check 'SMS' ([bool]$W.Sms)
    $script:cEmail = Add-Check 'Email personale' ([bool]$W.Email)
    $script:fMin = Add-Field 'Metodi minimi da registrare' $W.MinMethods -Width 60
    $script:fResetV = Add-Field 'Verifiche richieste per il reset' $W.ResetVerifications -Width 60
    $script:Y += 6; Add-Text 'Email (SMTP)' 'Black' | Out-Null
    $script:fSmtpHost = Add-Field 'Server SMTP' $W.SmtpHost
    $script:fSmtpPort = Add-Field 'Porta' $W.SmtpPort -Width 80
    $script:cSmtpTls = Add-Check 'STARTTLS' ([bool]$W.SmtpTls)
    $script:fSmtpFrom = Add-Field 'Mittente' $W.SmtpFrom
    $script:fSmtpUser = Add-Field 'Utente (vuoto = relay anonimo)' $W.SmtpUser
    $script:fSmtpPwd = Add-Field 'Password' $Secrets.SmtpPassword -Password
    $script:fSmtpTest = Add-Field 'Email di prova' ''
    Add-Button 'Invia email di prova' {
        $p = @{ SmtpServer = $script:fSmtpHost.Text; Port = [int]$script:fSmtpPort.Text; From = $script:fSmtpFrom.Text; To = $script:fSmtpTest.Text; Subject = 'Test FispaSSPR'; Body = 'Messaggio di prova dall''installer.'; Encoding = [Text.Encoding]::UTF8 }
        if ($script:cSmtpTls.Checked) { $p.UseSsl = $true }
        if ($script:fSmtpUser.Text) { $p.Credential = New-Object PSCredential($script:fSmtpUser.Text, (ConvertTo-SecureString $script:fSmtpPwd.Text -AsPlainText -Force)) }
        Send-MailMessage @p -WarningAction SilentlyContinue; Log 'Email di prova inviata.' 'OK'; Show-Info 'Email inviata.'
    } | Out-Null
    $script:Y += 6; Add-Text 'SMS: SMS Gateway for Android (app gratuita, modalita'' Local Server) su un telefono con SIM in LAN, oppure connettore HTTP generico.' 'Black' | Out-Null
    $script:cSmsProv = Add-Combo 'Provider' @('AndroidGatewayLocal', 'GenericHttp') $W.SmsProvider
    $script:fSmsUrl = Add-Field 'URL di invio' $W.SmsEndpoint -Width 520
    $script:fSmsUser = Add-Field 'Utente (dall''app)' $W.SmsUser
    $script:fSmsPwd = Add-Field 'Password (dall''app)' $Secrets.SmsPassword -Password
    $script:fSmsTest = Add-Field 'Cellulare di prova (+39...)' ''
    Add-Button 'Invia SMS di prova' {
        $h = @{}
        if ($script:fSmsUser.Text) { $h.Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:fSmsUser.Text + ':' + $script:fSmsPwd.Text)) }
        $body = @{ textMessage = @{ text = 'Test FispaSSPR' }; phoneNumbers = @($script:fSmsTest.Text) } | ConvertTo-Json -Depth 4
        Invoke-RestMethod -Method Post -Uri $script:fSmsUrl.Text -Headers $h -Body $body -ContentType 'application/json' -TimeoutSec 15 | Out-Null
        Log 'SMS di prova inviato.' 'OK'; Show-Info 'SMS inviato.'
    } | Out-Null
    $script:cBreach = Add-Combo 'Password compromesse' @('OnlineKAnonymity', 'OfflineList', 'Off') $W.Breached
    $script:fBanned = Add-Field 'Parole vietate (;)' ((@($W.BannedWords)) -join '; ')
} {
    $W.Company = $script:fCompany.Text.Trim(); $W.Helpdesk = $script:fHelp.Text.Trim()
    $W.Totp = $script:cTotp.Checked; $W.Sms = $script:cSms.Checked; $W.Email = $script:cEmail.Checked
    $W.MinMethods = [int]$script:fMin.Text; $W.ResetVerifications = [int]$script:fResetV.Text
    $W.SmtpHost = $script:fSmtpHost.Text.Trim(); $W.SmtpPort = [int]$script:fSmtpPort.Text; $W.SmtpTls = $script:cSmtpTls.Checked
    $W.SmtpFrom = $script:fSmtpFrom.Text.Trim(); $W.SmtpUser = $script:fSmtpUser.Text.Trim(); $Secrets.SmtpPassword = $script:fSmtpPwd.Text
    $W.SmsProvider = [string]$script:cSmsProv.SelectedItem; $W.SmsEndpoint = $script:fSmsUrl.Text.Trim(); $W.SmsUser = $script:fSmsUser.Text.Trim(); $Secrets.SmsPassword = $script:fSmsPwd.Text
    $W.Breached = [string]$script:cBreach.SelectedItem
    $W.BannedWords = @($script:fBanned.Text -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $m = [int]$W.Totp + [int]$W.Sms + [int]$W.Email
    if ($m -lt $W.MinMethods) { throw "Metodi attivi ($m) inferiori al minimo richiesto ($($W.MinMethods))." }
    if ($W.Email -and (-not $W.SmtpHost -or -not $W.SmtpFrom)) { throw 'Email attiva: indicare server SMTP e mittente.' }
    if ($W.Sms -and -not $W.SmsEndpoint) { throw "SMS attivi: indicare l'URL del gateway." }
    $true
}

# 7 - chiave e installazione ---------------------------------------------------------------
Add-Page 'Installazione' {
    New-Page 'Chiave master e installazione' 'I dati registrati in AD sono cifrati con una chiave master leggibile solo dal gMSA. Serve una password per il file di backup della chiave: conservali separati (es. password nel gestore aziendale, file in un archivio sicuro).'
    $exists = Test-Path (Join-Path $DataDir 'keys\*.key')
    if ($exists) { Add-Text 'Chiave master gia'' presente: viene mantenuta (aggiornamento).' 'DarkGreen' | Out-Null }
    $script:fBkFile = Add-Field 'File di backup della chiave' $W.BackupFile -Width 520
    $script:fBkPwd = Add-Field 'Password del backup (min 12)' '' -Password
    $script:fBkPwd2 = Add-Field 'Ripeti la password' '' -Password
    $script:Y += 6
    Add-Text ("Riepilogo:`r`n- Applicazione in $InstallDir, dati in $DataDir`r`n- Servizio $ServiceName come $($W.GmsaName)`$, porta $($W.Port)`r`n- OU abilitate: $(@($W.UserOus).Count)`r`n- Regola firewall in ingresso solo per i profili Dominio e Privato") 'Black' | Out-Null
    Add-Text 'Premi Avanti per installare.' 'Black' | Out-Null
} {
    $exists = Test-Path (Join-Path $DataDir 'keys\*.key')
    if (-not $exists) {
        if ($script:fBkPwd.Text.Length -lt 12) { throw 'La password del backup deve avere almeno 12 caratteri.' }
        if ($script:fBkPwd.Text -ne $script:fBkPwd2.Text) { throw 'Le password non coincidono.' }
        $Secrets.BackupPassword = $script:fBkPwd.Text
    }
    $W.BackupFile = $script:fBkFile.Text.Trim()
    Install-Portal
    $true
}

function Install-Portal {
    Save-State
    $di = Get-DomainInfo
    # 1. file dell'applicazione
    $svc = Get-Service $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') { Log 'Arresto del servizio esistente...'; Stop-Service $ServiceName -Force; Start-Sleep -Seconds 2 }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Log "Copia dell'applicazione in $InstallDir..."
    $rc = Invoke-Async { & robocopy.exe $src $dst /MIR /R:2 /W:2 /NP /NFL /NDL /NJH /NJS | Out-Null; $LASTEXITCODE } @{ src = $W.Package; dst = $InstallDir }
    if ([int]@($rc)[-1] -ge 8) { throw "Copia dei file non riuscita (robocopy $(@($rc)[-1]))." }
    # 2. cartella dati: SYSTEM, Administrators, gMSA
    foreach ($d in @($DataDir, (Join-Path $DataDir 'keys'), (Join-Path $DataDir 'audit'))) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    & icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($W.GmsaSid):(OI)(CI)M" /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Permessi sulla cartella dati non assegnati.' }
    # 3. configurazione
    $cfgFile = Join-Path $DataDir 'config.json'
    $cfg = if (Test-Path $cfgFile) { Get-Content $cfgFile -Raw | ConvertFrom-Json } else { $null }
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    $host1 = if ($W.Alias) { $W.Alias } else { $fqdn }
    $url = if ([int]$W.Port -eq 443) { "https://$host1/" } else { "https://${host1}:$($W.Port)/" }
    if ($cfg -and (Confirm-Box "Configurazione esistente trovata (eventualmente modificata dal pannello).`r`nSi = mantenerla aggiornando solo certificato, porta, gMSA e gruppi operatori.`r`nNo = sostituirla con i valori di questa procedura.")) {
        $cfg.hosting.port = [int]$W.Port; $cfg.hosting.certificateThumbprint = $W.CertThumbprint; $cfg.hosting.serviceAccountSid = $W.GmsaSid
        $cfg.admin.adminGroupSid = $W.AdminGroupSid; $cfg.admin.helpdeskGroupSid = $W.HelpdeskGroupSid
        $new = $cfg
    } else { $new = [ordered]@{
        configVersion = 1
        general = [ordered]@{ companyName = $W.Company; portalUrl = $url; logoPath = $null; helpdeskContact = $W.Helpdesk; defaultCountryCode = '39'; culture = 'it-IT' }
        hosting = [ordered]@{ port = [int]$W.Port; certificateThumbprint = $W.CertThumbprint; serviceAccountSid = $W.GmsaSid }
        directory = [ordered]@{ domainController = ''; allowedOus = @($W.UserOus); excludedGroupSids = @($W.ExcludedGroupSids) }
        verification = [ordered]@{ totpEnabled = [bool]$W.Totp; smsEnabled = [bool]$W.Sms; emailEnabled = [bool]$W.Email; minimumEnrolledMethods = [int]$W.MinMethods; resetVerifications = [int]$W.ResetVerifications; unlockVerifications = 1; changeRequiresVerification = $true; codeLifetimeMinutes = 5; codeMaxAttempts = 5; totpWindowSteps = 1; flowSessionMinutes = 10; totpIssuer = $(if ($W.Company) { $W.Company } else { 'FispaSSPR' }) }
        rateLimits = [ordered]@{ perUserPerHour = 5; perIpPerHour = 30; globalPerMinute = 120; codesPerUserPerHour = 6 }
        passwords = [ordered]@{ minLength = 12; bannedWords = @($W.BannedWords); breachedCheck = $W.Breached; offlineListPath = $null; blockWhenBreachCheckUnavailable = $false }
        smtp = [ordered]@{ host = $W.SmtpHost; port = [int]$W.SmtpPort; useStartTls = [bool]$W.SmtpTls; from = $W.SmtpFrom; userName = $(if ($W.SmtpUser) { $W.SmtpUser } else { $null }); passwordEnvelope = $(if ($cfg) { $cfg.smtp.passwordEnvelope } else { $null }) }
        sms = [ordered]@{ provider = $(if ($W.Sms) { $W.SmsProvider } else { 'None' }); endpoint = $W.SmsEndpoint; userName = $(if ($W.SmsUser) { $W.SmsUser } else { $null }); passwordEnvelope = $(if ($cfg) { $cfg.sms.passwordEnvelope } else { $null }); genericBodyTemplate = $null; senderName = '' }
        admin = [ordered]@{ adminGroupSid = $W.AdminGroupSid; helpdeskGroupSid = $W.HelpdeskGroupSid; requireTotpForAdmins = $true; sessionMinutes = 30 }
    } }
    [IO.File]::WriteAllText($cfgFile, ([pscustomobject]$new | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Log 'Configurazione scritta.' 'OK'
    # 4. chiave master e segreti (comando dell'applicazione, segreti solo in variabili d'ambiente del processo)
    $exe = Join-Path $InstallDir 'FispaSSPR.exe'
    if (-not (Test-Path (Join-Path $DataDir 'keys\*.key'))) {
        $env:FISPASSPR_BACKUP_FILE = $W.BackupFile; $env:FISPASSPR_BACKUP_PASSWORD = $Secrets.BackupPassword
        $env:FISPASSPR_SMTP_PASSWORD = $Secrets.SmtpPassword; $env:FISPASSPR_SMS_PASSWORD = $Secrets.SmsPassword
        try { $out = & $exe init --sid $W.GmsaSid 2>&1 } finally { foreach ($v in 'FISPASSPR_BACKUP_FILE', 'FISPASSPR_BACKUP_PASSWORD', 'FISPASSPR_SMTP_PASSWORD', 'FISPASSPR_SMS_PASSWORD') { Remove-Item "env:$v" -ErrorAction SilentlyContinue } }
        if ($LASTEXITCODE -ne 0) { throw "Creazione della chiave master non riuscita: $out" }
        $Secrets.BackupPassword = ''
        Log "Chiave master creata ($out). Backup: $($W.BackupFile)" 'OK'
    } elseif ($Secrets.SmtpPassword -or $Secrets.SmsPassword) {
        Log 'Chiave esistente: le password SMTP/SMS nuove vanno inserite dal pannello (Configurazione).' 'WARN'
    }
    $v = & $exe validate 2>&1
    Log "Verifica configurazione: $(@($v) -join ' | ')"
    # 5. Registro eventi
    if (-not [Diagnostics.EventLog]::SourceExists('FispaSSPR')) { New-EventLog -LogName 'SSPR' -Source 'FispaSSPR'; Limit-EventLog -LogName 'SSPR' -MaximumSize 64MB -OverflowAction OverwriteAsNeeded }
    # 6. servizio come gMSA, diritto "Accedi come servizio", ripristino automatico
    $account = "$($di.NetBios)\$($W.GmsaName)`$"
    Grant-LogonAsService $W.GmsaSid
    if (-not (Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
        New-Service -Name $ServiceName -BinaryPathName "`"$exe`"" -DisplayName 'FispaSSPR - Portale password' -Description 'Self Service Password Reset (fispas/tools)' -StartupType Automatic | Out-Null
    }
    $o = & sc.exe config $ServiceName obj= $account password= '""' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Impostazione dell'account del servizio non riuscita: $o" }
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
    # 7. firewall
    Get-NetFirewallRule -DisplayName 'FispaSSPR HTTPS' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName 'FispaSSPR HTTPS' -Direction Inbound -Protocol TCP -LocalPort $W.Port -Profile Domain, Private -Action Allow | Out-Null
    # 8. avvio e verifica
    Log 'Avvio del servizio...'
    Start-Service $ServiceName
    $ok = $false
    for ($i = 0; $i -lt 30 -and -not $ok; $i++) {
        Start-Sleep -Seconds 2
        try {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $r = Invoke-WebRequest -Uri "https://localhost:$($W.Port)/api/v1/session" -UseBasicParsing -TimeoutSec 5
            $ok = $r.StatusCode -eq 200
        } catch { } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback = $null }
    }
    if (-not $ok) { throw "Il servizio non risponde: controllare il Registro eventi 'SSPR' e il log $LogFile." }
    $W.PortalUrl = $url
    Save-State
    Log "Portale attivo: $url" 'OK'
}

function Grant-LogonAsService([string]$Sid) {
    if (-not ('FispaSspr.Lsa' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
namespace FispaSspr {
public static class Lsa {
  [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes, int AccessMask, out IntPtr PolicyHandle);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr PolicyHandle, byte[] AccountSid, LSA_UNICODE_STRING[] UserRights, int CountOfRights);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr PolicyHandle);
  [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(uint status);
  public static void Grant(byte[] sid, string right) {
    var oa = new LSA_OBJECT_ATTRIBUTES(); IntPtr h;
    uint st = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x00000800 | 0x00000010, out h);
    if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
    try {
      var s = new LSA_UNICODE_STRING(); s.Buffer = Marshal.StringToHGlobalUni(right); s.Length = (ushort)(right.Length * 2); s.MaximumLength = (ushort)(s.Length + 2);
      try { st = LsaAddAccountRights(h, sid, new[] { s }, 1); if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st)); }
      finally { Marshal.FreeHGlobal(s.Buffer); }
    } finally { LsaClose(h); }
  }
}}
'@
    }
    $s = New-Object Security.Principal.SecurityIdentifier($Sid)
    $b = New-Object byte[] $s.BinaryLength; $s.GetBinaryForm($b, 0)
    [FispaSspr.Lsa]::Grant($b, 'SeServiceLogonRight')
    Log 'Diritto "Accedi come servizio" assegnato al gMSA.' 'OK'
}

# 8 - fine ---------------------------------------------------------------------------------
Add-Page 'Fine' {
    New-Page 'Installazione completata' ''
    $url = if ($W.Contains('PortalUrl')) { $W.PortalUrl } else { '' }
    Add-Text "Portale utenti:  $url" 'Black' | Out-Null
    Add-Text "Pannello amministrazione:  $($url)admin/" 'Black' | Out-Null
    Add-Text "Prossimi passi (pochi minuti):`r`n1. Accedere al pannello da un PC del dominio con un account del gruppo $($W.AdminGroup) (dopo un nuovo logon) e configurare l'app di autenticazione dell'operatore.`r`n2. Se si usa un nome DNS dedicato, creare il record CNAME $($W.Alias) -> $env:COMPUTERNAME.`r`n3. Per l'accesso automatico con Windows aggiungere l'indirizzo del portale alla zona Intranet (GPO: Elenco di assegnazione siti alle aree, valore 1).`r`n4. Personalizzare logo, colori, testi, notifiche e funzioni dal pannello (Configurazione).`r`n5. Comunicare l'indirizzo agli utenti o inviare gli inviti dal pannello.`r`n6. Conservare il backup della chiave: $($W.BackupFile)" | Out-Null
    Add-Button 'Apri il portale' { Start-Process $url } 4 | Out-Null
    Add-Button 'Apri il pannello' { Start-Process "$($url)admin/" } 4 | Out-Null
} { $form.Close(); $true }

# ------------------------------------------------------------------ navigazione
$script:Page = 0
function Show-Page([int]$i) {
    $script:Page = $i
    $steps.SelectedIndex = $i
    $btnBack.Enabled = $i -gt 0 -and $i -lt ($Pages.Count - 1)
    $btnNext.Text = if ($i -eq $Pages.Count - 2) { 'Installa' } elseif ($i -eq $Pages.Count - 1) { 'Fine' } else { 'Avanti >' }
    try { & $Pages[$i].Show } catch { Log $_.Exception.Message 'ERROR'; Show-Error $_.Exception.Message }
}
$btnNext.Add_Click({
    $btnNext.Enabled = $false
    try {
        $r = & $Pages[$script:Page].Leave
        if (@($r)[-1] -eq $true) { Save-State; if ($script:Page -lt $Pages.Count - 1) { Show-Page ($script:Page + 1) } }
    } catch { Log $_.Exception.Message 'ERROR'; Show-Error $_.Exception.Message }
    finally { $btnNext.Enabled = $true }
})
$btnBack.Add_Click({ if ($script:Page -gt 0) { Show-Page ($script:Page - 1) } })
$btnClose.Add_Click({ $form.Close() })
$form.Add_FormClosing({ Save-State })
$form.Add_Shown({
    Log "Installer FispaSSPR $Version - log: $LogFile"
    Show-Page 0
})
[void]$form.ShowDialog()
