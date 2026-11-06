# Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# 1. Controllo privilegi di Amministratore
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [System.Windows.Forms.MessageBox]::Show("Questo script deve essere eseguito come Amministratore.", "Errore Privilegi", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
    Exit
}

# 2. Configurazione Log
$logDirectory = "C:\temp"
if (-not (Test-Path -Path $logDirectory)) { New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null }
$global:logFile = Join-Path -Path $logDirectory -ChildPath "FSLogix_Migration_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# 3. Controllo pre-requisito critico (frx.exe)
$fslogixAppPath = "C:\Program Files\fslogix\apps"
if (-not (Test-Path -Path (Join-Path $fslogixAppPath "frx.exe"))) {
    [System.Windows.Forms.MessageBox]::Show("Eseguibile frx.exe non trovato in $fslogixAppPath. FSLogix deve essere installato su questo server.", "Errore FSLogix", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
    Exit
}
$env:PATH = "$env:PATH;$fslogixAppPath"

# 4. Abilitazione Long Paths
$longpathsregistrypath = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
$longpathsregistryname = "LongPathsEnabled"
$longPathsStatus = Get-ItemPropertyValue -Path $longpathsregistrypath -Name $longpathsregistryname -ErrorAction SilentlyContinue
if ($longPathsStatus -ne 1) {
    New-ItemProperty -Path $longpathsregistrypath -Name $longpathsregistryname -Value 1 -PropertyType DWORD -Force | Out-Null
}

# Configurazione Form principale
$form = New-Object System.Windows.Forms.Form
$form.Text = "FSLogix Migration Tool Portable"
$form.Size = New-Object System.Drawing.Size(700, 720)
$form.StartPosition = "CenterScreen"

# Sorgente
$lblSource = New-Object System.Windows.Forms.Label
$lblSource.Location = New-Object System.Drawing.Point(10, 15)
$lblSource.Text = "Cartella Profili Locali:"
$lblSource.AutoSize = $true
$form.Controls.Add($lblSource)

$txtSource = New-Object System.Windows.Forms.TextBox
$txtSource.Location = New-Object System.Drawing.Point(10, 35)
$txtSource.Size = New-Object System.Drawing.Size(500, 20)
$txtSource.Text = "C:\Users"
$form.Controls.Add($txtSource)

$btnSource = New-Object System.Windows.Forms.Button
$btnSource.Location = New-Object System.Drawing.Point(520, 33)
$btnSource.Text = "Sfoglia..."
$btnSource.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dialog.ShowDialog() -eq 'OK') { $txtSource.Text = $dialog.SelectedPath }
})
$form.Controls.Add($btnSource)

# Destinazione
$lblDest = New-Object System.Windows.Forms.Label
$lblDest.Location = New-Object System.Drawing.Point(10, 65)
$lblDest.Text = "Destinazione FSLogix:"
$lblDest.AutoSize = $true
$form.Controls.Add($lblDest)

$txtDest = New-Object System.Windows.Forms.TextBox
$txtDest.Location = New-Object System.Drawing.Point(10, 85)
$txtDest.Size = New-Object System.Drawing.Size(500, 20)
$txtDest.Text = "E:\profili"
$form.Controls.Add($txtDest)

$btnDest = New-Object System.Windows.Forms.Button
$btnDest.Location = New-Object System.Drawing.Point(520, 83)
$btnDest.Text = "Sfoglia..."
$btnDest.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($dialog.ShowDialog() -eq 'OK') { $txtDest.Text = $dialog.SelectedPath }
})
$form.Controls.Add($btnDest)

# Dimensione VHDX
$lblSize = New-Object System.Windows.Forms.Label
$lblSize.Location = New-Object System.Drawing.Point(10, 115)
$lblSize.Text = "Dimensione VHDX (MB):"
$lblSize.AutoSize = $true
$form.Controls.Add($lblSize)

$txtSize = New-Object System.Windows.Forms.TextBox
$txtSize.Location = New-Object System.Drawing.Point(150, 112)
$txtSize.Size = New-Object System.Drawing.Size(100, 20)
$txtSize.Text = "30000"
$form.Controls.Add($txtSize)

# Log Output
$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Location = New-Object System.Drawing.Point(10, 420)
$txtLog.Size = New-Object System.Drawing.Size(660, 180)
$txtLog.ReadOnly = $true
$txtLog.ScrollBars = "Vertical"
$form.Controls.Add($txtLog)

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logLine = "[$timestamp] $Message"
    $txtLog.AppendText("$logLine`r`n")
    $txtLog.ScrollToCaret()
    $form.Refresh()
    Add-Content -Path $global:logFile -Value $logLine
}

# Lista Profili
$btnLoad = New-Object System.Windows.Forms.Button
$btnLoad.Location = New-Object System.Drawing.Point(10, 145)
$btnLoad.Size = New-Object System.Drawing.Size(150, 25)
$btnLoad.Text = "Carica Profili"
$btnLoad.Add_Click({
    $checkedListBox.Items.Clear()
    if (Test-Path $txtSource.Text) {
        $profiles = Get-ChildItem -Path $txtSource.Text -Directory | Where-Object { 
            $_.Name -notmatch "^(Public|Default|Default User|TEMP|All Users|Administrator)$"
        }
        foreach ($p in $profiles) { $checkedListBox.Items.Add($p.Name) | Out-Null }
        Write-Log "Profili caricati da $($txtSource.Text)."
    } else {
        Write-Log "Errore: Percorso sorgente non valido."
    }
})
$form.Controls.Add($btnLoad)

$checkedListBox = New-Object System.Windows.Forms.CheckedListBox
$checkedListBox.Location = New-Object System.Drawing.Point(10, 180)
$checkedListBox.Size = New-Object System.Drawing.Size(660, 190)
$checkedListBox.CheckOnClick = $true
$form.Controls.Add($checkedListBox)

# Counter / Progress Label
$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Location = New-Object System.Drawing.Point(10, 385)
$lblProgress.Size = New-Object System.Drawing.Size(660, 20)
$lblProgress.Text = "In attesa di avvio..."
$lblProgress.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($lblProgress)

# Tasto Migrazione
$btnMigrate = New-Object System.Windows.Forms.Button
$btnMigrate.Location = New-Object System.Drawing.Point(10, 615)
$btnMigrate.Size = New-Object System.Drawing.Size(660, 45)
$btnMigrate.Text = "AVVIA MIGRAZIONE"
$btnMigrate.BackColor = [System.Drawing.Color]::LightGreen
$btnMigrate.Add_Click({
    
    if ($checkedListBox.CheckedItems.Count -eq 0) {
        Write-Log "Nessun profilo selezionato."
        return
    }

    $btnMigrate.Enabled = $false
    $checkedUsers = @($checkedListBox.CheckedItems)
    
    # Hash table sincronizzata per il Runspace
    $syncHash = [hashtable]::Synchronized(@{})
    $syncHash.form = $form
    $syncHash.txtLog = $txtLog
    $syncHash.lblProgress = $lblProgress
    $syncHash.btnMigrate = $btnMigrate
    $syncHash.logFile = $global:logFile
    $syncHash.users = $checkedUsers
    $syncHash.dest = $txtDest.Text
    $syncHash.size = $txtSize.Text
    $syncHash.domain = $env:userdomain

    $runspace = [runspacefactory]::CreateRunspace()
    $runspace.Open()
    $runspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

    $ps = [powershell]::Create()
    $ps.Runspace = $runspace

    $scriptBlock = {
        function Write-LogUI {
            param([string]$Message)
            if ($syncHash.form.IsHandleCreated) {
                $syncHash.form.Invoke([System.Action]{
                    $timestamp = Get-Date -Format "HH:mm:ss"
                    $logLine = "[$timestamp] $Message"
                    $syncHash.txtLog.AppendText("$logLine`r`n")
                    $syncHash.txtLog.ScrollToCaret()
                    Add-Content -Path $syncHash.logFile -Value $logLine
                })
            }
        }

        Write-LogUI "--- Inizio Operazioni. Log salvato in: $($syncHash.logFile) ---"
        
        $dest = $syncHash.dest
        if (-not (Test-Path $dest)) {
            Write-LogUI "Creazione cartella di destinazione $dest..."
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
        }

        $total = $syncHash.users.Count
        $current = 0
        $successCounter = 0
        $failCounter = 0

        foreach ($user in $syncHash.users) {
            $current++
            
            if ($syncHash.form.IsHandleCreated) {
                $syncHash.form.Invoke([System.Action]{
                    $syncHash.lblProgress.Text = "Migrazione in corso: Profilo $current di $total ($user)"
                })
            }

            Write-LogUI "--- Avvio migrazione per: ${user} ---"
            try {
                $sidObj = New-Object System.Security.Principal.NTAccount($user)
                $sid = $sidObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                Write-LogUI "[Pre-Check] SID Risolto: $sid"

                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
                
                if (-not (Test-Path $regPath)) {
                    Write-LogUI "[Pre-Check Fallito] Nessuna voce nel registro per il SID $sid. L'utente non ha mai effettuato un login valido."
                    $failCounter++
                    continue
                }

                $profileImagePath = (Get-ItemProperty -Path $regPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
                if (-not (Test-Path $profileImagePath)) {
                    Write-LogUI "[Pre-Check Fallito] Il registro punta alla cartella '$profileImagePath', ma questa non esiste sul disco."
                    $failCounter++
                    continue
                }
                
                if (Test-Path "$regPath.bak") {
                    Write-LogUI "[Pre-Check Fallito] Rilevata chiave .bak. Il profilo di Windows è in stato corrotto/temporaneo."
                    $failCounter++
                    continue
                }

                $ntuserPath = Join-Path $profileImagePath "ntuser.dat"
                if (Test-Path $ntuserPath) {
                    try {
                        $fileStream = [System.IO.File]::Open($ntuserPath, 'Open', 'Read', 'None')
                        $fileStream.Close()
                    } catch {
                        Write-LogUI "[Pre-Check Fallito] Impossibile accedere a ntuser.dat (File in uso). Disconnettere l'utente."
                        $failCounter++
                        continue
                    }
                }

                $nfolder = Join-Path -Path $dest -ChildPath ("${sid}_${user}")
                $vhdxfile = Join-Path -Path $nfolder -ChildPath ("Profile_${user}.vhdx")

                if (-not (Test-Path $nfolder)) {
                    New-Item -Path $nfolder -ItemType Directory -Force | Out-Null
                    
                    $domain = $syncHash.domain
                    $icaclsOwner = & icacls $nfolder /setowner "$domain\${user}" /T /C 2>&1
                    Write-LogUI "ICACLS SetOwner Output: $icaclsOwner"
                    
                    $icaclsGrant = & icacls $nfolder /grant "$domain\${user}:(OI)(CI)F" /T 2>&1
                    Write-LogUI "ICACLS Grant Output: $icaclsGrant"
                }

                Write-LogUI "Copia profilo in corso (frx.exe)..."
                
                $processInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processInfo.FileName = "frx.exe"
                $processInfo.Arguments = "copy-profile -filename `"$vhdxfile`" -sid $sid -size-mbs $($syncHash.size) -dynamic 1 -verbose"
                $processInfo.RedirectStandardOutput = $true
                $processInfo.RedirectStandardError = $true
                $processInfo.UseShellExecute = $false
                $processInfo.CreateNoWindow = $true

                $process = New-Object System.Diagnostics.Process
                $process.StartInfo = $processInfo
                $process.Start() | Out-Null
                $process.WaitForExit()

                $output = $process.StandardOutput.ReadToEnd()
                $err = $process.StandardError.ReadToEnd()

                if ($process.ExitCode -eq 0) {
                    Write-LogUI "frx.exe Output:`r`n$output"
                    
                    # TEST POST-MIGRAZIONE
                    if (Test-Path $vhdxfile) {
                        $vhdxSize = (Get-Item $vhdxfile).Length
                        if ($vhdxSize -gt 0) {
                            $sizeMB = [math]::Round(($vhdxSize / 1MB), 2)
                            Write-LogUI "SUCCESSO E TEST SUPERATO: Profilo ${user} migrato. VHDX creato ($sizeMB MB)."
                            $successCounter++
                        } else {
                            Write-LogUI "ERRORE TEST: Profilo ${user} migrato, ma VHDX ha dimensione 0 byte."
                            $failCounter++
                        }
                    } else {
                        Write-LogUI "ERRORE TEST: Profilo ${user} processato, ma file VHDX non trovato in destinazione."
                        $failCounter++
                    }

                } else {
                    Write-LogUI "ERRORE frx.exe (Exit Code $($process.ExitCode)):`r`nError Stream: $err`r`nOutput Stream: $output"
                    $failCounter++
                }
            } catch {
                Write-LogUI "ERRORE CRITICO per ${user}: $($_.Exception.Message)"
                $failCounter++
            }
        }
        
        Write-LogUI "--- Operazione conclusa ---"
        
        if ($syncHash.form.IsHandleCreated) {
            $syncHash.form.Invoke([System.Action]{
                $syncHash.lblProgress.Text = "Completato. Totale: $total | Successi: $successCounter | Falliti: $failCounter"
                $syncHash.btnMigrate.Enabled = $true
            })
        }
    }

    $ps.AddScript($scriptBlock) | Out-Null
    $asyncResult = $ps.BeginInvoke()
})
$form.Controls.Add($btnMigrate)

$form.ShowDialog() | Out-Null
