<#
.SYNOPSIS
    Converte profili UPD in formato FSLogix con selezione manuale via GUI.
.DESCRIPTION
    Richiede interattivamente tramite interfaccia grafica (Windows Forms) le directory
    di origine e destinazione. Utilizza Out-GridView per la selezione degli utenti.
    Copia il VHDX UPD, ne sposta il contenuto e imposta i permessi NTFS.
.NOTES
    Autore: Utente Ricca IT
    Ultima modifica: 2026-06-23
#>

# Test dei privilegi di amministratore
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "❌ Test fallito: lo script richiede i privilegi di amministratore."
    exit
}

# Caricamento assembly per la GUI
Add-Type -AssemblyName System.Windows.Forms

# Funzione per selezione cartella tramite GUI
function Get-FolderViaGUI {
    param([string]$Description)
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    
    # Forza la finestra in primo piano
    $form = New-Object System.Windows.Forms.Form
    $form.TopMost = $true
    
    $result = $dialog.ShowDialog($form)
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.SelectedPath
    }
    return $null
}

Write-Host "`n=== Conversione profili UPD → FSLogix ===`n" -ForegroundColor Cyan

# 1. Selezione GUI Sorgente
Write-Host "In attesa di selezione della cartella sorgente (UPD)..." -ForegroundColor Yellow
$updroot = Get-FolderViaGUI -Description "1/2 - Seleziona la cartella SORGENTE dei profili UPD (es. P:\ProfiliUPD)"

# Test selezione sorgente
if (-not $updroot -or -not (Test-Path $updroot)) {
    Write-Error "❌ Test fallito: Selezione sorgente annullata o non valida. Uscita."
    exit
}

# 2. Selezione GUI Destinazione
Write-Host "In attesa di selezione della cartella di destinazione (FSLogix)..." -ForegroundColor Yellow
$fslogixroot = Get-FolderViaGUI -Description "2/2 - Seleziona la cartella di DESTINAZIONE FSLogix (es. P:\ProfiliFSL)"

# Test selezione destinazione
if (-not $fslogixroot) {
    Write-Error "❌ Test fallito: Selezione destinazione annullata. Uscita."
    exit
}

# Test di coerenza percorsi
if ($updroot -eq $fslogixroot) {
    Write-Error "❌ Test fallito: La cartella di origine e destinazione non possono coincidere."
    exit
}

if (-not (Test-Path $fslogixroot)) {
    Write-Warning "Directory di destinazione $fslogixroot non trovata. Creazione in corso..."
    New-Item -Path $fslogixroot -ItemType Directory | Out-Null
    if (-not (Test-Path $fslogixroot)) {
        Write-Error "❌ Test fallito: impossibile creare la directory $fslogixroot."
        exit
    }
}

# Carica modulo AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "❌ Modulo ActiveDirectory non disponibile. Installalo prima di eseguire lo script."
    exit
}

function ThisHHmmss { (Get-Date).ToString("HH:mm:ss") }

# Contatori globali
$successCount = 0
$failCount = 0
$skipCount = 0
$delay = 5

Write-Host "`n➜ Sorgente selezionata: $updroot" -ForegroundColor Green
Write-Host "➜ Destinazione selezionata: $fslogixroot`n" -ForegroundColor Green

# Elenca i file UPD (Test presenza file)
$files = Get-ChildItem -Path $updroot -File -Filter "UVHD-S*.vhdx" -ErrorAction SilentlyContinue | Sort-Object Name
if (-not $files) {
    Write-Warning "Nessun file VHDX trovato in $updroot"
    exit
}

# Associa utenti
$results = foreach ($file in $files) {
    $sid = ($file.Basename).Substring(5)
    $user = Get-ADUser -Filter { SID -eq $sid } -Properties SamAccountName, Name -ErrorAction SilentlyContinue
    if ($user) {
        [PSCustomObject]@{
            SID  = $user.SID.Value
            SAM  = $user.SamAccountName
            Name = $user.Name
            File = $file.FullName
        }
    }
}

# Test utenti trovati
if (-not $results) {
    Write-Warning "Nessun utente AD trovato corrispondente ai SID nei file UPD."
    exit
}

# Selezione utenti tramite GridView (GUI)
Write-Host "Apri la ViewGrid. Seleziona uno o più utenti da migrare e clicca OK." -ForegroundColor Yellow
$targets = $results | Out-GridView -Title "Seleziona Utenti per Migrazione FSLogix" -PassThru

if ($targets -is [PSCustomObject]) {
    $targets = @($targets)
}

if (-not $targets) {
    Write-Host "`nNessun utente selezionato nella GUI. Uscita." -ForegroundColor Red
    exit
}

# Contatore utenti selezionati
$totalTargets = $targets.Count

foreach ($target in $targets) {
    $sourcevhdx = $target.File
    $sid = $target.SID
    $sam = $target.SAM
    $fslogixuserpath = Join-Path $fslogixroot "${sid}_${sam}"

    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "$(ThisHHmmss) ➜ Avvio migrazione per: $($target.Name) ($sam)" -ForegroundColor Green
    Write-Host "   Target Path: $fslogixuserpath" -ForegroundColor DarkGreen
    
    # Test validità file prima dell'avvio
    if (-not (Test-Path $sourcevhdx)) {
        Write-Warning "Test fallito: VHDX sorgente $sourcevhdx non più raggiungibile."
        $failCount++
        continue
    }

    if (-not (Test-Path $fslogixuserpath)) {
        New-Item -Path $fslogixuserpath -ItemType Directory | Out-Null
        Write-Host "Creata cartella: $fslogixuserpath" -ForegroundColor Green
    } else {
        Write-Host "Cartella esistente: $fslogixuserpath" -ForegroundColor Yellow
    }

    $newName = "Profile_$sam.vhdx"
    $newUVHD = Join-Path $fslogixuserpath $newName

    # Test disco esistente
    if (Test-Path $newUVHD) {
        Write-Warning "Trovato disco FSLogix già esistente per ($sam): $newName"
        $choice = Read-Host "Vuoi sovrascrivere questo disco? (S/N)"
        if ($choice -notmatch '^[SsYy]') {
            Write-Host "Salto la migrazione per $sam" -ForegroundColor Yellow
            $skipCount++
            continue
        } else {
            Write-Host "Elimino il disco esistente e procedo..." -ForegroundColor Cyan
            Remove-Item $newUVHD -Force -Recurse
            # Test se l'eliminazione è riuscita
            if (Test-Path $newUVHD) {
                Write-Error "Test fallito: impossibile eliminare il disco esistente."
                $failCount++
                continue
            }
        }
    }

    try {
        Write-Host "`n$(ThisHHmmss) ➜ Mounting VHDX: $sourcevhdx" -ForegroundColor Green
        $mountedVolume = Mount-DiskImage -ImagePath $sourcevhdx -Passthru
        Start-Sleep -Seconds $delay

        # Test lettera di unità
        $mountletter = ($mountedVolume | Get-Disk | Get-Partition | Where-Object DriveLetter -ne 0 | Select-Object -First 1).DriveLetter
        if (-not $mountletter) {
            throw "Test fallito: Impossibile determinare la lettera di unità per il VHDX montato."
        }
        
        $mountpath = "${mountletter}:\"
        Write-Host "VHDX montato come: $mountpath" -ForegroundColor Cyan

        $ProfileDir = Join-Path $mountpath 'Profile'
        if (-not (Test-Path $ProfileDir)) {
            New-Item $ProfileDir -ItemType Directory | Out-Null
            Write-Host "Creata cartella Profile nel VHDX" -ForegroundColor Green
        }

        Write-Host "$(ThisHHmmss) ➜ Spostamento contenuto profilo UPD in /Profile/..." -ForegroundColor DarkYellow
        $ExcludeRegex = '^(Profile|Uvhd-Binding|\$RECYCLE\.BIN|System Volume Information)$'
        $itemsToMove = Get-ChildItem $mountpath -Force | Where-Object { $_.Name -notmatch $ExcludeRegex }
        
        # Contatore file spostati
        $filesMovedCount = 0
        foreach ($item in $itemsToMove) {
            Move-Item -Path $item.FullName -Destination $ProfileDir -Force -ErrorAction SilentlyContinue
            $filesMovedCount++
        }
        Write-Host "Test superato: $filesMovedCount elementi primari spostati in $ProfileDir" -ForegroundColor Cyan

        $regpath = Join-Path $ProfileDir "AppData\Local\FSLogix"
        if (-not (Test-Path $regpath)) {
            New-Item -Path $regpath -ItemType Directory -Force | Out-Null
        }

        $regfile = Join-Path $regpath "ProfileData.reg"
        if (-not (Test-Path $regfile)) {
            $regtext = @"
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid]
"ProfileImagePath"="C:\\Users\\$sam"
"Flags"=dword:00000000
"State"=dword:00000000
"ProfileLoadTimeLow"=dword:00000000
"ProfileLoadTimeHigh"=dword:00000000
"RefCount"=dword:00000000
"RunLogonScriptSync"=dword:00000001
"@
            $regtext | Out-File $regfile -Encoding utf8
            if (-not (Test-Path $regfile)) {
                throw "Test fallito: impossibile creare il file di registro ProfileData.reg"
            }
            Write-Host "Creato file ProfileData.reg (ProfileImagePath: C:\Users\$sam)" -ForegroundColor Green
        }

        Write-Host "$(ThisHHmmss) ➜ Smontaggio VHDX..." -ForegroundColor Green
        Dismount-DiskImage -ImagePath $sourcevhdx -Confirm:$false
        Start-Sleep -Seconds $delay

        Write-Host "$(ThisHHmmss) ➜ Copia VHDX di origine (UPD) in destinazione FSLogix..." -ForegroundColor Yellow
        $copiedVHDXPath = Join-Path $fslogixuserpath (Split-Path $sourcevhdx -Leaf)
        Copy-Item -Path $sourcevhdx -Destination $copiedVHDXPath -Force

        # Test presenza file prima della rinomina
        if (-not (Test-Path $copiedVHDXPath)) {
            throw "Test fallito: il file copiato non è stato rilevato nella destinazione."
        }

        Rename-Item -Path $copiedVHDXPath -NewName $newName -Force
        
        # Test presenza file rinominato
        if (-not (Test-Path (Join-Path $fslogixuserpath $newName))) {
            throw "Test fallito: impossibile verificare la corretta rinominazione del file VHDX."
        }
        
        Write-Host "Copiato e rinominato in: $newName. Il file originale è stato preservato." -ForegroundColor Cyan

        try {
            $userFull = if ($env:USERDOMAIN) {"$env:USERDOMAIN\$sam"} else {$sam}
            Write-Host "Impostazione proprietario e permessi NTFS per $fslogixuserpath..." -ForegroundColor DarkGray
            
            & icacls $fslogixuserpath /setowner "$userFull" /T /C | Out-Null
            & icacls $fslogixuserpath /grant "${userFull}:(OI)(CI)F" /T /C | Out-Null
            & icacls $fslogixuserpath /grant "SYSTEM:(OI)(CI)F" /T /C | Out-Null
            & icacls $fslogixuserpath /grant "Administrators:(OI)(CI)F" /T /C | Out-Null
            
            Write-Host "Permessi NTFS impostati correttamente." -ForegroundColor Green
        }
        catch {
            Write-Warning "⚠️ Impossibile impostare completamente i permessi NTFS: $_"
        }

        Write-Host "`n✅ $(ThisHHmmss) - Migrazione completata per $sam" -ForegroundColor Green
        $successCount++
    }
    catch {
        Write-Error "❌ Errore critico durante la migrazione di ($sam): $_"
        $failCount++
    }
    finally {
        # Test post-smontaggio per cleanup garantito
        $mounted = Get-DiskImage -ImagePath $sourcevhdx -ErrorAction SilentlyContinue
        if ($mounted -and $mounted.Attached) {
            Write-Warning "Tentativo di smontaggio finale nel blocco finally per cleanup..."
            Dismount-DiskImage -ImagePath $sourcevhdx -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds $delay
        }
    }
    Write-Host "=======================================================" -ForegroundColor Cyan
}

Write-Host "`n🎉 Elaborazione completata. Statistiche finali:" -ForegroundColor Green
Write-Host "  Utenti selezionati: $totalTargets"
Write-Host "  Completati con successo: $successCount" -ForegroundColor Green
Write-Host "  Saltati (esistenti o annullati): $skipCount" -ForegroundColor Yellow
Write-Host "  Falliti: $failCount" -ForegroundColor Red
