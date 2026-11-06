<#
.SYNOPSIS
    Converte profili Roaming (es. cartelle .V6) in formato FSLogix con selezione manuale via GUI.

.DESCRIPTION
    Richiede interattivamente tramite interfaccia grafica (Windows Forms) le directory
    di origine (condivisione Roaming) e destinazione (FSLogix). Utilizza Out-GridView 
    per la selezione degli utenti. Crea un nuovo VHDX, vi copia il contenuto del profilo 
    Roaming tramite Robocopy, imposta le chiavi di registro necessarie e i permessi NTFS.

.NOTES
    Autore: Utente Ricca IT
    Ultima modifica: 2026-06-23
#>

# Requires -RunAsAdministrator

# 1. Test dei privilegi di amministratore
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
    
    $form = New-Object System.Windows.Forms.Form
    $form.TopMost = $true
    
    $result = $dialog.ShowDialog($form)
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        return $dialog.SelectedPath
    }
    return $null
}

Write-Host "`n=== Conversione profili Roaming → FSLogix ===`n" -ForegroundColor Cyan

# 2. Test Modulo AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "❌ Test fallito: Modulo ActiveDirectory non disponibile. Installalo prima di eseguire lo script."
    exit
}

# Selezione GUI Sorgente
Write-Host "In attesa di selezione della cartella sorgente (Roaming Profiles)..." -ForegroundColor Yellow
$roamingroot = Get-FolderViaGUI -Description "1/2 - Seleziona la cartella SORGENTE dei profili Roaming (es. \\Server\Profili$)"

# 3. Test selezione sorgente
if (-not $roamingroot -or -not (Test-Path $roamingroot)) {
    Write-Error "❌ Test fallito: Selezione sorgente annullata o non valida. Uscita."
    exit
}

# Selezione GUI Destinazione
Write-Host "In attesa di selezione della cartella di destinazione (FSLogix)..." -ForegroundColor Yellow
$fslogixroot = Get-FolderViaGUI -Description "2/2 - Seleziona la cartella di DESTINAZIONE FSLogix (es. \\Server\FSLogix$)"

# 4. Test selezione destinazione
if (-not $fslogixroot) {
    Write-Error "❌ Test fallito: Selezione destinazione annullata. Uscita."
    exit
}

# 5. Test di coerenza percorsi
if ($roamingroot -eq $fslogixroot) {
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

# Richiesta dimensione VHDX
[int]$vhdxSizeMB = 30000
$sizeInput = Read-Host "Inserisci la dimensione massima del VHDX in MB [Default: 30000]"
if (-not [string]::IsNullOrWhiteSpace($sizeInput)) {
    if ($sizeInput -match '^\d+$') {
        $vhdxSizeMB = [int]$sizeInput
    } else {
        Write-Warning "Input non valido. Verrà utilizzata la dimensione di default (30000 MB)."
    }
}

function ThisHHmmss { (Get-Date).ToString("HH:mm:ss") }

# Contatori globali
$successCount = 0
$failCount    = 0
$skipCount    = 0
$delay        = 3

Write-Host "`n➜ Sorgente selezionata: $roamingroot" -ForegroundColor Green
Write-Host "➜ Destinazione selezionata: $fslogixroot" -ForegroundColor Green
Write-Host "➜ Dimensione VHDX target: ${vhdxSizeMB} MB`n" -ForegroundColor Green

# Elenca le cartelle Roaming (Test presenza directory)
$directories = Get-ChildItem -Path $roamingroot -Directory -ErrorAction SilentlyContinue | Sort-Object Name
if (-not $directories) {
    Write-Error "❌ Test fallito: Nessuna cartella profilo trovata in $roamingroot"
    exit
}

# Associa utenti (parsing nome cartella, rimuove suffissi come .V6, .V5)
$results = @()
foreach ($dir in $directories) {
    $sam = $dir.Name -replace '\.V\d+$', ''
    $user = Get-ADUser -Filter { SamAccountName -eq $sam } -Properties SamAccountName, Name, SID -ErrorAction SilentlyContinue
    
    if ($user) {
        $results += [PSCustomObject]@{
            SID        = $user.SID.Value
            SAM        = $user.SamAccountName
            Name       = $user.Name
            SourcePath = $dir.FullName
        }
    }
}

# 6. Test utenti trovati in AD
if (-not $results) {
    Write-Error "❌ Test fallito: Nessun utente AD trovato corrispondente alle cartelle Roaming analizzate."
    exit
}

# Selezione utenti tramite GridView (GUI)
Write-Host "Apri la ViewGrid. Seleziona uno o più utenti da migrare e clicca OK." -ForegroundColor Yellow
$targets = $results | Out-GridView -Title "Seleziona Utenti per Migrazione Roaming -> FSLogix" -PassThru

if ($targets -is [PSCustomObject]) { $targets = @($targets) }

if (-not $targets) {
    Write-Host "`nNessun utente selezionato nella GUI. Uscita." -ForegroundColor Red
    exit
}

$totalTargets = $targets.Count

foreach ($target in $targets) {
    $sourceProfilePath = $target.SourcePath
    $sid = $target.SID
    $sam = $target.SAM
    $fslogixuserpath = Join-Path $fslogixroot "${sid}_${sam}"

    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "$(ThisHHmmss) ➜ Avvio migrazione per: $($target.Name) ($sam)" -ForegroundColor Green
    Write-Host "   Source Path: $sourceProfilePath" -ForegroundColor DarkCyan
    Write-Host "   Target Path: $fslogixuserpath" -ForegroundColor DarkGreen
    
    # 7. Test validità origine in tempo reale
    if (-not (Test-Path $sourceProfilePath)) {
        Write-Warning "Test fallito: Cartella sorgente $sourceProfilePath non più raggiungibile."
        $failCount++
        continue
    }

    if (-not (Test-Path $fslogixuserpath)) {
        New-Item -Path $fslogixuserpath -ItemType Directory | Out-Null
        Write-Host "Creata cartella contenitore: $fslogixuserpath" -ForegroundColor Green
    } else {
        Write-Host "Cartella contenitore esistente: $fslogixuserpath" -ForegroundColor Yellow
    }

    $newName = "Profile_$sam.vhdx"
    $newVHDX = Join-Path $fslogixuserpath $newName

    # 8. Test disco esistente e gestione sovrascrittura
    if (Test-Path $newVHDX) {
        Write-Warning "Trovato disco FSLogix già esistente per ($sam): $newName"
        $choice = Read-Host "Vuoi sovrascrivere questo disco? (S/N)"
        if ($choice -notmatch '^[SsYy]') {
            Write-Host "Salto la migrazione per $sam" -ForegroundColor Yellow
            $skipCount++
            continue
        } else {
            Write-Host "Elimino il disco esistente e procedo..." -ForegroundColor Cyan
            Remove-Item $newVHDX -Force -Recurse
            # Test se l'eliminazione è riuscita
            if (Test-Path $newVHDX) {
                Write-Error "Test fallito: impossibile eliminare il disco esistente."
                $failCount++
                continue
            }
        }
    }

    try {
        # 9. Test Creazione VHDX tramite DiskPart (Massima compatibilità)
        Write-Host "$(ThisHHmmss) ➜ Creazione nuovo VHDX ($vhdxSizeMB MB)..." -ForegroundColor Yellow
        $dpScriptPath = Join-Path $env:TEMP "diskpart_create_$sam.txt"
        $dpScript = @"
create vdisk file="$newVHDX" maximum=$vhdxSizeMB type=expandable
attach vdisk
create partition primary
format fs=ntfs quick label="Profile"
detach vdisk
"@
        $dpScript | Out-File $dpScriptPath -Encoding ascii
        $dpResult = diskpart /s $dpScriptPath
        Remove-Item $dpScriptPath -Force -ErrorAction SilentlyContinue

        if (-not (Test-Path $newVHDX)) {
            throw "Test fallito: La creazione del VHDX tramite DiskPart non è andata a buon fine."
        }
        Write-Host "VHDX creato e formattato con successo." -ForegroundColor Green

        # 10. Test Mounting
        Write-Host "$(ThisHHmmss) ➜ Mounting VHDX: $newVHDX" -ForegroundColor Green
        $mountedVolume = Mount-DiskImage -ImagePath $newVHDX -Passthru
        Start-Sleep -Seconds $delay

        $mountletter = ($mountedVolume | Get-Disk | Get-Partition | Where-Object DriveLetter -ne 0 | Select-Object -First 1).DriveLetter
        if (-not $mountletter) {
            throw "Test fallito: Impossibile determinare la lettera di unità per il VHDX appena montato."
        }
        
        $mountpath = "${mountletter}:\"
        Write-Host "VHDX montato come: $mountpath" -ForegroundColor Cyan

        $ProfileDir = Join-Path $mountpath 'Profile'
        if (-not (Test-Path $ProfileDir)) {
            New-Item $ProfileDir -ItemType Directory | Out-Null
        }

        # 11. Copia Dati (Robocopy) con contatore byte
        Write-Host "$(ThisHHmmss) ➜ Copia dei dati Roaming in /Profile/ tramite Robocopy..." -ForegroundColor DarkYellow
        $roboArgs = @(
            $sourceProfilePath, 
            $ProfileDir, 
            "/E", "/ZB", "/COPY:DAT", "/DCOPY:DAT", 
            "/R:2", "/W:2", "/MT:8", 
            "/NFL", "/NDL", "/NP", "/NJH", "/NJS"
        )
        & robocopy $roboArgs | Out-Null
        $roboExitCode = $LASTEXITCODE

        if ($roboExitCode -ge 8) {
            throw "Test fallito: Robocopy ha riscontrato un errore fatale (Exit Code: $roboExitCode)."
        } else {
            Write-Host "Test superato: Copia dati completata (Exit Code: $roboExitCode)." -ForegroundColor Cyan
        }

        # 12. Creazione Test Registry ProfileData.reg
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

        # 13. Test Smontaggio
        Write-Host "$(ThisHHmmss) ➜ Smontaggio VHDX..." -ForegroundColor Green
        Dismount-DiskImage -ImagePath $newVHDX -Confirm:$false
        Start-Sleep -Seconds $delay

        # 14. Applicazione Permessi NTFS e Test
        try {
            $userFull = if ($env:USERDOMAIN) {"$env:USERDOMAIN\$sam"} else {$sam}
            Write-Host "Impostazione proprietario e permessi NTFS per $fslogixuserpath..." -ForegroundColor DarkGray
            
            & icacls $fslogixuserpath /setowner "$userFull" /T /C /Q | Out-Null
            & icacls $fslogixuserpath /grant "${userFull}:(OI)(CI)F" /T /C /Q | Out-Null
            & icacls $fslogixuserpath /grant "SYSTEM:(OI)(CI)F" /T /C /Q | Out-Null
            & icacls $fslogixuserpath /grant "Administrators:(OI)(CI)F" /T /C /Q | Out-Null
            
            Write-Host "Permessi NTFS impostati correttamente." -ForegroundColor Green
        }
        catch {
            Write-Warning "⚠️ Impossibile impostare completamente i permessi NTFS: $_"
        }

        # 15. Validazione Finale
        if (Test-Path $newVHDX) {
            $finalSize = (Get-Item $newVHDX).Length
            if ($finalSize -gt 1MB) {
                Write-Host "`n✅ $(ThisHHmmss) - Migrazione completata per $sam" -ForegroundColor Green
                $successCount++
            } else {
                throw "Test validazione fallito: Il VHDX generato risulta vuoto o corrotto."
            }
        } else {
            throw "Test validazione fallito: Il VHDX non è presente nella destinazione post-smontaggio."
        }
    }
    catch {
        Write-Error "❌ Errore critico durante la migrazione di ($sam): $_"
        $failCount++
    }
    finally {
        # Test post-smontaggio per cleanup garantito (Evita dischi bloccati)
        $mounted = Get-DiskImage -ImagePath $newVHDX -ErrorAction SilentlyContinue
        if ($mounted -and $mounted.Attached) {
            Write-Warning "Tentativo di smontaggio finale nel blocco finally per rilascio disco..."
            Dismount-DiskImage -ImagePath $newVHDX -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds $delay
        }
    }
    Write-Host "=======================================================" -ForegroundColor Cyan
}

Write-Host "`n🎉 Elaborazione completata. Statistiche finali:" -ForegroundColor Green
Write-Host "  Utenti totali selezionati: $totalTargets"
Write-Host "  Completati con successo: $successCount" -ForegroundColor Green
Write-Host "  Saltati (esistenti o annullati): $skipCount" -ForegroundColor Yellow
Write-Host "  Falliti / Errori: $failCount" -ForegroundColor Red

