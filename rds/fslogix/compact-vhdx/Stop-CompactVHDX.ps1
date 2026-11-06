<#
.SYNOPSIS
    Ferma in modo pulito la compattazione VHDX in corso (alternativa a riga di comando
    del pulsante "Stop pulito" di CompactVHDX Manager).

.DESCRIPTION
    Da lanciare sul server profili in PowerShell elevata, in qualsiasi momento.
      1. se la compattazione e' in corso crea il file di stop: il disco in lavorazione
         viene completato (pochi secondi), poi il job genera i report ed esce
      2. attende la chiusura (max -TimeoutSec)
      3. verifica che nessun VHDX dei profili sia rimasto agganciato e lo sgancia
    Con -Force, allo scadere del timeout termina il job e sgancia i dischi rimasti.
#>
[CmdletBinding()]
param(
    [int]$TimeoutSec = 300,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'CompactVHDX-Common.ps1')
if (-not (Test-CVAdmin)) { throw 'Esegui Stop-CompactVHDX.ps1 da PowerShell come amministratore' }
$cfg = Get-CVConfig

Write-Host "`n== Stop compattazione VHDX" -ForegroundColor Cyan
if (-not (Test-CVJobRunning)) {
    Write-Host '   Nessuna compattazione in esecuzione' -ForegroundColor Green
} else {
    Request-CVStop
    Write-Host '   Stop richiesto: attendo il completamento del disco in corso...'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ((Test-CVJobRunning) -and $sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        Write-Host ("`r   {0:N0}s" -f $sw.Elapsed.TotalSeconds) -NoNewline
        Start-Sleep -Seconds 2
    }
    Write-Host ''
    if (Test-CVJobRunning) {
        if ($Force) {
            Write-Host "   Timeout di $TimeoutSec s: stop forzato" -ForegroundColor Yellow
            Stop-CVForce (Get-CVProfilePaths $cfg) | ForEach-Object { Write-Host "   $_" -ForegroundColor Yellow }
        } else {
            Write-Host "   Ancora attivo dopo $TimeoutSec s: si fermerà a fine disco. Rilancia per verificare, o usa -Force." -ForegroundColor Yellow
            return
        }
    } else {
        Write-Host ("   Fermato in modo pulito in {0:N0}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
    }
}

$msgs = @(Dismount-CVLeftovers (Get-CVProfilePaths $cfg))
if ($msgs.Count) { $msgs | ForEach-Object { Write-Host "   $_" -ForegroundColor Yellow } }
else { Write-Host '   Nessun VHDX dei profili agganciato al server' -ForegroundColor Green }
if (Test-Path -LiteralPath $script:CVStopFile) { Remove-Item -LiteralPath $script:CVStopFile -Force }
