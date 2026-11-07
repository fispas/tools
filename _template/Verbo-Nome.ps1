<#
.SYNOPSIS
    Una riga su cosa fa.

.DESCRIPTION
    Descrizione estesa. Tool generico: nessun valore specifico di ambiente,
    tutto parametrizzato o auto-rilevato.

.PARAMETER OutputPath
    Cartella di output. Default: $env:TEMP\<NomeTool>

.EXAMPLE
    .\Verbo-Nome.ps1

.NOTES
    Versione: 1.0.0
    Repo:     fispas/tools
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath = (Join-Path $env:TEMP 'NomeTool')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$computer  = $env:COMPUTERNAME
$logFile   = Join-Path $OutputPath "NomeTool_${computer}_$timestamp.log"

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $logFile -Value $line
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host $Message -ForegroundColor Red }
        default { Write-Verbose $Message }
    }
}

Write-Log "Avvio su $computer"

# --- logica ---

Write-Log 'Fine'
Write-Host "Output: $OutputPath"
