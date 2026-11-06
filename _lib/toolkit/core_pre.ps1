
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
