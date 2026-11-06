<#
.SYNOPSIS
    Crea i pacchetti di installazione di CompactVHDX:
      - CompactVHDX-Setup.ps1   installatore PowerShell autonomo (sempre)
      - CompactVHDX-Manager.exe installatore/avvio compilato con csc.exe (salvo -SetupOnly)
    ed eventualmente li firma con un certificato di firma del codice.

.DESCRIPTION
    Da lanciare nella cartella che contiene:
      CompactVHDX-Common.ps1, Compact-ProfileDisks.ps1, Stop-CompactVHDX.ps1,
      CompactVHDX-Manager.ps1, Build-CompactVHDXExe.ps1

    Entrambi i pacchetti contengono gli script e, al primo avvio su un server:
      - chiedono la cartella di installazione (predefinita C:\Scripts\CompactVHDX)
        e la memorizzano in HKLM\SOFTWARE\CompactVHDX
      - copiano/aggiornano gli script (configurazione, log, storico e report non vengono toccati)
      - aprono CompactVHDX Manager, che al primo avvio parte con la configurazione guidata
    Il Setup.ps1 crea anche i collegamenti "CompactVHDX Manager" sul desktop pubblico e nel
    menu Start: utile dove un antivirus blocca gli eseguibili non noti.

    L'exe richiede csc.exe del .NET Framework 4.x (presente in Windows). Nessun download.

    Firma: certificato con utilizzo "Firma del codice" valido in CurrentUser\My o
    LocalMachine\My, oppure -CertThumbprint. Con -SignScripts firma anche gli script
    incorporati (necessario se una GPO impone l'Execution Policy AllSigned).

.EXAMPLE
    .\Build-CompactVHDXExe.ps1
    .\Build-CompactVHDXExe.ps1 -SetupOnly -NoSign
    .\Build-CompactVHDXExe.ps1 -SignScripts -TimestampServer http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [string]$CertThumbprint,
    [string]$TimestampServer,
    [switch]$SignScripts,
    [switch]$NoSign,
    [switch]$SetupOnly,
    [switch]$ToDesktop
)

$ErrorActionPreference = 'Stop'
$src = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $OutputDir) { $OutputDir = $src }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
function Ok([string]$m) { Write-Host "   $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "   $m" -ForegroundColor Yellow }

$scripts = 'CompactVHDX-Common.ps1', 'Compact-ProfileDisks.ps1', 'Stop-CompactVHDX.ps1', 'CompactVHDX-Manager.ps1'

# ------------------------------------------------------------------ verifiche
Write-Host "`n== Verifiche" -ForegroundColor Cyan
foreach ($s in $scripts) {
    $p = Join-Path $src $s
    if (-not (Test-Path -LiteralPath $p)) { throw "File mancante: $p" }
    $tok = $null; $err = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tok, [ref]$err)
    if ($err.Count) { throw "Errore di sintassi in ${s}: $($err[0].Message) (riga $($err[0].Extent.StartLineNumber))" }
    Ok $s
}
$version = '1.0.0'
$m = Select-String -LiteralPath (Join-Path $src 'CompactVHDX-Common.ps1') -Pattern "CVVersion\s*=\s*'([\d\.]+)'" | Select-Object -First 1
if ($m) { $version = $m.Matches[0].Groups[1].Value }
Ok "Versione $version"

$csc = $null
if (-not $SetupOnly) {
    $csc = @("$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe", "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe") |
           Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $csc) { throw 'csc.exe del .NET Framework 4.x non trovato: usa -SetupOnly per creare solo CompactVHDX-Setup.ps1' }
    Ok "Compilatore: $csc"
}

# ------------------------------------------------------------------ certificato
$cert = $null
if (-not $NoSign) {
    if ($CertThumbprint) {
        $t = $CertThumbprint -replace '\s', ''
        $cert = @(Get-Item "Cert:\CurrentUser\My\$t", "Cert:\LocalMachine\My\$t" -ErrorAction SilentlyContinue) | Select-Object -First 1
        if (-not $cert) { throw "Certificato $t non trovato in CurrentUser\My o LocalMachine\My" }
    } else {
        $cert = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue) +
                @(Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue) |
                Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
                Sort-Object NotAfter -Descending | Select-Object -First 1
    }
    if ($cert) { Ok "Certificato: $($cert.Subject) (scade $($cert.NotAfter.ToString('dd/MM/yyyy')), $($cert.Thumbprint))" }
    else { Warn 'Nessun certificato di firma del codice valido: i pacchetti resteranno NON firmati' }
}

function Set-CVSignature([string]$File) {
    $p = @{ FilePath = $File; Certificate = $cert; HashAlgorithm = 'SHA256' }
    if ($TimestampServer) { $p.TimestampServer = $TimestampServer }
    $r = Set-AuthenticodeSignature @p
    if ($r.Status -ne 'Valid') { throw "Firma di $(Split-Path $File -Leaf) non valida: $($r.Status) - $($r.StatusMessage)" }
}

$build = Join-Path ([IO.Path]::GetTempPath()) ("CompactVHDX_build_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null
try {
    # ------------------------------------------------------------ script (eventualmente firmati)
    Write-Host "`n== Preparazione script" -ForegroundColor Cyan
    foreach ($s in $scripts) {
        Copy-Item -LiteralPath (Join-Path $src $s) -Destination (Join-Path $build $s)
        if ($SignScripts -and $cert) { Set-CVSignature (Join-Path $build $s); Ok "Firmato $s" }
    }
    if ($SignScripts -and -not $cert) { Warn '-SignScripts ignorato: nessun certificato' }

    # ------------------------------------------------------------ CompactVHDX-Setup.ps1
    Write-Host "`n== CompactVHDX-Setup.ps1" -ForegroundColor Cyan
    $payload = ($scripts | ForEach-Object {
        "    '$_' = '" + [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $build $_))) + "'"
    }) -join "`r`n"

    $setupTemplate = @'
<#
.SYNOPSIS
    Installatore di CompactVHDX __VERSION__ (compattazione offline dei VHDX FSLogix).

.DESCRIPTION
    Da eseguire sul server che ospita i profili FSLogix, come amministratore:
        powershell -ExecutionPolicy Bypass -File .\CompactVHDX-Setup.ps1

    - chiede la cartella di installazione (predefinita C:\Scripts\CompactVHDX, oppure quella
      gia' registrata in HKLM\SOFTWARE\CompactVHDX)
    - copia o aggiorna gli script: configurazione, log, storico e report non vengono toccati
    - crea i collegamenti "CompactVHDX Manager" sul desktop pubblico e nel menu Start
    - apre CompactVHDX Manager: al primo avvio parte la configurazione guidata

.PARAMETER InstallDir
    Cartella di installazione, senza richiesta interattiva.
.PARAMETER Silent
    Nessuna finestra: usa -InstallDir, la cartella registrata o quella predefinita.
.PARAMETER NoLaunch
    Non apre CompactVHDX Manager a fine installazione.
.PARAMETER NoShortcuts
    Non crea i collegamenti.
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$Silent,
    [switch]$NoLaunch,
    [switch]$NoShortcuts
)

$ErrorActionPreference = 'Stop'
$Version = '__VERSION__'
$RegKey = 'HKLM:\SOFTWARE\CompactVHDX'
$DefaultDir = 'C:\Scripts\CompactVHDX'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($InstallDir) { $a += " -InstallDir `"$InstallDir`"" }
    if ($Silent) { $a += ' -Silent' }
    if ($NoLaunch) { $a += ' -NoLaunch' }
    if ($NoShortcuts) { $a += ' -NoShortcuts' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    return
}

$Payload = @{
__PAYLOAD__
}

$current = $null
try { $current = (Get-ItemProperty -Path $RegKey -ErrorAction Stop).InstallDir } catch { }
if (-not $InstallDir) { $InstallDir = if ($current) { $current } else { $DefaultDir } }

if (-not $Silent) {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Installazione CompactVHDX $Version"
    $f.Size = New-Object System.Drawing.Size(560, 230)
    $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $l = New-Object System.Windows.Forms.Label
    $l.Location = New-Object System.Drawing.Point(16, 14); $l.Size = New-Object System.Drawing.Size(520, 60)
    $l.Text = "Cartella di installazione di CompactVHDX su $env:COMPUTERNAME.`nVa installato sul server che ospita i profili FSLogix. Un'installazione esistente viene aggiornata senza toccare configurazione, log e storico."
    $f.Controls.Add($l)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point(16, 82); $t.Size = New-Object System.Drawing.Size(420, 24); $t.Text = $InstallDir
    $f.Controls.Add($t)
    $b = New-Object System.Windows.Forms.Button
    $b.Location = New-Object System.Drawing.Point(444, 81); $b.Size = New-Object System.Drawing.Size(84, 26); $b.Text = 'Sfoglia'
    $b.Add_Click({ $d = New-Object System.Windows.Forms.FolderBrowserDialog; $d.SelectedPath = $t.Text; if ($d.ShowDialog() -eq 'OK') { $t.Text = $d.SelectedPath } })
    $f.Controls.Add($b)
    $ok = New-Object System.Windows.Forms.Button
    $ok.Location = New-Object System.Drawing.Point(318, 140); $ok.Size = New-Object System.Drawing.Size(120, 30); $ok.Text = 'Installa'; $ok.DialogResult = 'OK'
    $f.Controls.Add($ok); $f.AcceptButton = $ok
    $cn = New-Object System.Windows.Forms.Button
    $cn.Location = New-Object System.Drawing.Point(446, 140); $cn.Size = New-Object System.Drawing.Size(82, 30); $cn.Text = 'Annulla'; $cn.DialogResult = 'Cancel'
    $f.Controls.Add($cn); $f.CancelButton = $cn
    if ($f.ShowDialog() -ne 'OK') { return }
    $InstallDir = $t.Text.Trim()
}

$InstallDir = $InstallDir.TrimEnd('\')
if (-not $InstallDir -or $InstallDir.StartsWith('\\')) { throw "Cartella di installazione non valida: $InstallDir (usare un percorso locale)" }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($name in $Payload.Keys) {
    $target = Join-Path $InstallDir $name
    $bytes = [Convert]::FromBase64String($Payload[$name])
    [IO.File]::WriteAllBytes($target, $bytes)
}

New-Item -Path $RegKey -Force | Out-Null
Set-ItemProperty -Path $RegKey -Name InstallDir -Value $InstallDir
Set-ItemProperty -Path $RegKey -Name Version -Value $Version

if (-not $NoShortcuts) {
    $ws = New-Object -ComObject WScript.Shell
    foreach ($dir in [Environment]::GetFolderPath('CommonDesktopDirectory'), [Environment]::GetFolderPath('CommonPrograms')) {
        $sc = $ws.CreateShortcut((Join-Path $dir 'CompactVHDX Manager.lnk'))
        $sc.TargetPath = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
        $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$InstallDir\CompactVHDX-Manager.ps1`""
        $sc.WorkingDirectory = $InstallDir
        $sc.IconLocation = "$env:WINDIR\System32\shell32.dll,8"
        $sc.Description = 'CompactVHDX - compattazione offline dei VHDX FSLogix'
        $sc.Save()
    }
}

Write-Host "CompactVHDX $Version installato in $InstallDir" -ForegroundColor Green
if (-not $NoLaunch) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$InstallDir\CompactVHDX-Manager.ps1`""
}
'@
    $setupText = $setupTemplate.Replace('__VERSION__', $version).Replace('__PAYLOAD__', $payload)
    $setupFile = Join-Path $OutputDir 'CompactVHDX-Setup.ps1'
    [IO.File]::WriteAllText($setupFile, $setupText, (New-Object System.Text.UTF8Encoding($true)))
    if ($cert) { Set-CVSignature $setupFile; Ok 'Firmato CompactVHDX-Setup.ps1' }
    Ok "Creato $setupFile"

    # ------------------------------------------------------------ CompactVHDX-Manager.exe
    if (-not $SetupOnly) {
        Write-Host "`n== CompactVHDX-Manager.exe" -ForegroundColor Cyan
        $exe = Join-Path $OutputDir 'CompactVHDX-Manager.exe'
        $v4 = "$version.0"

@"
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="$v4" name="CompactVHDX.Manager"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"@ | Set-Content -LiteralPath (Join-Path $build 'app.manifest') -Encoding UTF8

@"
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("CompactVHDX Manager")]
[assembly: AssemblyDescription("Compattazione offline dei VHDX FSLogix")]
[assembly: AssemblyProduct("CompactVHDX")]
[assembly: AssemblyVersion("$v4")]
[assembly: AssemblyFileVersion("$v4")]

static class Program
{
    const string RegPath = @"SOFTWARE\CompactVHDX";
    const string DefaultDir = @"C:\Scripts\CompactVHDX";
    const string Version = "$version";
    static readonly string[] Tabs = { "Situazione", "Esecuzione", "Pianificazione", "Report", "Impostazioni" };

    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            Application.EnableVisualStyles();
            string dir = ReadInstallDir();
            bool reinstall = args.Length > 0 && string.Equals(args[0], "/install", StringComparison.OrdinalIgnoreCase);
            if (dir == null || reinstall)
            {
                dir = AskInstallDir(dir ?? DefaultDir);
                if (dir == null) return 0;
            }
            Directory.CreateDirectory(dir);

            Assembly asm = Assembly.GetExecutingAssembly();
            string skipped = "";
            foreach (string res in asm.GetManifestResourceNames())
            {
                if (!res.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)) continue;
                string target = Path.Combine(dir, res);
                byte[] data;
                using (Stream s = asm.GetManifestResourceStream(res))
                using (MemoryStream ms = new MemoryStream())
                {
                    s.CopyTo(ms);
                    data = ms.ToArray();
                }
                try
                {
                    if (File.Exists(target) && Same(File.ReadAllBytes(target), data)) continue;
                    File.WriteAllBytes(target, data);
                }
                catch (IOException)
                {
                    skipped += "\n" + res;
                }
            }
            WriteInstallDir(dir);
            if (skipped.Length > 0)
            {
                MessageBox.Show("Alcuni script non sono stati aggiornati perche' in uso:" + skipped +
                    "\n\nVerranno aggiornati al prossimo avvio.", "CompactVHDX", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            string tab = "Situazione";
            foreach (string a in args) if (Array.IndexOf(Tabs, a) >= 0) tab = a;

            ProcessStartInfo psi = new ProcessStartInfo("powershell.exe",
                "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"" +
                Path.Combine(dir, "CompactVHDX-Manager.ps1") + "\" -StartTab " + tab);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.WorkingDirectory = dir;
            Process.Start(psi);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show("Errore nell'avvio di CompactVHDX Manager:\n\n" + ex.Message, "CompactVHDX",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static RegistryKey Hklm()
    {
        return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    }

    static string ReadInstallDir()
    {
        using (RegistryKey k = Hklm().OpenSubKey(RegPath))
        {
            if (k == null) return null;
            string v = k.GetValue("InstallDir") as string;
            return string.IsNullOrEmpty(v) ? null : v;
        }
    }

    static void WriteInstallDir(string dir)
    {
        using (RegistryKey k = Hklm().CreateSubKey(RegPath))
        {
            k.SetValue("InstallDir", dir);
            k.SetValue("Version", Version);
        }
    }

    static string AskInstallDir(string current)
    {
        Form f = new Form();
        f.Text = "Installazione CompactVHDX " + Version;
        f.ClientSize = new Size(540, 170);
        f.StartPosition = FormStartPosition.CenterScreen;
        f.FormBorderStyle = FormBorderStyle.FixedDialog;
        f.MaximizeBox = false; f.MinimizeBox = false;
        f.Font = new Font("Segoe UI", 9);
        Label l = new Label();
        l.SetBounds(14, 12, 512, 56);
        l.Text = "Cartella di installazione di CompactVHDX su " + Environment.MachineName + ".\n" +
                 "Va installato sul server che ospita i profili FSLogix. Un'installazione esistente viene aggiornata senza toccare configurazione, log e storico.";
        TextBox t = new TextBox();
        t.SetBounds(14, 76, 420, 24);
        t.Text = current;
        Button b = new Button();
        b.SetBounds(442, 75, 84, 26);
        b.Text = "Sfoglia";
        b.Click += delegate
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog())
            {
                d.SelectedPath = t.Text;
                if (d.ShowDialog() == DialogResult.OK) t.Text = d.SelectedPath;
            }
        };
        Button ok = new Button();
        ok.SetBounds(316, 124, 120, 30);
        ok.Text = "Installa";
        ok.DialogResult = DialogResult.OK;
        Button cn = new Button();
        cn.SetBounds(444, 124, 82, 30);
        cn.Text = "Annulla";
        cn.DialogResult = DialogResult.Cancel;
        f.Controls.AddRange(new Control[] { l, t, b, ok, cn });
        f.AcceptButton = ok;
        f.CancelButton = cn;
        while (true)
        {
            if (f.ShowDialog() != DialogResult.OK) return null;
            string dir = t.Text.Trim().TrimEnd('\\');
            if (dir.Length > 2 && !dir.StartsWith(@"\\") && Path.IsPathRooted(dir)) return dir;
            MessageBox.Show("Indica un percorso locale valido, es. C:\\Scripts\\CompactVHDX", "CompactVHDX",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    static bool Same(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }
}
"@ | Set-Content -LiteralPath (Join-Path $build 'Launcher.cs') -Encoding UTF8

        $cscArgs = @('/nologo', '/target:winexe', '/platform:anycpu', '/optimize+',
                     "/out:$exe", "/win32manifest:$(Join-Path $build 'app.manifest')",
                     '/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll')
        foreach ($s in $scripts) { $cscArgs += "/resource:$(Join-Path $build $s),$s" }
        $cscArgs += (Join-Path $build 'Launcher.cs')
        $out = & $csc @cscArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Compilazione fallita:`n$($out -join "`n")" }
        if ($cert) { Set-CVSignature $exe; Ok "Firmato: $((Get-AuthenticodeSignature $exe).SignerCertificate.Subject)" }
        Ok "Creato $exe"

        if ($ToDesktop) {
            $desk = Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'CompactVHDX-Manager.exe'
            Copy-Item -LiteralPath $exe -Destination $desk -Force
            Ok "Copiato sul desktop pubblico: $desk"
        }
    }
} finally {
    Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nFatto. Su ogni server: CompactVHDX-Setup.ps1 (o l'exe) installa/aggiorna e apre CompactVHDX Manager, che al primo avvio parte con la configurazione guidata." -ForegroundColor Cyan
