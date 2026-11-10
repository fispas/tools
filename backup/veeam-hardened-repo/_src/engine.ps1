
    #region SPECIFICO: hardened repository Veeam su Ubuntu via OpenSSH

    # vrepo-setup.sh incorporato da _lib/build.py (base64, fine riga LF)
    $script:VrepoB64 = '__EMBED:backup/veeam-hardened-repo/vrepo-setup.sh__'
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
