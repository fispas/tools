
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Percorsi' }
    @{ Key = 'DestinationPath'; Label = 'Cartella FSLogix (destinazione)'; Type = 'Folder'; Help = 'Radice dei contenitori FSLogix, locale o UNC (es. D:\FSLogix oppure \\SRV01\FSLogix$). I profili di origine vengono letti dal registro di questa macchina.' }
    @{ Key = 'FrxPath'; Label = 'Percorso frx.exe'; Type = 'File'; Filter = 'frx.exe|frx.exe'; Help = 'Letto dal registro di FSLogix (HKLM\SOFTWARE\FSLogix\Apps), altrimenti %ProgramFiles%\FSLogix\Apps.' }
    @{ Type = 'Section'; Label = 'Disco FSLogix' }
    @{ Key = 'VolumeType'; Label = 'Formato'; Type = 'Choice'; Choices = @('VHDX', 'VHD'); Help = 'Deve corrispondere a VolumeType di FSLogix.' }
    @{ Key = 'SizeMB'; Label = 'Dimensione massima (MB)'; Type = 'Int'; Min = 1024; Max = 2097152; Help = 'Come SizeInMBs di FSLogix. Precompilato dal registro FSLogix, altrimenti 30000.' }
    @{ Key = 'DiskType'; Label = 'Tipo disco'; Type = 'Choice'; Choices = @('Dinamico', 'Fisso'); Help = 'Dinamico cresce con i dati (IsDynamic=1). Fisso occupa subito tutta la dimensione.' }
    @{ Key = 'FolderPattern'; Label = 'Nome cartella utente'; Type = 'Text'; Help = 'Come SIDDirNamePattern: %sid%_%username% (predefinito) oppure %username%_%sid% (FlipFlopProfileDirectoryName=1).' }
    @{ Key = 'DiskNamePattern'; Label = 'Nome disco (senza estensione)'; Type = 'Text'; Help = 'Come VHDNamePattern (predefinito Profile_%username%).' }
    @{ Type = 'Section'; Label = 'Utenti' }
    @{ Key = 'IncludeLocalAccounts'; Label = 'Includi account locali della macchina'; Type = 'Bool'; Help = 'Di norma si migrano solo gli account di dominio.' }
    @{ Key = 'ExcludeUsers'; Label = 'Utenti esclusi'; Type = 'List'; Help = 'SamAccountName separati da punto e virgola.' }
    @{ Type = 'Section'; Label = 'Comportamento' }
    @{ Key = 'ExistingDisk'; Label = "Se il disco FSLogix esiste gia'"; Type = 'Choice'; Choices = @('Salta', 'Rinomina', 'Sovrascrivi'); Help = "Salta: l'utente non viene toccato. Rinomina: il disco esistente diventa <nome>.bak-<data>. Sovrascrivi: viene eliminato." }
    @{ Key = 'SetFolderAcl'; Label = 'Imposta owner e permessi sulla cartella utente'; Type = 'Bool'; Help = 'Owner = utente; controllo completo a utente, SYSTEM e Administrators (per SID).' }
    @{ Key = 'CleanupOnError'; Label = 'Elimina il disco creato se la migrazione fallisce'; Type = 'Bool'; Help = 'Evita che FSLogix agganci un disco incompleto.' }
    @{ Key = 'EnableLongPaths'; Label = 'Abilita i percorsi lunghi (LongPathsEnabled=1)'; Type = 'Bool'; Help = 'Modifica il registro di sistema di questa macchina. Utile solo se la copia fallisce per percorsi oltre 260 caratteri.' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = 'Attiva di default: verifica tutto e registra le operazioni senza modificare nulla. Disattivarla per la migrazione reale.' }
)

$ToolColumns = @(
    @{ Name = 'Utente'; Header = 'Utente'; Weight = 12 }
    @{ Name = 'Nome'; Header = 'Nome'; Weight = 14 }
    @{ Name = 'Dominio'; Header = 'Dominio'; Weight = 8 }
    @{ Name = 'Cartella'; Header = 'Cartella'; Weight = 16 }
    @{ Name = 'UltimoUso'; Header = 'Ultimo uso'; Weight = 10 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 14 }
)
#endregion
