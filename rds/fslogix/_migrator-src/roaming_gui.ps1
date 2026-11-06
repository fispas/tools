
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Percorsi' }
    @{ Key = 'SourcePath'; Label = 'Cartella profili Roaming (origine)'; Type = 'Folder'; Help = 'Cartella che contiene i profili (es. \\SRV01\Profili$ con cartelle utente.V6). Non viene modificata.' }
    @{ Key = 'DestinationPath'; Label = 'Cartella FSLogix (destinazione)'; Type = 'Folder'; Help = 'Radice dei contenitori FSLogix, locale o UNC (es. \\SRV01\FSLogix$).' }
    @{ Type = 'Section'; Label = 'Utenti' }
    @{ Key = 'Domain'; Label = 'Dominio (NetBIOS)'; Type = 'Text'; Help = "Dominio in cui cercare gli utenti. Predefinito: dominio dell'utente che esegue lo script." }
    @{ Key = 'SuffixRegex'; Label = 'Suffisso da togliere al nome cartella'; Type = 'Text'; Help = 'Espressione regolare. Predefinito \.V\d+$ (mario.rossi.V6 -> mario.rossi).' }
    @{ Key = 'ExcludeUsers'; Label = 'Utenti esclusi'; Type = 'List'; Help = 'SamAccountName separati da punto e virgola.' }
    @{ Type = 'Section'; Label = 'Disco FSLogix' }
    @{ Key = 'VolumeType'; Label = 'Formato'; Type = 'Choice'; Choices = @('VHDX', 'VHD'); Help = 'Deve corrispondere a VolumeType di FSLogix.' }
    @{ Key = 'SizeMB'; Label = 'Dimensione massima (MB)'; Type = 'Int'; Min = 1024; Max = 2097152; Help = 'Come SizeInMBs di FSLogix. Precompilato dal registro FSLogix, altrimenti 30000.' }
    @{ Key = 'DiskType'; Label = 'Tipo disco'; Type = 'Choice'; Choices = @('Dinamico', 'Fisso'); Help = "Dinamico cresce con i dati (come IsDynamic=1). Fisso occupa subito tutta la dimensione." }
    @{ Key = 'FolderPattern'; Label = 'Nome cartella utente'; Type = 'Text'; Help = 'Come SIDDirNamePattern: %sid%_%username% (predefinito) oppure %username%_%sid% (FlipFlopProfileDirectoryName=1).' }
    @{ Key = 'DiskNamePattern'; Label = 'Nome disco (senza estensione)'; Type = 'Text'; Help = 'Come VHDNamePattern (predefinito Profile_%username%).' }
    @{ Key = 'ProfileRoot'; Label = 'Cartella profili sul session host'; Type = 'Text'; Help = 'Usata per ProfileImagePath in ProfileData.reg (predefinito C:\Users).' }
    @{ Type = 'Section'; Label = 'Copia' }
    @{ Key = 'RobocopyThreads'; Label = 'Thread robocopy (/MT)'; Type = 'Int'; Min = 1; Max = 64 }
    @{ Key = 'RobocopyRetries'; Label = 'Tentativi su file bloccati (/R)'; Type = 'Int'; Min = 0; Max = 10 }
    @{ Key = 'ExcludeDirs'; Label = 'Cartelle da non copiare'; Type = 'List'; Help = 'Nomi o percorsi passati a robocopy /XD, separati da punto e virgola.' }
    @{ Type = 'Section'; Label = 'Comportamento' }
    @{ Key = 'ExistingDisk'; Label = "Se il disco FSLogix esiste gia'"; Type = 'Choice'; Choices = @('Salta', 'Rinomina', 'Sovrascrivi'); Help = "Salta: l'utente non viene toccato. Rinomina: il disco esistente diventa <nome>.bak-<data>. Sovrascrivi: viene eliminato." }
    @{ Key = 'SetProfileAcl'; Label = 'Imposta owner e permessi dentro il disco'; Type = 'Bool'; Help = "robocopy non copia le ACL (/COPY:DAT): l'utente diventa owner della cartella \Profile con controllo completo." }
    @{ Key = 'SetFolderAcl'; Label = 'Imposta owner e permessi sulla cartella utente'; Type = 'Bool'; Help = 'Owner = utente; controllo completo a utente, SYSTEM e Administrators (per SID).' }
    @{ Key = 'CleanupOnError'; Label = 'Elimina il disco creato se la migrazione fallisce'; Type = 'Bool'; Help = 'Evita che FSLogix agganci un disco incompleto.' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder'; Help = 'Contiene anche i log robocopy per utente.' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = 'Attiva di default: verifica tutto e registra le operazioni senza modificare nulla. Disattivarla per la migrazione reale.' }
)

$ToolColumns = @(
    @{ Name = 'Utente'; Header = 'Utente'; Weight = 12 }
    @{ Name = 'Nome'; Header = 'Nome'; Weight = 14 }
    @{ Name = 'Cartella'; Header = 'Cartella'; Weight = 14 }
    @{ Name = 'SID'; Header = 'SID'; Weight = 20 }
    @{ Name = 'Modificato'; Header = 'Modificato'; Weight = 10 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 12 }
)
#endregion
