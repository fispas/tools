
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Percorsi' }
    @{ Key = 'SourcePath'; Label = 'Cartella UPD (origine)'; Type = 'Folder'; Help = 'Cartella che contiene i dischi UVHD-S-*.vhdx / .vhd. I dischi originali non vengono modificati: si lavora su una copia.' }
    @{ Key = 'DestinationPath'; Label = 'Cartella FSLogix (destinazione)'; Type = 'Folder'; Help = 'Radice dei contenitori FSLogix, locale o UNC (es. \\SRV01\FSLogix$).' }
    @{ Type = 'Section'; Label = 'Formato FSLogix' }
    @{ Key = 'FolderPattern'; Label = 'Nome cartella utente'; Type = 'Text'; Help = "Come SIDDirNamePattern di FSLogix: %sid%_%username% (predefinito) oppure %username%_%sid% (FlipFlopProfileDirectoryName=1). Precompilato dal registro FSLogix della macchina, se presente." }
    @{ Key = 'DiskNamePattern'; Label = 'Nome disco (senza estensione)'; Type = 'Text'; Help = "Come VHDNamePattern (predefinito Profile_%username%). L'estensione resta quella del disco UPD: VolumeType di FSLogix deve corrispondere." }
    @{ Key = 'ProfileRoot'; Label = 'Cartella profili sul session host'; Type = 'Text'; Help = 'Usata per ProfileImagePath in ProfileData.reg (predefinito C:\Users).' }
    @{ Type = 'Section'; Label = 'Comportamento' }
    @{ Key = 'ExistingDisk'; Label = "Se il disco FSLogix esiste gia'"; Type = 'Choice'; Choices = @('Salta', 'Rinomina', 'Sovrascrivi'); Help = "Salta: l'utente non viene toccato. Rinomina: il disco esistente diventa <nome>.bak-<data>. Sovrascrivi: viene eliminato." }
    @{ Key = 'SetFolderAcl'; Label = 'Imposta owner e permessi sulla cartella utente'; Type = 'Bool'; Help = "Owner = utente; controllo completo a utente, SYSTEM e Administrators (per SID, indipendente dalla lingua di Windows)." }
    @{ Key = 'CleanupOnError'; Label = 'Elimina il disco copiato se la migrazione fallisce'; Type = 'Bool'; Help = 'Evita che FSLogix agganci un disco incompleto.' }
    @{ Key = 'ExcludeUsers'; Label = 'Utenti esclusi'; Type = 'List'; Help = 'SamAccountName separati da punto e virgola.' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = 'Attiva di default: verifica tutto e registra le operazioni senza modificare nulla. Disattivarla per la migrazione reale.' }
)

$ToolColumns = @(
    @{ Name = 'Utente'; Header = 'Utente'; Weight = 12 }
    @{ Name = 'Nome'; Header = 'Nome'; Weight = 14 }
    @{ Name = 'SID'; Header = 'SID'; Weight = 22 }
    @{ Name = 'DimensioneMB'; Header = 'MB'; Weight = 6 }
    @{ Name = 'Modificato'; Header = 'Modificato'; Weight = 10 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 12 }
)
#endregion
