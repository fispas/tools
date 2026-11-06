
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'File server e share' }
    @{ Key = 'FileServer'; Label = 'File server'; Type = 'Text'; Help = 'Nome del server con le share. Predefinito: questa macchina. In remoto servono WinRM (o DCOM) e i diritti di amministratore sul server.' }
    @{ Key = 'IncludeShares'; Label = 'Solo queste share'; Type = 'List'; Help = 'Nomi o caratteri jolly separati da punto e virgola (es. Contab*; Tecnico). Vuoto = tutte.' }
    @{ Key = 'ExcludeShares'; Label = 'Share escluse'; Type = 'List'; Help = 'Le share amministrative (C$, ADMIN$, IPC$) sono sempre escluse.' }
    @{ Key = 'IncludeHidden'; Label = 'Includi le share nascoste (nome$)'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Gruppi AD' }
    @{ Key = 'GroupOU'; Label = 'OU dei gruppi'; Type = 'Text'; Help = 'distinguishedName dell''OU in cui creare i gruppi, es. OU=Condivisioni,OU=Gruppi,DC=contoso,DC=local.' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente. Tutte le operazioni LDAP usano lo stesso DC, cosi'' un gruppo appena creato e'' subito utilizzabile.' }
    @{ Key = 'GroupPrefix'; Label = 'Prefisso'; Type = 'Text'; Help = 'Il nome del gruppo e'' <prefisso><NomeShare><suffisso>, es. GR-Contabilita_RW.' }
    @{ Key = 'GroupMode'; Label = 'Gruppi per share'; Type = 'Choice'; Choices = @('Separati (RW/RO)', 'Unico (Modifica)'); Help = 'Separati: un gruppo in modifica e uno in lettura, con gli utenti assegnati in base al permesso che hanno oggi. Unico: un solo gruppo in modifica (come gli script originali).' }
    @{ Key = 'GroupSuffixRW'; Label = 'Suffisso modifica'; Type = 'Text' }
    @{ Key = 'GroupSuffixRO'; Label = 'Suffisso lettura'; Type = 'Text' }
    @{ Key = 'GroupScope'; Label = 'Ambito dei gruppi'; Type = 'Choice'; Choices = @('DomainLocal', 'Global', 'Universal'); Help = 'DomainLocal e'' la scelta consigliata per i gruppi di risorsa (modello AGDLP: utenti -> gruppi globali di ruolo -> gruppi locali di dominio sulla risorsa).' }
    @{ Type = 'Section'; Label = 'Migrazione dei permessi' }
    @{ Key = 'CreateGroups'; Label = 'Crea i gruppi mancanti'; Type = 'Bool' }
    @{ Key = 'PopulateGroups'; Label = 'Popola i gruppi con gli utenti trovati nelle ACL'; Type = 'Bool'; Help = 'Utenti con permesso di scrittura -> gruppo modifica; solo lettura -> gruppo lettura. Account amministrativi, di sistema e orfani non vengono aggiunti.' }
    @{ Key = 'IncludeAclGroups'; Label = 'Aggiungi anche i gruppi presenti nelle ACL come membri'; Type = 'Bool'; Help = 'Annida nei nuovi gruppi i gruppi che oggi hanno permessi sulla share (Domain Users e simili esclusi).' }
    @{ Key = 'GrantGroupNtfs'; Label = 'Permesso NTFS ai gruppi sulla cartella della share'; Type = 'Bool'; Help = 'Modifica / Lettura ed esecuzione, ereditato da tutte le sottocartelle e file.' }
    @{ Key = 'RemoveUserAces'; Label = 'Rimuovi le ACE esplicite degli utenti migrati'; Type = 'Choice'; Choices = @('No', 'Solo radice', 'Intero albero'); Help = "Solo per gli utenti aggiunti con successo al gruppo del loro livello. 'Intero albero' toglie anche i loro permessi espliciti nelle sottocartelle: chi aveva accessi particolari in una sottocartella li perde. Valutare prima con la simulazione." }
    @{ Type = 'Section'; Label = 'Hardening della share' }
    @{ Key = 'SharePermissions'; Label = 'Permessi della share'; Type = 'Choice'; Choices = @('Non modificare', 'Standard (Authenticated Users Modifica, Administrators Full)'); Help = "Standard: i permessi effettivi li decide NTFS; viene rimosso Everyone. I nomi degli account sono risolti sul file server, quindi funziona con qualunque lingua di Windows." }
    @{ Key = 'EnableABE'; Label = 'Attiva Access-Based Enumeration'; Type = 'Bool'; Help = "Ogni utente vede solo le cartelle a cui ha accesso." }
    @{ Key = 'EncryptData'; Label = 'Attiva la cifratura SMB'; Type = 'Bool'; Help = 'Richiede client SMB 3 (Windows 8 / Server 2012 e successivi): gli altri non accedono piu''.' }
    @{ Type = 'Section'; Label = 'Backup, log e simulazione' }
    @{ Key = 'BackupDir'; Label = 'Cartella dei backup'; Type = 'Folder'; Help = 'Per ogni share: ACL (icacls /save) e permessi della share in JSON, prima di qualunque modifica. Il comando di ripristino e'' scritto nel log.' }
    @{ Key = 'BackupTree'; Label = "Backup delle ACL di tutto l'albero"; Type = 'Bool'; Help = "Consigliato se si rimuovono le ACE nell'intero albero. Su share molto grandi richiede tempo." }
    @{ Key = 'ExcludeUsers'; Label = 'Utenti da non migrare'; Type = 'List'; Help = 'SamAccountName separati da punto e virgola: restano con i permessi attuali.' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = 'Attiva di default: per ogni share mostra gruppi, membri e passi che verrebbero eseguiti.' }
)

$ToolColumns = @(
    @{ Name = 'Share'; Header = 'Share'; Weight = 10 }
    @{ Name = 'Percorso'; Header = 'Percorso'; Weight = 14 }
    @{ Name = 'Utenti'; Header = 'Utenti in ACL'; Weight = 8 }
    @{ Name = 'GruppiAcl'; Header = 'Gruppi in ACL'; Weight = 6 }
    @{ Name = 'Ampio'; Header = 'Accesso ampio'; Weight = 12 }
    @{ Name = 'PermShare'; Header = 'Permessi share'; Weight = 14 }
    @{ Name = 'ABE'; Header = 'ABE'; Weight = 4 }
    @{ Name = 'Gruppi'; Header = 'Gruppi previsti'; Weight = 14 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 16 }
)
#endregion
