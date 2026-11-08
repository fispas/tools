#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Modalita''' }
    @{ Key = 'Mode'; Label = 'Modalita'''; Type = 'Choice'; Choices = @('Fotografia', 'Hardening', 'Ripristino'); Help = 'Fotografia: controlli in sola lettura e report. Hardening: azioni correttive selezionabili una per una, con verifica prima e dopo, backup e report. Ripristino: annulla le azioni di un''esecuzione di hardening partendo dai suoi backup. Dopo il cambio premere Analizza.' }
    @{ Key = 'DryRun'; Label = 'Simulazione (hardening)'; Type = 'Bool'; Help = 'Attiva di default: mostra cosa verrebbe fatto senza modificare nulla. Toglierla solo dopo aver letto il report di simulazione.' }
    @{ Key = 'CompareWith'; Label = 'Fotografia da confrontare'; Type = 'File'; Filter = 'Fotografia (*.json)|*.json'; Help = 'Vuoto = l''ultima fotografia dello stesso dominio nella cartella dei report. Il report mostra rischi nuovi, risolti, peggiorati e la variazione del punteggio.' }
    @{ Key = 'RestoreFolder'; Label = 'Cartella da ripristinare'; Type = 'Folder'; Help = 'Solo modalita'' Ripristino: cartella Hardening_<dominio>_<data> con i file *.backup.json da annullare.' }
    @{ Type = 'Section'; Label = 'Dominio' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente. Letture LDAP, GPO e SYSVOL usano tutte questo DC (niente conflitti di replica).' }
    @{ Type = 'Section'; Label = 'Soglie' }
    @{ Key = 'InactiveDays'; Label = 'Giorni di inattivita'''; Type = 'Int'; Min = 30; Max = 730; Help = 'Utenti e computer senza logon oltre questa soglia: segnalati in fotografia, disattivabili in hardening.' }
    @{ Key = 'KrbtgtMaxDays'; Label = 'Eta'' massima password krbtgt (giorni)'; Type = 'Int'; Min = 30; Max = 3650; Help = 'Oltre: Attenzione; oltre il triplo: Critico. In hardening: oltre questa eta'' si propone la rotazione.' }
    @{ Key = 'PrivilegedMax'; Label = 'Numero massimo di Domain Admins'; Type = 'Int'; Min = 1; Max = 100 }
    @{ Key = 'MaxEvidence'; Label = 'Evidenze massime per controllo'; Type = 'Int'; Min = 10; Max = 100000; Help = 'Righe mostrate nel report HTML; il JSON e il CSV delle evidenze contengono lo stesso limite.' }
    @{ Type = 'Section'; Label = 'Controlli opzionali (fotografia)' }
    @{ Key = 'CheckDcServices'; Label = 'Interroga i servizi dei DC (Print Spooler)'; Type = 'Bool'; Help = 'Richiede privilegi di amministratore sui DC e WinRM/WMI raggiungibile; altrimenti il controllo risulta Non verificato.' }
    @{ Key = 'ScanSysvolGpp'; Label = 'Cerca password GPP in SYSVOL (cpassword)'; Type = 'Bool'; Help = 'Legge tutti i file XML delle GPO in SYSVOL.' }
    @{ Type = 'Section'; Label = 'Hardening - GPO' }
    @{ Key = 'GpoPrefix'; Label = 'Prefisso delle GPO e della PSO'; Type = 'Text'; Help = 'Es. FispaTools: GPO "FispaTools - DC Hardening", "FispaTools - DC Audit", "FispaTools - Member Hardening", "FispaTools - Windows LAPS".' }
    @{ Key = 'GpoLinkMode'; Label = 'Collegamento delle GPO'; Type = 'Choice'; Choices = @('Collegata e attiva', 'Collegata disattivata', 'Non collegata'); Help = 'Collegata disattivata: la GPO e'' pronta e si attiva a mano dopo la revisione in GPMC.' }
    @{ Key = 'MemberHardeningOus'; Label = 'OU per server e client'; Type = 'List'; Help = 'Distinguished name separati da ; (es. OU=Server,DC=contoso,DC=local). Vuoto = azioni HD-MB-* non applicabili.' }
    @{ Key = 'LmCompatibilityLevel'; Label = 'Livello NTLM (LmCompatibilityLevel)'; Type = 'Int'; Min = 3; Max = 5; Help = '5 = solo NTLMv2, rifiuta LM e NTLMv1 (consigliato); 3 = invia solo NTLMv2 ma accetta tutto.' }
    @{ Key = 'LdapChannelBinding'; Label = 'Channel binding LDAPS'; Type = 'Choice'; Choices = @('Se supportato', 'Sempre'); Help = '"Sempre" rifiuta i client che non lo supportano: prima usare "Se supportato" e controllare gli eventi 3039.' }
    @{ Key = 'SecurityLogMaxMB'; Label = 'Dimensione del registro Security sui DC (MB)'; Type = 'Int'; Min = 128; Max = 4096 }
    @{ Key = 'StopSpoolerNow'; Label = 'Ferma subito lo Spooler sui DC'; Type = 'Bool'; Help = 'Oltre alla GPO, ferma e disattiva il servizio via WMI/CIM (servono WinRM e privilegi sui DC).' }
    @{ Type = 'Section'; Label = 'Hardening - password e account privilegiati' }
    @{ Key = 'DomainMinPasswordLength'; Label = 'Lunghezza minima password di dominio'; Type = 'Int'; Min = 8; Max = 14; Help = 'Policy di dominio (massimo 14 senza l''opzione relax). Vale al prossimo cambio di ogni utente.' }
    @{ Key = 'DomainLockoutThreshold'; Label = 'Blocco dopo N tentativi errati'; Type = 'Int'; Min = 3; Max = 50 }
    @{ Key = 'DomainLockoutMinutes'; Label = 'Durata del blocco (minuti)'; Type = 'Int'; Min = 5; Max = 1440 }
    @{ Key = 'AdminPsoMinLength'; Label = 'Lunghezza minima password admin (PSO)'; Type = 'Int'; Min = 14; Max = 128 }
    @{ Key = 'AdminPsoMaxAgeDays'; Label = 'Scadenza password admin (giorni, 0 = mai)'; Type = 'Int'; Min = 0; Max = 3650 }
    @{ Key = 'ProtectedUsersMode'; Label = 'Protected Users'; Type = 'Choice'; Choices = @('Elenco', 'Tutti gli account privilegiati'); Help = 'Elenco = solo gli account indicati sotto. Gli account con SPN, l''Administrator integrato e i break-glass sono sempre esclusi.' }
    @{ Key = 'ProtectedUsersList'; Label = 'Account da mettere in Protected Users'; Type = 'List'; Help = 'sAMAccountName separati da ;' }
    @{ Key = 'BreakGlassAccounts'; Label = 'Account di emergenza (break-glass)'; Type = 'List'; Help = 'Mai in Protected Users e mai disattivati per inattivita''.' }
    @{ Key = 'KrbtgtMinHours'; Label = 'Ore minime tra le due rotazioni di krbtgt'; Type = 'Int'; Min = 10; Max = 720; Help = 'Almeno la durata massima dei ticket (10 ore) piu'' la replica completa.' }
    @{ Type = 'Section'; Label = 'Hardening - account inattivi' }
    @{ Key = 'InactiveAction'; Label = 'Azione sugli inattivi'; Type = 'Choice'; Choices = @('Disattiva', 'Disattiva e sposta') }
    @{ Key = 'QuarantineOu'; Label = 'OU di quarantena'; Type = 'Text'; Help = 'Distinguished name dell''OU in cui spostare gli account disattivati.' }
    @{ Key = 'InactiveExclude'; Label = 'Account esclusi'; Type = 'List'; Help = 'sAMAccountName (anche computer, con $) separati da ;' }
    @{ Key = 'InactiveSkipWithSpn'; Label = 'Escludi gli utenti con SPN (account di servizio)'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Hardening - Windows LAPS' }
    @{ Key = 'LapsOus'; Label = 'OU dei computer gestiti da LAPS'; Type = 'List'; Help = 'Distinguished name separati da ; (permessi SELF e collegamento della GPO). Vuoto = azioni LAPS non applicabili.' }
    @{ Key = 'LapsPasswordLength'; Label = 'Lunghezza della password LAPS'; Type = 'Int'; Min = 14; Max = 64 }
    @{ Key = 'LapsPasswordAgeDays'; Label = 'Rotazione della password LAPS (giorni)'; Type = 'Int'; Min = 1; Max = 365 }
    @{ Key = 'LapsAdminAccount'; Label = 'Account admin locale gestito'; Type = 'Text'; Help = 'Vuoto = Administrator integrato (RID 500).' }
    @{ Type = 'Section'; Label = 'Hardening - tier model' }
    @{ Key = 'TierRootName'; Label = 'OU radice del tier model'; Type = 'Text'; Help = 'Creata sotto la radice del dominio con Tier0/1/2 (Accounts, Groups, Devices, ServiceAccounts) e i gruppi TierN-Admins.' }
    @{ Key = 'TierLinkGpos'; Label = 'Collega le GPO di restrizione dei logon'; Type = 'Bool'; Help = 'Spento = GPO create ma non collegate. Prima spostare server e PC nelle OU Devices dei tier giusti.' }
    @{ Type = 'Section'; Label = 'Output' }
    @{ Key = 'OutputDir'; Label = 'Cartella dei report'; Type = 'Folder'; Help = 'Fotografia: HTML, JSON, CSV. Hardening: una cartella per esecuzione con report e backup dello stato precedente.' }
    @{ Key = 'LogDir'; Label = 'Cartella log'; Type = 'Folder' }
)

$ToolColumns = @(
    @{ Name = 'Id'; Header = 'ID'; Weight = 9 }
    @{ Name = 'Categoria'; Header = 'Categoria'; Weight = 12 }
    @{ Name = 'Controllo'; Header = 'Controllo / azione'; Weight = 28 }
    @{ Name = 'Peso'; Header = 'Peso / impatto'; Weight = 6 }
    @{ Name = 'Stato'; Header = 'Stato attuale'; Weight = 26 }
    @{ Name = 'Richiede'; Header = 'Richiede'; Weight = 11 }
)
#endregion
