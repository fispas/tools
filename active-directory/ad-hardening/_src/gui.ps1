
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Dominio' }
    @{ Key = 'DomainController'; Label = 'Domain controller'; Type = 'Text'; Help = 'Vuoto = scelto automaticamente nel dominio della macchina. Tutte le letture LDAP usano questo DC.' }
    @{ Type = 'Section'; Label = 'Soglie' }
    @{ Key = 'InactiveDays'; Label = 'Giorni di inattivita'''; Type = 'Int'; Min = 30; Max = 730; Help = 'Oltre questa soglia utenti e computer senza logon sono segnalati come inattivi.' }
    @{ Key = 'KrbtgtMaxDays'; Label = 'Eta'' massima password krbtgt (giorni)'; Type = 'Int'; Min = 30; Max = 3650; Help = 'Oltre: Attenzione; oltre il triplo: Critico.' }
    @{ Key = 'PrivilegedMax'; Label = 'Numero massimo di Domain Admins'; Type = 'Int'; Min = 1; Max = 100 }
    @{ Key = 'MaxEvidence'; Label = 'Evidenze massime per controllo'; Type = 'Int'; Min = 10; Max = 100000; Help = 'Righe mostrate nel report HTML; il JSON e il CSV delle evidenze contengono lo stesso limite.' }
    @{ Type = 'Section'; Label = 'Controlli opzionali' }
    @{ Key = 'CheckDcServices'; Label = 'Interroga i servizi dei DC (Print Spooler)'; Type = 'Bool'; Help = 'Richiede privilegi di amministratore sui DC e WinRM/WMI raggiungibile; altrimenti il controllo risulta Non verificato.' }
    @{ Key = 'ScanSysvolGpp'; Label = 'Cerca password GPP in SYSVOL (cpassword)'; Type = 'Bool'; Help = 'Legge tutti i file XML delle GPO in SYSVOL.' }
    @{ Type = 'Section'; Label = 'Output' }
    @{ Key = 'OutputDir'; Label = 'Cartella dei report'; Type = 'Folder'; Help = 'Report HTML, JSON completo, CSV dei controlli e delle evidenze.' }
    @{ Key = 'LogDir'; Label = 'Cartella log'; Type = 'Folder' }
)

$ToolColumns = @(
    @{ Name = 'Id'; Header = 'ID'; Weight = 8 }
    @{ Name = 'Categoria'; Header = 'Categoria'; Weight = 14 }
    @{ Name = 'Controllo'; Header = 'Controllo'; Weight = 30 }
    @{ Name = 'Peso'; Header = 'Peso'; Weight = 5 }
    @{ Name = 'Richiede'; Header = 'Richiede'; Weight = 16 }
)
#endregion
