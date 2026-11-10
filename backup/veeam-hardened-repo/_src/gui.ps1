
#region SPECIFICO: campi della configurazione e colonne
$ToolSchema = @(
    @{ Type = 'Section'; Label = 'Server vrepo (SSH)' }
    @{ Key = 'Host'; Label = 'Server'; Type = 'Text'; Help = 'IP o nome del server Ubuntu appena installato (rete di gestione).' }
    @{ Key = 'Port'; Label = 'Porta SSH'; Type = 'Int'; Min = 1; Max = 65535 }
    @{ Key = 'SshUser'; Label = 'Utente amministratore'; Type = 'Text'; Help = "Utente creato durante l'installazione di Ubuntu (con sudo). Al passo Accesso si inseriscono una volta la sua password SSH e quella di sudo in una finestra console." }
    @{ Key = 'SshKeyFile'; Label = 'Chiave SSH privata'; Type = 'File'; Help = 'Chiave dedicata al tool: se non esiste viene creata (ed25519) al passo Accesso. La blindatura la rimuove dal server.' }
    @{ Type = 'Section'; Label = 'iSCSI' }
    @{ Key = 'InitiatorName'; Label = 'InitiatorName'; Type = 'Text'; Help = "Vuoto = mantiene quello generato da Ubuntu (mostrato da Analizza, da autorizzare sul NAS). Es. iqn.2004-10.com.ubuntu:01:vrepo01" }
    @{ Key = 'IscsiPortals'; Label = 'Portali del target'; Type = 'List'; Help = 'IP del NAS/SAN separati da punto e virgola: uno per percorso, es. 10.10.1.10; 10.10.2.10. Con due o piu'' portali il multipath si attiva in automatico.' }
    @{ Key = 'IscsiPort'; Label = 'Porta iSCSI'; Type = 'Int'; Min = 1; Max = 65535 }
    @{ Key = 'IscsiTargets'; Label = 'Target (IQN)'; Type = 'List'; Help = 'IQN o caratteri jolly, es. iqn.2004-04.com.qnap:*:veeam*. Vuoto = tutti i target scoperti. I record degli altri target vengono eliminati, cosi'' al riavvio non si collega altro.' }
    @{ Key = 'OnlyListedPortals'; Label = 'Login solo sui portali indicati'; Type = 'Bool'; Help = "Il NAS annuncia il target su tutte le sue interfacce (anche la LAN di gestione): con questa opzione il login avviene solo sugli IP indicati sopra." }
    @{ Key = 'ChapUser'; Label = 'Utente CHAP'; Type = 'Text'; Help = 'Vuoto = nessuna autenticazione CHAP.' }
    @{ Key = 'ChapPassword'; Label = 'Password CHAP'; Type = 'Text'; Help = 'Attenzione: viene salvata in chiaro nel profilo JSON (non nel log). Lasciare vuoto se non serve.' }
    @{ Type = 'Section'; Label = 'Multipath' }
    @{ Key = 'Multipath'; Label = 'Multipath'; Type = 'Choice'; Choices = @('Automatico', 'Si', 'No'); Help = "Automatico: attivo se ci sono piu' portali o LUN viste su piu' percorsi." }
    @{ Key = 'MultipathProfile'; Label = 'Profilo'; Type = 'Choice'; Choices = @('QNAP', 'Generico'); Help = "QNAP: round-robin 0, multibus, alua, uid ID_SERIAL, failback immediate, no_path_retry fail. Generico: user_friendly_names e find_multipaths. /etc/multipath.conf esistente salvato in backup." }
    @{ Key = 'MultipathAlias'; Label = 'Alias multipath = nome della LUN'; Type = 'Bool'; Help = '/dev/mapper/<nome> invece di mpatha, mpathb...' }
    @{ Type = 'Section'; Label = 'LUN e repository' }
    @{ Key = 'LunPrefix'; Label = 'Prefisso dei nomi'; Type = 'Text'; Help = 'Nomi proposti per le LUN senza nome assegnato: <prefisso>01, <prefisso>02... Il nome e'' etichetta XFS (primi 12 caratteri), alias multipath e cartella di mount.' }
    @{ Key = 'LunNames'; Label = 'Nomi delle LUN'; Type = 'List'; Help = 'Associazioni WWID=nome o dispositivo=nome separate da punto e virgola, es. 36e843b6...=repo-giornaliero; sdc=repo-mensile. Il WWID si copia dalla scheda Passi dopo Analizza.' }
    @{ Key = 'MountBase'; Label = 'Cartella dei punti di mount'; Type = 'Text'; Help = 'Ogni LUN si monta in <cartella>/<nome>, es. /mnt/veeam-repo01. Il punto di mount vuoto e'' reso immutabile (chattr +i): se la LUN non si monta nessuno scrive sul disco di sistema.' }
    @{ Key = 'Partition'; Label = 'Crea una partizione GPT'; Type = 'Bool'; Help = 'Una partizione su tutto il disco (consigliato). Senza, XFS viene creato direttamente sul dispositivo.' }
    @{ Key = 'ForceFormat'; Label = 'Consenti di formattare LUN con dati'; Type = 'Bool'; Help = 'Disattivo: le LUN con filesystem, partizioni o firme esistenti non si toccano. Le LUN montate o in uso non si toccano mai.' }
    @{ Type = 'Section'; Label = 'Utente Veeam e sistema' }
    @{ Key = 'VeeamUser'; Label = 'Utente Veeam'; Type = 'Text'; Help = "Utente locale per le credenziali single-use in VBR. La password viene generata e mostrata nel log al passo Utente; la blindatura la blocca." }
    @{ Key = 'NtpServers'; Label = 'Server NTP'; Type = 'List'; Help = "Vuoto = predefiniti di Ubuntu. L'immutabilita' dipende da un orologio corretto: con rete isolata indicare un NTP interno (es. il domain controller)." }
    @{ Key = 'Timezone'; Label = 'Fuso orario'; Type = 'Text'; Help = 'Es. Europe/Rome. Vuoto = non modificare.' }
    @{ Type = 'Section'; Label = "Blindatura (dopo l'aggiunta del repository in VBR)" }
    @{ Key = 'SshDisable'; Label = 'Disattiva SSH'; Type = 'Bool'; Help = "Dopo la blindatura la GUI non si collega piu'. Per aggiornare i componenti Veeam: da console sudo vrepo-setup.sh unlock, poi di nuovo lockdown." }
    @{ Key = 'LockVeeamPassword'; Label = "Blocca la password dell'utente Veeam"; Type = 'Bool'; Help = 'Dopo l''aggiunta VBR usa i certificati: la password non serve piu''.' }
    @{ Key = 'LockdownForce'; Label = 'Blinda anche se Veeam non risulta installato'; Type = 'Bool'; Help = "Normalmente la blindatura si rifiuta se non trova /opt/veeam, per non chiudere fuori l'operatore prima dell'aggiunta in VBR." }
    @{ Key = 'RemoveTargets'; Label = 'Target da disconnettere'; Type = 'List'; Help = 'IQN o caratteri jolly: aggiunge il passo Disconnessione (logout ed eliminazione del nodo). Le LUN montate bloccano la disconnessione.' }
    @{ Key = 'RemoveDiscovery'; Label = 'Elimina anche la discovery del portale'; Type = 'Bool' }
    @{ Type = 'Section'; Label = 'Script, log e simulazione' }
    @{ Key = 'ScriptPath'; Label = 'vrepo-setup.sh alternativo'; Type = 'File'; Filter = 'Script bash (*.sh)|*.sh|Tutti i file (*.*)|*.*'; Help = 'Vuoto = la versione incorporata in questo tool (consigliato).' }
    @{ Key = 'LogDir'; Label = 'Cartella log e report'; Type = 'Folder' }
    @{ Key = 'DryRun'; Label = 'Simulazione (nessuna modifica)'; Type = 'Bool'; Help = "Attiva di default: ogni passo mostra i comandi che eseguirebbe sul server. Fa eccezione il passo Accesso, che installa chiave e script anche in simulazione (non tocca storage, rete o utenti)." }
)

$ToolColumns = @(
    @{ Name = 'Passo'; Header = 'Passo'; Weight = 9 }
    @{ Name = 'Dettaglio'; Header = 'Dettaglio'; Weight = 26 }
    @{ Name = 'Dispositivo'; Header = 'Dispositivo'; Weight = 10 }
    @{ Name = 'Dimensione'; Header = 'Dimensione'; Weight = 6 }
    @{ Name = 'Percorsi'; Header = 'Percorsi'; Weight = 5 }
    @{ Name = 'Nome'; Header = 'Nome'; Weight = 9 }
    @{ Name = 'Mount'; Header = 'Mount'; Weight = 11 }
    @{ Name = 'Stato'; Header = 'Stato'; Weight = 10 }
)
#endregion
