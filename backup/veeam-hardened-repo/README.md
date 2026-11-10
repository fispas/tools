# veeam-hardened-repo — Configurazione della macchina vrepo (Veeam Hardened Repository su Ubuntu)

Versione 1.0.0

Prepara un server Ubuntu appena installato come Linux Hardened Repository per Veeam Backup & Replication:
iSCSI, multipath, LUN XFS, fstab, utente Veeam con sudo temporaneo e, dopo l'aggiunta in VBR, la blindatura.

Si usa in due modi, con lo stesso motore:

| Modo | Dove | Quando |
|---|---|---|
| `Initialize-VeeamHardenedRepo.ps1` | PC Windows del tecnico | pannello con profili salvabili; lavora sul server via SSH |
| `vrepo-setup.sh` | sul server | wizard a menu (whiptail) in SSH o da console, oppure comandi singoli con file di configurazione |

`vrepo-setup.sh` è incorporato nel `.ps1`, quindi per la GUI basta un solo file.

## Requisiti

- Server: Ubuntu Server 22.04 / 24.04 (20.04 funziona ma non è più consigliato), con un utente amministratore che ha sudo, accesso SSH e accesso a Internet o a un mirror apt per installare i pacchetti
- Storage: LUN iSCSI (QNAP o qualunque target), FC/SAS multipath o dischi locali; i dischi di sistema (`/`, `/boot`, swap) vengono sempre esclusi
- GUI: Windows 10/11 o Server 2019+, PowerShell 5.1, client OpenSSH di Windows (`ssh.exe`, `ssh-keygen.exe`), che è installato di serie. Non servono i privilegi di amministratore su Windows.

## Flusso tipico con la GUI

1. **Configurazione**: server, utente amministratore, portali iSCSI, nomi delle LUN e così via. **Salva come…** crea un profilo per ogni server.
2. **Passi > Analizza**. Al primo avvio il server non è ancora raggiungibile con la chiave: si vede solo il passo **Accesso**.
3. Esegui **Accesso** (una volta sola). Si aprono due finestre console:
   - nella prima si inserisce la password SSH, per installare una chiave ed25519 dedicata;
   - nella seconda la password sudo, per installare `vrepo-setup.sh` in `/usr/local/sbin` e una regola sudo `NOPASSWD` limitata a quello script.

   Da qui in poi la GUI lavora senza chiedere password.
4. **Analizza** mostra lo stato di ogni passo (Fatto / Pronto), l'InitiatorName da autorizzare sul NAS e i target scoperti.
5. Esegui **Pacchetti, NTP, Initiator, Target, Multipath**, prima in simulazione e poi togliendo la spunta *Simulazione*.
6. **Analizza** di nuovo: compaiono le LUN viste dal server, con dimensione, numero di percorsi, WWID, nome proposto e punto di mount.
   - Per dare nomi precisi: copiare il WWID nel campo *Nomi delle LUN* (`WWID=nome`).
   - Spuntare le LUN e **Utente**, poi eseguire.
   - Nel log compare la password generata per l'utente Veeam.
7. In VBR aggiungi il server: Linux, *Single-use credentials for hardened repository*, utente `veeambck`. Poi crea il repository sul punto di mount, con Fast Clone e immutabilità.
8. Esegui **Blindatura**:
   - l'utente Veeam esce da sudo e la sua password viene bloccata;
   - la chiave e la regola sudo del tool vengono rimosse;
   - SSH viene spento.

   Il passo si rifiuta di partire se sul server non trova `/opt/veeam`, così non ci si chiude fuori prima dell'aggiunta in VBR.

Esegui i passi in ordine, dall'alto in basso: la griglia li presenta già nella sequenza giusta.

## Flusso sul server (senza GUI)

```bash
scp vrepo-setup.sh admin@vrepo01:/tmp/
ssh admin@vrepo01
sudo bash /tmp/vrepo-setup.sh            # menu: 1 = configurazione guidata completa
```

Il wizard chiede InitiatorName, portali, CHAP, NTP e profilo multipath. Mostra i target scoperti in una checklist e le LUN libere in un'altra.
Per ogni LUN propone il nome e il punto di mount, poi chiede di scrivere `FORMATTA` come conferma. Alla fine crea l'utente e mostra i passi da fare in VBR.
Le risposte (senza password) vengono salvate in `/etc/vrepo-setup/vrepo.conf` e riproposte al giro successivo.

Comandi singoli, con `--dry-run` per la simulazione:

```bash
sudo ./vrepo-setup.sh --config vrepo.conf --dry-run prepare     # pacchetti, NTP, initiator, target, multipath, utente
sudo ./vrepo-setup.sh lun --dev /dev/mapper/mpatha --name repo01
sudo ./vrepo-setup.sh --config vrepo.conf --yes luns            # tutte le LUN libere
sudo ./vrepo-setup.sh status
sudo ./vrepo-setup.sh lockdown                                   # dopo l'aggiunta in VBR
sudo ./vrepo-setup.sh unlock                                     # solo da console: riapre per aggiornare i componenti Veeam
sudo ./vrepo-setup.sh remove-targets --target 'iqn.2004-04.com.qnap:*:vecchio*'
```

Esempio di configurazione: [`vrepo.conf.example`](vrepo.conf.example). Log: `/var/log/vrepo-setup.log`.
Codici di uscita: 0 riuscito, 1 errore, 2 configurazione o argomenti non validi.

## Cosa fa rispetto alla procedura manuale

| Procedura manuale | Tool |
|---|---|
| `node.startup = automatic` in `iscsid.conf`, InitiatorName | passo Initiator. Il file corretto è `/etc/iscsi/initiatorname.iscsi`. `open-iscsi` viene riavviato solo se non ci sono sessioni attive. |
| discovery, `node.startup` e `node.conn[0].startup` automatici, login, rescan | passo Target. Login solo sui portali indicati (non sulle altre interfacce del NAS). I record dei target non scelti vengono eliminati, così al riavvio non si collega altro. CHAP opzionale. |
| `/etc/multipath.conf` (sezione defaults QNAP), restart, `multipath -ll` | passo Multipath. Backup del file esistente, controllo con `multipath -t` (avvisa su opzioni deprecate come `readsector0`), alias `/dev/mapper/<nome>` per ogni LUN. |
| `lsblk -f`, `cfdisk`, `mkfs.xfs -b size=4096 -m reflink=1,crc=1` | passo LUN. Rileva le LUN libere (niente filesystem, partizioni, firme o holder), crea la partizione GPT e l'XFS con etichetta. Le LUN con dati richiedono *Consenti di formattare*; quelle montate non si toccano mai. |
| riga UUID in `/etc/fstab`, `mount -av` | stesso passo LUN. Opzioni `_netdev,nofail` (iSCSI) con backup di fstab e verifica con `findmnt --verify`. Il punto di mount vuoto viene reso immutabile (`chattr +i`): se la LUN non si monta, Veeam non può scrivere sul disco di sistema. Viene verificato che reflink sia attivo. |
| `adduser veeambck`, `chown`, `chmod 700`, `usermod -aG sudo` | passo Utente. Password generata (o mantenuta) e permessi su tutti i repository creati. |
| `deluser veeambck sudo`, disattivare ssh e ssh.socket | passo Blindatura. In più: password bloccata, controllo di altre regole sudo, rimozione di chiave e regola del tool. |
| logout, delete del nodo, pulizia della discovery | passo Disconnessione / `remove-targets`. Si rifiuta se i dischi del target sono montati. |

## Configurazione della GUI

Ogni campo ha la descrizione nella scheda Configurazione. Il profilo JSON si trova in `%ProgramData%\FispaTools\VeeamHardenedRepo\config.json`; con *Salva come* se ne creano altri.

| Campo | Default | Note |
|---|---|---|
| Server / Porta SSH / Utente amministratore | — / 22 / — | utente creato all'installazione di Ubuntu |
| Chiave SSH privata | `%USERPROFILE%\.ssh\vrepo_ed25519` | creata al passo Accesso |
| InitiatorName | vuoto | vuoto = mantiene quello di Ubuntu |
| Portali / Porta / Target | — / 3260 / tutti | target anche con caratteri jolly |
| Login solo sui portali indicati | sì | |
| CHAP | vuoto | la password resta in chiaro nel JSON (mai nel log) |
| Multipath / Profilo / Alias | Automatico / QNAP / sì | |
| Prefisso / Nomi LUN / Cartella mount | `veeam-repo` / — / `/mnt` | `WWID=nome` o `sdc=nome` |
| Partizione GPT / Consenti di formattare | sì / no | |
| Utente Veeam / NTP / Fuso orario | `veeambck` / predefiniti / invariato | |
| Disattiva SSH / Blocca password / Blinda senza Veeam | sì / sì / no | |
| Target da disconnettere | vuoto | se indicati, aggiunge il passo Disconnessione |
| vrepo-setup.sh alternativo | vuoto | vuoto = versione incorporata |
| Simulazione | sì | il passo Accesso viene eseguito comunque |

Senza GUI, i passi si scelgono con `-User`:

```powershell
.\Initialize-VeeamHardenedRepo.ps1 -NoGui -ConfigPath D:\Profili\vrepo01.json -User Pacchetti,NTP,Initiator,Target,Multipath -Simulate
.\Initialize-VeeamHardenedRepo.ps1 -NoGui -ConfigPath D:\Profili\vrepo01.json -User LUN:veeam-repo01,Utente
```

## Sicurezza

- La regola sudo del tool vale solo per `/usr/local/sbin/vrepo-setup.sh` (root:root 0755) e per l'utente amministratore che già aveva sudo. La rimuove la blindatura.
- La chiave SSH ha il commento `vrepo-setup` e la blindatura la toglie da tutti gli `authorized_keys`.
- Configurazione e password CHAP passano al server tramite lo standard input di SSH, non sulla riga di comando.
- La password generata per l'utente Veeam compare nel log. Dopo la blindatura è bloccata, perché VBR usa i certificati.
- Per aggiornare i componenti Veeam: da console `sudo vrepo-setup.sh unlock`, che riattiva SSH, rimette il sudo e imposta una nuova password. Poi aggiornamento da VBR e di nuovo `lockdown`.
- Se il server è stato reinstallato con lo stesso IP, SSH segnala la chiave host cambiata. Si risolve con `ssh-keygen -R <server>`.

## Output

- GUI: log e report CSV/HTML in `%ProgramData%\FispaTools\VeeamHardenedRepo\Log`
- Server: `/var/log/vrepo-setup.log`; stato del tool in `/etc/vrepo-setup/` (repository creati, alias multipath, profilo, configurazione salvata); backup `*.bak-<data>` di ogni file modificato

## Sviluppo

- Sorgenti GUI in `_src/`; `Initialize-VeeamHardenedRepo.ps1` si genera con `python _lib/build.py`, che incorpora `vrepo-setup.sh` in base64.
- Test dello script senza storage reale: `VREPO_TEST_LOOP=1` include i loop device tra i dischi utilizzabili. Per esempio con `truncate -s 1G lun.img; losetup -f --show lun.img`.

## Changelog
- **1.0.0** — prima versione:
  - `vrepo-setup.sh`: wizard a menu e comandi, simulazione, iSCSI, multipath con alias, LUN XFS con mount protetto, utente, blindatura, riapertura, disconnessione, stato
  - GUI con analisi del server, passi selezionabili, accesso via chiave e regola sudo dedicata
