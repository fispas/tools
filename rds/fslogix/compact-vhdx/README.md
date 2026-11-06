# compact-vhdx — Compattazione offline dei VHDX FSLogix

Compattazione offline dei dischi profilo FSLogix (VHD/VHDX) sul file server che li ospita,
con pannello grafico, pianificazione, report, storico e notifiche email.

## Dove installarlo

Sul **file server che ospita i profili FSLogix**, perché la compattazione lavora sui file
locali e verifica quali dischi sono in uso tramite le sessioni SMB di quel server.
Non va installato sui session host.

Requisiti, controllati dalla configurazione guidata:

- Windows Server 2012 R2 o successivo
- Windows PowerShell 5.1
- account amministratore
- diskpart, cmdlet Storage e SMB (presenti di serie sui file server Windows)

## Installazione

### Metodo consigliato: CompactVHDX-Setup.ps1

```powershell
powershell -ExecutionPolicy Bypass -File .\CompactVHDX-Setup.ps1
```

1. Chiede la cartella di installazione (predefinita `C:\Scripts\CompactVHDX`).
2. Copia gli script.
3. Registra l'installazione in `HKLM\SOFTWARE\CompactVHDX`.
4. Crea il collegamento **CompactVHDX Manager** sul desktop pubblico e nel menu Start.
5. Apre il pannello.

Funziona anche dove un antivirus blocca gli eseguibili non noti.

Opzioni: `-InstallDir D:\Tools\CompactVHDX`, `-Silent`, `-NoLaunch`, `-NoShortcuts`.

### In alternativa: CompactVHDX-Manager.exe

Si genera con `Build-CompactVHDXExe.ps1`. Fa le stesse cose del Setup, tranne i collegamenti,
e resta utilizzabile come icona di avvio. Con `CompactVHDX-Manager.exe /install` si cambia la
cartella di installazione.

### Aggiornamento

Si rilancia il Setup (o l'exe) della nuova versione. Gli script vengono sostituiti;
configurazione, log, storico e report restano invariati.

## Configurazione guidata (primo avvio)

Al primo avvio del pannello, o con **Impostazioni → Configurazione guidata**, si impostano:

| Impostazione | Note |
|---|---|
| Cartelle dei profili | Rilevate automaticamente nelle condivisioni del server. Se ne possono indicare più di una. Percorsi locali, non UNC. Riconosce sia `SID_utente` sia `utente_SID` (FlipFlopProfileDirectoryName) e sia i dischi Profile_ sia gli ODFC_. |
| Cartella report | Predefinita `<installazione>\Report` |
| Limite FSLogix (SizeInMBs) | Letto dal registro se l'agente FSLogix è presente, altrimenti 30000 |
| Soglia di avviso dello spazio libero | In percentuale |
| Pianificazione iniziale | Domenica sera con orario di stop, opzionale |

Si impostano dopo, in **Impostazioni**:

- utenti esclusi;
- giorni di inattività;
- conservazione di log e report;
- email.

## Email

- **Microsoft 365 (Graph API)**, consigliato per Exchange Online:
  - registrazione app in Entra ID con permesso applicazione `Mail.Send` e consenso amministratore;
  - segreto client;
  - casella mittente, anche condivisa;
  - limitazione dell'app alla sola casella mittente con `New-ApplicationAccessPolicy` (o RBAC for Applications).
- **SMTP relay anonimo**: solo per relay che accettano invii senza autenticazione.

Il segreto viene cifrato con DPAPI e funziona solo sul server dove è stato salvato.
Quando si salva, la cartella di installazione viene limitata a SYSTEM e Administrators.

## Cosa crea sul server

| Elemento | Dettaglio |
|---|---|
| Cartella di installazione | Script, `config.json`, `Log\`, `Data\history.csv`, `status.json` |
| Task `FSLogix-CompactVHDX` | Compattazione pianificata, come SYSTEM |
| Task `FSLogix-CompactVHDX-Monitor` | Apre il pannello agli amministratori collegati (opzionale) |
| Task `FSLogix-CompactVHDX-Manual` | Esecuzioni avviate dal pannello |
| Registro | `HKLM\SOFTWARE\CompactVHDX` (InstallDir, Version) |
| Eventi | Registro applicazioni, sorgente `CompactVHDX`: 1000 avvio, 1001 ok, 1002 errori, 1003 interrotta, 1004 spazio sotto soglia, 1005 errore imprevisto |

## Antivirus / EDR

Il job esegue `powershell.exe -ExecutionPolicy Bypass` e `diskpart`. Se l'EDR lo blocca,
le eccezioni da chiedere sono:

- la cartella di installazione;
- la firma del codice degli script e dell'exe (`Build-CompactVHDXExe.ps1 -SignScripts`);
- in alternativa, l'hash dei file.

## Disinstallazione

Dal pannello: **Impostazioni → Disinstalla CompactVHDX**. Rimuove task, collegamenti e
registrazione, e a scelta anche la cartella con configurazione, log e storico.

## Regola d'oro

Non terminare mai il task di compattazione da Utilità di pianificazione: un disco in
lavorazione resterebbe agganciato al server e l'utente non potrebbe accedere. Usare
**Stop pulito** nel pannello oppure `Stop-CompactVHDX.ps1`.

## File

| File | Ruolo |
|---|---|
| `CompactVHDX-Manager.ps1` | Pannello grafico: stato, esecuzione, pianificazione, report, impostazioni, configurazione guidata |
| `Compact-ProfileDisks.ps1` | Job di compattazione eseguito dai task come SYSTEM |
| `CompactVHDX-Common.ps1` | Libreria comune (config, inventario, report, task, email) |
| `Stop-CompactVHDX.ps1` | Stop pulito da riga di comando |
| `Build-CompactVHDXExe.ps1` | Genera `CompactVHDX-Setup.ps1` (e opzionalmente l'exe), con firma opzionale |
| `CompactVHDX-Setup.ps1` | Installatore autonomo **generato**: contiene gli altri script in base64. Dopo ogni modifica ai sorgenti va rigenerato con `Build-CompactVHDXExe.ps1 -SetupOnly` |

## Changelog
- **2.0.0** — importato in `fispas/tools`
