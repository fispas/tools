# roaming-to-fslogix — Profili Roaming → FSLogix

Migra i profili Roaming (cartelle `utente.V6`, `utente.V2`, …) in nuovi dischi FSLogix. La cartella Roaming originale non viene modificata.

## Requisiti
- Windows Server 2012 R2+ / Windows 10+, PowerShell 5.1
- Amministratore (la GUI chiede l'elevazione da sola)
- `diskpart`, `robocopy`, cmdlet `Mount-DiskImage` (presenti di serie)
- Macchina nel dominio. **Non serve il modulo ActiveDirectory**

## Uso

```powershell
.\Convert-RoamingProfileToFSLogix.ps1
```

1. **Configurazione**: percorsi, dominio, formato e dimensione del disco, opzioni di copia. *Salva* scrive in `%ProgramData%\FispaTools\RoamingToFSLogix\config.json`; *Salva come* / *Carica* per più ambienti.
2. **Profili** → *Analizza*: per ogni cartella ricava l'utente (togliendo il suffisso `.V6`) e ne risolve il SID nel dominio. Non selezionabili: utente non trovato, escluso. In arancione: `NTUSER.DAT` assente o disco FSLogix già presente.
3. Spunta i profili → **Avvia migrazione** → conferma con riepilogo.
4. **Log** in tempo reale; *Annulla* completa il profilo in corso e si ferma.

La **simulazione è attiva di default**.

### Senza GUI

```powershell
.\Convert-RoamingProfileToFSLogix.ps1 -NoGui
.\Convert-RoamingProfileToFSLogix.ps1 -NoGui -ConfigPath D:\Mig\roaming.json -User mario.rossi -Simulate
```
Codici di uscita: `0` ok, `1` configurazione non valida, `2` almeno un profilo fallito.

## Parametri della configurazione

| Campo | Default | Note |
|---|---|---|
| Cartella profili Roaming | — | Es. `\\SRV01\Profili$` |
| Cartella FSLogix | — | Locale o UNC |
| Dominio (NetBIOS) | dominio dell'utente corrente | Dove cercare gli utenti |
| Suffisso da togliere | `\.V\d+$` | Regex; `mario.rossi.V6` → `mario.rossi` |
| Formato | dal registro FSLogix, altrimenti VHDX | VHDX / VHD |
| Dimensione massima (MB) | dal registro FSLogix, altrimenti 30000 | |
| Tipo disco | dal registro FSLogix, altrimenti Dinamico | Dinamico / Fisso |
| Nome cartella utente / Nome disco | come FSLogix | `%sid%_%username%`, `Profile_%username%` |
| Cartella profili sul session host | `C:\Users` | Per `ProfileData.reg` |
| Thread / tentativi robocopy | 8 / 2 | `/MT`, `/R` |
| Cartelle da non copiare | — | Passate a `robocopy /XD` |
| Se il disco esiste già | Salta | Salta / Rinomina / Sovrascrivi |
| Permessi dentro il disco | sì | robocopy non copia le ACL: l'utente diventa owner di `\Profile` |
| Permessi sulla cartella utente | sì | Per SID: utente, SYSTEM, Administrators |
| Elimina il disco se fallisce | sì | |
| Utenti esclusi | — | Separati da `;` |
| Cartella log e report | `%ProgramData%\FispaTools\RoamingToFSLogix\Log` | Anche i log robocopy per utente |
| Simulazione | sì | |

## Cosa fa per ogni utente
1. Gestisce un disco già presente; con disco fisso verifica lo spazio libero.
2. Crea il disco con `diskpart` (controllando il codice di uscita), partizione NTFS etichettata `Profile`.
3. Lo monta su una cartella temporanea (nessuna lettera di unità) e copia il profilo in `\Profile`: `robocopy /E /ZB /COPY:DAT /DCOPY:DAT /XJ`, log per utente.
4. Imposta owner e permessi dell'utente su `\Profile`, crea `ProfileData.reg`.
5. Smonta, imposta owner e permessi sulla cartella utente, verifica il disco finale.
6. Se qualcosa fallisce: smonta comunque e, se configurato, elimina il disco incompleto.

## Output
- Log: `<cartella log>\RoamingToFSLogix_<data>.log`, `robocopy_<utente>.log`
- Report: `<cartella log>\RoamingToFSLogix_Report_<data>.csv`

## Changelog
- **2.0.0** — riscritto: GUI a schede con configurazione salvabile, analisi con stato per utente, simulazione di default, esecuzione in background con annullamento pulito, modalità `-NoGui`. Formato, tipo disco, dominio, suffisso e opzioni robocopy configurabili. Nessuna domanda da console. Niente modulo ActiveDirectory. Controllo del codice di uscita di diskpart. Montaggio senza lettera di unità. `/XJ` contro i loop sui junction. Permessi dell'utente anche dentro il disco (la 1.x non li impostava). Permessi per SID con controllo errori. Pulizia dei dischi incompleti. Report CSV.
- **1.1.0** — rimossi riferimenti aziendali dall'header, esempi di percorso neutri.
- **1.0.1** — importato in `fispas/tools` dal repo `fispas/fslogix-RoamingProfile-migrator`; rimossi i delimitatori markdown che impedivano l'esecuzione.
