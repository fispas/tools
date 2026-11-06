# winauditpro — Audit e ottimizzazione Windows Server / Terminal Server

Audit completo di un server (meglio se RDS/Terminal Server) con report HTML interattivo, ottimizzazioni RDS applicabili e revertibili una per una con stato persistente, confronto tra due audit con severity. Unico file, nessuna dipendenza.

## Requisiti
- Windows Server 2012 R2+ / Windows 10+, PowerShell 5.1
- Amministratore (si eleva da solo)

## Uso

```powershell
.\Invoke-WinAuditPro.ps1
```

Si apre il **pannello**:
- **Impostazioni**: cartella di output, timeout dei cmdlet lenti, giorni di Registro eventi da analizzare, numero massimo di eventi, apertura automatica del report. *Salva* scrive in `%ProgramData%\FispaTools\WinAuditPro\config.json`; *Salva come* / *Carica* per tenere più configurazioni.
- **Audit salvati**: elenco con data, score, critici, warning, ruolo. Doppio clic = report HTML dell'audit.
- **Azioni**:
  - audit completo + report;
  - solo audit (JSON);
  - report da un audit;
  - apri l'ultimo report;
  - gestione ottimizzazioni (finestra apply/revert sull'audit selezionato);
  - dry run delle ottimizzazioni;
  - confronto tra 2 audit selezionati (il più vecchio è la baseline);
  - cartella di output;
  - menu testuale.
- Ogni azione gira **in un processo separato**: il pannello resta reattivo, il log arriva in tempo reale e *Annulla* interrompe audit e report, che sono in sola lettura. La gestione ottimizzazioni non si può interrompere dal pannello: si chiude la sua finestra.

### Senza GUI

```powershell
.\Invoke-WinAuditPro.ps1 -NoGui                                  # audit completo con la config salvata
.\Invoke-WinAuditPro.ps1 -Action AuditJson -OutputPath D:\Audit
.\Invoke-WinAuditPro.ps1 -Action Report -JsonPath D:\Audit\TS_AuditData_SRV01_20260101_120000.json
.\Invoke-WinAuditPro.ps1 -Action DryRun
.\Invoke-WinAuditPro.ps1 -Action Compare -BaselinePath .\a.json -CurrentPath .\b.json
.\Invoke-WinAuditPro.ps1 -Console                                # menu testuale della 2.0
```
Codici di uscita: `0` ok, `1` errore. Utile come operazione pianificata (audit periodico da confrontare con la baseline).

## Configurazione

| Campo | Default | Note |
|---|---|---|
| Cartella output | `C:\PerformanceAudit` | Audit JSON, report, confronti, `optimizations_state.json` |
| Timeout cmdlet (s) | 30 | Per contatori e WMI che possono bloccarsi |
| Giorni di eventi | 7 | Finestra del Registro eventi analizzata |
| Max eventi per log | 200 | |
| Apri il report al termine | sì | |

I parametri `-OutputPath` e `-CmdletTimeoutSec` sulla riga di comando hanno la precedenza sulla configurazione.

## Output
- `<output>\<ruolo>_AuditData_<server>_<data>.json` e `<ruolo>_Report_<server>_<data>.html`
- `<output>\audit_<server>_<data>.log`
- `<output>\optimizations_state.json` (+ `.bak`): stato delle ottimizzazioni e snapshot per il revert

## Note di sviluppo
- Sorgente **solo ASCII** (accenti scritti come `e'`), compatibile con `Set-StrictMode -Version 1.0`.
- Le ottimizzazioni sono definite in `Invoke-Optimize` (id, categoria, check, script, revert/regs, rischio).

## Changelog
- **2.1.0** — importato in `fispas/tools` (era `WinAuditPro_v2.ps1`):
  - **pannello grafico** di avvio con impostazioni salvabili, elenco degli audit, azioni in processo separato con log e annullamento;
  - `-Action` / `-NoGui` per l'uso non interattivo, con codici di uscita; il menu testuale resta con `-Console`;
  - giorni di eventi e numero massimo di eventi diventano configurabili;
  - stato delle ottimizzazioni scritto in modo atomico, con copia `.bak` letta in automatico se il file principale è danneggiato: gli snapshot del revert non si perdono più;
  - corretto il calcolo di "da applicare": `-as [bool]` restituiva `$null` con i check che emettono oggetti;
  - rimossi i caratteri non ASCII rimasti, che PowerShell 5.1 mostrava come caratteri corrotti.
- **2.0** — versione monolitica con audit, report, ottimizzazioni WPF e confronto baseline.
