# tools

Tool e script operativi generici, eseguibili su qualunque ambiente. Nessun dato specifico di clienti: tutto è parametrizzato o auto-rilevato.

Regole complete in [CLAUDE.md](CLAUDE.md). Per un nuovo tool si parte da [`_template/`](_template/).

## Indice

### Active Directory — [`active-directory/`](active-directory/)
| Tool | Descrizione | Versione |
|---|---|---|
| _nessuno ancora_ | | |

### Remote Desktop / Terminal Server — [`rds/`](rds/)
| Tool | Descrizione | Versione |
|---|---|---|
| [fslogix/compact-vhdx](rds/fslogix/compact-vhdx/) | Compattazione offline pianificata dei VHDX FSLogix sul file server: pannello, report, storico, email | 2.1.0 |
| [fslogix/roaming-to-fslogix](rds/fslogix/roaming-to-fslogix/) | Migra profili Roaming (.V6) in nuovi dischi FSLogix: GUI configurabile, simulazione, -NoGui | 2.0.0 |
| [fslogix/upd-to-fslogix](rds/fslogix/upd-to-fslogix/) | Migra User Profile Disk (UPD) in FSLogix lavorando su copia: GUI configurabile, simulazione, -NoGui | 2.0.0 |
| [fslogix/local-to-fslogix](rds/fslogix/local-to-fslogix/) | Migra profili locali in FSLogix con frx.exe, profili letti da ProfileList: GUI configurabile, simulazione, -NoGui | 2.0.0 |
| [winauditpro](rds/winauditpro/) | Audit Windows Server / RDS con report HTML, ottimizzazioni apply/revert, confronto baseline: pannello, -NoGui | 2.1.0 |

### Windows — [`windows/`](windows/)
| Tool | Descrizione | Versione |
|---|---|---|
| _nessuno ancora_ | | |

### Utility — [`utility/`](utility/)
| Tool | Descrizione | Versione |
|---|---|---|
| _nessuno ancora_ | | |
