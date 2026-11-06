# tools

Tool e script operativi generici, eseguibili su qualunque ambiente. Nessun dato specifico di clienti: tutto è parametrizzato o auto-rilevato.

Regole complete in [CLAUDE.md](CLAUDE.md). Per un nuovo tool si parte da [`_template/`](_template/) (script semplice) oppure dalla libreria [`_lib/toolkit`](_lib/toolkit/) (tool con GUI configurabile, generato con `python _lib/build.py`).

## Indice

### Active Directory — [`active-directory/`](active-directory/)
| Tool | Descrizione | Versione |
|---|---|---|
| [share-permissions](active-directory/share-permissions/) | Share: migrazione dei permessi da utenti a gruppi AD (RW/RO) e hardening (permessi share, ABE, cifratura), con backup e simulazione | 1.0.0 |

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

## Progetti in definizione
| Progetto | Descrizione | Stato |
|---|---|---|
| [ad-hardening](active-directory/ad-hardening/) | Fotografia della sicurezza e salute di AD (stile PingCastle / Purple Knight), hardening guidato con rollback (gMSA, LAPS, Protected Users, audit policy, Tier model), documentazione | Fase 1 (fotografia, 28 controlli): `Invoke-ADAssessment.ps1` 0.1.0 |
| [sspr](active-directory/sspr/) | Self Service Password Reset on-prem: reset, cambio, sblocco, pannello admin, TOTP/SMS/email, dati in attributi AD confidenziali, installer guidato | 0.2.0: servizio, portale, pannello admin, installer guidato con gMSA (C#/.NET, pacchetto dalla CI; da collaudare) |
