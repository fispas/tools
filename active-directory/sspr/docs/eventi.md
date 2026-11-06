# Eventi di audit (Registro eventi "SSPR")

| ID | Evento | Note |
|---|---|---|
| 1000 / 1001 | Servizio avviato / fermato | |
| 1101 | Metodo di verifica registrato | Notificato sugli altri metodi dell'utente |
| 1102 | Metodo di verifica rimosso | |
| 1103 | Metodi azzerati da un amministratore | Con operatore e motivo |
| 1104 | Dati di registrazione non decifrabili | Valore alterato, copiato da un altro utente o chiave master diversa |
| 1201 / 1202 | Cambio password riuscito / fallito | |
| 1301 | Richiesta di reset o sblocco | Registrata anche per utenti inesistenti (senza rivelarlo all'utente) |
| 1302 | Verifica fallita durante un reset | Codice errato, scaduto, troppi tentativi |
| 1303 | Password reimpostata | |
| 1304 | Reset bloccato | Limite di tentativi o account non gestibile |
| 1401 / 1402 | Account sbloccato / sblocco fallito | |
| 1501 | Accesso al pannello di amministrazione | Con ruolo |
| 1502 | Azione amministrativa | Sblocco, azzeramento metodi, reset con password temporanea, invito: operatore, utente, motivo |
| 1503 | Accesso al pannello negato | |
| 1601 | Tentativo su un account protetto | Admin, gruppi privilegiati, Protected Users, account di servizio |
| 1602 | Limite di tentativi raggiunto | Per utente, IP o globale |
| 1900 | Configurazione modificata | Con operatore; i segreti non vengono registrati |
| 1990 | Errore imprevisto | |

Ogni evento riporta: esito, utente interessato, operatore (se diverso), IP del client e messaggio. Password, codici e segreti non compaiono mai.
