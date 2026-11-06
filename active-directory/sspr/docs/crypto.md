# Cifratura dei dati di registrazione

Formato indipendente dal linguaggio, così un backend diverso (Node.js) può leggere e scrivere gli stessi attributi.

## Busta (envelope)
```
v1:<kid>:<base64( nonce[12] | ciphertext[n] | tag[16] )>
```
- Algoritmo: **AES-256-GCM**, nonce casuale di 12 byte, tag di 16 byte.
- `kid`: identificativo della chiave master (8 caratteri esadecimali). Permette la rotazione: le chiavi vecchie restano disponibili in sola decifratura.
- **Dati associati (AAD)**: `"<lDAPDisplayName>|<SID dell'utente>"` in UTF-8, es. `fispaSsprMobile|S-1-5-21-...-1105`. Un valore copiato da un utente a un altro, o da un attributo a un altro, **non si decifra**.
- Contenuto in chiaro:
  - `fispaSsprTotp`: segreto TOTP (20 byte casuali);
  - `fispaSsprMobile` ed `fispaSsprEmail`: stringa UTF-8;
  - `fispaSsprState`: JSON UTF-8 (vedi sotto).

## Chiave master
- 32 byte casuali generati all'installazione.
- Salvata in `%ProgramData%\FispaSSPR\keys\<kid>.key`, protetta con **DPAPI-NG** verso il SID del gMSA del portale (descrittore `SID=<sid gMSA>`). La decifra solo un processo che gira come quel gMSA, anche su un secondo server del portale.
- Cartella con ACL limitata a SYSTEM, Administrators e gMSA.
- **Backup**: l'installer esporta la chiave in un file cifrato con una password scelta dall'operatore (PBKDF2-SHA256, 600.000 iterazioni, poi AES-256-GCM). Se la chiave va persa non si perdono password né accessi: gli utenti devono solo registrare di nuovo i metodi.

## Stato (`fispaSsprState`, JSON in chiaro prima della cifratura)
```json
{
  "v": 1,
  "enrolledAt": "2026-11-06T10:00:00Z",
  "totpVerifiedAt": "2026-11-06T10:00:00Z",
  "mobileVerifiedAt": null,
  "emailVerifiedAt": "2026-11-06T10:02:00Z",
  "lastResetAt": null,
  "lastTotpStep": 59245920
}
```
`lastTotpStep` impedisce di riusare un codice TOTP già accettato (anti-replay).

## Codici monouso (SMS / email)
- 6 cifre generate con un RNG crittografico, valide 5 minuti, al massimo 5 tentativi.
- Si conserva solo `HMAC-SHA256(chiave di sessione del servizio, "<idSfida>:<codice>")`, in memoria, mai in AD né nei log.
