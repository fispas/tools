# Schema AD di FispaSSPR

File di import: [`installer/schema/FispaSSPR-Schema.ldf`](../installer/schema/FispaSSPR-Schema.ldf).

Radice OID (metodo Microsoft da GUID): `1.2.840.113556.1.8000.2554.5811.899.4382.19277.44156.3796773.11388313`

| Oggetto | lDAPDisplayName | OID | schemaIDGUID | Sintassi |
|---|---|---|---|---|
| Attributo | `fispaSsprTotp` | `<radice>.1.1` | `e0101ee0-1337-489b-af18-19030f5541b3` | Unicode string, max 2048 |
| Attributo | `fispaSsprMobile` | `<radice>.1.2` | `add97609-b42b-4356-b2fa-de347b6296a5` | Unicode string, max 2048 |
| Attributo | `fispaSsprEmail` | `<radice>.1.3` | `f5f5c563-eb3b-401c-888b-9228100d4316` | Unicode string, max 2048 |
| Attributo | `fispaSsprState` | `<radice>.1.4` | `e7b77c31-6dde-4b73-a8e5-25603cc507a5` | Unicode string, max 4096 |
| Classe ausiliaria | `fispaSsprUser` | `<radice>.2.1` | `a7cd6b2b-35f0-4fd9-bc6c-17ee8b4f4de7` | `mayContain` dei 4 attributi, aggiunta come `auxiliaryClass` di `user` |

## Proprietà di sicurezza
- `searchFlags = 128` (**confidential**): per leggere il valore non basta *Read Property*, serve anche il diritto *Control Access* sull'attributo. Di default ce l'hanno solo gli amministratori del dominio.
- `isMemberOfPartialAttributeSet = FALSE`: gli attributi non vanno nel Global Catalog.
- I valori sono comunque **cifrati** (vedi [crypto.md](crypto.md)). Anche chi riesce a leggerli, come un amministratore o un backup, non ottiene segreti TOTP, numeri o indirizzi in chiaro.

## Permessi assegnati dall'installer (solo sulle OU abilitate, ereditati dagli oggetti `user`)
| A chi | Diritti |
|---|---|
| gMSA del portale | Reset Password (extended right `00299570-246d-11d0-a768-00aa006e0529`); Write `lockoutTime`, `pwdLastSet`; Read/Write/Control Access sui 4 attributi `fispaSspr*` |
| Nessun altro | Gli utenti **non** ricevono permessi sui propri attributi `fispaSspr*`: li modifica solo il portale dopo la verifica |

## Ciclo di vita
- L'estensione si fa una sola volta per foresta: membro di Schema Admins, sul DC con il ruolo di Schema Master.
- Un'aggiunta allo schema non si può eliminare. Se si dismette il portale si possono svuotare gli attributi (lo fa il disinstallatore) e rendere defunct attributi e classe.
- Le ACL per attributo usano gli `schemaIDGUID` qui sopra, che sono fissi e uguali in tutte le installazioni.
