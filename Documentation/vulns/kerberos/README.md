# Kerberos (14 vulnérabilités)

**Sévérité :** 4 Critical, 5 High, 4 Medium, 1 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 11 | ADMIN_ASREP_ROASTABLE | Critical | Privileged Account AS-REP Roastable | ✅ | **20** | Confirmé |
| 12 | ASREP_ROASTING_RISK | Critical | AS-REP Roasting Risk | ✅ | **25** | Confirmé |
| 13 | GOLDEN_TICKET_RISK | Critical | Golden Ticket Risk | ❌ | 0 | Non trouvé (krbtgt changé il y a 92j) |
| 14 | UNCONSTRAINED_DELEGATION | Critical | Unconstrained Delegation | ✅ | **20** | Confirmé |
| 15 | KERBEROASTING_RISK | High | Kerberoasting Risk | ✅ | **35** | Confirmé |
| 16 | CONSTRAINED_DELEGATION | High | Constrained Delegation | ✅ | **17** | Confirmé |
| 17 | KERBEROS_AES_DISABLED | High | AES Encryption Disabled | ✅ | **3** | Confirmé |
| 18 | WEAK_ENCRYPTION_DES | High | Weak DES Encryption | ✅ | **19** | Confirmé |
| 19 | KERBEROS_RC4_FALLBACK | Medium | RC4 Fallback Enabled | ✅ | **5** | Confirmé |
| 20 | WEAK_ENCRYPTION_FLAG | Medium | Weak Encryption Flag | ✅ | **19** | Confirmé |
| 21 | WEAK_ENCRYPTION_RC4 | Medium | Weak RC4 Encryption | ✅ | **2** | Confirmé |
| 22 | KERBEROS_TICKET_LIFETIME_LONG | Medium | Kerberos Ticket Lifetime Too Long | ✅ | **1** | Confirmé (20h > 10h) |
| 23 | KERBEROS_RENEWABLE_TICKET_LONG | Low | Kerberos Renewable Ticket Lifetime Too Long | ✅ | **1** | Confirmé (injecté MaxRenewAge=14j) |
| 24 | DELEGATION_UNKNOWN_TARGET | High | Constrained Delegation to Unknown Target | ❓ | - | Non vérifié |

**Résumé : 12/14 confirmés (dont 1 injecté) | 1 non injectable | 1 non vérifié**

---

## Détail des vulnérabilités

### 11. ADMIN_ASREP_ROASTABLE (Critical) — ✅ 20 instances
**Description :** Privileged accounts (adminCount=1) without Kerberos pre-authentication. Immediate domain compromise risk.
**Comptes trouvés :** `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `anderson.robert`, `alsalem.maryam`, `demir.hussein`, `shimizu.hana`, `singh.james`, `thompson.naomi`, `desai.luis`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `alrashid.ali`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 12. ASREP_ROASTING_RISK (Critical) — ✅ 25 instances
**Description :** User accounts without Kerberos pre-authentication required (UAC 0x400000). Vulnerable to AS-REP roasting.
**Comptes trouvés :** 20 admins ci-dessus + `yildiz.hatice`, `koc.yusuf`, `sanchez.elena`, `svc.exchange.mailbox`, `svc.bi.reporting`

---

### 13. GOLDEN_TICKET_RISK (Critical) — ❌ Non vulnérable
**Description :** krbtgt account password unchanged for 180+ days. Enables persistent Golden Ticket attacks.
**Résultat :** krbtgt PasswordLastSet: 2025-11-17 (92 jours). Seuil: 180 jours. Non vulnérable actuellement.

---

### 14. UNCONSTRAINED_DELEGATION (Critical) — ✅ 20 instances
**Description :** User accounts with unconstrained Kerberos delegation (UAC 0x80000). Can impersonate any user to any service.
**Comptes trouvés :** `Administrator`, `svc_n8n`, `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `anderson.robert`, `johnson.james`, `demir.hussein`, `shimizu.hana`, `thompson.naomi`, `desai.luis`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 15. KERBEROASTING_RISK (High) — ✅ 35 instances
**Description :** User accounts with SPNs. Vulnerable to Kerberoasting attacks to crack service account passwords.
**Comptes trouvés :** 20 comptes admin avec CIFS/MSSQL/HTTP SPNs + 15 comptes de service (svc.exchange.mailbox, svc_interactive_bkp, svc.app.crm, martin.james, svc_interactive_mon, perez.maria, svc.bi.reporting, svc.sharepoint, svc.iis.web, ma.xiao, perez.valentina, svc.sql.prod, anderson.charlotte, cruz.rosa, zhang.ying)

---

### 16. CONSTRAINED_DELEGATION (High) — ✅ 17 instances
**Description :** User accounts with constrained Kerberos delegation. Can impersonate users to specific services.
**Comptes trouvés :**
- `kato.sora` — TrustedToAuthForDelegation + delegTo: MSSQL/dbserver, HTTP/webserver, CIFS/fileserver
- 16 comptes avec msDS-AllowedToDelegateTo: HOST/server.aza-me.cc (jackson.akira, nakamura.naomi, wilson.olivia, jackson.john, anderson.robert, demir.hussein, shimizu.hana, thompson.naomi, he.lan2, luo.lan2, desai.amit, thompson.zara, oliveira.maria, thompson.olivia, lee.john2, wilson.amelia)

---

### 17. KERBEROS_AES_DISABLED (High) — ✅ 3 instances
**Description :** User accounts with AES Kerberos encryption disabled. Forces use of weaker DES/RC4.
**Comptes trouvés :**
- `he.lan2` — encType: 0 (aucun type défini)
- `svc.sql.prod` — encType: 7 (DES+RC4 seulement)
- `svc.app.crm` — encType: 7 (DES+RC4 seulement)

---

### 18. WEAK_ENCRYPTION_DES (High) — ✅ 19 instances
**Description :** User accounts with DES encryption enabled (UAC 0x200000). DES is cryptographically broken.
**Comptes trouvés :** `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `anderson.robert`, `smith.emma`, `torres.pedro`, `demir.hussein`, `shimizu.hana`, `thompson.naomi`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `villanueva.isabella`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 19. KERBEROS_RC4_FALLBACK (Medium) — ✅ 5 instances
**Description :** User accounts support both AES and RC4. RC4 fallback enables downgrade attacks.
**Comptes trouvés :**
- `matsumoto.daiki` — encType: 28 (RC4+AES128+AES256)
- `sasaki.sakura` — encType: 28
- `iyer.rohan` — encType: 28
- `akter.karim` — encType: 28
- `gutierrez.rosa2` — encType: 28

---

### 20. WEAK_ENCRYPTION_FLAG (Medium) — ✅ 19 instances
**Description :** User accounts with USE_DES_KEY_ONLY flag (UAC 0x200000). Forces weak DES encryption.
**Résultat :** Identique à #18 — 19 comptes avec UseDESKeyOnly activé.

---

### 21. WEAK_ENCRYPTION_RC4 (Medium) — ✅ 2 instances
**Description :** User accounts supporting RC4 without AES. RC4 is deprecated and vulnerable.
**Comptes trouvés :**
- `svc.sql.prod` — encType: 7 (DES+RC4 seulement)
- `svc.app.crm` — encType: 7 (DES+RC4 seulement)

---

### 22. KERBEROS_TICKET_LIFETIME_LONG (Medium) — ✅ 1 instance (policy)
**Description :** TGT lifetime exceeds recommended 10 hours, increasing attack window for stolen tickets.
**Résultat :** MaxTicketAge = 20 heures (recommandé: 10h). MaxServiceAge = 1200 min. Politique domaine vulnérable.

---

### 23. KERBEROS_RENEWABLE_TICKET_LONG (Low) — ✅ 1 instance
**Description :** Renewable ticket lifetime exceeds recommended 7 days.
**Résultat :** MaxRenewAge = **14 jours** (injecté via secedit, recommandé: 7 jours). Fenêtre de renouvellement trop longue.

---

### 24. DELEGATION_UNKNOWN_TARGET (High) — ❓ Non vérifié
**Description :** Accounts with constrained delegation to SPNs whose target hostname does not match any known computer in AD. May indicate stale delegation or delegation to external/unknown systems. Attackers could register a machine with the missing hostname.
**Résultat :** Non testé individuellement.
