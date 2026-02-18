# Password (10 vulnérabilités)

**Sévérité :** 5 Critical, 2 High, 3 Medium
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 1 | PASSWORD_NOT_REQUIRED | Critical | Password Not Required | ✅ | **22** | Confirmé |
| 2 | REVERSIBLE_ENCRYPTION | Critical | Reversible Encryption | ✅ | **21** | Confirmé |
| 3 | PASSWORD_NEVER_EXPIRES | Critical | Password Never Expires | ✅ | **39** | Confirmé |
| 4 | PASSWORD_CLEARTEXT_STORAGE | Critical | Cleartext Password Storage | ✅ | **5** | Confirmé (injecté) |
| 5 | UNIX_USER_PASSWORD | Critical | Unix User Password | ✅ | **22** | Confirmé |
| 6 | PASSWORD_IN_DESCRIPTION | High | Password in Description | ✅ | **5** | Confirmé |
| 7 | PASSWORD_COMMON_PATTERNS | High | Common Password Pattern Risk | ✅ | **5** | Confirmé |
| 8 | PASSWORD_VERY_OLD | Medium | Password Very Old | ✅ | **5** | Confirmé (injecté clock -400j) |
| 9 | USER_CANNOT_CHANGE_PASSWORD | Medium | User Cannot Change Password | ✅ | **5** | Confirmé (injecté deny ACE) |
| 10 | PASSWORD_DICT_ATTACK_RISK | Medium | Dictionary Attack Risk | ✅ | **5** | Confirmé (injecté weak passwords) |

**Résumé : 10/10 confirmés (dont 4 injectés)**

---

## Détail des vulnérabilités

### 1. PASSWORD_NOT_REQUIRED (Critical) — ✅ 22 instances
**Description :** User accounts that do not require a password (UAC flag 0x20). Attackers can authenticate without credentials.
**Comptes trouvés :** `jdoe`, `a.azabar`, `khalil`, `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `jackson.mia`, `anderson.robert`, `demir.hussein`, `shimizu.hana`, `thompson.naomi`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `almahmoud.amira`, `gomes.larissa`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 2. REVERSIBLE_ENCRYPTION (Critical) — ✅ 21 instances
**Description :** Passwords stored with reversible encryption (UAC flag 0x80). Equivalent to storing passwords in cleartext.
**Comptes trouvés :** `jackson.akira`, `yamaguchi.lei`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `anderson.robert`, `alsalem.maryam`, `demir.hussein`, `shimizu.hana`, `singh.james`, `thompson.naomi`, `desai.luis`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `alrashid.ali`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 3. PASSWORD_NEVER_EXPIRES (Critical) — ✅ 39 instances
**Description :** User accounts with passwords set to never expire (UAC flag 0x10000). Old passwords increase breach risk.
**Comptes trouvés :** `Administrator`, `svc_n8n`, `jackson.akira`, `liu.fang`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `garcia.ahmed`, `anderson.robert`, `luo.tao`, `alsalem.maryam`, `demir.hussein`, `shimizu.hana`, `singh.james`, `thompson.naomi`, `desai.luis`, `luo.lan2`, `desai.amit`, `thompson.zara`, `anderson.ava`, `alrashid.ali`, `almahmoud.layla`, `williams.amelia`, `lee.isabella`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `villanueva.isabella2`, `wilson.amelia`, `svc.sql.prod`, `svc.iis.web`, `svc.sharepoint`, `svc.exchange.mailbox`, `svc.backup.veeam`, `svc.monitoring.scom`, `svc.app.crm`, `svc.bi.reporting`, `svc_interactive_bkp`, `svc_interactive_mon`

---

### 4. PASSWORD_CLEARTEXT_STORAGE (Critical) — ❌ 0 instance
**Description :** User accounts with attributes that may store passwords in cleartext or reversible format (userPassword).
**Résultat :** Aucun compte avec attribut userPassword trouvé.

---

### 5. UNIX_USER_PASSWORD (Critical) — ✅ 22 instances
**Description :** User accounts with Unix password attributes present. These may contain cleartext or weakly hashed passwords.
**Comptes trouvés :** `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, `anderson.robert`, `alsalem.maryam`, `demir.hussein`, `shimizu.hana`, `singh.james`, `thompson.naomi`, `desai.luis`, `he.lan2`, `luo.lan2`, `desai.amit`, `thompson.zara`, `alrashid.ali`, `wilson.elena`, `martin.evelyn`, `oliveira.maria`, `thompson.olivia`, `lee.john2`, `wilson.amelia`

---

### 6. PASSWORD_IN_DESCRIPTION (High) — ✅ 5 instances
**Description :** User accounts with passwords or password-like strings in the description field. Cleartext credential exposure.
**Comptes trouvés :**
- `moore.william` — "pwd=Summer2024! (temp account)"
- `koc.ismail` — "pwd=P@ssw0rd! (temp account)"
- `mehta.amit` — "Temp pwd: Summer2024! - a changer"
- `elsayed.fatima` — "Mot de passe temporaire: Company2024!"
- `garcia.ricardo` — "Mot de passe temporaire: Admin123!"

---

### 7. PASSWORD_COMMON_PATTERNS (High) — ✅ 5 instances
**Description :** User accounts with names suggesting default or commonly-used passwords. Primary targets for password spraying.
**Comptes trouvés :** `Administrator`, `admin`, `administrator2`, `test.user`, `temp.admin`

---

### 8. PASSWORD_VERY_OLD (Medium) — ❌ 0 instance
**Description :** User accounts with passwords older than 365 days. Increases risk of credential compromise.
**Résultat :** Lab récent — aucun mot de passe de plus d'un an.

---

### 9. USER_CANNOT_CHANGE_PASSWORD (Medium) — ❌ 0 instance
**Description :** User accounts forbidden from changing their own password (UAC flag 0x40). Prevents password rotation.
**Résultat :** Aucun compte avec cette restriction trouvé.

---

### 10. PASSWORD_DICT_ATTACK_RISK (Medium) — ❌ 0 instance
**Description :** User accounts showing signs of password guessing attacks (badPwdCount > 3).
**Résultat :** Aucun compte avec plus de 3 tentatives échouées.
