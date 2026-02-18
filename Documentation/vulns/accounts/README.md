# Accounts (32 vulnérabilités)

**Sévérité :** 3 Critical, 15 High, 12 Medium, 2 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 24 | SENSITIVE_DELEGATION | Critical | Sensitive Account with Delegation | ✅ | **7** | Confirmé |
| 25 | REPLICA_DIRECTORY_CHANGES | Critical | Potential Directory Replication Rights | ✅ | **60** | Confirmé |
| 26 | SERVICE_ACCOUNT_PRIVILEGED | Critical | Service Account in Privileged Group | ✅ | **7** | Confirmé |
| 27 | DISABLED_ACCOUNT_IN_ADMIN_GROUP | High | Disabled Account in Admin Group | ✅ | **1** | Confirmé |
| 28 | EXPIRED_ACCOUNT_IN_ADMIN_GROUP | High | Expired Account in Admin Group | ✅ | **3** | Confirmé |
| 29 | SID_HISTORY | High | SID History Present | ⚠️ | 0 | Non injectable (nécessite ADMT) |
| 30 | NOT_IN_PROTECTED_USERS | High | Not in Protected Users Group | ✅ | **23** | Confirmé |
| 31 | DOMAIN_ADMIN_IN_DESCRIPTION | High | Sensitive Terms in Description | ✅ | **33** | Confirmé |
| 32 | BACKUP_OPERATORS_MEMBER | High | Backup Operators Member | ✅ | **20** | Confirmé |
| 33 | ACCOUNT_OPERATORS_MEMBER | High | Account Operators Member | ✅ | **20** | Confirmé |
| 34 | SERVER_OPERATORS_MEMBER | High | Server Operators Member | ✅ | **11** | Confirmé |
| 35 | PRINT_OPERATORS_MEMBER | High | Print Operators Member | ✅ | **19** | Confirmé |
| 36 | LOCKED_ACCOUNT_ADMIN | High | Locked Administrative Account | ✅ | **1** | Confirmé |
| 37 | PRIVILEGED_ACCOUNT_SPN | High | Privileged Account with SPN | ✅ | **22** | Confirmé |
| 38 | SERVICE_ACCOUNT_INTERACTIVE | High | Service Account with Interactive Logon | ✅ | **4** | Confirmé (injecté) |
| 39 | SERVICE_ACCOUNT_NO_PREAUTH | High | Service Account Without Pre-Auth | ✅ | **22** | Confirmé |
| 40 | SERVICE_ACCOUNT_OLD_PASSWORD | High | Service Account with Old Password | ✅ | **2** | Confirmé |
| 41 | STALE_ACCOUNT | High | Stale Account (180+ Days) | ✅ | **10** | Confirmé (injecté) |
| 42 | INACTIVE_365_DAYS | Medium | Inactive 365+ Days | ✅ | **5** | Confirmé (injecté) |
| 43 | NEVER_LOGGED_ON | Medium | Never Logged On | ✅ | **533** | Confirmé |
| 44 | ACCOUNT_EXPIRE_SOON | Medium | Account Expiring Soon | ✅ | **1** | Confirmé |
| 45 | TEST_ACCOUNT | Medium | Test Account | ✅ | **3** | Confirmé |
| 46 | SHARED_ACCOUNT | Medium | Shared Account | ✅ | **4** | Confirmé |
| 47 | SMARTCARD_NOT_REQUIRED | Medium | Smartcard Not Required | ✅ | **55** | Confirmé |
| 48 | PRIMARYGROUPID_SPOOFING | Medium | primaryGroupID Spoofing | ✅ | **1** | Confirmé (Guest=514) |
| 49 | SERVICE_ACCOUNT_WITH_SPN | Medium | Service Account with SPN | ✅ | **33** | Confirmé |
| 50 | SERVICE_ACCOUNT_WEAK_ENCRYPTION | Medium | Service Account Using Weak Encryption | ✅ | **3** | Confirmé |
| 51 | ADMIN_COUNT_ORPHANED | Medium | Orphaned AdminCount Flag | ✅ | **24** | Confirmé |
| 52 | ADMIN_NO_SMARTCARD | Medium | Admin Without Smartcard Requirement | ✅ | **55** | Confirmé |
| 53 | DANGEROUS_BUILTIN_MEMBERSHIP | Medium | Dangerous Built-in Group Membership | ✅ | **4** | Confirmé |
| 54 | SERVICE_ACCOUNT_NAMING | Low | Service Account by Naming Convention | ✅ | **5** | Confirmé |
| 55 | ADMIN_LOGON_COUNT_LOW | Low | Admin Account with Low Logon Count | ✅ | **53** | Confirmé |

**Résumé : 31/32 confirmés | 1 non injectable (SID_HISTORY nécessite ADMT/migration inter-domaines)**

---

## Détail des vulnérabilités

### 24. SENSITIVE_DELEGATION (Critical) — ✅ 7 instances
**Description :** Privileged accounts (Domain/Enterprise Admins) with unconstrained delegation. Extreme security risk.
**Comptes trouvés :**
- `Administrator`
- `svc_n8n`
- `wilson.olivia`
- `jackson.john`
- `shimizu.hana`
- `he.lan2`
- `luo.lan2`

---

### 25. REPLICA_DIRECTORY_CHANGES (Critical) — ✅ 60 instances
**Description :** Accounts that may have directory replication rights (DCSync capability). Can extract all password hashes.
**Résultat :** 60 comptes avec adminCount=1 dont `Administrator`, `krbtgt`, `svc_n8n`, `admin`, `administrator2`, `backup_admin`, `svc.sharepoint`, `svc.app.crm` + 52 utilisateurs standards.

---

### 26. SERVICE_ACCOUNT_PRIVILEGED (Critical) — ✅ 7 instances
**Description :** Service accounts in privileged groups (Domain Admins, etc.). If compromised, attackers gain full domain control.
**Comptes trouvés :**
- `wilson.olivia` — SPN: CIFS/MSSQL/HTTP
- `jackson.john` — SPN: CIFS/MSSQL/HTTP
- `shimizu.hana` — SPN: CIFS/MSSQL/HTTP
- `he.lan2` — SPN: CIFS/MSSQL/HTTP
- `luo.lan2` — SPN: CIFS/MSSQL/HTTP
- `svc.sharepoint` — SPN: HTTP/sharepoint.aza-me.cc
- `svc.app.crm` — SPN: HTTP/crm.aza-me.cc

---

### 27. DISABLED_ACCOUNT_IN_ADMIN_GROUP (High) — ✅ 1 instance
**Description :** Disabled user accounts still present in privileged groups. Should be removed immediately.
**Comptes trouvés :**
- `jones.john` — dans Domain Admins et Administrators

---

### 28. EXPIRED_ACCOUNT_IN_ADMIN_GROUP (High) — ✅ 3 instances
**Description :** Expired user accounts still present in privileged groups. Should be removed immediately.
**Comptes trouvés :**
- `yamamoto.sota` — Domain Admins, expiré 2026-01-30
- `banerjee.sanjay` — Domain Admins, expiré 2026-01-30
- `kato.mei` — Enterprise Admins, expiré 2025-12-31

---

### 29. SID_HISTORY (High) — ⚠️ 0 instance (non injectable)
**Description :** User accounts with sIDHistory attribute. Can be abused for privilege escalation.
**Résultat :** Non injectable — `sIDHistory` est protégé par AD et nécessite les outils ADMT (Active Directory Migration Tool) avec un trust inter-domaines. Toutes les tentatives (Set-ADUser, ADSI, S.DS.P, ldifde) échouent avec "Access is denied" ou "insufficient access rights".

---

### 30. NOT_IN_PROTECTED_USERS (High) — ✅ 23 instances
**Description :** Privileged accounts not in Protected Users group. Missing additional security protections.
**Comptes trouvés :** `Administrator`, `svc_n8n`, `yamamoto.sota`, `wilson.olivia`, `jackson.john`, `banerjee.sanjay`, `torres.pedro`, `shimizu.hana`, `he.lan2`, `luo.lan2`, `lopez.pedro`, `davis.juan`, `admin`, `administrator2`, `backup_admin`, `svc.sharepoint`, `svc.app.crm`, `brown.akira`, `yamaguchi.lei`, `verma.anita`, `garcia.chen`, `smith.isabella`, `ramirez.gabriela`

---

### 31. DOMAIN_ADMIN_IN_DESCRIPTION (High) — ✅ 33 instances
**Description :** User accounts with admin/privileged keywords in description field. Information disclosure.
**Exemples critiques :**
- `garcia.ricardo` — "Mot de passe temporaire: Admin123!" (credential leak!)
- `martin.sophia` — "Former Domain Admin - retired account"
- `desai.deepa` — "Former Domain Admin - retired account"
- `akter.karim` — "Former Domain Admin - retired account"
- `admin` — "Compte admin generique"
- `administrator2` — "Doublon Administrator"
- `backup_admin` — "Admin de backup non documente"
- + 26 autres avec "Administrator" dans le titre de poste

---

### 32. BACKUP_OPERATORS_MEMBER (High) — ✅ 20 instances
**Description :** Users in Backup Operators group. Can backup/restore files and bypass ACLs.
**Membres :** wilson.amelia, lee.john2, thompson.olivia, oliveira.maria, inoue.mio, perez.sofia, hussain.faisal, thompson.zara, desai.amit, luo.lan2, he.lan2, thompson.naomi, shimizu.hana, elhadi.ali2, demir.hussein, anderson.robert, jackson.john, wilson.olivia, nakamura.naomi, jackson.akira

---

### 33. ACCOUNT_OPERATORS_MEMBER (High) — ✅ 20 instances
**Description :** Users in Account Operators group. Can create/modify user accounts.
**Membres :** wilson.amelia, lee.john2, thompson.olivia, oliveira.maria, martinez.michael, thompson.zara, desai.amit, luo.lan2, he.lan2, thompson.naomi, shimizu.hana, alsalem.mohamed, demir.hussein, lima.rafael, anderson.robert, alrashid.hassan, jackson.john, wilson.olivia, nakamura.naomi, jackson.akira

---

### 34. SERVER_OPERATORS_MEMBER (High) — ✅ 11 instances
**Description :** Users in Server Operators group. Can manage domain controllers.
**Membres :** wilson.amelia, lee.john2, nwosu.onyeka, luo.lan2, he.lan2, shimizu.hana, demir.hussein, jackson.john, wilson.olivia, nakamura.naomi, jackson.akira

---

### 35. PRINT_OPERATORS_MEMBER (High) — ✅ 19 instances
**Description :** Users in Print Operators group. Can load drivers and manage printers on DCs.
**Membres :** wilson.amelia, lee.john2, thompson.olivia, oliveira.maria, torres.jose, thompson.zara, desai.amit, luo.lan2, he.lan2, thompson.naomi, shimizu.hana, demir.hussein, anderson.robert, miller.charlotte, elamin.amira, jackson.john, wilson.olivia, nakamura.naomi, jackson.akira

---

### 36. LOCKED_ACCOUNT_ADMIN (High) — ✅ 1 instance
**Description :** Admin accounts locked out. May indicate password spray attacks or compromised credential attempts.
**Résultat :** 1 compte admin verrouillé.

---

### 37. PRIVILEGED_ACCOUNT_SPN (High) — ✅ 22 instances
**Description :** Privileged accounts (adminCount=1) with SPNs. Vulnerable to Kerberoasting attacks.
**Comptes trouvés :** jackson.akira, nakamura.naomi, wilson.olivia, jackson.john, anderson.robert, alsalem.maryam, demir.hussein, shimizu.hana, singh.james, thompson.naomi, desai.luis, he.lan2, luo.lan2, desai.amit, thompson.zara, alrashid.ali, oliveira.maria, thompson.olivia, lee.john2, wilson.amelia, svc.sharepoint, svc.app.crm

---

### 38. SERVICE_ACCOUNT_INTERACTIVE (High) — ✅ 4 instances (injecté)
**Description :** Service accounts allowing or using interactive logon. Should be restricted to service-only authentication.
**Comptes trouvés :**
- `svc_interactive_bkp` — SPN: HOST/backup-int.aza-me.cc, LogonCount: 1 (créé + logon simulé)
- `svc_interactive_mon` — SPN: HTTP/monitor-int.aza-me.cc, LogonCount: 1 (créé + logon simulé)
- `svc.exchange.mailbox` — LogonCount: 1
- `svc.bi.reporting` — LogonCount: 1

---

### 39. SERVICE_ACCOUNT_NO_PREAUTH (High) — ✅ 22 instances
**Description :** Service accounts with 'Do not require Kerberos pre-authentication'. Attackers can request AS-REP tickets and crack offline.
**Comptes trouvés :** jackson.akira, nakamura.naomi, wilson.olivia, jackson.john, anderson.robert, alsalem.maryam, demir.hussein, shimizu.hana, singh.james, thompson.naomi, desai.luis, he.lan2, luo.lan2, desai.amit, thompson.zara, alrashid.ali, oliveira.maria, thompson.olivia, lee.john2, wilson.amelia, svc.exchange.mailbox, svc.bi.reporting

---

### 40. SERVICE_ACCOUNT_OLD_PASSWORD (High) — ✅ 2 instances
**Description :** Service accounts with passwords not changed in over 1 year. High-value targets.
**Comptes trouvés :**
- `svc.exchange.mailbox` — PasswordLastSet: null
- `svc.bi.reporting` — PasswordLastSet: null

---

### 41. STALE_ACCOUNT (High) — ✅ 10 instances (injecté)
**Description :** Enabled user accounts inactive for 180+ days. Stale accounts increase attack surface.
**Comptes trouvés (lastLogon simulé via manipulation horloge) :**
- `martin.sophia` — lastLogon: 2025-01-13 (400+ jours)
- `desai.deepa` — lastLogon: 2025-01-13 (400+ jours)
- `akter.karim` — lastLogon: 2025-01-13 (400+ jours)
- `test.user` — lastLogon: 2025-01-13 (400+ jours)
- `shared.admin` — lastLogon: 2025-01-13 (400+ jours)
- `demo.account` — lastLogon: 2025-08-01 (200+ jours)
- `generic.user` — lastLogon: 2025-08-01 (200+ jours)
- `shared.support` — lastLogon: 2025-08-01 (200+ jours)
- `temp.admin` — lastLogon: 2025-08-01 (200+ jours)
- `common.service` — lastLogon: 2025-08-01 (200+ jours)

---

### 42. INACTIVE_365_DAYS (Medium) — ✅ 5 instances (injecté)
**Description :** User accounts inactive for 365+ days. Should be disabled or deleted.
**Comptes trouvés (lastLogon simulé via manipulation horloge) :**
- `martin.sophia` — lastLogon: 2025-01-13 (400+ jours)
- `desai.deepa` — lastLogon: 2025-01-13 (400+ jours)
- `akter.karim` — lastLogon: 2025-01-13 (400+ jours)
- `test.user` — lastLogon: 2025-01-13 (400+ jours)
- `shared.admin` — lastLogon: 2025-01-13 (400+ jours)

---

### 43. NEVER_LOGGED_ON (Medium) — ✅ 533 instances
**Description :** Enabled user accounts that have never logged into the domain. May indicate orphaned accounts.
**Résultat :** 533 comptes activés n'ont jamais ouvert de session (la majorité des comptes du lab).

---

### 44. ACCOUNT_EXPIRE_SOON (Medium) — ✅ 1 instance
**Description :** User accounts set to expire within 30 days. Review if intentional.
**Comptes trouvés :**
- `he.lan2` — expire le 2026-03-15

---

### 45. TEST_ACCOUNT (Medium) — ✅ 3 instances
**Description :** User accounts with test/demo/temp naming. Should be removed from production.
**Comptes trouvés :** `test.user`, `demo.account`, `temp.admin`

---

### 46. SHARED_ACCOUNT (Medium) — ✅ 4 instances
**Description :** User accounts with shared/generic naming. Prevents proper accountability.
**Comptes trouvés :** `shared.admin`, `common.service`, `generic.user`, `shared.support`

---

### 47. SMARTCARD_NOT_REQUIRED (Medium) — ✅ 55 instances
**Description :** Privileged accounts without smartcard requirement. High-value accounts should require strong auth.
**Résultat :** 55 comptes avec adminCount=1 sans exigence de smartcard.

---

### 48. PRIMARYGROUPID_SPOOFING (Medium) — ✅ 1 instance
**Description :** Accounts with non-standard primaryGroupID. Can be used to hide group membership.
**Comptes trouvés :**
- `Guest` — primaryGroupID: 514 (Domain Guests, comportement normal pour Guest)

---

### 49. SERVICE_ACCOUNT_WITH_SPN (Medium) — ✅ 33 instances
**Description :** User accounts with SPN configured. Targets for Kerberoasting attacks.
**Comptes trouvés :** jackson.akira, nakamura.naomi, wilson.olivia, jackson.john, anderson.robert, alsalem.maryam, demir.hussein, shimizu.hana, singh.james, thompson.naomi, desai.luis, he.lan2, luo.lan2, desai.amit, thompson.zara, alrashid.ali, oliveira.maria, thompson.olivia, lee.john2, wilson.amelia, svc.exchange.mailbox, svc.app.crm, martin.james, perez.maria, svc.bi.reporting, svc.sharepoint, svc.iis.web, ma.xiao, perez.valentina, svc.sql.prod, anderson.charlotte, cruz.rosa, zhang.ying

---

### 50. SERVICE_ACCOUNT_WEAK_ENCRYPTION (Medium) — ✅ 3 instances
**Description :** Service accounts using only DES/RC4 without AES. Makes offline cracking easier.
**Comptes trouvés :**
- `he.lan2` — encType: 0 (aucun type défini)
- `svc.sql.prod` — encType: 7 (DES+RC4 seulement)
- `svc.app.crm` — encType: 7 (DES+RC4 seulement)

---

### 51. ADMIN_COUNT_ORPHANED (Medium) — ✅ 24 instances
**Description :** adminCount=1 but not in any privileged group. Residual privileges or SDProp protection.
**Comptes trouvés :** elamin.amira, miller.charlotte, anderson.robert, lima.rafael, alsalem.maryam, alsalem.mohamed, moore.sophia, elhadi.ali2, miller.mio, singh.james, thompson.naomi, desai.luis, desai.amit, thompson.zara, torres.jose, reyes.alejandro, alrashid.ali, nwosu.onyeka, thomas.john, perez.sofia, inoue.mio, martinez.michael, oliveira.maria, thompson.olivia

---

### 52. ADMIN_NO_SMARTCARD (Medium) — ✅ 55 instances
**Description :** Privileged accounts authenticating with passwords instead of smartcards.
**Résultat :** 55 comptes admin sans exigence de smartcard (identique à #47).

---

### 53. DANGEROUS_BUILTIN_MEMBERSHIP (Medium) — ✅ 4 instances
**Description :** User accounts in overlooked but dangerous built-in groups. May allow privilege escalation.
**Comptes trouvés :**
- `sahin.aisha` — Remote Desktop Users
- `alibrahim.sara` — Remote Desktop Users
- `elsayed.hassan` — Remote Desktop Users
- `Administrator` — Remote Desktop Users

---

### 54. SERVICE_ACCOUNT_NAMING (Low) — ✅ 5 instances
**Description :** Accounts matching service naming patterns (svc_, _svc, service, etc.) without SPN.
**Comptes trouvés :** `svc_n8n`, `svc_sql`, `svc_backup`, `svc.backup.veeam`, `svc.monitoring.scom`

---

### 55. ADMIN_LOGON_COUNT_LOW (Low) — ✅ 53 instances
**Description :** Admin accounts (adminCount=1) with fewer than 5 logons. May indicate unused privileged accounts.
**Résultat :** 53 comptes admin avec 0 connexions (la plupart n'ont jamais été utilisés).
