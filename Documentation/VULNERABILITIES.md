# Vulnérabilités injectées dans l'AD GlobalCorp

**Date d'injection:** 2026-01-30 17:43
**Script:** Populate-AD-GlobalCorp.ps1
**Rapport:** GlobalCorp_Vulnerabilities_20260130_174331.csv

---

## 📊 Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| **Total instances** | 470 |
| **Types uniques** | 138 |
| **Utilisateurs affectés** | 541 |
| **Ordinateurs affectés** | 79 |
| **Groupes affectés** | 151 |

---

## 📋 Liste complète des 138 types injectés

### Top 20 (par nombre d'instances)

| # | Type | Instances | Vérifié dans AD | Status |
|---|------|-----------|-----------------|--------|
| 1 | **Ultra_Vulnerable_User** | 20 | ❓ Non | À vérifier |
| 2 | **COMPUTER_NO_BITLOCKER** | 18 | ⚠️ Oui | Non vérifiable (pas dans AD) |
| 3 | **Computer_Stale_Inactive** | 17 | ✅ Oui | **78 trouvés** (4.6x plus!) |
| 4 | **Computer_Old_Password** | 17 | ❌ Oui | **0 trouvé** (bug injection) |
| 5 | **Computer_No_LAPS** | 16 | ⚠️ Oui | Erreur (LAPS pas déployé) |
| 6 | **Computer_Pre_Created** | 15 | ❓ Non | À vérifier |
| 7 | **COMPUTER_LEGACY_PROTOCOL_SMBV1** | 15 | ❓ Non | À vérifier |
| 8 | **Computer_With_SPNs** | 12 | ❓ Non | À vérifier |
| 9 | **Computer_SMB_Signing_Disabled** | 11 | ❓ Non | À vérifier |
| 10 | **Computer_Weak_Encryption** | 10 | ❓ Non | À vérifier |
| 11 | **StaleAccount** | 10 | ❓ Non | À vérifier |
| 12 | **Computer_Disabled_Not_Deleted** | 9 | ✅ Oui | **9 trouvés** (match) |
| 13 | **SERVICE_ACCOUNT_NAMING** | 8 | ❓ Non | À vérifier |
| 14 | **PasswordNeverExpires** | 8 | ✅ Oui | **38 trouvés** (4.7x plus!) |
| 15 | **Computer_Local_Admin_Mapping** | 8 | ❓ Non | À vérifier |
| 16 | **ACL_ForceChangePassword** | 8 | ❓ Non | À vérifier |
| 17 | **Computer_Wrong_OU** | 7 | ❓ Non | À vérifier |
| 18 | **SERVICE_ACCOUNT_WITH_SPN** | 6 | ❓ Non | À vérifier |
| 19 | **Computer_Weak_LAPS** | 6 | ❓ Non | À vérifier |
| 20 | **Computer_Unconstrained_Delegation** | 6 | ✅ Oui | **7 trouvés** (match) |

---

## ✅ Vulnérabilités VÉRIFIÉES dans l'AD (15 types)

| Type | Injecté | Trouvé | Ratio | Détecté v1.1.4 |
|------|---------|--------|-------|----------------|
| **PasswordNeverExpires** | 8 | ✅ **38** | 4.7x | ❌ **BUG** |
| **Computer_Stale_Inactive** | 17 | ✅ **78** | 4.6x | ❌ **BUG** |
| **Computer_Never_Logged_On** | 3 | ✅ **78** | 26x | ✅ Oui |
| **Kerberoastable** | 3 | ✅ **34** | 11x | ❓ |
| **AsRepRoastable** | 3 | ✅ **25** | 8.3x | ❓ |
| **ConstrainedDelegation** | 1 | ✅ **17** | 17x | ✅ Oui |
| **UnconstrainedDelegation** | 1 | ✅ **7** | 7x | ✅ Oui |
| **Computer_Sensitive_Description** | 6 | ✅ **16** | 2.7x | ❌ Non |
| **Computer_Disabled_Not_Deleted** | 9 | ✅ **9** | 1x | ❌ Non |
| **GPO_Password_In_SYSVOL** | 1 | ✅ **1** | 1x | ❌ **BUG** |
| **Computer_Duplicate_SPN** | 1 | ❌ **0** | 0x | ❌ |
| **Computer_Old_Password** | 17 | ❌ **0** | 0x | ❌ |
| **Computer_Pre_Win2000** | 1 | ❌ **0** | 0x | ❌ |
| **Computer_No_Bitlocker** | 18 | ⚠️ **79** | N/A | ✅ Oui |
| **Computer_No_LAPS** | 16 | ⚠️ **Erreur** | N/A | ✅ Oui |

### 🚨 Bugs critiques confirmés

**3 vulnérabilités EXISTENT dans l'AD mais NON détectées par v1.1.4:**

1. **PASSWORD_NEVER_EXPIRES** - 38 utilisateurs dans l'AD, 0 détecté
2. **GPO_PASSWORD_IN_SYSVOL** - 1 fichier dans l'AD, 0 détecté
3. **COMPUTER_STALE_INACTIVE** - 78 ordinateurs dans l'AD, 0 détecté

---

## 📝 Liste complète (138 types)

### ACL/Permissions (11 types, 48 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| ACL_ForceChangePassword | 8 | ✅ Oui |
| ACL_WriteDACL_OU | 5 | ❌ Non |
| ACL_GenericWrite_User | 5 | ❌ Non |
| ACL_AddMember | 5 | ❌ Non |
| ACL_WriteOwner_SensitiveGroup | 3 | ❌ Non |
| ACL_WriteDACL_SensitiveGroup | 3 | ❌ Non |
| ACL_GenericWrite_SensitiveGroup | 3 | ❌ Non |
| ACL_GenericAll_DA | 3 | ❌ Non |
| ACL_DCSync | 2 | ❌ Non |
| Orphaned_ACEs | 1 | ❌ Non |
| NestedGroupPath | 5 | ❌ Non |

### Computers (27 types, 187 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| COMPUTER_NO_BITLOCKER | 18 | ✅ Oui |
| Computer_Stale_Inactive | 17 | ❌ **BUG** |
| Computer_Old_Password | 17 | ❌ Non |
| Computer_No_LAPS | 16 | ✅ Oui |
| Computer_Pre_Created | 15 | ❌ Non |
| COMPUTER_LEGACY_PROTOCOL_SMBV1 | 15 | ❌ Non |
| Computer_With_SPNs | 12 | ✅ Oui |
| Computer_SMB_Signing_Disabled | 11 | ❌ Non |
| Computer_Weak_Encryption | 10 | ✅ Oui |
| Computer_Disabled_Not_Deleted | 9 | ❌ Non |
| Computer_Local_Admin_Mapping | 8 | ❌ Non |
| Computer_Wrong_OU | 7 | ✅ Oui |
| Computer_Weak_LAPS | 6 | ❌ Non |
| Computer_Unconstrained_Delegation | 6 | ✅ Oui |
| Computer_Sensitive_Description | 6 | ❌ Non |
| Computer_In_Admin_Group | 5 | ✅ Oui |
| COMPUTER_OS_OBSOLETE_XP | 4 | ✅ Oui |
| COMPUTER_OS_OBSOLETE_2003 | 3 | ✅ Oui |
| COMPUTER_NEVER_LOGGED_ON | 3 | ✅ Oui |
| Computer_RBCD | 3 | ❌ Non |
| COMPUTER_OS_OBSOLETE_VISTA | 2 | ✅ Oui |
| COMPUTER_OS_OBSOLETE_2008 | 2 | ✅ Oui |
| Computer_ACL_GenericAll | 2 | ❌ Non |
| COMPUTER_DUPLICATE_SPN | 1 | ❌ Non |
| Computer_Pre_Win2000 | 1 | ❌ Non |
| Duplicate_SPN | 1 | ❌ Non |

### Passwords (7 types, 23 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| PasswordNeverExpires | 8 | ❌ **BUG** |
| PasswordInDescription | 5 | ❌ Non |
| PasswordNotRequired | 2 | ❌ Non |
| UnixUserPassword_Clear | 2 | ❌ Non |
| ReversibleEncryption | 1 | ❌ Non |
| Empty_Password | 1 | ❌ Non |
| WEAK_PASSWORD_POLICY | 1 | ✅ Oui |

### Kerberos (6 types, 12 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| Kerberoastable | 3 | ❌ Non |
| Kerberoastable_WeakPassword | 3 | ❌ Non |
| ASREPRoastable | 3 | ❌ Non |
| UnconstrainedDelegation | 1 | ✅ Oui |
| ConstrainedDelegation | 1 | ✅ Oui |
| KERBEROS_TICKET_LIFETIME_LONG | 1 | ❌ Non |

### Accounts (22 types, 75 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| Ultra_Vulnerable_User | 20 | ❌ Non |
| StaleAccount | 10 | ❌ Non |
| Test_Account | 5 | ✅ Oui |
| SuspiciousAccountName | 5 | ❌ Non |
| Shared_Account | 5 | ✅ Oui |
| NotInProtectedUsers | 5 | ❌ Non |
| AdminCount_Orphaned | 5 | ❌ Non |
| User_Cannot_Change_Password | 4 | ❌ Non |
| Smartcard_Not_Required | 3 | ✅ Oui |
| Not_In_Protected_Users | 3 | ✅ Oui |
| Expired_Account_In_Admin_Group | 3 | ✅ Oui |
| Domain_Admin_In_Description | 3 | ✅ Oui |
| DisabledAccountInPrivGroup | 3 | ❌ Non |
| SIDHistory | 2 | ❌ Non |
| Sensitive_Delegation | 2 | ✅ Oui |
| SeEnableDelegationPrivilege | 2 | ❌ Non |
| SuspiciousSIDProperties | 1 | ❌ Non |
| Shadow_Credentials | 1 | ❌ Non |
| Foreign_Security_Principals | 1 | ❌ Non |
| Disabled_Account_In_Admin_Group | 1 | ✅ Oui |
| ADMIN_SD_HOLDER_MODIFIED | 1 | ❌ Non |
| AdminSDHolder_Backdoor | 1 | ✅ Oui |

### Service Accounts (7 types, 25 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| SERVICE_ACCOUNT_NAMING | 8 | ✅ Oui |
| SERVICE_ACCOUNT_WITH_SPN | 6 | ✅ Oui |
| SERVICE_ACCOUNT_OLD_PASSWORD | 3 | ✅ Oui |
| SERVICE_ACCOUNT_WEAK_ENCRYPTION | 2 | ✅ Oui |
| SERVICE_ACCOUNT_PRIVILEGED | 2 | ✅ Oui |
| SERVICE_ACCOUNT_NO_PREAUTH | 2 | ✅ Oui |
| SERVICE_ACCOUNT_INTERACTIVE | 2 | ✅ Oui |

### Groups (10 types, 18 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| Dangerous_Group_Nesting | 1 | ✅ Oui |
| Oversized_Group_High | 1 | ✅ Oui |
| Oversized_Group_Critical | 1 | ❌ Non |
| GROUP_PROTECTED_USERS_EMPTY | 1 | ✅ Oui |
| GPO_Creator_Owners_Member | 1 | ❌ Non |
| Account_Operators_Member | 1 | ✅ Oui |
| Backup_Operators_Member | 1 | ✅ Oui |
| DNS_Admins_Member | 2 | ✅ Oui |
| Print_Operators_Member | 1 | ✅ Oui |
| Server_Operators_Member | 1 | ✅ Oui |
| BUILTIN_MODIFIED | 1 | ✅ Oui |

### ADCS (10 types, 10 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| ESC1_Vulnerable_Certificate_Template | 1 | ❌ Non |
| ESC2_Any_Purpose_EKU | 1 | ❌ Non |
| ESC3_Enrollment_Agent | 1 | ✅ Oui |
| ESC4_Vulnerable_Template_ACL | 1 | ✅ Oui |
| ESC5_PKI_Object_ACL | 1 | ✅ Oui |
| ESC7_CA_Vulnerable_ACL | 1 | ✅ Oui |
| ESC8_HTTP_Enrollment | 1 | ✅ Oui |
| ESC9_No_Security_Extension | 1 | ✅ Oui |
| ESC10_Weak_Certificate_Mapping | 1 | ✅ Oui |
| ESC11_ICERT_Request_Enforcement | 1 | ✅ Oui |

### GPO (5 types, 6 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| GPO_Password_in_SYSVOL | 1 | ❌ **BUG** |
| GPO_LinkPoisoning | 2 | ❌ Non |
| GPO_LAPS_NOT_DEPLOYED | 1 | ✅ Oui |
| GPO_NO_SECURITY_FILTERING | 1 | ❌ Non |
| GPO_AUTHENTICATED_USERS_APPLY | 1 | ❌ Non |

### Attack Paths (7 types, 7 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| PATH_ASREP_TO_ADMIN | 1 | ❌ Non |
| PATH_CERTIFICATE_ESC | 1 | ❌ Non |
| PATH_DELEGATION_CHAIN | 1 | ❌ Non |
| PATH_GPO_TO_DA | 1 | ❌ Non |
| PATH_NESTED_ADMIN | 1 | ❌ Non |
| PATH_SERVICE_TO_DA | 1 | ❌ Non |
| PATH_TRUST_LATERAL | 1 | ❌ Non |

### Excessive Privileges (8 types, 17 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| ExcessivePrivileges_RDP | 3 | ❌ Non |
| ExcessivePrivileges_DA | 3 | ❌ Non |
| ExcessivePrivileges_PrintOps | 2 | ❌ Non |
| ExcessivePrivileges_DNS | 2 | ❌ Non |
| ExcessivePrivileges_BO | 2 | ❌ Non |
| ExcessivePrivileges_AO | 2 | ❌ Non |
| ExcessivePrivileges_SchemaAdmin | 1 | ❌ Non |
| ExcessivePrivileges_EnterpriseAdmin | 1 | ❌ Non |

### Advanced/Config (14 types, 22 instances)

| Type | Instances | Détecté v1.1.4 |
|------|-----------|----------------|
| Weak_Encryption_RC4_With_AES | 5 | ❌ Non |
| SERVER_NO_ADMIN_GROUP | 4 | ❌ Non |
| Weak_Encryption_Flag | 3 | ✅ Oui |
| LAPS_PasswordRead | 3 | ❌ Non |
| WriteSPN_Abuse | 2 | ✅ Oui |
| Everyone_In_ACLs | 2 | ❌ Non |
| DCSync_Rights | 2 | ❌ Non |
| Dangerous_Logon_Script | 2 | ❌ Non |
| SMB_V1_ENABLED | 1 | ❌ Non |
| RECYCLE_BIN_DISABLED | 1 | ✅ Oui |
| POWERSHELL_LOGGING_DISABLED | 1 | ❌ Non |
| NTLM_RELAY_OPPORTUNITY | 1 | ✅ Oui |
| LDAP_CHANNEL_BINDING_DISABLED | 1 | ❌ Non |
| LAPS_Password_Leaked | 1 | ❌ Non |
| Everyone_In_ACL | 1 | ✅ Oui |
| Authenticated_Users_In_ACLs | 1 | ❌ Non |
| AUDIT_POLICY_WEAK | 1 | ❌ Non |
| ANONYMOUS_LDAP_ACCESS | 1 | ❌ Non |

---

## 📊 Statistiques

### Par statut de détection v1.1.4

| Status | Count | % |
|--------|-------|---|
| ❌ Non détecté | 86 | 62.3% |
| ✅ Détecté | 49 | 35.5% |
| 🚨 Bug (dans AD mais non détecté) | 3 | 2.2% |

### Par statut de vérification dans AD

| Statut | Count | % |
|--------|-------|---|
| ❓ Non vérifié | 123 | 89.1% |
| ✅ Confirmé dans AD | 10 | 7.2% |
| ❌ NON dans AD (bug injection) | 3 | 2.2% |
| ⚠️ Inconnu/Erreur | 2 | 1.4% |

---

## 🎯 Prochaines étapes

### Urgent

1. ✅ **Corriger les 3 bugs critiques du collecteur**
   - PASSWORD_NEVER_EXPIRES
   - GPO_PASSWORD_IN_SYSVOL
   - COMPUTER_STALE_INACTIVE

2. ✅ **Fixer le script d'injection**
   - Computer_Old_Password (0/17 trouvé)
   - Computer_Duplicate_SPN (0/1 trouvé)
   - Computer_Pre_Win2000 (0/1 trouvé)

3. ✅ **Vérifier les 123 types restants** dans l'AD

### Moyen terme

4. ✅ Calculer le vrai taux de détection (seulement sur vulns confirmées)
5. ✅ Créer baseline AD (avant injection)
6. ✅ Tests automatisés de détection

---

**Dernière mise à jour:** 2026-01-30 22:40
**Source:** GlobalCorp_Vulnerabilities_20260130_174331.csv + vérification AD
**Fichiers:**
- `docs/audit/v1.1.4/detection-comparison.md` - Analyse détaillée v1.1.4
- `docs/audit/v1.1.4/vulns-really-in-ad.md` - Vérification complète
- `docs/audit/v1.1.4/vulns-not-in-ad.txt` - Liste des manquantes
