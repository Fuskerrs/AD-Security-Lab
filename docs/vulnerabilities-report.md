# Rapport des vulnérabilités présentes dans l'AD GlobalCorp

**Date:** 2026-01-30 17:43:31
**Domaine:** aza-me.cc
**Total vulnérabilités:** 470 instances

---

## Résumé par sévérité

| Sévérité | Count | Pourcentage |
|----------|-------|-------------|
| **Critical** | 115 | 24.5% |
| **High** | 141 | 30.0% |
| **Medium** | 168 | 35.7% |
| **Low** | 45 | 9.6% |

---

## Top 20 vulnérabilités les plus fréquentes

| Rang | Type | Count | Description |
|------|------|-------|-------------|
| 1 | Ultra_Vulnerable_User | 20 | Utilisateurs avec 10-30 vulnérabilités cumulées |
| 2 | COMPUTER_NO_BITLOCKER | 18 | Ordinateurs sans chiffrement BitLocker |
| 3 | Computer_Stale_Inactive | 17 | Ordinateurs inactifs depuis longtemps |
| 4 | Computer_Old_Password | 17 | Mots de passe machine très anciens |
| 5 | Computer_No_LAPS | 16 | Ordinateurs sans LAPS déployé |
| 6 | Computer_Pre_Created | 15 | Comptes machines pré-créés |
| 7 | COMPUTER_LEGACY_PROTOCOL_SMBV1 | 15 | SMBv1 activé (EternalBlue) |
| 8 | Computer_With_SPNs | 12 | Ordinateurs avec SPNs non standard |
| 9 | Computer_SMB_Signing_Disabled | 11 | Signature SMB désactivée |
| 10 | StaleAccount | 10 | Comptes utilisateurs inactifs |
| 11 | Computer_Weak_Encryption | 10 | Chiffrement faible (RC4/DES) |
| 12 | Computer_Disabled_Not_Deleted | 9 | Ordinateurs désactivés non supprimés |
| 13 | SERVICE_ACCOUNT_NAMING | 8 | Comptes de service avec nommage suspect |
| 14 | PasswordNeverExpires | 8 | Mots de passe n'expirant jamais |
| 15 | Computer_Local_Admin_Mapping | 8 | Mapping admin local dangereux |
| 16 | ACL_ForceChangePassword | 8 | Droits de forcer le changement de MDP |
| 17 | Computer_Wrong_OU | 7 | Ordinateurs dans mauvaise OU |
| 18 | SERVICE_ACCOUNT_WITH_SPN | 6 | Comptes service avec SPN (Kerberoastable) |
| 19 | Computer_Weak_LAPS | 6 | LAPS avec config faible |
| 20 | Computer_Unconstrained_Delegation | 6 | Délégation non contrainte |

---

## Vulnérabilités par catégorie

### Passwords (14 types détectés)
- PASSWORD_NOT_REQUIRED ✅
- REVERSIBLE_ENCRYPTION ✅ (ReversibleEncryption)
- PASSWORD_NEVER_EXPIRES ✅ (PasswordNeverExpires)
- PASSWORD_IN_DESCRIPTION ✅ (PasswordInDescription)
- USER_CANNOT_CHANGE_PASSWORD ✅ (User_Cannot_Change_Password)
- UNIX_USER_PASSWORD ✅ (UnixUserPassword_Clear)
- PASSWORD_COMMON_PATTERNS ✅ (Test_Account, Shared_Account, SuspiciousAccountName)
- EMPTY_PASSWORD ✅ (Empty_Password)
- WEAK_PASSWORD_POLICY ✅

### Kerberos (12 types détectés)
- ASREP_ROASTING_RISK ✅ (ASREPRoastable)
- UNCONSTRAINED_DELEGATION ✅ (UnconstrainedDelegation)
- KERBEROASTING_RISK ✅ (Kerberoastable, Kerberoastable_WeakPassword)
- CONSTRAINED_DELEGATION ✅ (ConstrainedDelegation)
- WEAK_ENCRYPTION_FLAG ✅ (Weak_Encryption_Flag)
- WEAK_ENCRYPTION_RC4 ✅ (Weak_Encryption_RC4_With_AES)
- KERBEROS_TICKET_LIFETIME_LONG ✅ (KERBEROS_TICKET_LIFETIME_LONG)

### Accounts (25 types détectés)
- SENSITIVE_DELEGATION ✅ (Sensitive_Delegation)
- DISABLED_ACCOUNT_IN_ADMIN_GROUP ✅ (Disabled_Account_In_Admin_Group, DisabledAccountInPrivGroup)
- EXPIRED_ACCOUNT_IN_ADMIN_GROUP ✅ (Expired_Account_In_Admin_Group)
- SID_HISTORY ✅ (SIDHistory)
- NOT_IN_PROTECTED_USERS ✅ (Not_In_Protected_Users, NotInProtectedUsers)
- DOMAIN_ADMIN_IN_DESCRIPTION ✅ (Domain_Admin_In_Description)
- BACKUP_OPERATORS_MEMBER ✅ (Backup_Operators_Member)
- ACCOUNT_OPERATORS_MEMBER ✅ (Account_Operators_Member)
- SERVER_OPERATORS_MEMBER ✅ (Server_Operators_Member)
- PRINT_OPERATORS_MEMBER ✅ (Print_Operators_Member)
- INACTIVE_365_DAYS ✅ (StaleAccount)
- NEVER_LOGGED_ON ✅ (COMPUTER_NEVER_LOGGED_ON pour computers)
- TEST_ACCOUNT ✅ (Test_Account)
- SHARED_ACCOUNT ✅ (Shared_Account)
- SMARTCARD_NOT_REQUIRED ✅ (Smartcard_Not_Required)
- SERVICE_ACCOUNT_WITH_SPN ✅ (SERVICE_ACCOUNT_WITH_SPN)
- SERVICE_ACCOUNT_NAMING ✅ (SERVICE_ACCOUNT_NAMING)
- SERVICE_ACCOUNT_OLD_PASSWORD ✅ (SERVICE_ACCOUNT_OLD_PASSWORD)
- SERVICE_ACCOUNT_PRIVILEGED ✅ (SERVICE_ACCOUNT_PRIVILEGED)
- SERVICE_ACCOUNT_NO_PREAUTH ✅ (SERVICE_ACCOUNT_NO_PREAUTH)
- SERVICE_ACCOUNT_WEAK_ENCRYPTION ✅ (SERVICE_ACCOUNT_WEAK_ENCRYPTION)
- ADMIN_COUNT_ORPHANED ✅ (AdminCount_Orphaned)
- SERVICE_ACCOUNT_INTERACTIVE ✅ (SERVICE_ACCOUNT_INTERACTIVE)
- REPLICA_DIRECTORY_CHANGES ✅ (DCSync_Rights)

### Groups (11 types détectés)
- DNS_ADMINS_MEMBER ✅ (DNS_Admins_Member)
- PRE_WINDOWS_2000_ACCESS ✅ (Computer_Pre_Win2000)
- OVERSIZED_GROUP_CRITICAL ✅ (Oversized_Group_Critical)
- OVERSIZED_GROUP_HIGH ✅ (Oversized_Group_High)
- DANGEROUS_GROUP_NESTING ✅ (Dangerous_Group_Nesting, NestedGroupPath)
- BUILTIN_MODIFIED ✅ (BUILTIN_MODIFIED)
- GROUP_AUTHENTICATED_USERS_PRIVILEGED ✅ (Authenticated_Users_In_ACLs)
- GROUP_PROTECTED_USERS_EMPTY ✅ (GROUP_PROTECTED_USERS_EMPTY)
- EVERYONE_IN_ACL ✅ (Everyone_In_ACL, Everyone_In_ACLs)
- GPO_MODIFY_RIGHTS ✅ (GPO_Creator_Owners_Member)

### Computers (27 types détectés)
- COMPUTER_CONSTRAINED_DELEGATION ✅ (ConstrainedDelegation)
- COMPUTER_RBCD ✅ (Computer_RBCD)
- COMPUTER_IN_ADMIN_GROUP ✅ (Computer_In_Admin_Group)
- COMPUTER_DCSYNC_RIGHTS ✅ (DCSync_Rights)
- COMPUTER_UNCONSTRAINED_DELEGATION ✅ (Computer_Unconstrained_Delegation)
- COMPUTER_STALE_INACTIVE ✅ (Computer_Stale_Inactive)
- COMPUTER_PASSWORD_OLD ✅ (Computer_Old_Password)
- COMPUTER_WITH_SPNS ✅ (Computer_With_SPNs)
- COMPUTER_NO_LAPS ✅ (Computer_No_LAPS)
- COMPUTER_ACL_ABUSE ✅ (Computer_ACL_GenericAll)
- COMPUTER_DISABLED_NOT_DELETED ✅ (Computer_Disabled_Not_Deleted)
- COMPUTER_WRONG_OU ✅ (Computer_Wrong_OU)
- COMPUTER_WEAK_ENCRYPTION ✅ (Computer_Weak_Encryption)
- COMPUTER_DESCRIPTION_SENSITIVE ✅ (Computer_Sensitive_Description)
- COMPUTER_PRE_WINDOWS_2000 ✅ (Computer_Pre_Win2000)
- COMPUTER_SMB_SIGNING_DISABLED ✅ (Computer_SMB_Signing_Disabled)
- COMPUTER_OS_OBSOLETE_XP ✅ (COMPUTER_OS_OBSOLETE_XP)
- COMPUTER_OS_OBSOLETE_2003 ✅ (COMPUTER_OS_OBSOLETE_2003)
- COMPUTER_OS_OBSOLETE_2008 ✅ (COMPUTER_OS_OBSOLETE_2008)
- COMPUTER_OS_OBSOLETE_VISTA ✅ (COMPUTER_OS_OBSOLETE_VISTA)
- COMPUTER_NEVER_LOGGED_ON ✅ (COMPUTER_NEVER_LOGGED_ON)
- COMPUTER_DUPLICATE_SPN ✅ (COMPUTER_DUPLICATE_SPN)
- SERVER_NO_ADMIN_GROUP ✅ (SERVER_NO_ADMIN_GROUP)
- COMPUTER_NO_BITLOCKER ✅ (COMPUTER_NO_BITLOCKER)
- COMPUTER_LEGACY_PROTOCOL ✅ (COMPUTER_LEGACY_PROTOCOL_SMBV1)

### Advanced (22 types détectés)
- SHADOW_CREDENTIALS ✅ (Shadow_Credentials)
- RBCD_ABUSE ✅ (Computer_RBCD)
- LAPS_PASSWORD_READABLE ✅ (LAPS_PasswordRead)
- REPLICATION_RIGHTS ✅ (DCSync_Rights)
- DUPLICATE_SPN ✅ (Duplicate_SPN)
- WEAK_PASSWORD_POLICY ✅ (WEAK_PASSWORD_POLICY)
- MACHINE_ACCOUNT_QUOTA_HIGH ❌ (non injecté)
- DELEGATION_PRIVILEGE ✅ (SeEnableDelegationPrivilege)
- FOREIGN_SECURITY_PRINCIPALS ✅ (Foreign_Security_Principals)
- NTLM_RELAY_OPPORTUNITY ✅ (NTLM_RELAY_OPPORTUNITY)
- LAPS_PASSWORD_LEAKED ✅ (LAPS_Password_Leaked)
- DANGEROUS_LOGON_SCRIPTS ✅ (Dangerous_Logon_Script)
- ANONYMOUS_LDAP_ACCESS ✅ (ANONYMOUS_LDAP_ACCESS)
- RECYCLE_BIN_DISABLED ✅ (RECYCLE_BIN_DISABLED)
- LDAP_CHANNEL_BINDING_DISABLED ✅ (LDAP_CHANNEL_BINDING_DISABLED)
- SMB_V1_ENABLED ✅ (SMB_V1_ENABLED)
- AUDIT_POLICY_WEAK ✅ (AUDIT_POLICY_WEAK)
- POWERSHELL_LOGGING_DISABLED ✅ (POWERSHELL_LOGGING_DISABLED)
- ADMIN_SD_HOLDER_MODIFIED ✅ (ADMIN_SD_HOLDER_MODIFIED)

### Permissions (14 types détectés)
- ACL_GENERICALL ✅ (ACL_GenericAll_DA)
- ACL_WRITEDACL ✅ (ACL_WriteDACL_OU, ACL_WriteDACL_SensitiveGroup)
- ACL_WRITEOWNER ✅ (ACL_WriteOwner_SensitiveGroup)
- ACL_GENERICWRITE ✅ (ACL_GenericWrite_User, ACL_GenericWrite_SensitiveGroup)
- ACL_FORCECHANGEPASSWORD ✅ (ACL_ForceChangePassword)
- EVERYONE_IN_ACL ✅ (Everyone_In_ACL)
- WRITESPN_ABUSE ✅ (WriteSPN_Abuse)
- GPO_LINK_POISONING ✅ (GPO_LinkPoisoning)
- ADMINSDHOLDER_BACKDOOR ✅ (AdminSDHolder_Backdoor)
- ACL_ADD_MEMBER ✅ (ACL_AddMember)
- ACL_DS_REPLICATION_GET_CHANGES ✅ (ACL_DCSync)
- ORPHANED_ACES ✅ (Orphaned_ACEs)

### ADCS (11 types détectés)
- ESC1_VULNERABLE_TEMPLATE ✅ (ESC1_Vulnerable_Certificate_Template)
- ESC2_ANY_PURPOSE ✅ (ESC2_Any_Purpose_EKU)
- ESC3_ENROLLMENT_AGENT ✅ (ESC3_Enrollment_Agent)
- ESC4_VULNERABLE_TEMPLATE_ACL ✅ (ESC4_Vulnerable_Template_ACL)
- ESC5_PKI_OBJECT_ACL ✅ (ESC5_PKI_Object_ACL)
- ESC7_CA_VULNERABLE_ACL ✅ (ESC7_CA_Vulnerable_ACL)
- ESC8_HTTP_ENROLLMENT ✅ (ESC8_HTTP_Enrollment)
- ESC9_NO_SECURITY_EXTENSION ✅ (ESC9_No_Security_Extension)
- ESC10_WEAK_CERTIFICATE_MAPPING ✅ (ESC10_Weak_Certificate_Mapping)
- ESC11_ICERT_REQUEST_ENFORCEMENT ✅ (ESC11_ICERT_Request_Enforcement)

### GPO (5 types détectés)
- GPO_LAPS_NOT_DEPLOYED ✅ (GPO_LAPS_NOT_DEPLOYED)
- GPO_NO_SECURITY_FILTERING ✅ (GPO_NO_SECURITY_FILTERING)
- GPO_AUTHENTICATED_USERS_APPLY ✅ (GPO_AUTHENTICATED_USERS_APPLY)
- GPO_PASSWORD_IN_SYSVOL ✅ (GPO_Password_in_SYSVOL)

### Attack Paths (7 types détectés)
- PATH_ASREP_TO_ADMIN ✅ (PATH_ASREP_TO_ADMIN)
- PATH_DELEGATION_CHAIN ✅ (PATH_DELEGATION_CHAIN)
- PATH_NESTED_ADMIN ✅ (PATH_NESTED_ADMIN)
- PATH_SERVICE_TO_DA ✅ (PATH_SERVICE_TO_DA)
- PATH_GPO_TO_DA ✅ (PATH_GPO_TO_DA)
- PATH_CERTIFICATE_ESC ✅ (PATH_CERTIFICATE_ESC)
- PATH_TRUST_LATERAL ✅ (PATH_TRUST_LATERAL)

---

## Couverture de détection de l'outil

**Total types dans AD:** 138 types uniques
**Total catalogue outil:** 216 types de détection
**Couverture:** ~64% (138/216)

### Types vulnérabilités détectables manquants dans l'AD

Les vulnérabilités suivantes sont détectables par l'outil mais **absentes** de l'AD actuel :

#### Passwords
- PASSWORD_VERY_OLD
- PASSWORD_DICT_ATTACK_RISK
- PASSWORD_CLEARTEXT_STORAGE

#### Kerberos
- GOLDEN_TICKET_RISK
- WEAK_ENCRYPTION_DES
- KERBEROS_AES_DISABLED
- KERBEROS_RC4_FALLBACK
- KERBEROS_RENEWABLE_TICKET_LONG

#### Accounts
- ACCOUNT_EXPIRE_SOON
- ADMIN_LOGON_COUNT_LOW
- PRIMARYGROUPID_SPOOFING
- ADMIN_NO_SMARTCARD
- PRIVILEGED_ACCOUNT_SPN
- DANGEROUS_BUILTIN_MEMBERSHIP
- LOCKED_ACCOUNT_ADMIN

#### Groups
- GROUP_EMPTY_PRIVILEGED
- GROUP_CIRCULAR_NESTING
- GROUP_EXCESSIVE_MEMBERS
- GROUP_EVERYONE_IN_PRIVILEGED

#### Computers
- COMPUTER_ADMIN_COUNT
- DC_NOT_IN_DC_OU (non injecté)
- WORKSTATION_IN_SERVER_OU (non injecté)

#### Advanced
- LAPS_NOT_DEPLOYED (non injecté)
- LAPS_LEGACY_ATTRIBUTE (non injecté)
- WEAK_KERBEROS_POLICY
- MACHINE_ACCOUNT_QUOTA_ABUSE
- ADCS_WEAK_PERMISSIONS
- LDAP_SIGNING_DISABLED (non injecté)
- DS_HEURISTICS_MODIFIED (non injecté)
- EXCHANGE_PRIV_ESC_PATH (non injecté)

#### GPO
- GPO_DANGEROUS_PERMISSIONS
- GPO_WEAK_PASSWORD_POLICY (non injecté)
- GPO_UNLINKED (non injecté)
- GPO_DISABLED_BUT_LINKED (non injecté)
- GPO_ORPHANED (non injecté)

#### Trusts (0 détectés - domaine single forest)
- Aucune vulnérabilité de trust présente

#### Attack Paths
- PATH_KERBEROASTING_TO_DA (non injecté)
- PATH_ACL_TO_DA (non injecté)
- PATH_COMPUTER_TAKEOVER (non injecté)

#### Monitoring (0 détectés)
- Aucune vulnérabilité de monitoring testée

#### Compliance (0 détectés)
- Aucune vulnérabilité de compliance testée

#### Network (0 détectés)
- Aucune vulnérabilité réseau testée

---

## Recommandations pour améliorer le lab

Pour augmenter la couverture de test de ton outil :

1. **Ajouter des vulnérabilités manquantes** dans le script de peuplement
2. **Créer des trusts** entre domaines/forêts pour tester les vulns Trust
3. **Configurer des policies GPO** spécifiques pour test GPO
4. **Simuler des problèmes de monitoring** (logs, audit)
5. **Ajouter des checks de compliance** (ANSSI, NIST, CIS, etc.)
6. **Créer des problèmes réseau AD** (DNS, NTP, réplication)

---

**Généré le:** 2026-01-30
**Script:** Populate-AD-GlobalCorp.ps1
