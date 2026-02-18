# Computers (30 vulnérabilités)

**Sévérité :** 8 Critical, 9 High, 10 Medium, 3 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 71 | COMPUTER_CONSTRAINED_DELEGATION | Critical | Computer Constrained Delegation | ✅ | **3** | Confirmé (injecté msDS-AllowedToDelegateTo) |
| 72 | COMPUTER_DCSYNC_RIGHTS | Critical | Computer DCSync Rights | ✅ | **2** | Confirmé (injecté DS-Replication ACEs) |
| 73 | COMPUTER_IN_ADMIN_GROUP | Critical | Computer in Admin Group | ✅ | **5** | Confirmé |
| 74 | COMPUTER_RBCD | Critical | Computer RBCD | ✅ | **3** | Confirmé |
| 75 | COMPUTER_UNCONSTRAINED_DELEGATION | Critical | Computer Unconstrained Delegation | ✅ | **6** | Confirmé |
| 76 | COMPUTER_OS_OBSOLETE_XP | Critical | Obsolete OS: Windows XP | ✅ | **4** | Confirmé |
| 77 | COMPUTER_OS_OBSOLETE_2003 | Critical | Obsolete OS: Windows Server 2003 | ✅ | **3** | Confirmé |
| 78 | COMPUTER_ACL_ABUSE | High | Computer ACL Abuse | ✅ | **19** | Confirmé (échantillon 19/20) |
| 79 | COMPUTER_STALE_INACTIVE | High | Computer Stale/Inactive | ❌ | 0 | Non trouvé (lab récent) |
| 80 | COMPUTER_PASSWORD_OLD | High | Computer Password Old | ✅ | **5** | Confirmé (injecté clock -400j) |
| 81 | COMPUTER_WITH_SPNS | High | Computer with SPNs | ✅ | **18** | Confirmé |
| 82 | COMPUTER_NO_LAPS | High | LAPS Not Deployed on Computer | ✅ | **18** | Confirmé |
| 83 | COMPUTER_NO_BITLOCKER | High | BitLocker Not Detected | ✅ | **71** | Confirmé |
| 84 | COMPUTER_OS_OBSOLETE_2008 | High | Obsolete OS: Windows Server 2008 | ✅ | **2** | Confirmé |
| 85 | COMPUTER_OS_OBSOLETE_VISTA | High | Obsolete OS: Windows Vista | ✅ | **2** | Confirmé |
| 86 | DC_NOT_IN_DC_OU | High | Domain Controller Not in DC OU | ✅ | **1** | Confirmé (injecté move DC-01) |
| 87 | COMPUTER_DISABLED_NOT_DELETED | Medium | Computer Disabled Not Deleted | ✅ | **24** | Confirmé |
| 88 | COMPUTER_WRONG_OU | Medium | Computer in Default Container | ✅ | **1** | Confirmé |
| 89 | COMPUTER_WEAK_ENCRYPTION | Medium | Computer Weak Encryption | ✅ | **10** | Confirmé |
| 90 | COMPUTER_DESCRIPTION_SENSITIVE | Medium | Computer Description Sensitive | ✅ | **12** | Confirmé |
| 91 | COMPUTER_PRE_WINDOWS_2000 | Medium | Pre-Windows 2000 Computer | ✅ | **1** | Confirmé (injecté flag) |
| 92 | COMPUTER_NEVER_LOGGED_ON | Medium | Computer Never Logged On | ✅ | **69** | Confirmé |
| 93 | COMPUTER_DUPLICATE_SPN | Medium | Duplicate SPNs Detected | ⚠️ | 0 | Non injectable (AD bloque nativement) |
| 94 | COMPUTER_LEGACY_PROTOCOL | Medium | Legacy Protocol Support | ❌ | 0 | Non trouvé (SMBv1 désactivé) |
| 95 | COMPUTER_PRE_CREATED | Medium | Computer Pre-Created (Staging) | ✅ | **2** | Confirmé (injecté staging accounts) |
| 96 | SERVER_NO_ADMIN_GROUP | Medium | Server Without Managed Admin Group | ❌ | 0 | Non vérifiable à distance |
| 97 | COMPUTER_ADMIN_COUNT | Low | Computer adminCount Set | ✅ | **5** | Confirmé |
| 98 | COMPUTER_SMB_SIGNING_DISABLED | Low | Computer SMB Signing Disabled | ❌ | 0 | Non trouvé (signing requis) |
| 99 | WORKSTATION_IN_SERVER_OU | Low | Workstation in Server OU | ✅ | **1** | Confirmé (injecté move WKS→Servers) |
| 100 | COMPUTER_OS_OBSOLETE_NT | Critical | Obsolete OS: Windows NT/2000 | ❓ | - | Non vérifié |

**Résumé : 24/30 confirmés (dont 7 injectés) | 1 non injectable | 4 non trouvés/vérifiables | 1 non vérifié**

---

## Détail des vulnérabilités

### 73. COMPUTER_IN_ADMIN_GROUP (Critical) — ✅ 5 instances
**Description :** Computer accounts in Domain Admins. Extremely dangerous — compromised computers gain full domain control.
**Comptes :** WKS-DHAKA-298, WKS-KOLKATA-1684, WKS-NEW-YORK-5736, WKS-MANILA-1584, VDI-OSAKA-5022

---

### 74. COMPUTER_RBCD (Critical) — ✅ 3 instances
**Description :** Computers with Resource-Based Constrained Delegation configured. Can be abused for privilege escalation.
**Comptes :** WKS-KARACHI-1490, WKS-MANILA-697, WKS-NEW-YORK-3995

---

### 75. COMPUTER_UNCONSTRAINED_DELEGATION (Critical) — ✅ 6 instances
**Description :** Non-DC computers with unconstrained delegation. Can capture TGTs from any connecting user.
**Comptes :** WEB-SERVER-VULN, APP-SERVER-VULN, FILE-SERVER-VULN, WKS-OSAKA-9105, WKS-OSAKA-4691, LAP-KARACHI-9274

---

### 76. COMPUTER_OS_OBSOLETE_XP (Critical) — ✅ 4 instances
**Description :** Windows XP machines — no security patches since 2014.
**Comptes :** WKS-SHANGHAI-7555, WKS-TOKYO-8026, LAP-KOLKATA-3080, LAP-OSAKA-3370

---

### 77. COMPUTER_OS_OBSOLETE_2003 (Critical) — ✅ 3 instances
**Description :** Windows Server 2003 — no security patches since 2015.
**Comptes :** WKS-MANILA-7452, SRV-LAGOS-1956, SRV-MUMBAI-4104

---

### 78. COMPUTER_ACL_ABUSE (High) — ✅ ~19 instances (échantillon)
**Description :** Computer objects with dangerous ACLs allowing non-admin users GenericAll/WriteDacl rights.
**Résultat :** 19/20 computers échantillonnés ont des ACLs dangereuses (Account Operators GenericAll, utilisateurs individuels GenericAll).

---

### 82. COMPUTER_NO_LAPS (High) — ✅ 18 instances
**Description :** Computers without LAPS (Local Administrator Password Solution) configured.
**Résultat :** 18 ordinateurs sans LAPS, dont DC-01 et WIN-11.

---

### 83. COMPUTER_NO_BITLOCKER (High) — ✅ 71 instances
**Description :** Computers without BitLocker recovery information in AD.
**Résultat :** 71 ordinateurs sans informations BitLocker (tous les ordinateurs du lab).

---

### 84. COMPUTER_OS_OBSOLETE_2008 (High) — ✅ 2 instances
**Description :** Windows Server 2008 — end of extended support.
**Comptes :** WKS-NEW-YORK-9957 (2008 R2 Standard), LAP-BEIJING-8646 (2008 Standard)

---

### 85. COMPUTER_OS_OBSOLETE_VISTA (High) — ✅ 2 instances
**Description :** Windows Vista — no security patches since 2017.
**Comptes :** WKS-MANILA-4917, LAP-MUMBAI-4442

---

### 87. COMPUTER_DISABLED_NOT_DELETED (Medium) — ✅ 24 instances
**Description :** Disabled computer accounts still in AD.
**Résultat :** 24 ordinateurs désactivés dont 15 PRE-STAGED et 9 anciens workstations/laptops.

---

### 89. COMPUTER_WEAK_ENCRYPTION (Medium) — ✅ 10 instances
**Description :** Computers with only DES/RC4 encryption (no AES).
**Comptes :** WKS-MANILA-4917, WKS-CAIRO-8310, WKS-KOLKATA-6471, WKS-MANILA-1584, WKS-KOLKATA-6197, SRV-GUANGZHOU-2311, LAP-MUMBAI-2830, LAP-DELHI-6678, LAP-LAGOS-5049, LAP-OSAKA-3370 (encType: 3)

---

### 90. COMPUTER_DESCRIPTION_SENSITIVE (Medium) — ✅ 12 instances
**Description :** Computer descriptions containing sensitive keywords.
**Exemples critiques :**
- `WKS-KOLKATA-6197` — "Password: Welcome2024!" (credential leak!)
- `LAP-MUMBAI-2987` — "LocalAdmin: P@ssw0rd123" (credential leak!)
- 5 machines avec "Machine password > 90 days old"
- 3 machines avec "No LAPS - local admin password not managed"

---

### 92. COMPUTER_NEVER_LOGGED_ON (Medium) — ✅ 69 instances
**Description :** Enabled computers that have never logged on to the domain.
**Résultat :** 69 ordinateurs (la majorité du lab n'a jamais démarré).

---

### 71. COMPUTER_CONSTRAINED_DELEGATION (Critical) — ✅ 3 instances
**Description :** Computer accounts with constrained delegation configured (msDS-AllowedToDelegateTo).
**Résultat :** 3 computers avec msDS-AllowedToDelegateTo injecté vers HOST/DC-01.aza-me.cc.

---

### 72. COMPUTER_DCSYNC_RIGHTS (Critical) — ✅ 2 instances
**Description :** Computer accounts with DCSync rights (DS-Replication-Get-Changes + Get-Changes-All).
**Résultat :** 2 computers avec ACEs DS-Replication injectées sur la racine du domaine (GUIDs 1131f6aa/1131f6ad).

---

### 80. COMPUTER_PASSWORD_OLD (High) — ✅ 5 instances
**Description :** Computer accounts with passwords older than 90 days.
**Résultat :** 5 computers avec PasswordLastSet remonté à ~400 jours via manipulation d'horloge (clock -400j).

---

### 86. DC_NOT_IN_DC_OU (High) — ✅ 1 instance
**Description :** Domain Controller not in the default Domain Controllers OU.
**Résultat :** DC-01 déplacé hors de l'OU Domain Controllers (injecté).

---

### 91. COMPUTER_PRE_WINDOWS_2000 (Medium) — ✅ 1 instance
**Description :** Computer accounts with Pre-Windows 2000 compatible flag.
**Résultat :** 1 computer avec flag Pre-Windows 2000 injecté.

---

### 93. COMPUTER_DUPLICATE_SPN (Medium) — ⚠️ Non injectable
**Description :** Duplicate SPNs on different computers causing Kerberos failures.
**Résultat :** AD bloque nativement l'enregistrement de SPNs dupliqués (forest-wide uniqueness check). Cette vulnérabilité **ne peut pas exister** dans un AD moderne.

---

### 95. COMPUTER_PRE_CREATED (Medium) — ✅ 2 instances
**Description :** Pre-created (staged) computer accounts waiting to join domain.
**Résultat :** 2 comptes computer pré-créés (staging) injectés.

---

### 99. WORKSTATION_IN_SERVER_OU (Low) — ✅ 1 instance
**Description :** Workstation placed in server OU, indicating miscategorization.
**Résultat :** 1 workstation déplacé dans l'OU Servers (injecté).

---

### 97. COMPUTER_ADMIN_COUNT (Low) — ✅ 5 instances
**Description :** Computer accounts with adminCount=1 set.
**Comptes :** WKS-DHAKA-298, WKS-KOLKATA-1684, WKS-NEW-YORK-5736, WKS-MANILA-1584, VDI-OSAKA-5022

---

### 100. COMPUTER_OS_OBSOLETE_NT (Critical) — ❓ Non vérifié
**Description :** Computers running Windows NT 4.0 or Windows 2000, extremely outdated and unsupported. These systems lack all modern security features and are trivially exploitable.
**Résultat :** Non testé individuellement.
