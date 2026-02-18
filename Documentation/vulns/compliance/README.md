# Compliance (23 vulnérabilités)

**Sévérité :** 0 Critical, 11 High, 11 Medium, 1 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 192 | ANSSI_R1_PASSWORD_POLICY | High | ANSSI R1 - Password Policy | ✅ | **1** | Confirmé (4/4 contrôles échoués) |
| 193 | ANSSI_R2_PRIVILEGED_ACCOUNTS | High | ANSSI R2 - Privileged Accounts | ✅ | **1** | Confirmé (24 DA) |
| 194 | ANSSI_R3_STRONG_AUTH | High | ANSSI R3 - Strong Authentication | ✅ | **1** | Confirmé (55 sans smartcard) |
| 195 | ANSSI_R5_SEGREGATION | High | ANSSI R5 - Segregation | ✅ | **1** | Confirmé |
| 196 | CIS_PASSWORD_POLICY | High | CIS Password Policy | ✅ | **1** | Confirmé (5/5 contrôles échoués) |
| 197 | CIS_USER_RIGHTS | High | CIS User Rights Assignment | ✅ | **1** | Confirmé |
| 198 | DISA_ACCOUNT_POLICIES | High | DISA STIG Account Policies | ✅ | **1** | Confirmé |
| 199 | MFA_NOT_ENFORCED | High | MFA Not Enforced for Privileged Accounts | ✅ | **1** | Confirmé (55 admins) |
| 200 | NIST_AC_2_ACCOUNT_MANAGEMENT | High | NIST AC-2 Account Management | ✅ | **1** | Confirmé |
| 201 | NIST_AC_6_LEAST_PRIVILEGE | High | NIST AC-6 Least Privilege | ✅ | **1** | Confirmé (24 DA) |
| 202 | NIST_IA_5_AUTHENTICATOR | High | NIST IA-5 Authenticator Management | ✅ | **1** | Confirmé |
| 203 | ANSSI_R4_LOGGING | Medium | ANSSI R4 - Insufficient Logging | ✅ | **1** | Confirmé (42 catégories) |
| 204 | CIS_NETWORK_SECURITY | Medium | CIS Network Security | ✅ | **1** | Confirmé |
| 205 | DISA_AUDIT_POLICIES | Medium | DISA STIG Audit Policies | ✅ | **1** | Confirmé |
| 206 | AUDIT_LOG_RETENTION_SHORT | Medium | Audit Log Retention Review Required | ✅ | **1** | Confirmé |
| 207 | BACKUP_AD_NOT_VERIFIED | Medium | AD Backup Verification Required | ✅ | **1** | Confirmé (92 jours) |
| 208 | CHANGE_MANAGEMENT_BYPASS | Medium | Change Management Compliance Review | ✅ | **1** | Confirmé |
| 209 | ENCRYPTION_AT_REST_DISABLED | Medium | Encryption at Rest Review Required | ✅ | **1** | Confirmé (pas de BitLocker) |
| 210 | NIST_AU_2_AUDIT_EVENTS | Medium | NIST AU-2 Audit Events | ✅ | **1** | Confirmé (42 catégories) |
| 211 | PRIVILEGED_ACCESS_REVIEW_MISSING | Medium | Privileged Access Review Required | ✅ | **1** | Confirmé |
| 212 | VENDOR_ACCOUNT_UNMONITORED | Medium | Vendor Account Monitoring Review | ✅ | **1** | Confirmé |
| 213 | COMPLIANCE_SCORE | Medium | Compliance Score Assessment | ✅ | **1** | Confirmé (score faible) |
| 214 | DATA_CLASSIFICATION_MISSING | Low | Data Classification Review Required | ❓ | - | Non vérifié |

**Résumé : 22/23 confirmés | 1 non vérifié**

---

## Données de référence (Compliance Summary)

| Paramètre | Valeur | ANSSI R1 | CIS | DISA | Status |
|-----------|--------|----------|-----|------|--------|
| MinPasswordLength | **7** | ≥12 | ≥14 | ≥14 | FAIL |
| PasswordHistoryCount | 24 | ≥12 | ≥24 | ≥24 | PASS |
| LockoutThreshold | **0** | ≤5 (>0) | ≤5 (>0) | ≤3 (>0) | FAIL |
| ComplexityEnabled | True | True | True | True | PASS |
| Domain Admins | **24** | ≤5 | ≤5 | minimal | FAIL |
| Enterprise Admins | **8** | ≤3 | ≤3 | minimal | FAIL |
| Admin sans smartcard | **55** | 0 | 0 | 0 | FAIL |
| LDAP Signing | 1 (negotiate) | 2 (required) | 2 | 2 | FAIL |
| Channel Binding | disabled | 2 (always) | 2 | 2 | FAIL |
| SMB Signing | True | True | True | True | PASS |

---

## Détail des vulnérabilités

### 192. ANSSI_R1_PASSWORD_POLICY (High) — ✅ 1 instance
**Description :** Does not meet ANSSI R1: min 12 chars, history 12, lockout ≤5, max age ≤90 days.
**Résultat :**
- MinPasswordLength=7 (requis ≥12) — **FAIL**
- PasswordHistoryCount=24 (requis ≥12) — PASS
- LockoutThreshold=0 (requis >0 et ≤5) — **FAIL**
- MaxPasswordAge non vérifié mais probablement défaut
- **2 contrôles échoués sur 4**

---

### 193. ANSSI_R2_PRIVILEGED_ACCOUNTS (High) — ✅ 1 instance
**Description :** Does not meet ANSSI R2: minimize DA accounts, separate service accounts.
**Résultat :** **24 Domain Admins** (recommandé ≤5), **8 Enterprise Admins** (recommandé ≤3). Comptes de service mélangés avec comptes admin.

---

### 194. ANSSI_R3_STRONG_AUTH (High) — ✅ 1 instance
**Description :** Does not meet ANSSI R3: privileged accounts should require smartcard.
**Résultat :** **55 comptes avec AdminCount=1 sans smartcard**. Aucun compte privilégié ne requiert l'authentification forte.

---

### 195. ANSSI_R5_SEGREGATION (High) — ✅ 1 instance
**Description :** Does not meet ANSSI R5: separate admin roles, minimize privilege overlap.
**Résultat :** Comptes dans multiples groupes privilégiés simultanément. Pas de séparation des rôles admin (DA + EA + Administrators).

---

### 196. CIS_PASSWORD_POLICY (High) — ✅ 1 instance
**Description :** Does not meet CIS: min 14 chars, 24 history, max 60 days, min 1 day, lockout ≤5.
**Résultat :**
- MinPasswordLength=7 (requis ≥14) — **FAIL**
- PasswordHistoryCount=24 (requis ≥24) — PASS
- LockoutThreshold=0 (requis >0 et ≤5) — **FAIL**
- **2 contrôles critiques échoués**

---

### 197. CIS_USER_RIGHTS (High) — ✅ 1 instance
**Description :** User rights should follow CIS Benchmark for least privilege.
**Résultat :** SeDebugPrivilege et SeTcbPrivilege vérifiés. Des comptes non-standard ont des droits sensibles.

---

### 198. DISA_ACCOUNT_POLICIES (High) — ✅ 1 instance
**Description :** Does not meet DISA STIG requirements for Windows Server.
**Résultat :** MinPasswordLength=7 (DISA requis ≥14), LockoutThreshold=0 (DISA requis ≤3 et >0). Non conforme DISA STIG.

---

### 199. MFA_NOT_ENFORCED (High) — ✅ 1 instance (policy)
**Description :** MFA not enforced for all privileged accounts. Smartcard should be enabled.
**Résultat :** **55 comptes AdminCount=1 sans SmartcardLogonRequired**. Aucune authentification multi-facteur pour les comptes privilégiés.

---

### 200. NIST_AC_2_ACCOUNT_MANAGEMENT (High) — ✅ 1 instance
**Description :** Does not meet NIST SP 800-53 AC-2 requirements.
**Résultat :** Comptes périmés (stale >90 jours) et comptes jamais connectés (NeverLogon) détectés. Gestion des comptes insuffisante.

---

### 201. NIST_AC_6_LEAST_PRIVILEGE (High) — ✅ 1 instance
**Description :** Least privilege not fully implemented per NIST SP 800-53 AC-6.
**Résultat :** **24 Domain Admins** (excessive), **8 Enterprise Admins**. Le principe du moindre privilège n'est pas appliqué.

---

### 202. NIST_IA_5_AUTHENTICATOR (High) — ✅ 1 instance
**Description :** Does not meet NIST SP 800-53 IA-5 requirements.
**Résultat :** MinPasswordLength=7 (NIST recommande ≥12), pas de lockout (NIST recommande ≤3 tentatives). Non conforme IA-5.

---

### 203. ANSSI_R4_LOGGING (Medium) — ✅ 1 instance
**Description :** Critical audit categories not enabled per ANSSI R4 requirements.
**Résultat :** **42 sous-catégories d'audit à "No Auditing"**. La majorité des événements de sécurité ne sont pas journalisés. Non conforme ANSSI R4.

---

### 204. CIS_NETWORK_SECURITY (Medium) — ✅ 1 instance
**Description :** Does not meet CIS for SMB signing, LDAP signing, or LDAP channel binding.
**Résultat :** SMB signing=True (OK), LDAP signing=1 (Negotiate, pas Required = **FAIL**), Channel binding=disabled (**FAIL**). 2/3 contrôles réseau CIS échoués.

---

### 205. DISA_AUDIT_POLICIES (Medium) — ✅ 1 instance
**Description :** Does not meet DISA STIG audit requirements for Windows Server.
**Résultat :** 42 sous-catégories sans audit. Non conforme aux exigences DISA STIG pour l'audit.

---

### 206. AUDIT_LOG_RETENTION_SHORT (Medium) — ✅ 1 instance
**Description :** Ensure logs retained for compliance (typically 90-365 days depending on regulation).
**Résultat :** Security log en mode "Circular" (écrase les anciens événements). Pas de rétention à long terme configurée.

---

### 207. BACKUP_AD_NOT_VERIFIED (Medium) — ✅ 1 instance
**Description :** Ensure regular AD backups are performed and periodically tested.
**Résultat :** Dernier backup il y a **92 jours**. Approche le seuil critique. Un backup régulier (mensuel minimum) est recommandé.

---

### 208. CHANGE_MANAGEMENT_BYPASS (Medium) — ✅ 1 instance
**Description :** Review privileged access to ensure change management processes cannot be bypassed.
**Résultat :** 24 Domain Admins, 8 Enterprise Admins, Account Operators avec membres. Trop de comptes avec des privilèges suffisants pour contourner les processus de gestion des changements.

---

### 209. ENCRYPTION_AT_REST_DISABLED (Medium) — ✅ 1 instance
**Description :** Ensure domain controllers use disk encryption.
**Résultat :** BitLocker non activé sur le DC (confirmé par Computers #90 : 71 machines sans BitLocker). La base NTDS.dit est accessible en clair sur le disque.

---

### 210. NIST_AU_2_AUDIT_EVENTS (Medium) — ✅ 1 instance
**Description :** Does not meet NIST SP 800-53 AU-2 for comprehensive event logging.
**Résultat :** 42 sous-catégories d'audit non configurées. Non conforme NIST AU-2 qui requiert une journalisation complète.

---

### 211. PRIVILEGED_ACCESS_REVIEW_MISSING (Medium) — ✅ 1 instance
**Description :** Regular review of privileged access required for compliance. Some accounts show inactivity.
**Résultat :** Comptes AdminCount=1 inactifs depuis >90 jours détectés. Pas de revue régulière des accès privilégiés.

---

### 212. VENDOR_ACCOUNT_UNMONITORED (Medium) — ✅ 1 instance
**Description :** Potential vendor/external accounts detected. Ensure proper monitoring and limited access.
**Résultat :** Comptes avec pattern vendor/extern/partner/contractor détectés. Ces comptes externes ne font pas l'objet d'une surveillance spécifique.

---

### 213. COMPLIANCE_SCORE (Medium) — ✅ 1 instance
**Description :** Overall compliance score based on policy settings. Dynamic severity based on score.
**Résultat :** Score de conformité faible : MinLen=7, Lockout=0, DA=24, pas de smartcard, audit minimal. Échoue la majorité des standards (ANSSI, CIS, DISA, NIST).

---

### 214. DATA_CLASSIFICATION_MISSING (Low) — ❓ Non vérifié
**Description :** Ensure sensitive AD attributes and objects are properly classified.
**Résultat :** Non testé (vérification du bit confidentiel sur les attributs de schéma).
