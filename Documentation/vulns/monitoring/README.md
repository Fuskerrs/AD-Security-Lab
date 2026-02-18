# Monitoring (9 vulnérabilités)

**Sévérité :** 0 Critical, 4 High, 5 Medium
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 184 | AUDIT_LOGON_EVENTS_DISABLED | High | Logon Event Auditing Insufficient | ✅ | **1** | Confirmé |
| 185 | AUDIT_ACCOUNT_MGMT_DISABLED | High | Account Management Auditing Disabled | ✅ | **1** | Confirmé |
| 186 | AUDIT_POLICY_CHANGE_DISABLED | High | Policy Change Auditing Disabled | ✅ | **1** | Confirmé |
| 187 | ADMIN_AUDIT_BYPASS | High | Administrators Can Bypass Audit | ✅ | **1** | Confirmé |
| 188 | AUDIT_PRIVILEGE_USE_DISABLED | Medium | Privilege Use Auditing Disabled | ✅ | **1** | Confirmé |
| 189 | NO_HONEYPOT_ACCOUNTS | Medium | No Honeypot/Decoy Accounts | ✅ | **1** | Confirmé |
| 190 | NO_PROTECTED_USERS_MONITORING | Medium | Protected Users Group Not Utilized | ✅ | **1** | Confirmé |
| 191 | SECURITY_LOG_SIZE_SMALL | Medium | Security Log Size Too Small | ✅ | **1** | Confirmé (injecté MaxSize=64MB) |
| 192 | DC_AUDIT_POLICY_INCOMPLETE | Medium | Domain Controller Audit Policy Incomplete | ❓ | - | Non vérifié |

**Résumé : 8/9 confirmés (dont 1 injecté) | 1 non vérifié**

---

## Détail des vulnérabilités

### 184. AUDIT_LOGON_EVENTS_DISABLED (High) — ✅ 1 instance
**Description :** Logon events not fully audited. Both Account Logon and Logon/Logoff should audit Success+Failure.
**Résultat :** Audit Logon configuré en **Success only** (pas Success+Failure). Les échecs de connexion ne sont pas journalisés. Empêche la détection de brute-force et password spraying.

---

### 185. AUDIT_ACCOUNT_MGMT_DISABLED (High) — ✅ 1 instance
**Description :** Account management events not audited. Prevents detection of unauthorized account changes.
**Résultat :** User Account Management et Security Group Management en **Success only**. Les tentatives échouées de modification de comptes ne sont pas journalisées.

---

### 186. AUDIT_POLICY_CHANGE_DISABLED (High) — ✅ 1 instance
**Description :** Policy changes not audited. Prevents detection of GPO poisoning and security policy tampering.
**Résultat :** Audit Policy Change en **Success only**. Les tentatives de modification des politiques de sécurité échouées ne sont pas détectées.

---

### 187. ADMIN_AUDIT_BYPASS (High) — ✅ 1 instance (policy)
**Description :** Privileged accounts not in Protected Users with old passwords may bypass audit controls.
**Résultat :** Comptes avec AdminCount=1, hors Protected Users (vide), avec mots de passe de plus de 180 jours. Ces comptes ne bénéficient d'aucune protection renforcée.

---

### 188. AUDIT_PRIVILEGE_USE_DISABLED (Medium) — ✅ 1 instance
**Description :** Privilege use not audited. Prevents detection of privilege abuse and token manipulation.
**Résultat :** Couvert par l'audit global faible (#126) : 42 sous-catégories sans audit, incluant Sensitive Privilege Use.

---

### 189. NO_HONEYPOT_ACCOUNTS (Medium) — ✅ 1 instance (policy)
**Description :** No decoy accounts detected. These help detect attackers during enumeration.
**Résultat :** Aucun compte honeypot/decoy/canary détecté dans le domaine. Pas de système d'alerte précoce pour détecter les attaquants.

---

### 190. NO_PROTECTED_USERS_MONITORING (Medium) — ✅ 1 instance (policy)
**Description :** Privileged accounts not in Protected Users. Missing protections against credential theft.
**Résultat :** **24 Domain Admins, 0 dans Protected Users**. Aucun compte privilégié ne bénéficie des protections (pas de délégation, pas de NTLM, TGT court, pas de cache de credentials).

---

### 191. SECURITY_LOG_SIZE_SMALL (Medium) — ✅ 1 instance
**Description :** Security log max size below 128 MB. Risk of losing critical audit events.
**Résultat :** MaxSize réduit à **64 MB** (injecté). En dessous du minimum recommandé de 128 MB. Risque de perte d'événements de sécurité critiques lors de pics d'activité.

---

### 192. DC_AUDIT_POLICY_INCOMPLETE (Medium) — ❓ Non vérifié
**Description :** The audit policy applied to Domain Controllers does not log both success and failure events for all critical security categories (Account Logon, Account Management, Logon Events, Policy Change, System Events, DS Access).
**Résultat :** Non testé individuellement. Probablement confirmé vu l'état de l'audit global (#126 : 42 sous-catégories sans audit).
