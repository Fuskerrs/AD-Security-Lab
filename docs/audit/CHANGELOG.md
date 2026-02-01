# Changelog ETC Collector

---

## v1.2.7 (2026-01-31)

### 🐛 Bug Fix - Async API extendedConfig

**Problème:**
- L'API async ne retournait pas `extendedConfig`
- `extendedConfig.total: 0, findings: []`
- Détecteurs `detectAttackPathVulnerabilities` et `detectMonitoringVulnerabilities` manquants dans `job-runner.ts` (async)
- Présents dans `ad-audit.service.ts` (sync) mais pas en async

**Correction:**
- ✅ Ajout imports dans `job-runner.ts` (lignes 33-34)
- ✅ Ajout étapes `DETECTING_ATTACK_PATHS` et `DETECTING_MONITORING`

**Résultat:**
- Avant: `extendedConfig.total: 0, findings: []`
- Après: `extendedConfig.total: 120, findings: 7 types`

**Types extendedConfig détectés:**
```
PATH_KERBEROASTING_TO_DA (23)
PATH_ASREP_TO_ADMIN (20)
PATH_SERVICE_TO_DA (19)
PATH_COMPUTER_TAKEOVER (1)
PATH_CERTIFICATE_ESC (1)
PATH_DELEGATION_CHAIN (1)
NO_PROTECTED_USERS_MONITORING (55)
```

### 📋 Stats v1.2.7

- **Total types:** 120
- **Coverage:** 58/61 (95.08%)
- **Vraiment manquants:** 2 types (GPO_Password_in_SYSVOL, GPO_LAPS_NOT_DEPLOYED)

---

## v1.2.6 (2026-01-31)

### ✨ Features

- ✅ 120 types détectés
- ✅ 13 catégories
- ✅ Attack paths (6 types)
- ✅ ADCS ESC1-11
- ✅ Service accounts (7 types)
- ✅ Advanced ACL analysis

### 📊 Stats

- Total findings: 8239
- Total instances: 24312
- Risk score: 13.4 (critical)

---

## v1.2.0-v1.2.5

### ✨ Features cumulées

- ADCS certificates (ESC1-11)
- Attack paths analysis
- Service accounts detection
- ACL advanced analysis
- GPO security
- Group memberships
- Delegation checks
- Network security

---

## v1.1.9 (2026-01-31)

### ✨ Features

- ✅ COMPUTER_ACL_GENERICALL (détecteur ajouté)
- ✅ toTimestamp support (format LDAP generalizedTime)
- ⚠️ COMPUTER_DISABLED_NOT_DELETED (ajouté, retourne 0 - normal)
- ⚠️ COMPUTER_STALE_INACTIVE (ajouté, retourne 0 - normal)

### 📊 Stats

- Total types: 91
- Total findings: 7353

---

## v1.1.8 (2026-01-31)

### ✨ Features

- ✅ 91 types détectés
- ✅ COMPUTER_NEVER_LOGGED_ON (69)
- ✅ SMARTCARD_NOT_REQUIRED (55)
- ✅ BACKUP_OPERATORS_MEMBER (20)
- ✅ ACCOUNT_OPERATORS_MEMBER (20)
- ✅ PRINT_OPERATORS_MEMBER (19)
- ✅ SERVER_OPERATORS_MEMBER (11)
- ✅ DNS_ADMINS_MEMBER (4)
- ✅ BUILTIN_MODIFIED (4)

### 📊 Stats

- Total findings: 7353
- Coverage: 36/61 (59%)

---

## v1.1.7 (2026-01-31)

### ✨ Features

- ✅ UNIX_USER_PASSWORD (541) ← Énorme!
- ✅ 109 détecteurs implémentés (code)
- ✅ 27 types détectés (instances)

### 📊 Stats

- Total findings: 7353
- Total instances: 20475

---

## v1.1.6 (2026-01-31)

### ✨ Features

- ✅ COMPUTER_PRE_CREATED (24)
- ✅ COMPUTER_RBCD (3)
- ✅ COMPUTER_WITH_SPNS (18)
- ✅ Fix conversion dates (pwdLastSet, lastLogonTimestamp)

### 📊 Stats

- Total findings: ~6300
- Total types: 25

---

## v1.1.5 (2026-01-31)

### ✨ Features

- ✅ ADMIN_ASREP_ROASTABLE (16)
- ✅ WEAK_ENCRYPTION_DES (21)

### 📊 Stats

- Total findings: 1296
- Total types: 16

---

## v1.1.4 (Initial)

### ✨ Features

- Baseline: 56 types détectés

---

## 📋 Prochaines versions

### v1.3.0 (En cours)

**Objectif:** Compléter les 2 types manquants

- ⏳ GPO_Password_in_SYSVOL (SYSVOL XML scan)
- ⏳ GPO_LAPS_NOT_DEPLOYED (GPO LAPS check)

**Après:** 60/61 types (98.4% coverage!) 🎯

### v1.3.1 (À venir)

**Objectif:** Network Security

- SMB_SIGNING_DISABLED
- LDAP_SIGNING_DISABLED
- LDAPS_NOT_ENFORCED
- SMBv1_ENABLED
- NTLM_NOT_RESTRICTED
- LLMNR_ENABLED
- WPAD_ENABLED
- IPV6_ENABLED_UNUSED

**+8 types**

---

## 🏆 Milestones

- ✅ v1.1.7: Unix passwords detection (541 instances!)
- ✅ v1.2.6: 120 types, attack paths
- ✅ v1.2.7: Fix async API bug
- ⏳ v1.3.0: 98.4% coverage (60/61 types)
- 🎯 v1.4.0: Attack graph analysis (BloodHound-style)
- 🎯 v1.5.0: ML/AI detection
