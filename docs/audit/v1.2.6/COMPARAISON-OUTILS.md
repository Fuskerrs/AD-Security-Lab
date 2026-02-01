# Comparaison ETC Collector vs Ping Castle vs Purple Knight

**Date:** 2026-01-31
**ETC Collector version:** v1.2.6

---

## 📊 Vue d'ensemble

| Critère | ETC Collector v1.2.6 | Ping Castle | Purple Knight |
|---------|---------------------|-------------|---------------|
| **Types détectés** | 120 | ~150+ | ~100+ |
| **Couverture testée** | 95% (58/61) | N/A | N/A |
| **Attack Paths** | ✅ 6 types | ✅ Complet | ✅ Limité |
| **ADCS (ESC1-11)** | ✅ 14 types | ✅ ESC1-8 | ✅ Basique |
| **ACL Analysis** | ✅ 9 types | ✅✅ Très complet | ✅ Moyen |
| **Kerberos** | ✅ 6 types | ✅ Complet | ✅ Complet |
| **GPO Security** | ✅ 7 types | ✅✅ Très complet | ✅ Complet |
| **Score/Rating** | ✅ Risk score | ✅✅ Maturity score | ✅ IOE score |
| **Reporting** | JSON/API | HTML/XML | HTML/PDF |
| **Open Source** | ❓ | ✅ Oui | ❌ Non |
| **Prix** | ❓ | 🆓 Gratuit | 🆓 Gratuit |

---

## 🎯 Par catégorie détaillée

### 1. Passwords & Kerberos

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| Password Never Expires | ✅ 39 | ✅ | ✅ |
| Reversible Encryption | ✅ 21 | ✅ | ✅ |
| Kerberoasting | ✅ 34 | ✅ | ✅ |
| AS-REP Roasting | ✅ 25 | ✅ | ✅ |
| Weak Encryption (DES/RC4) | ✅ 21 | ✅ | ✅ |
| **Cleartext Passwords (Unix)** | ✅✅ 541 | ❌ | ❌ |
| **Password in Description** | ✅ 3 | ✅ | ✅ |
| **Dict Attack Risk** | ✅ 535 | ⚠️ Partiel | ❌ |

**Gagnant:** ETC Collector (détection Unix passwords unique)

---

### 2. ADCS / PKI

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| ESC1 (SAN) | ✅ 5 | ✅ | ✅ |
| ESC2 (Any Purpose) | ✅ 6 | ✅ | ✅ |
| ESC3 (Enrollment Agent) | ✅ 8 | ✅ | ✅ |
| ESC4 (ACL) | ✅ 0 | ✅ | ⚠️ |
| ESC5 (PKI Objects) | ✅ 0 | ✅ | ⚠️ |
| ESC6 (EDITF_FLAG) | ✅ 0 | ✅ | ✅ |
| ESC7 (CA ACL) | ✅ 0 | ✅ | ⚠️ |
| ESC8 (HTTP Enrollment) | ✅ 0 | ✅ | ⚠️ |
| ESC9-11 | ✅ 17 | ⚠️ Récent | ❌ |

**Gagnant:** ETC Collector (ESC9-11 coverage)

---

### 3. ACL & Permissions

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| GenericAll | ✅ 790 | ✅ | ✅ |
| WriteDACL | ✅ 790 | ✅ | ✅ |
| WriteOwner | ✅ 790 | ✅ | ✅ |
| ForceChangePassword | ✅ 6 | ✅ | ✅ |
| Self-Membership | ✅ 790 | ✅ | ⚠️ |
| **Replication Rights** | ✅ 40 | ✅ | ✅ |
| **WriteSPN Abuse** | ✅ 92 | ✅ | ⚠️ |
| ACL Paths Analysis | ⚠️ Basique | ✅✅ Complet | ✅ |
| Nested Permissions | ❌ | ✅✅ | ✅ |

**Gagnant:** Ping Castle (analyse ACL la plus complète)

---

### 4. Computers

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| Never Logged On | ✅ 69 | ✅ | ✅ |
| Pre-Created | ✅ 24 | ✅ | ✅ |
| Obsolete OS | ✅ 10 | ✅ | ✅ |
| No LAPS | ✅ 1 | ✅ | ✅ |
| No BitLocker | ✅ 13 | ❌ | ✅ |
| Weak Encryption | ✅ 10 | ✅ | ✅ |
| Unconstrained Delegation | ✅ 7 | ✅ | ✅ |
| RBCD | ✅ 3 | ✅ | ✅ |
| **ACL Abuse** | ✅ 95 | ✅ | ⚠️ |
| SMB Signing | ❌ | ✅ | ✅ |
| LDAP Signing | ❌ | ✅ | ✅ |

**Gagnant:** Égalité (Ping Castle + Purple Knight ont SMB/LDAP signing)

---

### 5. Groups & Privileged Accounts

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| Backup Operators | ✅ 20 | ✅ | ✅ |
| Account Operators | ✅ 20 | ✅ | ✅ |
| Print Operators | ✅ 19 | ✅ | ✅ |
| Server Operators | ✅ 11 | ✅ | ✅ |
| DNS Admins | ✅ 4 | ✅ | ✅ |
| Builtin Modified | ✅ 4 | ✅ | ✅ |
| AdminCount Orphaned | ✅ 45 | ✅ | ✅ |
| **Not in Protected Users** | ✅ 27 | ✅ | ✅ |
| Oversized Groups | ✅ 4 | ✅ | ✅ |
| Dangerous Nesting | ✅ 3 | ✅✅ | ✅ |
| AdminSDHolder Backdoor | ✅ 1 | ✅ | ✅ |

**Gagnant:** Égalité

---

### 6. Attack Paths

| Type | ETC Collector | Ping Castle | Purple Knight |
|------|---------------|-------------|---------------|
| Kerberoasting → DA | ✅ 23 | ✅ | ⚠️ |
| AS-REP → Admin | ✅ 20 | ✅ | ⚠️ |
| Service → DA | ✅ 19 | ✅ | ⚠️ |
| Delegation Chains | ✅ 1 | ✅✅ | ⚠️ |
| Certificate Paths | ✅ 1 | ✅ | ⚠️ |
| Computer Takeover | ✅ 1 | ✅✅ | ⚠️ |
| **Graph Analysis** | ⚠️ Basique | ✅✅ Complet | ⚠️ Basique |

**Gagnant:** Ping Castle (graph analysis le plus complet)

---

### 7. GPO Security

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| GPO Modify Rights | ✅ 12 | ✅ | ✅ |
| Orphaned GPOs | ✅ 7 | ✅ | ✅ |
| Weak Permissions | ✅ 6 | ✅ | ✅ |
| Link Poisoning | ✅ 1 | ✅ | ⚠️ |
| **Password in SYSVOL** | ❌ | ✅ | ✅ |
| **LAPS Not Deployed** | ❌ | ✅ | ✅ |
| Weak Password Policy | ✅ 1 | ✅ | ✅ |

**Gagnant:** Ping Castle & Purple Knight (SYSVOL scan)

---

### 8. Service Accounts

| Détection | ETC Collector | Ping Castle | Purple Knight |
|-----------|---------------|-------------|---------------|
| Interactive Logon | ✅ 27 | ✅ | ✅ |
| Privileged | ✅ 19 | ✅ | ✅ |
| No Pre-Auth | ✅ 22 | ✅ | ✅ |
| With SPN | ✅ 33 | ✅ | ✅ |
| Old Password | ✅ 36 | ✅ | ✅ |
| Weak Encryption | ✅ 2 | ✅ | ✅ |
| Naming Convention | ✅ 3 | ⚠️ | ⚠️ |

**Gagnant:** ETC Collector (détection naming)

---

## 🏆 Score final

### Forces de chaque outil

**ETC Collector v1.2.6:**
- ✅ Unix cleartext passwords (unique!)
- ✅ ADCS ESC9-11 (le plus récent)
- ✅ Service account naming detection
- ✅ API REST moderne
- ✅ 95% coverage vérifié
- ✅ Bonne couverture ACL basique

**Ping Castle:**
- ✅✅ Analyse ACL la plus complète
- ✅✅ Attack graph le plus avancé
- ✅✅ Maturity scoring
- ✅✅ SYSVOL/GPO scan complet
- ✅ Open source
- ✅ Gratuit
- ✅ Communauté active
- ✅ Trusts & forests analysis

**Purple Knight:**
- ✅✅ Focus ransomware/resilience
- ✅✅ Recovery readiness
- ✅ SMB/LDAP signing checks
- ✅ Indicators of Exposure (IOE)
- ✅ Enterprise reporting
- ✅ Gratuit
- ✅ Support Semperis

---

## 📊 Classement par cas d'usage

### 🥇 Meilleur pour audit général
**Ping Castle** - Le plus complet, gratuit, open source

### 🥇 Meilleur pour ADCS/PKI
**ETC Collector v1.2.6** - ESC9-11 coverage

### 🥇 Meilleur pour ransomware/resilience
**Purple Knight** - Focus spécifique

### 🥇 Meilleur pour automation/CI-CD
**ETC Collector v1.2.6** - API REST moderne

### 🥇 Meilleur pour attack paths
**Ping Castle** - Graph analysis le plus avancé

---

## 💡 Recommandation

**Utiliser les 3 en complément:**

1. **Ping Castle** - Audit mensuel complet
2. **Purple Knight** - Check resilience trimestriel
3. **ETC Collector** - Monitoring continu via API

**Points d'amélioration ETC Collector:**
- ❌ Ajouter SYSVOL scan (GPO passwords)
- ❌ Ajouter SMB/LDAP signing checks
- ❌ Améliorer attack graph analysis
- ❌ Ajouter nested permissions analysis
- ❌ Ajouter trusts analysis

**Points forts uniques ETC Collector:**
- ✅ Unix cleartext password detection
- ✅ Modern REST API
- ✅ ESC9-11 coverage
- ✅ 95% verified coverage
- ✅ Service account naming

---

## 📈 Score de couverture estimé

| Outil | Coverage estimé | Types détectés |
|-------|-----------------|----------------|
| **Ping Castle** | ~85-90% | 150+ |
| **ETC Collector v1.2.6** | ~80-85% | 120 |
| **Purple Knight** | ~75-80% | 100+ |

**Note:** Les % sont basés sur le nombre de vulns détectées vs vulns possibles dans un AD réel.

---

**Conclusion:** ETC Collector v1.2.6 est **très compétitif** mais Ping Castle reste la référence pour l'audit complet. Utiliser les 3 en complément est la meilleure approche.
