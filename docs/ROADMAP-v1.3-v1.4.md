# Roadmap ETC Collector v1.3.x - v1.4.0

**Date:** 2026-02-01
**Status actuel:** v1.2.11 - 122 types détectés
**Objectif Phase 1:** 153 types (Parity avec Ping Castle)

---

## 🎯 Vue d'ensemble

| Version | Types | Sprint | Durée | Status |
|---------|-------|--------|-------|--------|
| v1.2.11 | 122 | - | - | ✅ Done |
| **v1.3.0** | **130** | **Sprint 1** | **2 semaines** | ⏳ Next |
| v1.3.1 | 137 | Sprint 2 | 2 semaines | 📋 Planned |
| v1.4.0 | 152 | Sprint 3 | 3 semaines | 📋 Planned |

---

## 📊 Progression Phase 1

```
v1.2.11 (122) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 79.7%
                                                                    ▼
v1.3.0  (130) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 85.0%
                                                                    ▼
v1.3.1  (137) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 89.5%
                                                                    ▼
v1.4.0  (152) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 99.3%
                Target: 153 types ═══════════════════════════════════════▶ 100%
```

---

## 🚀 Sprint 1: Network Security (v1.3.0)

**Durée:** 2 semaines
**Objectif:** +8 types (122 → 130)
**Priorité:** 🔴 P0 CRITICAL

### Stories

| Story | Types | Effort | Priorité |
|-------|-------|--------|----------|
| [Story 1.1](stories/story-1.1-smb-ldap-signing.md) | 2 types | 3 jours | P0 |
| [Story 1.2](stories/story-1.2-ldaps-protocols.md) | 2 types | 2 jours | P0 |
| [Story 1.3](stories/story-1.3-legacy-protocols.md) | 3 types | 3 jours | P0 |
| [Story 1.4](stories/story-1.4-ntlm-restrictions.md) | 1 type | 2 jours | P0 |

**Total:** 8 types, ~10 jours de dev

### Détails techniques

**Types à implémenter:**
1. `SMB_SIGNING_DISABLED` (critical)
2. `LDAP_SIGNING_DISABLED` (critical)
3. `LDAPS_NOT_ENFORCED` (high)
4. `SMBv1_ENABLED` (high)
5. `LLMNR_ENABLED` (high)
6. `WPAD_ENABLED` (medium)
7. `IPV6_ENABLED_UNUSED` (medium)
8. `NTLM_NOT_RESTRICTED` (critical)

**Impact:**
- Comble le gap principal vs Ping Castle
- Protection contre SMB relay, LLMNR poisoning, pass-the-hash
- Valeur immédiate pour pentesters

---

## 🛡️ Sprint 2: Ransomware Resilience (v1.3.1)

**Durée:** 2 semaines
**Objectif:** +7 types (130 → 137)
**Priorité:** 🟠 P0 HIGH

### Stories

| Story | Types | Effort | Priorité |
|-------|-------|--------|----------|
| [Story 2.1](stories/story-2.1-ad-recovery.md) | 3 types | 4 jours | P0 |
| [Story 2.2](stories/story-2.2-tiering-paw.md) | 2 types | 3 jours | P1 |
| [Story 2.3](stories/story-2.3-monitoring-gaps.md) | 2 types | 3 jours | P2 |

**Total:** 7 types, ~10 jours de dev

### Détails techniques

**Types à implémenter:**
1. `NO_AD_RECYCLE_BIN` (critical)
2. `NO_BACKUP_VERIFICATION` (critical)
3. `DSRM_PASSWORD_WEAK` (high)
4. `NO_TIERING_MODEL` (high)
5. `PRIVILEGED_NO_PAW` (medium)
6. `CRITICAL_SERVICES_UNMONITORED` (medium)
7. `NO_EMERGENCY_PROCEDURES` (medium)

**Impact:**
- Différenciation vs Ping Castle (focus Purple Knight)
- Protection ransomware (threat #1)
- Valeur SaaS pour compliance

---

## 🌲 Sprint 3: Trust, GPO & DNS (v1.4.0)

**Durée:** 3 semaines
**Objectif:** +15 types (137 → 152)
**Priorité:** 🟡 P1 MEDIUM

### Stories

| Story | Types | Effort | Priorité |
|-------|-------|--------|----------|
| [Story 3.1](stories/story-3.1-trust-forest.md) | 6 types | 5 jours | P1 |
| [Story 3.2](stories/story-3.2-advanced-gpo.md) | 5 types | 5 jours | P1 |
| [Story 3.3](stories/story-3.3-dns-security.md) | 4 types | 5 jours | P1 |

**Total:** 15 types, ~15 jours de dev

### Détails techniques

**Trust & Forest (6 types):**
- `FOREST_TRUST_WEAK`
- `SID_FILTERING_DISABLED`
- `EXTERNAL_TRUST_WEAK`
- `SELECTIVE_AUTH_DISABLED`
- `TRUST_TGT_DELEGATION`
- `CROSS_FOREST_KERBEROASTING`

**Advanced GPO (5 types):**
- `GPO_AUTHENTICATED_USERS_DANGEROUS`
- `GPO_STARTUP_SCRIPTS_UNSIGNED`
- `GPO_SCHEDULED_TASKS_PRIVILEGED`
- `GPO_LOCAL_ADMIN_ADDITIONS`
- `GPO_REGISTRY_ACL_WEAK`

**DNS Security (4 types):**
- `DNS_ZONE_TRANSFER_UNRESTRICTED`
- `DNS_DYNAMIC_UPDATES_INSECURE`
- `DNS_WILDCARD_RECORDS`
- `ADIDNS_EVERYONE_CREATE`

**Impact:**
- Multi-domain/forest support
- GPO coverage complète
- DNS attack surface reduction

---

## 📋 Process pour chaque Story

### 1. Développement
```bash
# Dev crée une branche
git checkout -b feature/story-1.1-smb-ldap-signing

# Développe les détecteurs
# Commit et push
```

### 2. Vérification
```bash
# Claude vérifie l'implémentation
powershell -ExecutionPolicy Bypass -File "scripts/Verify-Story-1.1.ps1"

# Compare avec acceptance criteria
# Valide les test cases
```

### 3. Validation
- ✅ Tous les types détectés
- ✅ Counts corrects
- ✅ Severities appropriées
- ✅ Tests passent

### 4. Merge & Next
```bash
git merge feature/story-1.1-smb-ldap-signing
# → Passer à Story suivante
```

---

## 🎯 Milestones

### Milestone 1: Network Security Complete
**Date:** ~2026-02-15
**Version:** v1.3.0 (130 types)
**Achievement:** Protection contre attaques réseau communes

### Milestone 2: Ransomware Ready
**Date:** ~2026-03-01
**Version:** v1.3.1 (137 types)
**Achievement:** Resilience ransomware niveau enterprise

### Milestone 3: Phase 1 Complete - PARITY
**Date:** ~2026-03-22
**Version:** v1.4.0 (152 types)
**Achievement:** 🏆 **Parity avec Ping Castle atteinte**

---

## 📊 Métriques de succès

### Couverture
- ✅ v1.2.11: 122 types (79.7% de Phase 1)
- 🎯 v1.3.0: 130 types (85.0% de Phase 1)
- 🎯 v1.3.1: 137 types (89.5% de Phase 1)
- 🎯 v1.4.0: 152 types (99.3% de Phase 1)

### Comparaison marché
| Outil | Types | Status après v1.4.0 |
|-------|-------|---------------------|
| Ping Castle | ~150 | ≈ Parity |
| ETC Collector v1.4.0 | 152 | ✅ Parity atteinte |
| Purple Knight | ~100 | ✅ Dépassé |

### Valeur business
- Network Security: Critique pour pentests
- Ransomware: Différenciation SaaS
- Trust/GPO/DNS: Enterprise features

---

## 🔄 Workflow Story

```
┌─────────────────┐
│  Story Ready    │
│  (doc créé)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Dev impl.      │
│  (branche)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Claude verify  │
│  (script test)  │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
  ❌ KO    ✅ OK
    │         │
    │         ▼
    │    ┌─────────────┐
    │    │  Merge      │
    │    │  Next Story │
    │    └─────────────┘
    │
    └──▶ Fix & retry
```

---

## 📁 Structure documentation

```
docs/
├── ROADMAP-v1.3-v1.4.md           (ce fichier)
└── stories/
    ├── story-1.1-smb-ldap-signing.md
    ├── story-1.2-ldaps-protocols.md
    ├── story-1.3-legacy-protocols.md
    ├── story-1.4-ntlm-restrictions.md
    ├── story-2.1-ad-recovery.md
    ├── story-2.2-tiering-paw.md
    ├── story-2.3-monitoring-gaps.md
    ├── story-3.1-trust-forest.md
    ├── story-3.2-advanced-gpo.md
    └── story-3.3-dns-security.md
```

---

## 🚦 Next Action

**Commencer par Story 1.1: SMB & LDAP Signing**

Voir: [docs/stories/story-1.1-smb-ldap-signing.md](stories/story-1.1-smb-ldap-signing.md)

---

**Créé par:** Claude Sonnet 4.5
**Date:** 2026-02-01
**Version:** 1.0
