# Stories - ETC Collector Development

Ce dossier contient les User Stories pour le développement itératif de l'ETC Collector.

---

## 📋 Process

### 1. Story Ready
- Story créée avec acceptance criteria
- Tests définis
- Expected results documentés

### 2. Development
```bash
# Dev crée une branche
git checkout -b feature/story-X.X-nom

# Développe les détecteurs
# Tests
# Commit
git commit -m "Implement story X.X: nom"
git push
```

### 3. Verification
```bash
# Deploy nouvelle version
# Run audit
curl -X POST http://localhost:3000/api/v1/audit/ad?async=true

# Claude vérifie avec script
powershell -ExecutionPolicy Bypass -File "scripts/Verify-Story-X.X.ps1"
```

### 4. Validation
- ✅ Tous les types détectés
- ✅ Counts corrects
- ✅ Severities appropriées
- ✅ Tests passent
- ✅ Documentation à jour

### 5. Merge & Next
```bash
git checkout main
git merge feature/story-X.X-nom
# → Passer à Story suivante
```

---

## 🚀 Sprint 1: Network Security (v1.3.0)

| Story | Types | Status | Effort |
|-------|-------|--------|--------|
| [1.1 - SMB & LDAP Signing](story-1.1-smb-ldap-signing.md) | 2 | 📋 TO DO | 3j |
| [1.2 - LDAPS & Protocols](story-1.2-ldaps-protocols.md) | 2 | 📋 TO DO | 2j |
| [1.3 - Legacy Protocols](story-1.3-legacy-protocols.md) | 3 | 📋 TO DO | 3j |
| [1.4 - NTLM Restrictions](story-1.4-ntlm-restrictions.md) | 1 | 📋 TO DO | 2j |

**Total:** 8 types, ~10 jours

---

## 🛡️ Sprint 2: Ransomware Resilience (v1.3.1)

| Story | Types | Status | Effort |
|-------|-------|--------|--------|
| 2.1 - AD Recovery | 3 | 📋 Planned | 4j |
| 2.2 - Tiering & PAW | 2 | 📋 Planned | 3j |
| 2.3 - Monitoring Gaps | 2 | 📋 Planned | 3j |

**Total:** 7 types, ~10 jours

---

## 🌲 Sprint 3: Trust, GPO & DNS (v1.4.0)

| Story | Types | Status | Effort |
|-------|-------|--------|--------|
| 3.1 - Trust & Forest | 6 | 📋 Planned | 5j |
| 3.2 - Advanced GPO | 5 | 📋 Planned | 5j |
| 3.3 - DNS Security | 4 | 📋 Planned | 5j |

**Total:** 15 types, ~15 jours

---

## 📊 Status Legend

- 📋 **TO DO** - Story prête, dev peut commencer
- 🏗️ **IN PROGRESS** - Dev en cours
- ✅ **DONE** - Story complétée et vérifiée
- 📋 **Planned** - À créer

---

## 🎯 Next Action

**Commencer Story 1.1: SMB & LDAP Signing**

1. Lire [story-1.1-smb-ldap-signing.md](story-1.1-smb-ldap-signing.md)
2. Créer branche `feature/story-1.1-smb-ldap-signing`
3. Implémenter détecteurs
4. Tester sur lab
5. Notifier Claude pour vérification

---

**Maintenu par:** Claude Sonnet 4.5
**Date:** 2026-02-01
