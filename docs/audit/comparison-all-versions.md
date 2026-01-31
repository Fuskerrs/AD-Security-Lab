# Comparaison complète - v1.1.1 vs v1.1.3 vs v1.1.4

**Date:** 2026-01-30
**Environnement:** GlobalCorp AD Lab (aza-me.cc)
**Vulnérabilités injectées:** 470 instances de 138 types

---

## 📊 Vue d'ensemble

| Métrique | v1.1.1 | v1.1.3 | v1.1.4 | Évolution |
|----------|--------|--------|--------|-----------|
| **Score** | 0/100 | 26/100 | 26/100 | 🟢 +26 |
| **Rating** | Critical | Critical | Critical | = |
| **Findings** | 19,246 ACEs | 6,501 objects | 6,501 objects | 🟢 Meilleure métrique |
| **Instances** | N/A | 19,246 ACEs | 19,246 ACEs | 🟢 Ajouté pour forensics |
| **Types détectés** | 100 | 97 | 98 | = |
| **Types matchés** | 52 | 52 | 52 | = |
| **Taux détection** | 37.7% | 37.7% | 37.7% | = |
| **Durée** | 3.5s | 0.96s | 3.5s | ⚠️ Variable |

---

## 🎯 Innovations par version

### v1.1.1 - ACE Counting (Baseline)

**Approche:**
- Comptage brut de toutes les ACEs
- 1 vulnérabilité ACL → 4,349 ACEs → 4,349 findings

**Problèmes:**
- Score 0/100 (trop sévère)
- 19,246 findings (confus pour le client)
- Compte les ACEs, pas les objets à corriger

**Avantages:**
- Détails forensics complets
- Rien n'est caché
- Transparence totale

**Structure:**
```json
{
  "risk": {
    "score": 0,
    "findings": {
      "total": 19246  // ACEs
    }
  }
}
```

---

### v1.1.3 - Hybrid Approach (Object + Instances)

**Approche:**
- Déduplication par objectDn (6,501 objets uniques)
- Conservation des instances pour forensics (19,246 ACEs)
- Structure hybride: `count` + `totalInstances`

**Améliorations:**
- Score 26/100 (plus réaliste)
- 6,501 objects (actionable pour SysAdmin)
- 19,246 instances (forensics pour pentester)

**Avantages:**
- Satisfait 3 audiences (RSSI, SysAdmin, Pentester)
- Score calculé sur objets (industrie standard)
- Détails ACEs conservés pour drill-down

**Structure:**
```json
{
  "risk": {
    "score": 26,
    "findings": {
      "total": 6501,         // Objects
      "totalInstances": 19246 // ACEs
    }
  },
  "findings": [
    {
      "type": "ACL_WRITEDACL",
      "count": 774,           // Unique objects
      "totalInstances": 4349  // Total ACEs
    }
  ]
}
```

---

### v1.1.4 - Type Name Normalizer

**Approche:**
- ~150 mappings de variations de nommage
- Normalisation automatique dans response-formatter
- Format canonique: UPPERCASE_WITH_UNDERSCORES

**Améliorations:**
- Cohérence des noms de types
- Harmonisation avec industrie (PingCastle, Purple Knight)
- Facilite comparaison et reporting

**Avantages:**
- Output plus professionnel
- Noms prévisibles
- Meilleure intégration

**Limitations:**
- **Taux de détection inchangé** (37.7%)
- Le normalizer ne détecte pas, il renomme
- Détecteurs manquants toujours manquants

**Exemples de normalisation:**
```
PasswordNeverExpires → PASSWORD_NEVER_EXPIRES
AsRepRoastable → ASREP_ROASTING_RISK
UnconstrainedDelegation → UNCONSTRAINED_DELEGATION
Kerberoastable → KERBEROASTING_RISK
ReversibleEncryption → REVERSIBLE_ENCRYPTION
```

---

## 🔍 Analyse comparative détaillée

### Score de sécurité

| Version | Score | Calcul | Justification |
|---------|-------|--------|---------------|
| v1.1.1 | 0/100 | Basé sur 19,246 ACEs | Trop sévère, compte chaque ACE |
| v1.1.3 | 26/100 | Basé sur 6,501 objects | Industrie standard (objets uniques) |
| v1.1.4 | 26/100 | Basé sur 6,501 objects | Identique à v1.1.3 |

**Conclusion:** v1.1.3+ utilise le bon calcul (objets au lieu d'ACEs).

---

### Breakdown par sévérité

#### v1.1.1 (ACEs)
| Sévérité | Count | % |
|----------|-------|---|
| Critical | 264 | 1.4% |
| High | 16,339 | 84.9% |
| Medium | 2,555 | 13.3% |
| Low | 88 | 0.5% |
| **TOTAL** | **19,246** | 100% |

#### v1.1.3 & v1.1.4 (Objects)
| Sévérité | Count | % |
|----------|-------|---|
| Critical | 184 | 2.8% |
| High | 3,852 | 59.3% |
| Medium | 2,377 | 36.6% |
| Low | 88 | 1.4% |
| **TOTAL** | **6,501** | 100% |

**Observation:**
- High: 84.9% (ACEs) → 59.3% (Objects) = Meilleure proportion
- La distribution par sévérité est plus équilibrée avec les objets

---

### Types détectés

| Version | Total types | Critical | High | Medium | Low |
|---------|-------------|----------|------|--------|-----|
| v1.1.1 | 100 | 15 | 44 | 40 | 4 |
| v1.1.3 | 97 | - | - | - | - |
| v1.1.4 | 98 | - | - | - | - |

**Observations:**
- v1.1.3 a 3 types de moins (97 vs 100)
- v1.1.4 a 1 type de plus (98 vs 97)
- Mais le match avec injectés est identique: **52 types**

---

### Taux de détection par catégorie

#### v1.1.1
| Catégorie | Injectés | Détectés | Taux |
|-----------|----------|----------|------|
| ADCS | 11 | 9 | 82% |
| Groups | 11 | 8 | 73% |
| Kerberos | 12 | 7 | 58% |
| Accounts | 25 | 13 | 52% |
| Computers | 27 | 12 | 44% |
| Advanced | 22 | 9 | 41% |
| Passwords | 14 | 3 | 21% |
| Permissions | 15 | 3 | 21% |
| GPO | 5 | 0 | 0% |
| Attack Paths | 7 | 0 | 0% |

#### v1.1.3 & v1.1.4
**Identique à v1.1.1** - Le taux de détection n'a pas changé.

---

## 🎯 Types détectés (52 types communs)

Ces 52 types sont détectés dans **TOUTES** les versions:

1. ACCOUNT_OPERATORS_MEMBER
2. ACL_FORCECHANGEPASSWORD
3. ADMINSDHOLDER_BACKDOOR
4. BACKUP_OPERATORS_MEMBER
5. BUILTIN_MODIFIED
6. COMPUTER_IN_ADMIN_GROUP
7. COMPUTER_NEVER_LOGGED_ON
8. COMPUTER_NO_BITLOCKER
9. COMPUTER_NO_LAPS
10. COMPUTER_OS_OBSOLETE_2003
11. COMPUTER_OS_OBSOLETE_2008
12. COMPUTER_OS_OBSOLETE_VISTA
13. COMPUTER_OS_OBSOLETE_XP
14. COMPUTER_UNCONSTRAINED_DELEGATION
15. COMPUTER_WEAK_ENCRYPTION
16. COMPUTER_WITH_SPNS
17. COMPUTER_WRONG_OU
18. DANGEROUS_GROUP_NESTING
19. DISABLED_ACCOUNT_IN_ADMIN_GROUP
20. DNS_ADMINS_MEMBER
21. DOMAIN_ADMIN_IN_DESCRIPTION
22. ESC10_WEAK_CERTIFICATE_MAPPING
23. ESC11_ICERT_REQUEST_ENFORCEMENT
24. ESC3_ENROLLMENT_AGENT
25. ESC4_VULNERABLE_TEMPLATE_ACL
26. ESC5_PKI_OBJECT_ACL
27. ESC7_CA_VULNERABLE_ACL
28. ESC8_HTTP_ENROLLMENT
29. ESC9_NO_SECURITY_EXTENSION
30. EVERYONE_IN_ACL
31. EXPIRED_ACCOUNT_IN_ADMIN_GROUP
32. GROUP_PROTECTED_USERS_EMPTY
33. NOT_IN_PROTECTED_USERS
34. NTLM_RELAY_OPPORTUNITY
35. OVERSIZED_GROUP_HIGH
36. PRINT_OPERATORS_MEMBER
37. RECYCLE_BIN_DISABLED
38. SENSITIVE_DELEGATION
39. SERVER_OPERATORS_MEMBER
40. SERVICE_ACCOUNT_INTERACTIVE
41. SERVICE_ACCOUNT_NAMING
42. SERVICE_ACCOUNT_NO_PREAUTH
43. SERVICE_ACCOUNT_OLD_PASSWORD
44. SERVICE_ACCOUNT_PRIVILEGED
45. SERVICE_ACCOUNT_WEAK_ENCRYPTION
46. SERVICE_ACCOUNT_WITH_SPN
47. SHARED_ACCOUNT
48. SMARTCARD_NOT_REQUIRED
49. TEST_ACCOUNT
50. WEAK_ENCRYPTION_FLAG
51. WEAK_PASSWORD_POLICY
52. WRITESPN_ABUSE

---

## ❌ Types NON détectés (86 types communs)

Ces 86 types ne sont détectés dans **AUCUNE** version:

### Attack Paths (7) - 0% détection
- PATH_ASREP_TO_ADMIN
- PATH_CERTIFICATE_ESC
- PATH_DELEGATION_CHAIN
- PATH_GPO_TO_DA
- PATH_NESTED_ADMIN
- PATH_SERVICE_TO_DA
- PATH_TRUST_LATERAL

### GPO (4) - 11% détection (1/9 seulement)
- GPO_AUTHENTICATED_USERS_APPLY
- GPO_LINKPOISONING
- GPO_NO_SECURITY_FILTERING
- GPO_PASSWORD_IN_SYSVOL

### Computers (15) - 44% détection
- COMPUTER_ACL_GENERICALL
- COMPUTER_DISABLED_NOT_DELETED
- COMPUTER_DUPLICATE_SPN
- COMPUTER_LEGACY_PROTOCOL_SMBV1
- COMPUTER_LOCAL_ADMIN_MAPPING
- COMPUTER_OLD_PASSWORD (17 instances!)
- COMPUTER_PRE_CREATED (15 instances!)
- COMPUTER_PRE_WIN2000
- COMPUTER_RBCD
- COMPUTER_SENSITIVE_DESCRIPTION
- COMPUTER_SMB_SIGNING_DISABLED
- COMPUTER_STALE_INACTIVE (17 instances!)
- COMPUTER_WEAK_LAPS
- DUPLICATE_SPN

### Passwords (6) - 21% détection
- EMPTY_PASSWORD
- PASSWORDINDESCRIPTION
- PASSWORDNEVEREXPIRES (→ PASSWORD_NEVER_EXPIRES)
- PASSWORDNOTREQUIRED (→ PASSWORD_NOT_REQUIRED)
- REVERSIBLEENCRYPTION (→ REVERSIBLE_ENCRYPTION)
- UNIXUSERPASSWORD_CLEAR

### ACL/Permissions (8)
- ACL_ADDMEMBER (5 instances)
- ACL_DCSYNC
- ACL_GENERICALL_DA
- ACL_GENERICWRITE_SENSITIVEGROUP (5 instances)
- ACL_GENERICWRITE_USER (5 instances)
- ACL_WRITEDACL_OU (5 instances)
- ACL_WRITEDACL_SENSITIVEGROUP
- ACL_WRITEOWNER_SENSITIVEGROUP

### Autres catégories (46)
Voir `v1.1.4/analysis-v1.1.4.md` pour la liste complète.

---

## 📈 Évolution du code

### v1.1.1 → v1.1.3

**Changements:**
```typescript
// Avant (v1.1.1)
findings.total = allACEs.length; // 19,246

// Après (v1.1.3)
const uniqueObjects = getUniqueObjects(allACEs);
findings.total = uniqueObjects.length; // 6,501
findings.totalInstances = allACEs.length; // 19,246

function getUniqueObjects(entities) {
  const seen = new Set();
  return entities.filter(e => {
    if (seen.has(e.objectDn)) return false;
    seen.add(e.objectDn);
    return true;
  });
}
```

**Fichiers modifiés:**
- `src/services/audit/response-formatter.ts`
- `src/utils/deduplication.ts` (nouveau)

---

### v1.1.3 → v1.1.4

**Changements:**
```typescript
// Nouveau fichier: src/utils/type-name-normalizer.ts
const typeNameMap = {
  'PasswordNeverExpires': 'PASSWORD_NEVER_EXPIRES',
  'AsRepRoastable': 'ASREP_ROASTING_RISK',
  'UnconstrainedDelegation': 'UNCONSTRAINED_DELEGATION',
  // ... ~150 mappings
};

function normalizeTypeName(rawType: string): string {
  return typeNameMap[rawType] || rawType.toUpperCase();
}

// Intégration dans response-formatter.ts
findings.forEach(f => {
  f.type = normalizeTypeName(f.type);
});
```

**Fichiers modifiés:**
- `src/utils/type-name-normalizer.ts` (nouveau)
- `src/services/audit/response-formatter.ts`

---

## 🎯 Impact sur les audiences

### RSSI (Risk Officer)

| Version | Métrique | Impact |
|---------|----------|--------|
| v1.1.1 | Score: 0/100, 19k findings | ❌ Inacceptable |
| v1.1.3 | Score: 26/100, 6.5k objects | ✅ Compréhensible |
| v1.1.4 | Score: 26/100, 6.5k objects | ✅ Identique |

**Verdict:** v1.1.3+ est bien plus clair pour présenter au management.

---

### SysAdmin (Correction)

| Version | Métrique | Impact |
|---------|----------|--------|
| v1.1.1 | 19,246 ACEs à corriger | ❌ Confus (ACEs != Objets) |
| v1.1.3 | 6,501 objets à corriger | ✅ Actionable |
| v1.1.4 | 6,501 objets, noms clairs | ✅ Meilleur |

**Verdict:** v1.1.4 est le meilleur pour l'action (noms normalisés + objets uniques).

---

### Pentester (Forensics)

| Version | Métrique | Impact |
|---------|----------|--------|
| v1.1.1 | 19,246 ACEs détaillées | ✅ Complet |
| v1.1.3 | 6,501 objects + 19,246 instances | ✅ Hybride parfait |
| v1.1.4 | Identique + noms normalisés | ✅ Optimal |

**Verdict:** v1.1.3+ conserve tous les détails forensics (totalInstances).

---

## 🏆 Classement par cas d'usage

### Meilleure pour le score: v1.1.3 & v1.1.4
- Score réaliste (26/100)
- Méthodologie industrie standard
- Basé sur objets, pas ACEs

### Meilleure pour l'action: v1.1.4
- Noms de types normalisés
- Objets uniques à corriger
- Cohérence professionnelle

### Meilleure pour le forensics: v1.1.3 & v1.1.4
- Conservation de totalInstances
- Drill-down possible
- Aucun détail perdu

### Meilleure pour la détection: Aucune
- Les 3 versions détectent exactement les mêmes 52 types
- Taux: 37.7% constant
- Besoin d'améliorer les détecteurs (pas juste la présentation)

---

## 🔮 Recommandations

### Court terme

1. ✅ **Utiliser v1.1.4** en production
   - Structure hybride (objects + instances)
   - Noms normalisés
   - Score réaliste

2. ❌ **Ne pas rester sur v1.1.1**
   - Score 0/100 inacceptable
   - Comptage ACE confus
   - Présentation non-professionnelle

### Moyen terme

**v1.1.5 - Attack Paths Detection**
- Implémenter les 7 types Attack Paths
- Objectif: 37.7% → 42-45%

**v1.1.6 - GPO Security**
- Implémenter les 4 types GPO manquants
- Objectif: 45% → 48-50%

**v1.1.7 - Computer Detection**
- Corriger les 15 types Computer manquants
- Objectif: 50% → 55-58%

### Long terme

**v1.2.0 - Coverage Goal**
- Objectif: 70%+ de couverture
- Implémenter Passwords (6 types)
- Implémenter Advanced (10 types)
- Implémenter ACL avancés (8 types)

---

## 📊 Conclusion finale

### Ce qui a changé entre les versions

| Aspect | Changement |
|--------|------------|
| **Méthodologie de comptage** | 🟢 ACEs → Objects (v1.1.3) |
| **Structure de données** | 🟢 Hybride objects+instances (v1.1.3) |
| **Cohérence des noms** | 🟢 Normalizer (v1.1.4) |
| **Score** | 🟢 0 → 26 (v1.1.3) |
| **Présentation** | 🟢 Amélioration continue |

### Ce qui n'a PAS changé

| Aspect | Status |
|--------|--------|
| **Taux de détection** | 🔴 37.7% (constant) |
| **Types détectés** | 🔴 52/138 (constant) |
| **Détecteurs implémentés** | 🔴 Identiques |
| **Attack Paths** | 🔴 0% (toujours) |
| **GPO** | 🔴 11% (toujours) |

### Verdict final

**v1.1.4 est la meilleure version pour la présentation et le reporting**, mais:
- ⚠️ **La détection n'a pas progressé**
- ⚠️ **Il faut maintenant améliorer les détecteurs**, pas la présentation
- ✅ **La structure est bonne**, il faut maintenant remplir les trous

**Prochaine priorité:** Implémenter les détecteurs manquants (Attack Paths, GPO, Computers).

---

**Généré le :** 2026-01-30 19:55
**Auteur :** Analysis complète des 3 versions
