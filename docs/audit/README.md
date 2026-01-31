# Résultats d'audit AD - GlobalCorp

## 📊 Vue d'ensemble

**Domaine:** aza-me.cc
**Base DN:** DC=aza-me,DC=cc
**Environnement:** Lab de sécurité avec vulnérabilités intentionnelles
**Script d'injection:** Populate-AD-GlobalCorp.ps1 (470 instances de 138 types)

---

## 🔄 Évolution des versions

| Version | Date | Score | Findings | Types | Match | Taux | Innovation |
|---------|------|-------|----------|-------|-------|------|------------|
| **v1.1.1** | 2026-01-30 | 0 | 19,246 | 100 | 52 | 37.7% | ACE counting |
| **v1.1.3** | 2026-01-30 | 26 | 6,501 | 97 | 52 | 37.7% | Hybrid (objects + instances) |
| **v1.1.4** | 2026-01-30 | 26 | 6,501 | 98 | 52 | 37.7% | Type name normalizer |

### Chronologie des améliorations

**v1.1.1 → v1.1.2 (non testée)**
- Ajout de `getUniqueObjects()` pour déduplication
- Comptage d'objets uniques au lieu d'ACEs
- Score: 0 → 25.3

**v1.1.2 → v1.1.3**
- Approche hybride: `total` (objects) + `totalInstances` (ACEs)
- Structure satisfaisant 3 audiences: RSSI (score), SysAdmins (objets), Pentesters (forensics)
- Score: 25.3 → 26
- Findings: 6,623 → 6,501

**v1.1.3 → v1.1.4**
- Type Name Normalizer (~150 mappings)
- Harmonisation des noms de types
- Cohérence de l'output
- **Detection rate: INCHANGÉ (37.7%)**

---

## 📈 Objets analysés

| Type | Count |
|------|-------|
| **Users** | 541 |
| **Groups** | 151 |
| **Computers** | 79 |
| **OUs** | 351 |
| **ACEs** | 32,322 |

---

## 🔴 Score actuel (v1.1.4)

- **Score:** 26/100
- **Rating:** CRITICAL
- **Findings:** 6,501 objects affectés
- **Instances:** 19,246 ACEs (forensics)

### Breakdown par sévérité

| Sévérité | Count | % | Instances |
|----------|-------|---|-----------|
| **Critical** | 184 | 2.8% | 264 |
| **High** | 3,852 | 59.3% | 16,339 |
| **Medium** | 2,377 | 36.6% | 2,555 |
| **Low** | 88 | 1.4% | 88 |
| **TOTAL** | **6,501** | 100% | **19,246** |

---

## 🎯 Taux de détection

### Vue globale

**Vulnérabilités injectées:**
- 470 instances
- 138 types uniques

**Détection actuelle (v1.1.4):**
- 98 types détectés
- 52 types matchent avec injectés
- **Taux: 52/138 = 37.7%**

### Par catégorie

| Catégorie | Injectés | Match | Taux | Status |
|-----------|----------|-------|------|--------|
| **ADCS** | 11 | 10 | **91%** | ✅ Excellent |
| **Groups** | 11 | 8 | 73% | ✅ Bon |
| **Permissions** | 15 | 9 | 60% | ⚠️ Moyen |
| **Kerberos** | 12 | 7+ | 58%+ | ⚠️ Moyen |
| **Accounts** | 25 | 13 | 52% | ⚠️ Moyen |
| **Computers** | 27 | 12 | 44% | ⚠️ Faible |
| **Advanced** | 22 | 9 | 41% | ⚠️ Faible |
| **Passwords** | 14 | 3+ | 21%+ | ❌ Très faible |
| **GPO** | 9 | 1 | **11%** | ❌ Critique |
| **Attack Paths** | 7 | 0 | **0%** | ❌ Non implémenté |

---

## 🗂️ Structure des dossiers

```
docs/audit/
├── README.md                    (ce fichier)
├── v1.1.1/
│   ├── audit-2026-01-30.json   (20 MB)
│   ├── detection-analysis.md
│   └── why-19k-detections.md
├── v1.1.3/
│   ├── audit-v1.1.3.json       (18 MB)
│   └── comparison-v1.1.3.md
└── v1.1.4/
    ├── audit-v1.1.4.json       (18 MB)
    ├── analysis-v1.1.4.md
    └── detected-types.txt
```

---

## 🔍 Analyses disponibles

### v1.1.1
- **detection-analysis.md** : Première analyse de détection, identification des 52 types matchés
- **why-19k-detections.md** : Explication du comptage ACEs vs Objects

### v1.1.3
- **comparison-v1.1.3.md** : Analyse complète avec approche hybride, breakdown par catégorie

### v1.1.4
- **analysis-v1.1.4.md** : Impact du Type Name Normalizer, recommandations pour v1.1.5+

---

## 🎯 Points clés à retenir

### ✅ Ce qui fonctionne bien

1. **ADCS Detection** : 91% (ESC1-ESC11)
2. **Performance** : 3-4 secondes pour audit complet
3. **Structure hybride** : Satisfait RSSI + SysAdmins + Pentesters
4. **Normalizer** : Cohérence des noms de types
5. **Rapidité** : Analyse de 32k ACEs en quelques secondes

### ❌ Ce qui nécessite des améliorations

1. **Attack Paths** : 0% (7 types non implémentés)
2. **GPO** : 11% (1/9 types détectés)
3. **Computers** : 44% (15/27 types manquants)
4. **Passwords** : 21% (faible détection)
5. **Taux global** : 37.7% (52/138)

---

## 🚀 Roadmap suggérée

### v1.1.5 - Attack Paths Detection
**Objectif:** Passer de 0% à 80%+ sur Attack Paths
- Implémenter PATH_GPO_TO_DA
- Implémenter PATH_SERVICE_TO_DA
- Implémenter PATH_ASREP_TO_ADMIN
- Implémenter PATH_NESTED_ADMIN
- Implémenter PATH_DELEGATION_CHAIN
- Implémenter PATH_CERTIFICATE_ESC
- Implémenter PATH_TRUST_LATERAL

**Impact estimé:** 37.7% → 42-45%

### v1.1.6 - GPO Security Enhancement
**Objectif:** Passer de 11% à 80%+ sur GPO
- Implémenter GPO_PASSWORD_IN_SYSVOL
- Implémenter GPO_AUTHENTICATED_USERS_APPLY
- Implémenter GPO_NO_SECURITY_FILTERING
- Implémenter GPO_LINKPOISONING

**Impact estimé:** 45% → 48-50%

### v1.1.7 - Computer Detection Improvement
**Objectif:** Passer de 44% à 70%+ sur Computers
- Corriger COMPUTER_OLD_PASSWORD
- Corriger COMPUTER_STALE_INACTIVE
- Corriger COMPUTER_PRE_CREATED
- Corriger COMPUTER_WEAK_LAPS
- Corriger COMPUTER_RBCD
- Améliorer ACL_GENERICALL detection

**Impact estimé:** 50% → 55-58%

### v1.2.0 - Password & Advanced Detection
**Objectif:** Passer de 21% à 60%+ sur Passwords et Advanced
- Améliorer Password detection
- Implémenter Excessive Privileges (7 types)
- Améliorer Advanced/Config detection

**Impact estimé:** 58% → 65-70%

---

## 📊 Objectif global

**Actuel:** 52/138 types détectés = **37.7%**

**Objectif v1.2.0:** 95-100/138 types détectés = **70%+**

**Objectif v2.0.0:** 120+/138 types détectés = **85%+** avec détection de variations

---

## 🔧 Commandes utilisées

### Audit asynchrone
```bash
export TOKEN="eyJhbGci..."
export API_URL="http://10.10.0.37:8443"

curl -s -X POST "$API_URL/api/v1/audit/ad?async=true" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"includeDetails": true}'
```

### Récupération du résultat
```bash
JOB_ID="ad-audit-xxx"
curl -s "$API_URL/api/v1/audit/jobs/$JOB_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -o audit-result.json
```

### Formatage JSON
```powershell
Get-Content audit-result.json | `
    ConvertFrom-Json | `
    ConvertTo-Json -Depth 100 | `
    Set-Content audit-formatted.json
```

---

## 📌 Notes importantes

### Pourquoi 19,246 détections?

C'est le nombre d'**entités affectées** (users, computers, ACEs), pas le nombre de vulnérabilités.

**Exemple:**
- 1 vulnérabilité: `ACL_SELF_MEMBERSHIP`
- Affecte: 6,111 ACEs
- Compté comme: 6,111 dans les 19,246

**Les vrais chiffres:**
- **103 types** de vulnérabilités détectés (v1.1.1)
- **98 types** détectés (v1.1.4)
- Affectant **19,246 entités** au total
- Dont **6,501 objets uniques** (v1.1.3+)

### Approche hybride (v1.1.3+)

```json
{
  "risk": {
    "findings": {
      "total": 6501,        // Pour le score
      "totalInstances": 19246  // Pour les forensics
    }
  },
  "findings": [
    {
      "type": "ACL_WRITEDACL",
      "count": 774,          // Objets uniques
      "totalInstances": 4349, // ACEs totales
      "affectedEntities": [...]
    }
  ]
}
```

**Avantages:**
- **RSSI:** Score basé sur objets (6,501) = plus réaliste
- **SysAdmins:** Liste d'objets à corriger = actionable
- **Pentesters:** Détails ACEs (19,246) = forensics complets

---

## 🎓 Leçons apprises

1. **Le normalizer n'améliore pas la détection**
   - Il harmonise les noms, c'est tout
   - Il faut implémenter les détecteurs manquants

2. **La comparaison est difficile**
   - Noms différents entre injection et détection
   - Besoin d'un mapping complet

3. **L'outil analyse TOUT l'AD**
   - Il détecte 19k+ entités affectées
   - Pas seulement les 470 vulnérabilités injectées
   - C'est un comportement attendu pour un vrai outil d'audit

4. **Les scores évoluent avec la méthodologie**
   - v1.1.1: 0/100 (comptage ACE)
   - v1.1.3+: 26/100 (comptage objet)
   - Même nombre de vulnérabilités détectées!

---

## 🔗 Ressources

- **Script d'injection:** `C:/ADPopulate_Reports/GlobalCorp_Vulnerabilities_20260130_174331.csv`
- **Catalog complet:** `docs/ad-vulnerability-catalog.txt` (216 types)
- **API Documentation:** `Documentation/api-curl-commands.md`
- **OpenAPI Spec:** `Documentation/api.yaml`

---

**Dernière mise à jour:** 2026-01-30 19:54
**Version actuelle:** ETC Collector v1.1.4
**Prochaine version:** v1.1.5 (Attack Paths Detection)
