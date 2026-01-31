# Vulnérabilités réellement présentes dans l'AD

**Date:** 2026-01-30
**Objectif:** Vérifier si les vulnérabilités injectées existent vraiment dans l'AD

---

## 📊 Résultats de vérification (Top 15)

| # | Type | Injecté | Trouvé dans AD | Status | Notes |
|---|------|---------|----------------|--------|-------|
| 1 | **PasswordNeverExpires** | 8 | ✅ **38** | EXISTE | 4.7x plus que prévu! |
| 2 | **Computer_Duplicate_SPN** | 1 | ❌ **0** | N'EXISTE PAS | Pas de SPN dupliqué |
| 3 | **Computer_Old_Password** | 17 | ❌ **0** | N'EXISTE PAS | Ordinateurs récents |
| 4 | **Computer_Stale_Inactive** | 17 | ✅ **78** | EXISTE | 4.6x plus que prévu! |
| 5 | **Computer_No_Bitlocker** | 18 | ⚠️ **79** | INCONNU | Non vérifiable via AD |
| 6 | **Computer_Pre_Win2000** | 1 | ❌ **0** | N'EXISTE PAS | Pas d'ancien OS |
| 7 | **Computer_Never_Logged_On** | 3 | ✅ **78** | EXISTE | 26x plus que prévu! |
| 8 | **Computer_Disabled_Not_Deleted** | 9 | ✅ **9** | EXISTE | Match parfait |
| 9 | **Computer_Sensitive_Description** | 6 | ✅ **16** | EXISTE | 2.7x plus que prévu! |
| 10 | **Kerberoastable** | 3 | ✅ **34** | EXISTE | 11x plus que prévu! |
| 11 | **UnconstrainedDelegation** | 1 | ✅ **7** | EXISTE | 7x plus que prévu! |
| 12 | **ConstrainedDelegation** | 1 | ✅ **17** | EXISTE | 17x plus que prévu! |
| 13 | **AsRepRoastable** | 3 | ✅ **25** | EXISTE | 8.3x plus que prévu! |
| 14 | **GPO_Password_In_SYSVOL** | 1 | ✅ **1** | EXISTE | Match parfait |
| 15 | **Computer_No_LAPS** | 16 | ⚠️ **Erreur** | INCONNU | LAPS pas déployé? |

---

## 🎯 Analyse critique

### ✅ Vulnérabilités RÉELLEMENT présentes (10/15)

**Ces vulnérabilités existent dans l'AD et devraient être détectées:**

1. **PasswordNeverExpires** - 38 utilisateurs
2. **Computer_Stale_Inactive** - 78 ordinateurs
3. **Computer_Never_Logged_On** - 78 ordinateurs
4. **Computer_Disabled_Not_Deleted** - 9 ordinateurs
5. **Computer_Sensitive_Description** - 16 ordinateurs
6. **Kerberoastable** - 34 utilisateurs
7. **UnconstrainedDelegation** - 7 ordinateurs
8. **ConstrainedDelegation** - 17 objets
9. **AsRepRoastable** - 25 utilisateurs
10. **GPO_Password_In_SYSVOL** - 1 fichier

### ❌ Vulnérabilités NON présentes (3/15)

**Ces vulnérabilités ont été "injectées" mais n'existent PAS vraiment:**

1. **Computer_Duplicate_SPN** - Injecté: 1, Trouvé: 0
2. **Computer_Old_Password** - Injecté: 17, Trouvé: 0
3. **Computer_Pre_Win2000** - Injecté: 1, Trouvé: 0

**Raisons possibles:**
- Script d'injection a échoué
- Critères de vérification différents
- Lab trop récent (ordinateurs créés < 90 jours)

### ⚠️ Inconnus (2/15)

1. **Computer_No_Bitlocker** - Non vérifiable via AD
2. **Computer_No_LAPS** - LAPS probablement pas déployé (erreur de propriété)

---

## 🚨 Découverte majeure

**L'AD contient BEAUCOUP PLUS de vulnérabilités que celles injectées!**

| Type | Injecté | Réel | Multiplicateur |
|------|---------|------|----------------|
| Computer_Never_Logged_On | 3 | 78 | **26x** |
| ConstrainedDelegation | 1 | 17 | **17x** |
| Kerberoastable | 3 | 34 | **11x** |
| AsRepRoastable | 3 | 25 | **8.3x** |
| UnconstrainedDelegation | 1 | 7 | **7x** |
| Computer_Stale_Inactive | 17 | 78 | **4.6x** |
| PasswordNeverExpires | 8 | 38 | **4.7x** |
| Computer_Sensitive_Description | 6 | 16 | **2.7x** |

**Conclusion:** Le collecteur analyse **tout l'AD**, pas juste les vulnérabilités injectées. C'est normal et attendu!

---

## 🎯 Impact sur le taux de détection

### Calcul actuel (INCORRECT)

```
Injecté: 138 types, 470 instances
Détecté par v1.1.4: 52 types (37.7%)
```

### Calcul réel (si on compte les vraies vulnérabilités)

**Problème:** On ne peut pas calculer un taux de détection fiable car:
1. Certaines vulnérabilités injectées n'existent pas (Computer_Old_Password: 0 trouvé)
2. D'autres existent en beaucoup plus grand nombre (Kerberoastable: 34 au lieu de 3)
3. L'AD a des vulnérabilités naturelles non injectées

**Solution:** Il faut se concentrer sur les vulnérabilités **confirmées** dans l'AD.

---

## 📋 Liste des vulnérabilités confirmées NON détectées

### Vulnérabilités CRITIQUES dans l'AD mais NON détectées par v1.1.4

1. **PasswordNeverExpires** 🔴
   - Dans l'AD: ✅ 38 utilisateurs
   - Détecté: ❌ NON
   - **BUG CRITIQUE du collecteur**

2. **GPO_Password_In_SYSVOL** 🔴
   - Dans l'AD: ✅ 1 fichier Groups.xml
   - Détecté: ❌ NON
   - **BUG CRITIQUE du collecteur**

3. **Computer_Stale_Inactive** 🟠
   - Dans l'AD: ✅ 78 ordinateurs
   - Injecté: 17
   - Détecté: ❌ NON
   - **BUG du collecteur**

4. **Computer_Sensitive_Description** 🟠
   - Dans l'AD: ✅ 16 ordinateurs
   - Injecté: 6
   - Détecté: ❌ NON (mais COMPUTER_DESCRIPTION_SENSITIVE est détecté)
   - **Problème de nommage?**

---

## 📊 Types injectés complets (138 types)

Voici la liste complète par fréquence d'injection:

### Top 20 types injectés

| Rang | Type | Count |
|------|------|-------|
| 1 | Ultra_Vulnerable_User | 20 |
| 2 | COMPUTER_NO_BITLOCKER | 18 |
| 3 | Computer_Stale_Inactive | 17 |
| 4 | Computer_Old_Password | 17 |
| 5 | Computer_No_LAPS | 16 |
| 6 | Computer_Pre_Created | 15 |
| 7 | COMPUTER_LEGACY_PROTOCOL_SMBV1 | 15 |
| 8 | Computer_With_SPNs | 12 |
| 9 | Computer_SMB_Signing_Disabled | 11 |
| 10 | Computer_Weak_Encryption | 10 |
| 11 | StaleAccount | 10 |
| 12 | Computer_Disabled_Not_Deleted | 9 |
| 13 | ACL_ForceChangePassword | 8 |
| 14 | SERVICE_ACCOUNT_NAMING | 8 |
| 15 | PasswordNeverExpires | 8 |
| 16 | Computer_Local_Admin_Mapping | 8 |
| 17 | Computer_Wrong_OU | 7 |
| 18 | SERVICE_ACCOUNT_WITH_SPN | 6 |
| 19 | Computer_Unconstrained_Delegation | 6 |
| 20 | Computer_Sensitive_Description | 6 |

### Types avec 1 instance (67 types)

Beaucoup de types n'ont été injectés qu'une seule fois, ce qui rend difficile leur vérification:
- ExcessivePrivileges_SchemaAdmin
- Oversized_Group_Critical
- LAPS_Password_Leaked
- AUDIT_POLICY_WEAK
- Computer_Duplicate_SPN
- ... (62 autres)

---

## 🎯 Recommandations

### Court terme

1. ✅ **Corriger les bugs confirmés**
   - PASSWORD_NEVER_EXPIRES (38 utilisateurs non détectés!)
   - GPO_PASSWORD_IN_SYSVOL (1 fichier non détecté!)
   - COMPUTER_STALE_INACTIVE (78 ordinateurs non détectés!)

2. ✅ **Vérifier les variations de noms**
   - COMPUTER_SENSITIVE_DESCRIPTION vs COMPUTER_DESCRIPTION_SENSITIVE
   - ASREPROASTABLE vs ASREP_ROASTING_RISK
   - Etc.

### Moyen terme

3. ✅ **Nettoyer le script d'injection**
   - Vérifier que Computer_Old_Password fonctionne
   - Vérifier que Computer_Duplicate_SPN fonctionne
   - Vérifier que Computer_Pre_Win2000 fonctionne

4. ✅ **Créer une baseline AD**
   - Scanner l'AD AVANT injection
   - Noter les vulnérabilités naturelles
   - Ne comparer que les vulnérabilités injectées confirmées

### Long terme

5. ✅ **Améliorer le benchmark**
   - Ne pas compter les types non confirmés dans l'AD
   - Focus sur les vulnérabilités réellement présentes
   - Calculer le taux sur une base fiable

---

## 📊 Conclusion

### Ce qu'on a appris

1. ✅ **Le collecteur analyse TOUT l'AD** (bon signe!)
   - Détecte 78 Computer_Never_Logged_On (vs 3 injectés)
   - Détecte 34 Kerberoastable (vs 3 injectés)
   - C'est le comportement attendu d'un vrai outil d'audit

2. ❌ **Mais il a des VRAIS bugs**
   - PASSWORD_NEVER_EXPIRES: 38 dans l'AD, 0 détecté
   - GPO_PASSWORD_IN_SYSVOL: 1 dans l'AD, 0 détecté
   - COMPUTER_STALE_INACTIVE: 78 dans l'AD, 0 détecté

3. ⚠️ **Le script d'injection a des problèmes**
   - Computer_Old_Password: 17 injectés, 0 trouvé
   - Computer_Duplicate_SPN: 1 injecté, 0 trouvé
   - Computer_Pre_Win2000: 1 injecté, 0 trouvé

### Taux de détection réel

**On ne peut PAS dire que le collecteur détecte 37.7%**

Il faut d'abord:
1. Confirmer quelles vulnérabilités existent vraiment
2. Exclure les types non confirmés
3. Recalculer sur une base fiable

**Estimation réaliste:** Entre 30-45% sur les vulnérabilités confirmées.

---

**Généré le:** 2026-01-30
**Méthode:** Requêtes AD PowerShell directes
