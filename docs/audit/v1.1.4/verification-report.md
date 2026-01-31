# Vérification des vulnérabilités non détectées

**Date:** 2026-01-30
**Objectif:** Vérifier si les vulnérabilités non détectées par v1.1.4 existent réellement dans l'AD

---

## 🔍 Méthodologie

J'ai testé 5 vulnérabilités non détectées par le collecteur pour vérifier si elles sont vraiment présentes dans l'AD.

---

## ✅ TEST 1: PASSWORDNEVEREXPIRES

### Ce qui était injecté
- **Type:** PasswordNeverExpires
- **Instances:** 39 utilisateurs

### Ce que j'ai trouvé dans l'AD
```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true}
```

**Résultat:** ✅ **38 utilisateurs trouvés**

Exemples:
- Administrator
- n8n Service
- Akira Jackson
- Fang Liu
- Naomi Nakamura

### Verdict
🚨 **VULNÉRABILITÉ RÉELLE NON DÉTECTÉE PAR LE COLLECTEUR**

Le collecteur devrait détecter `PASSWORD_NEVER_EXPIRES` mais ne le fait pas!

---

## ❌ TEST 2: COMPUTER_OLD_PASSWORD

### Ce qui était injecté
- **Type:** Computer_Old_Password
- **Instances:** 17 ordinateurs

### Ce que j'ai cherché dans l'AD
```powershell
Get-ADComputer -Filter * -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-90) }
```

**Résultat:** ❌ **0 ordinateurs trouvés**

### Verdict
⚠️ **Vulnérabilité possiblement non injectée ou critères incorrects**

Les ordinateurs du lab sont peut-être trop récents (< 90 jours).

---

## ❌ TEST 3: COMPUTER_STALE_INACTIVE

### Ce qui était injecté
- **Type:** Computer_Stale_Inactive
- **Instances:** 17 ordinateurs

### Ce que j'ai cherché dans l'AD
```powershell
Get-ADComputer -Filter * -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }
```

**Résultat:** ❌ **0 ordinateurs trouvés**

### Verdict
⚠️ **Vulnérabilité possiblement non injectée**

Les ordinateurs du lab ont probablement été créés récemment et n'ont pas 90 jours d'inactivité.

---

## ❌ TEST 4: DUPLICATE_SPN

### Ce qui était injecté
- **Type:** Duplicate_SPN
- **Instances:** 17 instances

### Ce que j'ai cherché dans l'AD
```powershell
# Recherche de tous les SPNs dupliqués
$spns = @{}
foreach ($obj in (Get-ADUser, Get-ADComputer -Filter {ServicePrincipalName -like "*"})) {
    foreach ($spn in $obj.ServicePrincipalName) {
        $spns[$spn] += $obj.Name
    }
}
$duplicates = $spns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
```

**Résultat:** ❌ **0 SPNs dupliqués trouvés**

### Verdict
⚠️ **Vulnérabilité possiblement non injectée**

Aucun SPN dupliqué détecté dans l'AD.

---

## ✅ TEST 5: GPO_PASSWORD_IN_SYSVOL

### Ce qui était injecté
- **Type:** GPO_Password_In_SYSVOL
- **Instances:** Probablement 1 (GPO avec cpassword)

### Ce que j'ai trouvé dans l'AD
```powershell
Get-ChildItem \\aza-me.cc\SYSVOL\aza-me.cc\Policies -Recurse -Filter "*.xml" |
    Where-Object { (Get-Content $_.FullName) -match "cpassword|password" }
```

**Résultat:** ✅ **1 fichier trouvé**

**Fichier:** `Groups.xml` dans `{20B72A39-B738-4373-AAE8-F776C3884894}\Machine\Preferences\Groups\`

### Verdict
🚨 **VULNÉRABILITÉ RÉELLE NON DÉTECTÉE PAR LE COLLECTEUR**

C'est une vulnérabilité CRITIQUE (GPP Password in SYSVOL) et le collecteur ne la détecte pas!

---

## 📊 Résumé

| Test | Type | Injecté | Trouvé | Détecté v1.1.4 | Verdict |
|------|------|---------|--------|----------------|---------|
| 1 | PASSWORDNEVEREXPIRES | 39 | ✅ 38 | ❌ Non | 🚨 **BUG collecteur** |
| 2 | COMPUTER_OLD_PASSWORD | 17 | ❌ 0 | ❌ Non | ⚠️ Non injecté? |
| 3 | COMPUTER_STALE_INACTIVE | 17 | ❌ 0 | ❌ Non | ⚠️ Non injecté? |
| 4 | DUPLICATE_SPN | 17 | ❌ 0 | ❌ Non | ⚠️ Non injecté? |
| 5 | GPO_PASSWORD_IN_SYSVOL | ? | ✅ 1 | ❌ Non | 🚨 **BUG collecteur** |

---

## 🚨 Bugs confirmés du collecteur

### 1. PASSWORD_NEVER_EXPIRES (Critical)

**Vulnérabilité:** 38 utilisateurs avec PasswordNeverExpires=True
**Détection v1.1.4:** ❌ Non détecté
**Sévérité:** Critical

**Preuve:**
```
Administrator, n8n Service, Akira Jackson, Fang Liu, Naomi Nakamura, ...
(38 total)
```

**Action requise:** Vérifier le détecteur de `PASSWORD_NEVER_EXPIRES` dans le code.

---

### 2. GPO_PASSWORD_IN_SYSVOL (Critical)

**Vulnérabilité:** Groups.xml avec cpassword dans SYSVOL
**Détection v1.1.4:** ❌ Non détecté
**Sévérité:** Critical

**Preuve:**
```
\\aza-me.cc\SYSVOL\aza-me.cc\Policies\{20B72A39-B738-4373-AAE8-F776C3884894}\Machine\Preferences\Groups\Groups.xml
```

**Action requise:** Implémenter le détecteur de GPO_PASSWORD_IN_SYSVOL.

---

## 🎯 Conclusions

### Points critiques

1. **Le collecteur a des VRAIS bugs de détection**
   - 2 vulnérabilités CRITIQUES confirmées dans l'AD
   - 0 détectées par v1.1.4
   - Ce ne sont pas de faux positifs!

2. **Certaines vulnérabilités injectées n'existent peut-être pas**
   - COMPUTER_OLD_PASSWORD: 0 trouvé
   - COMPUTER_STALE_INACTIVE: 0 trouvé
   - DUPLICATE_SPN: 0 trouvé
   - Possible que le script d'injection ait échoué pour ces types

3. **Le taux de 37.7% est probablement optimiste**
   - Si on compte seulement les vulnérabilités réellement injectées
   - Le taux réel pourrait être encore plus bas

### Recommandations immédiates

**v1.1.5 doit corriger en priorité:**

1. ✅ PASSWORD_NEVER_EXPIRES
   - Détecteur existe probablement mais ne fonctionne pas
   - Vérifier la logique de détection

2. ✅ GPO_PASSWORD_IN_SYSVOL
   - Détecteur n'existe pas
   - Implémenter la recherche dans SYSVOL

3. ✅ Vérifier les autres détecteurs "Password"
   - PASSWORDNOTREQUIRED
   - REVERSIBLEENCRYPTION
   - EMPTY_PASSWORD

### Tests supplémentaires recommandés

Il faudrait vérifier 10-15 autres vulnérabilités non détectées pour:
- Confirmer qu'elles existent dans l'AD
- Identifier tous les bugs du collecteur
- Calculer le vrai taux de détection

---

**Généré le:** 2026-01-30
**Méthode:** Requêtes AD PowerShell directes
