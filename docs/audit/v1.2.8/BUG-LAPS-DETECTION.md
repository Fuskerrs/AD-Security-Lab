# Bug Report: COMPUTER_NO_LAPS Detection

**Date:** 2026-02-01
**Version:** v1.2.8
**Severity:** 🔴 HIGH
**Status:** ❌ Bug confirmé

---

## 🐛 Problème

Le détecteur `COMPUTER_NO_LAPS` **sous-estime gravement** le nombre de computers sans protection LAPS.

### Détection actuelle (v1.2.8)
```json
{
  "type": "COMPUTER_NO_LAPS",
  "count": 1,
  "severity": "medium",
  "details": {
    "note": "LAPS not deployed - local admin passwords are not being rotated."
  }
}
```

### Réalité vérifiée (AD manuel)
- **Schéma LAPS:** ❌ NON étendu
- **Total computers:** 95
- **Computers SANS LAPS:** **95** (TOUS!)

### Impact du bug
| Métrique | Détecté | Réel | Écart |
|----------|---------|------|-------|
| Count | 1 | 95 | **-94** |
| Severity | medium | HIGH | Sous-estimé |
| Risk | Faible | CRITIQUE | Masqué |

---

## 🔍 Root Cause

Le détecteur ne vérifie **pas si le schéma LAPS est étendu** avant de compter les computers.

**Schéma LAPS non étendu = aucun computer ne peut avoir LAPS**

### Attributs LAPS absents du schéma
```powershell
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
  -Filter * -Properties name |
  Where-Object { $_.name -like '*mcs-admpwd*' -or $_.name -like '*mslaps*' }
# Résultat: VIDE (aucun attribut trouvé)
```

Les attributs suivants n'existent pas:
- `ms-Mcs-AdmPwd`
- `ms-Mcs-AdmPwdExpirationTime`
- `msLAPS-Password`
- `msLAPS-PasswordExpirationTime`

---

## 💡 Solution

Le détecteur doit faire une vérification en 2 étapes:

### Étape 1: Vérifier si le schéma LAPS existe

```typescript
// Check if LAPS schema is extended
const lapsSchemaExists = await checkSchemaAttribute('ms-Mcs-AdmPwd');

if (!lapsSchemaExists) {
  // Schema not extended = ALL computers lack LAPS
  return {
    type: 'COMPUTER_NO_LAPS',
    count: totalComputers,
    severity: 'high',
    details: {
      note: 'LAPS schema not extended - ALL computers lack LAPS protection',
      totalComputers: totalComputers,
      schemaExtended: false
    }
  };
}
```

### Étape 2: Si schéma existe, compter computers sans LAPS

```typescript
// Schema exists, count computers without LAPS attributes populated
const computersWithoutLAPS = computers.filter(computer => {
  const hasLegacyLAPS = computer['ms-Mcs-AdmPwdExpirationTime'];
  const hasWindowsLAPS = computer['msLAPS-PasswordExpirationTime'];

  return !hasLegacyLAPS && !hasWindowsLAPS;
});

return {
  type: 'COMPUTER_NO_LAPS',
  count: computersWithoutLAPS.length,
  severity: computersWithoutLAPS.length > 0 ? 'high' : 'info',
  details: {
    note: `${computersWithoutLAPS.length} computers without LAPS`,
    totalComputers: computers.length,
    schemaExtended: true,
    coveragePercent: ((computers.length - computersWithoutLAPS.length) / computers.length * 100).toFixed(1)
  }
};
```

---

## 📝 Fonction helper nécessaire

```typescript
/**
 * Check if an attribute exists in AD schema
 */
async function checkSchemaAttribute(attributeName: string): Promise<boolean> {
  try {
    const schemaDN = await getRootDSE().then(r => r.schemaNamingContext);

    const result = await ldapSearch({
      base: schemaDN,
      scope: 'sub',
      filter: `(lDAPDisplayName=${attributeName})`,
      attributes: ['lDAPDisplayName']
    });

    return result.length > 0;
  } catch (error) {
    logger.warn(`Failed to check schema attribute ${attributeName}:`, error);
    return false;
  }
}
```

---

## 🧪 Cas de test

### Test 1: Schéma LAPS non étendu
**Input:**
- AD sans extension schéma LAPS
- 95 computers dans le domaine

**Expected output:**
```json
{
  "type": "COMPUTER_NO_LAPS",
  "count": 95,
  "severity": "high",
  "details": {
    "note": "LAPS schema not extended - ALL computers lack LAPS protection",
    "totalComputers": 95,
    "schemaExtended": false
  }
}
```

### Test 2: Schéma LAPS étendu, LAPS déployé sur tous
**Input:**
- AD avec schéma LAPS
- 95 computers, tous avec `ms-Mcs-AdmPwdExpirationTime` rempli

**Expected output:**
```json
{
  "type": "COMPUTER_NO_LAPS",
  "count": 0,
  "severity": "info",
  "details": {
    "note": "All computers have LAPS protection",
    "totalComputers": 95,
    "schemaExtended": true,
    "coveragePercent": "100.0"
  }
}
```

### Test 3: Schéma LAPS étendu, déploiement partiel
**Input:**
- AD avec schéma LAPS
- 95 computers, 80 avec LAPS, 15 sans LAPS

**Expected output:**
```json
{
  "type": "COMPUTER_NO_LAPS",
  "count": 15,
  "severity": "high",
  "details": {
    "note": "15 computers without LAPS",
    "totalComputers": 95,
    "schemaExtended": true,
    "coveragePercent": "84.2"
  }
}
```

---

## 📊 Impact business

### Avant fix (v1.2.8)
- ❌ Détection: 1 computer sans LAPS
- ❌ Severity: medium
- ❌ Risque perçu: Faible
- ❌ Admin pense: "Presque tout est OK"

### Après fix
- ✅ Détection: 95 computers sans LAPS
- ✅ Severity: HIGH
- ✅ Risque perçu: CRITIQUE
- ✅ Admin comprend: "LAPS pas déployé du tout!"

---

## 🎯 Priorité

**P0 - CRITIQUE**

Ce bug fait que le collecteur donne une **fausse impression de sécurité** alors que l'environnement est **complètement exposé** au risque de réutilisation de passwords admin locaux.

---

## 📎 Fichiers de vérification

- `Scripts/Check-LAPS-Schema.ps1` - Vérification manuelle
- `docs/audit/v1.2.8/audit-v1.2.8.json` - Données collecteur
- `docs/audit/v1.2.8/BUG-LAPS-DETECTION.md` - Ce rapport

---

## ✅ Checklist fix

- [ ] Ajouter fonction `checkSchemaAttribute()`
- [ ] Modifier détecteur `detectGPOVulnerabilities()`
- [ ] Ajouter vérification schéma LAPS en premier
- [ ] Si schéma absent → count = totalComputers
- [ ] Si schéma présent → count = computers sans attribut
- [ ] Ajuster severity selon le cas
- [ ] Ajouter `schemaExtended` dans details
- [ ] Ajouter tests unitaires
- [ ] Tester sur AD sans LAPS (ce lab)
- [ ] Tester sur AD avec LAPS partiel
- [ ] Tester sur AD avec LAPS complet
- [ ] Update CHANGELOG.md

---

**Créé par:** Claude Sonnet 4.5 (vérification automatique)
**Vérifié sur:** aza-me.cc domain (95 computers, schéma LAPS non étendu)
