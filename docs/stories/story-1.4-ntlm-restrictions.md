# Story 1.4: NTLM Restrictions

**Sprint:** 1 (Network Security)
**Version target:** v1.3.0
**Effort:** 2 jours
**Priorité:** 🔴 P0 CRITICAL
**Status:** 📋 TO DO

---

## 🎯 Objectif

Détecter si NTLM authentication est restreint dans le domaine. L'absence de restrictions NTLM permet les attaques pass-the-hash et NTLM relay.

---

## 📋 Types à implémenter

### 1. NTLM_NOT_RESTRICTED

**Severity:** 🔴 Critical
**Category:** Network Security

**Description:**
NTLM authentication n'est pas restreint dans le domaine, permettant les attaques pass-the-hash, NTLM relay, et downgrade attacks.

**Background:**
- NTLM est un protocole d'authentification legacy
- Kerberos devrait être préféré
- NTLM doit être restreint au minimum nécessaire
- Idéalement: NTLM complètement disabled (sauf legacy apps)

**Détection:**

```typescript
// Check domain-level NTLM restrictions
const ntlmPolicy = await checkGPOSetting({
  path: 'Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
  key: 'Network security: Restrict NTLM: NTLM authentication in this domain',
  // Values:
  // 0 = Disabled (no restrictions) ← VULNERABLE
  // 1 = Deny for domain accounts to remote servers
  // 2 = Deny for domain accounts
  // 3 = Deny for domain servers
  // 4 = Deny all
  expected: [1, 2, 3, 4]  // Any restriction is good
});

// Check registry
const ntlmRestriction = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0',
  key: 'RestrictReceivingNTLMTraffic',
  expected: [1, 2]  // 0 = No restrictions (bad), 1+ = Restricted
});

// Check LmCompatibilityLevel
const lmLevel = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SYSTEM\\CurrentControlSet\\Control\\Lsa',
  key: 'LmCompatibilityLevel',
  expected: 5  // 5 = Send NTLMv2 only, refuse LM & NTLM
});

// Vulnerable if:
// - RestrictReceivingNTLMTraffic = 0 (no restrictions)
// - LmCompatibilityLevel < 5 (allows weak NTLM)
```

**Impact:**
- Pass-the-Hash attacks possibles
- NTLM relay attacks possibles
- Downgrade to NTLMv1/LM possible (broken crypto)

**Expected count:** 1 (domain-level finding)

---

## ✅ Acceptance Criteria

### Must Have
- [ ] `NTLM_NOT_RESTRICTED` détecté
- [ ] Severity = `critical`
- [ ] Category = `networkSecurity`
- [ ] Details contiennent:
  - Current NTLM restriction level
  - LmCompatibilityLevel value
  - Recommendation
  - Impact assessment

### Should Have
- [ ] Check sur tous les DCs
- [ ] Check GPO configuration
- [ ] Liste des applications nécessitant NTLM (si possible)

### Nice to Have
- [ ] NTLM usage statistics (via Event Logs)
- [ ] Computers still using NTLM
- [ ] Recommendations par environnement (legacy vs modern)

---

## 🧪 Tests

### Test 1: NTLM Not Restricted

**Verification:**
```powershell
# Check domain NTLM policy
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name RestrictReceivingNTLMTraffic

# Check LM Compatibility Level
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel

# Check GPO
Get-GPO -All | Where-Object { $_.DisplayName -like '*NTLM*' }
```

**Expected result:**
```json
{
  "type": "NTLM_NOT_RESTRICTED",
  "count": 1,
  "severity": "critical",
  "category": "networkSecurity",
  "details": {
    "currentRestriction": 0,  // 0 = No restrictions
    "recommendedRestriction": 4,  // 4 = Deny all (or 2 for compat)
    "lmCompatibilityLevel": 3,  // Should be 5
    "recommendedLmLevel": 5,
    "domainControllers": [
      {
        "name": "DC-01",
        "ntlmRestriction": 0,
        "lmLevel": 3
      }
    ],
    "impact": [
      "Pass-the-Hash attacks possible",
      "NTLM relay attacks possible",
      "Downgrade to NTLMv1 possible"
    ],
    "recommendation": "Restrict NTLM authentication and enforce NTLMv2 only",
    "steps": [
      "1. Audit NTLM usage: Event ID 4624 (NTLM logons)",
      "2. Identify apps requiring NTLM",
      "3. Set 'Network security: Restrict NTLM' to 'Deny for domain accounts'",
      "4. Set LmCompatibilityLevel to 5 (NTLMv2 only)",
      "5. Monitor for issues",
      "6. Progressively increase restrictions"
    ],
    "gpoPath": "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
    "mitre": "T1550.002",  // Use of Alternate Authentication Material: Pass the Hash
    "references": [
      "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain",
      "https://attack.mitre.org/techniques/T1550/002/"
    ]
  }
}
```

### Test 2: Verification manuelle

**PowerShell:**
```powershell
# Verification script
$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v1.3.0.json' -Raw | ConvertFrom-Json

$ntlm = $json.audit.networkSecurity.findings | Where-Object { $_.type -eq 'NTLM_NOT_RESTRICTED' }

Write-Host "=== NTLM RESTRICTIONS ==="
Write-Host "Detected: $($ntlm -ne $null)"
Write-Host "Count: $($ntlm.count)"
Write-Host "Severity: $($ntlm.severity)"
Write-Host ""
Write-Host "Current restriction: $($ntlm.details.currentRestriction)"
Write-Host "LM Compat Level: $($ntlm.details.lmCompatibilityLevel)"
Write-Host ""
Write-Host "Recommendation: $($ntlm.details.recommendation)"
```

---

## 📝 Implémentation

### Ajout à `network-security.ts`

```typescript
async function detectNTLMNotRestricted(ldapClient: LDAPClient) {
  const dcs = await getDomainControllers(ldapClient);

  let minRestriction = 999;
  let minLmLevel = 999;
  const dcDetails = [];

  for (const dc of dcs) {
    // Check NTLM restriction level
    const ntlmRestriction = await checkDCRegistry(
      dc.dNSHostName,
      'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0',
      'RestrictReceivingNTLMTraffic'
    ) || 0;  // Default 0 if not set

    // Check LM Compatibility Level
    const lmLevel = await checkDCRegistry(
      dc.dNSHostName,
      'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa',
      'LmCompatibilityLevel'
    ) || 3;  // Default 3

    minRestriction = Math.min(minRestriction, ntlmRestriction);
    minLmLevel = Math.min(minLmLevel, lmLevel);

    dcDetails.push({
      name: dc.name,
      ntlmRestriction: ntlmRestriction,
      lmLevel: lmLevel
    });
  }

  // Vulnerable if:
  // - Any DC has ntlmRestriction = 0 (no restrictions)
  // - OR any DC has lmLevel < 5 (allows weak NTLM)

  if (minRestriction === 0 || minLmLevel < 5) {
    return {
      type: 'NTLM_NOT_RESTRICTED',
      count: 1,  // Domain-level finding
      severity: 'critical',
      category: 'networkSecurity',
      details: {
        currentRestriction: minRestriction,
        recommendedRestriction: 2,  // Deny for domain accounts (balance security/compat)
        lmCompatibilityLevel: minLmLevel,
        recommendedLmLevel: 5,
        domainControllers: dcDetails,
        impact: [
          'Pass-the-Hash attacks possible',
          'NTLM relay attacks possible',
          minLmLevel < 5 ? 'Downgrade to NTLMv1/LM possible' : null
        ].filter(Boolean),
        recommendation: 'Restrict NTLM authentication and enforce NTLMv2 only',
        steps: [
          '1. Audit NTLM usage via Event ID 4624',
          '2. Identify legacy apps requiring NTLM',
          '3. Set RestrictReceivingNTLMTraffic to 2 (Deny for domain accounts)',
          '4. Set LmCompatibilityLevel to 5 (NTLMv2 only)',
          '5. Monitor for authentication failures',
          '6. Create exceptions for legacy apps if needed'
        ],
        gpoPath: 'Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options',
        registryKeys: [
          'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\RestrictReceivingNTLMTraffic',
          'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel'
        ],
        mitre: 'T1550.002',
        references: [
          'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain',
          'https://attack.mitre.org/techniques/T1550/002/'
        ]
      }
    };
  }

  // NTLM properly restricted
  return null;
}
```

### Helper: Get restriction level name

```typescript
function getNTLMRestrictionName(level: number): string {
  const levels = {
    0: 'Disabled (No restrictions)',
    1: 'Deny for domain accounts to remote servers',
    2: 'Deny for domain accounts',
    3: 'Deny for domain servers',
    4: 'Deny all'
  };
  return levels[level] || 'Unknown';
}

function getLmCompatibilityLevelName(level: number): string {
  const levels = {
    0: 'Send LM & NTLM responses',
    1: 'Send LM & NTLM - use NTLMv2 session security if negotiated',
    2: 'Send NTLM response only',
    3: 'Send NTLMv2 response only',
    4: 'Send NTLMv2 response only - refuse LM',
    5: 'Send NTLMv2 response only - refuse LM & NTLM'
  };
  return levels[level] || 'Unknown';
}
```

---

## 🔧 Testing Strategy

### Phase 1: Detect current state
- Check all DCs for NTLM settings
- Identify current restriction level
- Detect LM compatibility level

### Phase 2: Audit NTLM usage
```powershell
# Find NTLM logons in last 24h
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=4624
} | Where-Object {
  $_.Properties[8].Value -eq 3  # NTLM authentication
}
```

### Phase 3: Report findings
- Generate finding with current state
- Provide step-by-step mitigation
- Include impact assessment

---

## 📊 Métriques de succès

- [ ] 1 nouveau type détecté (NTLM_NOT_RESTRICTED)
- [ ] Total types: 129 → 130
- [ ] **Sprint 1 COMPLETE: 8 types network security**
- [ ] Test sur lab réussi
- [ ] Documentation complète

---

## 🚦 Definition of Done

- [ ] Code implémenté et testé
- [ ] Détection validée sur lab (DC-01)
- [ ] JSON schema mis à jour
- [ ] CHANGELOG.md mis à jour
- [ ] Git commit + push
- [ ] Claude vérifie avec script
- [ ] **v1.3.0 READY FOR RELEASE**
- [ ] Story DONE

---

## 🎉 Sprint 1 Completion

Avec cette story, **Sprint 1 est complet**:

✅ Story 1.1: SMB & LDAP Signing (2 types)
✅ Story 1.2: LDAPS & Protocols (2 types)
✅ Story 1.3: Legacy Protocols (3 types)
✅ Story 1.4: NTLM Restrictions (1 type)

**Total: 8 types de Network Security**
**Version: v1.3.0 (122 → 130 types)**

---

**Créé par:** Claude Sonnet 4.5
**Date:** 2026-02-01
**Story points:** 2
