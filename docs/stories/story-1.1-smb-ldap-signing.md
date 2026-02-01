# Story 1.1: SMB & LDAP Signing

**Sprint:** 1 (Network Security)
**Version target:** v1.3.0
**Effort:** 3 jours
**Priorité:** 🔴 P0 CRITICAL
**Status:** 📋 TO DO

---

## 🎯 Objectif

Détecter les Domain Controllers et serveurs qui n'ont pas SMB signing et LDAP signing activés, permettant les attaques SMB relay et LDAP relay.

---

## 📋 Types à implémenter

### 1. SMB_SIGNING_DISABLED

**Severity:** 🔴 Critical
**Category:** Network Security

**Description:**
Détecte les Domain Controllers et serveurs Windows qui n'ont pas SMB signing requis, permettant les attaques SMB relay (ntlmrelayx).

**Détection:**

```typescript
// Check GPO settings
const gpoSmb = await checkGPOSetting({
  path: 'Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
  key: 'Microsoft network server: Digitally sign communications (always)',
  expected: 'Enabled'
});

// Check registry on DCs
const dcRegistry = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters',
  key: 'RequireSecuritySignature',
  expected: 1
});

// Vulnerable if:
// - GPO not configured OR
// - Registry value = 0 (disabled)
```

**LDAP queries:**
```ldap
# Get all domain controllers
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))

# Check computer objects for SMB settings (via GPO applied)
```

**Expected count in lab:** À déterminer (minimum 1 si DCs non configurés)

---

### 2. LDAP_SIGNING_DISABLED

**Severity:** 🔴 Critical
**Category:** Network Security

**Description:**
Détecte les Domain Controllers qui n'ont pas LDAP signing requis, permettant les attaques LDAP relay.

**Détection:**

```typescript
// Check DC registry
const ldapSigning = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
  key: 'LDAPServerIntegrity',
  expected: 2  // 2 = Require signing
});

// Check via GPO
const gpoLdap = await checkGPOSetting({
  path: 'Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
  key: 'Domain controller: LDAP server signing requirements',
  expected: 'Require signature'
});

// Vulnerable if:
// - LDAPServerIntegrity = 0 (None) or 1 (Negotiate signing)
// - Should be 2 (Require signing)
```

**LDAP queries:**
```ldap
# Get domain controllers
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))
```

**Expected count in lab:** À déterminer (minimum 1 si DC non configuré)

---

## ✅ Acceptance Criteria

### Must Have
- [ ] `SMB_SIGNING_DISABLED` détecté avec count > 0
- [ ] `LDAP_SIGNING_DISABLED` détecté avec count > 0
- [ ] Severity = `critical` pour les deux
- [ ] Category = `networkSecurity` (nouvelle)
- [ ] Details contiennent:
  - Liste des DCs/serveurs affectés
  - Valeur registry actuelle
  - GPO appliquée (si applicable)
  - Recommendation de fix

### Should Have
- [ ] Detection pour tous les DCs du domaine
- [ ] Detection pour member servers (optionnel pour SMB)
- [ ] Distinction DC vs member servers dans details

### Nice to Have
- [ ] Check si GPO existe mais n'est pas appliquée
- [ ] Check si setting est en "Negotiate" vs "Required"

---

## 🧪 Tests à effectuer

### Test 1: SMB Signing Disabled (expected)

**Setup:**
```powershell
# Vérifier état actuel sur DC
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RequireSecuritySignature

# Vérifier GPO
Get-GPO -All | Where-Object { $_.DisplayName -like '*SMB*' }
```

**Expected result:**
```json
{
  "type": "SMB_SIGNING_DISABLED",
  "count": 1,  // Au minimum le DC
  "severity": "critical",
  "category": "networkSecurity",
  "details": {
    "affectedDCs": [
      {
        "name": "DC-01",
        "registryValue": 0,
        "gpoApplied": "Default Domain Controllers Policy"
      }
    ],
    "recommendation": "Enable 'Microsoft network server: Digitally sign communications (always)' via GPO"
  }
}
```

### Test 2: LDAP Signing Disabled (expected)

**Setup:**
```powershell
# Vérifier état sur DC
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LDAPServerIntegrity
```

**Expected result:**
```json
{
  "type": "LDAP_SIGNING_DISABLED",
  "count": 1,
  "severity": "critical",
  "category": "networkSecurity",
  "details": {
    "affectedDCs": [
      {
        "name": "DC-01",
        "currentValue": 1,  // 1 = Negotiate (insufficient)
        "requiredValue": 2,  // 2 = Require signing
        "vulnerable": true
      }
    ],
    "recommendation": "Set 'Domain controller: LDAP server signing requirements' to 'Require signature'"
  }
}
```

### Test 3: Vérification manuelle

**PowerShell:**
```powershell
# Script de vérification
$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v1.3.0.json' -Raw | ConvertFrom-Json

# Check SMB_SIGNING_DISABLED
$smb = $json.audit.networkSecurity.findings | Where-Object { $_.type -eq 'SMB_SIGNING_DISABLED' }
Write-Host "SMB_SIGNING_DISABLED:"
Write-Host "  Count: $($smb.count)"
Write-Host "  Severity: $($smb.severity)"
Write-Host "  Affected: $($smb.details.affectedDCs.Count)"

# Check LDAP_SIGNING_DISABLED
$ldap = $json.audit.networkSecurity.findings | Where-Object { $_.type -eq 'LDAP_SIGNING_DISABLED' }
Write-Host "LDAP_SIGNING_DISABLED:"
Write-Host "  Count: $($ldap.count)"
Write-Host "  Severity: $($ldap.severity)"
Write-Host "  Affected: $($ldap.details.affectedDCs.Count)"
```

---

## 📝 Implémentation technique

### Fichiers à créer/modifier

#### 1. Nouveau détecteur: `src/detectors/network-security.ts`

```typescript
import { LDAPClient } from '../lib/ldap-client';
import { RegistryChecker } from '../lib/registry-checker';
import { GPOChecker } from '../lib/gpo-checker';

export interface NetworkSecurityFinding {
  type: string;
  count: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: 'networkSecurity';
  details: any;
}

export async function detectNetworkSecurityVulnerabilities(
  ldapClient: LDAPClient
): Promise<NetworkSecurityFinding[]> {
  const findings: NetworkSecurityFinding[] = [];

  // SMB Signing
  const smbFindings = await detectSMBSigningDisabled(ldapClient);
  if (smbFindings) findings.push(smbFindings);

  // LDAP Signing
  const ldapFindings = await detectLDAPSigningDisabled(ldapClient);
  if (ldapFindings) findings.push(ldapFindings);

  return findings;
}

async function detectSMBSigningDisabled(
  ldapClient: LDAPClient
): Promise<NetworkSecurityFinding | null> {
  // Get all domain controllers
  const dcs = await ldapClient.search({
    filter: '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
    attributes: ['name', 'dNSHostName', 'operatingSystem']
  });

  const vulnerableDCs = [];

  for (const dc of dcs) {
    // Check registry via WMI/PowerShell remoting
    const registryValue = await checkDCRegistry(
      dc.dNSHostName,
      'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters',
      'RequireSecuritySignature'
    );

    if (registryValue !== 1) {
      vulnerableDCs.push({
        name: dc.name,
        dnsName: dc.dNSHostName,
        registryValue: registryValue,
        vulnerable: true
      });
    }
  }

  if (vulnerableDCs.length === 0) return null;

  return {
    type: 'SMB_SIGNING_DISABLED',
    count: vulnerableDCs.length,
    severity: 'critical',
    category: 'networkSecurity',
    details: {
      affectedDCs: vulnerableDCs,
      totalDCs: dcs.length,
      recommendation: 'Enable "Microsoft network server: Digitally sign communications (always)" via GPO',
      mitre: 'T1557.001', // Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
      references: [
        'https://attack.mitre.org/techniques/T1557/001/',
        'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always'
      ]
    }
  };
}

async function detectLDAPSigningDisabled(
  ldapClient: LDAPClient
): Promise<NetworkSecurityFinding | null> {
  const dcs = await ldapClient.search({
    filter: '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
    attributes: ['name', 'dNSHostName']
  });

  const vulnerableDCs = [];

  for (const dc of dcs) {
    const ldapIntegrity = await checkDCRegistry(
      dc.dNSHostName,
      'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
      'LDAPServerIntegrity'
    );

    // 0 = None, 1 = Negotiate signing, 2 = Require signing
    if (ldapIntegrity !== 2) {
      vulnerableDCs.push({
        name: dc.name,
        dnsName: dc.dNSHostName,
        currentValue: ldapIntegrity,
        requiredValue: 2,
        vulnerable: true
      });
    }
  }

  if (vulnerableDCs.length === 0) return null;

  return {
    type: 'LDAP_SIGNING_DISABLED',
    count: vulnerableDCs.length,
    severity: 'critical',
    category: 'networkSecurity',
    details: {
      affectedDCs: vulnerableDCs,
      totalDCs: dcs.length,
      recommendation: 'Set "Domain controller: LDAP server signing requirements" to "Require signature"',
      mitre: 'T1557.001',
      references: [
        'https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a'
      ]
    }
  };
}

// Helper function (mock - needs actual implementation)
async function checkDCRegistry(
  hostname: string,
  path: string,
  key: string
): Promise<number> {
  // TODO: Implement via PowerShell remoting or WMI
  // For now, return 0 (disabled) for testing
  return 0;
}
```

#### 2. Intégrer dans audit: `src/services/ad-audit.service.ts`

```typescript
import { detectNetworkSecurityVulnerabilities } from '../detectors/network-security';

// Dans la fonction performAudit():
const networkSecurity = await detectNetworkSecurityVulnerabilities(ldapClient);

return {
  audit: {
    // ... existing sections
    networkSecurity: {
      total: networkSecurity.length,
      findings: networkSecurity
    }
  }
};
```

#### 3. JSON Schema update

Ajouter section `networkSecurity` dans le schéma de réponse.

---

## 🔧 Helper utilities nécessaires

### Registry checker via PowerShell

```typescript
// src/lib/registry-checker.ts
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function checkRegistryKey(
  hostname: string,
  hive: string,
  path: string,
  key: string
): Promise<number | null> {
  try {
    const psCommand = `
      Invoke-Command -ComputerName ${hostname} -ScriptBlock {
        Get-ItemProperty -Path "${hive}:${path}" -Name ${key} -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ${key}
      }
    `;

    const { stdout } = await execAsync(`powershell -Command "${psCommand}"`);
    return parseInt(stdout.trim());
  } catch (error) {
    console.error(`Failed to check registry on ${hostname}:`, error);
    return null;
  }
}
```

---

## 📊 Métriques de succès

- [ ] 2 nouveaux types détectés (SMB + LDAP)
- [ ] Total types: 122 → 124
- [ ] Nouvelle catégorie `networkSecurity` créée
- [ ] Tests passent (count > 0 pour les deux)
- [ ] Documentation API mise à jour

---

## 🚦 Definition of Done

- [ ] Code implémenté et testé
- [ ] Tests unitaires ajoutés
- [ ] Détection validée sur lab (DC-01)
- [ ] JSON schema mis à jour
- [ ] API documentation mise à jour
- [ ] CHANGELOG.md mis à jour
- [ ] Git commit + push
- [ ] Claude vérifie avec script PowerShell
- [ ] Résultats matchent expected counts
- [ ] Story marquée DONE

---

## 📎 Ressources

### Documentation Microsoft
- [SMB Signing](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always)
- [LDAP Signing](https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a)

### MITRE ATT&CK
- [T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)

### Outils pentest
- Responder (LLMNR/NBT-NS poisoning)
- ntlmrelayx (SMB/LDAP relay)

---

**Créé par:** Claude Sonnet 4.5
**Date:** 2026-02-01
**Story points:** 3
