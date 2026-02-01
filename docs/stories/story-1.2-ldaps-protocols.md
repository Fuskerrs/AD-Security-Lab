# Story 1.2: LDAPS & Protocol Security

**Sprint:** 1 (Network Security)
**Version target:** v1.3.0
**Effort:** 2 jours
**Priorité:** 🔴 P0 CRITICAL
**Status:** 📋 TO DO

---

## 🎯 Objectif

Détecter les Domain Controllers qui n'enforçent pas LDAPS (LDAP over SSL/TLS) et qui n'ont pas SMBv1 disabled, exposant le domaine aux attaques cleartext et exploits legacy.

---

## 📋 Types à implémenter

### 1. LDAPS_NOT_ENFORCED

**Severity:** 🔴 High
**Category:** Network Security

**Description:**
LDAP non-chiffré (port 389) est autorisé au lieu de forcer LDAPS (port 636), permettant la capture de credentials en cleartext.

**Détection:**

```typescript
// Check if DC enforces LDAPS
const ldapsEnforced = await checkGPOSetting({
  path: 'Computer Configuration\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
  key: 'Domain controller: Refuse machine account password changes',
  // Check LDAPS port 636 enabled and port 389 disabled
});

// Check registry
const channelBinding = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
  key: 'LdapEnforceChannelBinding',
  expected: 2  // 2 = Always
});

// Vulnerable if:
// - LdapEnforceChannelBinding != 2
// - Port 389 accepts unencrypted connections
```

**Expected count:** 1+ (DCs non configurés)

---

### 2. SMBv1_ENABLED

**Severity:** 🟡 High
**Category:** Network Security

**Description:**
SMBv1 est un protocole obsolète vulnérable à de nombreux exploits (WannaCry, EternalBlue). Devrait être disabled.

**Détection:**

```typescript
// Check via PowerShell on DCs and servers
const smbv1Status = await runPowerShell(`
  Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol |
  Select-Object -ExpandProperty State
`);

// Check computers
const computers = await ldapClient.search({
  filter: '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
  attributes: ['name', 'dNSHostName', 'operatingSystem']
});

// For each computer, check SMBv1
for (const computer of computers) {
  const smbv1 = await checkSMBv1Enabled(computer.dNSHostName);
  if (smbv1 === 'Enabled') {
    vulnerableComputers.push(computer);
  }
}
```

**Expected count:** Variable (dépend configuration serveurs)

---

## ✅ Acceptance Criteria

### Must Have
- [ ] `LDAPS_NOT_ENFORCED` détecté
- [ ] `SMBv1_ENABLED` détecté
- [ ] Severities correctes (high pour les deux)
- [ ] Category = `networkSecurity`
- [ ] Details avec liste computers affectés

### Should Have
- [ ] Distinction DCs vs member servers
- [ ] Check si certificat LDAPS existe
- [ ] Recommendation de fix

---

## 🧪 Tests

### Test 1: LDAPS Not Enforced

**Verification:**
```powershell
# Check LDAPS certificate
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*DC-01*" }

# Check channel binding
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name LdapEnforceChannelBinding
```

**Expected:**
```json
{
  "type": "LDAPS_NOT_ENFORCED",
  "count": 1,
  "severity": "high",
  "details": {
    "affectedDCs": ["DC-01"],
    "channelBinding": 1,  // Should be 2
    "recommendation": "Enable LDAP channel binding and require LDAPS"
  }
}
```

### Test 2: SMBv1 Enabled

**Verification:**
```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

**Expected:**
```json
{
  "type": "SMBv1_ENABLED",
  "count": 1,
  "severity": "high",
  "details": {
    "affectedComputers": ["DC-01"],
    "recommendation": "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
  }
}
```

---

## 📝 Implémentation

### Ajout à `network-security.ts`

```typescript
async function detectLDAPSNotEnforced(ldapClient: LDAPClient) {
  const dcs = await getDomainControllers(ldapClient);
  const vulnerable = [];

  for (const dc of dcs) {
    const channelBinding = await checkDCRegistry(
      dc.dNSHostName,
      'HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters',
      'LdapEnforceChannelBinding'
    );

    if (channelBinding !== 2) {
      vulnerable.push({
        name: dc.name,
        channelBinding: channelBinding,
        vulnerable: true
      });
    }
  }

  if (vulnerable.length === 0) return null;

  return {
    type: 'LDAPS_NOT_ENFORCED',
    count: vulnerable.length,
    severity: 'high',
    category: 'networkSecurity',
    details: {
      affectedDCs: vulnerable,
      recommendation: 'Enable LDAP channel binding (set to Always)',
      references: ['https://support.microsoft.com/ldap-channel-binding']
    }
  };
}

async function detectSMBv1Enabled(ldapClient: LDAPClient) {
  const computers = await ldapClient.search({
    filter: '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
    attributes: ['name', 'dNSHostName', 'operatingSystem']
  });

  const vulnerable = [];

  for (const computer of computers) {
    const smbv1 = await checkSMBv1Status(computer.dNSHostName);
    if (smbv1 === 'Enabled') {
      vulnerable.push(computer);
    }
  }

  if (vulnerable.length === 0) return null;

  return {
    type: 'SMBv1_ENABLED',
    count: vulnerable.length,
    severity: 'high',
    category: 'networkSecurity',
    details: {
      affectedComputers: vulnerable.map(c => c.name),
      recommendation: 'Disable SMBv1 on all computers',
      mitre: 'T1210', // Exploitation of Remote Services
      cve: ['CVE-2017-0144', 'CVE-2017-0145'], // EternalBlue
      references: ['https://aka.ms/stopusingsmb1']
    }
  };
}
```

---

## 🚦 Definition of Done

- [ ] 2 types implémentés (LDAPS + SMBv1)
- [ ] Tests passent
- [ ] Total types: 124 → 126
- [ ] Vérifié sur lab
- [ ] Story DONE

---

**Créé par:** Claude Sonnet 4.5
**Date:** 2026-02-01
**Story points:** 2
