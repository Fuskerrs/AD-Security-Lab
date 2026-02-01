# Story 1.3: Legacy Protocols (LLMNR, WPAD, IPv6)

**Sprint:** 1 (Network Security)
**Version target:** v1.3.0
**Effort:** 3 jours
**Priorité:** 🔴 P0 CRITICAL
**Status:** 📋 TO DO

---

## 🎯 Objectif

Détecter les protocoles legacy dangereux activés dans le domaine qui permettent les attaques de poisoning et man-in-the-middle.

---

## 📋 Types à implémenter

### 1. LLMNR_ENABLED

**Severity:** 🔴 High
**Category:** Network Security

**Description:**
Link-Local Multicast Name Resolution (LLMNR) est activé, permettant les attaques Responder pour capturer des hashes NetNTLMv2.

**Détection:**

```typescript
// Check GPO setting
const llmnrGPO = await checkGPOSetting({
  path: 'Computer Configuration\\Administrative Templates\\Network\\DNS Client',
  key: 'Turn off multicast name resolution',
  expected: 'Enabled'  // LLMNR should be DISABLED
});

// Check registry on computers
const llmnrRegistry = await checkRegistryKey({
  hive: 'HKLM',
  path: 'SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient',
  key: 'EnableMulticast',
  expected: 0  // 0 = Disabled
});

// Vulnerable if:
// - GPO not configured (LLMNR enabled by default)
// - EnableMulticast = 1
```

**Expected count:** Nombre de computers sans GPO disabling LLMNR

---

### 2. WPAD_ENABLED

**Severity:** 🟡 Medium
**Category:** Network Security

**Description:**
Web Proxy Auto-Discovery (WPAD) est activé, permettant les attaques de proxy spoofing.

**Détection:**

```typescript
// Check if WPAD is disabled via registry
const wpadRegistry = await checkRegistryKey({
  hive: 'HKCU',
  path: 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad',
  key: 'WpadOverride',
  expected: 1  // 1 = WPAD disabled
});

// Check DNS for WPAD record
const wpadDNS = await checkDNSRecord('wpad');

// Vulnerable if:
// - WPAD DNS record exists
// - WpadOverride != 1
```

**Expected count:** 1 si WPAD record existe dans DNS

---

### 3. IPV6_ENABLED_UNUSED

**Severity:** 🟡 Medium
**Category:** Network Security

**Description:**
IPv6 est activé mais non utilisé dans l'environnement, permettant les attaques DHCPv6 spoofing et IPv6 relay.

**Détection:**

```typescript
// Check if IPv6 is enabled on network adapters
const ipv6Status = await runPowerShell(`
  Get-NetAdapterBinding -ComponentID ms_tcpip6 |
  Where-Object { $_.Enabled -eq $true }
`);

// Check if IPv6 is actually used
const ipv6Traffic = await checkIPv6Usage();

// Vulnerable if:
// - IPv6 enabled on adapters
// - BUT no actual IPv6 traffic/config
```

**Expected count:** Nombre de computers avec IPv6 activé mais non utilisé

---

## ✅ Acceptance Criteria

### Must Have
- [ ] `LLMNR_ENABLED` détecté
- [ ] `WPAD_ENABLED` détecté
- [ ] `IPV6_ENABLED_UNUSED` détecté
- [ ] Severities correctes
- [ ] Category = `networkSecurity`
- [ ] Details avec mitigation steps

### Should Have
- [ ] Count précis de computers affectés
- [ ] Check si GPO existe pour mitigation
- [ ] Recommendations claires

---

## 🧪 Tests

### Test 1: LLMNR Enabled

**Verification:**
```powershell
# Check LLMNR status
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue

# Test avec Responder
# responder -I eth0 -A
```

**Expected:**
```json
{
  "type": "LLMNR_ENABLED",
  "count": 95,  // Tous les computers si pas de GPO
  "severity": "high",
  "details": {
    "totalComputers": 95,
    "gpoConfigured": false,
    "recommendation": "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution = Enabled",
    "attackTools": ["Responder", "Inveigh"],
    "mitre": "T1557.001"
  }
}
```

### Test 2: WPAD Enabled

**Verification:**
```powershell
# Check for WPAD DNS record
nslookup wpad

# Check registry
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -ErrorAction SilentlyContinue
```

**Expected:**
```json
{
  "type": "WPAD_ENABLED",
  "count": 1,
  "severity": "medium",
  "details": {
    "wpadDNSExists": true,
    "recommendation": "Remove WPAD DNS record and disable auto-proxy detection"
  }
}
```

### Test 3: IPv6 Enabled Unused

**Verification:**
```powershell
Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object { $_.Enabled -eq $true }
```

**Expected:**
```json
{
  "type": "IPV6_ENABLED_UNUSED",
  "count": 95,
  "severity": "medium",
  "details": {
    "computersWithIPv6": 95,
    "actualIPv6Usage": false,
    "recommendation": "Disable IPv6 if not used: Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6"
  }
}
```

---

## 📝 Implémentation

### Ajout à `network-security.ts`

```typescript
async function detectLLMNREnabled(ldapClient: LDAPClient) {
  // Check GPO
  const gpoConfigured = await checkGPOExists('Turn off multicast name resolution');

  if (gpoConfigured) {
    // GPO exists, check compliance
    const nonCompliant = await checkComputersWithLLMNR();
    if (nonCompliant.length === 0) return null;

    return {
      type: 'LLMNR_ENABLED',
      count: nonCompliant.length,
      severity: 'high',
      category: 'networkSecurity',
      details: {
        affectedComputers: nonCompliant,
        gpoConfigured: true,
        gpoNotApplied: true
      }
    };
  }

  // No GPO = all computers vulnerable
  const totalComputers = await getTotalComputersCount(ldapClient);

  return {
    type: 'LLMNR_ENABLED',
    count: totalComputers,
    severity: 'high',
    category: 'networkSecurity',
    details: {
      totalComputers: totalComputers,
      gpoConfigured: false,
      recommendation: 'Disable LLMNR via GPO',
      attackTools: ['Responder', 'Inveigh'],
      mitre: 'T1557.001'
    }
  };
}

async function detectWPADEnabled(ldapClient: LDAPClient) {
  // Check DNS for WPAD record
  const wpadExists = await checkDNSRecord('wpad');

  if (!wpadExists) return null;

  return {
    type: 'WPAD_ENABLED',
    count: 1,
    severity: 'medium',
    category: 'networkSecurity',
    details: {
      wpadDNSExists: true,
      recommendation: 'Remove WPAD DNS record',
      mitre: 'T1557.001'
    }
  };
}

async function detectIPv6EnabledUnused(ldapClient: LDAPClient) {
  const computers = await getEnabledComputers(ldapClient);

  // Check which computers have IPv6 enabled
  const ipv6Computers = await checkIPv6Enabled(computers);

  // Check if IPv6 is actually used in domain
  const ipv6Used = await checkIPv6UsageInDomain();

  if (ipv6Used) return null;  // IPv6 is used, not a finding

  if (ipv6Computers.length === 0) return null;

  return {
    type: 'IPV6_ENABLED_UNUSED',
    count: ipv6Computers.length,
    severity: 'medium',
    category: 'networkSecurity',
    details: {
      computersWithIPv6: ipv6Computers.length,
      totalComputers: computers.length,
      actualIPv6Usage: false,
      recommendation: 'Disable IPv6 if not used',
      attackVectors: ['DHCPv6 spoofing', 'IPv6 relay attacks']
    }
  };
}
```

---

## 🔧 Utilities

```typescript
// Check DNS record
async function checkDNSRecord(hostname: string): Promise<boolean> {
  const ps = `
    try {
      Resolve-DnsName -Name "${hostname}" -ErrorAction Stop
      return $true
    } catch {
      return $false
    }
  `;

  const result = await runPowerShell(ps);
  return result === 'True';
}
```

---

## 🚦 Definition of Done

- [ ] 3 types implémentés (LLMNR, WPAD, IPv6)
- [ ] Tests passent
- [ ] Total types: 126 → 129
- [ ] Vérifié sur lab
- [ ] Story DONE

---

**Créé par:** Claude Sonnet 4.5
**Date:** 2026-02-01
**Story points:** 3
