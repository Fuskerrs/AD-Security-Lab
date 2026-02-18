# GPO (32 vulnérabilités)

**Sévérité :** 6 Critical, 9 High, 13 Medium, 4 Low
**Dernière vérification :** 2026-02-18
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 158 | GPO_PASSWORD_IN_SYSVOL | Critical | Passwords Found in GPO SYSVOL | ✅ | **2** | Confirmé |
| 182 | PRINTNIGHTMARE_VULNERABLE | Critical | PrintNightmare Mitigation Not Applied | ❓ | - | Non vérifié |
| 183 | ZEROLOGON_PATCH_ENFORCEMENT | Critical | Zerologon Enforcement Not Enabled | ❓ | - | Non vérifié |
| 185 | PRIVILEGE_SEDEBUG_ABUSE | Critical | SeDebugPrivilege Assigned to Non-Admins | ❓ | - | Non vérifié |
| 187 | PRIVILEGE_SETCB_ABUSE | Critical | SeTcbPrivilege (Act as Part of OS) Assigned | ❓ | - | Non vérifié |
| 189 | PRIVILEGE_SELOADDRIVER_ABUSE | Critical | SeLoadDriverPrivilege Assigned to Non-Admins | ❓ | - | Non vérifié |
| 159 | GPO_DANGEROUS_PERMISSIONS | High | GPO Dangerous Permissions | ❓ | - | Non vérifié |
| 167 | GPO_LLMNR_NOT_DISABLED | High | LLMNR Not Disabled | ❓ | - | Non vérifié |
| 171 | HARDENED_UNC_PATHS_WEAK | High | Hardened UNC Paths Not Configured | ❓ | - | Non vérifié |
| 175 | WDIGEST_ENABLED | High | WDigest Stores Cleartext Credentials | ❓ | - | Non vérifié |
| 176 | LSA_PROTECTION_DISABLED | High | LSA Protection (RunAsPPL) Not Enabled | ❓ | - | Non vérifié |
| 178 | NTLMV1_ALLOWED | High | NTLMv1 Authentication Allowed | ❓ | - | Non vérifié |
| 181 | WSUS_HTTP_USED | High | WSUS Configured Over HTTP | ❓ | - | Non vérifié |
| 186 | PRIVILEGE_SEBACKUP_ABUSE | High | SeBackupPrivilege Overly Assigned | ❓ | - | Non vérifié |
| 188 | PRIVILEGE_SERESTORE_ABUSE | High | SeRestorePrivilege Overly Assigned | ❓ | - | Non vérifié |
| 160 | GPO_AUTHENTICATED_USERS_APPLY | Medium | GPO Applies to All Authenticated Users | ❓ | - | Non vérifié |
| 161 | GPO_DISABLED_BUT_LINKED | Medium | Disabled GPO Still Linked | ✅ | **1** | Confirmé (injecté GPO désactivée liée) |
| 162 | GPO_LAPS_NOT_DEPLOYED | Medium | LAPS Not Deployed via GPO | ✅ | **1** | Confirmé (aucune GPO LAPS) |
| 163 | GPO_NO_SECURITY_FILTERING | Medium | GPO Without Security Filtering | ❓ | - | Non vérifié |
| 164 | GPO_ORPHANED | Medium | Orphaned GPOs Detected | ❓ | - | Non vérifié |
| 165 | GPO_WEAK_PASSWORD_POLICY | Medium | Weak Password Policy (GPO) | ✅ | **1** | Confirmé |
| 168 | KERBEROS_ARMORING_DC_DISABLED | Medium | Kerberos Armoring (FAST) Not Enforced on DCs | ❓ | - | Non vérifié |
| 169 | KERBEROS_ARMORING_CLIENT_DISABLED | Medium | Kerberos Armoring (FAST) Not Required on Clients | ❓ | - | Non vérifié |
| 170 | TERMINAL_SERVICES_NOT_HARDENED | Medium | Terminal Services / RDP Not Hardened | ❓ | - | Non vérifié |
| 172 | NET_SESSION_HARDENING_MISSING | Medium | Net Session Hardening Not Configured | ❓ | - | Non vérifié |
| 173 | DEFENDER_ASR_NOT_CONFIGURED | Medium | Defender ASR Not Configured | ❓ | - | Non vérifié |
| 177 | CREDENTIAL_GUARD_DISABLED | Medium | Credential Guard Not Enabled | ❓ | - | Non vérifié |
| 180 | SAM_REMOTE_ACCESS_OPEN | Medium | Remote SAM Access Not Restricted | ❓ | - | Non vérifié |
| 166 | GPO_UNLINKED | Low | Unlinked Group Policy Objects | ✅ | **1** | Confirmé |
| 174 | FIREWALL_OUTBOUND_NOT_BLOCKED | Low | Windows Firewall Outbound Not Blocked | ❓ | - | Non vérifié |
| 179 | CACHED_LOGONS_EXCESSIVE | Low | Excessive Cached Logons | ❓ | - | Non vérifié |
| 184 | BITLOCKER_NOT_REQUIRED | Low | BitLocker Not Required via GPO | ❓ | - | Non vérifié |

**Résumé : 6/32 confirmés (dont 1 injecté) | 26 non vérifiés (dont 23 nouveaux détecteurs v2.7)**

---

## Détail des vulnérabilités

### 158. GPO_PASSWORD_IN_SYSVOL (Critical) — ✅ 2 instances
**Description :** GPO Preferences contain cleartext passwords (cPassword vulnerability MS14-025). Easily decrypted by any domain user.
**Résultat :** **2 fichiers XML contiennent `cpassword`** dans SYSVOL. Les mots de passe sont déchiffrables avec la clé AES publique Microsoft (KB2962486). Tout utilisateur du domaine peut les lire.

---

### 182. PRINTNIGHTMARE_VULNERABLE (Critical) — ❓ Non vérifié
**Description :** Point-and-Print NoWarningNoElevationOnInstall allows any user to install printer drivers without elevation (CVE-2021-34527), enabling RCE as SYSTEM.
**Résultat :** Non testé. Nécessite vérification des clés registry Point-and-Print via GPO.

---

### 183. ZEROLOGON_PATCH_ENFORCEMENT (Critical) — ❓ Non vérifié
**Description :** FullSecureChannelProtection not configured. DCs may accept unauthenticated Netlogon connections, allowing complete domain takeover (CVE-2020-1472).
**Résultat :** Non testé. Nécessite vérification de la clé registry FullSecureChannelProtection.

---

### 185. PRIVILEGE_SEDEBUG_ABUSE (Critical) — ❓ Non vérifié
**Description :** SeDebugPrivilege assigned beyond Administrators. Enables debugging any process, credential extraction from LSASS, process injection.
**Résultat :** Non testé. Nécessite vérification des User Rights Assignment via GPO.

---

### 187. PRIVILEGE_SETCB_ABUSE (Critical) — ❓ Non vérifié
**Description :** SeTcbPrivilege assigned to user accounts. Allows impersonating any user without authentication, equivalent to SYSTEM.
**Résultat :** Non testé. Nécessite vérification des User Rights Assignment via GPO.

---

### 189. PRIVILEGE_SELOADDRIVER_ABUSE (Critical) — ❓ Non vérifié
**Description :** SeLoadDriverPrivilege assigned beyond Administrators. Allows loading kernel-mode drivers, installing rootkits, disabling security.
**Résultat :** Non testé. Nécessite vérification des User Rights Assignment via GPO.

---

### 159. GPO_DANGEROUS_PERMISSIONS (High) — ❓ Non vérifié
**Description :** GPOs with dangerous permissions for non-admins. Allows unauthorized GPO modification.
**Résultat :** Non testé individuellement.

---

### 167. GPO_LLMNR_NOT_DISABLED (High) — ❓ Non vérifié
**Description :** Link-Local Multicast Name Resolution (LLMNR) is not disabled via GPO. LLMNR responds to broadcast name queries and can be abused to capture NTLMv2 hashes via poisoning attacks (Responder).
**Résultat :** Non testé. Nécessite vérification de la clé `EnableMulticast` dans registry.pol.

---

### 171. HARDENED_UNC_PATHS_WEAK (High) — ❓ Non vérifié
**Description :** Hardened UNC paths not configured for SYSVOL and NETLOGON. Without RequireMutualAuthentication and RequireIntegrity, GPO settings can be tampered with in transit.
**Résultat :** Non testé. Nécessite vérification des Hardened UNC Paths dans registry.pol.

---

### 175. WDIGEST_ENABLED (High) — ❓ Non vérifié
**Description :** WDigest UseLogonCredential is not explicitly disabled. WDigest stores cleartext passwords in LSASS memory, extractable with Mimikatz.
**Résultat :** Non testé. Nécessite vérification de la clé `UseLogonCredential` dans registry.pol.

---

### 176. LSA_PROTECTION_DISABLED (High) — ❓ Non vérifié
**Description :** LSASS is not running as Protected Process Light. Attackers can dump credentials from LSASS using Mimikatz, procdump, or task manager.
**Résultat :** Non testé. Nécessite vérification de la clé `RunAsPPL` dans registry.pol.

---

### 178. NTLMV1_ALLOWED (High) — ❓ Non vérifié
**Description :** LAN Manager authentication level does not enforce NTLMv2-only. NTLMv1 responses can be cracked offline in seconds. Level 5 should be enforced.
**Résultat :** Non testé. Nécessite vérification de `LmCompatibilityLevel` dans registry.pol.

---

### 181. WSUS_HTTP_USED (High) — ❓ Non vérifié
**Description :** WSUS uses HTTP instead of HTTPS. Enables MITM attacks to inject malicious updates on all domain-joined machines.
**Résultat :** Non testé. Nécessite vérification de la configuration WSUS dans registry.pol.

---

### 186. PRIVILEGE_SEBACKUP_ABUSE (High) — ❓ Non vérifié
**Description :** SeBackupPrivilege assigned beyond Administrators and Backup Operators. Allows reading any file, bypassing ACLs, extracting NTDS.dit.
**Résultat :** Non testé. Nécessite vérification des User Rights Assignment via GPO.

---

### 188. PRIVILEGE_SERESTORE_ABUSE (High) — ❓ Non vérifié
**Description :** SeRestorePrivilege assigned beyond Administrators and Backup Operators. Allows writing to any file/registry key, bypassing ACLs.
**Résultat :** Non testé. Nécessite vérification des User Rights Assignment via GPO.

---

### 160. GPO_AUTHENTICATED_USERS_APPLY (Medium) — ❓ Non vérifié
**Description :** GPOs with Authenticated Users granted 'Apply Group Policy'. Default but may be too broad.
**Résultat :** Non testé individuellement.

---

### 161. GPO_DISABLED_BUT_LINKED (Medium) — ✅ 1 instance
**Description :** GPOs disabled but still linked. Configuration drift or incomplete changes.
**Résultat :** GPO désactivée mais toujours liée à une OU (injecté). Dérive de configuration potentielle.

---

### 162. GPO_LAPS_NOT_DEPLOYED (Medium) — ✅ 1 instance (policy)
**Description :** No active GPO deploying LAPS. Local admin passwords vulnerable to reuse.
**Résultat :** Aucune GPO déployant LAPS trouvée. Confirmé par #114 (71/71 machines sans LAPS).

---

### 163. GPO_NO_SECURITY_FILTERING (Medium) — ❓ Non vérifié
**Description :** GPOs applying to all Authenticated Users or Everyone without specific filtering.
**Résultat :** Non testé individuellement.

---

### 164. GPO_ORPHANED (Medium) — ❓ Non vérifié
**Description :** Mismatched AD objects and SYSVOL directories. Processing errors, possible tampering.
**Résultat :** Non testé individuellement.

---

### 165. GPO_WEAK_PASSWORD_POLICY (Medium) — ✅ 1 instance
**Description :** Domain password policy requires too few characters.
**Résultat :** `MinPasswordLength=7` (recommandé ≥14 CIS, ≥12 ANSSI), `LockoutThreshold=0` (aucun verrouillage), `PasswordHistoryCount=24`, `ComplexityEnabled=True`.

---

### 168. KERBEROS_ARMORING_DC_DISABLED (Medium) — ❓ Non vérifié
**Description :** Kerberos FAST armoring is not configured on Domain Controllers. FAST protects pre-authentication exchanges from offline brute-force and AS-REP roasting.
**Résultat :** Non testé. Nécessite vérification des paramètres KDC FAST dans registry.pol.

---

### 169. KERBEROS_ARMORING_CLIENT_DISABLED (Medium) — ❓ Non vérifié
**Description :** Kerberos FAST armoring is not required on client machines. Pre-authentication exchanges remain vulnerable to interception.
**Résultat :** Non testé. Nécessite vérification des paramètres client Kerberos FAST dans registry.pol.

---

### 170. TERMINAL_SERVICES_NOT_HARDENED (Medium) — ❓ Non vérifié
**Description :** RDP security settings not properly hardened. Without NLA and TLS security layer, RDP sessions are vulnerable to MITM and credential theft.
**Résultat :** Non testé. Nécessite vérification des paramètres Terminal Services dans registry.pol.

---

### 172. NET_SESSION_HARDENING_MISSING (Medium) — ❓ Non vérifié
**Description :** NetSessionEnum is not restricted. Any authenticated user can enumerate active sessions on servers, aiding attack path mapping (BloodHound session collection).
**Résultat :** Non testé. Nécessite vérification de la restriction NetSession (NetCease) dans registry.pol.

---

### 173. DEFENDER_ASR_NOT_CONFIGURED (Medium) — ❓ Non vérifié
**Description :** Microsoft Defender ASR rules are not deployed via GPO. ASR blocks Office macros, script obfuscation, LSASS credential stealing, and other malware delivery methods.
**Résultat :** Non testé. Nécessite vérification des règles ASR dans registry.pol.

---

### 177. CREDENTIAL_GUARD_DISABLED (Medium) — ❓ Non vérifié
**Description :** Windows Credential Guard not deployed. Uses VBS to isolate NTLM hashes and Kerberos TGTs from direct memory access.
**Résultat :** Non testé. Nécessite vérification des paramètres Device Guard/Credential Guard dans registry.pol.

---

### 180. SAM_REMOTE_ACCESS_OPEN (Medium) — ❓ Non vérifié
**Description :** SAM remote access not restricted. Any authenticated user can enumerate local accounts and group memberships remotely.
**Résultat :** Non testé. Nécessite vérification de la clé `RestrictRemoteSAM` dans registry.pol.

---

### 166. GPO_UNLINKED (Low) — ✅ 1 instance
**Description :** GPOs not linked to any OU, domain, or site. May be orphaned or incomplete deployment.
**Résultat :** `VulnerableGPO-LocalAdmin-MS14-025` — GPO non liée, potentiellement un vestige de test MS14-025.

---

### 174. FIREWALL_OUTBOUND_NOT_BLOCKED (Low) — ❓ Non vérifié
**Description :** Windows Firewall does not block outbound connections by default. Enables malware C2 communication, data exfiltration, and reverse shells.
**Résultat :** Non testé. Nécessite vérification de la politique Firewall outbound dans registry.pol.

---

### 179. CACHED_LOGONS_EXCESSIVE (Low) — ❓ Non vérifié
**Description :** Cached logon credentials exceed recommended value of 2 for servers/DCs. Cached credentials can be extracted and cracked offline.
**Résultat :** Non testé. Nécessite vérification de `CachedLogonsCount` dans registry.pol.

---

### 184. BITLOCKER_NOT_REQUIRED (Low) — ❓ Non vérifié
**Description :** BitLocker not enforced via GPO. Stolen or decommissioned hardware exposes AD data and cached credentials.
**Résultat :** Non testé. Nécessite vérification de la politique BitLocker dans registry.pol.
