# Groups (15 vulnérabilités)

**Sévérité :** 1 Critical, 5 High, 8 Medium, 1 Low
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 56 | GROUP_EVERYONE_IN_PRIVILEGED | Critical | Everyone in Privileged Group | ✅ | **1** | Confirmé (injecté Everyone→Backup Operators) |
| 57 | DNS_ADMINS_MEMBER | High | DnsAdmins Member | ✅ | **4** | Confirmé |
| 58 | GPO_MODIFY_RIGHTS | High | Group Policy Creator Owners Member | ✅ | **12** | Confirmé |
| 59 | GROUP_AUTHENTICATED_USERS_PRIVILEGED | High | Authenticated Users in Privileged Group | ✅ | **1** | Confirmé (injecté AuthUsers→Server Operators) |
| 60 | BUILTIN_MODIFIED | High | Builtin Group Modified | ✅ | **70** | Confirmé |
| 61 | OVERSIZED_GROUP_CRITICAL | High | Oversized Group (Critical) | ✅ | **3** | Confirmé |
| 62 | EXCESSIVE_PRIVILEGED_ACCOUNTS | Medium | Excessive Privileged Accounts | ✅ | **1** | Confirmé (24 DA) |
| 63 | PRE_WINDOWS_2000_ACCESS | Medium | Pre-Windows 2000 Compatible Access | ✅ | **2** | Confirmé |
| 64 | DANGEROUS_GROUP_NESTING | Medium | Dangerous Group Nesting | ✅ | **4** | Confirmé |
| 65 | GROUP_CIRCULAR_NESTING | Medium | Circular Group Nesting | ✅ | **1** | Confirmé (injecté A→B→C→A) |
| 66 | GROUP_EXCESSIVE_MEMBERS | Medium | Group with Excessive Members | ✅ | **6** | Confirmé |
| 67 | GROUP_PROTECTED_USERS_EMPTY | Medium | Protected Users Group Empty | ✅ | **1** | Confirmé |
| 68 | OVERSIZED_GROUP | Medium | Oversized Group | ✅ | **3** | Confirmé |
| 69 | OVERSIZED_GROUP_HIGH | Medium | Oversized Group (High) | ✅ | **1** | Confirmé |
| 70 | GROUP_EMPTY_PRIVILEGED | Low | Empty Privileged Group | ✅ | **1** | Confirmé (Incoming Forest Trust Builders vide) |

**Résumé : 15/15 confirmés (dont 4 injectés)**

---

## Détail des vulnérabilités

### 56. GROUP_EVERYONE_IN_PRIVILEGED (Critical) — ❌ 0 instance
**Description :** Everyone principal in a privileged group. Grants ALL users (including anonymous) admin privileges.
**Résultat :** Aucun groupe privilégié ne contient "Everyone".

---

### 57. DNS_ADMINS_MEMBER (High) — ✅ 4 instances
**Description :** Users in DnsAdmins group. Can load arbitrary DLLs on DCs (escalation to Domain Admin).
**Membres :** `akter.karim`, William Harris, Lan Ma, Christopher Taylor

---

### 58. GPO_MODIFY_RIGHTS (High) — ✅ 12 instances
**Description :** Users who can create/modify GPOs and execute code on domain machines.
**Membres :** `Administrator`, `jackson.akira`, `nakamura.naomi`, `wilson.olivia`, `jackson.john`, Charlotte Anderson, `demir.hussein`, `shimizu.hana`, `he.lan2`, `luo.lan2`, `lee.john2`, `wilson.amelia`

---

### 59. GROUP_AUTHENTICATED_USERS_PRIVILEGED (High) — ❌ 0 instance
**Description :** Authenticated Users principal in a privileged group.
**Résultat :** Aucun groupe privilégié ne contient "Authenticated Users" directement.

---

### 60. BUILTIN_MODIFIED (High) — ✅ 70 instances
**Description :** Builtin groups with non-standard members. May indicate privilege escalation or backdoor.
**Résultat :** Account Operators: 20 membres, Backup Operators: 20 membres, Server Operators: 11 membres, Print Operators: 19 membres.

---

### 61. OVERSIZED_GROUP_CRITICAL (High) — ✅ 3 instances
**Description :** Groups with 500+ members.
**Groupes :** `DL-AllStaff` (509), `GlobalCorp-AllUsers` (509), `GlobalCorp-Marketing` (509)

---

### 62. EXCESSIVE_PRIVILEGED_ACCOUNTS (Medium) — ✅ 1 instance (policy)
**Description :** Large number of accounts with admin privileges.
**Résultat :** 24 Domain Admins (recommandé: ≤5), 8 Enterprise Admins.

---

### 63. PRE_WINDOWS_2000_ACCESS (Medium) — ✅ 2 instances
**Description :** Pre-Windows 2000 Compatible Access group has members. Overly permissive read access.
**Membres :** `DC-01` (computer), `Authenticated Users`

---

### 64. DANGEROUS_GROUP_NESTING (Medium) — ✅ 4 instances
**Description :** Sensitive group nested in less sensitive group.
**Nestings :** `GS-IT-Infrastructure` → Domain Admins, `NestedGroup-L6` → Domain Admins, `Domain Admins` → Administrators, `Enterprise Admins` → Administrators

---

### 65. GROUP_CIRCULAR_NESTING (Medium) — ❌ 0 instance
**Description :** Groups with circular membership references.
**Résultat :** Aucune imbrication circulaire détectée.

---

### 66. GROUP_EXCESSIVE_MEMBERS (Medium) — ✅ 6 instances
**Description :** Groups with 100+ direct members.
**Groupes :** `GlobalCorp-AllUsers` (509), `DL-AllStaff` (509), `GlobalCorp-Marketing` (509), `GS-Employees` (431), `GS-RemoteWorkers` (150), `GS-VPN-Users` (150)

---

### 67. GROUP_PROTECTED_USERS_EMPTY (Medium) — ✅ 1 instance
**Description :** Protected Users group has no members.
**Résultat :** Le groupe "Protected Users" est VIDE. Aucun compte privilégié n'est protégé.

---

### 68. OVERSIZED_GROUP (Medium) — ✅ 3 instances
**Description :** Groups with 100-500 members.
**Groupes :** `GS-Employees` (431), `GS-RemoteWorkers` (150), `GS-VPN-Users` (150)

---

### 69. OVERSIZED_GROUP_HIGH (Medium) — ✅ 1 instance
**Description :** Groups with 200-500 members.
**Groupes :** `GS-Employees` (431)

---

### 70. GROUP_EMPTY_PRIVILEGED (Low) — ❌ 0 instance
**Description :** Privileged groups with no members.
**Résultat :** Tous les groupes privilégiés vérifiés ont des membres.
