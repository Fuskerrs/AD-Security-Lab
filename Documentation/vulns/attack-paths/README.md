# Attack Paths (10 vulnérabilités)

**Sévérité :** 5 Critical, 5 High
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 174 | PATH_ACL_TO_DA | Critical | ACL-Based Privilege Escalation to DA | ✅ | **7** | Confirmé |
| 175 | PATH_CERTIFICATE_ESC | Critical | Certificate Template Escalation to DA | ✅ | **4** | Confirmé (ESC1) |
| 176 | PATH_KERBEROASTING_TO_DA | Critical | Kerberoasting Path to DA | ✅ | **7** | Confirmé |
| 177 | PATH_SERVICE_TO_DA | Critical | Service Account Path to DA | ✅ | **2** | Confirmé |
| 178 | PATH_GPO_TO_DA | Critical | GPO Modification Path to DA | ❓ | - | Non vérifié |
| 179 | PATH_ASREP_TO_ADMIN | High | AS-REP Roasting Path to Admin | ✅ | **5** | Confirmé |
| 180 | PATH_COMPUTER_TAKEOVER | High | RBCD Computer Takeover Path | ✅ | **3** | Confirmé |
| 181 | PATH_DELEGATION_CHAIN | High | Delegation Chain to Privileged Target | ✅ | **17** | Confirmé |
| 182 | PATH_NESTED_ADMIN | High | Excessive Group Nesting to Admin | ✅ | **2** | Confirmé |
| 183 | PATH_TRUST_LATERAL | High | Trust Enables Lateral Movement | ❌ | 0 | N/A (aucun trust) |

**Résumé : 8/10 confirmés | 1 N/A | 1 non vérifié**

---

## Détail des vulnérabilités

### 174. PATH_ACL_TO_DA (Critical) — ✅ 7 instances
**Description :** Non-privileged users can escalate to DA through ACL chain (WriteDACL, GenericAll, WriteOwner).
**Résultat :** **7 principals** avec GenericAll, WriteDACL, ou WriteOwner directement sur le groupe Domain Admins (hors SYSTEM/DA/EA/Administrators).

---

### 175. PATH_CERTIFICATE_ESC (Critical) — ✅ 4 instances
**Description :** Vulnerable templates (ESC1-like) allow users to request certificates for any user including DAs.
**Résultat :** 4 templates ESC1 vulnérables (CA, SubCA, OfflineRouter, CrossCA). Un utilisateur peut demander un certificat avec le SAN d'un Domain Admin et s'authentifier en tant que DA.

---

### 176. PATH_KERBEROASTING_TO_DA (Critical) — ✅ 7 instances
**Description :** User with SPN in privileged group. Kerberoasting + cracking leads to DA compromise.
**Résultat :** **7 membres de Domain Admins avec SPN**. Leurs tickets Kerberos TGS sont extractibles et crackables offline. Si le mot de passe est faible, le compte DA est compromis.

---

### 177. PATH_SERVICE_TO_DA (Critical) — ✅ 2 instances
**Description :** Service accounts with paths to DA through membership, ACLs, or delegation.
**Résultat :** **2 comptes de service** (pattern `svc|service|srv`) qui sont membres de Domain Admins avec SPN. Double risque : Kerberoasting + compte de service avec privilèges DA.

---

### 178. PATH_GPO_TO_DA (Critical) — ❓ Non vérifié
**Description :** GPOs modifiable by non-admins. If applied to privileged users or DCs, enables DA.
**Résultat :** Non testé individuellement. Voir GPO #159 (GPO_DANGEROUS_PERMISSIONS).

---

### 179. PATH_ASREP_TO_ADMIN (High) — ✅ 5 instances
**Description :** User without Kerberos pre-auth in admin group. AS-REP roasting leads to admin compromise.
**Résultat :** **5 membres de Domain Admins avec DoesNotRequirePreAuth=True**. Leurs AS-REP sont directement extractibles sans authentification et crackables offline.

---

### 180. PATH_COMPUTER_TAKEOVER (High) — ✅ 3 instances
**Description :** Privileged computers with RBCD configured. Attackers controlling delegating principal can compromise.
**Résultat :** 3 ordinateurs avec `msDS-AllowedToActOnBehalfOfOtherIdentity` configuré. Un attaquant contrôlant le principal délégant peut usurper n'importe quel utilisateur sur ces machines.

---

### 181. PATH_DELEGATION_CHAIN (High) — ✅ 17 instances
**Description :** Constrained delegation to DC services. Can impersonate privileged users.
**Résultat :** **17 objets avec délégation contrainte** vers des services sensibles (`ldap/`, `cifs/`, `host/`). Permet l'usurpation d'identité vers les DCs et services critiques.

---

### 182. PATH_NESTED_ADMIN (High) — ✅ 2 instances
**Description :** Users reach admin groups through excessive nesting (>3 levels). Hides admin access.
**Résultat :** 2 chaînes de nesting détectées : `DA → Group → SubGroup`. L'accès admin est masqué par l'imbrication de groupes.

---

### 183. PATH_TRUST_LATERAL (High) — ❌ N/A
**Description :** Trusts without proper controls (SID filtering, selective auth). Compromising trusted domain leads here.
**Résultat :** Aucune relation de confiance dans le domaine. Non applicable.
