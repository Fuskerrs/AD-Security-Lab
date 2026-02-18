# Trusts (7 vulnérabilités)

**Sévérité :** 0 Critical, 4 High, 3 Medium
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 167 | TRUST_SID_FILTERING_DISABLED | High | SID Filtering Disabled on Trust | ❌ | 0 | N/A (aucun trust) |
| 168 | TRUST_EXTERNAL_NO_SELECTIVE_AUTH | High | External Trust Without Selective Auth | ❌ | 0 | N/A (aucun trust) |
| 169 | TRUST_AES_DISABLED | High | AES Encryption Disabled on Trust | ❌ | 0 | N/A (aucun trust) |
| 170 | TRUST_RC4_ONLY | High | Trust Only Supports RC4 Encryption | ❌ | 0 | N/A (aucun trust) |
| 171 | TRUST_BIDIRECTIONAL | Medium | Bidirectional Trust Relationship | ❌ | 0 | N/A (aucun trust) |
| 172 | TRUST_FOREST_TRANSITIVE | Medium | Transitive Forest Trust | ❌ | 0 | N/A (aucun trust) |
| 173 | TRUST_INACTIVE | Medium | Inactive Trust Relationship | ❌ | 0 | N/A (aucun trust) |

**Résumé : 0/7 confirmés | 7 N/A — Aucune relation de confiance dans le domaine**

---

## Note

Ce domaine (`aza-me.cc`) est un domaine isolé sans aucune relation de confiance (trust) avec d'autres domaines ou forêts. Les 7 vulnérabilités de cette catégorie sont donc **non applicables**.

La commande `Get-ADTrust -Filter *` ne retourne aucun résultat.

---

## Détail des vulnérabilités

### 167. TRUST_SID_FILTERING_DISABLED (High) — ❌ N/A
**Description :** No SID filtering allows SID history injection. Attackers can impersonate any user.
**Résultat :** Aucun trust. Non applicable.

---

### 168. TRUST_EXTERNAL_NO_SELECTIVE_AUTH (High) — ❌ N/A
**Description :** Any user from trusted domain can authenticate to any resource in this domain.
**Résultat :** Aucun trust. Non applicable.

---

### 169. TRUST_AES_DISABLED (High) — ❌ N/A
**Description :** Forces use of weaker RC4/DES, more vulnerable to offline cracking.
**Résultat :** Aucun trust. Non applicable.

---

### 170. TRUST_RC4_ONLY (High) — ❌ N/A
**Description :** RC4 is deprecated. Kerberos tickets encrypted with RC4 are vulnerable to offline cracking.
**Résultat :** Aucun trust. Non applicable.

---

### 171. TRUST_BIDIRECTIONAL (Medium) — ❌ N/A
**Description :** Two-way trust increases attack surface. Compromise in either domain enables lateral movement.
**Résultat :** Aucun trust. Non applicable.

---

### 172. TRUST_FOREST_TRANSITIVE (Medium) — ❌ N/A
**Description :** All domains in trusted forest can access this domain. Significantly increases trust boundary.
**Résultat :** Aucun trust. Non applicable.

---

### 173. TRUST_INACTIVE (Medium) — ❌ N/A
**Description :** Trust not modified in 180+ days. May be abandoned/forgotten, should be reviewed.
**Résultat :** Aucun trust. Non applicable.
