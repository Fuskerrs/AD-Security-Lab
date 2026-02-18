# ADCS (11 vulnérabilités)

**Sévérité :** 3 Critical, 6 High, 2 Medium
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 147 | ESC1_VULNERABLE_TEMPLATE | Critical | ESC1 - Misconfigured Certificate Template | ✅ | **4** | Confirmé |
| 148 | ESC4_VULNERABLE_TEMPLATE_ACL | Critical | ESC4 - Vulnerable Certificate Template ACL | ❓ | - | Non vérifié |
| 149 | ESC8_HTTP_ENROLLMENT | Critical | ESC8 - HTTP Web Enrollment Enabled | ❓ | - | Non vérifié |
| 150 | ESC2_ANY_PURPOSE | High | ESC2 - Any Purpose Certificate Template | ✅ | **3** | Confirmé |
| 151 | ESC3_ENROLLMENT_AGENT | High | ESC3 - Enrollment Agent Certificate Template | ✅ | **4** | Confirmé |
| 152 | ESC6_EDITF_FLAG | High | ESC6 - CA Configuration Review Required | ✅ | **1** | Confirmé (injecté EDITF_ATTRIBUTESUBJECTALTNAME2) |
| 153 | ESC7_CA_VULNERABLE_ACL | High | ESC7 - CA Vulnerable ACL | ❓ | - | Non vérifié |
| 154 | ESC9_NO_SECURITY_EXTENSION | High | ESC9 - No Security Extension | ✅ | **24** | Confirmé |
| 155 | ESC10_WEAK_CERTIFICATE_MAPPING | High | ESC10 - Certificate Mapping Review Required | ✅ | **1** | Confirmé |
| 156 | ESC5_PKI_OBJECT_ACL | Medium | ESC5 - PKI Object Vulnerable ACL | ❓ | - | Non vérifié |
| 157 | ESC11_ICERT_REQUEST_ENFORCEMENT | Medium | ESC11 - RPC Encryption Enforcement Check | ❓ | - | Non vérifié |

**Résumé : 7/11 confirmés (dont 1 injecté) | 4 non vérifiés**

---

## Infrastructure PKI

- **CA :** 1 Autorité de Certification détectée (aza-me-DC-01-CA)
- **Templates :** 33 templates de certificats au total

---

## Détail des vulnérabilités

### 147. ESC1_VULNERABLE_TEMPLATE (Critical) — ✅ 4 instances
**Description :** Template allows enrollee to specify SAN and has client auth EKU. Enables privilege escalation to any user.
**Résultat :** 4 templates vulnérables ESC1 :
- `CA` — Subject Alternative Name (SAN) spécifiable + Client Authentication EKU
- `SubCA` — SAN spécifiable + Client Authentication EKU
- `OfflineRouter` — SAN spécifiable + Client Authentication EKU
- `CrossCA` — SAN spécifiable + Client Authentication EKU

Un attaquant peut demander un certificat pour n'importe quel utilisateur (y compris Domain Admin).

---

### 148. ESC4_VULNERABLE_TEMPLATE_ACL (Critical) — ❓ Non vérifié
**Description :** Templates with dangerous permissions granted to non-admins. Allows unauthorized modification of template properties.
**Résultat :** Non testé individuellement (ACLs des templates).

---

### 149. ESC8_HTTP_ENROLLMENT (Critical) — ❓ Non vérifié
**Description :** CA web enrollment accessible over HTTP. Enables NTLM relay against certificate enrollment.
**Résultat :** Non testé (nécessite test HTTP sur le service d'enrollment).

---

### 150. ESC2_ANY_PURPOSE (High) — ✅ 3 instances
**Description :** Template has 'Any Purpose' EKU or no EKU constraints. Issued certificates usable for any purpose including client auth.
**Résultat :** 3 templates avec EKU "Any Purpose" (OID 2.5.29.37.0) ou sans restriction EKU.

---

### 151. ESC3_ENROLLMENT_AGENT (High) — ✅ 4 instances
**Description :** Template allows enrollment agent certificates. Can enroll certificates on behalf of other users.
**Résultat :** 4 templates avec EKU "Certificate Request Agent" (OID 1.3.6.1.4.1.311.20.2.1). Permet à un agent d'enrollment de demander des certificats au nom d'autres utilisateurs.

---

### 152. ESC6_EDITF_FLAG (High) — ✅ 1 instance
**Description :** CA should be checked for EDITF_ATTRIBUTESUBJECTALTNAME2 flag which allows any requestor to specify SAN.
**Résultat :** Flag EDITF_ATTRIBUTESUBJECTALTNAME2 **activé** via `certutil -setreg`. Tout demandeur peut spécifier un SAN arbitraire dans sa requête de certificat, permettant l'usurpation d'identité.

---

### 153. ESC7_CA_VULNERABLE_ACL (High) — ❓ Non vérifié
**Description :** CA objects with ManageCA or ManageCertificates rights for non-admins. Allows certificate issuance and CA config changes.
**Résultat :** Non testé individuellement (ACLs de la CA).

---

### 154. ESC9_NO_SECURITY_EXTENSION (High) — ✅ 24 instances
**Description :** Schema v1 templates without szOID_NTDS_CA_SECURITY_EXT. Combined with weak mapping, enables impersonation.
**Résultat :** **24 templates Schema v1** sans l'extension de sécurité szOID_NTDS_CA_SECURITY_EXT. Combiné avec le weak certificate mapping (#155), ces templates permettent l'usurpation d'identité.

---

### 155. ESC10_WEAK_CERTIFICATE_MAPPING (High) — ✅ 1 instance
**Description :** DCs should be configured for strong certificate mapping to prevent impersonation attacks.
**Résultat :** Certificate mapping faible détecté. Combiné avec les 24 templates v1 (#154), cela crée un risque d'usurpation d'identité via certificats.

---

### 156. ESC5_PKI_OBJECT_ACL (Medium) — ❓ Non vérifié
**Description :** PKI-related objects with dangerous permissions. Could allow modification of CA config or templates.
**Résultat :** Non testé individuellement.

---

### 157. ESC11_ICERT_REQUEST_ENFORCEMENT (Medium) — ❓ Non vérifié
**Description :** CAs should enforce RPC encryption to prevent NTLM relay to ICertPassage RPC interface.
**Résultat :** Non testé (nécessite certutil -getreg).
