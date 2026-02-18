# Permissions (16 vulnérabilités)

**Sévérité :** 1 Critical, 5 High, 10 Medium
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 131 | ACL_DS_REPLICATION_GET_CHANGES | Critical | DS-Replication-Get-Changes Rights (DCSync) | ✅ | **76** | Confirmé |
| 132 | ACL_GENERICALL | High | ACL GenericAll | ✅ | **1** | Confirmé (injecté GenericAll sur domain root) |
| 133 | ACL_WRITEDACL | High | ACL WriteDACL | ✅ | **1** | Confirmé (injecté WriteDACL sur domain root) |
| 134 | ACL_WRITEOWNER | High | ACL WriteOwner | ✅ | **1** | Confirmé (injecté WriteOwner sur domain root) |
| 135 | ACL_SELF_MEMBERSHIP | High | Self-Membership Rights | ❓ | - | Non vérifié |
| 136 | COMPUTER_ACL_GENERICALL | High | Computer ACL GenericAll | ❓ | - | Non vérifié |
| 137 | ACL_GENERICWRITE | Medium | ACL GenericWrite | ❓ | - | Non vérifié |
| 138 | ACL_FORCECHANGEPASSWORD | Medium | ACL Force Change Password | ❓ | - | Non vérifié |
| 139 | ACL_USER_FORCE_CHANGE_PASSWORD | Medium | User-Force-Change-Password Rights | ❓ | - | Non vérifié |
| 140 | EVERYONE_IN_ACL | Medium | Everyone in ACL | ✅ | **1** | Confirmé (AdminSDHolder) |
| 141 | WRITESPN_ABUSE | Medium | Write SPN Abuse | ❓ | - | Non vérifié |
| 142 | GPO_LINK_POISONING | Medium | GPO Link Poisoning | ❓ | - | Non vérifié |
| 143 | ADMINSDHOLDER_BACKDOOR | Medium | AdminSDHolder Backdoor | ✅ | **11** | Confirmé |
| 144 | ACL_ADD_MEMBER | Medium | Add-Member Rights on Groups | ❓ | - | Non vérifié |
| 145 | ACL_WRITE_PROPERTY_EXTENDED | Medium | Extended Write Property Rights | ❓ | - | Non vérifié |
| 146 | ACL_COMPUTER_WRITE_VALIDATED_DNS | Medium | Validated-Write-DNS on Computers | ❓ | - | Non vérifié |

**Résumé : 7/16 confirmés (dont 3 injectés) | 9 non vérifiés**

---

## Détail des vulnérabilités

### 131. ACL_DS_REPLICATION_GET_CHANGES (Critical) — ✅ 76 instances
**Description :** Non-standard principals with directory replication rights. Enables DCSync to extract all password hashes.
**Résultat :** **76 principals non-standard** avec droits DS-Replication-Get-Changes et/ou Get-Changes-All sur la racine du domaine. Risque majeur de DCSync par des comptes non autorisés.

---

### 132. ACL_GENERICALL (High) — ✅ 1 instance
**Description :** GenericAll permission on sensitive AD objects. Full control (reset passwords, modify groups).
**Résultat :** ACE GenericAll injectée sur la racine du domaine pour un utilisateur non-admin. Contrôle total du domaine.

---

### 133. ACL_WRITEDACL (High) — ✅ 1 instance
**Description :** WriteDACL on sensitive objects. Can modify security descriptor to grant additional permissions.
**Résultat :** ACE WriteDACL injectée sur la racine du domaine. L'utilisateur peut modifier les permissions de sécurité du domaine.

---

### 134. ACL_WRITEOWNER (High) — ✅ 1 instance
**Description :** WriteOwner on sensitive objects. Can take ownership and modify permissions.
**Résultat :** ACE WriteOwner injectée sur la racine du domaine. L'utilisateur peut prendre la propriété de l'objet domaine.

---

### 135. ACL_SELF_MEMBERSHIP (High) — ❓ Non vérifié
**Description :** Self-membership rights on groups. Allows adding oneself to gain elevated privileges.
**Résultat :** Non testé individuellement sur les groupes privilégiés.

---

### 136. COMPUTER_ACL_GENERICALL (High) — ❓ Non vérifié
**Description :** GenericAll on computer objects. Can take over computer, configure RBCD, or extract credentials.
**Résultat :** Non testé individuellement. Voir Computers #79 (ACL_ABUSE: 19-20 instances).

---

### 137. ACL_GENERICWRITE (Medium) — ❓ Non vérifié
**Description :** GenericWrite on sensitive AD objects. Can modify many object attributes.
**Résultat :** Non testé individuellement sur la racine du domaine.

---

### 138. ACL_FORCECHANGEPASSWORD (Medium) — ❓ Non vérifié
**Description :** ExtendedRight to force password change. Can reset passwords without knowing current password.
**Résultat :** Non testé individuellement.

---

### 139. ACL_USER_FORCE_CHANGE_PASSWORD (Medium) — ❓ Non vérifié
**Description :** Rights to force password change on user accounts. Can reset passwords to take over accounts.
**Résultat :** Non testé individuellement.

---

### 140. EVERYONE_IN_ACL (Medium) — ✅ 1 instance
**Description :** Everyone or Authenticated Users with write permissions. Overly permissive access.
**Résultat :** **Everyone avec ExtendedRight sur AdminSDHolder**. Trouvé lors du test AdminSDHolder (#143).

---

### 141. WRITESPN_ABUSE (Medium) — ❓ Non vérifié
**Description :** WriteProperty for servicePrincipalName. Can set SPNs for targeted Kerberoasting.
**Résultat :** Non testé individuellement.

---

### 142. GPO_LINK_POISONING (Medium) — ❓ Non vérifié
**Description :** Weak ACLs on GPOs. Can modify GPO to execute code on targeted systems.
**Résultat :** Non testé individuellement. Voir catégorie GPO.

---

### 143. ADMINSDHOLDER_BACKDOOR (Medium) — ✅ 11 instances
**Description :** Unexpected ACL on AdminSDHolder. Persistent permissions on admin accounts.
**Résultat :** **11 ACEs non-standard sur AdminSDHolder**, dont :
- `sun.fang` avec **GenericAll** (contrôle total sur tous les comptes protégés)
- `Everyone` avec **ExtendedRight** (droits étendus pour tout le monde)

Ces permissions se propagent automatiquement via SDProp à tous les comptes avec `adminCount=1`.

---

### 144. ACL_ADD_MEMBER (Medium) — ❓ Non vérifié
**Description :** Rights to add members to groups. Can add accounts to privileged groups.
**Résultat :** Non testé individuellement.

---

### 145. ACL_WRITE_PROPERTY_EXTENDED (Medium) — ❓ Non vérifié
**Description :** Dangerous extended write property rights (script paths, home dirs, key credentials).
**Résultat :** Non testé individuellement.

---

### 146. ACL_COMPUTER_WRITE_VALIDATED_DNS (Medium) — ❓ Non vérifié
**Description :** Rights to modify DNS host names on computers. DNS spoofing and MITM risk.
**Résultat :** Non testé individuellement.
