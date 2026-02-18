# Advanced (32 vulnérabilités)

**Sévérité :** 5 Critical, 9 High, 15 Medium, 1 Low, 1 Info
**Dernière vérification :** 2026-02-17
**Cible :** DC-01 (10.10.0.83) — aza-me.cc

---

## Résultats

| # | Type | Sévérité | Titre | Vérifié | Instances | Status |
|---|------|----------|-------|---------|-----------|--------|
| 100 | SHADOW_CREDENTIALS | Critical | Shadow Credentials | ✅ | **3** | Confirmé (injecté msDS-KeyCredentialLink) |
| 101 | RBCD_ABUSE | Critical | RBCD Abuse | ✅ | **3** | Confirmé |
| 102 | EXCHANGE_PRIV_ESC_PATH | Critical | Exchange Privilege Escalation Risk | ❌ | 0 | Non trouvé |
| 103 | LDAP_SIGNING_DISABLED | Critical | LDAP Signing Not Required | ✅ | **1** | Confirmé |
| 104 | SMB_SIGNING_DISABLED | Critical | SMB Signing Not Required | ❌ | 0 | Non trouvé |
| 105 | DCSYNC_CAPABLE | High | DCSync Capable | ✅ | **42** | Confirmé |
| 106 | REPLICATION_RIGHTS | High | Replication Rights | ⚠️ | - | Non vérifié |
| 107 | LAPS_PASSWORD_READABLE | High | LAPS Password Readable | ⚠️ | - | N/A (pas de LAPS) |
| 108 | MACHINE_ACCOUNT_QUOTA_HIGH | High | Machine Account Quota Elevated | ✅ | **1** | Confirmé (injecté quota=50) |
| 109 | LDAP_CHANNEL_BINDING_DISABLED | High | LDAP Channel Binding Not Required | ✅ | **1** | Confirmé |
| 110 | SMB_V1_ENABLED | High | SMBv1 Enabled | ❌ | 0 | Non trouvé |
| 111 | ADMIN_SD_HOLDER_MODIFIED | High | AdminSDHolder Modified | ✅ | **12** | Confirmé |
| 112 | ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2 | High | ESC6 EDITF Flag (Advanced) | ✅ | **1** | Confirmé (injecté certutil -setreg) |
| 113 | ADCS_WEAK_PERMISSIONS | Medium | ADCS Weak Permissions | ✅ | **33** | Confirmé (33 templates) |
| 114 | LAPS_NOT_DEPLOYED | Medium | LAPS Not Deployed | ✅ | **71** | Confirmé (71/71 sans LAPS) |
| 115 | LAPS_LEGACY_ATTRIBUTE | Medium | LAPS Legacy Attribute | ❌ | 0 | Non trouvé (pas de LAPS du tout) |
| 116 | DUPLICATE_SPN | Medium | Duplicate SPN | ❌ | 0 | Non trouvé |
| 117 | WEAK_PASSWORD_POLICY | Medium | Weak Password Policy | ✅ | **1** | Confirmé |
| 118 | WEAK_KERBEROS_POLICY | Medium | Weak Kerberos Policy | ✅ | **1** | Confirmé |
| 119 | MACHINE_ACCOUNT_QUOTA_ABUSE | Medium | Machine Account Quota Abuse | ✅ | **1** | Confirmé (quota=10) |
| 120 | DELEGATION_PRIVILEGE | Medium | Delegation Privilege | ⚠️ | - | Non vérifié |
| 121 | FOREIGN_SECURITY_PRINCIPALS | Medium | Foreign Security Principals | ✅ | **4** | Confirmé |
| 122 | NTLM_RELAY_OPPORTUNITY | Medium | NTLM Relay Opportunity | ✅ | **1** | Confirmé |
| 123 | DANGEROUS_LOGON_SCRIPTS | Medium | Dangerous Logon Scripts | ✅ | **16** | Confirmé |
| 124 | ANONYMOUS_LDAP_ACCESS | Medium | Anonymous LDAP Access Allowed | ✅ | **1** | Confirmé (injecté dsHeuristics 7e char="2") |
| 125 | RECYCLE_BIN_DISABLED | Medium | AD Recycle Bin Not Enabled | ✅ | **1** | Confirmé |
| 126 | AUDIT_POLICY_WEAK | Medium | Weak Audit Policy Configuration | ✅ | **1** | Confirmé (42 catégories) |
| 127 | POWERSHELL_LOGGING_DISABLED | Medium | PowerShell Logging Disabled | ✅ | **1** | Confirmé |
| 128 | DS_HEURISTICS_MODIFIED | Medium | dsHeuristics Modified | ✅ | **1** | Confirmé (injecté "0000002") |
| 129 | LAPS_PASSWORD_LEAKED | Low | LAPS Password Leaked | ❌ | 0 | N/A (pas de LAPS) |
| 130 | LAPS_PASSWORD_SET | Info | LAPS Password Set | ❌ | 0 | Aucun LAPS déployé |
| 131 | DS_HEURISTICS_LDAP_SECURITY | High | dsHeuristics LDAP Security Weakened | ❓ | - | Non vérifié |

**Résumé : 23/32 confirmés (dont 5 injectés) | 3 non trouvés | 3 non vérifiés | 2 N/A | 1 non vérifié (nouveau)**

---

## Détail des vulnérabilités

### 100. SHADOW_CREDENTIALS (Critical) — ✅ 3 instances
**Description :** msDS-KeyCredentialLink configured. Allows Kerberos auth bypass by adding arbitrary public keys.
**Résultat :** 3 utilisateurs avec msDS-KeyCredentialLink injecté via ADSI DirectoryEntry (format DN-With-Binary `B:<hexcount>:<hex>:<DN>`).

---

### 101. RBCD_ABUSE (Critical) — ✅ 3 instances
**Description :** msDS-AllowedToActOnBehalfOfOtherIdentity configured. Enables RBCD attack privilege escalation.
**Résultat :** 3 objets avec RBCD configuré (même résultat que Computers #80).

---

### 102. EXCHANGE_PRIV_ESC_PATH (Critical) — ❌ 0 instance
**Description :** Exchange security groups with dangerous permissions. WriteDacl on domain (CVE-2019-1166).
**Résultat :** Aucun groupe Exchange trouvé. Exchange n'est pas installé.

---

### 103. LDAP_SIGNING_DISABLED (Critical) — ✅ 1 instance
**Description :** LDAP signing not required on DCs. Vulnerable to LDAP relay attacks.
**Résultat :** `LDAPServerIntegrity = 1` (Negotiate signing, NOT required). Devrait être `2` (Required).

---

### 104. SMB_SIGNING_DISABLED (Critical) — ❌ 0 instance
**Description :** SMB signing not required on DCs. Vulnerable to NTLM relay attacks.
**Résultat :** `RequireSecuritySignature = True`. SMB signing est requis.

---

### 105. DCSYNC_CAPABLE (High) — ✅ 42 instances
**Description :** Principals with DS-Replication-Get-Changes + Get-Changes-All. Can perform DCSync to extract all password hashes.
**Résultat :** 42 principals non-standard avec droits de réplication. Risque majeur de DCSync.

---

### 106. REPLICATION_RIGHTS (High) — ⚠️ Non vérifié
**Description :** Account with adminCount=1 outside standard admin groups. May have replication rights (DCSync).
**Résultat :** Non testé individuellement (couvert partiellement par #105).

---

### 107. LAPS_PASSWORD_READABLE (High) — ⚠️ N/A
**Description :** Non-admin users can read LAPS password attributes. Exposure of local admin passwords.
**Résultat :** LAPS n'est pas déployé (#114), donc non applicable.

---

### 108. MACHINE_ACCOUNT_QUOTA_HIGH (High) — ✅ 1 instance
**Description :** ms-DS-MachineAccountQuota higher than default (10). Intentionally increased.
**Résultat :** Quota injecté à **50** (au lieu de 10 par défaut). Tout utilisateur peut joindre 50 machines au domaine.

---

### 109. LDAP_CHANNEL_BINDING_DISABLED (High) — ✅ 1 instance
**Description :** LDAP channel binding not set to 'Always'. Vulnerable to LDAP relay attacks.
**Résultat :** `LdapEnforceChannelBinding` non configuré (disabled). Devrait être `2` (Always).

---

### 110. SMB_V1_ENABLED (High) — ❌ 0 instance
**Description :** SMBv1 enabled on DCs. Deprecated and vulnerable to EternalBlue, WannaCry.
**Résultat :** SMBv1 désactivé.

---

### 111. ADMIN_SD_HOLDER_MODIFIED (High) — ✅ 12 instances
**Description :** Non-standard permissions on AdminSDHolder. Propagates to all protected accounts via SDProp.
**Résultat :** 12 ACEs non-standard sur AdminSDHolder. Ces permissions se propagent à tous les comptes protégés.

---

### 112. ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2 (High) — ✅ 1 instance
**Description :** ADCS CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag. Allows arbitrary SAN in certificate requests.
**Résultat :** Flag EDITF_ATTRIBUTESUBJECTALTNAME2 activé via `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2`. Tout demandeur de certificat peut spécifier un SAN arbitraire.

---

### 113. ADCS_WEAK_PERMISSIONS (Medium) — ✅ 33 instances
**Description :** Weak permissions on ADCS objects or certificate templates allow unauthorized enrollment.
**Résultat :** 33 templates de certificats détectés. Plusieurs avec des permissions faibles (voir catégorie ADCS).

---

### 114. LAPS_NOT_DEPLOYED (Medium) — ✅ 71 instances
**Description :** LAPS not deployed on domain computers. Shared/static local admin passwords.
**Résultat :** **71/71 ordinateurs sans LAPS**. Aucun déploiement LAPS dans le domaine.

---

### 115. LAPS_LEGACY_ATTRIBUTE (Medium) — ❌ 0 instance
**Description :** Legacy LAPS attribute used instead of Windows LAPS. Less secure implementation.
**Résultat :** Ni legacy LAPS ni Windows LAPS déployé. Pas d'attribut à comparer.

---

### 116. DUPLICATE_SPN (Medium) — ❌ 0 instance
**Description :** SPN registered multiple times. Can cause Kerberos authentication failures.
**Résultat :** Aucun SPN dupliqué détecté (setspn -X clean).

---

### 117. WEAK_PASSWORD_POLICY (Medium) — ✅ 1 instance
**Description :** Domain password policy below minimum standards. Enables easier password cracking.
**Résultat :** `MinPasswordLength=7`, `LockoutThreshold=0` (pas de verrouillage), `ComplexityEnabled=True`. Politique faible par rapport aux standards (ANSSI=12, CIS=14).

---

### 118. WEAK_KERBEROS_POLICY (Medium) — ✅ 1 instance
**Description :** Kerberos ticket lifetimes exceed recommended values. Longer window for ticket-based attacks.
**Résultat :** `MaxTicketAge=20h` (recommandé: 10h), `MaxServiceAge=600min`. TGT trop long.

---

### 119. MACHINE_ACCOUNT_QUOTA_ABUSE (Medium) — ✅ 1 instance
**Description :** ms-DS-MachineAccountQuota > 0. Non-admin users can join computers to domain.
**Résultat :** Quota = 10. N'importe quel utilisateur peut joindre jusqu'à 10 machines au domaine.

---

### 120. DELEGATION_PRIVILEGE (Medium) — ⚠️ Non vérifié
**Description :** Account has SeEnableDelegationPrivilege. Can enable delegation on accounts.
**Résultat :** Non testé individuellement.

---

### 121. FOREIGN_SECURITY_PRINCIPALS (Medium) — ✅ 4 instances
**Description :** Foreign security principals from external forests. Cross-forest privilege escalation risk.
**Résultat :** 4 FSPs détectés dans CN=ForeignSecurityPrincipals.

---

### 122. NTLM_RELAY_OPPORTUNITY (Medium) — ✅ 1 instance
**Description :** LDAP signing or channel binding not enforced. Enables NTLM relay attacks.
**Résultat :** LDAP signing = Negotiate (pas Required) + Channel binding disabled. Double vulnérabilité relay.

---

### 123. DANGEROUS_LOGON_SCRIPTS (Medium) — ✅ 16 instances
**Description :** Logon scripts with weak ACLs can be modified for code execution on user login.
**Résultat :** 16 utilisateurs avec scripts de logon. **14 pointent vers `\\evil.com\share\payload.ps1`** — backdoor active !

---

### 124. ANONYMOUS_LDAP_ACCESS (Medium) — ✅ 1 instance
**Description :** LDAP accepts anonymous binds. Attackers can enumerate AD objects without credentials.
**Résultat :** dsHeuristics modifié (7e caractère = "2") pour activer l'accès anonyme LDAP. Les attaquants peuvent énumérer l'AD sans identifiants.

---

### 125. RECYCLE_BIN_DISABLED (Medium) — ✅ 1 instance
**Description :** Deleted objects cannot be easily recovered. Complicates incident response.
**Résultat :** Corbeille AD non activée. Les objets supprimés sont perdus définitivement.

---

### 126. AUDIT_POLICY_WEAK (Medium) — ✅ 1 instance (policy)
**Description :** Critical audit categories not configured for Success and Failure.
**Résultat :** **42 sous-catégories d'audit sans aucune configuration** (No Auditing). La majorité des événements de sécurité ne sont pas journalisés.

---

### 127. POWERSHELL_LOGGING_DISABLED (Medium) — ✅ 1 instance
**Description :** PowerShell Script Block Logging not enabled. Prevents detection of malicious PS activity.
**Résultat :** `EnableScriptBlockLogging` non configuré. Les commandes PowerShell malveillantes passent inaperçues.

---

### 128. DS_HEURISTICS_MODIFIED (Medium) — ✅ 1 instance
**Description :** dsHeuristics attribute modified from defaults. May weaken AD security.
**Résultat :** dsHeuristics modifié à "0000002" (active l'accès anonyme LDAP). Lié à #124.

---

### 129. LAPS_PASSWORD_LEAKED (Low) — ❌ 0 instance
**Description :** LAPS password visible to too many users. Reduces effectiveness of LAPS.
**Résultat :** N/A — LAPS non déployé.

---

### 130. LAPS_PASSWORD_SET (Info) — ❌ 0 instance
**Description :** LAPS password successfully managed. Informational - indicates proper deployment.
**Résultat :** 0 machines avec LAPS. Aucune gestion automatique des mots de passe locaux.

---

### 131. DS_HEURISTICS_LDAP_SECURITY (High) — ❓ Non vérifié
**Description :** The dsHeuristics attribute contains settings that weaken LDAP security. Position 7 controls anonymous LDAP operations binding; when not set to '2', anonymous binds may be permitted.
**Résultat :** Non testé individuellement. Note : lié à #124 (anonymous LDAP) et #128 (dsHeuristics modified).
