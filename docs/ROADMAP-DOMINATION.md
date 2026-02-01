# Roadmap pour dominer Ping Castle & Purple Knight

**Vision:** Devenir LA référence AD security avec un collecteur open source + SaaS premium

**Date:** 2026-01-31
**Version actuelle:** v1.2.6 (120 types, 95% coverage)

---

## 🎯 Objectif

**Surpasser:**
- Ping Castle (150+ types, gratuit, open source)
- Purple Knight (100+ types, gratuit)

**Avec:**
- Collecteur open source (gratuit, API REST)
- SaaS commercial (reporting, graphs, historique, ML)

---

## 📋 Ce qui manque AUJOURD'HUI

### ❌ Manques critiques (vs Ping Castle)

| Feature | Priorité | Difficulté | Impact |
|---------|----------|------------|--------|
| SYSVOL password scan | 🔴 P0 | 🟢 Facile | Haut |
| SMB signing check | 🔴 P0 | 🟡 Moyen | Haut |
| LDAP signing check | 🔴 P0 | 🟡 Moyen | Haut |
| Attack graph analysis | 🔴 P0 | 🔴 Difficile | Très haut |
| Nested ACL permissions | 🟠 P1 | 🔴 Difficile | Haut |
| Trusts analysis | 🟠 P1 | 🟡 Moyen | Moyen |
| Forest analysis | 🟡 P2 | 🟡 Moyen | Moyen |

### ❌ Manques vs Purple Knight

| Feature | Priorité | Difficulté | Impact |
|---------|----------|------------|--------|
| Ransomware indicators | 🔴 P0 | 🟡 Moyen | Très haut |
| Recovery readiness | 🔴 P0 | 🟡 Moyen | Très haut |
| Backup validation | 🟠 P1 | 🔴 Difficile | Haut |
| AD replication health | 🟠 P1 | 🟡 Moyen | Moyen |

---

## 🚀 ROADMAP - Phase 1: Parité (Q1 2026)

**Objectif:** Égaler Ping Castle & Purple Knight (150+ types)

### v1.3.0 - Network Security (2 semaines)
**+8 types**

```
✅ SMB_SIGNING_DISABLED (check registry/GPO)
✅ LDAP_SIGNING_DISABLED (check AD config)
✅ LDAPS_NOT_ENFORCED (port 636 check)
✅ SMBv1_ENABLED (feature check)
✅ NTLM_NOT_RESTRICTED (GPO check)
✅ LLMNR_ENABLED (network check)
✅ WPAD_ENABLED (DNS/DHCP check)
✅ IPV6_ENABLED_UNUSED (config check)
```

**Détection:** Registry + GPO + Network checks

### v1.3.1 - SYSVOL & GPO Complete (1 semaine)
**+5 types**

```
✅ GPO_PASSWORD_IN_SYSVOL (XML scan)
✅ GPO_LAPS_NOT_DEPLOYED (GPO search)
✅ GPO_AUTOLOGON_PASSWORD (scan cpassword)
✅ GPO_SCHEDULED_TASK_PASSWORD (XML check)
✅ GPO_SCRIPTS_WRITABLE (SYSVOL permissions)
```

**Détection:** File scan + XML parsing

### v1.3.2 - Ransomware Readiness (2 semaines)
**+12 types**

```
✅ RANSOMWARE_VSS_DISABLED (Shadow Copy check)
✅ RANSOMWARE_BACKUP_NOT_PROTECTED (backup account check)
✅ RANSOMWARE_RECOVERY_PLAN_MISSING (GPO/scripts check)
✅ RANSOMWARE_ADMIN_EXPOSURE (lateral movement risk)
✅ RANSOMWARE_PRIVILEGED_RDP (RDP to DC)
✅ RANSOMWARE_WMI_FILTER_ABUSE (WMI check)
✅ RANSOMWARE_DCSYNC_RISK (replication rights check - exists)
✅ RANSOMWARE_BACKUP_OPERATORS_RISK (member check - exists)
✅ AD_RECYCLE_BIN_DISABLED (exists)
✅ DSRM_PASSWORD_WEAK (DSRM check)
✅ KRBTGT_PASSWORD_OLD (check last change)
✅ DC_VIRTUALIZATION_SAFEGUARDS (VM-GenerationID check)
```

**Détection:** Config + Registry + GPO

### v1.3.3 - Trusts & Forests (1 semaine)
**+8 types**

```
✅ TRUST_SID_FILTERING_DISABLED (trust attributes)
✅ TRUST_SELECTIVE_AUTH_DISABLED (trust config)
✅ TRUST_EXTERNAL_UNVALIDATED (trust validation)
✅ FOREST_FUNCTIONAL_LEVEL_LOW (forest level check)
✅ DOMAIN_FUNCTIONAL_LEVEL_LOW (domain level check)
✅ CROSS_FOREST_TRUST_WEAK (trust cipher check)
✅ TRUST_TGT_DELEGATION (trust delegation check)
✅ TRUST_BIDIRECTIONAL_UNNECESSARY (trust direction)
```

**Détection:** Trust enumeration + validation

**Total Phase 1: +33 types → 153 types total** 🎯

---

## 🎯 ROADMAP - Phase 2: Domination (Q2 2026)

**Objectif:** Dépasser Ping Castle avec des features uniques

### v1.4.0 - Attack Graph Analysis (4 semaines)
**+15 types + Infrastructure**

```
✅ Infrastructure:
   - Neo4j integration (graph database)
   - BloodHound-style analysis
   - Path algorithms (Dijkstra, A*)
   - Cache & optimization

✅ Attack Paths (Enhanced):
   PATH_TO_DA_VIA_ACL (ACL chain → DA)
   PATH_TO_DA_VIA_GROUP (group nesting → DA)
   PATH_TO_DA_VIA_GPO (GPO modify → DA)
   PATH_TO_DA_VIA_COMPUTER (computer compromise → DA)
   PATH_TO_DA_VIA_CERTIFICATE (cert abuse → DA)
   PATH_TO_DC_TAKEOVER (paths to DC compromise)
   PATH_TO_FOREST_ROOT (escalation to forest root)
   PATH_LATERAL_MOVEMENT (shortest lateral paths)
   PATH_PRIVILEGE_ESCALATION (escalation chains)
   PATH_PERSISTENCE (persistence opportunities)

✅ Nested Analysis:
   NESTED_ACL_CHAIN (A → B → C permissions)
   NESTED_GROUP_CHAIN (deep group nesting)
   NESTED_DELEGATION_CHAIN (delegation chains)
   NESTED_TRUST_CHAIN (trust hopping paths)
   NESTED_GPO_INHERITANCE (GPO inheritance abuse)
```

**Détection:** Graph algorithms + BloodHound-style

### v1.4.1 - Advanced ACL Analysis (2 semaines)
**+10 types**

```
✅ ACL_OWNER_MODIFICATION (owner changes)
✅ ACL_INHERITED_WEAK (weak inherited permissions)
✅ ACL_EVERYONE_WRITE (Everyone with write)
✅ ACL_AUTHENTICATED_USERS_ABUSE (Authenticated Users dangerous)
✅ ACL_CREATOR_OWNER_ABUSE (Creator Owner exploitation)
✅ ACL_DENY_ACE_MISSING (missing deny ACEs)
✅ ACL_EXPLICIT_ALLOW_REDUNDANT (redundant permissions)
✅ ACL_ORPHANED_SID (orphaned SID in ACLs)
✅ ACL_FOREIGN_SECURITY_PRINCIPAL (FSP abuse)
✅ ACL_PROTECTED_NOT_ENABLED (AdminSDHolder not protected)
```

**Détection:** Deep ACL parsing + inheritance analysis

### v1.4.2 - Cloud & Hybrid (3 semaines)
**+20 types - GAME CHANGER!**

```
✅ Azure AD / Entra ID Integration:
   ENTRA_LEGACY_AUTH_ENABLED
   ENTRA_MFA_NOT_ENFORCED
   ENTRA_CONDITIONAL_ACCESS_GAPS
   ENTRA_PRIVILEGED_SYNC_ACCOUNT
   ENTRA_SEAMLESS_SSO_WEAK
   ENTRA_PASSWORD_HASH_SYNC_RISK
   ENTRA_FEDERATION_TRUST_WEAK
   ENTRA_DEVICE_JOIN_UNMANAGED

✅ Hybrid Identity:
   HYBRID_ADFS_SIGNING_CERT_WEAK
   HYBRID_ADFS_TOKEN_LIFETIME_LONG
   HYBRID_PASSTHROUGH_AUTH_RISK
   HYBRID_CLOUD_KERBEROS_TRUST
   HYBRID_SYNC_ACCOUNT_EXPOSED
   HYBRID_ON_PREM_TO_CLOUD_ATTACK
   HYBRID_CLOUD_TO_ON_PREM_ATTACK

✅ Azure AD Connect:
   AADC_OVER_PRIVILEGED
   AADC_PASSWORD_WRITEBACK_RISK
   AADC_VERSION_OUTDATED
   AADC_STAGED_ROLLOUT_RISK
   AADC_SEAMLESS_SSO_KEY_OLD
```

**Détection:** Azure AD Graph API + Microsoft Graph

**Total Phase 2: +45 types → 198 types total** 🚀

---

## 💎 ROADMAP - Phase 3: Innovation (Q3-Q4 2026)

**Objectif:** Features que PERSONNE n'a

### v1.5.0 - AI/ML Detection (8 semaines)
**+30 types comportementaux**

```
✅ ML-Powered Detection:
   ANOMALY_LOGIN_PATTERN (unusual login times/locations)
   ANOMALY_PRIVILEGE_ESCALATION (sudden privilege changes)
   ANOMALY_GROUP_MEMBERSHIP (unusual group additions)
   ANOMALY_GPO_MODIFICATION (suspicious GPO changes)
   ANOMALY_ACCOUNT_CREATION (bulk account creation)
   ANOMALY_PERMISSION_GRANT (unusual permission grants)
   ANOMALY_KERBEROS_USAGE (abnormal Kerberos patterns)
   ANOMALY_REPLICATION (unusual replication activity)

✅ Behavioral Analysis:
   BEHAVIOR_DORMANT_ACCOUNT_ACTIVATED (dormant → active)
   BEHAVIOR_PRIVILEGE_CREEP (gradual privilege accumulation)
   BEHAVIOR_LATERAL_MOVEMENT_PATTERN (movement patterns)
   BEHAVIOR_DATA_EXFILTRATION_RISK (unusual data access)
   BEHAVIOR_PERSISTENCE_INDICATORS (persistence attempts)

✅ Threat Intelligence:
   IOC_KNOWN_MALICIOUS_ACCOUNT (threat intel match)
   IOC_COMPROMISED_CREDENTIAL (leaked credentials)
   IOC_ATTACKER_PATTERN (known attack patterns)
   IOC_RANSOMWARE_SIGNATURE (ransomware IOCs)

✅ Drift Detection:
   DRIFT_FROM_BASELINE (configuration drift)
   DRIFT_SECURITY_POSTURE (security degradation)
   DRIFT_COMPLIANCE (compliance violations)

✅ Predictive:
   PREDICT_COMPROMISE_RISK (ML risk scoring)
   PREDICT_PRIVILEGE_ESCALATION (escalation likelihood)
   PREDICT_LATERAL_MOVEMENT (movement probability)
   PREDICT_DATA_BREACH_RISK (breach risk scoring)
   PREDICT_RANSOMWARE_TARGET (ransomware target likelihood)
   PREDICT_INSIDER_THREAT (insider risk scoring)
```

**Technologie:**
- TensorFlow / PyTorch
- Time-series analysis
- Anomaly detection models
- Threat intel feeds integration

### v1.5.1 - Real-Time Monitoring (4 semaines)
**Infrastructure**

```
✅ Event Stream Processing:
   - Windows Event Log streaming
   - LDAP change notifications
   - Real-time ACL monitoring
   - GPO change detection
   - Group membership changes
   - Authentication events

✅ Alerting:
   - Webhook notifications
   - Slack/Teams/Discord integration
   - Email alerts
   - SMS (Twilio)
   - PagerDuty integration
   - Custom webhooks

✅ Response:
   - Auto-remediation scripts
   - Incident creation (Jira/ServiceNow)
   - Playbook execution
   - Quarantine actions
```

### v1.5.2 - Compliance & Standards (2 semaines)
**+25 compliance checks**

```
✅ Frameworks:
   CIS_AD_BENCHMARK (v1.0.0 - 100+ checks)
   NIST_800_53 (AD controls)
   ISO_27001 (AD security controls)
   PCI_DSS_v4 (AD requirements)
   HIPAA (healthcare AD requirements)
   SOC2 (AD security controls)
   GDPR (data protection in AD)

✅ Custom Compliance:
   COMPLIANCE_CUSTOM_POLICY (user-defined)
   COMPLIANCE_POLICY_VIOLATION (violations)
   COMPLIANCE_DRIFT (compliance degradation)
   COMPLIANCE_EXCEPTION_TRACKING (tracked exceptions)
```

**Total Phase 3: +55 types → 253 types total** 🎆

---

## 🏆 Différenciateurs UNIQUES

**Ce que PERSONNE d'autre n'a:**

1. **ML/AI Detection** 🤖
   - Anomaly detection comportementale
   - Predictive risk scoring
   - Threat intelligence integration
   - Drift detection automatique

2. **Real-Time Monitoring** ⚡
   - Event streaming
   - Instant alerting
   - Auto-remediation
   - Live dashboard

3. **Cloud/Hybrid** ☁️
   - Azure AD/Entra integration
   - Hybrid identity risks
   - Cloud attack paths
   - Multi-cloud support

4. **Modern API** 🚀
   - GraphQL + REST
   - Webhooks
   - Real-time SSE
   - Bulk operations

5. **Developer-First** 👨‍💻
   - Docker/Kubernetes
   - CI/CD native
   - Infrastructure as Code
   - GitOps ready

---

## 💰 Modèle Business - Open Core

### 🆓 Open Source (Gratuit)

**Collecteur Core:**
- 253 types de détections
- API REST complète
- Scan on-demand
- Export JSON/CSV
- CLI tool
- Documentation complète
- Community support

**Licence:** Apache 2.0 / MIT

### 💎 SaaS Commercial

**Tier 1 - Starter ($99/mois):**
- Web dashboard
- Scheduled scans (daily)
- Basic graphs
- 30 days historique
- Email alerts
- 5 domains

**Tier 2 - Professional ($299/mois):**
- Advanced reporting
- Custom graphs
- 1 year historique
- Real-time alerts (webhooks)
- ML-powered insights
- 20 domains
- API rate limit increased
- Slack/Teams integration

**Tier 3 - Enterprise ($999/mois):**
- Unlimited domains
- Unlimited historique
- Custom compliance policies
- Threat intelligence feed
- Auto-remediation
- SSO/SAML
- Audit logs
- SLA 99.9%
- Priority support
- Custom integrations
- White-label option

**Tier 4 - Enterprise Plus (Custom):**
- On-premise deployment
- Air-gapped support
- Custom ML models
- Dedicated support
- Professional services
- Training & certification
- Custom development

---

## 📊 Comparaison finale (après roadmap)

| Feature | ETC Collector | Ping Castle | Purple Knight |
|---------|---------------|-------------|---------------|
| **Types détectés** | 253+ | 150+ | 100+ |
| **ML/AI** | ✅✅ | ❌ | ❌ |
| **Real-time** | ✅✅ | ❌ | ❌ |
| **Cloud/Hybrid** | ✅✅ | ❌ | ⚠️ |
| **Attack Graph** | ✅✅ | ✅ | ⚠️ |
| **API** | ✅✅ REST+GraphQL | ⚠️ Basique | ❌ |
| **Compliance** | ✅✅ Multi-framework | ⚠️ Basique | ✅ |
| **Open Source** | ✅ | ✅ | ❌ |
| **SaaS Option** | ✅✅ | ❌ | ❌ |
| **Price (OSS)** | 🆓 | 🆓 | 🆓 |
| **Price (SaaS)** | $99-999/mo | N/A | N/A |

---

## 🎯 Timeline Réaliste

```
Q1 2026 (Jan-Mar): Phase 1 - Parité
├─ v1.3.0: Network Security (2 sem)
├─ v1.3.1: SYSVOL & GPO (1 sem)
├─ v1.3.2: Ransomware (2 sem)
└─ v1.3.3: Trusts (1 sem)
→ 153 types

Q2 2026 (Apr-Jun): Phase 2 - Domination
├─ v1.4.0: Attack Graph (4 sem)
├─ v1.4.1: ACL Analysis (2 sem)
└─ v1.4.2: Cloud/Hybrid (3 sem)
→ 198 types

Q3-Q4 2026: Phase 3 - Innovation
├─ v1.5.0: AI/ML (8 sem)
├─ v1.5.1: Real-time (4 sem)
└─ v1.5.2: Compliance (2 sem)
→ 253 types

Q1 2027: SaaS Launch 🚀
```

---

## 💪 Team Requirements

**Pour réaliser cette roadmap:**

- 2 Backend devs (Go/Python)
- 1 ML engineer (Phase 3)
- 1 Frontend dev (SaaS dashboard)
- 1 DevOps (infra, CI/CD)
- 1 Security researcher (détections)
- 1 Product manager

**Budget estimé:** $500K/an (Phase 1-2), $1M/an (Phase 3)

---

## 🎉 Success Metrics

**À 6 mois:**
- 1000+ GitHub stars
- 10,000+ downloads
- 100+ SaaS customers

**À 12 mois:**
- 5000+ GitHub stars
- 50,000+ downloads
- 500+ SaaS customers
- $200K ARR

**À 24 mois:**
- 10,000+ GitHub stars
- 200,000+ downloads
- 2000+ SaaS customers
- $1M+ ARR
- #1 AD security tool

---

## 🚀 Go-to-Market

1. **Open Source First** (GitHub)
2. **Community Building** (Discord, Reddit)
3. **Content Marketing** (Blog, YouTube)
4. **Conference Talks** (DEF CON, Black Hat)
5. **Partnerships** (MSPs, MSSPs)
6. **Certifications** (training programs)

---

**Vision finale:** Devenir le BloodHound + Ping Castle + Purple Knight des années 2026+ avec ML/AI et SaaS ! 🎯
