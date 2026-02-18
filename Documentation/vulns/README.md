# Catalogue des Vulnérabilités AD - GlobalCorp

**Total : 253 détections uniques | 14 catégories**

**Cible :** DC-01 (10.10.0.83) — aza-me.cc
**Dernière vérification :** 2026-02-18
**Source :** go-collector v2.7 (253 detectors)

---

## Vue d'ensemble

| Catégorie | Vulns | Sévérité | Vérifié | Confirmé | Non trouvé | N/A |
|-----------|-------|----------|---------|----------|------------|-----|
| [Accounts](accounts/) | 32 | 3C, 15H, 12M, 2L | 32/32 | **31** | 0 | 1 (⚠️) |
| [Password](password/) | 10 | 5C, 2H, 3M | 10/10 | **10** | 0 | 0 |
| [Kerberos](kerberos/) | 14 | 4C, 5H, 4M, 1L | 13/14 | **12** | 1 | 0 |
| [Groups](groups/) | 15 | 1C, 5H, 8M, 1L | 15/15 | **15** | 0 | 0 |
| [Computers](computers/) | 30 | 8C, 9H, 10M, 3L | 29/30 | **24** | 5 | 0 |
| [Advanced](advanced/) | 32 | 5C, 9H, 15M, 1L, 1I | 28/32 | **23** | 3 | 2 |
| [Permissions](permissions/) | 16 | 1C, 5H, 10M | 7/16 | **7** | 0 | 0 |
| [ADCS](adcs/) | 11 | 3C, 6H, 2M | 7/11 | **7** | 0 | 0 |
| [GPO](gpo/) | 32 | 6C, 9H, 13M, 4L | 6/32 | **6** | 0 | 0 |
| [Trusts](trusts/) | 7 | 0C, 4H, 3M | 7/7 | **0** | 0 | 7 |
| [Attack Paths](attack-paths/) | 10 | 5C, 5H | 9/10 | **8** | 0 | 1 |
| [Monitoring](monitoring/) | 9 | 0C, 4H, 5M | 8/9 | **8** | 0 | 0 |
| [Compliance](compliance/) | 23 | 0C, 11H, 11M, 1L | 22/23 | **22** | 0 | 0 |
| [Network](network/) | 12 | 0C, 4H, 7M, 1L | 9/12 | **6** | 3 | 0 |
| **TOTAL** | **253** | | **202/253** | **179** | **12** | **11** |

---

## Résumé global

- **179/253 vulnérabilités confirmées** dans l'AD de lab (dont **29 injectées**)
- **12 non trouvées/non injectables** (protections AD natives, infrastructure manquante, ou risque trop élevé)
- **11 N/A** (7 trusts inexistants + 2 LAPS non déployé + 1 SID_HISTORY non injectable + 1 no trust)
- **51 non vérifiées** (24 tests ACL + 27 nouveaux détecteurs v2.7)

### Trouvailles critiques

| Priorité | Vulnérabilité | Impact |
|----------|---------------|--------|
| P0 | **GPO cpassword en SYSVOL** (#158) | Mots de passe en clair lisibles par tous |
| P0 | **Logon scripts vers \\evil.com** (#123) | 14 utilisateurs avec backdoor active |
| P0 | **AdminSDHolder backdoor** (#143) | sun.fang=GenericAll, Everyone=ExtendedRight |
| P0 | **DCSync 42 principals** (#105/#131) | 42+ comptes peuvent extraire tous les hashes |
| P0 | **ESC1 templates** (#147) | 4 templates permettent usurpation DA via cert |
| P1 | **24 Domain Admins** (#62/#193) | Surface d'attaque excessive |
| P1 | **55 admins sans smartcard** (#194/#199) | Pas d'authentification forte |
| P1 | **Protected Users vide** (#67/#190) | 0/24 DA protégés |
| P1 | **LDAP signing + channel binding** (#103/#109) | Relay NTLM possible |
| P1 | **71 machines sans LAPS** (#114) | Mots de passe locaux partagés |
| P2 | **Password policy MinLen=7** (#117/#165) | Sous tous les standards |
| P2 | **LockoutThreshold=0** (#117) | Brute-force illimité |
| P2 | **42 catégories audit=NoAuditing** (#126) | Détection quasi inexistante |
| P2 | **PowerShell logging disabled** (#127) | PS malveillant invisible |

---

## Scoring

| Sévérité | Poids | Impact |
|----------|-------|--------|
| Critical | 10 | Haut |
| High | 3 | Moyen |
| Medium | 1 | Faible |
| Low | 0.2 | Minimal |
| Info | 0 | Aucun |

---

## Légende

| Icône | Signification |
|-------|---------------|
| ✅ | Confirmé dans l'AD (vuln présente) |
| ❌ | Non trouvé dans l'AD |
| ⚠️ | Non vérifiable via LDAP/PowerShell |
| ❓ | Non encore vérifié |

---

*Dernière mise à jour :* 2026-02-18
*Source :* VULNERABILITY_CATALOG.md (go-collector v2.7, 253 detectors)
