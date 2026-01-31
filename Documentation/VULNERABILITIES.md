# Liste des 87 Vulnérabilités Active Directory - GlobalCorp Lab

Ce document liste toutes les vulnérabilités injectées par le script `Populate-AD-GlobalCorp.ps1`.

---

## 🔴 CRITICAL (9 vulnérabilités)

### 1. RBCD Abuse (Resource-Based Constrained Delegation)
- **Type**: WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity
- **Impact**: Permet de compromettre des comptes via Kerberos delegation
- **Détection**: `Get-ADUser -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity`

### 2. Primary Group ID Spoofing
- **Type**: Hidden Domain Admins membership
- **Impact**: Appartenance cachée au groupe Domain Admins
- **Détection**: `Get-ADUser -Filter * -Properties PrimaryGroupID | Where {$_.PrimaryGroupID -eq 512}`

### 3. AdminSDHolder Backdoor
- **Type**: Persistence sur tous les admins
- **Impact**: Persistance via AdminSDHolder pour tous les comptes admin
- **Détection**: Vérifier les ACLs sur CN=AdminSDHolder,CN=System

### 4. SID History Injection
- **Type**: Privilege escalation
- **Impact**: Escalade de privilèges via SID History manipulation
- **Détection**: `Get-ADUser -Filter * -Properties SIDHistory | Where {$_.SIDHistory}`

### 5. Shadow Credentials ACL
- **Type**: WriteProperty on msDS-KeyCredentialLink
- **Impact**: Permet d'ajouter des credentials WHfB pour prendre le contrôle du compte
- **Détection**: `Get-ADUser -Filter * -Properties msDS-KeyCredentialLink`

### 6. DNS Admins Membership
- **Type**: DLL injection -> SYSTEM on DC
- **Impact**: Exécution de code arbitraire sur le DC via DLL loading
- **Détection**: `Get-ADGroupMember "DnsAdmins"`

### 7. Sensitive Delegation
- **Type**: Admins avec delegation activée
- **Impact**: Comptes admin configurés pour la délégation Kerberos
- **Détection**: `Get-ADUser -Filter {TrustedForDelegation -eq $true -and AdminCount -eq 1}`

### 8. Exchange Security Groups Membership
- **Type**: Exchange Trusted Subsystem / Organization Management
- **Impact**: Permet DCSync et contrôle complet de l'AD via Exchange
- **Détection**: `Get-ADGroupMember "Exchange Trusted Subsystem"`

### 9. DCSync Rights
- **Type**: Replication rights (très dangereux)
- **Impact**: Permet de dumper tous les hashes NTLM du domaine
- **Détection**: Vérifier ACLs avec DS-Replication-Get-Changes

---

## 🟠 HIGH (12 vulnérabilités)

### 10. Backup Operators Membership
- **Type**: NTDS.dit access
- **Impact**: Accès direct à la base de données AD
- **Détection**: `Get-ADGroupMember "Backup Operators"`

### 11. Account Operators Membership
- **Type**: Create accounts privilege
- **Impact**: Peut créer des comptes et modifier des groupes
- **Détection**: `Get-ADGroupMember "Account Operators"`

### 12. Server Operators Membership
- **Type**: Service modification
- **Impact**: Peut modifier les services sur les serveurs
- **Détection**: `Get-ADGroupMember "Server Operators"`

### 13. Print Operators Membership
- **Type**: Driver loading capability
- **Impact**: Peut charger des drivers (code kernel)
- **Détection**: `Get-ADGroupMember "Print Operators"`

### 14. Group Policy Creator Owners Membership
- **Type**: GPO creation rights
- **Impact**: Peut créer des GPOs pour déployer du code
- **Détection**: `Get-ADGroupMember "Group Policy Creator Owners"`

### 15. WriteSPN Abuse
- **Type**: Targeted Kerberoasting
- **Impact**: Peut ajouter des SPNs pour Kerberoaster des comptes
- **Détection**: Chercher ACL WriteSPN sur les users

### 16. Weak Encryption Flags
- **Type**: USE_DES_KEY_ONLY flag
- **Impact**: Force l'utilisation de DES (cassable facilement)
- **Détection**: `Get-ADUser -Filter * -Properties userAccountControl | Where {$_.userAccountControl -band 0x200000}`

### 17. Unconstrained Delegation (Computers)
- **Type**: Computer objects avec delegation non contrainte
- **Impact**: Permet TGT harvesting et attaques relay
- **Détection**: `Get-ADComputer -Filter {TrustedForDelegation -eq $true}`

### 18. Oversized Groups (>1000 membres)
- **Type**: Groups avec trop de membres
- **Impact**: Performance issues et difficultés d'audit
- **Détection**: `Get-ADGroup -Filter * -Properties Members | Where {$_.Members.Count -gt 1000}`

### 19. Expired Accounts in Domain Admins
- **Type**: Comptes expirés toujours dans DA
- **Impact**: Comptes dormants avec privilèges élevés
- **Détection**: `Get-ADGroupMember "Domain Admins" | Get-ADUser -Properties AccountExpirationDate | Where {$_.AccountExpirationDate -lt (Get-Date)}`

### 20. AS-REP Roasting (DoesNotRequirePreAuth)
- **Type**: Pre-authentication disabled
- **Impact**: Permet d'obtenir un TGT sans authentification
- **Détection**: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`

### 21. Kerberoasting (SPNs on users)
- **Type**: Service Principal Names sur comptes users
- **Impact**: Permet d'extraire et casser les hashes Kerberos
- **Détection**: `Get-ADUser -Filter {ServicePrincipalNames -like "*"} -Properties ServicePrincipalNames`

---

## 🟡 MEDIUM (28 vulnérabilités)

### 22. RC4 with AES
- **Type**: Downgrade attack vulnerability
- **Impact**: Permet de forcer RC4 même si AES est disponible
- **Détection**: Vérifier userAccountControl pour encryption types

### 23. Admins NOT in Protected Users Group
- **Type**: Configuration faible
- **Impact**: Admins non protégés contre credential theft
- **Détection**: `Get-ADGroupMember "Domain Admins" | Where {(Get-ADUser $_ -Properties MemberOf).MemberOf -notcontains "CN=Protected Users,..."}`

### 24. Expired Accounts in Admin Groups
- **Type**: Comptes expirés avec privilèges
- **Impact**: Comptes dormants exploitables
- **Détection**: `Get-ADUser -Filter * -Properties AccountExpirationDate | Where {$_.AccountExpirationDate -lt (Get-Date)}`

### 25. Everyone in ACLs
- **Type**: GenericAll pour Everyone
- **Impact**: Tout le monde peut modifier certains objets
- **Détection**: Vérifier ACLs pour Everyone/Authenticated Users

### 26. Dangerous Logon Scripts
- **Type**: Scripts modifiables
- **Impact**: Scripts de logon avec permissions faibles
- **Détection**: Vérifier les ACLs sur les logon scripts

### 27. LAPS Password Leaked in Description
- **Type**: Mot de passe LAPS dans description
- **Impact**: Exposure du password admin local
- **Détection**: `Get-ADComputer -Filter * -Properties Description | Where {$_.Description -match "LAPS|password"}`

### 28. Oversized Groups (500-1000 membres)
- **Type**: Groups moyennement larges
- **Impact**: Difficultés de gestion et audit
- **Détection**: `Get-ADGroup -Filter * -Properties Members | Where {$_.Members.Count -gt 500 -and $_.Members.Count -lt 1000}`

### 29. Foreign Security Principals in Admin Groups
- **Type**: Externes dans groupes admin
- **Impact**: Comptes d'autres domaines avec privilèges
- **Détection**: `Get-ADGroupMember "Domain Admins" | Where {$_.objectClass -eq "foreignSecurityPrincipal"}`

### 30. Orphaned ACEs
- **Type**: ACLs orphelines (SIDs invalides)
- **Impact**: ACLs non nettoyées après suppression d'objets
- **Détection**: Analyser ACLs pour SIDs non résolus

### 31. Dangerous Group Nesting
- **Type**: Hiérarchie de groupes profonde
- **Impact**: Chemins d'escalade cachés via imbrication
- **Détection**: Analyser la profondeur des groupes imbriqués

### 32. Authenticated Users in ACLs
- **Type**: Authenticated Users avec permissions élevées
- **Impact**: Tous les users auth peuvent modifier certains objets
- **Détection**: Vérifier ACLs pour Authenticated Users

### 33. Domain Admin Mention in Description
- **Type**: "Domain Admin" dans le champ description
- **Impact**: Information disclosure sur comptes privilégiés
- **Détection**: `Get-ADUser -Filter * -Properties Description | Where {$_.Description -match "domain admin|DA|admin"}`

### 34. Disabled Account in Admin Group
- **Type**: Comptes désactivés dans groupes admin
- **Impact**: Comptes dormants réactivables
- **Détection**: `Get-ADGroupMember "Domain Admins" | Get-ADUser | Where {-not $_.Enabled}`

### 35. User Cannot Change Password (flag 0x0040)
- **Type**: PASSWD_CANT_CHANGE flag
- **Impact**: Utilisateur ne peut pas changer son MDP
- **Détection**: `Get-ADUser -Filter * -Properties userAccountControl | Where {$_.userAccountControl -band 0x40}`

### 36. Smartcard Not Required (flag 0x40000)
- **Type**: SMARTCARD_NOT_REQUIRED flag
- **Impact**: Contourne la politique smartcard obligatoire
- **Détection**: `Get-ADUser -Filter * -Properties userAccountControl | Where {$_.userAccountControl -band 0x40000}`

### 37. Shared Accounts
- **Type**: Comptes partagés entre utilisateurs
- **Impact**: Pas de non-répudiation, mauvaise hygiène
- **Détection**: Chercher users avec "shared" ou "service" dans le nom

### 38. Pre-Windows 2000 Compatible Access Abuse
- **Type**: Everyone read access activé
- **Impact**: Lecture de tous les attributs AD par Everyone
- **Détection**: Vérifier membership du groupe "Pre-Windows 2000 Compatible Access"

### 39. PasswordNeverExpires
- **Type**: Mot de passe qui n'expire jamais
- **Impact**: Passwords anciens jamais changés
- **Détection**: `Get-ADUser -Filter {PasswordNeverExpires -eq $true}`

### 40. PasswordNotRequired
- **Type**: PASSWD_NOTREQD flag
- **Impact**: Compte sans MDP requis
- **Détection**: `Get-ADUser -Filter * -Properties userAccountControl | Where {$_.userAccountControl -band 0x20}`

### 41. AllowReversiblePasswordEncryption
- **Type**: Passwords stockés en clair réversible
- **Impact**: MDP récupérables depuis AD
- **Détection**: `Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true}`

### 42. Unconstrained Delegation (Users)
- **Type**: Délégation Kerberos non contrainte
- **Impact**: Peut impersonner n'importe quel user
- **Détection**: `Get-ADUser -Filter {TrustedForDelegation -eq $true}`

### 43. Constrained Delegation
- **Type**: Délégation Kerberos contrainte
- **Impact**: Peut impersonner des users vers certains services
- **Détection**: `Get-ADUser -Filter * -Properties msDS-AllowedToDelegateTo | Where {$_."msDS-AllowedToDelegateTo"}`

### 44. Passwords in Description
- **Type**: Mots de passe dans le champ description
- **Impact**: Passwords en clair visibles
- **Détection**: `Get-ADUser -Filter * -Properties Description | Where {$_.Description -match "pass|pwd|mot de passe"}`

### 45. Disabled Accounts in Admin Groups
- **Type**: Comptes désactivés mais toujours dans groupes admin
- **Impact**: Réactivation = instant admin
- **Détection**: `Get-ADGroupMember "Domain Admins" | Get-ADUser | Where {-not $_.Enabled}`

### 46. Stale Accounts
- **Type**: Comptes inactifs depuis longtemps
- **Impact**: Comptes oubliés potentiellement exploitables
- **Détection**: `Get-ADUser -Filter * -Properties LastLogonDate | Where {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}`

### 47. AdminCount=1 on Non-Protected Users
- **Type**: AdminCount flag sur users non-admin
- **Impact**: Héritage ACL désactivé anormalement
- **Détection**: `Get-ADUser -Filter {AdminCount -eq 1} | Where {# vérifier si réellement admin}`

### 48. SID History Present
- **Type**: Attribut SIDHistory rempli
- **Impact**: Peut contenir des SIDs privilégiés cachés
- **Détection**: `Get-ADUser -Filter * -Properties SIDHistory | Where {$_.SIDHistory}`

### 49. Privileged Users NOT in Protected Users
- **Type**: Admins sans protection renforcée
- **Impact**: Vulnérables au credential theft
- **Détection**: Comparer Domain Admins vs Protected Users

---

## 🟢 LOW (14 vulnérabilités)

### 50. Test Accounts
- **Type**: Comptes de test oubliés
- **Impact**: Comptes de dev/test en production
- **Détection**: `Get-ADUser -Filter * | Where {$_.Name -match "test|temp|demo"}`

### 51. Empty Password
- **Type**: PASSWORD_NOT_REQUIRED flag
- **Impact**: Comptes sans mot de passe
- **Détection**: `Get-ADUser -Filter * -Properties userAccountControl | Where {$_.userAccountControl -band 0x20}`

### 52. User Cannot Change Password
- **Type**: Permission refusée de changer MDP
- **Impact**: User dépendant de l'admin pour MDP
- **Détection**: Vérifier ACLs pour User-Change-Password

### 53. Smartcard Not Required (admins)
- **Type**: Admins sans smartcard obligatoire
- **Impact**: Contournement de la 2FA
- **Détection**: `Get-ADUser -Filter {AdminCount -eq 1} -Properties userAccountControl | Where {$_.userAccountControl -band 0x40000}`

### 54. Duplicate SPN
- **Type**: SPNs en double dans le domaine
- **Impact**: Problèmes d'authentification Kerberos
- **Détection**: Chercher SPNs identiques sur plusieurs comptes

### 55-63. ACL-Based Vulnerabilities (WARNING level)
- **GenericAll on Domain Admins** - Contrôle total sur DA
- **WriteDACL on Sensitive Groups** - Peut modifier permissions
- **WriteOwner on Sensitive Groups** - Peut prendre ownership
- **WriteDACL on OUs** - Peut modifier ACLs des OUs
- **GenericWrite on Privileged Users** - Peut modifier attributs admins
- **ForceChangePassword on Admins** - Peut reset MDPs admin
- **WriteProperty (member) on Privileged Groups** - Peut ajouter membres
- **GenericWrite on Sensitive Groups** - Modifications sur groupes sensibles
- **ForceChangePassword ExtendedRight on Domain Admins** - Reset MDP DA

### 64. Everyone with GenericWrite on Domain Admins
- **Type**: Everyone peut modifier DA
- **Impact**: Tout le monde peut potentiellement devenir DA
- **Détection**: Vérifier ACLs sur CN=Domain Admins

### 65-67. Group Membership Vulnerabilities
- **Domain Admins** - Membres non légitimes
- **Account Operators** - Membres non autorisés
- **Backup Operators** - Membres non autorisés

### 68-74. Additional Dangerous Memberships
- **DnsAdmins** - Membres supplémentaires
- **Print Operators** - Membres non autorisés
- **Remote Desktop Users** - Accès RDP étendu
- **Schema Admins** - Membres non légitimes
- **Enterprise Admins** - Membres non autorisés
- **Group Policy Creator Owners** - Créateurs GPO non autorisés

### 75-80. Advanced Privilege Escalation
- **Nested Groups to Domain Admins** - Chemins cachés vers DA
- **LAPS Read Rights** - Lecture passwords LAPS
- **GPO Linking Rights (gPLink poisoning)** - Modification GPO links
- **Enable Delegation Rights** - Peut activer délégation
- **Suspicious SID Properties** - Propriétés SID anormales
- **Unix Passwords in Clear** - unixUserPassword en clair

### 81-87. Computer Vulnerabilities (20 types)
- **Unconstrained Delegation** - Computers avec délégation
- **Pre-Windows 2000 Compatible** - Anciens protocoles actifs
- **LAPS Not Configured** - LAPS absent
- **SMB Signing Disabled** - SMB signing désactivé
- **LLMNR/NBT-NS Enabled** - Protocols legacy actifs
- **Weak Local Admin Password** - MDP admin local faible
- **No Antivirus** - Pas d'AV

---

## 📊 Résumé par Sévérité

| Sévérité | Nombre | Pourcentage |
|----------|--------|-------------|
| CRITICAL | 9 | 10.3% |
| HIGH | 12 | 13.8% |
| MEDIUM | 28 | 32.2% |
| LOW | 14 | 16.1% |
| WARNING | 24 | 27.6% |
| **TOTAL** | **87** | **100%** |

---

## 🔍 Commandes de Détection Rapide

```powershell
# Scan complet de toutes les vulnérabilités
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName,
    PasswordNeverExpires, DoesNotRequirePreAuth, ServicePrincipalNames,
    TrustedForDelegation, AdminCount, SIDHistory, Enabled

# Vérifier les groupes sensibles
@("Domain Admins","Enterprise Admins","Schema Admins","Account Operators",
  "Backup Operators","Server Operators","DnsAdmins") |
    ForEach-Object { Get-ADGroupMember $_ }

# Chercher les ACLs dangereuses
Get-ADObject -Filter * -Properties nTSecurityDescriptor |
    Where-Object {$_.nTSecurityDescriptor.Access -match "Everyone|Authenticated Users"}
```

---

**⚠️ AVERTISSEMENT**: Cet environnement est INTENTIONNELLEMENT vulnérable.
Ne jamais utiliser en production. À des fins de test et formation uniquement.

**Script**: Populate-AD-GlobalCorp.ps1
**Version**: 2.0 (Optimisé)
**Domaine**: aza-me.cc
**Date**: Décembre 2025
