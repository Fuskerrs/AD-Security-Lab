# Changelog - Populate-AD-GlobalCorp.ps1

All notable changes to the Active Directory population script will be documented in this file.

## [3.0.0] - 2025-12-05

### 🎉 Major Release - 70 Vulnerability Types & Hidden Honeypots

### Added

#### New Vulnerability Types (30 new)
- **#35** - SID History Injection (0.1%) - Privilege escalation via Domain Admin SID in sidHistory
- **#36** - Shadow Credentials (0.1%) - CVE-2022-26923 - WriteProperty ACL on msDS-KeyCredentialLink
- **#37** - DNS Admins Membership (0.3%) - DLL injection → RCE as SYSTEM on DC
- **#38** - Backup Operators Membership (0.2%) - NTDS.dit access → full hash dump
- **#39** - Account Operators Membership (0.2%) - Account creation in OUs
- **#40** - Server Operators Membership (0.2%) - Service modification → RCE
- **#41** - Print Operators Membership (0.2%) - Driver loading → SYSTEM elevation
- **#42** - Group Policy Creator Owners (0.2%) - Malicious GPO deployment
- **#43** - WriteSPN Abuse (0.3%) - Targeted Kerberoasting via SPN manipulation
- **#44** - Sensitive Delegation (0.5%) - Domain Admin accounts with delegation enabled
- **#45** - Shared Accounts (1%) - shared.*, common.*, generic.*, team.* naming patterns
- **#46** - Test Accounts (1%) - test.*, demo.*, temp.*, sample.* naming patterns
- **#47** - Weak Encryption Flags (0.5%) - USE_DES_KEY_ONLY flag enabled
- **#48** - RC4 with AES (1%) - Downgrade attack via dual encryption support
- **#49** - Not in Protected Users (0.5%) - Domain Admins outside Protected Users group
- **#50** - Expired Accounts in Admin Groups (0.2%) - Expired but still privileged
- **#51** - Everyone in ACLs (0.3%) - GenericAll granted to Everyone (S-1-1-0)
- **#52** - Dangerous Logon Scripts (0.3%) - Modifiable scriptPath attributes
- **#53** - LAPS Password Leaked (0.1%) - LAPS password in description field
- **#54** - Computer Unconstrained Delegation (3 computers) - PrinterBug/PetitPotam vector
- **#55** - Oversized Group Critical (>1000 members) - GlobalCorp-AllUsers with ~1200 members
- **#56** - Oversized Group High (500-1000 members) - GlobalCorp-Marketing with ~600 members
- **#57** - Exchange Security Groups (0.1%) - Exchange Windows Permissions membership
- **#58** - Foreign Security Principals (0.2%) - External SIDs in sensitive groups
- **#59** - Orphaned ACEs (0.1%) - ACLs with unresolvable SIDs
- **#60** - Dangerous Group Nesting (1 chain) - 6-level deep group chain to Domain Admins
- **#61** - Authenticated Users in ACLs (0.2%) - GenericAll for Authenticated Users (S-1-5-11)
- **#62** - Domain Admin in Description (0.5%) - "Domain Admin" mentions in description
- **#63** - Disabled Account in Admin Group (0.2%) - Disabled but still in Schema Admins
- **#64** - Empty Password (0.1%) - PASSWORD_NOT_REQUIRED flag enabled
- **#65** - User Cannot Change Password (0.3%) - PASSWD_CANT_CHANGE flag
- **#66** - Smartcard Not Required (0.2%) - Admin accounts without smartcard requirement
- **#67** - Duplicate SPN (0.2%) - Same SPN on multiple accounts

#### Ultra-Vulnerable Hidden Honeypot Users (4 users)
**Designed to blend seamlessly into AD with realistic profiles and names:**

1. **robert.johnson** (30 vulnerabilities)
   - Title: Senior Systems Administrator
   - Department: IT
   - Password: Password123!
   - Memberships: Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Account Operators, Print Operators
   - Kerberos: AS-REP Roasting, Kerberoasting (3 SPNs), Unconstrained Delegation, Constrained Delegation
   - Attributes: PasswordNeverExpires, PasswordNotRequired, Reversible Encryption, UnixUserPassword, AdminCount=1

2. **sarah.williams** (11 vulnerabilities)
   - Title: Finance Manager
   - Department: Finance
   - Password: P@ssword123!
   - Kerberos: Kerberoasting (MSSQL SPN)
   - Encryption: Reversible + DES Only + Password Never Expires + AS-REP Roasting
   - Memberships: Print Operators
   - Attributes: Cannot Change Password, Malicious Script Path

3. **michael.brown** (16 vulnerabilities)
   - Title: HR Specialist
   - Department: HR
   - Password: P@ssword123!
   - Kerberos: Unconstrained Delegation, AS-REP Roasting, Kerberoasting (HTTP SPN)
   - Memberships: Server Operators, Account Operators, Backup Operators, DnsAdmins
   - ACLs: Everyone GenericWrite + Everyone Reset Password
   - Attributes: Email spoofing (ceo@aza-me.cc), Public home directory, AdminCount=1, Password Not Required

4. **jennifer.davis** (20+ vulnerabilities - GOD MODE)
   - Title: Senior DevOps Engineer
   - Department: IT
   - Password: P@ssword123!
   - **CRITICAL**: DCSync rights (DS-Replication-Get-Changes + Get-Changes-All)
   - **CRITICAL**: Shadow Admin on Domain Admins (WriteMember ACL)
   - **CRITICAL**: OU Poisoning (WriteOwner + WriteDACL + GenericAll + GPLink on IT OU)
   - Kerberos: Unconstrained Delegation, Kerberoasting (Restricted SPN)
   - Memberships: Group Policy Creator Owners, Schema Admins, Enterprise Admins
   - Attributes: Malicious script path, AdminCount=1

### Statistics

#### Vulnerability Coverage
- **Total Types**: 67/70 implemented (96%)
- **Missing**: 3 types (configuration checks: ADCS_ESC1, MACHINE_ACCOUNT_QUOTA, WEAK_PASSWORD_POLICY)
- **Previous Version**: 34 types → **Current**: 67 types (+97% increase)

#### Estimated Vulnerability Instances (7500 users)
- Regular vulnerabilities: ~600-700 instances
- Ultra-vulnerable users: 77 instances (30+11+16+20)
- **Total**: ~677-777 vulnerability instances

#### Code Metrics
- Lines added: +1347
- Total script size: ~3200 lines
- New functions: 30+ vulnerability injection routines
- New AD objects: 4 ultra-vulnerable users, 3 vulnerable computers, 8 vulnerable groups

### Changed
- Enhanced vulnerability distribution percentages for more realistic scenarios
- Improved error handling with try-catch blocks on all vulnerability injections
- Updated logging to show vulnerability counts and types

### Technical Details

#### New GUIDs Used
```powershell
msDS-KeyCredentialLink:                    5b47d60f-6090-40b2-9f37-2a4de88f3063
servicePrincipalName:                      f3a64788-5306-11d1-a9c5-0000f80367c1
User-Force-Change-Password:                00299570-246d-11d0-a768-00aa006e0529
member (WriteMember):                      bf9679c0-0de6-11d0-a285-00aa003049e2
```

#### New UserAccountControl Flags
```powershell
USE_DES_KEY_ONLY:                          0x200000
PASSWD_CANT_CHANGE:                        0x40
PASSWD_NOTREQD:                            0x20
```

#### New Groups Created
- Exchange Windows Permissions (Universal Security Group)
- GlobalCorp-AllUsers (Global Security Group, >1000 members)
- GlobalCorp-Marketing (Global Security Group, 500-1000 members)
- NestedGroup-L1 through NestedGroup-L6 (6-level nesting chain)

#### New Computer Objects
- WEB-SERVER-VULN (Unconstrained Delegation)
- APP-SERVER-VULN (Unconstrained Delegation)
- FILE-SERVER-VULN (Unconstrained Delegation)

---

## [2.0.0] - 2025-12-04

### Added
- RBCD Abuse (WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity)
- Primary Group ID Spoofing (hidden Domain Admin privileges)
- AdminSDHolder Backdoor (Tier 0 persistence)
- Pre-Windows 2000 Compatible Access Abuse

### Changed
- Improved GPO Linking vulnerability from simple flag to actual ACL manipulation

---

## [1.0.0] - 2025-12-03

### Initial Release
- 34 vulnerability types
- ~7500 users across 20 global cities
- 16 departments with complete hierarchy
- Security and distribution groups
- ACL-based vulnerabilities
- Kerberos attack vectors
- Password policy violations
- Privilege escalation paths

---

## Roadmap

### Future Enhancements
- [ ] ADCS Certificate Template abuse (requires AD CS installed)
- [ ] Automated vulnerability verification script
- [ ] Integration with security scanning tools
- [ ] Custom vulnerability scoring system
- [ ] Remediation guide generation

### Known Limitations
- ADCS_ESC1_TEMPLATE_ABUSE requires AD Certificate Services
- MACHINE_ACCOUNT_QUOTA_ABUSE is a domain-level configuration check
- WEAK_PASSWORD_POLICY requires GPO analysis
- Some ACL operations may fail without elevated privileges

---

## Contributors

- Claude Code (Anthropic) - AI-assisted development
- Fuskerrs - Project lead and testing

## License

This script is for **TESTING AND EDUCATIONAL PURPOSES ONLY**.

**⚠️ WARNING**: Never run this script in a production environment. It intentionally creates severe security vulnerabilities.
