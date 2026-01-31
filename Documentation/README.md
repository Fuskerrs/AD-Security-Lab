# Active Directory Population Script - GlobalCorp Simulation

A comprehensive PowerShell script that creates a realistic, multinational corporate Active Directory environment with **intentional security vulnerabilities** for penetration testing, security training, and defensive security tool development.

## 🎯 Overview

This script populates an Active Directory domain with:
- **100 to 50,000 users** (configurable) distributed across 20 global metropolises
- **120+ types of security vulnerabilities** covering the full spectrum of AD attack vectors including ADCS (ESC1-11), GPO attacks, Attack Paths, and Service Account weaknesses
- **Configurable ultra-vulnerable honeypot users** (0-100) with 10-30 vulnerabilities each
- **Up to 5,000 computer objects** with configurable vulnerability percentage (1-100%)
- **16 departments** with complete 4-tier management hierarchy
- **350+ organizational units** across continents, cities, and departments
- **95+ security and distribution groups** with dangerous permission configurations
- **ACL-based attack vectors** for privilege escalation paths
- **Automated HTML and CSV reports** with vulnerability tracking
- **Comprehensive logging** to .log files for audit trails

**Target Domain**: `aza-me.cc`

---

## ⚠️ CRITICAL WARNING

**THIS SCRIPT INTENTIONALLY CREATES SEVERE SECURITY VULNERABILITIES**

- ✅ **FOR TESTING/LAB ENVIRONMENTS ONLY**
- ❌ **NEVER RUN IN PRODUCTION**
- ❌ **DO NOT USE ON LIVE SYSTEMS**
- ❌ **CONTAINS KNOWN ATTACK VECTORS**

This is a **deliberate vulnerable-by-design** environment for:
- Security tool testing and validation
- Penetration testing practice
- Red team exercises
- Blue team detection capability development
- Security awareness training
- AD attack research and tool development

---

## 🚀 Quick Start

```powershell
# Basic execution (interactive prompts)
.\Populate-AD-GlobalCorp.ps1

# Production-ready command with 12K users, 7 ultra-vuln users, 1000 computers
.\Populate-AD-GlobalCorp.ps1 -TotalUsers 12000 -UltraVulnUsers 7 -TotalComputers 1000 -DefaultPassword "Welcome2024!" -Confirm

# Large enterprise simulation (50K users, 5K computers)
.\Populate-AD-GlobalCorp.ps1 -TotalUsers 50000 -TotalComputers 5000 -VulnComputerPercent 15 -Confirm
```

---

## 📋 Features

### 120+ Vulnerability Types

The script implements 120+ different vulnerability types categorized by severity:

- **CRITICAL** - DCSync rights, Unconstrained Delegation, ADCS vulnerabilities (ESC1-11), Exchange PrivExchange, GPO Password in SYSVOL, Credential exposure
- **HIGH** - Kerberoasting, AS-REP Roasting, RBCD, ACL abuse, Dangerous group memberships, Obsolete OS, Service Account misconfigurations
- **MEDIUM** - Password issues, Weak configurations, Legacy protocols (SMBv1), SID History, Computer misconfigurations
- **LOW** - Test accounts, Minor misconfigurations, Informational findings

Key vulnerability categories:
- **ADCS Attacks** - ESC1 through ESC11 (Certificate template abuse, vulnerable PKI configurations)
- **Kerberos Attacks** - AS-REP Roasting, Kerberoasting, Delegation abuse (Unconstrained/Constrained/RBCD)
- **Privilege Escalation** - ACLs (GenericAll, WriteDACL), Group nesting, Operators groups, Exchange PrivExchange (CVE-2019-1166)
- **Credential Attacks** - Password spraying vectors, Weak passwords, GPO Password in SYSVOL (MS14-025)
- **Computer Vulnerabilities** - Delegation, Obsolete OS (XP/2003/2008/Vista), LAPS issues, SMBv1, No BitLocker
- **Attack Paths** - 10 documented paths from initial access to Domain Admin
- **Service Accounts** - Kerberoastable SPNs, Old passwords, Privileged accounts, Weak encryption
- **Advanced** - Shadow Credentials, DCSync rights, AdminSDHolder backdoors, Protected Groups abuse

### Configurable Ultra-Vulnerable Honeypots

Create 0-100 ultra-vulnerable users with 10-30 vulnerabilities each:
- Blend seamlessly with realistic names and titles
- Multiple attack vectors per account
- Useful for threat hunting exercises
- Escalation path testing

### 1000+ Computer Objects

- Desktop, Laptop, and VDI workstations
- Distributed across all cities and departments
- Configurable vulnerability percentage (default: 10%)
- Vulnerable computers include: Unconstrained Delegation, Pre-Windows 2000 compatibility, LAPS issues, etc.

### 4-Tier Management Hierarchy

Realistic organizational structure with:
- **Executives (C-Level)**: ~2% of users - CEOs, CFOs, CTOs per department
- **Managers**: ~3% of users - Department managers by city
- **Team Leads**: ~10% of users - Team leads per city/department
- **Employees**: ~85% of users - Individual contributors

Optimized for performance: handles 50K+ users in minutes (not hours)

### Comprehensive Reporting

Auto-generated outputs in `C:\ADPopulate_Reports\`:
- **HTML Report**: Interactive dashboard with vulnerability breakdown, statistics, detection commands
- **CSV Export**: Complete user data with all attributes
- **Log File**: Detailed execution log with timestamps (AD_Population_YYYYMMDD_HHMMSS.log)

---

## 📦 Requirements

- **Windows Server 2016+** or Windows Server 2019/2022 recommended
- **Active Directory Domain Services** (ADDS) installed and configured
- **PowerShell 5.1+** (PowerShell 7+ compatible)
- **Domain Admin privileges** (required for creating users, groups, OUs)
- **ActiveDirectory PowerShell module** (auto-loaded by script)

---

## 💻 Usage

### Parameters

| Parameter | Type | Range | Default | Description |
|-----------|------|-------|---------|-------------|
| `TotalUsers` | int | 100-50000 | Interactive | Total number of users to create |
| `DefaultPassword` | string | - | Interactive | Default password for all users |
| `OutputPath` | string | - | C:\ADPopulate_Reports | Output directory for reports and logs |
| `VulnPercent` | int | 1-100 | 10 | Percentage of regular users with classic vulnerabilities |
| `UltraVulnUsers` | int | 0-100 | 0 | Number of ultra-vulnerable honeypot users (10-30 vulns each) |
| `UltraVulnMin` | int | 5-50 | 10 | Minimum vulnerabilities for ultra-vuln users |
| `UltraVulnMax` | int | 10-60 | 30 | Maximum vulnerabilities for ultra-vuln users |
| `TotalComputers` | int | 0-5000 | 0 | Number of computer objects to create |
| `VulnComputerPercent` | int | 1-100 | 10 | Percentage of computers with vulnerabilities |
| `Confirm` | switch | - | false | Skip confirmation prompts (unattended execution) |
| `NoOpenReport` | switch | - | false | Don't auto-open HTML report when complete |
| `SkipUserCreation` | switch | - | false | Skip user creation (vulnerabilities only) |
| `OnlyVulnerabilities` | switch | - | false | Only inject vulnerabilities on existing users |

### Examples

```powershell
# View detailed help
Get-Help .\Populate-AD-GlobalCorp.ps1 -Full

# Interactive mode (prompts for parameters)
.\Populate-AD-GlobalCorp.ps1

# Standard security lab (12K users, 7 ultra-vuln, 1K computers)
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 12000 `
    -UltraVulnUsers 7 `
    -TotalComputers 1000 `
    -DefaultPassword "Welcome2024!" `
    -Confirm

# High vulnerability environment (20% vuln users, 20% vuln computers)
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 10000 `
    -VulnPercent 20 `
    -TotalComputers 2000 `
    -VulnComputerPercent 20 `
    -DefaultPassword "P@ssw0rd!" `
    -Confirm

# Large enterprise with many honeypots
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 25000 `
    -UltraVulnUsers 50 `
    -UltraVulnMin 15 `
    -UltraVulnMax 40 `
    -TotalComputers 3000 `
    -Confirm

# Custom output directory
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 5000 `
    -OutputPath "D:\SecurityLab\Reports" `
    -Confirm

# Only inject vulnerabilities on existing users (no new creation)
.\Populate-AD-GlobalCorp.ps1 `
    -OnlyVulnerabilities `
    -VulnPercent 15 `
    -UltraVulnUsers 10 `
    -Confirm
```

---

## 🔍 Detection Examples

### Find Kerberoastable Accounts
```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
    Select-Object Name, SamAccountName, ServicePrincipalName
```

### Find AS-REP Roastable Accounts
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object Name, SamAccountName
```

### Find Domain Admins
```powershell
Get-ADGroupMember "Domain Admins" -Recursive |
    Get-ADUser -Properties Title, Department |
    Select-Object Name, SamAccountName, Title, Department
```

### Find Unconstrained Delegation
```powershell
# Users
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object Name, SamAccountName

# Computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object Name, DNSHostName
```

### Find Users with DCSync Rights
```powershell
# Check for replication rights
Get-ADUser -Filter * -SearchBase "OU=GlobalCorp,DC=aza-me,DC=cc" -Properties * |
    Where-Object {
        $acl = Get-Acl "AD:\$($_.DistinguishedName)"
        $acl.Access | Where-Object {
            $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" -and
            $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        }
    }
```

### Find Password in Description
```powershell
Get-ADUser -Filter * -Properties Description |
    Where-Object {$_.Description -match "pass|pwd|mot de passe"} |
    Select-Object Name, Description
```

### Find Disabled Accounts in Privileged Groups
```powershell
@("Domain Admins","Account Operators","Backup Operators") | ForEach-Object {
    Get-ADGroupMember $_ | Get-ADUser | Where-Object {-not $_.Enabled}
}
```

### Check for Shadow Credentials
```powershell
Get-ADUser -Filter * -SearchBase "OU=GlobalCorp,DC=aza-me,DC=cc" -Properties msDS-KeyCredentialLink |
    Where-Object {$_."msDS-KeyCredentialLink"} |
    Select-Object Name, SamAccountName
```

---

## 📊 Statistics

Typical deployment with 12,000 users, 7 ultra-vuln users, and 1,000 computers:

- **~11,788 users** (rounding due to percentage-based distribution)
- **350 Organizational Units** (continents → cities → departments)
- **95 Security Groups** (department, city, project, and role-based)
- **~700-900 total vulnerability instances** (10% of regular users + ultra-vulns)
- **7 ultra-vulnerable honeypot accounts** (70-210 additional vulnerabilities)
- **~1,000 computer objects** (DSK, LAP, VDI)
- **~100 vulnerable computers** (10% of total computers)
- **4-tier management hierarchy** (Executives → Managers → Team Leads → Employees)

Execution time: ~110 minutes for 12K users (optimized performance)

---

## 🌍 Global City Distribution

Users are distributed across 20 world metropolises proportional to real population data:

**Asia**: Tokyo, Delhi, Shanghai, Mumbai, Beijing, Dhaka, Osaka, Karachi, Kolkata, Manila, Guangzhou
**North America**: New-York, Mexico-City
**South America**: Sao-Paulo, Buenos-Aires, Rio-de-Janeiro
**Europe**: Istanbul
**Africa**: Cairo, Lagos

Each city contains all 16 departments with complete OU structure.

---

## 🏢 Organizational Structure

### 16 Departments
IT, HR, Finance, Marketing, Sales, Operations, Legal, R&D, Support, Logistics, Executive, Compliance, Security, Facilities, PR, Training

### OU Hierarchy
```
GlobalCorp/
├── Asia/
│   ├── Tokyo/
│   │   ├── IT/
│   │   ├── HR/
│   │   ├── Finance/
│   │   └── ... (all 16 departments)
│   ├── Delhi/
│   └── ... (all Asian cities)
├── North-America/
├── South-America/
├── Europe/
└── Africa/
```

---

## 🛡️ Cleanup

### Remove Entire GlobalCorp OU
```powershell
# Disable protection and remove recursively
Set-ADOrganizationalUnit -Identity "OU=GlobalCorp,DC=aza-me,DC=cc" -ProtectedFromAccidentalDeletion $false
Remove-ADOrganizationalUnit -Identity "OU=GlobalCorp,DC=aza-me,DC=cc" -Recursive -Confirm:$false
```

### Selective Cleanup
```powershell
# Count users in GlobalCorp
(Get-ADUser -Filter * -SearchBase 'OU=GlobalCorp,DC=aza-me,DC=cc').Count

# Count computers in GlobalCorp
(Get-ADComputer -Filter * -SearchBase 'OU=GlobalCorp,DC=aza-me,DC=cc').Count

# Remove specific vulnerable users
Get-ADUser -Filter {Description -like "*VULN*"} -SearchBase 'OU=GlobalCorp,DC=aza-me,DC=cc' |
    Remove-ADUser -Confirm:$false

# Remove all computers
Get-ADComputer -Filter * -SearchBase 'OU=GlobalCorp,DC=aza-me,DC=cc' |
    Remove-ADComputer -Confirm:$false
```

---

## 📝 Logging and Reports

### Log Files
All operations are logged to:
```
C:\ADPopulate_Reports\AD_Population_YYYYMMDD_HHMMSS.log
```

Log levels: INFO, SUCCESS, WARNING, ERROR, CRITICAL

### HTML Report
Interactive dashboard includes:
- Executive summary with statistics
- Vulnerability breakdown by type and severity
- City and department distribution charts
- Management hierarchy statistics
- PowerShell detection commands
- Hidden cheat sheet for audit exercises (toggle button)

### CSV Export
Complete user data exported to:
```
C:\ADPopulate_Reports\GlobalCorp_Users_YYYYMMDD_HHMMSS.csv
```

---

## ⚡ Performance Optimizations

### Manager Hierarchy Optimization
The script uses **hashtable-based O(1) lookups** instead of O(n²) Where-Object loops for manager assignment:
- Handles 50,000+ users efficiently
- Reduces execution time from hours to minutes
- Single-pass categorization with indexed lookups

### Batch Processing
- Users created in batches with progress logging every 500 users
- Groups created in parallel where possible
- OUs created with error handling and duplicate checking

---

## 🔧 Troubleshooting

### Common Issues

**Script hangs after user creation**
- Fixed in latest version with optimized Set-ManagerHierarchy function
- If using older version, ensure you have the latest code

**Validation errors for VulnUserCount**
- This is a cosmetic warning when VulnUserCount defaults to 0
- Does not affect execution, can be ignored

**Computer creation fails**
- Ensure OUs are created first (script handles this automatically)
- Check domain controller replication if running on multiple DCs

**Permission denied errors**
- Ensure you're running as Domain Admin
- Check UAC settings on Windows Server

---

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md) - Detailed version history and changes
- [Populate-AD-GlobalCorp.ps1](Populate-AD-GlobalCorp.ps1) - Main script (inline documentation)

---

## 🎯 Use Cases

### Penetration Testing Training
- Practice enumeration techniques
- Test privilege escalation paths
- Validate attack tool detection

### Blue Team Development
- Develop SIEM detection rules
- Test EDR/XDR capabilities
- Train SOC analysts on AD attacks

### Security Tool Validation
- Test AD security scanners (BloodHound, PingCastle, Purple Knight, etc.)
- Validate vulnerability assessment tools
- Benchmark detection accuracy

### Research and Development
- Study AD attack vectors
- Develop new detection techniques
- Test remediation procedures

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This script intentionally creates severe security vulnerabilities. Never use in production environments. The authors are not responsible for misuse or damage caused by this script.

By using this script, you acknowledge:
- This is for authorized testing in isolated lab environments only
- You understand the security risks involved
- You will not use this in production or on systems you don't own
- You accept full responsibility for any consequences

---

## 🤝 Contributing

Contributions welcome! Guidelines:
- Test thoroughly in isolated lab environments
- Document new vulnerability types
- Include detection examples
- Update CHANGELOG.md

---

## 📜 License

Educational and testing purposes only. Not for commercial use.

---

## 🏆 Credits

**Authors**: Fuskerrs, Claude Code (Anthropic)
**Version**: 4.0.0
**Last Updated**: 2025-12-14
**Repository**: Private security research project

---

## 📞 Support

For issues or questions:
- Review documentation and inline script comments
- Check CHANGELOG.md for recent changes
- Test in isolated environment before large deployments
- Ensure Domain Admin privileges and AD prerequisites

---

**Remember**: This is a vulnerable-by-design environment. Treat it as compromised from the start. Perfect for training, terrible for production. 🎯
