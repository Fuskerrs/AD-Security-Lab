# AD Security Lab - GlobalCorp Vulnerable Environment

A comprehensive Active Directory testing environment with **120+ intentional security vulnerabilities** for penetration testing, security tool validation, and defensive training.

![Version](https://img.shields.io/badge/version-4.1.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/license-Educational%20Use-green)
![Vulnerabilities](https://img.shields.io/badge/vulnerabilities-120%2B-red)

---

## ⚠️ CRITICAL WARNING

**THIS ENVIRONMENT INTENTIONALLY CREATES SEVERE SECURITY VULNERABILITIES**

- ✅ **FOR LAB/TESTING ENVIRONMENTS ONLY**
- ❌ **NEVER RUN IN PRODUCTION**
- ❌ **DO NOT USE ON LIVE SYSTEMS**
- ❌ **CONTAINS KNOWN EXPLOITABLE ATTACK VECTORS**

By using this lab, you acknowledge:
- This is for **authorized testing only** in isolated environments
- You understand the security risks involved
- You will NOT use this in production or on systems you don't own
- You accept full responsibility for any consequences

---

## 📁 Repository Structure

```
C:\AD-Security-Lab\
├── 📁 Scripts\                         # Core PowerShell scripts
│   ├── Populate-AD-GlobalCorp.ps1      # Main population script (277 KB, 5000+ lines)
│   └── Delete-GlobalCorp.ps1           # Cleanup script
│
├── 📁 Documentation\                   # Complete documentation
│   ├── README.md                       # Full feature documentation
│   ├── QUICK-START.md                  # 5-minute setup guide
│   ├── DETECTION-GUIDE.md              # PowerShell detection commands
│   ├── VULNERABILITIES.md              # Complete vulnerability catalog
│   └── CHANGELOG.md                    # Version history
│
├── 📁 Reports\                         # Auto-generated reports (created at runtime)
│   └── .gitkeep
│
├── 📁 Examples\                        # Ready-to-use examples
│   ├── example-small-lab.ps1           # 1K users, 5 min
│   ├── example-standard-lab.ps1        # 12K users, 20 min (RECOMMENDED)
│   └── example-enterprise-lab.ps1      # 50K users, 90 min
│
└── 📁 Tools\                           # Utility scripts (future)
    └── (coming soon)
```

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Windows Server 2016+ with Active Directory
- PowerShell 5.1+ (PowerShell 7 compatible)
- Domain Admin privileges
- 2+ GB free disk space

### Run Your First Lab

```powershell
# 1. Navigate to scripts directory
cd C:\AD-Security-Lab\Scripts

# 2. Run the standard lab example (RECOMMENDED)
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 12000 `
    -UltraVulnUsers 7 `
    -TotalComputers 1000 `
    -DefaultPassword "Welcome2024!" `
    -Confirm

# 3. Wait 15-20 minutes...

# 4. View the HTML report (auto-opens)
# Location: C:\ADPopulate_Reports\AD_Population_YYYYMMDD_HHMMSS.html
```

**That's it!** Your vulnerable AD is ready for testing.

📖 **For detailed setup**: See [Documentation/QUICK-START.md](Documentation/QUICK-START.md)

---

## 🎯 What Gets Created

### Infrastructure
- **100 to 50,000 users** distributed across 20 global metropolises
- **Up to 5,000 computer objects** (desktops, laptops, VDI)
- **350+ organizational units** (continents → cities → departments)
- **95+ security groups** with dangerous configurations
- **16 departments** with 4-tier management hierarchy
- **Service accounts** with realistic SPNs and misconfigurations

### Vulnerabilities (120+ Types)

#### CRITICAL Vulnerabilities
- **ADCS (ESC1-11)**: All certificate template attacks
- **DCSync Rights**: Non-admin users with replication rights
- **Exchange PrivExchange**: CVE-2019-1166 WriteDACL on domain
- **GPO Passwords**: MS14-025 passwords in SYSVOL
- **Unconstrained Delegation**: Kerberos delegation abuse
- **Obsolete OS**: Windows XP, Server 2003/2008
- **Credential Exposure**: Passwords in descriptions, reversible encryption

#### HIGH Vulnerabilities
- **Kerberoasting**: SPNs on user accounts
- **AS-REP Roasting**: Pre-auth disabled
- **RBCD**: Resource-Based Constrained Delegation
- **ACL Abuse**: GenericAll, WriteDACL, WriteOwner
- **Service Accounts**: In Domain Admins, old passwords
- **SMBv1**: MS17-010 EternalBlue vulnerable

#### Attack Paths (10 Complete Chains)
- Kerberoasting → Domain Admin
- AS-REP → Admin Group
- ACL Chain → Domain Admin
- GPO Modification → Code Execution
- ADCS Template → Certificate-based Escalation
- And 5 more documented paths...

### Reports & Logging
- **HTML Dashboard**: Interactive report with charts and statistics
- **CSV Export**: Complete user/computer inventory
- **Execution Log**: Detailed timestamped logs
- **Detection Commands**: PowerShell commands for each vulnerability

---

## 📊 Lab Size Options

| Lab Size | Users | Computers | Time | Use Case |
|----------|-------|-----------|------|----------|
| **Small** | 1,000 | 100 | 5 min | Quick testing, demos |
| **Standard** ⭐ | 12,000 | 1,000 | 20 min | **Recommended for training** |
| **Enterprise** | 50,000 | 5,000 | 90 min | Performance testing, benchmarks |

⭐ **Recommended**: Standard lab provides the best balance of features and performance.

---

## 🔬 Use Cases

### Security Testing
- ✅ Validate vulnerability scanners (BloodHound, PingCastle, Purple Knight)
- ✅ Test offensive tools (Impacket, Rubeus, Certipy)
- ✅ Practice exploitation techniques
- ✅ Benchmark detection capabilities

### Training & Education
- ✅ AD attack/defense training
- ✅ SOC analyst exercises
- ✅ Red team/Blue team drills
- ✅ Security awareness demonstrations

### Tool Development
- ✅ Test AD security tools
- ✅ Develop detection rules
- ✅ Validate remediation scripts
- ✅ Benchmark performance at scale

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [QUICK-START.md](Documentation/QUICK-START.md) | **Start here** - 5-minute setup guide |
| [DETECTION-GUIDE.md](Documentation/DETECTION-GUIDE.md) | PowerShell commands to find all vulnerabilities |
| [VULNERABILITIES.md](Documentation/VULNERABILITIES.md) | Complete catalog of 120+ vulnerability types |
| [README.md](Documentation/README.md) | Full feature documentation |
| [CHANGELOG.md](Documentation/CHANGELOG.md) | Version history and updates |

---

## 🛠️ Common Operations

### Run a Lab
```powershell
# Small lab (5 minutes)
.\Examples\example-small-lab.ps1

# Standard lab (recommended)
.\Examples\example-standard-lab.ps1

# Enterprise lab (90 minutes)
.\Examples\example-enterprise-lab.ps1
```

### Cleanup
```powershell
# Delete everything
.\Scripts\Delete-GlobalCorp.ps1

# Verify cleanup
Get-ADOrganizationalUnit -Filter "Name -eq 'GlobalCorp'"
# Should return nothing
```

### Detection Testing
```powershell
# Find Kerberoastable accounts
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# Find AS-REP Roastable accounts
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}

# Find DCSync rights
(Get-Acl "AD:DC=aza-me,DC=cc").Access | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl"}

# See DETECTION-GUIDE.md for 100+ more commands
```

---

## 🔍 Vulnerability Categories

### Core Categories (120+ total)

1. **ADCS Certificate Services** (11)
   - ESC1 through ESC11 attacks
   - Vulnerable templates, weak ACLs, dangerous flags

2. **Kerberos Attacks** (15)
   - AS-REP Roasting, Kerberoasting
   - Unconstrained/Constrained/RBCD delegation

3. **Privilege Escalation** (20)
   - ACL abuse (GenericAll, WriteDACL)
   - Nested groups, Operators groups
   - Exchange PrivExchange

4. **Credential Attacks** (18)
   - Password spraying vectors
   - GPO passwords in SYSVOL
   - Weak/old passwords

5. **Computer Vulnerabilities** (24)
   - Obsolete OS (XP, 2003, 2008, Vista)
   - SMBv1, No BitLocker, LAPS issues

6. **Service Accounts** (5)
   - Kerberoastable SPNs
   - Privileged accounts, old passwords

7. **Attack Paths** (10)
   - Complete documented chains to DA

8. **Advanced** (17)
   - Shadow Credentials, AdminSDHolder
   - DCSync, Protected Groups abuse

---

## ⚡ Performance

### Optimizations
- **Hashtable-based lookups**: O(1) manager hierarchy assignment
- **Batch processing**: Efficient user/group creation
- **Progress logging**: Track execution every 500 users
- **Memory efficient**: Handles 50K+ users without issues

### Execution Times (on modern DC)
- 1,000 users: ~5 minutes
- 12,000 users: ~20 minutes
- 50,000 users: ~90 minutes

---

## 🧪 Testing Your Lab

### Recommended Tools

#### Vulnerability Scanners
- **BloodHound**: Attack path visualization
- **PingCastle**: Comprehensive AD audit
- **Purple Knight**: Security assessment
- **Adalanche**: Attack path analysis

#### Offensive Tools
- **Impacket**: GetUserSPNs.py, GetNPUsers.py, secretsdump.py
- **Rubeus**: Kerberos attack toolkit
- **Certipy**: ADCS exploitation
- **PowerView**: AD enumeration

#### Defensive Tools
- **Splunk**: Log analysis and detection
- **Defender for Identity**: Attack detection
- **Sysmon**: Endpoint monitoring

---

## 📈 Statistics

Typical standard lab (12K users, 1K computers):

- **~11,788 user accounts** (distributed by population)
- **~1,200 vulnerabilities total**
  - Critical: ~150
  - High: ~400
  - Medium: ~500
  - Low: ~150
- **7 ultra-vulnerable honeypots** (70-210 vulns each)
- **350 organizational units**
- **95 security groups**
- **10 documented attack paths**

---

## 🔐 Security Notes

### This Lab Contains
- Known exploitable vulnerabilities (CVE references included)
- Weak passwords (default: "Welcome2024!")
- Dangerous ACL configurations
- Credential exposure in multiple forms
- Certificate misconfigurations
- Outdated/vulnerable systems

### Never Use For
- Production environments
- Live customer networks
- Systems with real data
- Internet-facing systems
- Systems you don't own/control

### Recommended Setup
- Isolated lab network (no internet)
- Dedicated test domain
- Snapshot/backup before running
- Firewall rules to prevent lateral movement to production

---

## 🤝 Contributing

This is a security research and training tool. Contributions welcome:

- New vulnerability types
- Detection improvements
- Documentation enhancements
- Performance optimizations
- Bug fixes

**Test thoroughly** in isolated environments before submitting.

---

## 📝 Version History

See [CHANGELOG.md](Documentation/CHANGELOG.md) for detailed version history.

**Current Version**: 4.1.0 (January 2026)
- Added 35+ new vulnerabilities
- ADCS ESC1-11 complete coverage
- Attack path documentation
- Service account vulnerabilities
- Performance optimizations

---

## 📞 Support & Resources

- **Quick Start**: [QUICK-START.md](Documentation/QUICK-START.md)
- **Detection Guide**: [DETECTION-GUIDE.md](Documentation/DETECTION-GUIDE.md)
- **Full Docs**: [Documentation/README.md](Documentation/README.md)
- **Examples**: See `Examples/` folder

---

## 🏆 Credits

**Authors**: Fuskerrs, Claude Code (Anthropic)
**Version**: 4.1.0
**Last Updated**: January 2026
**License**: Educational and authorized testing use only

---

## ⚖️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool intentionally creates severe security vulnerabilities. The authors are not responsible for misuse or damage. By using this:

- You confirm this is for **authorized testing in isolated lab environments only**
- You understand the security risks
- You will **NOT** use this in production or on systems you don't own
- You accept **full responsibility** for any consequences

**Unauthorized use may be illegal in your jurisdiction.**

---

## 🎯 Getting Started

Ready to build your vulnerable AD lab?

1. ✅ Read the [Quick Start Guide](Documentation/QUICK-START.md)
2. ✅ Choose your lab size (we recommend Standard: 12K users)
3. ✅ Run: `.\Examples\example-standard-lab.ps1`
4. ✅ Test your security tools!
5. ✅ Practice detection with [DETECTION-GUIDE.md](Documentation/DETECTION-GUIDE.md)

**Happy Testing!** 🚀🔐
