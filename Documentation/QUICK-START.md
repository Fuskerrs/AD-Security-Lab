# Quick Start Guide - AD Security Lab

## Prerequisites

- Windows Server 2016+ with Active Directory Domain Services
- PowerShell 5.1+ (PowerShell 7+ compatible)
- Domain Admin privileges
- ActiveDirectory PowerShell module

## 5-Minute Setup

### Step 1: Open PowerShell as Administrator

```powershell
# Navigate to scripts directory
cd C:\AD-Security-Lab\Scripts
```

### Step 2: Choose Your Lab Size

#### Small Lab (1000 users, 100 computers) - 5 minutes
```powershell
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 1000 `
    -TotalComputers 100 `
    -DefaultPassword "Welcome2024!" `
    -Confirm
```

#### Standard Lab (12K users, 1K computers) - 15-20 minutes
```powershell
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 12000 `
    -UltraVulnUsers 7 `
    -TotalComputers 1000 `
    -DefaultPassword "Welcome2024!" `
    -Confirm
```

#### Enterprise Lab (50K users, 5K computers) - 60-90 minutes
```powershell
.\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers 50000 `
    -TotalComputers 5000 `
    -VulnComputerPercent 15 `
    -DefaultPassword "Welcome2024!" `
    -Confirm
```

### Step 3: Wait for Completion

The script will:
- Create OUs (350+ organizational units)
- Create users across 20 global cities
- Create security groups (95+)
- Inject vulnerabilities (120+ types)
- Generate HTML and CSV reports

### Step 4: View Results

Reports are automatically saved to:
```
C:\ADPopulate_Reports\
├── AD_Population_YYYYMMDD_HHMMSS.log      # Execution log
├── AD_Population_YYYYMMDD_HHMMSS.html     # Interactive report
└── GlobalCorp_Users_YYYYMMDD_HHMMSS.csv   # User export
```

The HTML report opens automatically (unless `-NoOpenReport` is used).

## Testing Your Security Tools

### Test BloodHound
```powershell
# Run SharpHound collector
.\SharpHound.exe -c All -d aza-me.cc

# Upload to BloodHound and analyze:
# - Find attack paths to Domain Admin
# - Identify Kerberoastable accounts
# - Map ACL abuse chains
```

### Test Vulnerability Scanner
```powershell
# Example: PingCastle
PingCastle.exe --healthcheck --server dc.aza-me.cc

# Example: Purple Knight
.\PurpleKnight.exe
```

### Test Offensive Tools
```powershell
# Kerberoasting
Invoke-Kerberoast -Domain aza-me.cc

# AS-REP Roasting
Get-ASREPHash -Domain aza-me.cc

# Find delegation issues
Get-DomainComputer -Unconstrained -Domain aza-me.cc
```

## Cleanup

### Full Cleanup (Remove Everything)
```powershell
.\Delete-GlobalCorp.ps1
```

### Verify Cleanup
```powershell
Get-ADOrganizationalUnit -Filter "Name -eq 'GlobalCorp'" -ErrorAction SilentlyContinue
# Should return nothing
```

## Common Issues

### Script Hangs
- **Cause**: Large user count (50K+) with slow DC
- **Solution**: Use `-TotalUsers 12000` for testing first

### Permission Denied
- **Cause**: Not running as Domain Admin
- **Solution**: Run PowerShell as Domain Admin

### ADCS Vulnerabilities Not Created
- **Cause**: ADCS not installed
- **Solution**: Install Certificate Services role or ignore ADCS warnings

## Next Steps

1. Review the vulnerability report: `C:\ADPopulate_Reports\*.html`
2. Read the full documentation: `Documentation\README.md`
3. Explore detection commands: `Documentation\DETECTION-GUIDE.md`
4. Test your security tools against the lab
5. Practice remediation procedures

## Support

- Full documentation: `Documentation\README.md`
- Vulnerability catalog: `Documentation\VULNERABILITIES.md`
- Detection guide: `Documentation\DETECTION-GUIDE.md`
- Examples: `Examples\*.ps1`
