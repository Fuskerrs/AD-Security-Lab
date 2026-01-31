# Vulnerability Detection Guide

Complete PowerShell commands to detect all 120+ vulnerability types injected by the script.

## Table of Contents

1. [ADCS Vulnerabilities (ESC1-11)](#adcs-vulnerabilities)
2. [Kerberos Attacks](#kerberos-attacks)
3. [Password Vulnerabilities](#password-vulnerabilities)
4. [Privilege Escalation](#privilege-escalation)
5. [Computer Vulnerabilities](#computer-vulnerabilities)
6. [Service Accounts](#service-accounts)
7. [GPO Vulnerabilities](#gpo-vulnerabilities)
8. [Attack Paths](#attack-paths)

---

## ADCS Vulnerabilities

### ESC1 - Vulnerable Certificate Template
```powershell
# Check for templates allowing subject alternative name from request
certutil -v -template | findstr /i "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"
```

### ESC2 - Any Purpose EKU
```powershell
certutil -v -template | findstr /i "any purpose"
Get-ADObject -Filter * -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=aza-me,DC=cc' -Properties msPKI-Certificate-Application-Policy
```

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
```powershell
certutil -getreg policy\EditFlags
# Look for 0x00040000 bit set
```

### ESC8 - HTTP Enrollment
```powershell
# Check for web enrollment endpoints
netsh http show urlacl | findstr certsrv
Get-WebApplication | Where-Object {$_.Path -like '*certsrv*'}
```

### Complete ADCS Scan
```powershell
# Using Certipy (recommended)
certipy find -vulnerable -dc-ip <DC_IP> -u <username> -p <password>

# Using Certify
Certify.exe find /vulnerable
```

---

## Kerberos Attacks

### AS-REP Roastable Accounts
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} `
    -Properties DoesNotRequirePreAuth,ServicePrincipalNames,MemberOf |
    Select-Object Name,SamAccountName,DoesNotRequirePreAuth
```

### Kerberoastable Accounts (SPNs)
```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} `
    -Properties ServicePrincipalName,MemberOf,PasswordLastSet |
    Select-Object Name,SamAccountName,ServicePrincipalName,PasswordLastSet
```

### Unconstrained Delegation
```powershell
# Users
Get-ADUser -Filter {TrustedForDelegation -eq $true} `
    -Properties TrustedForDelegation |
    Select-Object Name,SamAccountName

# Computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516} `
    -Properties TrustedForDelegation,OperatingSystem |
    Select-Object Name,OperatingSystem
```

### Constrained Delegation
```powershell
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} `
    -Properties 'msDS-AllowedToDelegateTo' |
    Select-Object Name,SamAccountName,@{N='DelegateTo';E={$_.'msDS-AllowedToDelegateTo'}}
```

### Resource-Based Constrained Delegation (RBCD)
```powershell
Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' |
    Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'} |
    Select-Object Name,@{N='RBCD';E={$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'}}
```

---

## Password Vulnerabilities

### Password Never Expires
```powershell
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} `
    -Properties PasswordNeverExpires,PasswordLastSet,MemberOf |
    Select-Object Name,SamAccountName,PasswordLastSet,@{N='Groups';E={$_.MemberOf -join '; '}}
```

### Password Not Required
```powershell
Get-ADUser -Filter {PasswordNotRequired -eq $true} `
    -Properties PasswordNotRequired |
    Select-Object Name,SamAccountName,Enabled
```

### Reversible Encryption
```powershell
Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} `
    -Properties AllowReversiblePasswordEncryption |
    Select-Object Name,SamAccountName
```

### Password in Description
```powershell
Get-ADUser -Filter * -Properties Description |
    Where-Object {$_.Description -match 'pass|pwd|mot de passe|password'} |
    Select-Object Name,SamAccountName,Description
```

### Unix User Password (Cleartext)
```powershell
Get-ADUser -Filter * -Properties unixUserPassword |
    Where-Object {$_.unixUserPassword} |
    Select-Object Name,SamAccountName,@{N='CleartextPwd';E={$_.unixUserPassword}}
```

---

## Privilege Escalation

### Domain Admins Members
```powershell
Get-ADGroupMember "Domain Admins" -Recursive |
    Get-ADUser -Properties Title,Department,LastLogonDate |
    Select-Object Name,SamAccountName,Title,Department,LastLogonDate |
    Sort-Object LastLogonDate
```

### DCSync Rights
```powershell
# Check replication rights on domain
(Get-Acl "AD:DC=aza-me,DC=cc").Access |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner" -or
        ($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -and $_.ActiveDirectoryRights -match 'ExtendedRight')
    } |
    Select-Object IdentityReference,ActiveDirectoryRights,ObjectType
```

### GenericAll on Domain Admins
```powershell
$daGroup = Get-ADGroup "Domain Admins"
(Get-Acl "AD:$($daGroup.DistinguishedName)").Access |
    Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"} |
    Where-Object {$_.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins"} |
    Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType
```

### Nested Group Paths to DA
```powershell
# Find all paths to Domain Admins (requires recursion)
function Get-NestedGroupPath {
    param($GroupName, $Depth = 0, $Path = @())

    if ($Depth -gt 10) { return }

    $members = Get-ADGroupMember $GroupName -ErrorAction SilentlyContinue
    foreach ($member in $members) {
        if ($member.objectClass -eq 'group') {
            Get-NestedGroupPath -GroupName $member.Name -Depth ($Depth + 1) -Path ($Path + $GroupName)
        } else {
            Write-Output "$($Path -join ' -> ') -> $GroupName -> $($member.Name)"
        }
    }
}

Get-NestedGroupPath -GroupName "Domain Admins"
```

### Exchange PrivExchange (CVE-2019-1166)
```powershell
# Check if Exchange Windows Permissions has WriteDACL on domain
$domainDN = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:$domainDN").Access |
    Where-Object {$_.IdentityReference -match "Exchange.*Permissions" -and $_.ActiveDirectoryRights -match "WriteDacl"} |
    Select-Object IdentityReference,ActiveDirectoryRights
```

### AdminSDHolder Backdoors
```powershell
$adminSDHolder = "CN=AdminSDHolder,CN=System,DC=aza-me,DC=cc"
(Get-Acl "AD:$adminSDHolder").Access |
    Where-Object {$_.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins|Administrators"} |
    Select-Object IdentityReference,ActiveDirectoryRights
```

---

## Computer Vulnerabilities

### Obsolete Operating Systems
```powershell
# Windows XP
Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object {$_.OperatingSystem -match 'Windows XP'} |
    Select-Object Name,OperatingSystem

# Windows Server 2003
Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object {$_.OperatingSystem -match 'Server 2003'} |
    Select-Object Name,OperatingSystem

# Windows Server 2008
Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object {$_.OperatingSystem -match 'Server 2008'} |
    Select-Object Name,OperatingSystem

# Windows Vista
Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object {$_.OperatingSystem -match 'Vista'} |
    Select-Object Name,OperatingSystem
```

### SMBv1 Enabled (MS17-010 EternalBlue)
```powershell
# Check via registry (requires remote access)
Get-ADComputer -Filter * | ForEach-Object {
    Test-Connection $_.Name -Count 1 -Quiet
    # Then: Get-ItemProperty "\\$($_.Name)\HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1
}

# Or check via description
Get-ADComputer -Filter * -Properties Description |
    Where-Object {$_.Description -match 'SMBv1|SMB1'} |
    Select-Object Name,Description
```

### No LAPS Deployed
```powershell
Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' |
    Where-Object {-not $_.'ms-Mcs-AdmPwd'} |
    Select-Object Name,OperatingSystem |
    Measure-Object
```

### Stale Computer Accounts (Inactive > 90 days)
```powershell
$cutoffDate = (Get-Date).AddDays(-90)
Get-ADComputer -Filter * -Properties LastLogonDate |
    Where-Object {$_.LastLogonDate -lt $cutoffDate -or -not $_.LastLogonDate} |
    Select-Object Name,OperatingSystem,LastLogonDate |
    Sort-Object LastLogonDate
```

---

## Service Accounts

### Service Accounts with SPNs (Kerberoastable)
```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*" -and SamAccountName -like "svc*"} `
    -Properties ServicePrincipalName,PasswordLastSet,MemberOf |
    Select-Object Name,SamAccountName,ServicePrincipalName,PasswordLastSet
```

### Service Accounts in Privileged Groups
```powershell
@("Domain Admins","Enterprise Admins","Backup Operators","Account Operators") | ForEach-Object {
    $groupName = $_
    Get-ADGroupMember $groupName |
        Where-Object {$_.SamAccountName -like 'svc*'} |
        Select-Object @{N='Group';E={$groupName}},Name,SamAccountName
}
```

### Service Accounts with Old Passwords (> 1 year)
```powershell
$cutoffDate = (Get-Date).AddDays(-365)
Get-ADUser -Filter {SamAccountName -like "svc*"} -Properties PasswordLastSet |
    Where-Object {$_.PasswordLastSet -lt $cutoffDate -or -not $_.PasswordLastSet} |
    Select-Object Name,SamAccountName,PasswordLastSet,Enabled
```

---

## GPO Vulnerabilities

### GPO Password in SYSVOL (MS14-025)
```powershell
# Search for cpassword in all GPO XML files
findstr /S /I cpassword "\\aza-me.cc\SYSVOL\aza-me.cc\Policies\*.xml"

# PowerShell search
Get-ChildItem "\\aza-me.cc\SYSVOL\aza-me.cc\Policies" -Recurse -Filter *.xml |
    Select-String -Pattern "cpassword" |
    Select-Object Path,LineNumber,Line
```

### Decrypt GPP Passwords
```powershell
# Using Get-GPPPassword (PowerView)
Get-GPPPassword

# Manual decryption (AES key is public)
function Decrypt-GPPPassword {
    param([string]$EncryptedPassword)
    $AESKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    $bytes = [Convert]::FromBase64String($EncryptedPassword)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $AESKey
    $aes.IV = [byte[]]::new(16)
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [System.Text.Encoding]::Unicode.GetString($decryptedBytes)
}

# Example usage
Decrypt-GPPPassword "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
# Output: P@ssw0rd!
```

---

## Attack Paths

### BloodHound Analysis
```powershell
# Collect data with SharpHound
.\SharpHound.exe -c All -d aza-me.cc --outputdirectory C:\BloodHound

# Import to BloodHound and run queries:
# - Shortest Paths to Domain Admins
# - Find all Kerberoastable Paths to DA
# - Find Computers with Unconstrained Delegation
# - Find Dangerous Rights
```

### Manual Path Discovery
```powershell
# Users with path to DA via ACLs
Get-ADUser -Filter * -Properties MemberOf |
    ForEach-Object {
        $user = $_
        $groups = $user.MemberOf | ForEach-Object { Get-ADGroup $_ -Properties MemberOf }
        # Check for nested paths to Domain Admins
    }
```

---

## Complete Scan Script

```powershell
# Run all detections and export to CSV
$results = @()

# Kerberoasting
$results += Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
    Select-Object @{N='Type';E={'Kerberoastable'}},Name,SamAccountName,@{N='Detail';E={$_.ServicePrincipalName}}

# AS-REP Roasting
$results += Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} |
    Select-Object @{N='Type';E={'ASREPRoastable'}},Name,SamAccountName,@{N='Detail';E={'No PreAuth'}}

# Password Never Expires
$results += Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
    Select-Object @{N='Type';E={'PasswordNeverExpires'}},Name,SamAccountName,@{N='Detail';E={'Enabled'}}

# Export
$results | Export-Csv C:\ADPopulate_Reports\VulnerabilityScan.csv -NoTypeInformation
Write-Host "Scan complete. Results: C:\ADPopulate_Reports\VulnerabilityScan.csv"
```

---

## Recommended Tools

- **BloodHound**: Attack path visualization
- **PingCastle**: Comprehensive AD security audit
- **Purple Knight**: AD security assessment
- **Certipy**: ADCS vulnerability scanner
- **Impacket**: Kerberos attacks (GetUserSPNs.py, GetNPUsers.py)
- **Rubeus**: Kerberos abuse toolkit
- **PowerView**: AD enumeration and exploitation

## See Also

- Full documentation: `README.md`
- Vulnerability catalog: `VULNERABILITIES.md`
- Quick start guide: `QUICK-START.md`
