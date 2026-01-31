# Vérification complète des 138 types de vulnérabilités injectées
# Objectif: Vérifier si chaque type existe vraiment dans l'AD

param(
    [string]$CsvPath = "C:\ADPopulate_Reports\GlobalCorp_Vulnerabilities_20260130_174331.csv",
    [string]$OutputPath = "C:\AD-Security-Lab\docs\audit\v1.1.4\verification-all-138.csv"
)

Write-Host "`n=== VÉRIFICATION COMPLÈTE DES 138 TYPES ===" -ForegroundColor Cyan
Write-Host "Ceci va prendre plusieurs minutes...`n"

# Charger le CSV
$injected = Import-Csv $CsvPath
$byType = $injected | Group-Object Type

$results = @()
$i = 0
$total = $byType.Count

foreach ($group in $byType) {
    $i++
    $type = $group.Name
    $injectedCount = $group.Count
    $foundCount = 0
    $status = "NOT_CHECKED"
    $notes = ""

    Write-Progress -Activity "Vérification des vulnérabilités" -Status "$type ($i/$total)" -PercentComplete (($i/$total)*100)
    Write-Host "[$i/$total] $type (injecté: $injectedCount)... " -NoNewline -ForegroundColor Yellow

    try {
        switch -Regex ($type) {

            # === PASSWORDS ===
            "^PasswordNeverExpires$" {
                $users = @(Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -EA SilentlyContinue)
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^PasswordNotRequired$" {
                $users = @(Get-ADUser -Filter {PasswordNotRequired -eq $true} -EA SilentlyContinue)
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^ReversibleEncryption$" {
                $users = @(Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -EA SilentlyContinue)
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^EmptyPassword$" {
                $notes = "Cannot verify without password audit"
                $status = "UNKNOWN"
            }
            "^PasswordInDescription$" {
                $users = @(Get-ADUser -Filter * -Properties Description -EA SilentlyContinue | Where-Object {
                    $_.Description -match "password|pwd|pass|mdp"
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^UnixUserPassword_Clear$" {
                $users = @(Get-ADUser -Filter * -Properties unixUserPassword -EA SilentlyContinue | Where-Object {
                    $null -ne $_.unixUserPassword
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^WEAK_PASSWORD_POLICY$" {
                $policy = Get-ADDefaultDomainPasswordPolicy -EA SilentlyContinue
                $foundCount = if ($policy.MinPasswordLength -lt 8) { 1 } else { 0 }
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }

            # === KERBEROS ===
            "^Kerberoastable$|^Kerberoastable_WeakPassword$" {
                $users = @(Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -EA SilentlyContinue)
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^ASREPRoastable$" {
                $users = @(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -EA SilentlyContinue)
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^UnconstrainedDelegation$" {
                $objects = @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue)
                $foundCount = $objects.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^ConstrainedDelegation$" {
                $objects = @(Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo -EA SilentlyContinue)
                $foundCount = $objects.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^KERBEROS_TICKET_LIFETIME_LONG$" {
                $policy = Get-ADDefaultDomainPasswordPolicy -EA SilentlyContinue
                $foundCount = 0
                $status = "UNKNOWN"
                $notes = "Requires GPO analysis"
            }

            # === COMPUTERS ===
            "^Computer_No_LAPS$|^COMPUTER_NO_LAPS$" {
                # Vérifier si l'attribut LAPS existe
                $computers = @(Get-ADComputer -Filter * -EA SilentlyContinue)
                $foundCount = $computers.Count
                $status = "FOUND"
                $notes = "All computers (LAPS attribute check requires LAPS schema)"
            }
            "^Computer_Old_Password$" {
                $threshold = (Get-Date).AddDays(-90)
                $computers = @(Get-ADComputer -Filter * -Properties PasswordLastSet -EA SilentlyContinue | Where-Object {
                    $_.PasswordLastSet -and $_.PasswordLastSet -lt $threshold
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Stale_Inactive$" {
                $threshold = (Get-Date).AddDays(-90)
                $computers = @(Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                    $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Never_Logged_On$|^COMPUTER_NEVER_LOGGED_ON$" {
                $computers = @(Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                    $null -eq $_.LastLogonDate
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Unconstrained_Delegation$" {
                $computers = @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue)
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_No_Bitlocker$|^COMPUTER_NO_BITLOCKER$" {
                $computers = @(Get-ADComputer -Filter * -EA SilentlyContinue)
                $foundCount = $computers.Count
                $status = "UNKNOWN"
                $notes = "BitLocker status not in AD"
            }
            "^Computer_Duplicate_SPN$|^COMPUTER_DUPLICATE_SPN$|^Duplicate_SPN$" {
                $allComputers = @(Get-ADComputer -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -EA SilentlyContinue)
                $spns = @{}
                foreach ($comp in $allComputers) {
                    foreach ($spn in $comp.ServicePrincipalName) {
                        if (-not $spns.ContainsKey($spn)) { $spns[$spn] = @() }
                        $spns[$spn] += $comp.Name
                    }
                }
                $duplicates = @($spns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 })
                $foundCount = $duplicates.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_OS_Obsolete" {
                $osPattern = if ($type -match "XP") { "*XP*" }
                    elseif ($type -match "Vista") { "*Vista*" }
                    elseif ($type -match "2003") { "*2003*" }
                    elseif ($type -match "2008") { "*2008*" }
                    else { "*obsolete*" }
                $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem -EA SilentlyContinue | Where-Object {
                    $_.OperatingSystem -like $osPattern
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Wrong_OU$" {
                $computers = @(Get-ADComputer -Filter * -EA SilentlyContinue | Where-Object {
                    $_.DistinguishedName -notmatch "OU=Computers"
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Pre_Win2000$" {
                $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem -EA SilentlyContinue | Where-Object {
                    $_.OperatingSystem -match "Windows NT|Windows 2000"
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Disabled_Not_Deleted$" {
                $computers = @(Get-ADComputer -Filter {Enabled -eq $false} -EA SilentlyContinue)
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Sensitive_Description$" {
                $computers = @(Get-ADComputer -Filter * -Properties Description -EA SilentlyContinue | Where-Object {
                    $_.Description -match "password|admin|secret|sensitive"
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_With_SPNs$" {
                $computers = @(Get-ADComputer -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -EA SilentlyContinue)
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Weak_Encryption$" {
                $computers = @(Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes -EA SilentlyContinue | Where-Object {
                    $_.'msDS-SupportedEncryptionTypes' -band 0x7  # DES or RC4
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_In_Admin_Group$" {
                $adminGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
                $computerCount = 0
                foreach ($group in $adminGroups) {
                    $members = @(Get-ADGroupMember -Identity $group -EA SilentlyContinue | Where-Object { $_.objectClass -eq "computer" })
                    $computerCount += $members.Count
                }
                $foundCount = $computerCount
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Pre_Created$" {
                $notes = "Cannot verify (requires creation timestamp analysis)"
                $status = "UNKNOWN"
            }
            "^Computer_RBCD$" {
                $computers = @(Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity -EA SilentlyContinue | Where-Object {
                    $null -ne $_.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                })
                $foundCount = $computers.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Computer_Local_Admin_Mapping$|^Computer_Weak_LAPS$|^Computer_SMB_Signing_Disabled$|^COMPUTER_LEGACY_PROTOCOL_SMBV1$|^Computer_ACL_GenericAll$" {
                $notes = "Requires network scan or advanced ACL analysis"
                $status = "UNKNOWN"
            }

            # === GROUPS ===
            "^Oversized_Group" {
                $threshold = if ($type -match "Critical") { 500 } else { 100 }
                $groups = @(Get-ADGroup -Filter * -Properties Members -EA SilentlyContinue | Where-Object {
                    $_.Members.Count -gt $threshold
                })
                $foundCount = $groups.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Group_Protected_Users_Empty$|^GROUP_PROTECTED_USERS_EMPTY$" {
                $group = Get-ADGroup -Identity "Protected Users" -Properties Members -EA SilentlyContinue
                $isEmpty = ($null -eq $group.Members -or $group.Members.Count -eq 0)
                $foundCount = if ($isEmpty) { 1 } else { 0 }
                $status = if ($isEmpty) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Dangerous_Group_Nesting$" {
                $notes = "Requires recursive group analysis"
                $status = "UNKNOWN"
            }
            "^(Account_Operators|Backup_Operators|DNS_Admins|Print_Operators|Server_Operators|GPO_Creator_Owners)_Member$" {
                $groupName = if ($type -match "Account_Operators") { "Account Operators" }
                    elseif ($type -match "Backup_Operators") { "Backup Operators" }
                    elseif ($type -match "DNS_Admins") { "DnsAdmins" }
                    elseif ($type -match "Print_Operators") { "Print Operators" }
                    elseif ($type -match "Server_Operators") { "Server Operators" }
                    elseif ($type -match "GPO_Creator") { "Group Policy Creator Owners" }
                    else { $null }

                if ($groupName) {
                    $members = @(Get-ADGroupMember -Identity $groupName -EA SilentlyContinue)
                    $foundCount = $members.Count
                    $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
                }
            }
            "^BUILTIN_MODIFIED$" {
                $notes = "Requires baseline comparison"
                $status = "UNKNOWN"
            }

            # === ACCOUNTS ===
            "^Not_In_Protected_Users$|^NotInProtectedUsers$" {
                $protectedUsers = @(Get-ADGroupMember -Identity "Protected Users" -EA SilentlyContinue)
                $adminUsers = @(Get-ADGroupMember -Identity "Domain Admins" -EA SilentlyContinue)
                $notProtected = @($adminUsers | Where-Object { $protectedUsers.SID -notcontains $_.SID })
                $foundCount = $notProtected.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Inactive_365_Days$" {
                $threshold = (Get-Date).AddDays(-365)
                $users = @(Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                    $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Never_Logged_On$" {
                $users = @(Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                    $null -eq $_.LastLogonDate -and $_.Enabled -eq $true
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Disabled_Account_In_Admin_Group$|^DisabledAccountInPrivGroup$" {
                $adminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
                $disabledCount = 0
                foreach ($group in $adminGroups) {
                    $members = @(Get-ADGroupMember -Identity $group -EA SilentlyContinue | Where-Object { $_.objectClass -eq "user" })
                    foreach ($member in $members) {
                        $user = Get-ADUser -Identity $member -Properties Enabled -EA SilentlyContinue
                        if ($user -and $user.Enabled -eq $false) { $disabledCount++ }
                    }
                }
                $foundCount = $disabledCount
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Expired_Account_In_Admin_Group$" {
                $adminGroups = @("Domain Admins", "Enterprise Admins")
                $expiredCount = 0
                foreach ($group in $adminGroups) {
                    $members = @(Get-ADGroupMember -Identity $group -EA SilentlyContinue | Where-Object { $_.objectClass -eq "user" })
                    foreach ($member in $members) {
                        $user = Get-ADUser -Identity $member -Properties AccountExpirationDate -EA SilentlyContinue
                        if ($user -and $user.AccountExpirationDate -and $user.AccountExpirationDate -lt (Get-Date)) {
                            $expiredCount++
                        }
                    }
                }
                $foundCount = $expiredCount
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^SIDHistory$" {
                $users = @(Get-ADUser -Filter * -Properties SIDHistory -EA SilentlyContinue | Where-Object {
                    $null -ne $_.SIDHistory -and $_.SIDHistory.Count -gt 0
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^AdminCount_Orphaned$|^ADMINCOUNT_ORPHANED$" {
                $users = @(Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf -EA SilentlyContinue | Where-Object {
                    $privilegedGroups = @($_.MemberOf | Where-Object { $_ -match "Domain Admins|Enterprise Admins|Administrators|Schema Admins" })
                    $privilegedGroups.Count -eq 0
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Smartcard_Not_Required$" {
                $users = @(Get-ADUser -Filter {SmartcardLogonRequired -eq $false} -Properties SmartcardLogonRequired, AdminCount -EA SilentlyContinue | Where-Object {
                    $_.AdminCount -eq 1
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Domain_Admin_In_Description$" {
                $users = @(Get-ADUser -Filter * -Properties Description -EA SilentlyContinue | Where-Object {
                    $_.Description -match "admin|administrator|domain admin"
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Shared_Account$" {
                $users = @(Get-ADUser -Filter * -EA SilentlyContinue | Where-Object {
                    $_.Name -match "shared|generic|common"
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Test_Account$" {
                $users = @(Get-ADUser -Filter * -EA SilentlyContinue | Where-Object {
                    $_.Name -match "test|demo|temp"
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^StaleAccount$" {
                $threshold = (Get-Date).AddDays(-180)
                $users = @(Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                    $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^User_Cannot_Change_Password$" {
                $notes = "Requires ACL analysis"
                $status = "UNKNOWN"
            }
            "^Ultra_Vulnerable_User$|^SuspiciousAccountName$|^SuspiciousSIDProperties$|^Shadow_Credentials$|^Foreign_Security_Principals$|^Sensitive_Delegation$|^SeEnableDelegationPrivilege$|^ADMIN_SD_HOLDER_MODIFIED$" {
                $notes = "Requires specific analysis"
                $status = "UNKNOWN"
            }
            "^AdminSDHolder_Backdoor$" {
                $adminSDHolder = Get-ADObject "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties nTSecurityDescriptor -EA SilentlyContinue
                $foundCount = if ($adminSDHolder) { 1 } else { 0 }
                $status = "UNKNOWN"
                $notes = "Requires ACL analysis for backdoor detection"
            }

            # === SERVICE ACCOUNTS ===
            "^SERVICE_ACCOUNT" {
                $svcAccounts = @(Get-ADUser -Filter * -EA SilentlyContinue | Where-Object {
                    $_.Name -match "svc|service|srv"
                })
                $foundCount = $svcAccounts.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }

            # === GPO ===
            "^GPO_Password_in_SYSVOL$|^GPO_PASSWORD_IN_SYSVOL$" {
                $domain = (Get-ADDomain).DNSRoot
                $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
                if (Test-Path $sysvolPath) {
                    $xmlFiles = @(Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" -EA SilentlyContinue)
                    $passwordFiles = @($xmlFiles | Where-Object {
                        $content = Get-Content $_.FullName -Raw -EA SilentlyContinue
                        $content -match "cpassword"
                    })
                    $foundCount = $passwordFiles.Count
                    $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
                }
            }
            "^GPO_LAPS_NOT_DEPLOYED$" {
                $gpos = @(Get-GPO -All -EA SilentlyContinue | Where-Object { $_.DisplayName -match "LAPS" })
                $foundCount = if ($gpos.Count -eq 0) { 1 } else { 0 }
                $status = if ($gpos.Count -eq 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^GPO_LinkPoisoning$|^GPO_NO_SECURITY_FILTERING$|^GPO_AUTHENTICATED_USERS_APPLY$" {
                $notes = "Requires GPO ACL analysis"
                $status = "UNKNOWN"
            }

            # === ADCS ===
            "^ESC" {
                $notes = "Requires ADCS PKI cmdlets"
                $status = "UNKNOWN"
            }

            # === ADVANCED ===
            "^RECYCLE_BIN_DISABLED$" {
                $recycleBin = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"} -EA SilentlyContinue
                $isDisabled = ($null -eq $recycleBin -or $recycleBin.EnabledScopes.Count -eq 0)
                $foundCount = if ($isDisabled) { 1 } else { 0 }
                $status = if ($isDisabled) { "FOUND" } else { "NOT_FOUND" }
            }
            "^Weak_Encryption_Flag$" {
                $users = @(Get-ADUser -Filter * -Properties userAccountControl -EA SilentlyContinue | Where-Object {
                    $_.userAccountControl -band 0x200000  # USE_DES_KEY_ONLY
                })
                $foundCount = $users.Count
                $status = if ($foundCount -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
            "^WriteSPN_Abuse$" {
                $notes = "Requires ACL analysis"
                $status = "UNKNOWN"
            }
            "^Everyone_In_ACL$|^Everyone_In_ACLs$" {
                $notes = "Requires ACL scan"
                $status = "UNKNOWN"
            }
            "^NTLM_RELAY_OPPORTUNITY$" {
                $notes = "Requires network configuration analysis"
                $status = "UNKNOWN"
            }
            "^Weak_Encryption_RC4_With_AES$|^DCSync_Rights$|^Dangerous_Logon_Script$|^LAPS_PasswordRead$|^LAPS_Password_Leaked$|^SERVER_NO_ADMIN_GROUP$|^SMB_V1_ENABLED$|^POWERSHELL_LOGGING_DISABLED$|^LDAP_CHANNEL_BINDING_DISABLED$|^Authenticated_Users_In_ACLs$|^AUDIT_POLICY_WEAK$|^ANONYMOUS_LDAP_ACCESS$" {
                $notes = "Requires system/policy analysis"
                $status = "UNKNOWN"
            }

            # === ACL ===
            "^ACL_|^NestedGroupPath$|^Orphaned_ACEs$" {
                $notes = "Requires ACL analysis"
                $status = "UNKNOWN"
            }

            # === ATTACK PATHS ===
            "^PATH_" {
                $notes = "Requires graph analysis"
                $status = "UNKNOWN"
            }

            # === EXCESSIVE PRIVILEGES ===
            "^ExcessivePrivileges" {
                $notes = "Requires privilege analysis"
                $status = "UNKNOWN"
            }

            # === DEFAULT ===
            default {
                $notes = "No verification method implemented"
                $status = "NOT_CHECKED"
            }
        }

        # Affichage
        if ($status -eq "FOUND") {
            Write-Host "✓ $foundCount" -ForegroundColor Green
        } elseif ($status -eq "NOT_FOUND") {
            Write-Host "✗ 0" -ForegroundColor Red
        } elseif ($status -eq "UNKNOWN") {
            Write-Host "? Unknown" -ForegroundColor Yellow
        } else {
            Write-Host "- Not checked" -ForegroundColor Gray
        }

    } catch {
        Write-Host "ERROR" -ForegroundColor Red
        $status = "ERROR"
        $notes = $_.Exception.Message
    }

    $results += [PSCustomObject]@{
        Type = $type
        InjectedCount = $injectedCount
        FoundCount = $foundCount
        Status = $status
        Notes = $notes
    }
}

Write-Progress -Activity "Vérification" -Completed

# Export
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Résumé
Write-Host "`n=== RÉSUMÉ ===" -ForegroundColor Cyan
$found = @($results | Where-Object { $_.Status -eq "FOUND" })
$notFound = @($results | Where-Object { $_.Status -eq "NOT_FOUND" })
$unknown = @($results | Where-Object { $_.Status -eq "UNKNOWN" })
$notChecked = @($results | Where-Object { $_.Status -eq "NOT_CHECKED" })
$errors = @($results | Where-Object { $_.Status -eq "ERROR" })

Write-Host "Total types testés: $($results.Count)"
Write-Host "✓ Trouvés (FOUND): $($found.Count) ($([math]::Round($found.Count / $results.Count * 100, 1))%)" -ForegroundColor Green
Write-Host "✗ Non trouvés (NOT_FOUND): $($notFound.Count) ($([math]::Round($notFound.Count / $results.Count * 100, 1))%)" -ForegroundColor Red
Write-Host "? Inconnus (UNKNOWN): $($unknown.Count) ($([math]::Round($unknown.Count / $results.Count * 100, 1))%)" -ForegroundColor Yellow
Write-Host "- Non vérifiés (NOT_CHECKED): $($notChecked.Count) ($([math]::Round($notChecked.Count / $results.Count * 100, 1))%)" -ForegroundColor Gray
Write-Host "! Erreurs (ERROR): $($errors.Count)" -ForegroundColor Red

Write-Host "`nExporté vers: $OutputPath"

# Afficher les types NON trouvés (bugs d'injection)
if ($notFound.Count -gt 0) {
    Write-Host "`n=== BUGS D'INJECTION ($($notFound.Count) types) ===" -ForegroundColor Red
    $notFound | Select-Object Type, InjectedCount | Format-Table -AutoSize
}

# Statistiques par catégorie
Write-Host "`n=== PAR CATÉGORIE ===" -ForegroundColor Cyan
Write-Host "FOUND (vraiment dans l'AD): $($found.Count)"
Write-Host "NOT_FOUND (bug injection): $($notFound.Count)"
Write-Host "UNKNOWN (nécessite analyse manuelle): $($unknown.Count)"
Write-Host "NOT_CHECKED (pas de méthode): $($notChecked.Count)"
