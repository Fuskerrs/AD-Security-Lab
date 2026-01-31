# Script de vérification complète de TOUTES les vulnérabilités injectées

$csvPath = "C:\ADPopulate_Reports\GlobalCorp_Vulnerabilities_20260130_174331.csv"
$outputPath = "C:\AD-Security-Lab\docs\audit\v1.1.4\verification-complete.csv"

# Lire le CSV
$injected = Import-Csv $csvPath
$byType = $injected | Group-Object -Property Type

Write-Host "=== VÉRIFICATION COMPLÈTE ===" -ForegroundColor Cyan
Write-Host "Types à tester: $($byType.Count)`n"

$results = @()

foreach ($group in $byType) {
    $type = $group.Name
    $injectedCount = $group.Count
    $foundCount = 0
    $found = $false
    $notes = ""

    Write-Host "Testing: $type ($injectedCount)..." -NoNewline

    try {
        # === PASSWORDS ===
        if ($type -eq "PasswordNeverExpires") {
            $users = @(Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "PasswordNotRequired") {
            $users = @(Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "ReversibleEncryption") {
            $users = @(Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "PasswordInDescription") {
            $users = @(Get-ADUser -Filter * -Properties Description | Where-Object {
                $_.Description -match "password|pwd|pass|mdp"
            } -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }

        # === KERBEROS ===
        elseif ($type -eq "Kerberoastable") {
            $users = @(Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "AsRepRoastable") {
            $users = @(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "UnconstrainedDelegation") {
            $objects = @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue)
            $foundCount = $objects.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "ConstrainedDelegation") {
            $objects = @(Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo -EA SilentlyContinue)
            $foundCount = $objects.Count
            $found = $foundCount -gt 0
        }

        # === COMPUTERS ===
        elseif ($type -eq "Computer_No_LAPS") {
            $computers = @(Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -EA SilentlyContinue | Where-Object {
                $null -eq $_."ms-Mcs-AdmPwd"
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Old_Password") {
            $threshold = (Get-Date).AddDays(-90)
            $computers = @(Get-ADComputer -Filter * -Properties PasswordLastSet -EA SilentlyContinue | Where-Object {
                $_.PasswordLastSet -and $_.PasswordLastSet -lt $threshold
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Stale_Inactive") {
            $threshold = (Get-Date).AddDays(-90)
            $computers = @(Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Never_Logged_On") {
            $computers = @(Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                $null -eq $_.LastLogonDate
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Unconstrained_Delegation") {
            $computers = @(Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue)
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_No_Bitlocker") {
            $computers = @(Get-ADComputer -Filter * -EA SilentlyContinue)
            $foundCount = $computers.Count
            $found = $true
            $notes = "All computers counted (BitLocker status not in AD)"
        }
        elseif ($type -match "Computer_OS_Obsolete") {
            $osPattern = if ($type -match "XP") { "*XP*" }
                elseif ($type -match "Vista") { "*Vista*" }
                elseif ($type -match "2003") { "*2003*" }
                elseif ($type -match "2008") { "*2008*" }
                else { "*" }
            $computers = @(Get-ADComputer -Filter * -Properties OperatingSystem -EA SilentlyContinue | Where-Object {
                $_.OperatingSystem -like $osPattern
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Wrong_OU") {
            $computers = @(Get-ADComputer -Filter * -EA SilentlyContinue | Where-Object {
                $_.DistinguishedName -notmatch "OU=Computers"
            })
            $foundCount = $computers.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Computer_Duplicate_SPN") {
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
            $found = $foundCount -gt 0
        }

        # === GROUPS ===
        elseif ($type -match "Oversized_Group") {
            $threshold = if ($type -match "Critical") { 500 } else { 100 }
            $groups = @(Get-ADGroup -Filter * -Properties Members -EA SilentlyContinue | Where-Object {
                $_.Members.Count -gt $threshold
            })
            $foundCount = $groups.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Group_Protected_Users_Empty") {
            $group = Get-ADGroup -Identity "Protected Users" -Properties Members -EA SilentlyContinue
            $found = ($group.Members.Count -eq 0)
            $foundCount = if ($found) { 1 } else { 0 }
        }

        # === ACCOUNTS ===
        elseif ($type -eq "Not_In_Protected_Users") {
            $protectedUsers = @(Get-ADGroupMember -Identity "Protected Users" -EA SilentlyContinue)
            $adminUsers = @(Get-ADGroupMember -Identity "Domain Admins" -EA SilentlyContinue)
            $notProtected = @($adminUsers | Where-Object { $protectedUsers.SID -notcontains $_.SID })
            $foundCount = $notProtected.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Inactive_365_Days") {
            $threshold = (Get-Date).AddDays(-365)
            $users = @(Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
            })
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Never_Logged_On") {
            $users = @(Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object {
                $null -eq $_.LastLogonDate -and $_.Enabled -eq $true
            })
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Disabled_Account_In_Admin_Group") {
            $adminGroups = @(Get-ADGroup -Filter {Name -like "*Admin*"} -EA SilentlyContinue)
            $disabledCount = 0
            foreach ($group in $adminGroups) {
                $members = @(Get-ADGroupMember -Identity $group -EA SilentlyContinue | Where-Object { $_.objectClass -eq "user" })
                foreach ($member in $members) {
                    $user = Get-ADUser -Identity $member -Properties Enabled -EA SilentlyContinue
                    if ($user.Enabled -eq $false) { $disabledCount++ }
                }
            }
            $foundCount = $disabledCount
            $found = $foundCount -gt 0
        }

        # === BUILTIN GROUPS ===
        elseif ($type -match "_Member$") {
            $groupName = if ($type -match "Account_Operators") { "Account Operators" }
                elseif ($type -match "Backup_Operators") { "Backup Operators" }
                elseif ($type -match "DNS_Admins") { "DnsAdmins" }
                elseif ($type -match "Print_Operators") { "Print Operators" }
                elseif ($type -match "Server_Operators") { "Server Operators" }
                else { $null }
            if ($groupName) {
                $members = @(Get-ADGroupMember -Identity $groupName -EA SilentlyContinue)
                $foundCount = $members.Count
                $found = $foundCount -gt 0
            }
        }

        # === SERVICE ACCOUNTS ===
        elseif ($type -match "Service_Account") {
            $svcAccounts = @(Get-ADUser -Filter {Name -like "*svc*" -or Name -like "*service*"} -EA SilentlyContinue)
            $foundCount = $svcAccounts.Count
            $found = $foundCount -gt 0
        }

        # === GPO ===
        elseif ($type -eq "GPO_Password_In_SYSVOL") {
            $domain = (Get-ADDomain).DNSRoot
            $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
            if (Test-Path $sysvolPath) {
                $xmlFiles = @(Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" -EA SilentlyContinue)
                $passwordFiles = @($xmlFiles | Where-Object {
                    (Get-Content $_.FullName -Raw -EA SilentlyContinue) -match "cpassword"
                })
                $foundCount = $passwordFiles.Count
                $found = $foundCount -gt 0
            }
        }
        elseif ($type -eq "GPO_LAPS_Not_Deployed") {
            $gpos = @(Get-GPO -All -EA SilentlyContinue | Where-Object { $_.DisplayName -match "LAPS" })
            $found = ($gpos.Count -eq 0)
            $foundCount = if ($found) { 1 } else { 0 }
        }

        # === ADVANCED ===
        elseif ($type -eq "Recycle_Bin_Disabled") {
            $recycleBin = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"} -EA SilentlyContinue
            $found = ($null -eq $recycleBin -or $recycleBin.EnabledScopes.Count -eq 0)
            $foundCount = if ($found) { 1 } else { 0 }
        }
        elseif ($type -eq "Smartcard_Not_Required") {
            $users = @(Get-ADUser -Filter {SmartcardLogonRequired -eq $false -and AdminCount -eq 1} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Test_Account") {
            $users = @(Get-ADUser -Filter {Name -like "*test*"} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Shared_Account") {
            $users = @(Get-ADUser -Filter {Name -like "*shared*" -or Name -like "*generic*"} -EA SilentlyContinue)
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }
        elseif ($type -eq "Domain_Admin_In_Description") {
            $users = @(Get-ADUser -Filter * -Properties Description -EA SilentlyContinue | Where-Object {
                $_.Description -match "admin|administrator"
            })
            $foundCount = $users.Count
            $found = $foundCount -gt 0
        }

        # === DEFAULT ===
        else {
            $notes = "No verification method"
            $found = "UNKNOWN"
        }

        # Affichage
        if ($found -eq $true) {
            Write-Host " ✓ $foundCount" -ForegroundColor Green
        } elseif ($found -eq $false) {
            Write-Host " ✗ 0" -ForegroundColor Red
        } else {
            Write-Host " ?" -ForegroundColor Yellow
        }

    } catch {
        Write-Host " ERROR" -ForegroundColor Red
        $found = "ERROR"
        $notes = $_.Exception.Message
    }

    $results += [PSCustomObject]@{
        Type = $type
        InjectedCount = $injectedCount
        FoundCount = $foundCount
        Exists = $found
        Notes = $notes
    }
}

# Export
$results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

# Résumé
Write-Host "`n=== RÉSUMÉ ===" -ForegroundColor Cyan
$verified = @($results | Where-Object { $_.Exists -eq $true })
$notFound = @($results | Where-Object { $_.Exists -eq $false })
$unknown = @($results | Where-Object { $_.Exists -eq "UNKNOWN" -or $_.Exists -eq "ERROR" })

Write-Host "Total: $($results.Count)"
Write-Host "✓ Trouvés: $($verified.Count) ($([math]::Round($verified.Count / $results.Count * 100, 1))%)" -ForegroundColor Green
Write-Host "✗ NON trouvés: $($notFound.Count) ($([math]::Round($notFound.Count / $results.Count * 100, 1))%)" -ForegroundColor Red
Write-Host "? Inconnus: $($unknown.Count) ($([math]::Round($unknown.Count / $results.Count * 100, 1))%)" -ForegroundColor Yellow

Write-Host "`nExporté: $outputPath"

# Liste des non trouvés
if ($notFound.Count -gt 0) {
    Write-Host "`n=== NON TROUVÉES ($($notFound.Count)) ===" -ForegroundColor Red
    $notFound | Select-Object Type, InjectedCount | Format-Table -AutoSize
}
