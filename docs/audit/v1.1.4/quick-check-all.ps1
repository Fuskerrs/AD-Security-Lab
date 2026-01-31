$csv = Import-Csv 'C:\ADPopulate_Reports\GlobalCorp_Vulnerabilities_20260130_174331.csv'
$byType = $csv | Group-Object Type | Sort-Object Count -Descending

Write-Host "`n=== VÉRIFICATION DE TOUS LES TYPES ($($byType.Count)) ===" -ForegroundColor Cyan
Write-Host "Cela va prendre quelques minutes...`n"

$results = @()

foreach ($group in $byType) {
    $type = $group.Name
    $injected = $group.Count
    $found = 0
    $status = "UNKNOWN"

    Write-Host "$type ($injected injecté)... " -NoNewline

    try {
        # PASSWORDS
        if ($type -eq "PasswordNeverExpires") {
            $found = (Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "PasswordNotRequired") {
            $found = (Get-ADUser -Filter {PasswordNotRequired -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "ReversibleEncryption") {
            $found = (Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "PasswordInDescription") {
            $found = (Get-ADUser -Filter * -Properties Description -EA SilentlyContinue | Where-Object { $_.Description -match "password|pwd|pass" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # KERBEROS
        elseif ($type -match "^Kerberoastable") {
            $found = (Get-ADUser -Filter {ServicePrincipalName -like "*"} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "ASREPRoastable") {
            $found = (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "UnconstrainedDelegation") {
            $found = (Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "ConstrainedDelegation") {
            $found = (Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # COMPUTERS
        elseif ($type -eq "Computer_Stale_Inactive") {
            $threshold = (Get-Date).AddDays(-90)
            $found = (Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object { $_.LastLogonDate -lt $threshold }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_Old_Password") {
            $threshold = (Get-Date).AddDays(-90)
            $found = (Get-ADComputer -Filter * -Properties PasswordLastSet -EA SilentlyContinue | Where-Object { $_.PasswordLastSet -lt $threshold }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "Computer_Never_Logged_On|COMPUTER_NEVER_LOGGED_ON") {
            $found = (Get-ADComputer -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object { $null -eq $_.LastLogonDate }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_Disabled_Not_Deleted") {
            $found = (Get-ADComputer -Filter {Enabled -eq $false} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_Sensitive_Description") {
            $found = (Get-ADComputer -Filter * -Properties Description -EA SilentlyContinue | Where-Object { $_.Description -match "password|admin|secret" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_Unconstrained_Delegation") {
            $found = (Get-ADComputer -Filter {TrustedForDelegation -eq $true} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "Computer_Duplicate_SPN|COMPUTER_DUPLICATE_SPN|Duplicate_SPN") {
            $comps = Get-ADComputer -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName -EA SilentlyContinue
            $spns = @{}
            foreach ($c in $comps) {
                foreach ($spn in $c.ServicePrincipalName) {
                    if (-not $spns.ContainsKey($spn)) { $spns[$spn] = @() }
                    $spns[$spn] += $c.Name
                }
            }
            $found = ($spns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_Wrong_OU") {
            $found = (Get-ADComputer -Filter * -EA SilentlyContinue | Where-Object { $_.DistinguishedName -notmatch "OU=Computers" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_With_SPNs") {
            $found = (Get-ADComputer -Filter {ServicePrincipalName -like "*"} -EA SilentlyContinue).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "COMPUTER_OS_OBSOLETE") {
            $os = if ($type -match "XP") { "*XP*" }
                elseif ($type -match "2003") { "*2003*" }
                elseif ($type -match "Vista") { "*Vista*" }
                elseif ($type -match "2008") { "*2008*" }
                else { "*" }
            $found = (Get-ADComputer -Filter * -Properties OperatingSystem -EA SilentlyContinue | Where-Object { $_.OperatingSystem -like $os }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Computer_In_Admin_Group") {
            $members = Get-ADGroupMember -Identity "Domain Admins" -EA SilentlyContinue | Where-Object { $_.objectClass -eq "computer" }
            $found = $members.Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # GPO
        elseif ($type -match "GPO_Password_in_SYSVOL|GPO_PASSWORD_IN_SYSVOL") {
            $domain = (Get-ADDomain).DNSRoot
            $xmlFiles = Get-ChildItem "\\$domain\SYSVOL\$domain\Policies" -Recurse -Filter "*.xml" -EA SilentlyContinue
            $found = ($xmlFiles | Where-Object { (Get-Content $_.FullName -Raw -EA SilentlyContinue) -match "cpassword" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # SERVICE ACCOUNTS
        elseif ($type -match "SERVICE_ACCOUNT") {
            $found = (Get-ADUser -Filter * -EA SilentlyContinue | Where-Object { $_.Name -match "svc|service" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # GROUPS
        elseif ($type -match "Oversized_Group") {
            $threshold = if ($type -match "Critical") { 500 } else { 100 }
            $found = (Get-ADGroup -Filter * -Properties Members -EA SilentlyContinue | Where-Object { $_.Members.Count -gt $threshold }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "_Member") {
            $groupName = if ($type -match "Account_Operators") { "Account Operators" }
                elseif ($type -match "Backup_Operators") { "Backup Operators" }
                elseif ($type -match "DNS_Admins") { "DnsAdmins" }
                elseif ($type -match "Print_Operators") { "Print Operators" }
                elseif ($type -match "Server_Operators") { "Server Operators" }
                else { $null }
            if ($groupName) {
                $found = (Get-ADGroupMember -Identity $groupName -EA SilentlyContinue).Count
                $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
            }
        }

        # ACCOUNTS
        elseif ($type -match "Shared_Account") {
            $found = (Get-ADUser -Filter * -EA SilentlyContinue | Where-Object { $_.Name -match "shared|generic" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "Test_Account") {
            $found = (Get-ADUser -Filter * -EA SilentlyContinue | Where-Object { $_.Name -match "test|demo|temp" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "StaleAccount") {
            $threshold = (Get-Date).AddDays(-180)
            $found = (Get-ADUser -Filter * -Properties LastLogonDate -EA SilentlyContinue | Where-Object { $_.LastLogonDate -lt $threshold }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -match "Not_In_Protected_Users|NotInProtectedUsers") {
            $protected = Get-ADGroupMember -Identity "Protected Users" -EA SilentlyContinue
            $admins = Get-ADGroupMember -Identity "Domain Admins" -EA SilentlyContinue
            $found = ($admins | Where-Object { $protected.SID -notcontains $_.SID }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }
        elseif ($type -eq "Domain_Admin_In_Description") {
            $found = (Get-ADUser -Filter * -Properties Description -EA SilentlyContinue | Where-Object { $_.Description -match "admin" }).Count
            $status = if ($found -gt 0) { "FOUND" } else { "NOT_FOUND" }
        }

        # Afficher
        if ($status -eq "FOUND") { Write-Host "+ $found" -ForegroundColor Green }
        elseif ($status -eq "NOT_FOUND") { Write-Host "- 0" -ForegroundColor Red }
        else { Write-Host "? unknown" -ForegroundColor Yellow }

    } catch {
        Write-Host "ERROR" -ForegroundColor Red
        $status = "ERROR"
    }

    $results += [PSCustomObject]@{
        Type = $type
        Injected = $injected
        Found = $found
        Status = $status
    }
}

# Export
$results | Export-Csv "C:\AD-Security-Lab\docs\audit\v1.1.4\verification-all-138.csv" -NoTypeInformation

# Résumé
$foundCount = ($results | Where-Object { $_.Status -eq "FOUND" }).Count
$notFoundCount = ($results | Where-Object { $_.Status -eq "NOT_FOUND" }).Count
$unknownCount = ($results | Where-Object { $_.Status -eq "UNKNOWN" }).Count

Write-Host "`n=== RESUME ===" -ForegroundColor Cyan
Write-Host "Total: $($results.Count) types"
Write-Host "+ FOUND: $foundCount ($([math]::Round($foundCount/$results.Count*100,1))%)" -ForegroundColor Green
Write-Host "- NOT_FOUND: $notFoundCount ($([math]::Round($notFoundCount/$results.Count*100,1))%)" -ForegroundColor Red
Write-Host "? UNKNOWN: $unknownCount ($([math]::Round($unknownCount/$results.Count*100,1))%)" -ForegroundColor Yellow

# Liste des NOT_FOUND
$notFoundList = $results | Where-Object { $_.Status -eq "NOT_FOUND" }
if ($notFoundList.Count -gt 0) {
    Write-Host "`n=== BUGS D'INJECTION ($($notFoundList.Count)) ===" -ForegroundColor Red
    $notFoundList | Format-Table Type, Injected -AutoSize
}
