$results = @()

function Log($status, $vuln, $action) {
    $icon = if ($status -eq "OK") { "OK" } else { "FAIL" }
    Write-Host "[$icon] $vuln : $action" -ForegroundColor $(if ($status -eq "OK") { "Green" } else { "Red" })
    $script:results += [PSCustomObject]@{ Status=$status; Vuln=$vuln; Action=$action }
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AD VULNERABILITY FIX - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# --- FIX 1: GPO Orphaned ---
Write-Host "[1/10] GPO_ORPHANED - Delete VulnerableGPO-LocalAdmin-MS14-025" -ForegroundColor Yellow
try {
    Remove-GPO -Name "VulnerableGPO-LocalAdmin-MS14-025" -Confirm:$false
    Log "OK" "GPO_ORPHANED" "Deleted 'VulnerableGPO-LocalAdmin-MS14-025'"
} catch { Log "FAIL" "GPO_ORPHANED" $_.Exception.Message }

# --- FIX 2: DNS Admins - Remove non-admin users ---
Write-Host ""
Write-Host "[2/10] DNS_ADMINS_MEMBER - Remove regular users from DnsAdmins" -ForegroundColor Yellow
$dnsUsers = @("akter.karim", "harris.william", "ma.lan", "taylor.christopher")
foreach ($user in $dnsUsers) {
    try {
        Remove-ADGroupMember -Identity "DnsAdmins" -Members $user -Confirm:$false
        Log "OK" "DNS_ADMINS_MEMBER" "Removed $user from DnsAdmins"
    } catch { Log "FAIL" "DNS_ADMINS_MEMBER" "Failed to remove $user : $($_.Exception.Message)" }
}

# --- FIX 3: Computer sensitive descriptions - Clear them ---
Write-Host ""
Write-Host "[3/10] COMPUTER_DESCRIPTION_SENSITIVE - Clear sensitive descriptions" -ForegroundColor Yellow
$sensitiveComputers = @("WKS-OSAKA-3749", "WKS-LAGOS-8648", "WKS-KARACHI-1490", "WKS-MANILA-4917")
foreach ($computer in $sensitiveComputers) {
    try {
        Set-ADComputer -Identity $computer -Description ""
        Log "OK" "COMPUTER_DESCRIPTION_SENSITIVE" "Cleared description on $computer"
    } catch { Log "FAIL" "COMPUTER_DESCRIPTION_SENSITIVE" "Failed $computer : $($_.Exception.Message)" }
}

# --- FIX 4: Password Policy - MinLength 7 -> 12 ---
Write-Host ""
Write-Host "[4/10] GPO_WEAK_PASSWORD_POLICY - Fix min password length (7 -> 12)" -ForegroundColor Yellow
try {
    Set-ADDefaultDomainPasswordPolicy -Identity "aza-me.cc" -MinPasswordLength 12
    Log "OK" "GPO_WEAK_PASSWORD_POLICY" "MinPasswordLength set to 12"
} catch { Log "FAIL" "GPO_WEAK_PASSWORD_POLICY" $_.Exception.Message }

# --- FIX 5: Password Policy - Lockout threshold ---
Write-Host ""
Write-Host "[5/10] GPO_WEAK_PASSWORD_POLICY - Enable account lockout (0 -> 5)" -ForegroundColor Yellow
try {
    Set-ADDefaultDomainPasswordPolicy -Identity "aza-me.cc" -LockoutThreshold 5 -LockoutDuration "00:30:00" -LockoutObservationWindow "00:30:00"
    Log "OK" "GPO_WEAK_PASSWORD_POLICY" "LockoutThreshold set to 5 (30min lockout)"
} catch { Log "FAIL" "GPO_WEAK_PASSWORD_POLICY" $_.Exception.Message }

# --- FIX 6: Protected Users - Add Domain Admins members ---
Write-Host ""
Write-Host "[6/10] GROUP_PROTECTED_USERS_EMPTY - Add DA members to Protected Users" -ForegroundColor Yellow
try {
    $daMembers = Get-ADGroupMember "Domain Admins" | Where-Object { $_.ObjectClass -eq "user" }
    foreach ($member in $daMembers) {
        Add-ADGroupMember -Identity "Protected Users" -Members $member.SamAccountName -ErrorAction SilentlyContinue
    }
    $count = (Get-ADGroupMember "Protected Users").Count
    Log "OK" "GROUP_PROTECTED_USERS_EMPTY" "Added $count Domain Admin users to Protected Users"
} catch { Log "FAIL" "GROUP_PROTECTED_USERS_EMPTY" $_.Exception.Message }

# --- FIX 7: Dangerous group nesting - Remove groups from Domain Admins ---
Write-Host ""
Write-Host "[7/10] DANGEROUS_GROUP_NESTING - Remove group nesting from Domain Admins" -ForegroundColor Yellow
$nestedGroups = @("GS-IT-Infrastructure", "NestedGroup-L6")
foreach ($grp in $nestedGroups) {
    try {
        Remove-ADGroupMember -Identity "Domain Admins" -Members $grp -Confirm:$false
        Log "OK" "DANGEROUS_GROUP_NESTING" "Removed group '$grp' from Domain Admins"
    } catch { Log "FAIL" "DANGEROUS_GROUP_NESTING" "Failed $grp : $($_.Exception.Message)" }
}

# --- FIX 8: Password Never Expires - Fix for 3 regular users ---
Write-Host ""
Write-Host "[8/10] USER_PASSWORD_NEVER_EXPIRES - Enable password expiry for 3 users" -ForegroundColor Yellow
$usersToFix = @("jackson.akira", "liu.fang", "nakamura.naomi")
foreach ($user in $usersToFix) {
    try {
        Set-ADUser -Identity $user -PasswordNeverExpires $false
        Log "OK" "USER_PASSWORD_NEVER_EXPIRES" "Enabled password expiry for $user"
    } catch { Log "FAIL" "USER_PASSWORD_NEVER_EXPIRES" "Failed $user : $($_.Exception.Message)" }
}

# --- FIX 9: Computer description auto-generated - Clean ---
Write-Host ""
Write-Host "[9/10] COMPUTER_DESCRIPTION_SENSITIVE - Clear auto-generated description" -ForegroundColor Yellow
try {
    Set-ADComputer -Identity "WKS-SHANGHAI-1010" -Description ""
    Log "OK" "COMPUTER_DESCRIPTION_SENSITIVE" "Cleared description on WKS-SHANGHAI-1010"
} catch { Log "FAIL" "COMPUTER_DESCRIPTION_SENSITIVE" $_.Exception.Message }

# --- FIX 10: MaxPasswordAge - Reduce from 42 to 90 days ---
Write-Host ""
Write-Host "[10/10] GPO_WEAK_PASSWORD_POLICY - MaxPasswordAge 42 -> 90 days" -ForegroundColor Yellow
try {
    Set-ADDefaultDomainPasswordPolicy -Identity "aza-me.cc" -MaxPasswordAge "90.00:00:00"
    Log "OK" "GPO_WEAK_PASSWORD_POLICY" "MaxPasswordAge set to 90 days"
} catch { Log "FAIL" "GPO_WEAK_PASSWORD_POLICY" $_.Exception.Message }

# --- Summary ---
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$ok   = ($results | Where-Object { $_.Status -eq "OK" }).Count
$fail = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
Write-Host "Total fixes attempted : $($results.Count)"
Write-Host "Success               : $ok" -ForegroundColor Green
Write-Host "Failed                : $fail" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "=== CHANGES APPLIED ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
