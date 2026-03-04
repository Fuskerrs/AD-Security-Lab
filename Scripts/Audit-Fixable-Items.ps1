Write-Host "=== 1. GPO ORPHANED & UNLINKED ===" -ForegroundColor Cyan
Get-GPO -All | Where-Object {
    $links = (Get-GPOReport -Guid $_.Id -ReportType XML 2>$null)
    ($links -notmatch "LinksTo")
} | Select-Object DisplayName, Id, CreationTime | Format-Table -AutoSize

Write-Host ""
Write-Host "=== 2. DNS ADMINS MEMBERS ===" -ForegroundColor Cyan
Get-ADGroupMember "DnsAdmins" | Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize

Write-Host ""
Write-Host "=== 3. COMPUTERS WITH SENSITIVE DESCRIPTION (sample) ===" -ForegroundColor Cyan
Get-ADComputer -Filter {Description -like "*"} -Properties Description, Name |
    Where-Object { $_.Description -match "password|pass|mdp|admin|secret|key|pwd" -or $_.Description.Length -gt 0 } |
    Select-Object Name, Description | Select-Object -First 5 | Format-Table -AutoSize

Write-Host ""
Write-Host "=== 4. COMPUTERS NEVER LOGGED ON (sample - older than 180 days) ===" -ForegroundColor Cyan
$cutoff = (Get-Date).AddDays(-180)
Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -lt $cutoff} -Properties LastLogonDate, Created |
    Where-Object { $_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoff } |
    Select-Object Name, LastLogonDate, Created | Select-Object -First 5 | Format-Table -AutoSize

Write-Host ""
Write-Host "=== 5. PASSWORD POLICY ===" -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength, MaxPasswordAge, PasswordHistoryCount, LockoutThreshold, ComplexityEnabled | Format-List

Write-Host ""
Write-Host "=== 6. PROTECTED USERS GROUP ===" -ForegroundColor Cyan
Get-ADGroupMember "Protected Users" -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName | Format-Table -AutoSize
Write-Host "(empty = nobody in Protected Users)"

Write-Host ""
Write-Host "=== 7. DANGEROUS GROUP NESTING ===" -ForegroundColor Cyan
$privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($grp in $privGroups) {
    $members = Get-ADGroupMember $grp | Where-Object { $_.ObjectClass -eq "group" }
    if ($members) {
        Write-Host "Groups nested in '$grp':"
        $members | Select-Object Name, SamAccountName | Format-Table -AutoSize
    }
}

Write-Host ""
Write-Host "=== 8. USERS WITH PASSWORD NEVER EXPIRES (sample) ===" -ForegroundColor Cyan
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires, PasswordLastSet |
    Where-Object { $_.SamAccountName -notlike "krbtgt*" -and $_.SamAccountName -ne "Administrator" } |
    Select-Object Name, SamAccountName, PasswordLastSet | Select-Object -First 10 | Format-Table -AutoSize
