$csv = Import-Csv 'C:\ADPopulate_Reports\GlobalCorp_Vulnerabilities_20260130_174331.csv'
$byType = $csv | Group-Object Type | Select-Object Name, Count | Sort-Object Count -Descending

Write-Host "`n=== TYPES INJECTÉS ($($byType.Count)) ===" -ForegroundColor Cyan
$byType | Format-Table -AutoSize

Write-Host "`n=== VÉRIFICATION TOP 15 ===" -ForegroundColor Yellow

# 1. PasswordNeverExpires
Write-Host "`n1. PasswordNeverExpires:" -NoNewline
$count = (Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 2. Computer_Duplicate_SPN
Write-Host "2. Computer_Duplicate_SPN:" -NoNewline
$comps = Get-ADComputer -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName
$spns = @{}
foreach ($c in $comps) {
    foreach ($spn in $c.ServicePrincipalName) {
        if (-not $spns.ContainsKey($spn)) { $spns[$spn] = @() }
        $spns[$spn] += $c.Name
    }
}
$dups = $spns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
Write-Host " $($dups.Count) trouvés" -ForegroundColor $(if ($dups.Count -gt 0) {'Green'} else {'Red'})

# 3. Computer_Old_Password
Write-Host "3. Computer_Old_Password:" -NoNewline
$threshold = (Get-Date).AddDays(-90)
$count = (Get-ADComputer -Filter * -Properties PasswordLastSet | Where-Object { $_.PasswordLastSet -lt $threshold }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 4. Computer_Stale_Inactive
Write-Host "4. Computer_Stale_Inactive:" -NoNewline
$count = (Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt $threshold }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 5. Computer_No_Bitlocker
Write-Host "5. Computer_No_Bitlocker:" -NoNewline
$count = (Get-ADComputer -Filter *).Count
Write-Host " $count (tous - non vérifiable)" -ForegroundColor Yellow

# 6. Computer_Pre_Win2000
Write-Host "6. Computer_Pre_Win2000:" -NoNewline
$count = (Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object { $_.OperatingSystem -match 'NT|2000' }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 7. Computer_Never_Logged_On
Write-Host "7. Computer_Never_Logged_On:" -NoNewline
$count = (Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object { $null -eq $_.LastLogonDate }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 8. Computer_Disabled_Not_Deleted
Write-Host "8. Computer_Disabled_Not_Deleted:" -NoNewline
$count = (Get-ADComputer -Filter {Enabled -eq $false}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 9. Computer_Sensitive_Description
Write-Host "9. Computer_Sensitive_Description:" -NoNewline
$count = (Get-ADComputer -Filter * -Properties Description | Where-Object { $_.Description -match 'password|admin|secret' }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 10. Kerberoastable
Write-Host "10. Kerberoastable:" -NoNewline
$count = (Get-ADUser -Filter {ServicePrincipalName -like '*'}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 11. UnconstrainedDelegation
Write-Host "11. UnconstrainedDelegation:" -NoNewline
$count = (Get-ADComputer -Filter {TrustedForDelegation -eq $true}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 12. ConstrainedDelegation
Write-Host "12. ConstrainedDelegation:" -NoNewline
$count = (Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 13. AsRepRoastable
Write-Host "13. AsRepRoastable:" -NoNewline
$count = (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

# 14. GPO_Password_In_SYSVOL
Write-Host "14. GPO_Password_In_SYSVOL:" -NoNewline
$domain = (Get-ADDomain).DNSRoot
$sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
if (Test-Path $sysvolPath) {
    $xmlFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" -EA SilentlyContinue
    $passwordFiles = $xmlFiles | Where-Object {
        (Get-Content $_.FullName -Raw -EA SilentlyContinue) -match "cpassword"
    }
    Write-Host " $($passwordFiles.Count) trouvés" -ForegroundColor $(if ($passwordFiles.Count -gt 0) {'Green'} else {'Red'})
} else {
    Write-Host " SYSVOL inaccessible" -ForegroundColor Yellow
}

# 15. Computer_No_LAPS
Write-Host "15. Computer_No_LAPS:" -NoNewline
$count = (Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object { $null -eq $_."ms-Mcs-AdmPwd" }).Count
Write-Host " $count trouvés" -ForegroundColor $(if ($count -gt 0) {'Green'} else {'Red'})

Write-Host "`n=== RÉSUMÉ ===" -ForegroundColor Cyan
Write-Host "Ces vulnérabilités doivent être confirmées dans l'AD pour valider le collecteur."
