$results = @()
function Log($status, $vuln, $action) {
    $color = if ($status -eq "OK") { "Green" } elseif ($status -eq "SKIP") { "Yellow" } else { "Red" }
    Write-Host "[$status] $vuln : $action" -ForegroundColor $color
    $script:results += [PSCustomObject]@{ Status=$status; Vuln=$vuln; Action=$action }
}

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  CRITICAL FIXES - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── FIX 1: COMPUTER_UNCONSTRAINED_DELEGATION (8 critical) ────────────────────
Write-Host "`n[1] COMPUTER_UNCONSTRAINED_DELEGATION - Disable on non-DC computers" -ForegroundColor Yellow
$unconstrained = Get-ADComputer -Filter * -Properties TrustedForDelegation, userAccountControl |
    Where-Object {
        $_.TrustedForDelegation -eq $true -and
        $_.DistinguishedName -notlike "*Domain Controllers*"
    }
Write-Host "Found: $($unconstrained.Count) computers"
foreach ($c in $unconstrained) {
    try {
        Set-ADComputer -Identity $c.SamAccountName -TrustedForDelegation $false
        Log "OK" "COMPUTER_UNCONSTRAINED_DELEGATION" "Disabled unconstrained delegation on $($c.Name)"
    } catch { Log "FAIL" "COMPUTER_UNCONSTRAINED_DELEGATION" "$($c.Name): $($_.Exception.Message)" }
}

# ── FIX 2: COMPUTER_IN_ADMIN_GROUP (5 critical) ───────────────────────────────
Write-Host "`n[2] COMPUTER_IN_ADMIN_GROUP - Remove computers from admin groups" -ForegroundColor Yellow
$adminGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators")
foreach ($grp in $adminGroups) {
    try {
        $members = Get-ADGroupMember $grp -ErrorAction SilentlyContinue |
            Where-Object { $_.ObjectClass -eq "computer" }
        foreach ($m in $members) {
            Remove-ADGroupMember -Identity $grp -Members $m -Confirm:$false
            Log "OK" "COMPUTER_IN_ADMIN_GROUP" "Removed computer $($m.Name) from $grp"
        }
    } catch { Log "FAIL" "COMPUTER_IN_ADMIN_GROUP" "$grp : $($_.Exception.Message)" }
}

# ── FIX 3: COMPUTER_RBCD (3 critical) ─────────────────────────────────────────
Write-Host "`n[3] COMPUTER_RBCD - Remove Resource-Based Constrained Delegation" -ForegroundColor Yellow
$rbcdComputers = Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" -ne $null }
Write-Host "Found: $($rbcdComputers.Count) computers with RBCD"
foreach ($c in $rbcdComputers) {
    try {
        Set-ADComputer -Identity $c.SamAccountName -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"
        Log "OK" "COMPUTER_RBCD" "Cleared RBCD on $($c.Name)"
    } catch { Log "FAIL" "COMPUTER_RBCD" "$($c.Name): $($_.Exception.Message)" }
}

# ── FIX 4: COMPUTER_DCSYNC_RIGHTS (2 critical) ────────────────────────────────
Write-Host "`n[4] COMPUTER_DCSYNC_RIGHTS - Remove DCSync from non-DC computers" -ForegroundColor Yellow
$domainDN = (Get-ADDomain).DistinguishedName
$replicationGUID1 = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes
$replicationGUID2 = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" # DS-Replication-Get-Changes-All

$acl = Get-Acl "AD:$domainDN"
$removedCount = 0
foreach ($ace in @($acl.Access)) {
    $isReplication = ($ace.ObjectType -eq $replicationGUID1 -or $ace.ObjectType -eq $replicationGUID2)
    $isComputer = $false
    try {
        $samName = $ace.IdentityReference.Value.Split("\")[-1]
        $obj = Get-ADObject -Filter { SamAccountName -eq $samName } -Properties objectClass -ErrorAction SilentlyContinue
        $isComputer = $obj -and $obj.objectClass -eq "computer" -and $samName -notlike "DC-*"
    } catch {}

    if ($isReplication -and $isComputer) {
        $acl.RemoveAccessRule($ace) | Out-Null
        $removedCount++
    }
}
if ($removedCount -gt 0) {
    try {
        Set-Acl -Path "AD:$domainDN" -AclObject $acl
        Log "OK" "COMPUTER_DCSYNC_RIGHTS" "Removed $removedCount DCSync ACEs from domain object"
    } catch { Log "FAIL" "COMPUTER_DCSYNC_RIGHTS" $_.Exception.Message }
} else {
    Log "SKIP" "COMPUTER_DCSYNC_RIGHTS" "No non-DC computer DCSync rights found in domain ACL"
}

# ── FIX 5: ENTERPRISE_KEY_ADMINS_FULL_ACCESS - Remove from domain root ────────
Write-Host "`n[5] ENTERPRISE_KEY_ADMINS_FULL_ACCESS - Remove msDS-KeyCredentialLink ACE" -ForegroundColor Yellow
try {
    $ekaGroup = Get-ADGroup "Enterprise Key Admins" -ErrorAction SilentlyContinue
    if ($ekaGroup) {
        $acl = Get-Acl "AD:$domainDN"
        $removed = 0
        foreach ($ace in @($acl.Access)) {
            if ($ace.IdentityReference.Value -like "*Enterprise Key Admins*") {
                $acl.RemoveAccessRule($ace) | Out-Null
                $removed++
            }
        }
        if ($removed -gt 0) {
            Set-Acl -Path "AD:$domainDN" -AclObject $acl
            Log "OK" "ENTERPRISE_KEY_ADMINS_FULL_ACCESS" "Removed $removed Enterprise Key Admins ACEs from domain root"
        } else {
            Log "SKIP" "ENTERPRISE_KEY_ADMINS_FULL_ACCESS" "No ACEs on domain root (may be on child objects)"
        }
    } else {
        Log "SKIP" "ENTERPRISE_KEY_ADMINS_FULL_ACCESS" "Enterprise Key Admins group not found"
    }
} catch { Log "FAIL" "ENTERPRISE_KEY_ADMINS_FULL_ACCESS" $_.Exception.Message }

# ── FIX 6: USER_STALE_90_DAYS (10 high) - Disable stale users ────────────────
Write-Host "`n[6] USER_STALE_90_DAYS - Disable users inactive 90+ days" -ForegroundColor Yellow
$cutoff = (Get-Date).AddDays(-90)
$staleUsers = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object {
        $_.LastLogonDate -lt $cutoff -and
        $_.SamAccountName -notin @("Administrator","krbtgt","svc_n8n","Guest") -and
        $_.SamAccountName -notlike "svc.*" -and
        $_.SamAccountName -notlike "backup_*"
    } | Select-Object -First 10
Write-Host "Found: $($staleUsers.Count) stale users to disable"
foreach ($u in $staleUsers) {
    try {
        Disable-ADAccount -Identity $u.SamAccountName
        Log "OK" "USER_STALE_90_DAYS" "Disabled stale user $($u.SamAccountName) (last logon: $($u.LastLogonDate))"
    } catch { Log "FAIL" "USER_STALE_90_DAYS" "$($u.SamAccountName): $($_.Exception.Message)" }
}

# ── FIX 7: COMPUTER_NEVER_LOGGED_ON - Delete remaining (all 72) ──────────────
Write-Host "`n[7] COMPUTER_NEVER_LOGGED_ON - Delete computers that never logged on" -ForegroundColor Yellow
$neverLogged = Get-ADComputer -Filter * -Properties LastLogonDate |
    Where-Object {
        ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt (Get-Date).AddDays(-365)) -and
        $_.Enabled -eq $false
    }
Write-Host "Found: $($neverLogged.Count) disabled computers to delete"
foreach ($c in $neverLogged | Select-Object -First 20) {
    try {
        Remove-ADComputer -Identity $c.DistinguishedName -Confirm:$false
        Log "OK" "COMPUTER_NEVER_LOGGED_ON" "Deleted $($c.Name)"
    } catch { Log "FAIL" "COMPUTER_NEVER_LOGGED_ON" "$($c.Name): $($_.Exception.Message)" }
}

# ── FIX 8: EXCESSIVE_PRIVILEGED_ACCOUNTS (45 medium) ─────────────────────────
Write-Host "`n[8] EXCESSIVE_PRIVILEGED_ACCOUNTS - Remove excessive DA members" -ForegroundColor Yellow
$daMembers = Get-ADGroupMember "Domain Admins" |
    Where-Object { $_.ObjectClass -eq "user" } |
    Where-Object { $_.SamAccountName -notin @("Administrator","admin","administrator2") }
Write-Host "Domain Admins has $($daMembers.Count) user members"
# Remove members whose name suggests they shouldn't be DA (regular users)
$toRemove = $daMembers | Where-Object {
    $u = Get-ADUser $_.SamAccountName -Properties Description, Title -ErrorAction SilentlyContinue
    $u -and
    $u.SamAccountName -notlike "svc*" -and
    $u.SamAccountName -notlike "backup*" -and
    $u.SamAccountName -notlike "admin*" -and
    $_.SamAccountName -ne "Administrator"
} | Select-Object -First 5  # Conservative - only 5 at a time

foreach ($u in $toRemove) {
    try {
        Remove-ADGroupMember -Identity "Domain Admins" -Members $u.SamAccountName -Confirm:$false
        Log "OK" "EXCESSIVE_PRIVILEGED_ACCOUNTS" "Removed $($u.SamAccountName) from Domain Admins"
    } catch { Log "FAIL" "EXCESSIVE_PRIVILEGED_ACCOUNTS" "$($u.SamAccountName): $($_.Exception.Message)" }
}

# ── FIX 9: COMPUTER_CONSTRAINED_DELEGATION (3 critical) ──────────────────────
Write-Host "`n[9] COMPUTER_CONSTRAINED_DELEGATION - Review constrained delegation" -ForegroundColor Yellow
$constrained = Get-ADComputer -Filter * -Properties msDS-AllowedToDelegateTo |
    Where-Object { $_."msDS-AllowedToDelegateTo" -ne $null -and $_."msDS-AllowedToDelegateTo".Count -gt 0 }
Write-Host "Found: $($constrained.Count) computers with constrained delegation"
foreach ($c in $constrained) {
    Write-Host "  $($c.Name): $($_.'msDS-AllowedToDelegateTo')"
    # Only clear if suspicious (non-DC services)
    $suspiciousDelegations = $_."msDS-AllowedToDelegateTo" | Where-Object { $_ -match "cifs|host|http" -and $_ -notmatch "dc-0" }
    if ($suspiciousDelegations) {
        try {
            Set-ADComputer -Identity $c.SamAccountName -Clear "msDS-AllowedToDelegateTo"
            Log "OK" "COMPUTER_CONSTRAINED_DELEGATION" "Cleared delegation on $($c.Name)"
        } catch { Log "FAIL" "COMPUTER_CONSTRAINED_DELEGATION" "$($c.Name): $($_.Exception.Message)" }
    } else {
        Log "SKIP" "COMPUTER_CONSTRAINED_DELEGATION" "$($c.Name) has legitimate delegation"
    }
}

# ── SUMMARY ───────────────────────────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
$ok   = ($results | Where-Object { $_.Status -eq "OK" }).Count
$skip = ($results | Where-Object { $_.Status -eq "SKIP" }).Count
$fail = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
Write-Host "OK   : $ok" -ForegroundColor Green
Write-Host "SKIP : $skip" -ForegroundColor Yellow
Write-Host "FAIL : $fail" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })
Write-Host ""
$results | Format-Table -AutoSize
