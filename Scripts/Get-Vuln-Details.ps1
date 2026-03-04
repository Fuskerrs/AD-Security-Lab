$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v1.3.0.json' -Raw | ConvertFrom-Json

function Show-Details($section, $type) {
    $f = $json.audit.$section.findings | Where-Object { $_.type -eq $type }
    if ($f) {
        Write-Host "=== $type ==="
        $f.details | ConvertTo-Json -Depth 3
        Write-Host ""
    }
}

Show-Details "gpoSecurity" "GPO_ORPHANED"
Show-Details "gpoSecurity" "GPO_UNLINKED"
Show-Details "gpoSecurity" "GPO_WEAK_PASSWORD_POLICY"
Show-Details "computers"   "COMPUTER_DESCRIPTION_SENSITIVE"
Show-Details "computers"   "COMPUTER_WRONG_OU"
Show-Details "groups"      "DNS_ADMINS_MEMBER"
Show-Details "groups"      "GROUP_PROTECTED_USERS_EMPTY"
Show-Details "groups"      "DANGEROUS_GROUP_NESTING"
Show-Details "computers"   "COMPUTER_NEVER_LOGGED_ON"
