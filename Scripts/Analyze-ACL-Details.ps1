$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v2.7.5.json' -Raw | ConvertFrom-Json
$audit = $json.audit

function Show-FindingDetails($section, $type) {
    $f = $audit.$section.findings | Where-Object { $_.type -eq $type }
    if ($f) {
        Write-Host "=== $type (count=$($f.count), severity=$($f.severity)) ===" -ForegroundColor Cyan
        # Show first 5 affected objects
        if ($f.details) {
            $f.details | Select-Object -First 1 | ConvertTo-Json -Depth 4
        }
        if ($f.affected) {
            Write-Host "Sample affected objects:"
            $f.affected | Select-Object -First 5 | ConvertTo-Json -Depth 2
        }
        Write-Host ""
    }
}

Show-FindingDetails "permissions" "ENTERPRISE_KEY_ADMINS_FULL_ACCESS"
Show-FindingDetails "permissions" "ACL_GENERICALL"
Show-FindingDetails "permissions" "ACL_SELF_MEMBERSHIP"
Show-FindingDetails "computers"   "COMPUTER_UNCONSTRAINED_DELEGATION"
Show-FindingDetails "computers"   "COMPUTER_IN_ADMIN_GROUP"
Show-FindingDetails "computers"   "COMPUTER_DCSYNC_RIGHTS"
Show-FindingDetails "permissions" "ACL_DS_REPLICATION_GET_CHANGES"
Show-FindingDetails "adcs"        "ESC4_VULNERABLE_TEMPLATE_ACL"
Show-FindingDetails "computers"   "COMPUTER_RBCD"
