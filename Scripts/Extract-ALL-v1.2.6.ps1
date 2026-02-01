$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.2.6\audit-v1.2.6.json' -Raw | ConvertFrom-Json

Write-Host "=== EXTRACTION COMPLÈTE TOUTES CATÉGORIES v1.2.6 ==="
Write-Host ""

$allFindings = @()

# ALL categories including subcategories
$categories = @(
    $json.audit.security.passwords.findings,
    $json.audit.security.kerberos.findings,
    $json.audit.security.advanced.findings,
    $json.audit.computers.findings,
    $json.audit.accounts.dangerous.findings,
    $json.audit.accounts.privileged.findings,  # ← MANQUAIT!
    $json.audit.accounts.service.findings,      # ← MANQUAIT!
    $json.audit.accounts.status.findings,       # ← MANQUAIT!
    $json.audit.groups.findings,
    $json.audit.permissions.findings,
    $json.audit.adcs.findings,
    $json.audit.gpoSecurity.findings,
    $json.audit.domainConfig.findings,
    $json.audit.trustsAnalysis.findings,
    $json.audit.extendedConfig.findings         # ← BONUS!
)

foreach ($cat in $categories) {
    if ($cat) {
        $allFindings += $cat
    }
}

Write-Host "Total types détectés: $($allFindings.Count)"
Write-Host ""

# Save complete list
$allFindings | Select-Object type, count, severity | Sort-Object type |
    Export-Csv -Path "C:\AD-Security-Lab\docs\audit\v1.2.6\all-findings-complete.csv" -NoTypeInformation

Write-Host "Saved: C:\AD-Security-Lab\docs\audit\v1.2.6\all-findings-complete.csv"
Write-Host ""

# Check specific types
$checkTypes = @(
    'DOMAIN_ADMIN_IN_DESCRIPTION',
    'NOT_IN_PROTECTED_USERS',
    'SENSITIVE_DELEGATION',
    'SERVICE_ACCOUNT_INTERACTIVE',
    'SERVICE_ACCOUNT_PRIVILEGED',
    'SERVICE_ACCOUNT_OLD_PASSWORD',
    'EXPIRED_ACCOUNT_IN_ADMIN_GROUP',
    'DISABLED_ACCOUNT_IN_ADMIN_GROUP'
)

Write-Host "=== VÉRIFICATION TYPES CRITIQUES ==="
foreach ($type in $checkTypes) {
    $finding = $allFindings | Where-Object { $_.type -eq $type }
    if ($finding) {
        Write-Host "✅ $type : $($finding.count)"
    } else {
        Write-Host "❌ $type : PAS TROUVÉ"
    }
}
