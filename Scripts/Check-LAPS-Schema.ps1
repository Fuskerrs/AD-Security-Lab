# Check if LAPS schema is extended in AD

$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.2.8\audit-v1.2.8.json' -Raw | ConvertFrom-Json

Write-Host "=== COLLECTOR DETECTION ==="
Write-Host ""
$noLaps = $json.audit.gpoSecurity.findings | Where-Object { $_.type -eq 'COMPUTER_NO_LAPS' }
if ($noLaps) {
    Write-Host "COMPUTER_NO_LAPS Count: $($noLaps.count)"
    Write-Host "Severity: $($noLaps.severity)"
    Write-Host "Note: $($noLaps.details.note)"
}

Write-Host ""
Write-Host "=== LAPS SCHEMA CHECK ==="
Write-Host ""

# Check if LAPS attributes exist in schema
$schema = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter * -Properties name | Where-Object { $_.name -like '*mcs-admpwd*' -or $_.name -like '*mslaps*' }

if ($schema) {
    Write-Host "OK LAPS schema IS extended"
    Write-Host ""
    Write-Host "LAPS attributes found:"
    $schema | Select-Object Name
} else {
    Write-Host "ERROR LAPS schema NOT extended"
    Write-Host ""
    Write-Host "This means:"
    Write-Host "  - LAPS is not installed/configured in this domain"
    Write-Host "  - ALL computers lack LAPS protection"
    Write-Host "  - No local admin password rotation"
}

Write-Host ""
Write-Host "=== COMPUTER COUNT ==="
$totalComputers = (Get-ADComputer -Filter *).Count
Write-Host "Total computers in domain: $totalComputers"

Write-Host ""
Write-Host "=== VERDICT ==="
Write-Host ""

if (-not $schema) {
    Write-Host "WARNING PROBLEME DETECTE:"
    Write-Host "  - Le schema LAPS n'est PAS etendu"
    Write-Host "  - Il y a $totalComputers computers SANS protection LAPS"
    Write-Host "  - Le collecteur dit: 1 computer sans LAPS"
    Write-Host ""
    Write-Host "ERREUR Le collecteur SOUS-ESTIME le probleme!"
    Write-Host "   Devrait detecter: $totalComputers computers sans LAPS"
    Write-Host "   Detecte: 1"
    Write-Host ""
    Write-Host "RECOMMENDATION:"
    Write-Host "   Le detecteur devrait verifier:"
    Write-Host "   1. Si le schema LAPS est etendu (ms-Mcs-AdmPwd exists)"
    Write-Host "   2. Si non = Tous les computers n'ont pas LAPS"
    Write-Host "   3. Si oui = Compter combien de computers n'ont pas l'attribut rempli"
}
