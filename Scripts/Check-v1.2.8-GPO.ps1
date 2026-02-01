$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.2.8\audit-v1.2.8.json' -Raw | ConvertFrom-Json

Write-Host "=== v1.2.8 GPO SECURITY ==="
Write-Host ""

if ($json.audit.gpoSecurity) {
    Write-Host "Total: $($json.audit.gpoSecurity.total)"
    Write-Host "Findings: $($json.audit.gpoSecurity.findings.Count)"
    Write-Host ""

    Write-Host "=== FINDINGS ==="
    $json.audit.gpoSecurity.findings | Select-Object type, count, severity,
        @{N='Note';E={$_.details.note}} | Format-Table -AutoSize

    Write-Host ""
    Write-Host "=== DÉTAILS GPO_PASSWORD_IN_SYSVOL ==="
    $gpoPassword = $json.audit.gpoSecurity.findings | Where-Object { $_.type -eq 'GPO_PASSWORD_IN_SYSVOL' }
    if ($gpoPassword) {
        Write-Host "Count: $($gpoPassword.count)"
        Write-Host "Note: $($gpoPassword.details.note)"
        if ($gpoPassword.details.scannedGPOs) {
            Write-Host "GPOs scannés: $($gpoPassword.details.scannedGPOs)"
        }
    } else {
        Write-Host "NON TROUVÉ"
    }

    Write-Host ""
    Write-Host "=== DÉTAILS COMPUTER_NO_LAPS ==="
    $noLaps = $json.audit.gpoSecurity.findings | Where-Object { $_.type -eq 'COMPUTER_NO_LAPS' }
    if ($noLaps) {
        Write-Host "Count: $($noLaps.count)"
        Write-Host "Severity: $($noLaps.severity)"
        Write-Host "Note: $($noLaps.details.note)"

        if ($noLaps.affectedEntities) {
            Write-Host ""
            Write-Host "Computers sans LAPS:"
            $noLaps.affectedEntities | Select-Object -First 5 sAMAccountName, dn | Format-Table -AutoSize
        }
    } else {
        Write-Host "NON TROUVÉ"
    }
} else {
    Write-Host "Section gpoSecurity ABSENTE"
}

Write-Host ""
Write-Host "=== VÉRIFICATION MANUELLE AD ==="
Write-Host ""

# Count computers with LAPS
$computersWithLAPS = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime' |
    Where-Object {
        $_.'ms-Mcs-AdmPwdExpirationTime' -or $_.'msLAPS-PasswordExpirationTime'
    }

$totalComputers = (Get-ADComputer -Filter *).Count
$withoutLAPS = $totalComputers - $computersWithLAPS.Count

Write-Host "Total computers: $totalComputers"
Write-Host "Avec LAPS: $($computersWithLAPS.Count)"
Write-Host "Sans LAPS: $withoutLAPS"
Write-Host ""

if ($withoutLAPS -gt 0) {
    Write-Host "Computers SANS LAPS:"
    Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-PasswordExpirationTime' |
        Where-Object {
            -not $_.'ms-Mcs-AdmPwdExpirationTime' -and -not $_.'msLAPS-PasswordExpirationTime'
        } | Select-Object -First 10 Name, DistinguishedName | Format-Table -AutoSize

    Write-Host ""
    Write-Host "=== VERDICT ==="
    if ($withoutLAPS -eq 1) {
        Write-Host "✅ CORRECT: Le collecteur détecte bien 1 computer sans LAPS"
    } else {
        Write-Host "⚠️ DIFFÉRENCE: Collecteur dit 1, mais AD a $withoutLAPS computers sans LAPS"
    }
} else {
    Write-Host "✅ Tous les computers ont LAPS"
    Write-Host "⚠️ Le collecteur dit 1, mais AD dit 0"
}
