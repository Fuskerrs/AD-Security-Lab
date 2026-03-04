$computers = @('WKS-OSAKA-3749','WKS-LAGOS-8648','WKS-KARACHI-1490','WKS-MANILA-4917','WKS-SHANGHAI-1010')
foreach ($c in $computers) {
    try {
        Get-ADComputer $c | Set-ADObject -Clear Description
        Write-Host "[OK] Cleared description on $c" -ForegroundColor Green
    } catch {
        Write-Host "[FAIL] $c : $($_.Exception.Message)" -ForegroundColor Red
    }
}
