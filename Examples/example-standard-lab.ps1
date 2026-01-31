# Example: Standard Security Lab (Recommended)
# Perfect for: Security tool testing, training, realistic simulations
# Execution time: ~15-20 minutes
# Disk space: ~500 MB

# Configuration
$TotalUsers = 12000
$TotalComputers = 1000
$UltraVulnUsers = 7
$DefaultPassword = "Welcome2024!"
$OutputPath = "C:\ADPopulate_Reports"

# Execute
C:\AD-Security-Lab\Scripts\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers $TotalUsers `
    -TotalComputers $TotalComputers `
    -UltraVulnUsers $UltraVulnUsers `
    -DefaultPassword $DefaultPassword `
    -OutputPath $OutputPath `
    -VulnPercent 10 `
    -VulnComputerPercent 10 `
    -Confirm

# Results
Write-Host ""
Write-Host "=== Standard Lab Created ===" -ForegroundColor Green
Write-Host "Users: $TotalUsers" -ForegroundColor Cyan
Write-Host "Computers: $TotalComputers" -ForegroundColor Cyan
Write-Host "Ultra-vulnerable honeypots: $UltraVulnUsers (70-210 vulnerabilities)" -ForegroundColor Yellow
Write-Host "Vulnerable users: ~$([math]::Round($TotalUsers * 0.10))" -ForegroundColor Yellow
Write-Host "Vulnerable computers: ~$([math]::Round($TotalComputers * 0.10))" -ForegroundColor Yellow
Write-Host ""
Write-Host "This lab includes:"
Write-Host "- 120+ vulnerability types" -ForegroundColor Cyan
Write-Host "- ADCS vulnerabilities (ESC1-11)" -ForegroundColor Cyan
Write-Host "- Attack paths to Domain Admin" -ForegroundColor Cyan
Write-Host "- Service account misconfigurations" -ForegroundColor Cyan
Write-Host "- GPO password in SYSVOL (MS14-025)" -ForegroundColor Cyan
Write-Host "- Exchange PrivExchange (CVE-2019-1166)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Recommended tests:"
Write-Host "1. BloodHound analysis"
Write-Host "2. PingCastle audit"
Write-Host "3. Kerberoasting attacks"
Write-Host "4. ADCS exploitation (Certipy)"
Write-Host "5. Privilege escalation testing"
Write-Host ""
