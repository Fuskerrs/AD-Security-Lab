# Example: Small Security Lab
# Perfect for: Quick testing, learning, laptop demos
# Execution time: ~5 minutes
# Disk space: ~50 MB

# Configuration
$TotalUsers = 1000
$TotalComputers = 100
$UltraVulnUsers = 3
$DefaultPassword = "Welcome2024!"
$OutputPath = "C:\ADPopulate_Reports"

# Execute
C:\AD-Security-Lab\Scripts\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers $TotalUsers `
    -TotalComputers $TotalComputers `
    -UltraVulnUsers $UltraVulnUsers `
    -DefaultPassword $DefaultPassword `
    -OutputPath $OutputPath `
    -VulnPercent 15 `
    -VulnComputerPercent 20 `
    -Confirm

# Results
Write-Host ""
Write-Host "=== Small Lab Created ===" -ForegroundColor Green
Write-Host "Users: $TotalUsers" -ForegroundColor Cyan
Write-Host "Computers: $TotalComputers" -ForegroundColor Cyan
Write-Host "Ultra-vulnerable honeypots: $UltraVulnUsers" -ForegroundColor Yellow
Write-Host "Vulnerable users: ~$([math]::Round($TotalUsers * 0.15))" -ForegroundColor Yellow
Write-Host "Vulnerable computers: ~$([math]::Round($TotalComputers * 0.20))" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:"
Write-Host "1. Open the HTML report in: $OutputPath"
Write-Host "2. Run BloodHound: SharpHound.exe -c All -d aza-me.cc"
Write-Host "3. Test Kerberoasting: Invoke-Kerberoast -Domain aza-me.cc"
Write-Host ""
