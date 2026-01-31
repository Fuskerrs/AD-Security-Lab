# Example: Enterprise-Scale Lab
# Perfect for: Performance testing, large-scale simulations, tool benchmarking
# Execution time: ~60-90 minutes
# Disk space: ~2-3 GB
# WARNING: Requires powerful DC (8+ GB RAM recommended)

# Configuration
$TotalUsers = 50000
$TotalComputers = 5000
$UltraVulnUsers = 25
$DefaultPassword = "Welcome2024!"
$OutputPath = "C:\ADPopulate_Reports"

Write-Host "=== Creating Enterprise-Scale Lab ===" -ForegroundColor Yellow
Write-Host "This will create 50,000 users and 5,000 computers." -ForegroundColor Yellow
Write-Host "Estimated time: 60-90 minutes" -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to continue or Ctrl+C to abort"

# Execute with higher vulnerability percentages for more realistic enterprise
C:\AD-Security-Lab\Scripts\Populate-AD-GlobalCorp.ps1 `
    -TotalUsers $TotalUsers `
    -TotalComputers $TotalComputers `
    -UltraVulnUsers $UltraVulnUsers `
    -DefaultPassword $DefaultPassword `
    -OutputPath $OutputPath `
    -VulnPercent 15 `
    -VulnComputerPercent 15 `
    -Confirm

# Results
Write-Host ""
Write-Host "=== Enterprise Lab Created ===" -ForegroundColor Green
Write-Host "Users: $TotalUsers" -ForegroundColor Cyan
Write-Host "Computers: $TotalComputers" -ForegroundColor Cyan
Write-Host "Ultra-vulnerable honeypots: $UltraVulnUsers" -ForegroundColor Yellow
Write-Host "Vulnerable users: ~$([math]::Round($TotalUsers * 0.15)) (15%)" -ForegroundColor Yellow
Write-Host "Vulnerable computers: ~$([math]::Round($TotalComputers * 0.15)) (15%)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Performance optimization notes:" -ForegroundColor Cyan
Write-Host "- Optimized manager hierarchy (O(1) hashtable lookups)" -ForegroundColor Gray
Write-Host "- Batch processing for large datasets" -ForegroundColor Gray
Write-Host "- Efficient AD object creation" -ForegroundColor Gray
Write-Host ""
Write-Host "Use cases for this lab:"
Write-Host "1. Benchmark security scanner performance (BloodHound, PingCastle)"
Write-Host "2. Test detection at scale (SIEM, EDR)"
Write-Host "3. Stress-test remediation procedures"
Write-Host "4. Enterprise architecture validation"
Write-Host ""
Write-Host "WARNING: BloodHound collection on 50K users may take 30+ minutes" -ForegroundColor Yellow
Write-Host ""
