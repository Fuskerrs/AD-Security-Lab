$content = Get-Content "C:\AD-Security-Lab\Scripts\Populate-AD-GlobalCorp.ps1" -Raw

# Replace all occurrences of : $_ with - error details
$content = $content -replace '(Write-Log [^"]*"[^"]*): \$_"', '$1 - error"'
$content = $content -replace '(Write-Log [^"]*"[^"]*): \$\(\$_\.Exception\.Message\)"', '$1 - error"'

Set-Content "C:\AD-Security-Lab\Scripts\Populate-AD-GlobalCorp.ps1" -Value $content -NoNewline
Write-Host "Fixed!"
