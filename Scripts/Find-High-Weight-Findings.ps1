$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v2.7.5.json' -Raw | ConvertFrom-Json
$audit = $json.audit

$all = @()
foreach ($key in $audit.PSObject.Properties.Name) {
    $section = $audit.$key
    if ($section -and $section.PSObject.Properties.Name -contains 'findings') {
        foreach ($f in $section.findings) {
            if ($f.count -gt 0) {
                $all += [PSCustomObject]@{
                    Section  = $key
                    Type     = $f.type
                    Count    = $f.count
                    Severity = $f.severity
                    # Score impact = count * severity weight
                    Weight   = $f.count * $(if($f.severity -eq "critical"){10} elseif($f.severity -eq "high"){5} elseif($f.severity -eq "medium"){2} else {1})
                }
            }
        }
    }
}

Write-Host "=== TOP 30 FINDINGS BY SCORE IMPACT ===" -ForegroundColor Cyan
$all | Sort-Object Weight -Descending | Select-Object -First 30 |
    Format-Table Section, Type, Count, Severity, Weight -AutoSize

Write-Host "`n=== CRITICAL FINDINGS (most impactful) ===" -ForegroundColor Red
$all | Where-Object { $_.Severity -eq "critical" } | Sort-Object Count -Descending |
    Format-Table Section, Type, Count -AutoSize

Write-Host "`n=== HIGH FINDINGS avec Count > 10 ===" -ForegroundColor Yellow
$all | Where-Object { $_.Severity -eq "high" -and $_.Count -gt 10 } | Sort-Object Count -Descending |
    Format-Table Section, Type, Count -AutoSize
