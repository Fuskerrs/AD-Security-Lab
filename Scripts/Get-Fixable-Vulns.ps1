$json = Get-Content 'C:\AD-Security-Lab\docs\audit\v1.3.0\audit-v1.3.0.json' -Raw | ConvertFrom-Json

# Collect all findings across sections
$sections = $json.audit | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

Write-Host "=== ALL FINDINGS WITH COUNT > 0 ==="
foreach ($section in $sections) {
    $s = $json.audit.$section
    if ($s.findings) {
        foreach ($f in $s.findings) {
            if ($f.count -gt 0) {
                Write-Host "[$section] $($f.type) | count=$($f.count) | severity=$($f.severity)"
            }
        }
    }
}
