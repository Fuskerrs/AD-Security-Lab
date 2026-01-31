# Script de vérification des vulnérabilités non détectées

Write-Host "`n=== TEST 1: PASSWORDNEVEREXPIRES (39 instances injectées) ===" -ForegroundColor Yellow
try {
    $users = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires
    Write-Host "Trouvé: $($users.Count) utilisateurs avec PasswordNeverExpires=True"
    $users | Select-Object -First 5 Name, PasswordNeverExpires | Format-Table -AutoSize
} catch {
    Write-Host "Erreur: $_" -ForegroundColor Red
}

Write-Host "`n=== TEST 2: COMPUTER_OLD_PASSWORD (17 instances injectées) ===" -ForegroundColor Yellow
try {
    $threshold = (Get-Date).AddDays(-90)
    $computers = Get-ADComputer -Filter * -Properties PasswordLastSet | Where-Object {
        $_.PasswordLastSet -and $_.PasswordLastSet -lt $threshold
    }
    Write-Host "Trouvé: $($computers.Count) ordinateurs avec mot de passe > 90 jours"
    $computers | Select-Object -First 5 Name, PasswordLastSet | Format-Table -AutoSize
} catch {
    Write-Host "Erreur: $_" -ForegroundColor Red
}

Write-Host "`n=== TEST 3: COMPUTER_STALE_INACTIVE (17 instances injectées) ===" -ForegroundColor Yellow
try {
    $threshold = (Get-Date).AddDays(-90)
    $computers = Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {
        $_.LastLogonDate -and $_.LastLogonDate -lt $threshold
    }
    Write-Host "Trouvé: $($computers.Count) ordinateurs inactifs > 90 jours"
    $computers | Select-Object -First 5 Name, LastLogonDate | Format-Table -AutoSize
} catch {
    Write-Host "Erreur: $_" -ForegroundColor Red
}

Write-Host "`n=== TEST 4: DUPLICATE_SPN (17 instances injectées) ===" -ForegroundColor Yellow
try {
    $allObjects = @()
    $allObjects += Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
    $allObjects += Get-ADComputer -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

    $spns = @{}
    foreach ($obj in $allObjects) {
        foreach ($spn in $obj.ServicePrincipalName) {
            if (-not $spns.ContainsKey($spn)) {
                $spns[$spn] = @()
            }
            $spns[$spn] += $obj.Name
        }
    }

    $duplicates = $spns.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
    Write-Host "Trouvé: $($duplicates.Count) SPNs dupliqués"
    $duplicates | Select-Object -First 3 | ForEach-Object {
        Write-Host "  SPN: $($_.Key) - Utilisé par: $($_.Value -join ', ')"
    }
} catch {
    Write-Host "Erreur: $_" -ForegroundColor Red
}

Write-Host "`n=== TEST 5: GPO_PASSWORD_IN_SYSVOL ===" -ForegroundColor Yellow
try {
    $domain = (Get-ADDomain).DNSRoot
    $sysvolPath = "\\$domain\SYSVOL\$domain\Policies"
    Write-Host "Recherche dans: $sysvolPath"

    if (Test-Path $sysvolPath) {
        $xmlFiles = Get-ChildItem -Path $sysvolPath -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue
        $passwordFiles = $xmlFiles | Where-Object {
            $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
            $content -match "cpassword|password" -and $content -notmatch "<!--"
        }
        Write-Host "Trouvé: $($passwordFiles.Count) fichiers XML avec 'password' ou 'cpassword'"
        $passwordFiles | Select-Object -First 3 Name, FullName | Format-Table -AutoSize
    } else {
        Write-Host "Chemin SYSVOL non accessible" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Erreur: $_" -ForegroundColor Red
}

Write-Host "`n=== RÉSUMÉ ===" -ForegroundColor Cyan
Write-Host "Les vulnérabilités testées existent-elles vraiment dans l'AD?"
