Import-Module ActiveDirectory

Write-Host "=== Suppression de l'OU GlobalCorp ===" -ForegroundColor Red
Write-Host ""

try {
    # Désactiver la protection contre la suppression
    Write-Host "Étape 1/2: Désactivation de la protection..." -ForegroundColor Yellow
    Set-ADOrganizationalUnit -Identity "OU=GlobalCorp,DC=aza-me,DC=cc" -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
    Write-Host "  Protection désactivée" -ForegroundColor Green

    # Supprimer l'OU et tout son contenu
    Write-Host "Étape 2/2: Suppression récursive de l'OU et de tout son contenu..." -ForegroundColor Yellow
    Remove-ADOrganizationalUnit -Identity "OU=GlobalCorp,DC=aza-me,DC=cc" -Recursive -Confirm:$false -ErrorAction Stop
    Write-Host "  OU GlobalCorp supprimée avec succès!" -ForegroundColor Green

    Write-Host ""
    Write-Host "=== Suppression terminée ===" -ForegroundColor Green

} catch {
    Write-Host "ERREUR: $_" -ForegroundColor Red
    exit 1
}
