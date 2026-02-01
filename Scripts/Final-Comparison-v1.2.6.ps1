# Load confirmed types from AD (FOUND or PARTIAL status)
$confirmedTypes = Import-Csv 'C:\AD-Security-Lab\docs\audit\v1.1.4\resultats\FINAL-DEFINITIVE-RESULTS.csv' |
    Where-Object { $_.Status -in @('FOUND', 'PARTIAL') }

# Load v1.2.6 detected types
$detected = Import-Csv 'C:\AD-Security-Lab\docs\audit\v1.2.6\all-findings-exact.csv'

Write-Host "=== COMPARAISON 1000000% PRÉCISE v1.2.6 ==="
Write-Host ""
Write-Host "Types confirmés dans AD (FOUND/PARTIAL): $($confirmedTypes.Count)"
Write-Host "Types détectés par v1.2.6: $($detected.Count)"
Write-Host ""

# Create exact mapping based on dev's feedback
$exactMapping = @{
    # Perfect matches (uppercase conversion)
    'UnixUserPassword_Clear' = 'UNIX_USER_PASSWORD'
    'PasswordNeverExpires' = 'PASSWORD_NEVER_EXPIRES'
    'PasswordNotRequired' = 'PASSWORD_NOT_REQUIRED'
    'Empty_Password' = 'PASSWORD_NOT_REQUIRED'
    'ReversibleEncryption' = 'REVERSIBLE_ENCRYPTION'
    'PasswordInDescription' = 'PASSWORD_IN_DESCRIPTION'
    'ASREPRoastable' = 'ASREP_ROASTING_RISK'
    'Kerberoastable' = 'KERBEROASTING_RISK'
    'Kerberoastable_WeakPassword' = 'KERBEROASTING_RISK'
    'UnconstrainedDelegation' = 'UNCONSTRAINED_DELEGATION'
    'Computer_Unconstrained_Delegation' = 'COMPUTER_UNCONSTRAINED_DELEGATION'
    'ConstrainedDelegation' = 'CONSTRAINED_DELEGATION'
    'Weak_Encryption_Flag' = 'WEAK_ENCRYPTION_FLAG'
    'WEAK_PASSWORD_POLICY' = 'WEAK_PASSWORD_POLICY'
    'RECYCLE_BIN_DISABLED' = 'RECYCLE_BIN_DISABLED'

    # Computers
    'Computer_No_LAPS' = 'COMPUTER_NO_LAPS'
    'COMPUTER_NEVER_LOGGED_ON' = 'COMPUTER_NEVER_LOGGED_ON'
    'Computer_Wrong_OU' = 'COMPUTER_WRONG_OU'
    'Smartcard_Not_Required' = 'SMARTCARD_NOT_REQUIRED'
    'COMPUTER_NO_BITLOCKER' = 'COMPUTER_NO_BITLOCKER'
    'Computer_With_SPNs' = 'COMPUTER_WITH_SPNS'
    'Computer_Pre_Created' = 'COMPUTER_PRE_CREATED'
    'Computer_RBCD' = 'COMPUTER_RBCD'
    'Computer_Sensitive_Description' = 'COMPUTER_DESCRIPTION_SENSITIVE'
    'COMPUTER_LEGACY_PROTOCOL_SMBV1' = 'COMPUTER_LEGACY_PROTOCOL'
    'Computer_Weak_Encryption' = 'COMPUTER_WEAK_ENCRYPTION'
    'Computer_In_Admin_Group' = 'COMPUTER_IN_ADMIN_GROUP'
    'COMPUTER_OS_OBSOLETE_XP' = 'COMPUTER_OS_OBSOLETE_XP'
    'COMPUTER_OS_OBSOLETE_2003' = 'COMPUTER_OS_OBSOLETE_2003'
    'COMPUTER_OS_OBSOLETE_VISTA' = 'COMPUTER_OS_OBSOLETE_VISTA'
    'COMPUTER_OS_OBSOLETE_2008' = 'COMPUTER_OS_OBSOLETE_2008'
    'Computer_Disabled_Not_Deleted' = 'COMPUTER_DISABLED_NOT_DELETED'

    # Groups
    'Backup_Operators_Member' = 'BACKUP_OPERATORS_MEMBER'
    'Account_Operators_Member' = 'ACCOUNT_OPERATORS_MEMBER'
    'Print_Operators_Member' = 'PRINT_OPERATORS_MEMBER'
    'Server_Operators_Member' = 'SERVER_OPERATORS_MEMBER'
    'DNS_Admins_Member' = 'DNS_ADMINS_MEMBER'
    'BUILTIN_MODIFIED' = 'BUILTIN_MODIFIED'
    'AdminCount_Orphaned' = 'EXCESSIVE_PRIVILEGED_ACCOUNTS'
    'Dangerous_Group_Nesting' = 'DANGEROUS_GROUP_NESTING'
    'Oversized_Group_High' = 'OVERSIZED_GROUP_HIGH'
    'Oversized_Group_Critical' = 'OVERSIZED_GROUP_HIGH'

    # Accounts
    'Shared_Account' = 'SHARED_ACCOUNT'
    'Test_Account' = 'TEST_ACCOUNT'
    'SERVER_NO_ADMIN_GROUP' = 'SERVER_NO_ADMIN_GROUP'

    # ACL
    'Computer_ACL_GenericAll' = 'ACL_GENERICALL'

    # Based on dev's analysis
    'Domain_Admin_In_Description' = 'DOMAIN_ADMIN_IN_DESCRIPTION'
    'Not_In_Protected_Users' = 'NOT_IN_PROTECTED_USERS'
    'NotInProtectedUsers' = 'NOT_IN_PROTECTED_USERS'
    'Sensitive_Delegation' = 'SENSITIVE_DELEGATION'
    'SERVICE_ACCOUNT_INTERACTIVE' = 'SERVICE_ACCOUNT_INTERACTIVE'
    'SERVICE_ACCOUNT_PRIVILEGED' = 'SERVICE_ACCOUNT_PRIVILEGED'
    'SERVICE_ACCOUNT_NO_PREAUTH' = 'SERVICE_ACCOUNT_NO_PREAUTH'
    'SERVICE_ACCOUNT_WITH_SPN' = 'SERVICE_ACCOUNT_WITH_SPN'
    'SERVICE_ACCOUNT_NAMING' = 'SERVICE_ACCOUNT_NAMING'
    'SERVICE_ACCOUNT_OLD_PASSWORD' = 'SERVICE_ACCOUNT_OLD_PASSWORD'
    'SERVICE_ACCOUNT_WEAK_ENCRYPTION' = 'SERVICE_ACCOUNT_WEAK_ENCRYPTION'
    'GPO_Creator_Owners_Member' = 'GPO_MODIFY_RIGHTS'
    'Expired_Account_In_Admin_Group' = 'EXPIRED_ACCOUNT_IN_ADMIN_GROUP'
    'AdminSDHolder_Backdoor' = 'ADMINSDHOLDER_BACKDOOR'
    'Disabled_Account_In_Admin_Group' = 'DISABLED_ACCOUNT_IN_ADMIN_GROUP'
    'DisabledAccountInPrivGroup' = 'DISABLED_ACCOUNT_IN_ADMIN_GROUP'
}

# Check each confirmed type
$matched = @()
$notFound = @()

foreach ($confirmed in $confirmedTypes) {
    $adType = $confirmed.Type
    $detectorType = $exactMapping[$adType]

    if ($detectorType) {
        # Check if detected
        $finding = $detected | Where-Object { $_.type -eq $detectorType -and [int]$_.count -gt 0 }
        if ($finding) {
            $matched += [PSCustomObject]@{
                ADType = $adType
                DetectorType = $detectorType
                ADCount = [int]$confirmed.Found
                DetectedCount = [int]$finding.count
                Diff = [int]$finding.count - [int]$confirmed.Found
            }
        } else {
            $notFound += [PSCustomObject]@{
                ADType = $adType
                ExpectedDetector = $detectorType
                ADCount = [int]$confirmed.Found
                Reason = "Détecteur existe mais count=0"
            }
        }
    } else {
        $notFound += [PSCustomObject]@{
            ADType = $adType
            ExpectedDetector = "???"
            ADCount = [int]$confirmed.Found
            Reason = "Pas de mapping connu"
        }
    }
}

Write-Host "=== RÉSULTAT FINAL ==="
Write-Host "Détectés: $($matched.Count)/$($confirmedTypes.Count) types"
Write-Host "Non détectés: $($notFound.Count) types"
Write-Host ""

if ($notFound.Count -gt 0) {
    Write-Host "=== TYPES NON DÉTECTÉS ==="
    $notFound | Sort-Object -Property ADCount -Descending | Format-Table -AutoSize
    Write-Host ""
    Write-Host "Total instances manquantes: $(($notFound | Measure-Object -Property ADCount -Sum).Sum)"
} else {
    Write-Host "✅ TOUS LES TYPES CONFIRMÉS SONT DÉTECTÉS!"
}

Write-Host ""
Write-Host "=== TOP DÉTECTIONS ==="
$matched | Sort-Object -Property DetectedCount -Descending | Select-Object -First 15 | Format-Table -AutoSize

# Save results
$notFound | Export-Csv -Path "C:\AD-Security-Lab\docs\audit\v1.2.6\vraiment-manquants.csv" -NoTypeInformation
Write-Host ""
Write-Host "Saved: C:\AD-Security-Lab\docs\audit\v1.2.6\vraiment-manquants.csv"
